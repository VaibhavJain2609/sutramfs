//! AVB (Android Verified Boot) `vbmeta` structures.
//!
//! A vbmeta blob is a 256-byte big-endian `AvbVBMetaImageHeader` followed by
//! an *authentication* block (hash + signature over the header+aux data) and
//! an *auxiliary* block (descriptors, public key). Descriptors declare the
//! dm-verity hash trees protecting each partition — the tamper-relevant
//! state a forensic report must surface: algorithm, rollback index, the
//! HASHTREE_DISABLED / VERIFICATION_DISABLED flags, and per-partition
//! hashtree/hash/chain records.
//!
//! A boot image may instead end with a 64-byte `AvbFooter` (`AVBf`) pointing
//! back at an embedded vbmeta blob — [`parse_footer`] + [`parse_at`] cover
//! that case.
//!
//! All fields are **big-endian** — the exception to the project's LE rule.

use sutram_fs::FsError;
use sutram_io::le;
use sutram_io::ByteSource;

use crate::Result;

/// `AvbVBMetaImageHeader.magic`.
pub const VBMETA_MAGIC: &[u8; 4] = b"AVB0";
/// `AvbFooter.magic` — footer sits in the last 64 bytes of its partition.
pub const FOOTER_MAGIC: &[u8; 4] = b"AVBf";
/// Fixed vbmeta header size.
pub const VBMETA_HEADER_SIZE: u64 = 256;
/// `AvbFooter` size.
pub const FOOTER_SIZE: u64 = 64;

/// `flags` bit: hashtree verification disabled (dm-verity off).
pub const FLAG_HASHTREE_DISABLED: u32 = 1 << 0;
/// `flags` bit: all verification disabled.
pub const FLAG_VERIFICATION_DISABLED: u32 = 1 << 1;

/// Cap on descriptor count — a corrupt `descriptors_size` must not OOM us.
const MAX_DESCRIPTORS: usize = 512;
/// Cap on a descriptor's total size — real descriptors are < 1 KiB + strings.
const MAX_DESCRIPTOR_BYTES: u64 = 1 << 20;
/// Cap on the whole vbmeta blob read.
const MAX_VBMETA_BYTES: u64 = 16 << 20;

/// dm-verity enforcement state as declared by the vbmeta flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmVerityState {
    /// Neither disable flag is set — hashtree verification expected.
    Enabled,
    /// `HASHTREE_DISABLED` set — dm-verity off but signatures still checked.
    HashtreeDisabled,
    /// `VERIFICATION_DISABLED` set — nothing verified at all.
    VerificationDisabled,
}

impl DmVerityState {
    /// Short label for reports.
    pub fn as_str(self) -> &'static str {
        match self {
            DmVerityState::Enabled => "enabled",
            DmVerityState::HashtreeDisabled => "hashtree_disabled",
            DmVerityState::VerificationDisabled => "verification_disabled",
        }
    }
}

/// `AvbFooter` — 64-byte tail of a boot-style partition embedding vbmeta.
#[derive(Debug, Clone)]
pub struct VbmetaFooter {
    /// Footer version (major.minor, normally 1.0).
    pub version: (u32, u32),
    /// Size of the original (unappended) image.
    pub original_image_size: u64,
    /// Absolute offset of the embedded vbmeta blob within the source.
    pub vbmeta_offset: u64,
    /// Size of the embedded vbmeta blob.
    pub vbmeta_size: u64,
    /// Absolute offset where this footer was found.
    pub footer_offset: u64,
}

/// One parsed vbmeta descriptor.
#[derive(Debug, Clone)]
pub enum VbmetaDescriptor {
    /// `AVB_DESCRIPTOR_TAG_PROPERTY` — free-form key/value.
    Property {
        /// Property name (e.g. `com.android.build.system.fingerprint`).
        key: String,
        /// Property value (kept as raw bytes — not guaranteed UTF-8).
        value: Vec<u8>,
    },
    /// `AVB_DESCRIPTOR_TAG_HASHTREE` — dm-verity tree for a partition.
    Hashtree {
        /// Partition the tree protects.
        partition_name: String,
        /// dm-verity table version.
        dm_verity_version: u32,
        /// Size of the hashed filesystem image.
        image_size: u64,
        /// Offset of the hash tree inside the partition.
        tree_offset: u64,
        /// Hash tree size.
        tree_size: u64,
        /// Filesystem block size.
        data_block_size: u32,
        /// Hash block size.
        hash_block_size: u32,
        /// FEC root count (0 = no FEC).
        fec_num_roots: u32,
        /// FEC offset inside the partition.
        fec_offset: u64,
        /// FEC size.
        fec_size: u64,
        /// Hash algorithm name (`sha1`, `sha256`, …).
        hash_algorithm: String,
        /// Salt length in bytes.
        salt_len: u32,
        /// Root digest length in bytes.
        root_digest_len: u32,
        /// Descriptor flags.
        flags: u32,
    },
    /// `AVB_DESCRIPTOR_TAG_HASH` — whole-image hash (non-verity partitions).
    Hash {
        /// Partition hashed.
        partition_name: String,
        /// Image size hashed.
        image_size: u64,
        /// Hash algorithm name.
        hash_algorithm: String,
        /// Salt length.
        salt_len: u32,
        /// Stored digest length.
        digest_len: u32,
        /// Descriptor flags.
        flags: u32,
    },
    /// `AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE`.
    KernelCmdline {
        /// Cmdline flags (USE_ONLY_IF_HASHTREE_*).
        flags: u32,
        /// The kernel command line.
        cmdline: String,
    },
    /// `AVB_DESCRIPTOR_TAG_CHAIN_PARTITION` — delegated verification.
    ChainPartition {
        /// Partition whose vbmeta verifies this sub-image.
        partition_name: String,
        /// Which rollback index slot protects this chain.
        rollback_index_location: u32,
        /// Embedded public key length.
        public_key_len: u32,
        /// Descriptor flags.
        flags: u32,
    },
    /// Tag this build doesn't decode — `(tag, payload_len)`.
    Unknown {
        /// Raw descriptor tag.
        tag: u64,
        /// Declared payload size.
        len: u64,
    },
}

impl VbmetaDescriptor {
    /// Partition name for partition-bound descriptors.
    pub fn partition_name(&self) -> Option<&str> {
        match self {
            VbmetaDescriptor::Hashtree { partition_name, .. }
            | VbmetaDescriptor::Hash { partition_name, .. }
            | VbmetaDescriptor::ChainPartition { partition_name, .. } => Some(partition_name),
            _ => None,
        }
    }
}

/// Everything extracted from a vbmeta blob.
#[derive(Debug)]
pub struct VbmetaInfo {
    /// Absolute offset of the vbmeta header within the source examined.
    pub offset: u64,
    /// Total blob size (header + authentication + auxiliary blocks).
    pub size: u64,
    /// `required_libavb_version` as `major.minor`.
    pub libavb_version: (u32, u32),
    /// `algorithm_type` (0 = unsigned/none, 1..=7 = hash+sig algorithms).
    pub algorithm_type: u32,
    /// Rollback index.
    pub rollback_index: u64,
    /// Rollback index location (top-level vbmeta only).
    pub rollback_index_location: u32,
    /// Raw `flags` field.
    pub flags: u32,
    /// Derived dm-verity enforcement state.
    pub dm_verity: DmVerityState,
    /// `release_string` (e.g. `avbtool 1.2.0`).
    pub release_string: String,
    /// Parsed descriptors.
    pub descriptors: Vec<VbmetaDescriptor>,
    /// `true` when a hash is stored in the authentication block.
    pub has_hash: bool,
    /// `true` when a signature is stored in the authentication block.
    pub has_signature: bool,
    /// `true` when a public key is stored in the auxiliary block.
    pub has_public_key: bool,
    /// Footer that located this blob, when found via [`parse_from_footer`].
    pub footer: Option<VbmetaFooter>,
    /// Non-fatal parse notes.
    pub warnings: Vec<String>,
}

/// Parse an `AvbFooter`, if present.
///
/// The canonical position is `src.len() - 64`. Partition views, however,
/// are usually padded to a sector boundary, so the real footer can sit a
/// few sectors *before* the view's end — scan the tail (up to 4 KiB) at
/// 64-byte alignment for the `AVBf` magic.
pub fn parse_footer(src: &dyn ByteSource) -> Result<Option<VbmetaFooter>> {
    let len = src.len();
    if len < FOOTER_SIZE {
        return Ok(None);
    }
    let scan = (len as usize).min(4096);
    let start = len - scan as u64;
    let buf = src.read_slice(start, scan).map_err(FsError::Io)?;
    if buf.len() < FOOTER_SIZE as usize {
        return Ok(None);
    }
    let last = buf.len() - FOOTER_SIZE as usize;
    for pos in (0..=last / FOOTER_SIZE as usize).rev() {
        let pos = pos * FOOTER_SIZE as usize + last % FOOTER_SIZE as usize;
        if &buf[pos..pos + 4] == FOOTER_MAGIC {
            let b = &buf[pos..pos + FOOTER_SIZE as usize];
            let off = start + pos as u64;
            return Ok(Some(parse_footer_at(b, off)));
        }
    }
    Ok(None)
}

fn parse_footer_at(buf: &[u8], off: u64) -> VbmetaFooter {
    VbmetaFooter {
        version: (
            le::u32_be(buf, 4).unwrap_or(0),
            le::u32_be(buf, 8).unwrap_or(0),
        ),
        original_image_size: le::u64_be(buf, 12).unwrap_or(0),
        vbmeta_offset: le::u64_be(buf, 20).unwrap_or(0),
        vbmeta_size: le::u64_be(buf, 28).unwrap_or(0),
        footer_offset: off,
    }
}

/// Parse a vbmeta blob whose header sits at offset 0 of `src`.
pub fn parse(src: &dyn ByteSource) -> Result<VbmetaInfo> {
    parse_at(src, 0, None)
}

/// Parse a vbmeta blob at absolute `offset`; `footer` records how it was
/// found when located through [`parse_footer`].
pub fn parse_at(
    src: &dyn ByteSource,
    offset: u64,
    footer: Option<VbmetaFooter>,
) -> Result<VbmetaInfo> {
    let hdr = src
        .read_slice(offset, VBMETA_HEADER_SIZE as usize)
        .map_err(FsError::Io)?;
    if hdr.len() < VBMETA_HEADER_SIZE as usize {
        return Err(FsError::truncated(
            offset,
            VBMETA_HEADER_SIZE,
            hdr.len() as u64,
        ));
    }
    if &hdr[0..4] != VBMETA_MAGIC {
        return Err(FsError::corrupt(offset, "no vbmeta AVB0 magic"));
    }

    let auth_size = le::u64_be(&hdr, 12).unwrap_or(0);
    let aux_size = le::u64_be(&hdr, 20).unwrap_or(0);
    let algorithm_type = le::u32_be(&hdr, 28).unwrap_or(0);
    let hash_offset = le::u64_be(&hdr, 32).unwrap_or(0);
    let hash_size = le::u64_be(&hdr, 40).unwrap_or(0);
    let sig_offset = le::u64_be(&hdr, 48).unwrap_or(0);
    let sig_size = le::u64_be(&hdr, 56).unwrap_or(0);
    // public_key_size @64; @72 is public_key_offset.
    let pubkey_size = le::u64_be(&hdr, 64).unwrap_or(0);
    let desc_offset = le::u64_be(&hdr, 96).unwrap_or(0);
    let desc_size = le::u64_be(&hdr, 104).unwrap_or(0);
    let rollback_index = le::u64_be(&hdr, 112).unwrap_or(0);
    let flags = le::u32_be(&hdr, 120).unwrap_or(0);
    let rollback_index_location = le::u32_be(&hdr, 124).unwrap_or(0);
    let release_string = le::ascii(&hdr, 128, 48).unwrap_or_default();

    let mut warnings = Vec::new();
    let total = VBMETA_HEADER_SIZE
        .saturating_add(auth_size)
        .saturating_add(aux_size);
    if auth_size & 0x3f != 0 || aux_size & 0x3f != 0 {
        warnings.push("vbmeta: auth/aux block sizes not 64-byte aligned".into());
    }
    if total > MAX_VBMETA_BYTES {
        return Err(FsError::corrupt(
            offset + 12,
            format!("implausible vbmeta blob size {total:#x}"),
        ));
    }
    if offset.saturating_add(total) > src.len() {
        warnings.push(format!(
            "vbmeta blob ({total:#x} bytes) extends past end of source {:#x}",
            src.len()
        ));
    }
    if hash_offset.saturating_add(hash_size) > auth_size
        || sig_offset.saturating_add(sig_size) > auth_size
    {
        warnings.push("vbmeta: hash/signature runs past authentication block".into());
    }
    if desc_offset.saturating_add(desc_size) > aux_size {
        warnings.push("vbmeta: descriptor region runs past auxiliary block".into());
    }

    let descriptors = if desc_size > 0 && desc_offset.saturating_add(desc_size) <= aux_size {
        // Saturating adds: `offset` is caller-supplied and need not relate
        // to a real source length — clamp rather than wrap/panic.
        let base = offset
            .saturating_add(VBMETA_HEADER_SIZE)
            .saturating_add(auth_size);
        let blob = src
            .read_slice(base.saturating_add(desc_offset), desc_size as usize)
            .map_err(FsError::Io)?;
        parse_descriptors(&blob, base.saturating_add(desc_offset), &mut warnings)
    } else {
        Vec::new()
    };

    let dm_verity = if flags & FLAG_VERIFICATION_DISABLED != 0 {
        DmVerityState::VerificationDisabled
    } else if flags & FLAG_HASHTREE_DISABLED != 0 {
        DmVerityState::HashtreeDisabled
    } else {
        DmVerityState::Enabled
    };

    Ok(VbmetaInfo {
        offset,
        size: total,
        libavb_version: (
            le::u32_be(&hdr, 4).unwrap_or(0),
            le::u32_be(&hdr, 8).unwrap_or(0),
        ),
        algorithm_type,
        rollback_index,
        rollback_index_location,
        flags,
        dm_verity,
        release_string,
        descriptors,
        has_hash: hash_size > 0,
        has_signature: sig_size > 0,
        has_public_key: pubkey_size > 0,
        footer,
        warnings,
    })
}

/// Try the footer path first (boot-style image), then offset 0.
///
/// Returns `Ok(None)` when neither yields a vbmeta blob — callers use this
/// for "does this partition embed vbmeta" probing.
pub fn find_vbmeta(src: &dyn ByteSource) -> Option<VbmetaInfo> {
    if let Ok(Some(footer)) = parse_footer(src) {
        if footer.vbmeta_size >= VBMETA_HEADER_SIZE
            && footer.vbmeta_offset.saturating_add(footer.vbmeta_size) <= src.len()
        {
            if let Ok(info) = parse_at(src, footer.vbmeta_offset, Some(footer)) {
                return Some(info);
            }
        }
    }
    parse(src).ok()
}

fn cstr(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

fn parse_descriptors(
    blob: &[u8],
    base_off: u64,
    warnings: &mut Vec<String>,
) -> Vec<VbmetaDescriptor> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 16 <= blob.len() && out.len() < MAX_DESCRIPTORS {
        let tag = le::u64_be(blob, pos).unwrap_or(0);
        let nbytes = le::u64_be(blob, pos + 8).unwrap_or(0);
        let desc_off = pos + 16;
        if nbytes > MAX_DESCRIPTOR_BYTES || desc_off.saturating_add(nbytes as usize) > blob.len() {
            warnings.push(format!(
                "vbmeta descriptor at {:#x}: declared size {nbytes} runs past region — stop",
                base_off + pos as u64
            ));
            break;
        }
        let d = &blob[desc_off..desc_off + nbytes as usize];
        out.push(parse_one_descriptor(tag, d, warnings));
        // Descriptors are 8-byte aligned; num_bytes_following excludes the
        // 16-byte tag/size header and is already padded to 8.
        pos = desc_off + nbytes as usize;
    }
    if pos < blob.len() && out.len() < MAX_DESCRIPTORS {
        // Trailing bytes < a descriptor header are alignment padding; only
        // warn if they are non-zero.
        if blob[pos..].iter().any(|&b| b != 0) {
            warnings.push(format!(
                "vbmeta: {} trailing non-descriptor bytes",
                blob.len() - pos
            ));
        }
    }
    out
}

fn parse_one_descriptor(tag: u64, d: &[u8], _warnings: &mut Vec<String>) -> VbmetaDescriptor {
    match tag {
        // PROPERTY: key_num_bytes u64, value_num_bytes u64, then key bytes +
        // NUL, then value bytes + NUL (lengths exclude the terminators).
        0 => {
            let key_len = le::u64_be(d, 0).unwrap_or(0) as usize;
            let value_len = le::u64_be(d, 8).unwrap_or(0) as usize;
            let key = d
                .get(16..16usize.saturating_add(key_len))
                .map(cstr)
                .unwrap_or_default();
            let voff = 16usize.saturating_add(key_len).saturating_add(1);
            let value = d
                .get(voff..voff.saturating_add(value_len))
                .map(|v| v.to_vec())
                .unwrap_or_default();
            VbmetaDescriptor::Property { key, value }
        }
        // HASHTREE — fixed part 104 bytes + reserved[60], then
        // name/salt/digest at offset 164.
        1 => {
            let name_len = le::u32_be(d, 88).unwrap_or(0) as usize;
            let partition_name = d
                .get(164..164usize.saturating_add(name_len))
                .map(cstr)
                .unwrap_or_default();
            VbmetaDescriptor::Hashtree {
                partition_name,
                dm_verity_version: le::u32_be(d, 0).unwrap_or(0),
                image_size: le::u64_be(d, 4).unwrap_or(0),
                tree_offset: le::u64_be(d, 12).unwrap_or(0),
                tree_size: le::u64_be(d, 20).unwrap_or(0),
                data_block_size: le::u32_be(d, 28).unwrap_or(0),
                hash_block_size: le::u32_be(d, 32).unwrap_or(0),
                fec_num_roots: le::u32_be(d, 36).unwrap_or(0),
                fec_offset: le::u64_be(d, 40).unwrap_or(0),
                fec_size: le::u64_be(d, 48).unwrap_or(0),
                hash_algorithm: cstr(d.get(56..88).unwrap_or(&[])),
                salt_len: le::u32_be(d, 92).unwrap_or(0),
                root_digest_len: le::u32_be(d, 96).unwrap_or(0),
                flags: le::u32_be(d, 100).unwrap_or(0),
            }
        }
        // HASH — fixed part 116 bytes, then name/salt/digest.
        2 => {
            let name_len = le::u32_be(d, 40).unwrap_or(0) as usize;
            let partition_name = d.get(116..116 + name_len).map(cstr).unwrap_or_default();
            VbmetaDescriptor::Hash {
                partition_name,
                image_size: le::u64_be(d, 0).unwrap_or(0),
                hash_algorithm: cstr(d.get(8..40).unwrap_or(&[])),
                salt_len: le::u32_be(d, 44).unwrap_or(0),
                digest_len: le::u32_be(d, 48).unwrap_or(0),
                flags: le::u32_be(d, 52).unwrap_or(0),
            }
        }
        // KERNEL_CMDLINE: flags u32, length u32, bytes (not NUL-terminated).
        3 => {
            let flags = le::u32_be(d, 0).unwrap_or(0);
            let len = le::u32_be(d, 4).unwrap_or(0) as usize;
            let cmdline = d
                .get(8..8 + len)
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default();
            VbmetaDescriptor::KernelCmdline { flags, cmdline }
        }
        // CHAIN_PARTITION: rollback_index_location u32, name_len u32,
        // pubkey_len u32, flags u32, reserved[60], name(NUL), pubkey.
        4 => {
            let name_len = le::u32_be(d, 4).unwrap_or(0) as usize;
            let partition_name = d.get(76..76 + name_len).map(cstr).unwrap_or_default();
            VbmetaDescriptor::ChainPartition {
                partition_name,
                rollback_index_location: le::u32_be(d, 0).unwrap_or(0),
                public_key_len: le::u32_be(d, 8).unwrap_or(0),
                flags: le::u32_be(d, 12).unwrap_or(0),
            }
        }
        other => VbmetaDescriptor::Unknown {
            tag: other,
            len: d.len() as u64,
        },
    }
}
