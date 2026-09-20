//! `nx_superblock_t` (container superblock) and the checkpoint descriptor
//! area scan that locates the latest valid checkpoint.
//!
//! The container superblock lives in block 0 *and* inside the checkpoint
//! descriptor area (a ring buffer of `nx_xp_desc_blocks` blocks starting at
//! `nx_xp_desc_base`). Per the spec, mounting uses block 0 only to find the
//! descriptor area; the authoritative superblock is the descriptor-area copy
//! with the largest transaction id whose checksum validates.
//!
//! Forensically this is the best part of APFS: the descriptor area retains
//! *older* checkpoints, and each checkpoint maps its own generation of
//! ephemeral objects — including superseded B-tree roots that still contain
//! records for since-deleted files.

use sutram_fs::{DetectConfidence, FsError, Result};
use sutram_io::{le, ByteSource};

use crate::checksum;
use crate::object::{otype, ObjHdr, Storage};

/// `"NXSB"` little-endian.
pub(crate) const NX_MAGIC: u32 = 0x4253_584e;

/// Maximum checkpoint descriptor blocks we will scan — a guard against a
/// corrupted `nx_xp_desc_blocks`. Real containers use tens of blocks.
pub(crate) const MAX_DESC_BLOCKS: u64 = 1 << 20;

/// A parsed container superblock (plus the block it was read from).
#[derive(Debug, Clone)]
pub(crate) struct NxSuperblock {
    /// The object's own header (oid is `OID_NX_SUPERBLOCK`, xid = checkpoint).
    pub hdr: ObjHdr,
    /// Absolute byte offset this copy was read from.
    pub disk_offset: u64,
    /// `nx_block_size`.
    pub block_size: u32,
    /// `nx_block_count`.
    pub block_count: u64,
    /// `nx_features`.
    pub features: u64,
    /// `nx_readonly_compatible_features`.
    pub ro_compat: u64,
    /// `nx_incompatible_features`.
    pub incompat: u64,
    /// `nx_uuid` — 16 bytes, stored big-endian, rendered as a UUID string.
    pub uuid: String,
    /// `nx_next_oid`.
    pub next_oid: u64,
    /// `nx_next_xid`.
    pub next_xid: u64,
    /// Checkpoint descriptor area geometry.
    pub xp_desc_blocks: u32,
    pub xp_data_blocks: u32,
    pub xp_desc_base: u64,
    pub xp_data_base: u64,
    /// Whether the descriptor area is contiguous (MSB of the raw
    /// `nx_xp_desc_blocks` clear). If false the area is a B-tree of pranges —
    /// unsupported in v1.
    pub xp_desc_contiguous: bool,
    /// `nx_xp_desc_index` / `nx_xp_desc_len` — where this checkpoint's blocks
    /// sit in the descriptor ring.
    pub xp_desc_index: u32,
    pub xp_desc_len: u32,
    /// `nx_spaceman_oid` — ephemeral oid resolved via the checkpoint map.
    pub spaceman_oid: u64,
    /// `nx_omap_oid` — oid of the container object map (ephemeral; resolved
    /// via the checkpoint map). Some writers leave a physical block number
    /// here — the mount path falls back to that interpretation.
    pub omap_oid: u64,
    /// `nx_reaper_oid`.
    pub reaper_oid: u64,
    /// `nx_max_file_systems`.
    pub max_file_systems: u32,
    /// Populated `nx_fs_oid[]` entries (volume superblock virtual oids).
    pub fs_oids: Vec<u64>,
    /// `nx_flags`.
    pub nx_flags: u64,
    /// `nx_keybag_base` / `nx_keybag_blocks` — container keybag extent
    /// (allocated blocks we must not report as free space).
    pub keybag_base: u64,
    pub keybag_blocks: u64,
}

impl NxSuperblock {
    /// Parse and fully validate the superblock in `block` (read at `off`).
    /// `block` is exactly one `nx_block_size` block.
    pub(crate) fn parse(block: &[u8], off: u64) -> Result<Self> {
        Self::parse_maybe(block, off, true)
    }

    /// `strict_cksum=false` is used for the block-0 probe: we still want the
    /// geometry fields even if the checksum is damaged.
    pub(crate) fn parse_maybe(block: &[u8], off: u64, strict_cksum: bool) -> Result<Self> {
        let hdr = ObjHdr::parse(block, off, strict_cksum)?;
        if hdr.type_code() != otype::NX_SUPERBLOCK {
            return Err(FsError::corrupt(
                off + 24,
                format!("o_type {:#x} is not NX_SUPERBLOCK", hdr.otype),
            ));
        }
        if le::u32(block, 32) != Some(NX_MAGIC) {
            return Err(FsError::corrupt(off + 32, "missing NXSB magic"));
        }
        let block_size = le::u32(block, 36).unwrap_or(0);
        if !(512..=65536).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(FsError::corrupt(
                off + 36,
                format!("bad nx_block_size {block_size}"),
            ));
        }
        if block.len() < block_size as usize {
            return Err(FsError::truncated(
                off,
                block_size as u64,
                block.len() as u64,
            ));
        }
        let block_count = le::u64(block, 40).unwrap_or(0);
        if block_count == 0 {
            return Err(FsError::corrupt(off + 40, "nx_block_count is 0"));
        }
        let raw_desc_blocks = le::u32(block, 104).unwrap_or(0);
        let raw_data_blocks = le::u32(block, 108).unwrap_or(0);
        let xp_desc_contiguous = raw_desc_blocks & 0x8000_0000 == 0;
        let xp_desc_blocks = raw_desc_blocks & 0x7fff_ffff;
        let xp_data_blocks = raw_data_blocks & 0x7fff_ffff;
        let xp_desc_base = le::u64(block, 112).unwrap_or(0);
        let xp_data_base = le::u64(block, 120).unwrap_or(0);
        let max_fs = le::u32(block, 180).unwrap_or(0).min(100);
        let mut fs_oids = Vec::new();
        for i in 0..max_fs as usize {
            if let Some(oid) = le::u64(block, 184 + i * 8) {
                if oid != 0 {
                    fs_oids.push(oid);
                }
            }
        }
        Ok(NxSuperblock {
            hdr,
            disk_offset: off,
            block_size,
            block_count,
            features: le::u64(block, 48).unwrap_or(0),
            ro_compat: le::u64(block, 56).unwrap_or(0),
            incompat: le::u64(block, 64).unwrap_or(0),
            uuid: uuid_be(block, 72).unwrap_or_default(),
            next_oid: le::u64(block, 88).unwrap_or(0),
            next_xid: le::u64(block, 96).unwrap_or(0),
            xp_desc_blocks,
            xp_data_blocks,
            xp_desc_base,
            xp_data_base,
            xp_desc_contiguous,
            xp_desc_index: le::u32(block, 136).unwrap_or(0),
            xp_desc_len: le::u32(block, 140).unwrap_or(0),
            spaceman_oid: le::u64(block, 152).unwrap_or(0),
            omap_oid: le::u64(block, 160).unwrap_or(0),
            reaper_oid: le::u64(block, 168).unwrap_or(0),
            max_file_systems: max_fs,
            fs_oids,
            nx_flags: le::u64(block, 1264).unwrap_or(0),
            keybag_base: le::u64(block, 1296).unwrap_or(0),
            keybag_blocks: le::u64(block, 1304).unwrap_or(0),
        })
    }

    /// Read the block-0 superblock, discovering the block size.
    ///
    /// Deliberately checksum-lenient: per the spec, block 0 is only a pointer
    /// to the checkpoint descriptor area and may hold a stale or damaged
    /// copy; the authoritative superblock comes from the descriptor scan
    /// (which *is* checksum-verified). Callers record whether the block-0
    /// checksum was valid via [`NxSuperblock::checksum_ok`].
    pub(crate) fn read_block0(src: &dyn ByteSource) -> Result<Self> {
        let head = src.read_slice(0, 4096).map_err(FsError::Io)?;
        if head.len() < 132 {
            return Err(FsError::truncated(0, 132, head.len() as u64));
        }
        if le::u32(&head, 32) != Some(NX_MAGIC) {
            return Err(FsError::corrupt(32, "missing NXSB magic"));
        }
        let block_size = le::u32(&head, 36).unwrap_or(0);
        if !(512..=65536).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(FsError::corrupt(
                36,
                format!("bad nx_block_size {block_size}"),
            ));
        }
        let block = src
            .read_slice(0, block_size as usize)
            .map_err(FsError::Io)?;
        Self::parse_maybe(&block, 0, false)
    }

    /// Whether the block this was parsed from passes Fletcher-64.
    /// Callers use it on the block-0 copy for reporting.
    pub(crate) fn checksum_ok_at(&self, src: &dyn ByteSource) -> bool {
        src.read_slice(self.disk_offset, self.block_size as usize)
            .map(|b| b.len() == self.block_size as usize && checksum::verify(&b))
            .unwrap_or(false)
    }
}

/// One entry of a `checkpoint_map_phys_t` (`checkpoint_mapping_t`, 40 bytes).
#[derive(Debug, Clone, Copy)]
pub(crate) struct CpMapEntry {
    /// `cpm_size` — object size in bytes.
    pub size: u32,
    /// `cpm_fs_oid` — owning volume oid, or 0 for container objects.
    pub fs_oid: u64,
    /// `cpm_oid` — the ephemeral object identifier.
    pub oid: u64,
    /// `cpm_paddr` — block number where the object lives.
    pub paddr: u64,
}

/// A valid checkpoint found in the descriptor area: a checksummed
/// `nx_superblock_t` plus the checkpoint-map entries tagged with its xid.
#[derive(Debug)]
pub(crate) struct Checkpoint {
    /// The checkpoint's superblock copy.
    pub nx: NxSuperblock,
    /// `o_xid` of this checkpoint.
    pub xid: u64,
    /// Merged map entries from every `checkpoint_map_phys_t` carrying this
    /// xid (ephemeral oid → location).
    pub map: Vec<CpMapEntry>,
}

impl Checkpoint {
    /// Resolve an ephemeral *container* object oid to `(paddr, size)`.
    /// Container-owned objects carry `cpm_fs_oid == 0`.
    pub(crate) fn lookup(&self, oid: u64) -> Option<(u64, u32)> {
        // Highest-paddr matching entry wins; the map can carry stale pairs.
        self.map
            .iter()
            .filter(|e| e.oid == oid && e.fs_oid == 0)
            .max_by_key(|e| e.paddr)
            .map(|e| (e.paddr, e.size))
    }
}

/// Outcome of scanning the checkpoint descriptor area.
#[derive(Debug)]
pub(crate) struct CheckpointScan {
    /// Every *valid* checkpoint found, ascending by xid.
    pub checkpoints: Vec<Checkpoint>,
    /// Blocks that looked like superblocks/checkpoint maps but failed
    /// checksum or decode — forensic signal.
    pub malformed_slots: Vec<u64>,
}

/// Scan the checkpoint descriptor area described by `label` (the block-0
/// superblock).
///
/// Every block in the area is read; valid `nx_superblock_t` copies become
/// checkpoint candidates and valid `checkpoint_map_phys_t` blocks contribute
/// their entries to the checkpoint matching their `o_xid`. Invalid blocks are
/// recorded in `malformed_slots` and skipped — a torn checkpoint must not
/// become the mount target.
pub(crate) fn scan_checkpoints(src: &dyn ByteSource, label: &NxSuperblock) -> Result<CheckpointScan> {
    if !label.xp_desc_contiguous {
        // Caller handles this earlier (Unsupported) — belt & braces.
        return Ok(CheckpointScan {
            checkpoints: Vec::new(),
            malformed_slots: Vec::new(),
        });
    }
    let bs = label.block_size as u64;
    let dev_blocks = src.len() / bs;
    let n = (label.xp_desc_blocks as u64).min(dev_blocks).min(MAX_DESC_BLOCKS);
    let base = label.xp_desc_base;

    let mut supers: Vec<(u64, NxSuperblock)> = Vec::new(); // (slot, nxsb)
    let mut maps: Vec<(u64, u64, Vec<CpMapEntry>)> = Vec::new(); // (slot, xid, entries)
    let mut malformed = Vec::new();

    for i in 0..n {
        let paddr = base.saturating_add(i);
        let off = paddr.saturating_mul(bs);
        let block = src.read_slice(off, bs as usize).map_err(FsError::Io)?;
        if block.len() < bs as usize {
            malformed.push(i);
            continue;
        }
        if !checksum::verify(&block) {
            malformed.push(i);
            continue;
        }
        let hdr = ObjHdr::parse(&block, off, true)?;
        match hdr.type_code() {
            otype::NX_SUPERBLOCK => match NxSuperblock::parse(&block, off) {
                Ok(nx) => supers.push((i, nx)),
                Err(_) => malformed.push(i),
            },
            otype::CHECKPOINT_MAP => {
                let count = le::u32(&block, 36).unwrap_or(0) as usize;
                // Each entry is 40 bytes; bound by what fits in the block.
                let max_entries = (bs as usize - 40) / 40;
                let count = count.min(max_entries);
                let mut entries = Vec::with_capacity(count);
                for j in 0..count {
                    let e = 40 + j * 40;
                    entries.push(CpMapEntry {
                        size: le::u32(&block, e + 8).unwrap_or(0),
                        fs_oid: le::u64(&block, e + 16).unwrap_or(0),
                        oid: le::u64(&block, e + 24).unwrap_or(0),
                        paddr: le::u64(&block, e + 32).unwrap_or(0),
                    });
                }
                maps.push((i, hdr.xid, entries));
            }
            _ => {
                // Zeroed or foreign slot — not malformed, just unused.
            }
        }
    }

    let mut checkpoints: Vec<Checkpoint> = supers
        .into_iter()
        .map(|(_slot, nx)| {
            let xid = nx.hdr.xid;
            let map = maps
                .iter()
                .filter(|(_, mx, _)| *mx == xid)
                .flat_map(|(_, _, e)| e.iter().copied())
                .collect();
            Checkpoint { nx, xid, map }
        })
        .collect();
    checkpoints.sort_by_key(|c| c.xid);
    Ok(CheckpointScan {
        checkpoints,
        malformed_slots: malformed,
    })
}

/// Detection confidence for an APFS container.
///
/// Cheap: reads block 0 only. `Certain` requires the Fletcher-64 to verify;
/// `High` for a sane superblock whose checksum fails (forensic images can be
/// damaged); `None` without the NXSB magic.
pub(crate) fn detect(src: &dyn ByteSource) -> DetectConfidence {
    let head = match src.read_slice(0, 4096) {
        Ok(b) if b.len() >= 64 => b,
        _ => return DetectConfidence::None,
    };
    if le::u32(&head, 32) != Some(NX_MAGIC) {
        return DetectConfidence::None;
    }
    let bs = le::u32(&head, 36).unwrap_or(0);
    if !(512..=65536).contains(&bs) || !bs.is_power_of_two() {
        return DetectConfidence::Low;
    }
    let block_count = le::u64(&head, 40).unwrap_or(0);
    if block_count == 0 {
        return DetectConfidence::Low;
    }
    // Full-block checksum verification.
    if let Ok(block) = src.read_slice(0, bs as usize) {
        if block.len() == bs as usize && checksum::verify(&block) {
            if let Ok(hdr) = ObjHdr::parse(&block, 0, false) {
                if hdr.type_code() == otype::NX_SUPERBLOCK
                    && hdr.storage() == Storage::Ephemeral
                {
                    return DetectConfidence::Certain;
                }
                if hdr.type_code() == otype::NX_SUPERBLOCK {
                    return DetectConfidence::High;
                }
            }
            return DetectConfidence::High;
        }
    }
    DetectConfidence::Medium
}

/// UUID from 16 big-endian bytes (APFS stores UUIDs in network order).
pub(crate) fn uuid_be(buf: &[u8], off: usize) -> Option<String> {
    let raw = le::get(buf, off, 16)?;
    Some(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]
    ))
}
