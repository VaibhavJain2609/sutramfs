//! HFS+/HFSX volume header parsing and wrapped-volume detection.
//!
//! All HFS+ metadata is **big-endian** — every multi-byte field is decoded
//! with the explicit `*_be` helpers in [`sutram_io::le`]. The volume header
//! sits 1024 bytes into the volume (sector 2), with an alternate copy 1024
//! bytes before the end. HFS+ may also live *embedded* in a legacy HFS
//! wrapper: the HFS Master Directory Block (`"BD"` signature at 1024) then
//! describes the embedded volume's location via `drEmbedSigWord`/`drEmbedExtent`.
//!
//! Layout references: Apple TN1150 ("HFS Plus Volume Format") and
//! `fs/hfsplus/hfsplus_raw.h` (Linux).

use sutram_fs::{DetectConfidence, FsError, Result};
use sutram_io::le;
use sutram_io::ByteSource;

/// Byte offset of the volume header / MDB within a volume.
pub(crate) const VH_OFFSET: u64 = 1024;
/// Size of the volume header structure.
const VH_LEN: usize = 512;

/// `"H+"` — HFS+ signature.
pub(crate) const SIG_HFSPLUS: u16 = 0x482B;
/// `"HX"` — HFSX signature.
pub(crate) const SIG_HFSX: u16 = 0x4858;
/// `"BD"` — HFS Master Directory Block (wrapper or pure HFS).
pub(crate) const SIG_HFS_MDB: u16 = 0x4244;

/// Volume attributes: `kHFSVolumeJournaledMask`.
pub(crate) const VOL_JOURNALED: u32 = 1 << 13;
/// `kHFSVolumeSoftwareLockMask` (read-only / locked volume).
pub(crate) const VOL_SOFTLOCK: u32 = 1 << 15;
/// `kHFSVolumeUnmountedMask` (cleanly unmounted).
pub(crate) const VOL_UNMOUNTED: u32 = 1 << 8;

/// One extent descriptor: `start_block` + `block_count` (BE on disk).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Extent {
    /// First allocation block.
    pub start: u32,
    /// Number of contiguous blocks (0 = unused descriptor).
    pub count: u32,
}

/// `HFSPlusForkData` — 80 bytes: logical size, clump size, block count and
/// the first 8 extent descriptors of a fork.
#[derive(Debug, Clone, Default)]
pub(crate) struct ForkData {
    /// Logical byte length of the fork.
    pub logical_size: u64,
    /// Clump size (allocation hint).
    pub clump_size: u32,
    /// Total allocation blocks owned by the fork.
    pub total_blocks: u32,
    /// First 8 extents.
    pub extents: [Extent; 8],
}

impl ForkData {
    /// Decode from `buf` at `off` (big-endian). Needs 80 bytes.
    pub(crate) fn parse(buf: &[u8], off: usize) -> Option<ForkData> {
        let mut extents = [Extent::default(); 8];
        for (i, e) in extents.iter_mut().enumerate() {
            e.start = le::u32_be(buf, off + 16 + i * 8)?;
            e.count = le::u32_be(buf, off + 16 + i * 8 + 4)?;
        }
        Some(ForkData {
            logical_size: le::u64_be(buf, off)?,
            clump_size: le::u32_be(buf, off + 8)?,
            total_blocks: le::u32_be(buf, off + 12)?,
            extents,
        })
    }
}

/// Parsed HFS+ volume header plus the base offset it was found at
/// (`embed_base` is 0 for a normal volume, non-zero inside an HFS wrapper —
/// all allocation-block math is relative to it).
#[derive(Debug, Clone)]
pub(crate) struct VolumeHeader {
    /// `SIG_HFSPLUS` or `SIG_HFSX`.
    pub signature: u16,
    /// Format version (4 for HFS+, 5 for HFSX).
    pub version: u16,
    /// Volume attribute bits (`VOL_*`).
    pub attributes: u32,
    /// `lastMountedVersion` (e.g. `"H+Lx"`, `"10.0"`).
    pub last_mounted: u32,
    /// Allocation block holding the `JournalInfoBlock` (0 = none).
    pub journal_info_block: u32,
    /// Volume creation/modify/backup/fsck timestamps (1904-epoch seconds).
    pub create_date: u32,
    pub modify_date: u32,
    pub backup_date: u32,
    pub checked_date: u32,
    /// Statistic counters.
    pub file_count: u32,
    pub folder_count: u32,
    /// Allocation-block size in bytes.
    pub block_size: u32,
    /// Total / free allocation blocks.
    pub total_blocks: u32,
    pub free_blocks: u32,
    /// `nextAllocation` hint, clump sizes, `nextCatalogID`, write count.
    pub next_alloc: u32,
    pub rsrc_clump: u32,
    pub data_clump: u32,
    pub next_cnid: u32,
    pub write_count: u32,
    /// Text-encoding bitmap + Finder info.
    pub encodings: u64,
    pub finder_info: [u32; 8],
    /// Fork data for the five special files.
    pub alloc_fork: ForkData,
    pub ext_fork: ForkData,
    pub cat_fork: ForkData,
    pub attr_fork: ForkData,
    pub start_fork: ForkData,
    /// Absolute byte offset where allocation block 0 lives (== `embed_base`).
    pub block0_offset: u64,
    /// `true` when this HFS+ volume is embedded in an HFS wrapper.
    pub wrapped: bool,
    /// HFS wrapper volume label, when wrapped.
    pub wrapper_label: Option<String>,
}

impl VolumeHeader {
    /// Absolute byte offset of allocation block `n`.
    pub(crate) fn block_off(&self, n: u32) -> u64 {
        self.block0_offset + n as u64 * self.block_size as u64
    }

    /// Expand a fork's extent descriptors into `(block, count)` pairs,
    /// skipping empty descriptors.
    pub(crate) fn extents_of(fork: &ForkData) -> Vec<Extent> {
        fork.extents
            .iter()
            .copied()
            .filter(|e| e.count != 0)
            .collect()
    }

    /// Parse + validate the volume header at `base + 1024`, following an HFS
    /// wrapper's embedded extent when present. Firmer than [`detect`].
    pub(crate) fn parse(src: &dyn ByteSource) -> Result<VolumeHeader> {
        let b = src.read_slice(VH_OFFSET, VH_LEN).map_err(FsError::Io)?;
        if b.len() < VH_LEN {
            return Err(FsError::truncated(VH_OFFSET, VH_LEN as u64, b.len() as u64));
        }
        let sig = le::u16_be(&b, 0).unwrap_or(0);
        match sig {
            SIG_HFSPLUS | SIG_HFSX => Self::parse_vh(&b, 0, false, None),
            SIG_HFS_MDB => Self::parse_wrapped(src, &b),
            _ => Err(FsError::corrupt(
                VH_OFFSET,
                format!("bad signature {sig:#06x} (want H+/HX/BD)"),
            )),
        }
    }

    /// Follow an HFS wrapper's embedded-volume descriptor.
    fn parse_wrapped(src: &dyn ByteSource, mdb: &[u8]) -> Result<VolumeHeader> {
        let embed_sig = le::u16_be(mdb, 0x7C).unwrap_or(0);
        if embed_sig != SIG_HFSPLUS {
            return Err(FsError::unsupported(
                "pure HFS (non-plus) volume: no embedded HFS+ signature",
            ));
        }
        let al_blk_siz = le::u32_be(mdb, 0x14).unwrap_or(0) as u64;
        let al_bl_st = le::u16_be(mdb, 0x1C).unwrap_or(0) as u64;
        let embed_start = le::u16_be(mdb, 0x7E).unwrap_or(0) as u64;
        if al_blk_siz == 0 {
            return Err(FsError::corrupt(0x14, "wrapper drAlBlkSiz is 0"));
        }
        let embed_off = al_bl_st * 512 + embed_start * al_blk_siz;
        // Wrapper volume name: drVN at 0x24 — Pascal string (len byte + ≤27).
        let wrapper_label = {
            let n = mdb.get(0x24).copied().unwrap_or(0).min(27) as usize;
            let raw = le::get(mdb, 0x25, n).unwrap_or(&[]);
            let s = String::from_utf8_lossy(raw).to_string();
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        };
        let b = src
            .read_slice(embed_off + VH_OFFSET, VH_LEN)
            .map_err(FsError::Io)?;
        if b.len() < VH_LEN {
            return Err(FsError::truncated(
                embed_off + VH_OFFSET,
                VH_LEN as u64,
                b.len() as u64,
            ));
        }
        let sig = le::u16_be(&b, 0).unwrap_or(0);
        if sig != SIG_HFSPLUS && sig != SIG_HFSX {
            return Err(FsError::corrupt(
                embed_off + VH_OFFSET,
                format!("embedded volume signature {sig:#06x} is not H+/HX"),
            ));
        }
        Self::parse_vh(&b, embed_off, true, wrapper_label)
    }

    /// Validate + decode a raw 512-byte volume header buffer.
    pub(crate) fn parse_vh(
        b: &[u8],
        embed_base: u64,
        wrapped: bool,
        wrapper_label: Option<String>,
    ) -> Result<VolumeHeader> {
        let signature = le::u16_be(b, 0).unwrap_or(0);
        let version = le::u16_be(b, 2).unwrap_or(0);
        if !(4..=5).contains(&version) {
            return Err(FsError::corrupt(
                VH_OFFSET + 2,
                format!("bad HFS+ version {version}"),
            ));
        }
        let block_size = le::u32_be(b, 40).unwrap_or(0);
        if block_size < 512 || !block_size.is_power_of_two() {
            return Err(FsError::corrupt(
                VH_OFFSET + 40,
                format!("bad block size {block_size}"),
            ));
        }
        let total_blocks = le::u32_be(b, 44).unwrap_or(0);
        if total_blocks == 0 {
            return Err(FsError::corrupt(VH_OFFSET + 44, "zero total blocks"));
        }
        // The catalog file must have at least one extent to be mountable.
        let cat_fork = ForkData::parse(b, 272)
            .ok_or_else(|| FsError::corrupt(VH_OFFSET + 272, "catalog fork truncated"))?;
        if cat_fork.logical_size == 0 || cat_fork.total_blocks == 0 {
            return Err(FsError::corrupt(
                VH_OFFSET + 272,
                "catalog file has no extents",
            ));
        }
        let mut finder_info = [0u32; 8];
        for (i, f) in finder_info.iter_mut().enumerate() {
            *f = le::u32_be(b, 80 + i * 4).unwrap_or(0);
        }
        Ok(VolumeHeader {
            signature,
            version,
            attributes: le::u32_be(b, 4).unwrap_or(0),
            last_mounted: le::u32_be(b, 8).unwrap_or(0),
            journal_info_block: le::u32_be(b, 12).unwrap_or(0),
            create_date: le::u32_be(b, 16).unwrap_or(0),
            modify_date: le::u32_be(b, 20).unwrap_or(0),
            backup_date: le::u32_be(b, 24).unwrap_or(0),
            checked_date: le::u32_be(b, 28).unwrap_or(0),
            file_count: le::u32_be(b, 32).unwrap_or(0),
            folder_count: le::u32_be(b, 36).unwrap_or(0),
            block_size,
            total_blocks,
            free_blocks: le::u32_be(b, 48).unwrap_or(0),
            next_alloc: le::u32_be(b, 52).unwrap_or(0),
            rsrc_clump: le::u32_be(b, 56).unwrap_or(0),
            data_clump: le::u32_be(b, 60).unwrap_or(0),
            next_cnid: le::u32_be(b, 64).unwrap_or(0),
            write_count: le::u32_be(b, 68).unwrap_or(0),
            encodings: le::u64_be(b, 72).unwrap_or(0),
            finder_info,
            alloc_fork: ForkData::parse(b, 112)
                .ok_or_else(|| FsError::corrupt(VH_OFFSET + 112, "alloc fork truncated"))?,
            ext_fork: ForkData::parse(b, 192)
                .ok_or_else(|| FsError::corrupt(VH_OFFSET + 192, "extents fork truncated"))?,
            cat_fork,
            attr_fork: ForkData::parse(b, 352)
                .ok_or_else(|| FsError::corrupt(VH_OFFSET + 352, "attr fork truncated"))?,
            start_fork: ForkData::parse(b, 432)
                .ok_or_else(|| FsError::corrupt(VH_OFFSET + 432, "startup fork truncated"))?,
            block0_offset: embed_base,
            wrapped,
            wrapper_label,
        })
    }

    /// Cheap detection probe. Reads at most a few KiB at fixed offsets.
    pub(crate) fn detect(src: &dyn ByteSource) -> DetectConfidence {
        let b = match src.read_slice(VH_OFFSET, VH_LEN) {
            Ok(b) if b.len() >= VH_LEN => b,
            _ => return DetectConfidence::None,
        };
        let sig = le::u16_be(&b, 0).unwrap_or(0);
        match sig {
            SIG_HFSPLUS | SIG_HFSX => {
                let version = le::u16_be(&b, 2).unwrap_or(0);
                let block_size = le::u32_be(&b, 40).unwrap_or(0);
                let total_blocks = le::u32_be(&b, 44).unwrap_or(0);
                let mut score = 2;
                if (4..=5).contains(&version) {
                    score += 2;
                }
                if block_size >= 512 && block_size.is_power_of_two() {
                    score += 1;
                }
                if total_blocks > 0 && u64::from(total_blocks) * u64::from(block_size) > VH_OFFSET {
                    score += 1;
                }
                // Catalog fork must carry plausible extents.
                if let Some(cat) = ForkData::parse(&b, 272) {
                    if cat.logical_size > 0 && cat.extents[0].count > 0 {
                        score += 2;
                    }
                }
                match score {
                    0..=3 => DetectConfidence::Low,
                    4..=5 => DetectConfidence::Medium,
                    6..=7 => DetectConfidence::High,
                    _ => DetectConfidence::Certain,
                }
            }
            SIG_HFS_MDB => {
                // HFS wrapper (or a pure HFS volume — recognised but only
                // mountable when it embeds an HFS+ volume).
                if le::u16_be(&b, 0x7C).unwrap_or(0) != SIG_HFSPLUS {
                    return DetectConfidence::Low; // pure HFS: unsupported
                }
                match Self::parse(src) {
                    Ok(_) => DetectConfidence::High,
                    Err(_) => DetectConfidence::Medium,
                }
            }
            _ => DetectConfidence::None,
        }
    }
}

/// Journal info block awareness: if `journal_info_block` is set, decode the
/// `JournalInfoBlock` (flags + device signature + buffer offset/size) and
/// peek at the journal header magic (`'JNLx'`/`'jnlx'`).
///
/// Returns `(info_meta_keys, raw_journal_header_magic)` — all best-effort;
/// callers record keys into `FsInfo::meta`.
pub(crate) struct JournalInfo {
    /// Allocation block the JIB was read from.
    pub jib_block: u32,
    /// JIB flags.
    pub flags: u32,
    /// Byte offset + size of the on-disk journal buffer.
    pub buffer_offset: u64,
    pub buffer_size: u64,
    /// Journal header magic if readable (`"JNLx"` big-endian header seen).
    pub journal_magic: Option<u32>,
}

/// Read and decode the `JournalInfoBlock` at `journal_info_block`.
/// All-BE on disk. Returns `None` when the block is absent/unreadable.
pub(crate) fn read_journal_info(src: &dyn ByteSource, vh: &VolumeHeader) -> Option<JournalInfo> {
    if vh.journal_info_block == 0 {
        return None;
    }
    let off = vh.block_off(vh.journal_info_block);
    let b = src.read_slice(off, 512).ok()?;
    if b.len() < 52 {
        return None;
    }
    let buffer_offset = le::u64_be(&b, 36)?;
    let buffer_size = le::u64_be(&b, 44)?;
    let journal_magic = if buffer_size > 0 && buffer_offset > 0 {
        let h = src.read_slice(buffer_offset, 16).ok()?;
        if h.len() >= 4 {
            let m = le::u32_be(&h, 0).unwrap_or(0);
            Some(m)
        } else {
            None
        }
    } else {
        None
    };
    Some(JournalInfo {
        jib_block: vh.journal_info_block,
        flags: le::u32_be(&b, 0).unwrap_or(0),
        buffer_offset,
        buffer_size,
        journal_magic,
    })
}
