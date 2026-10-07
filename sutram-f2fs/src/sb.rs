//! F2FS superblock parsing and detection.
//!
//! The superblock lives at byte `0x400` inside block 0 and spans the rest of
//! the first 4 KiB block (1024..4096). A second copy sits at `0x1400`
//! (block 1). All multi-byte fields are little-endian.
//!
//! Layout notes (offsets are relative to the superblock base, `0x400`):
//!
//! ```text
//! 0x000  magic (0xF2F52010), major/minor version
//! 0x008  log_sectorsize, log_sectors_per_block, log_blocksize,
//!        log_blocks_per_seg, segs_per_sec, secs_per_zone
//! 0x020  checksum_offset, block_count(u64 @36 — packed)
//! 0x02C  section_count, segment_count{,_ckpt,_sit,_nat,_ssa,_main}
//! 0x048  segment0_blkaddr, cp_blkaddr, sit_blkaddr, nat_blkaddr,
//!        ssa_blkaddr, main_blkaddr, root_ino, node_ino, meta_ino
//! 0x06C  uuid[16], volume_name[512×u16]
//! 0x480  extension_count, extension_list, cp_payload, version strings
//! 0x884  feature flags, encryption level/salt, devices, quota inos,
//!        encoding, stop reasons, error counters, reserved, crc
//! ```

use sutram_fs::{DetectConfidence, FsError, Result};
use sutram_io::le;
use sutram_io::ByteSource;

/// F2FS magic at superblock offset 0.
pub(crate) const F2FS_MAGIC: u32 = 0xF2F5_2010;
/// Primary superblock byte offset.
pub(crate) const SB_OFF: u64 = 0x400;
/// Backup superblock byte offset (block 1 + 0x400).
pub(crate) const SB2_OFF: u64 = 0x1400;
/// On-disk superblock struct size (occupies the rest of block 0).
pub(crate) const SB_SIZE: usize = 0xC00; // 3072 bytes

/// `feature` bits (`F2FS_FEATURE_*`).
#[allow(dead_code)]
pub(crate) mod feature {
    pub const ENCRYPT: u32 = 0x0001;
    pub const BLKZONED: u32 = 0x0002;
    pub const ATOMIC_WRITE: u32 = 0x0004;
    pub const EXTRA_ATTR: u32 = 0x0008;
    pub const PRJQUOTA: u32 = 0x0010;
    pub const INODE_CHKSUM: u32 = 0x0020;
    pub const FLEXIBLE_INLINE_XATTR: u32 = 0x0040;
    pub const QUOTA_INO: u32 = 0x0080;
    pub const INODE_CRTIME: u32 = 0x0100;
    pub const LOST_FOUND: u32 = 0x0200;
    pub const VERITY: u32 = 0x0400;
    pub const SB_CHKSUM: u32 = 0x0800;
    pub const CASEFOLD: u32 = 0x1000;
    pub const COMPRESSION: u32 = 0x2000;
    pub const RO: u32 = 0x4000;
    pub const DEVICE_ALIAS: u32 = 0x8000;
    pub const PACKED_SSA: u32 = 0x1_0000;
}

/// Parsed and sanity-checked superblock.
#[derive(Debug, Clone)]
pub(crate) struct SuperBlock {
    pub major_ver: u16,
    pub minor_ver: u16,
    pub block_size: u64,
    /// log2 blocks per segment (almost always 9 → 512 blocks / 2 MiB).
    pub log_blocks_per_seg: u32,
    pub blks_per_seg: u64,
    pub segs_per_sec: u32,
    pub secs_per_zone: u32,
    /// Total user blocks on the device.
    pub block_count: u64,
    pub section_count: u32,
    pub segment_count: u32,
    pub segment_count_ckpt: u32,
    pub segment_count_sit: u32,
    pub segment_count_nat: u32,
    pub segment_count_ssa: u32,
    pub segment_count_main: u32,
    pub segment0_blkaddr: u64,
    pub cp_blkaddr: u64,
    pub sit_blkaddr: u64,
    pub nat_blkaddr: u64,
    pub ssa_blkaddr: u64,
    pub main_blkaddr: u64,
    pub root_ino: u32,
    pub node_ino: u32,
    pub meta_ino: u32,
    pub uuid: String,
    pub volume_name: Option<String>,
    pub extension_count: u32,
    pub cp_payload: u32,
    pub feature: u32,
    /// Kernel version strings (raw, NUL-trimmed).
    pub version: String,
    /// Set when the superblock CRC verified (`SB_CHKSUM` only).
    pub crc_ok: bool,
}

impl SuperBlock {
    /// Byte offset of block `b`.
    pub fn blk_off(&self, b: u64) -> u64 {
        b * self.block_size
    }

    /// Main-area-relative segment index for `blk` (`None` outside main).
    pub fn main_segno(&self, blk: u64) -> Option<u64> {
        if blk < self.main_blkaddr {
            return None;
        }
        let s = (blk - self.main_blkaddr) / self.blks_per_seg;
        (s < self.segment_count_main as u64).then_some(s)
    }

    /// First block of main-area segment `s` (main-relative index).
    pub fn main_seg_blk(&self, s: u64) -> u64 {
        self.main_blkaddr + s * self.blks_per_seg
    }

    /// Number of SIT blocks per copy: ceil(main_segs / SIT_ENTRY_PER_BLOCK).
    pub fn sit_block_count(&self) -> u64 {
        let per = (self.block_size / 74).max(1);
        self.segment_count_main.div_ceil(per as u32) as u64
    }

    /// Blocks in one SIT copy (half the SIT area).
    pub fn sit_blocks(&self) -> u64 {
        (self.segment_count_sit as u64 / 2) * self.blks_per_seg
    }

    /// Blocks in one NAT copy (half the NAT area).
    pub fn nat_blocks(&self) -> u64 {
        (self.segment_count_nat as u64 / 2) * self.blks_per_seg
    }

    /// Maximum addressable node id.
    pub fn max_nid(&self) -> u64 {
        let per = (self.block_size / 9).max(1);
        per * self.nat_blocks()
    }

    /// Whether the `feature` bit is set.
    pub fn has_feature(&self, f: u32) -> bool {
        self.feature & f != 0
    }

    /// Parse and validate the superblock (primary then backup).
    pub fn parse(src: &dyn ByteSource) -> Result<Self> {
        match Self::parse_at(src, SB_OFF) {
            Ok(sb) => Ok(sb),
            Err(e1) => match Self::parse_at(src, SB2_OFF) {
                Ok(sb) => Ok(sb),
                Err(_) => Err(e1),
            },
        }
    }

    /// Parse the superblock at absolute byte `off`.
    fn parse_at(src: &dyn ByteSource, off: u64) -> Result<Self> {
        let b = src.read_slice(off, SB_SIZE).map_err(FsError::Io)?;
        if b.len() < SB_SIZE {
            return Err(FsError::truncated(off, SB_SIZE as u64, b.len() as u64));
        }
        Self::decode(&b, off)
    }

    fn decode(b: &[u8], off: u64) -> Result<Self> {
        let magic = le::u32(b, 0).unwrap_or(0);
        if magic != F2FS_MAGIC {
            return Err(FsError::corrupt(
                off,
                format!("bad F2FS magic {magic:#x} (want {F2FS_MAGIC:#x})"),
            ));
        }
        let log_sector = le::u32(b, 8).unwrap_or(0);
        let log_sectors_per_block = le::u32(b, 12).unwrap_or(0);
        let log_blocksize = le::u32(b, 16).unwrap_or(0);
        if !(9..=14).contains(&log_sector) {
            return Err(FsError::corrupt(off + 8, "implausible sector size"));
        }
        if log_blocksize != log_sector + log_sectors_per_block {
            return Err(FsError::corrupt(
                off + 16,
                "log_blocksize != log_sectorsize + log_sectors_per_block",
            ));
        }
        if !(12..=16).contains(&log_blocksize) {
            return Err(FsError::corrupt(
                off + 16,
                format!("unsupported log_blocksize {log_blocksize}"),
            ));
        }
        let log_blocks_per_seg = le::u32(b, 20).unwrap_or(0);
        // The SIT validity map is a fixed 64 bytes → at most 512 blocks/seg.
        if log_blocks_per_seg == 0 || log_blocks_per_seg > 9 {
            return Err(FsError::corrupt(
                off + 20,
                format!("implausible log_blocks_per_seg {log_blocks_per_seg}"),
            ));
        }
        let block_size = 1u64 << log_blocksize;
        let blks_per_seg = 1u64 << log_blocks_per_seg;
        let segs_per_sec = le::u32(b, 24).unwrap_or(0);
        let secs_per_zone = le::u32(b, 28).unwrap_or(0);
        let checksum_offset = le::u32(b, 32).unwrap_or(0);
        let block_count = le::u64(b, 36).unwrap_or(0);
        let section_count = le::u32(b, 44).unwrap_or(0);
        let segment_count = le::u32(b, 48).unwrap_or(0);
        let seg_ckpt = le::u32(b, 52).unwrap_or(0);
        let seg_sit = le::u32(b, 56).unwrap_or(0);
        let seg_nat = le::u32(b, 60).unwrap_or(0);
        let seg_ssa = le::u32(b, 64).unwrap_or(0);
        let seg_main = le::u32(b, 68).unwrap_or(0);
        let segment0_blkaddr = le::u32(b, 72).unwrap_or(0) as u64;
        let cp_blkaddr = le::u32(b, 76).unwrap_or(0) as u64;
        let sit_blkaddr = le::u32(b, 80).unwrap_or(0) as u64;
        let nat_blkaddr = le::u32(b, 84).unwrap_or(0) as u64;
        let ssa_blkaddr = le::u32(b, 88).unwrap_or(0) as u64;
        let main_blkaddr = le::u32(b, 92).unwrap_or(0) as u64;
        let root_ino = le::u32(b, 96).unwrap_or(0);
        let node_ino = le::u32(b, 100).unwrap_or(0);
        let meta_ino = le::u32(b, 104).unwrap_or(0);

        if block_count == 0 || segment_count == 0 || seg_main == 0 {
            return Err(FsError::corrupt(off + 36, "zero block/segment counts"));
        }
        // Segment accounting must fit the declared total.
        let meta_segs = seg_ckpt as u64 + seg_sit as u64 + seg_nat as u64 + seg_ssa as u64;
        if meta_segs + seg_main as u64 > segment_count as u64 {
            return Err(FsError::corrupt(
                off + 52,
                "per-area segment counts exceed segment_count",
            ));
        }
        // Area block addresses must sit inside the device and be ordered.
        let dev_blks = segment_count as u64 * blks_per_seg;
        let ordered = segment0_blkaddr <= cp_blkaddr
            && cp_blkaddr < sit_blkaddr
            && sit_blkaddr < nat_blkaddr
            && nat_blkaddr < ssa_blkaddr
            && ssa_blkaddr < main_blkaddr;
        if !ordered {
            return Err(FsError::corrupt(
                off + 72,
                "segment-area block addresses out of order",
            ));
        }
        let main_end = main_blkaddr.saturating_add(seg_main as u64 * blks_per_seg);
        if main_end > segment0_blkaddr + dev_blks {
            return Err(FsError::corrupt(
                off + 92,
                "main area extends past declared segment space",
            ));
        }
        if root_ino == 0 {
            return Err(FsError::corrupt(off + 96, "root_ino is 0"));
        }
        if segs_per_sec == 0 || secs_per_zone == 0 {
            return Err(FsError::corrupt(off + 24, "zero section/zone geometry"));
        }

        let uuid = le::uuid_le(b, 108).unwrap_or_default();
        let volume_name = (0..512)
            .map(|i| le::u16(b, 124 + i * 2).unwrap_or(0))
            .take_while(|&c| c != 0)
            .map(|c| char::from_u32(c as u32).unwrap_or('\u{FFFD}'))
            .collect::<String>();
        let volume_name = (!volume_name.is_empty()).then_some(volume_name);
        let extension_count = le::u32(b, 1148).unwrap_or(0);
        let cp_payload = le::u32(b, 1664).unwrap_or(0);
        let version = le::ascii(b, 1668, 256).unwrap_or_default();
        let feature = le::u32(b, 2180).unwrap_or(0);

        // Optional superblock CRC (F2FS_FEATURE_SB_CHKSUM): stored at
        // `checksum_offset` which must point at the crc field (offset 3068).
        let mut crc_ok = false;
        if feature & feature::SB_CHKSUM != 0 && checksum_offset as usize == SB_SIZE - 4 {
            if let Some(stored) = le::u32(b, checksum_offset as usize) {
                let want = crate::crc32::f2fs_crc32(F2FS_MAGIC, &b[..checksum_offset as usize]);
                crc_ok = stored == want;
            }
        }

        Ok(SuperBlock {
            major_ver: le::u16(b, 4).unwrap_or(0),
            minor_ver: le::u16(b, 6).unwrap_or(0),
            block_size,
            log_blocks_per_seg,
            blks_per_seg,
            segs_per_sec,
            secs_per_zone,
            block_count,
            section_count,
            segment_count,
            segment_count_ckpt: seg_ckpt,
            segment_count_sit: seg_sit,
            segment_count_nat: seg_nat,
            segment_count_ssa: seg_ssa,
            segment_count_main: seg_main,
            segment0_blkaddr,
            cp_blkaddr,
            sit_blkaddr,
            nat_blkaddr,
            ssa_blkaddr,
            main_blkaddr,
            root_ino,
            node_ino,
            meta_ino,
            uuid,
            volume_name,
            extension_count,
            cp_payload,
            feature,
            version,
            crc_ok,
        })
    }

    /// Detection confidence for an F2FS-looking source.
    ///
    /// Checks the magic at `0x400` (and the backup at `0x1400`), then
    /// geometry coherence. Cheap: a few KiB at fixed offsets only.
    pub fn detect(src: &dyn ByteSource) -> DetectConfidence {
        for off in [SB_OFF, SB2_OFF] {
            let b = match src.read_slice(off, 8) {
                Ok(b) if b.len() >= 8 => b,
                _ => continue,
            };
            if le::u32(&b, 0) != Some(F2FS_MAGIC) {
                continue;
            }
            // Magic matched — grade by geometry sanity.
            return match Self::parse_at(src, off) {
                Ok(_) => DetectConfidence::Certain,
                Err(FsError::Truncated { .. }) => DetectConfidence::High,
                Err(_) => DetectConfidence::Medium,
            };
        }
        DetectConfidence::None
    }
}
