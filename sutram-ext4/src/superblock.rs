//! ext2/3/4 superblock parsing, feature flags, detection and backup
//! superblock geometry.
//!
//! The primary superblock always lives at absolute byte offset 1024
//! (`SB_OFFSET`), 1024 bytes long, regardless of the filesystem block
//! size. All fields are little-endian.

use sutram_fs::{DetectConfidence, FsError, Result};
use sutram_io::{le, ByteSource};

/// Absolute byte offset of the primary superblock.
pub(crate) const SB_OFFSET: u64 = 1024;
/// On-disk superblock size in bytes.
pub(crate) const SB_LEN: usize = 1024;
/// `s_magic` — stored at superblock offset 0x38 (absolute 0x438).
pub(crate) const EXT_MAGIC: u16 = 0xEF53;

// -- s_feature_compat bits ---------------------------------------------------
/// A jbd2 journal exists (ext3/ext4 marker; the journal inode is normally 8).
pub(crate) const COMPAT_HAS_JOURNAL: u32 = 0x0004;
/// Extended attributes in use.
pub(crate) const COMPAT_EXT_ATTR: u32 = 0x0008;
/// Directories may be HTree-indexed (dx_root/dx_node blocks).
pub(crate) const COMPAT_DIR_INDEX: u32 = 0x0020;

// -- s_feature_incompat bits -------------------------------------------------
/// Dirents carry a file_type byte.
pub(crate) const INCOMPAT_FILETYPE: u32 = 0x0002;
/// Journal must be replayed before mount (recovery pending).
pub(crate) const INCOMPAT_RECOVER: u32 = 0x0004;
/// Meta block groups.
pub(crate) const INCOMPAT_META_BG: u32 = 0x0010;
/// Inodes use extent trees instead of block maps (the ext4 signature).
pub(crate) const INCOMPAT_EXTENTS: u32 = 0x0040;
/// 64-bit block numbers / ≥ 32-byte group descriptors.
pub(crate) const INCOMPAT_64BIT: u32 = 0x0080;
/// Flexible block groups.
pub(crate) const INCOMPAT_FLEX_BG: u32 = 0x0200;
/// Data may live inside the inode itself.
pub(crate) const INCOMPAT_INLINE_DATA: u32 = 0x8000;
/// File contents/names may be encrypted (fscrypt).
pub(crate) const INCOMPAT_ENCRYPT: u32 = 0x1_0000;
/// Case-insensitive directories (per-dir `EXT4_CASEFOLD_FL`).
pub(crate) const INCOMPAT_CASEFOLD: u32 = 0x2_0000;

// -- s_feature_ro_compat bits -------------------------------------------------
/// Backup superblocks only in groups 0, 1 and powers of 3, 5, 7.
pub(crate) const RO_SPARSE_SUPER: u32 = 0x0001;
/// >2 GiB files permitted.
pub(crate) const RO_LARGE_FILE: u32 = 0x0002;
/// `i_size_high`/`i_blocks` high bits honoured.
pub(crate) const RO_HUGE_FILE: u32 = 0x0008;
/// Group descriptors carry checksums; `BLOCK_UNINIT`/`INODE_UNINIT` flags.
pub(crate) const RO_GDT_CSUM: u32 = 0x0010;
/// Directory `i_links_count` may saturate at 1.
pub(crate) const RO_DIR_NLINK: u32 = 0x0020;
/// Inodes carry `i_extra_isize` extended fields (nsec times, crtime).
pub(crate) const RO_EXTRA_ISIZE: u32 = 0x0040;
/// Cluster (not block) allocation.
pub(crate) const RO_BIGALLOC: u32 = 0x0200;
/// Whole-metadata checksumming (crc32c).
pub(crate) const RO_METADATA_CSUM: u32 = 0x0400;

/// Filesystem flavour, inferred from the feature flags — the on-disk
/// structures are shared across ext2/3/4; only the flags differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtVariant {
    /// No journal, no extents.
    Ext2,
    /// Journal but no extents.
    Ext3,
    /// Extents (the defining ext4 incompat feature).
    Ext4,
}

impl ExtVariant {
    pub(crate) fn name(self) -> &'static str {
        match self {
            ExtVariant::Ext2 => "ext2",
            ExtVariant::Ext3 => "ext3",
            ExtVariant::Ext4 => "ext4",
        }
    }
}

/// Parsed and sanity-checked superblock.
#[derive(Debug, Clone)]
pub(crate) struct Superblock {
    pub inodes_count: u32,
    pub blocks_count: u64,
    pub free_blocks_count: u64,
    pub free_inodes_count: u32,
    /// Block holding the superblock (0 for block_size>1k, 1 for 1k).
    pub first_data_block: u32,
    /// `1024 << s_log_block_size`.
    pub block_size: u64,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub mtime: u32,
    pub wtime: u32,
    pub mnt_count: u16,
    pub state: u16,
    pub errors: u16,
    pub rev_level: u32,
    pub first_ino: u32,
    pub inode_size: u16,
    pub feature_compat: u32,
    pub feature_incompat: u32,
    pub feature_ro_compat: u32,
    pub uuid: String,
    pub label: String,
    pub journal_inum: u32,
    pub last_orphan: u32,
    /// Group descriptor size (32 without 64bit, ≥32/`s_desc_size` with it).
    pub desc_size: u16,
    /// `s_log_groups_per_flex` when flex_bg is on.
    pub log_groups_per_flex: u8,
    pub mkfs_time: u32,
    /// Number of block groups.
    pub groups_count: u32,
    pub variant: ExtVariant,
}

impl Superblock {
    /// Parse + validate the primary superblock. Firmer than `detect`:
    /// nonsense geometry is `Corrupt`, short image is `Truncated`.
    pub fn parse(src: &dyn ByteSource) -> Result<Self> {
        Self::parse_at(src, SB_OFFSET)
    }

    /// Parse a superblock copy at an arbitrary offset (backup superblocks).
    pub fn parse_at(src: &dyn ByteSource, off: u64) -> Result<Self> {
        let b = src.read_slice(off, SB_LEN).map_err(FsError::Io)?;
        if b.len() < SB_LEN {
            return Err(FsError::truncated(off, SB_LEN as u64, b.len() as u64));
        }
        if le::u16(&b, 0x38) != Some(EXT_MAGIC) {
            return Err(FsError::corrupt(off + 0x38, "bad ext magic (not 0xef53)"));
        }
        let inodes_count = le::u32(&b, 0x00).unwrap_or(0);
        let blocks_lo = le::u32(&b, 0x04).unwrap_or(0) as u64;
        let free_lo = le::u32(&b, 0x0C).unwrap_or(0) as u64;
        let first_data_block = le::u32(&b, 0x14).unwrap_or(0);
        let log_block_size = le::u32(&b, 0x18).unwrap_or(0);
        let blocks_per_group = le::u32(&b, 0x20).unwrap_or(0);
        let inodes_per_group = le::u32(&b, 0x28).unwrap_or(0);
        let rev_level = le::u32(&b, 0x4C).unwrap_or(0);
        let feature_compat = le::u32(&b, 0x5C).unwrap_or(0);
        let feature_incompat = le::u32(&b, 0x60).unwrap_or(0);
        let feature_ro_compat = le::u32(&b, 0x64).unwrap_or(0);

        if log_block_size > 6 {
            return Err(FsError::corrupt(
                off + 0x18,
                format!("s_log_block_size {log_block_size} > 6"),
            ));
        }
        let block_size = 1024u64 << log_block_size;
        if inodes_count == 0 || blocks_lo == 0 {
            return Err(FsError::corrupt(
                off,
                "zero inode or block count".to_string(),
            ));
        }
        if blocks_per_group == 0 || inodes_per_group == 0 {
            return Err(FsError::corrupt(
                off + 0x20,
                "zero blocks/inodes per group".to_string(),
            ));
        }
        // Bitmaps are one block each; a group can describe at most
        // block_size*8 blocks / inodes are bounded by the table too, but
        // the cheap sanity bound is enough here.
        if blocks_per_group as u64 > block_size * 8 {
            return Err(FsError::corrupt(
                off + 0x20,
                format!("blocks_per_group {blocks_per_group} exceeds bitmap capacity"),
            ));
        }
        // first_data_block is 0 for block_size > 1 KiB, 1 for 1 KiB.
        let expect_fdb = if block_size == 1024 { 1 } else { 0 };
        if first_data_block != expect_fdb {
            return Err(FsError::corrupt(
                off + 0x14,
                format!("first_data_block {first_data_block} inconsistent with block size {block_size}"),
            ));
        }

        // Inode size: rev 0 volumes use 128; rev ≥1 store s_inode_size.
        let inode_size = if rev_level == 0 {
            128
        } else {
            le::u16(&b, 0x58).unwrap_or(0)
        };
        if inode_size < 128 || !inode_size.is_power_of_two() {
            return Err(FsError::corrupt(
                off + 0x58,
                format!("bad inode_size {inode_size}"),
            ));
        }
        // Inode table must fit in the group's blocks.
        let itable_bytes = inodes_per_group as u64 * inode_size as u64;
        if itable_bytes > blocks_per_group as u64 * block_size {
            return Err(FsError::corrupt(
                off + 0x28,
                "inode table larger than a whole block group".to_string(),
            ));
        }

        let has_64bit = feature_incompat & INCOMPAT_64BIT != 0;
        let desc_size = if has_64bit {
            le::u16(&b, 0xFE).unwrap_or(0).max(32)
        } else {
            32
        };
        let blocks_hi = if has_64bit {
            le::u32(&b, 0x150).unwrap_or(0) as u64
        } else {
            0
        };
        let free_hi = if has_64bit {
            le::u32(&b, 0x158).unwrap_or(0) as u64
        } else {
            0
        };
        let blocks_count = (blocks_hi << 32) | blocks_lo;
        let free_blocks_count = (free_hi << 32) | free_lo;

        let groups_count = blocks_count.div_ceil(blocks_per_group as u64) as u32;
        if groups_count == 0 || groups_count > (1 << 24) {
            return Err(FsError::corrupt(
                off,
                format!("implausible group count {groups_count}"),
            ));
        }
        // Loose consistency: the inode tables must be able to hold
        // s_inodes_count within groups_count groups.
        if inodes_count as u64 > inodes_per_group as u64 * groups_count as u64 {
            return Err(FsError::corrupt(
                off,
                "inodes_count exceeds inode tables".to_string(),
            ));
        }

        // ext4 UUIDs are stored in plain RFC-4122 byte order (not GPT's
        // mixed-endian form), so format the 16 bytes directly.
        let uuid = match le::get(&b, 0x68, 16) {
            Some(u) => format!(
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9],
                u[10], u[11], u[12], u[13], u[14], u[15]
            ),
            None => String::new(),
        };
        let label = le::ascii(&b, 0x78, 16).unwrap_or_default();
        let journal_inum = le::u32(&b, 0xE0).unwrap_or(0);
        let variant = if feature_incompat & INCOMPAT_EXTENTS != 0 {
            ExtVariant::Ext4
        } else if feature_compat & COMPAT_HAS_JOURNAL != 0 {
            ExtVariant::Ext3
        } else {
            ExtVariant::Ext2
        };

        Ok(Superblock {
            inodes_count,
            blocks_count,
            free_blocks_count,
            free_inodes_count: le::u32(&b, 0x10).unwrap_or(0),
            first_data_block,
            block_size,
            blocks_per_group,
            inodes_per_group,
            mtime: le::u32(&b, 0x2C).unwrap_or(0),
            wtime: le::u32(&b, 0x30).unwrap_or(0),
            mnt_count: le::u16(&b, 0x34).unwrap_or(0),
            state: le::u16(&b, 0x3A).unwrap_or(0),
            errors: le::u16(&b, 0x3C).unwrap_or(0),
            rev_level,
            first_ino: le::u32(&b, 0x54).unwrap_or(11).max(1),
            inode_size,
            feature_compat,
            feature_incompat,
            feature_ro_compat,
            uuid,
            label,
            journal_inum: if journal_inum == 0 { 8 } else { journal_inum },
            last_orphan: le::u32(&b, 0xE8).unwrap_or(0),
            desc_size,
            log_groups_per_flex: le::u8(&b, 0x174).unwrap_or(0),
            mkfs_time: le::u32(&b, 0x108).unwrap_or(0),
            groups_count,
            variant,
        })
    }

    /// Cheap structural probe — reads only the 1 KiB superblock window.
    pub fn detect(src: &dyn ByteSource) -> DetectConfidence {
        let b = match src.read_slice(SB_OFFSET, SB_LEN) {
            Ok(b) if b.len() >= SB_LEN => b,
            _ => return DetectConfidence::None,
        };
        if le::u16(&b, 0x38) != Some(EXT_MAGIC) {
            return DetectConfidence::None;
        }
        let mut score = 2u32; // magic
        let log_bs = le::u32(&b, 0x18).unwrap_or(0xFF);
        if log_bs <= 6 {
            score += 1;
        }
        let inos = le::u32(&b, 0x00).unwrap_or(0);
        let blocks = le::u32(&b, 0x04).unwrap_or(0);
        if inos > 0 && blocks > 0 {
            score += 1;
        }
        if le::u32(&b, 0x20).unwrap_or(0) > 0 && le::u32(&b, 0x28).unwrap_or(0) > 0 {
            score += 1;
        }
        let state = le::u16(&b, 0x3A).unwrap_or(0);
        if (1..=4).contains(&state) {
            score += 1;
        }
        // Full structural parse is the strongest signal.
        if Self::parse(src).is_ok() {
            score += 2;
        }
        // Image long enough to plausibly hold the volume.
        if src.len() >= SB_OFFSET + blocks as u64 * (1024u64 << log_bs.min(6)) {
            score += 1;
        }
        match score {
            0..=2 => DetectConfidence::Low,
            3..=5 => DetectConfidence::Medium,
            6..=7 => DetectConfidence::High,
            _ => DetectConfidence::Certain,
        }
    }

    /// Absolute offset of the group descriptor table.
    ///
    /// For 1 KiB blocks the GDT sits in the block after the superblock
    /// block (block 2); for larger blocks it is block 1.
    pub(crate) fn gdt_offset(&self) -> u64 {
        (self.first_data_block as u64 + 1) * self.block_size
    }

    /// True when group `g` holds a backup superblock.
    ///
    /// Without SPARSE_SUPER every group does; with it, backups live in
    /// group 0, 1 and powers of 3, 5, 7 only.
    pub(crate) fn group_has_backup_sb(&self, g: u32) -> bool {
        if self.feature_ro_compat & RO_SPARSE_SUPER == 0 {
            return true;
        }
        if g <= 1 {
            return true;
        }
        fn is_power_of(mut n: u32, base: u32) -> bool {
            while n % base == 0 {
                n /= base;
            }
            n == 1
        }
        is_power_of(g, 3) || is_power_of(g, 5) || is_power_of(g, 7)
    }

    /// Block numbers holding backup superblock copies (bounded by group
    /// count). Group `g`'s copy sits at `g * blocks_per_group +
    /// first_data_block` for 1 KiB volumes; for larger blocks it is the
    /// group's first block.
    pub(crate) fn backup_sb_blocks(&self) -> Vec<u64> {
        (0..self.groups_count)
            .filter(|&g| self.group_has_backup_sb(g))
            .map(|g| {
                g as u64 * self.blocks_per_group as u64
                    + if self.block_size == 1024 { 1 } else { 0 }
            })
            .collect()
    }
}
