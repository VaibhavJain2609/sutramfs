//! Block-group descriptor table (GDT) decoding.
//!
//! Group descriptors are `s_desc_size` bytes each (32 without the 64bit
//! feature, ≥32 with it). For 1 KiB volumes the GDT starts at block 2,
//! otherwise at block 1 — [`Superblock::gdt_offset`] computes it.

use sutram_fs::{FsError, Result};
use sutram_io::{le, ByteSource};

use crate::superblock::Superblock;

/// `bg_flags`: inode table and bitmap uninitialised.
pub(crate) const BG_INODE_UNINIT: u16 = 0x0001;
/// `bg_flags`: block bitmap uninitialised.
pub(crate) const BG_BLOCK_UNINIT: u16 = 0x0002;
/// `bg_flags`: inode table zeroed past `bg_itable_unused`.
pub(crate) const BG_INODE_ZEROED: u16 = 0x0004;

/// One block-group descriptor.
#[derive(Debug, Clone, Copy)]
pub(crate) struct GroupDesc {
    /// Block holding the group's block-allocation bitmap.
    pub block_bitmap: u64,
    /// Block holding the group's inode-allocation bitmap.
    pub inode_bitmap: u64,
    /// First block of the group's inode table.
    pub inode_table: u64,
    pub free_blocks: u32,
    pub free_inodes: u32,
    pub used_dirs: u32,
    pub flags: u16,
    /// Inodes at the tail of the table never used (for `INODE_ZEROED`).
    pub itable_unused: u32,
    /// Absolute byte offset of this descriptor (provenance).
    pub disk_offset: u64,
}

impl GroupDesc {
    /// Decode one descriptor from `buf` at `off` (relative), honouring the
    /// 64-bit high halves when `has_64bit` is set.
    pub(crate) fn parse(
        buf: &[u8],
        off: usize,
        has_64bit: bool,
        disk_offset: u64,
    ) -> Option<Self> {
        let get16 = |o: usize| le::u16(buf, off + o).unwrap_or(0) as u32;
        let get32 = |o: usize| le::u32(buf, off + o).unwrap_or(0) as u64;
        let mut d = GroupDesc {
            block_bitmap: get32(0x00),
            inode_bitmap: get32(0x04),
            inode_table: get32(0x08),
            free_blocks: get16(0x0C),
            free_inodes: get16(0x0E),
            used_dirs: get16(0x10),
            flags: get16(0x12) as u16,
            itable_unused: get16(0x1C),
            disk_offset,
        };
        if has_64bit {
            d.block_bitmap |= get32(0x20) << 32;
            d.inode_bitmap |= get32(0x24) << 32;
            d.inode_table |= get32(0x28) << 32;
            d.free_blocks |= get16(0x2C) << 16;
            d.free_inodes |= get16(0x2E) << 16;
            d.used_dirs |= get16(0x30) << 16;
            // bg_itable_unused_hi @0x32 (0x34 is bg_exclude_bitmap_hi).
            d.itable_unused |= get16(0x32) << 16;
        }
        Some(d)
    }
}

/// Read the whole GDT. Bounded by `groups_count * desc_size` — live
/// metadata, not image bytes.
pub(crate) fn read_gdt(src: &dyn ByteSource, sb: &Superblock) -> Result<Vec<GroupDesc>> {
    let has_64bit = sb.feature_incompat & crate::superblock::INCOMPAT_64BIT != 0;
    let desc = sb.desc_size as u64;
    let total = sb.groups_count as u64 * desc;
    let off = sb.gdt_offset();
    let raw = src.read_slice(off, total as usize).map_err(FsError::Io)?;
    if (raw.len() as u64) < total {
        return Err(FsError::truncated(off, total, raw.len() as u64));
    }
    let mut out = Vec::with_capacity(sb.groups_count as usize);
    for g in 0..sb.groups_count {
        let rel = g as usize * desc as usize;
        match GroupDesc::parse(&raw, rel, has_64bit, off + rel as u64) {
            Some(d) => out.push(d),
            None => {
                return Err(FsError::corrupt(
                    off + rel as u64,
                    "short group descriptor".to_string(),
                ))
            }
        }
    }
    Ok(out)
}
