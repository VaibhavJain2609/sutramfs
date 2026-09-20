//! Segment-level metadata tables: SIT (Segment Information Table), NAT
//! (Node Address Table) and SSA (Segment Summary Area).
//!
//! Both SIT and NAT are **double-buffered**: every logical table block has
//! two physical copies, and a per-block version bit in the checkpoint's
//! `sit_nat_version_bitmap` selects the current one. The stale copy is a
//! forensic goldmine — it still describes the previous checkpoint's state,
//! including NAT entries for since-deleted nids and older node-block
//! locations for live ones.
//!
//! SIT copy layout: copy A occupies the first half of the SIT area, copy B
//! the second (`blk = sit_blkaddr + boff [+ sit_blocks]`).
//!
//! NAT copy layout: copies interleave by segment — NAT block index `b`
//! lives at `nat_blkaddr + (b<<1) - (b & (blks_per_seg-1))` for copy A and
//! one segment higher for copy B.

use sutram_fs::{FsError, Result};
use sutram_io::le;
use sutram_io::ByteSource;

use crate::sb::SuperBlock;

/// Test bit `i` of a little-endian bitmap (kernel `test_bit_le` order).
pub(crate) fn bit_le(bitmap: &[u8], i: u64) -> bool {
    let byte = (i / 8) as usize;
    match bitmap.get(byte) {
        Some(b) => b & (1 << (i % 8)) != 0,
        None => false,
    }
}

/// One SIT entry (74 bytes): vblocks u16, valid_map[64], mtime u64.
#[derive(Debug, Clone)]
pub(crate) struct SitEntry {
    /// Raw `vblocks` field — low 10 bits = valid block count, top bits = type.
    pub vblocks: u16,
    /// Validity bitmap of the segment's blocks (bit i = block i is live data).
    pub valid_map: [u8; 64],
    /// Segment age (elapsed-time seconds at last checkpoint write).
    pub mtime: u64,
}

impl SitEntry {
    /// Valid (currently allocated) block count in the segment.
    pub fn valid_blocks(&self) -> u32 {
        (self.vblocks & 0x3FF) as u32
    }

    /// `true` when no block in the segment is marked valid — the segment is
    /// free per the last checkpoint, so whatever bytes remain are stale.
    pub fn is_free(&self) -> bool {
        self.valid_blocks() == 0 || !self.valid_map.iter().any(|&b| b != 0)
    }
}

/// One NAT entry (9 bytes): version u8, ino u32, block_addr u32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NatEntry {
    pub version: u8,
    /// Owning inode number (== nid for inode nodes).
    pub ino: u32,
    /// Block address of the node block; 0 (`NULL_ADDR`) = free nid.
    pub block_addr: u32,
}

impl NatEntry {
    pub fn is_free(&self) -> bool {
        self.block_addr == 0
    }
}

/// One SSA summary entry (7 bytes): nid u32, version u8, ofs_in_node u16.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // `version` documents the entry; not yet consumed
pub(crate) struct SumEntry {
    /// Owner: for data blocks the *dnode* nid; for node blocks the nid itself.
    pub nid: u32,
    /// Node version of the owner at summary write time.
    pub version: u8,
    /// Block index within the owning node (data blocks only).
    pub ofs_in_node: u16,
}

/// Access layer over the on-disk tables. All reads are lazy and bounded —
/// one 4 KiB block per call — so mounting never buffers whole tables.
pub(crate) struct Tables<'a> {
    pub src: &'a dyn ByteSource,
    pub sb: &'a SuperBlock,
    /// SIT/NAT block-version bitmaps from the winning checkpoint.
    pub sit_bitmap: &'a [u8],
    pub nat_bitmap: &'a [u8],
}

impl<'a> Tables<'a> {
    /// Current physical block of SIT block index `boff`.
    pub fn sit_blk(&self, boff: u64) -> u64 {
        let mut blk = self.sb.sit_blkaddr + boff;
        if bit_le(self.sit_bitmap, boff) {
            blk += self.sb.sit_blocks();
        }
        blk
    }

    /// Current physical block of NAT block index `boff` (`nid / 455`).
    pub fn nat_blk(&self, boff: u64) -> u64 {
        let mask = self.sb.blks_per_seg - 1;
        let mut blk = self.sb.nat_blkaddr + (boff << 1) - (boff & mask);
        if bit_le(self.nat_bitmap, boff) {
            blk += self.sb.blks_per_seg;
        }
        blk
    }

    /// The stale (other-copy) physical block of NAT block index `boff`.
    /// The copies sit one segment apart: current at `nat_blk(boff)`, stale
    /// a segment below when the bitmap selects copy B, above otherwise.
    pub fn stale_nat_blk(&self, boff: u64) -> u64 {
        let mask = self.sb.blks_per_seg - 1;
        let base = self.sb.nat_blkaddr + (boff << 1) - (boff & mask);
        if bit_le(self.nat_bitmap, boff) {
            base // current is copy B → stale is copy A
        } else {
            base + self.sb.blks_per_seg // current is copy A → stale is copy B
        }
    }

    /// Fetch the *current* NAT entry for `nid` (None if out of range).
    pub fn nat_entry(&self, nid: u32) -> Result<Option<NatEntry>> {
        let per_block = self.sb.block_size / 9;
        if nid as u64 >= per_block * self.sb.nat_blocks() {
            return Ok(None);
        }
        let boff = nid as u64 / per_block;
        let blk = self.nat_blk(boff);
        let idx = (nid as u64 % per_block) as usize;
        let off = self.sb.blk_off(blk) + idx as u64 * 9;
        let b = src_read(self.src, off, 9)?;
        Ok(Some(NatEntry {
            version: b[0],
            ino: le::u32(&b, 1).unwrap_or(0),
            block_addr: le::u32(&b, 5).unwrap_or(0),
        }))
    }

    /// Fetch the *stale* (previous-checkpoint) NAT entry for `nid`.
    pub fn stale_nat_entry(&self, nid: u32) -> Result<Option<NatEntry>> {
        let per_block = self.sb.block_size / 9;
        if nid as u64 >= per_block * self.sb.nat_blocks() {
            return Ok(None);
        }
        let boff = nid as u64 / per_block;
        let blk = self.stale_nat_blk(boff);
        let idx = (nid as u64 % per_block) as usize;
        let off = self.sb.blk_off(blk) + idx as u64 * 9;
        let b = src_read(self.src, off, 9)?;
        Ok(Some(NatEntry {
            version: b[0],
            ino: le::u32(&b, 1).unwrap_or(0),
            block_addr: le::u32(&b, 5).unwrap_or(0),
        }))
    }

    /// Read a whole NAT block (one copy) — for the streaming stale-NAT scan.
    /// Returns `(cur_entries, stale_entries)` for block index `boff`.
    pub fn nat_block_pair(&self, boff: u64) -> Result<(Vec<NatEntry>, Vec<NatEntry>)> {
        let cur = self.nat_blk(boff);
        let stale = self.stale_nat_blk(boff);
        let cur_e = self.parse_nat_block(cur)?;
        let stale_e = self.parse_nat_block(stale)?;
        Ok((cur_e, stale_e))
    }

    fn parse_nat_block(&self, blk: u64) -> Result<Vec<NatEntry>> {
        let per = (self.sb.block_size / 9) as usize;
        let b = src_read(self.src, self.sb.blk_off(blk), self.sb.block_size as usize)?;
        let mut out = Vec::with_capacity(per);
        for i in 0..per {
            let o = i * 9;
            out.push(NatEntry {
                version: b[o],
                ino: le::u32(&b, o + 1).unwrap_or(0),
                block_addr: le::u32(&b, o + 5).unwrap_or(0),
            });
        }
        Ok(out)
    }

    /// Fetch the SSA summary entry for block `blk` (main area only).
    /// Non-packed SSA only — `PACKED_SSA` images report `Ok(None)`.
    pub fn sum_entry(&self, blk: u64) -> Result<Option<SumEntry>> {
        if self.sb.has_feature(crate::sb::feature::PACKED_SSA) {
            return Ok(None);
        }
        let Some(seg) = self.sb.main_segno(blk) else {
            return Ok(None);
        };
        let sblk = self.sb.ssa_blkaddr + seg; // sums_per_block == 1
        let off = (blk - self.sb.main_seg_blk(seg)) as usize;
        if off >= 512 {
            return Ok(None);
        }
        let b = src_read(self.src, self.sb.blk_off(sblk) + off as u64 * 7, 7)?;
        Ok(Some(SumEntry {
            nid: le::u32(&b, 0).unwrap_or(0),
            version: b[4],
            ofs_in_node: le::u16(&b, 5).unwrap_or(0),
        }))
    }
}

fn src_read(src: &dyn ByteSource, off: u64, len: usize) -> Result<Vec<u8>> {
    let b = src.read_slice(off, len).map_err(FsError::Io)?;
    if b.len() < len {
        return Err(FsError::truncated(off, len as u64, b.len() as u64));
    }
    Ok(b)
}
