//! Generic XFS B+tree block decoding.
//!
//! All XFS btrees share one block shape:
//!
//! ```text
//! [header][keys (maxrecs × key_len)][ptrs (maxrecs × ptr_len)]  node
//! [header][records (numrecs × rec_len)]                          leaf
//! ```
//!
//! The pointer array sits at a **fixed** offset (`hdr + maxrecs*key_len`),
//! not packed after `numrecs` keys — matching `xfs_btree_ptr_offset` in the
//! kernel. Two header flavours exist:
//!
//! * *short form* (per-AG trees: bnobt, cntbt, inobt, finobt) — 32-bit
//!   block links/pointers. Header = 16 bytes (v4) or 56 bytes (v5 CRC).
//! * *long form* (bmbt) — 64-bit fsblock pointers. Header = 24 bytes (v4)
//!   or 72 bytes (v5). Parsed in `extent.rs` since the root lives in an
//!   inode fork.
//!
//! Everything is big-endian on disk.

use std::collections::HashSet;

use sutram_fs::{FsError, Result};
use sutram_io::le::{u16_be, u32_be};
use sutram_io::ByteSource;

use crate::crc;
use crate::sb::{Superblock, NULLAGBLOCK};

/// Maximum btree depth we will descend (real trees are ≤ 5; this is a
/// loop guard against corrupt images).
pub(crate) const MAX_BTREE_DEPTH: u16 = 8;
/// Hard cap on blocks visited during one tree walk.
const MAX_BTREE_BLOCKS: usize = 1 << 20;

/// Parsed btree block header (short form).
#[derive(Debug)]
pub(crate) struct SBlock {
    pub level: u16,
    pub numrecs: u16,
    /// Sibling links — kept for structural completeness; the walker
    /// descends via the root rather than chaining leaves.
    #[allow(dead_code)]
    pub leftsib: u32,
    #[allow(dead_code)]
    pub rightsib: u32,
    /// Bytes consumed by the header (16 for v4, 56 for v5/CRC form).
    pub hdr_len: usize,
    /// CRC verification result, when the block carries one.
    pub crc_ok: Option<bool>,
}

/// Btree flavour parameters.
#[derive(Clone, Copy)]
pub(crate) struct TreeKind {
    /// magic for the non-CRC (v4) block form.
    pub magic_v4: u32,
    /// magic for the CRC (v5) block form.
    pub magic_v5: u32,
    /// key size in bytes (node blocks).
    pub key_len: usize,
    /// pointer size in bytes (node blocks; 4 for short form).
    pub ptr_len: usize,
    /// record size in bytes (leaf blocks).
    pub rec_len: usize,
}

/// bnobt — free space ordered by block number ('ABTB'/'AB3B').
pub(crate) const BNOBT: TreeKind = TreeKind {
    magic_v4: 0x4142_5442,
    magic_v5: 0x4142_3342,
    key_len: 8, // xfs_alloc_key_t = xfs_alloc_rec {startblock,blockcount}
    ptr_len: 4,
    rec_len: 8,
};

/// cntbt — free space ordered by extent length ('ABTC'/'AB3C').
#[allow(dead_code)]
pub(crate) const CNTBT: TreeKind = TreeKind {
    magic_v4: 0x4142_5443,
    magic_v5: 0x4142_3343,
    key_len: 8,
    ptr_len: 4,
    rec_len: 8,
};

/// inobt — inode chunk index ('IABT'/'IAB3').
pub(crate) const INOBT: TreeKind = TreeKind {
    magic_v4: 0x4941_4254,
    magic_v5: 0x4941_4233,
    key_len: 4,
    ptr_len: 4,
    rec_len: 16,
};

/// finobt — free-inode index ('FIBT'/'FIB3'); same record shape as inobt.
pub(crate) const FINOBT: TreeKind = TreeKind {
    magic_v4: 0x4649_4254,
    magic_v5: 0x4649_4233,
    key_len: 4,
    ptr_len: 4,
    rec_len: 16,
};

/// Byte length of the short-form block header.
pub(crate) fn sblock_hdr_len(crc: bool) -> usize {
    if crc {
        8 + 48 // bb_{magic,level,numrecs} + xfs_btree_block_shdr
    } else {
        8 + 8 // + leftsib/rightsib (u32 each)
    }
}

/// CRC field offset inside a short-form block (bb_u.s.bb_crc).
const SBLOCK_CRC_OFF: usize = 52;

/// Parse the header of a short-form block. `blk` is the whole fs block;
/// `off` its absolute byte offset (for errors). Accepts either magic
/// variant — a v4 block on a v5 filesystem still parses.
pub(crate) fn parse_sblock(
    blk: &[u8],
    off: u64,
    sb: &Superblock,
    kind: TreeKind,
) -> Result<SBlock> {
    if blk.len() < 16 {
        return Err(FsError::truncated(off, 16, blk.len() as u64));
    }
    let magic = u32_be(blk, 0).unwrap_or(0);
    let is_v5 = magic == kind.magic_v5;
    if magic != kind.magic_v4 && magic != kind.magic_v5 {
        return Err(FsError::corrupt(
            off,
            format!("bad btree magic {magic:#010x} (want {:#010x}/{:#010x})",
                    kind.magic_v4, kind.magic_v5),
        ));
    }
    let hdr_len = sblock_hdr_len(is_v5);
    if blk.len() < hdr_len {
        return Err(FsError::truncated(off, hdr_len as u64, blk.len() as u64));
    }
    let crc_ok = if is_v5 && sb.has_crc() {
        let stored = u32::from_le_bytes([
            blk[SBLOCK_CRC_OFF],
            blk[SBLOCK_CRC_OFF + 1],
            blk[SBLOCK_CRC_OFF + 2],
            blk[SBLOCK_CRC_OFF + 3],
        ]);
        crc::verify(blk, SBLOCK_CRC_OFF, stored)
    } else {
        None
    };
    Ok(SBlock {
        level: u16_be(blk, 4).unwrap_or(0),
        numrecs: u16_be(blk, 6).unwrap_or(0),
        leftsib: u32_be(blk, 8).unwrap_or(NULLAGBLOCK),
        rightsib: u32_be(blk, 12).unwrap_or(NULLAGBLOCK),
        hdr_len,
        crc_ok,
    })
}

/// Collect the leaf block numbers (AG-relative) of a per-AG btree by
/// descending from `root` (level `levels`). Bounded by `MAX_BTREE_BLOCKS`
/// and `MAX_BTREE_DEPTH`; cycles are cut by a visited set.
pub(crate) fn collect_leaves(
    src: &dyn ByteSource,
    sb: &Superblock,
    agno: u32,
    root: u32,
    levels: u32,
    kind: TreeKind,
) -> Result<Vec<u32>> {
    let mut leaves = Vec::new();
    let mut visited: HashSet<u32> = HashSet::new();
    let ag_base = sb.ag_off(agno);
    let bs = sb.blocksize as usize;
    // Iterative DFS over node blocks; `levels` bounds the first descent.
    let _ = levels;
    let mut stack: Vec<u32> = vec![root];
    while let Some(agbno) = stack.pop() {
        if visited.len() >= MAX_BTREE_BLOCKS {
            return Err(FsError::corrupt(
                ag_base + agbno as u64 * sb.blocksize as u64,
                "btree block visit cap exceeded",
            ));
        }
        if agbno == NULLAGBLOCK || agbno >= sb.agblocks || !visited.insert(agbno) {
            continue;
        }
        let off = ag_base + agbno as u64 * sb.blocksize as u64;
        let blk = src.read_slice(off, bs).map_err(FsError::Io)?;
        if blk.len() < bs {
            return Err(FsError::truncated(off, bs as u64, blk.len() as u64));
        }
        let hdr = parse_sblock(&blk, off, sb, kind)?;
        let maxrecs_node = (bs - hdr.hdr_len) / (kind.key_len + kind.ptr_len);
        if hdr.level == 0 {
            leaves.push(agbno);
            continue;
        }
        if hdr.level > MAX_BTREE_DEPTH {
            return Err(FsError::corrupt(
                off + 4,
                format!("btree level {} exceeds max", hdr.level),
            ));
        }
        // numrecs must fit in the block's key/ptr capacity.
        let n = (hdr.numrecs as usize).min(maxrecs_node);
        if hdr.numrecs as usize > maxrecs_node {
            return Err(FsError::corrupt(
                off + 6,
                format!("numrecs {} exceeds node capacity {maxrecs_node}", hdr.numrecs),
            ));
        }
        let ptr_area = hdr.hdr_len + maxrecs_node * kind.key_len;
        for i in (0..n).rev() {
            if let Some(child) = u32_be(&blk, ptr_area + i * kind.ptr_len) {
                stack.push(child);
            }
        }
    }
    Ok(leaves)
}

/// Read one leaf block and hand back `(record_offset_in_block)` positions
/// — the caller decodes `kind.rec_len`-sized records at each.
///
/// Returns `(hdr, blk)` so callers can also use sibling pointers/CRC info.
pub(crate) fn read_leaf(
    src: &dyn ByteSource,
    sb: &Superblock,
    agno: u32,
    agbno: u32,
    kind: TreeKind,
) -> Result<(SBlock, Vec<u8>, u64)> {
    let off = sb.ag_off(agno) + agbno as u64 * sb.blocksize as u64;
    let blk = src
        .read_slice(off, sb.blocksize as usize)
        .map_err(FsError::Io)?;
    if blk.len() < sb.blocksize as usize {
        return Err(FsError::truncated(
            off,
            sb.blocksize as u64,
            blk.len() as u64,
        ));
    }
    let hdr = parse_sblock(&blk, off, sb, kind)?;
    if hdr.level != 0 {
        return Err(FsError::corrupt(
            off + 4,
            format!("expected leaf block, level {}", hdr.level),
        ));
    }
    Ok((hdr, blk, off))
}
