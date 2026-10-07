//! Block-map btree (bmbt) extent decoding.
//!
//! An extent record is a packed 128-bit value (two big-endian u64s):
//!
//! ```text
//! l0: [63]      flag — 1 = unwritten/preallocated extent
//! l0: [62..9]   logical file offset, 54 bits (in filesystem blocks)
//! l0: [8..0]    top 9 bits of the physical block number
//! l1: [63..21]  low 43 bits of the physical block number (fsblock)
//! l1: [20..0]   block count, 21 bits
//! ```
//!
//! `di_format == EXTENTS` forks hold `di_nextents` records inline.
//! `di_format == BTREE` forks hold an in-inode root (`xfs_bmdr_block`:
//! level u16, numrecs u16, then `maxrecs` u64 keys followed by `maxrecs`
//! u64 fsblock pointers) pointing at disk blocks with a long-form btree
//! header (magic 'BMAP' v4 / 'BMA3' v5); level-0 blocks carry the records.

use std::collections::HashSet;

use sutram_fs::{FsError, Result};
use sutram_io::le::{u16_be, u32_be, u64_be};
use sutram_io::ByteSource;

use crate::crc;
use crate::sb::{Superblock, NULLFSBLOCK};

/// bmbt leaf/node magics.
const BMAP_MAGIC_V4: u32 = 0x424D_4150; // 'BMAP'
const BMAP_MAGIC_V5: u32 = 0x424D_4133; // 'BMA3'

/// Long-form btree header lengths: 24 bytes (v4) or 72 (v5 CRC form).
const LBLOCK_LEN: usize = 24;
const LBLOCK_CRC_LEN: usize = 72;
/// crc field offset inside a long-form block (bb_u.l.bb_crc).
const LBLOCK_CRC_OFF: usize = 64;

/// Loop guards.
const MAX_BMBT_BLOCKS: usize = 1 << 20;
const MAX_BMBT_DEPTH: u16 = 10;
/// Hard cap on extents decoded for one fork.
pub(crate) const MAX_EXTENTS: usize = 1 << 22;

/// One decoded bmbt extent record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Extent {
    /// Logical file offset, in filesystem blocks.
    pub fileoff: u64,
    /// Physical filesystem block.
    pub fsb: u64,
    /// Length in filesystem blocks.
    pub len: u32,
    /// Unwritten/preallocated extent flag.
    pub unwritten: bool,
}

impl Extent {
    /// Decode one 16-byte record. Returns `None` if `b` is shorter.
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 16 {
            return None;
        }
        let l0 = u64_be(b, 0)?;
        let l1 = u64_be(b, 8)?;
        Some(Extent {
            unwritten: (l0 >> 63) != 0,
            fileoff: (l0 >> 9) & 0x003F_FFFF_FFFF_FFFF,
            fsb: ((l0 & 0x1FF) << 43) | (l1 >> 21),
            len: (l1 & 0x1F_FFFF) as u32,
        })
    }

    /// Disk byte offset of the extent start.
    pub fn disk_off(&self, sb: &Superblock) -> u64 {
        sb.fsb_off(self.fsb)
    }

    /// Byte length on disk.
    pub fn disk_len(&self, sb: &Superblock) -> u64 {
        self.len as u64 * sb.blocksize as u64
    }

    /// File byte offset this extent starts at.
    pub fn file_off_bytes(&self, sb: &Superblock) -> u64 {
        self.fileoff * sb.blocksize as u64
    }
}

/// Parse an inode's in-fork btree root header (`xfs_bmdr_block`).
/// Returns `(level, numrecs)`; `numrecs` is clamped to `maxrecs`.
fn bmdr_hdr(fork: &[u8]) -> Option<(u16, u16)> {
    let level = u16_be(fork, 0)?;
    let numrecs = u16_be(fork, 2)?;
    Some((level, numrecs))
}

/// In-inode root maxrecs: (fork bytes - 4-byte hdr) / (key 8 + ptr 8).
fn bmdr_maxrecs(fork_len: usize) -> usize {
    fork_len.saturating_sub(4) / 16
}

/// Decode `numrecs` inline extent records starting at `fork[pos]`.
fn decode_rec_table(fork: &[u8], pos: usize, numrecs: usize, out: &mut Vec<Extent>) {
    for i in 0..numrecs {
        if out.len() >= MAX_EXTENTS {
            break;
        }
        let at = pos + i * 16;
        if at + 16 > fork.len() {
            break;
        }
        if let Some(e) = Extent::decode(&fork[at..at + 16]) {
            if e.fsb != NULLFSBLOCK {
                out.push(e);
            }
        }
    }
}

/// Collect all extents from an inode fork.
///
/// `fork` is the fork's byte range inside the inode (data or attr fork).
/// `fmt` is `di_format` / `di_aformat`; `nextents` is the claimed extent
/// count for `EXTENTS` format (used as a bound, not trusted).
///
/// For `LOCAL`/`DEV`/`UUID` formats returns an empty vec — the fork
/// holds literal data, not extent records.
pub(crate) fn collect_extents(
    src: &dyn ByteSource,
    sb: &Superblock,
    fork: &[u8],
    fmt: u8,
    nextents: u64,
) -> Result<Vec<Extent>> {
    const FMT_EXTENTS: u8 = 2;
    const FMT_BTREE: u8 = 3;
    let mut out = Vec::new();
    match fmt {
        FMT_EXTENTS => {
            let cap = (fork.len() / 16).min(MAX_EXTENTS);
            let n = (nextents as usize).min(cap);
            decode_rec_table(fork, 0, n, &mut out);
        }
        FMT_BTREE => {
            walk_btree(src, sb, fork, &mut out)?;
        }
        _ => {}
    }
    Ok(out)
}

/// Walk a fork stored as `BTREE`: in-inode root + disk leaf blocks.
fn walk_btree(
    src: &dyn ByteSource,
    sb: &Superblock,
    fork: &[u8],
    out: &mut Vec<Extent>,
) -> Result<()> {
    let (level, numrecs) = bmdr_hdr(fork)
        .ok_or_else(|| FsError::corrupt(0, "truncated bmdr root"))?;
    if level > MAX_BMBT_DEPTH {
        return Err(FsError::corrupt(0, format!("bmbt depth {level} exceeds max")));
    }
    let maxrecs = bmdr_maxrecs(fork.len());
    if numrecs as usize > maxrecs {
        return Err(FsError::corrupt(
            2,
            format!("bmdr numrecs {numrecs} exceeds fork capacity {maxrecs}"),
        ));
    }
    if level == 0 {
        decode_rec_table(fork, 4, numrecs as usize, out);
        return Ok(());
    }
    // Root is a node: keys at [4, 4+8*maxrecs), ptrs follow.
    let ptr_base = 4 + maxrecs * 8;
    let mut visited: HashSet<u64> = HashSet::new();
    for i in 0..numrecs as usize {
        let fsb = u64_be(fork, ptr_base + i * 8).unwrap_or(NULLFSBLOCK);
        if fsb == NULLFSBLOCK {
            continue;
        }
        walk_btree_block(src, sb, fsb, level, &mut visited, out)?;
    }
    Ok(())
}

/// Descend one on-disk bmbt block; emits leaf records into `out`.
fn walk_btree_block(
    src: &dyn ByteSource,
    sb: &Superblock,
    fsb: u64,
    expected_level: u16,
    visited: &mut HashSet<u64>,
    out: &mut Vec<Extent>,
) -> Result<()> {
    if visited.len() >= MAX_BMBT_BLOCKS || out.len() >= MAX_EXTENTS {
        return Err(FsError::corrupt(0, "bmbt walk cap exceeded"));
    }
    if fsb == NULLFSBLOCK || fsb >= sb.dblocks || !visited.insert(fsb) {
        return Ok(());
    }
    let off = sb.fsb_off(fsb);
    let bs = sb.blocksize as usize;
    let blk = src.read_slice(off, bs).map_err(FsError::Io)?;
    if blk.len() < bs {
        return Err(FsError::truncated(off, bs as u64, blk.len() as u64));
    }
    let magic = u32_be(&blk, 0).unwrap_or(0);
    let is_v5 = magic == BMAP_MAGIC_V5;
    if magic != BMAP_MAGIC_V4 && magic != BMAP_MAGIC_V5 {
        return Err(FsError::corrupt(
            off,
            format!("bad bmbt block magic {magic:#010x}"),
        ));
    }
    let hdr_len = if is_v5 { LBLOCK_CRC_LEN } else { LBLOCK_LEN };
    let level = u16_be(&blk, 4).unwrap_or(0);
    let numrecs = u16_be(&blk, 6).unwrap_or(0);
    if level > expected_level || level > MAX_BMBT_DEPTH {
        return Err(FsError::corrupt(
            off + 4,
            format!("bmbt level {level} > expected {expected_level}"),
        ));
    }
    if is_v5 && sb.has_crc() {
        let stored = u32::from_le_bytes([
            blk[LBLOCK_CRC_OFF],
            blk[LBLOCK_CRC_OFF + 1],
            blk[LBLOCK_CRC_OFF + 2],
            blk[LBLOCK_CRC_OFF + 3],
        ]);
        if crc::verify(&blk, LBLOCK_CRC_OFF, stored) == Some(false) {
            return Err(FsError::corrupt(off, "bmbt block CRC mismatch"));
        }
    }
    if level == 0 {
        let cap = (bs - hdr_len) / 16;
        let n = (numrecs as usize).min(cap);
        if numrecs as usize > cap {
            return Err(FsError::corrupt(
                off + 6,
                format!("bmbt leaf numrecs {numrecs} exceeds capacity {cap}"),
            ));
        }
        decode_rec_table(&blk, hdr_len, n, out);
        return Ok(());
    }
    let maxrecs = (bs - hdr_len) / 16;
    let n = (numrecs as usize).min(maxrecs);
    if numrecs as usize > maxrecs {
        return Err(FsError::corrupt(
            off + 6,
            format!("bmbt node numrecs {numrecs} exceeds capacity {maxrecs}"),
        ));
    }
    let ptr_base = hdr_len + maxrecs * 8;
    for i in 0..n {
        let child = u64_be(&blk, ptr_base + i * 8).unwrap_or(NULLFSBLOCK);
        walk_btree_block(src, sb, child, level - 1, visited, out)?;
    }
    Ok(())
}
