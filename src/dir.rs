//! XFS directory decoding.
//!
//! Supported on-disk shapes (all big-endian):
//!
//! * **shortform / local** — `xfs_dir2_sf` inside the inode data fork:
//!   `{count u8, i8count u8, parent u32|u64}` then per entry
//!   `{namelen u8, offset u16, name[], [ftype u8], ino u32|u64}`.
//!   Inode fields are 4 bytes unless `i8count != 0` (then 8 bytes).
//!   The ftype byte sits between name and inode on ftype filesystems.
//!
//! * **block / single-block** — one directory block, magic 'XD2B'
//!   (v2) or 'XDB3' (v5), entries then a leaf array and 8-byte
//!   `{count, stale}` tail at the block end.
//!
//! * **leaf / node / btree** — multi-block directories. Data blocks
//!   ('XD2D'/'XDD3') live at directory offsets < 32 GiB; leaf and
//!   freeindex blocks sit at the 32 GiB/64 GiB spaces and only accelerate
//!   lookups, so we simply scan every data-space block — which is also
//!   what a forensic tool wants (we see all residue).
//!
//! Data entries (v3): `{ino u64, namelen u8, name[], ftype u8, tag u16}`
//! where the tag repeats the entry's start offset. Freed space becomes a
//! `{freetag=0xffff u16, length u16, tag u16}` run that overwrites the
//! first 4 bytes of the old entry — the low 32 bits of the inode number
//! plus the whole name usually survive as residue, which we recover.

use sutram_fs::{FsError, Result};
use sutram_io::le::{u16_be, u32_be, u64_be};

use crate::sb::Superblock;

/// Directory block magics (u32 at offset 0 of data blocks).
pub(crate) const MAGIC_DIR2_BLOCK: u32 = 0x5844_3242; // 'XD2B'
pub(crate) const MAGIC_DIR3_BLOCK: u32 = 0x5844_4233; // 'XDB3'
pub(crate) const MAGIC_DIR2_DATA: u32 = 0x5844_3244; // 'XD2D'
pub(crate) const MAGIC_DIR3_DATA: u32 = 0x5844_4433; // 'XDD3'
#[allow(dead_code)]
pub(crate) const MAGIC_DIR2_FREE: u32 = 0x5844_3246; // 'XD2F'
#[allow(dead_code)]
pub(crate) const MAGIC_DIR3_FREE: u32 = 0x5844_4633; // 'XDF3'

/// Directory data-space limit: leaf blocks live at byte offset 1<<35 of
/// the directory address space.
pub(crate) const DIR_LEAF_OFFSET: u64 = 1 << 35;
/// Directory freeindex space offset.
#[allow(dead_code)]
pub(crate) const DIR_FREE_OFFSET: u64 = 2 << 35;

/// Freed space marker inside data blocks.
const FREE_TAG: u16 = 0xFFFF;

/// First data-entry offset inside a data/block block — the kernel's
/// `data_entry_offset` is `sizeof(xfs_dir3_data_hdr)` (56+24+4 = 84)
/// on v5, else `sizeof(xfs_dir2_data_hdr)` (4+24 = 28).
fn data_entry_offset(v3: bool) -> usize {
    if v3 {
        84
    } else {
        28
    }
}

/// Aligned size of a data entry (entries are 8-byte aligned).
fn entsize(namelen: usize, ftype: bool) -> usize {
    let raw = 9 + namelen + if ftype { 1 } else { 0 } + 2;
    (raw + 7) & !7
}

/// A decoded directory entry.
#[derive(Debug, Clone)]
pub(crate) struct RawDirent {
    /// Target inode number.
    pub ino: u64,
    /// Raw name bytes (caller sanitizes).
    pub name: Vec<u8>,
    /// XFS_DIR3_FT_* file-type byte (0 = unknown).
    pub ftype: u8,
    /// Absolute disk offset of the entry's first byte.
    pub off: u64,
    /// Recovered from a freed region rather than the live entry chain.
    #[allow(dead_code)]
    pub stale: bool,
    /// Inode number was truncated by the free-run header — only the low
    /// 32 bits survived.
    pub ino_truncated: bool,
}

/// Result of scanning one directory data block.
#[derive(Debug, Default)]
pub(crate) struct DirBlock {
    /// Live and stale entries found.
    pub entries: Vec<RawDirent>,
    /// Freed regions (offset-in-block, length) — residue candidates.
    pub unused: Vec<(u32, u32)>,
    /// True when this was a single-block directory (XD2B/XDB3).
    #[allow(dead_code)]
    pub is_block_dir: bool,
    /// The raw block bytes — retained so [`scan_residue`] can recover
    /// stale entries out of the `unused` regions.
    pub raw: Vec<u8>,
}

/// Parse a shortform (in-inode) directory.
///
/// `buf` is the data fork contents; `base` its absolute disk offset.
/// Returns `(parent_ino, entries)`.
pub(crate) fn parse_shortform(
    buf: &[u8],
    base: u64,
    sb: &Superblock,
) -> Result<(u64, Vec<RawDirent>)> {
    if buf.len() < 6 {
        return Err(FsError::truncated(base, 6, buf.len() as u64));
    }
    let count = buf[0] as usize;
    let i8count = buf[1] != 0;
    let (parent, mut pos) = if i8count {
        if buf.len() < 10 {
            return Err(FsError::truncated(base, 10, buf.len() as u64));
        }
        (u64_be(buf, 2).unwrap_or(0), 10)
    } else {
        (u32_be(buf, 2).unwrap_or(0) as u64, 6)
    };
    let ino_len = if i8count { 8 } else { 4 };
    let ftype_len = if sb.has_ftype() { 1 } else { 0 };
    let mut out = Vec::with_capacity(count.min(64));
    for _ in 0..count.min(255) {
        if pos + 3 > buf.len() {
            break;
        }
        let namelen = buf[pos] as usize;
        let need = 3 + namelen + ftype_len + ino_len;
        if pos + need > buf.len() {
            break;
        }
        let name = buf[pos + 3..pos + 3 + namelen].to_vec();
        let ftype = if sb.has_ftype() {
            buf[pos + 3 + namelen]
        } else {
            0
        };
        let ino_pos = pos + 3 + namelen + ftype_len;
        let ino = if i8count {
            u64_be(buf, ino_pos).unwrap_or(0) & 0x3FFF_FFFF_FFFF_FFFF
        } else {
            u32_be(buf, ino_pos).unwrap_or(0) as u64
        };
        out.push(RawDirent {
            ino,
            name,
            ftype,
            off: base + pos as u64,
            stale: false,
            ino_truncated: false,
        });
        pos += need;
    }
    Ok((parent, out))
}

/// Parse one directory data block (`buf` is `dirbsize` bytes).
///
/// `base` is the block's absolute disk offset. Iterates the entry chain
/// from `data_entry_offset` to the data end, collecting live entries and
/// freed regions. Residue inside freed runs is decoded separately by
/// [`scan_residue`].
pub(crate) fn parse_data_block(
    buf: &[u8],
    base: u64,
    sb: &Superblock,
) -> Result<DirBlock> {
    if buf.len() < 24 {
        return Err(FsError::truncated(base, 24, buf.len() as u64));
    }
    let magic = u32_be(buf, 0).unwrap_or(0);
    let v3 = matches!(magic, MAGIC_DIR3_BLOCK | MAGIC_DIR3_DATA);
    let is_block = matches!(magic, MAGIC_DIR2_BLOCK | MAGIC_DIR3_BLOCK);
    if !is_block && !matches!(magic, MAGIC_DIR2_DATA | MAGIC_DIR3_DATA) {
        return Err(FsError::corrupt(
            base,
            format!("bad dir block magic {magic:#010x}"),
        ));
    }
    let blksize = buf.len();
    let mut end = blksize;
    if is_block {
        // Last 8 bytes: {count u32, stale u32}; leaf entries precede it.
        if blksize < 8 {
            return Err(FsError::truncated(base, 8, blksize as u64));
        }
        let count = u32_be(buf, blksize - 8).unwrap_or(0) as usize;
        let leaf_bytes = count.saturating_mul(8);
        if leaf_bytes > blksize - 8 {
            return Err(FsError::corrupt(
                base + blksize as u64 - 8,
                format!("block dir leaf count {count} exceeds block"),
            ));
        }
        end = blksize - 8 - leaf_bytes;
    }
    let mut out = DirBlock {
        is_block_dir: is_block,
        raw: buf.to_vec(),
        ..DirBlock::default()
    };
    let ftype = sb.has_ftype();
    let mut off = data_entry_offset(v3);
    // Bound iterations: min entry is 8 bytes.
    let mut steps = 0usize;
    while off + 8 <= end && steps < blksize / 8 {
        steps += 1;
        let tag = u16_be(buf, off).unwrap_or(0);
        if tag == FREE_TAG {
            let len = u16_be(buf, off + 2).unwrap_or(0) as usize;
            if len < 8 || off + len > end {
                return Err(FsError::corrupt(
                    base + off as u64,
                    format!("bad dir free run length {len}"),
                ));
            }
            // The run's own tag should point back at its start.
            let back = u16_be(buf, off + len - 2).unwrap_or(0) as usize;
            if back != off {
                return Err(FsError::corrupt(
                    base + off as u64 + len as u64 - 2,
                    "dir free run tag mismatch",
                ));
            }
            out.unused.push((off as u32, len as u32));
            off += len;
            continue;
        }
        let ino = u64_be(buf, off).unwrap_or(0);
        let namelen = buf[off + 8] as usize;
        let esize = entsize(namelen, ftype);
        if namelen == 0 || off + esize > end {
            return Err(FsError::corrupt(
                base + off as u64,
                format!("bad dir entry namelen {namelen}"),
            ));
        }
        // Entry tag must repeat the entry offset.
        let etag = u16_be(buf, off + esize - 2).unwrap_or(0) as usize;
        if etag != off {
            return Err(FsError::corrupt(
                base + off as u64 + esize as u64 - 2,
                "dir entry tag mismatch",
            ));
        }
        let name = buf[off + 9..off + 9 + namelen].to_vec();
        let ft = if ftype { buf[off + 9 + namelen] } else { 0 };
        out.entries.push(RawDirent {
            ino,
            name,
            ftype: ft,
            off: base + off as u64,
            stale: false,
            ino_truncated: false,
        });
        off += esize;
    }
    Ok(out)
}

/// Scan a freed region of a directory block for stale entry residue.
///
/// When XFS deletes an entry the kernel writes `{freetag, length}` over
/// the first 4 bytes (destroying the high 32 bits of the inode number)
/// and a tag at the end. The surviving layout is therefore:
///
/// ```text
/// run+4   low 32 bits of the old inode number
/// run+8   namelen u8
/// run+9   name[namelen]
/// ...     ftype u8, (tag overwritten by the run tag)
/// ```
///
/// If a run covers several merged entries, entries past the first are
/// fully intact — we re-scan the run at 8-byte alignment for entries
/// whose tag still points back at their own offset.
pub(crate) fn scan_residue(
    buf: &[u8],
    run: (u32, u32),
    base: u64,
    sb: &Superblock,
) -> Vec<RawDirent> {
    let (start, len) = (run.0 as usize, run.1 as usize);
    let end = start.saturating_add(len).min(buf.len());
    let ftype = sb.has_ftype();
    let mut out = Vec::new();
    if end.saturating_sub(start) < 16 {
        return out;
    }

    // Candidate 1: the truncated first entry of the run.
    if let Some(e) = decode_truncated_entry(buf, start, end, base, ftype) {
        out.push(e);
    }

    // Candidate 2+: intact entries merged into the free run. Require the
    // entry tag to confirm — this is deliberately strict to avoid
    // hallucinating names out of arbitrary residue.
    let mut off = start + 8;
    while off + 16 <= end {
        if let Some(e) = decode_intact_entry(buf, off, end, base, sb, ftype) {
            out.push(e);
        }
        off += 8;
    }
    out
}

/// Decode the partially-overwritten entry at the head of a free run.
fn decode_truncated_entry(
    buf: &[u8],
    start: usize,
    run_end: usize,
    base: u64,
    ftype: bool,
) -> Option<RawDirent> {
    // bytes [0..4) of the entry are destroyed (freetag+length).
    let ino_lo = u32_be(buf, start + 4)?;
    if ino_lo == 0 {
        return None;
    }
    let namelen = *buf.get(start + 8)? as usize;
    if namelen == 0 || namelen > 255 {
        return None;
    }
    let esize = entsize(namelen, ftype);
    if start + esize > run_end {
        return None;
    }
    let name = &buf[start + 9..start + 9 + namelen];
    if !plausible_name(name) {
        return None;
    }
    let ft = if ftype {
        buf.get(start + 9 + namelen).copied().unwrap_or(0)
    } else {
        0
    };
    Some(RawDirent {
        // High 32 bits of the inode number are unrecoverable; low bits
        // usually suffice on typical filesystems (inos < 2^32).
        ino: ino_lo as u64,
        name: name.to_vec(),
        ftype: ft,
        off: base + start as u64,
        stale: true,
        ino_truncated: true,
    })
}

/// Decode a fully-intact stale entry embedded in a free run.
fn decode_intact_entry(
    buf: &[u8],
    off: usize,
    run_end: usize,
    base: u64,
    sb: &Superblock,
    ftype: bool,
) -> Option<RawDirent> {
    if u16_be(buf, off)? == FREE_TAG {
        return None;
    }
    let ino = u64_be(buf, off)?;
    if !sb.ino_valid(ino) {
        return None;
    }
    let namelen = *buf.get(off + 8)? as usize;
    if namelen == 0 {
        return None;
    }
    let esize = entsize(namelen, ftype);
    if off + esize > run_end {
        return None;
    }
    // The tag must point back at the entry start — strong confidence.
    if u16_be(buf, off + esize - 2)? as usize != off {
        return None;
    }
    let name = &buf[off + 9..off + 9 + namelen];
    if !plausible_name(name) {
        return None;
    }
    let ft = if ftype { buf[off + 9 + namelen] } else { 0 };
    Some(RawDirent {
        ino,
        name: name.to_vec(),
        ftype: ft,
        off: base + off as u64,
        stale: true,
        ino_truncated: false,
    })
}

/// Loose name plausibility for residue recovery: no NUL or '/', and no
/// C0 control bytes (names may carry arbitrary high bytes/UTF-8).
fn plausible_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .all(|&b| b != b'/' && b >= 0x20 && b != 0x7F)
}
