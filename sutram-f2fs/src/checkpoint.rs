//! F2FS checkpoint pack parsing.
//!
//! Two checkpoint packs sit at `cp_blkaddr` and `cp_blkaddr + blks_per_seg`.
//! Each pack is:
//!
//! ```text
//! blk 0                          checkpoint block (+ cp_payload continuation
//! blk 1 .. 1+cp_payload          blocks holding the version bitmap tail)
//! blk 1+cp_payload .. start_sum  orphan-inode blocks
//! blk start_sum .. total-1       data/node segment summaries
//! blk total-1                    second copy of the checkpoint block
//! ```
//!
//! A pack is trustworthy when both checkpoint blocks agree on
//! `checkpoint_ver` and the CRC validates. The kernel picks the pack with the
//! highest version; we do the same, with lenient fallbacks for damaged
//! images.

use sutram_fs::{FsError, Result};
use sutram_io::le;
use sutram_io::ByteSource;

use crate::sb::{SuperBlock, F2FS_MAGIC};

/// `ckpt_flags` bits.
#[allow(dead_code)]
pub(crate) mod cp_flag {
    pub const UMOUNT: u32 = 0x0001;
    pub const ORPHAN_PRESENT: u32 = 0x0002;
    pub const COMPACT_SUM: u32 = 0x0004;
    pub const ERROR: u32 = 0x0008;
    pub const FSCK: u32 = 0x0010;
    pub const FASTBOOT: u32 = 0x0020;
    pub const CRC_RECOVERY: u32 = 0x0040;
    pub const NAT_BITS: u32 = 0x0080;
    pub const TRIMMED: u32 = 0x0100;
    pub const NOCRC_RECOVERY: u32 = 0x0200;
    pub const LARGE_NAT_BITMAP: u32 = 0x0400;
    pub const QUOTA_NEED_FSCK: u32 = 0x0800;
    pub const DISABLED: u32 = 0x1000;
    pub const DISABLED_QUICK: u32 = 0x2000;
    pub const RESIZEFS: u32 = 0x4000;
}

/// Fixed offset of `sit_nat_version_bitmap` inside the checkpoint block.
const BITMAP_OFF: usize = 192;

/// One validated checkpoint.
#[derive(Debug, Clone)]
pub(crate) struct Checkpoint {
    /// Absolute block where the winning pack starts.
    pub pack_blk: u64,
    pub checkpoint_ver: u64,
    pub user_block_count: u64,
    pub valid_block_count: u64,
    pub free_segment_count: u32,
    pub overprov_segment_count: u32,
    pub ckpt_flags: u32,
    pub cp_pack_total_block_count: u32,
    pub cp_pack_start_sum: u32,
    pub valid_node_count: u32,
    pub valid_inode_count: u32,
    pub next_free_nid: u32,
    pub elapsed_time: u64,
    /// SIT block-version bitmap (bit per SIT block index).
    pub sit_bitmap: Vec<u8>,
    /// NAT block-version bitmap (bit per NAT block index).
    pub nat_bitmap: Vec<u8>,
    /// Orphan inode numbers recorded in the pack.
    pub orphan_inos: Vec<u32>,
    /// CRC validation outcome of the winning checkpoint block.
    pub crc_ok: bool,
    /// Notes for `FsInfo::meta` (e.g. validation shortcuts taken).
    pub notes: Vec<String>,
}

/// Raw decoded first checkpoint block of a pack.
struct CpBlock {
    version: u64,
    flags: u32,
    pack_total: u32,
    pack_start_sum: u32,
    crc_ok: bool,
}

fn read_cp_block(src: &dyn ByteSource, sb: &SuperBlock, blk: u64) -> Result<CpBlock> {
    let off = sb.blk_off(blk);
    let b = src
        .read_slice(off, sb.block_size as usize)
        .map_err(FsError::Io)?;
    if (b.len() as u64) < sb.block_size {
        return Err(FsError::truncated(off, sb.block_size, b.len() as u64));
    }
    let version = le::u64(&b, 0).unwrap_or(0);
    let pack_total = le::u32(&b, 136).unwrap_or(0);
    let checksum_offset = le::u32(&b, 164).unwrap_or(0);
    let flags = le::u32(&b, 132).unwrap_or(0);

    // CRC: crc32(magic, ckpt[0..checksum_offset]); when the stored checksum
    // is not at the block tail, continue over the remaining bytes.
    let mut crc_ok = false;
    let cs = checksum_offset as usize;
    if (BITMAP_OFF..sb.block_size as usize - 4).contains(&cs) && cs + 4 <= b.len() {
        let stored = le::u32(&b, cs).unwrap_or(0);
        let mut crc = crate::crc32::f2fs_crc32(F2FS_MAGIC, &b[..cs]);
        if cs < sb.block_size as usize - 4 {
            crc = crate::crc32::crc32(crc, &b[cs + 4..]);
        }
        crc_ok = crc == stored;
    }
    Ok(CpBlock {
        version,
        flags,
        pack_total,
        pack_start_sum: le::u32(&b, 140).unwrap_or(0),
        crc_ok,
    })
}

/// A pack validates when first and last checkpoint blocks carry the same
/// version (the kernel's `validate_checkpoint`). `strict` additionally
/// requires the CRC.
fn pack_version(src: &dyn ByteSource, sb: &SuperBlock, start_blk: u64) -> Option<(u64, bool)> {
    let first = read_cp_block(src, sb, start_blk).ok()?;
    // A pack always holds ≥2 blocks: the first cp block and its trailing
    // copy at `pack_total - 1`. Zero/single-block packs are meaningless.
    if first.pack_total < 2 || first.pack_total as u64 > sb.blks_per_seg {
        return None;
    }
    let last = read_cp_block(src, sb, start_blk + first.pack_total as u64 - 1).ok()?;
    if last.version != first.version {
        return None;
    }
    Some((first.version, first.crc_ok))
}

/// Select and decode the current checkpoint pack.
pub(crate) fn read_checkpoint(src: &dyn ByteSource, sb: &SuperBlock) -> Result<Checkpoint> {
    let mut notes = Vec::new();
    let packs = [sb.cp_blkaddr, sb.cp_blkaddr + sb.blks_per_seg];
    let mut best: Option<(u64, u64, bool)> = None; // (version, pack_blk, crc_ok)
    for (i, &p) in packs.iter().enumerate() {
        if let Some((ver, crc_ok)) = pack_version(src, sb, p) {
            let better = best.is_none_or(|(bv, _, bcrc)| {
                // Prefer higher version; break ties toward valid CRC.
                ver > bv || (ver == bv && crc_ok && !bcrc)
            });
            if better {
                best = Some((ver, p, crc_ok));
            }
        } else {
            notes.push(format!("checkpoint pack {} did not validate", i + 1));
        }
    }

    // Lenient fallback: a pack whose trailing copy is gone/corrupt still
    // carries a usable first block — accept the best-looking one.
    let (pack_blk, crc_ok) = match best {
        Some((_, p, c)) => (p, c),
        None => {
            let mut cand: Option<(u64, u64, bool)> = None;
            for &p in &packs {
                if let Ok(first) = read_cp_block(src, sb, p) {
                    if first.version == 0 || first.pack_total == 0 {
                        continue;
                    }
                    if cand.is_none_or(|(v, _, _)| first.version > v) {
                        cand = Some((first.version, p, first.crc_ok));
                    }
                }
            }
            match cand {
                Some((_, p, c)) => {
                    notes.push("no checkpoint pack fully validated; using best first block".into());
                    (p, c)
                }
                None => {
                    return Err(FsError::corrupt(
                        sb.blk_off(sb.cp_blkaddr),
                        "no readable checkpoint pack",
                    ))
                }
            }
        }
    };

    // Read the whole checkpoint region (1 + cp_payload blocks).
    let first = read_cp_block(src, sb, pack_blk)?;
    let cp_payload = sb.cp_payload.min(sb.blks_per_seg as u32 - 1) as usize;
    let span = (1 + cp_payload) as u64 * sb.block_size;
    let ckpt = src
        .read_slice(sb.blk_off(pack_blk), span as usize)
        .map_err(FsError::Io)?;

    let sit_sz = le::u32(&ckpt, 156).unwrap_or(0) as usize;
    let nat_sz = le::u32(&ckpt, 160).unwrap_or(0) as usize;
    // Guard the bitmap extents against the bytes actually present.
    let avail = ckpt.len().saturating_sub(BITMAP_OFF);
    let (sit_bitmap, nat_bitmap) = if first.flags & cp_flag::LARGE_NAT_BITMAP != 0 {
        // Each bitmap is preceded by a 4-byte checksum; NAT first.
        let nat = slice(&ckpt, BITMAP_OFF + 4, nat_sz.min(avail));
        let sit = slice(&ckpt, BITMAP_OFF + 4 + nat_sz, sit_sz.min(avail));
        (sit, nat)
    } else if cp_payload > 0 {
        // NAT bitmap follows the fixed fields; SIT bitmap starts in the
        // first payload block.
        let nat = slice(&ckpt, BITMAP_OFF, nat_sz);
        let sit = slice(&ckpt, sb.block_size as usize, sit_sz);
        (sit, nat)
    } else {
        let sit = slice(&ckpt, BITMAP_OFF, sit_sz);
        let nat = slice(&ckpt, BITMAP_OFF + sit_sz, nat_sz);
        (sit, nat)
    };

    let mut cp = Checkpoint {
        pack_blk,
        checkpoint_ver: first.version,
        user_block_count: le::u64(&ckpt, 8).unwrap_or(0),
        valid_block_count: le::u64(&ckpt, 16).unwrap_or(0),
        free_segment_count: le::u32(&ckpt, 32).unwrap_or(0),
        overprov_segment_count: le::u32(&ckpt, 28).unwrap_or(0),
        ckpt_flags: first.flags,
        cp_pack_total_block_count: first.pack_total,
        cp_pack_start_sum: first.pack_start_sum,
        valid_node_count: le::u32(&ckpt, 144).unwrap_or(0),
        valid_inode_count: le::u32(&ckpt, 148).unwrap_or(0),
        next_free_nid: le::u32(&ckpt, 152).unwrap_or(0),
        elapsed_time: le::u64(&ckpt, 168).unwrap_or(0),
        sit_bitmap,
        nat_bitmap,
        orphan_inos: Vec::new(),
        crc_ok,
        notes,
    };
    cp.orphan_inos = read_orphan_blocks(src, sb, &cp)?;
    Ok(cp)
}

fn slice(b: &[u8], off: usize, len: usize) -> Vec<u8> {
    b.get(off..off.saturating_add(len)).unwrap_or(&[]).to_vec()
}

/// Orphan-inode blocks sit between the payload blocks and the data
/// summaries: pack-relative `[1 + cp_payload, cp_pack_start_sum)`.
fn read_orphan_blocks(src: &dyn ByteSource, sb: &SuperBlock, cp: &Checkpoint) -> Result<Vec<u32>> {
    if cp.ckpt_flags & cp_flag::ORPHAN_PRESENT == 0 {
        return Ok(Vec::new());
    }
    let start = cp.pack_blk + 1 + sb.cp_payload as u64;
    let count = cp.cp_pack_start_sum.saturating_sub(1 + sb.cp_payload) as usize;
    let inos_per_blk = ((sb.block_size - 16) / 4) as usize;
    let mut out = Vec::new();
    for i in 0..count {
        let off = sb.blk_off(start + i as u64);
        let b = match src.read_slice(off, sb.block_size as usize) {
            Ok(b) => b,
            Err(e) => return Err(FsError::Io(e)),
        };
        if (b.len() as u64) < sb.block_size {
            break; // truncated — emit what we have
        }
        let tail = sb.block_size as usize - 16;
        let blk_addr = le::u16(&b, tail + 4).unwrap_or(0) as usize;
        let blk_count = le::u16(&b, tail + 6).unwrap_or(0) as usize;
        // entry_count is the TOTAL orphan count across all blocks of
        // this CP, not the count stored in this block.
        let entry_count = le::u32(&b, tail + 8).unwrap_or(0) as usize;
        // Structural sanity before trusting the ino array: the block
        // index must be in range and the claimed total must fit the
        // declared number of orphan blocks.
        if blk_addr >= count || blk_count > count || entry_count > inos_per_blk * count {
            continue; // lenient: skip blocks that don't look like orphan lists
        }
        // Entries in *this* block = total minus those in earlier blocks.
        let have = entry_count
            .saturating_sub(blk_addr * inos_per_blk)
            .min(inos_per_blk);
        for j in 0..have {
            if let Some(ino) = le::u32(&b, j * 4) {
                if ino != 0 {
                    out.push(ino);
                }
            }
        }
    }
    Ok(out)
}
