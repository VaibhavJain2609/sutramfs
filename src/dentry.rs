//! Directory-entry (dentry) block decoding.
//!
//! A dentry block packs, inside one filesystem block:
//!
//! ```text
//! dentry_bitmap[ceil(nr/8)]   — one bit per *used* slot (incl. name
//! reserved[]                    continuation slots of multi-slot names)
//! dentry[nr]   (11 B each)    — {hash_code u32, ino u32, name_len u16,
//!                                file_type u8}
//! filename[nr][8]             — the name bytes, 8 B per slot
//! ```
//!
//! `nr` = `blksize * 8 / ((11 + 8) * 8 + 1)` — 214 slots for 4 KiB blocks.
//! Each name occupies `ceil(name_len / 8)` consecutive slots.
//!
//! Forensic note: deleting a dentry only clears its bitmap bits — the
//! `f2fs_dir_entry` and filename bytes usually survive until the block is
//! rewritten. Slots with a *clear* bitmap bit but a plausible stale dentry
//! are emitted as deleted-name residue.

use sutram_fs::{FsError, Result};
use sutram_io::le;

use crate::tables::bit_le;

/// One decoded dentry slot.
#[derive(Debug, Clone)]
pub(crate) struct Dentry {
    /// Slot index within the block.
    pub slot: u16,
    /// `hash_code` (meaningless for encrypted dirs).
    pub hash: u32,
    /// Target inode number (== nid).
    pub ino: u32,
    /// Raw name bytes.
    pub name: Vec<u8>,
    /// `file_type` (`FT_*` shared numbering).
    pub file_type: u8,
    /// `true` = bitmap-marked live entry; `false` = residue.
    pub live: bool,
    /// Byte offset of the `f2fs_dir_entry` inside the block (provenance).
    pub rec_off: u64,
}

/// Layout of a dentry-bearing region (a full block, or an inline-dentry
/// region inside an inode's `i_addr` area).
#[derive(Debug, Clone, Copy)]
pub(crate) struct DentryLayout {
    pub nr_slots: usize,
    pub bitmap_len: usize,
    pub dentry_off: usize,
    pub filename_off: usize,
}

impl DentryLayout {
    /// Layout for a region of `len` bytes (the full block for regular
    /// dentry blocks; the inline region for inline dentries).
    pub fn for_len(len: usize) -> Option<DentryLayout> {
        // NR_DENTRY_IN_BLOCK = BITS*len / ((11+8)*BITS + 1)
        let nr = len * 8 / (19 * 8 + 1);
        if nr < 2 {
            return None;
        }
        let bitmap_len = nr.div_ceil(8);
        let dentry_off = bitmap_len + (len - (19 * nr + bitmap_len));
        let filename_off = dentry_off + 11 * nr;
        if filename_off + 8 * nr > len {
            return None;
        }
        Some(DentryLayout {
            nr_slots: nr,
            bitmap_len,
            dentry_off,
            filename_off,
        })
    }
}

/// Hard cap on slots we accept per region (bounded-memory guard).
const MAX_SLOTS: usize = 4096;

/// Parse a dentry-bearing region into live entries and residue.
///
/// `max_nid` bounds acceptable inode numbers for residue plausibility.
/// Returns `(dentries, errors)` — errors are non-fatal notes the caller
/// may surface as `Err` walk items.
pub(crate) fn parse_dentries(
    b: &[u8],
    region_off: usize,
    region_len: usize,
    max_nid: u64,
) -> Result<(Vec<Dentry>, Vec<String>)> {
    let region = b
        .get(region_off..region_off + region_len)
        .ok_or_else(|| FsError::corrupt(0, "dentry region out of bounds"))?;
    let layout = DentryLayout::for_len(region_len)
        .ok_or_else(|| FsError::corrupt(0, "dentry region too small"))?;
    if layout.nr_slots > MAX_SLOTS {
        return Err(FsError::corrupt(0, "implausible dentry slot count"));
    }
    let mut out = Vec::new();
    let mut errs = Vec::new();
    let mut i = 0usize;
    while i < layout.nr_slots {
        let marked = bit_le(&region[..layout.bitmap_len], i as u64);
        let de_off = layout.dentry_off + i * 11;
        let hash = le::u32(region, de_off).unwrap_or(0);
        let ino = le::u32(region, de_off + 4).unwrap_or(0);
        let name_len = le::u16(region, de_off + 8).unwrap_or(0) as usize;
        let file_type = region[de_off + 10];
        let slots = name_len.div_ceil(8).max(1);
        let plausible = (1..=255).contains(&name_len)
            && ino != 0
            && ino as u64 <= max_nid
            && i + slots <= layout.nr_slots;
        if marked {
            if plausible {
                let name = read_name(region, &layout, i, name_len);
                out.push(Dentry {
                    slot: i as u16,
                    hash,
                    ino,
                    name,
                    file_type,
                    live: true,
                    rec_off: (region_off + de_off) as u64,
                });
                i += slots;
                continue;
            }
            // Set bit but insane dentry — corruption; step one slot.
            errs.push(format!(
                "insane dentry at slot {i} (name_len {name_len}, ino {ino})"
            ));
            i += 1;
            continue;
        }
        // Residue: clear bit, stale-looking entry. Require a plausible
        // dentry *and* a nonzero first name byte to cut false positives.
        if plausible && name_byte(region, &layout, i) != 0 {
            let name = read_name(region, &layout, i, name_len);
            out.push(Dentry {
                slot: i as u16,
                hash,
                ino,
                name,
                file_type,
                live: false,
                rec_off: (region_off + de_off) as u64,
            });
            i += slots;
            continue;
        }
        i += 1;
    }
    Ok((out, errs))
}

/// First byte of a slot's filename area.
fn name_byte(region: &[u8], layout: &DentryLayout, slot: usize) -> u8 {
    region
        .get(layout.filename_off + slot * 8)
        .copied()
        .unwrap_or(0)
}

/// Read `name_len` bytes across `ceil(len/8)` filename slots.
fn read_name(region: &[u8], layout: &DentryLayout, slot: usize, name_len: usize) -> Vec<u8> {
    let mut name = Vec::with_capacity(name_len);
    let slots = name_len.div_ceil(8);
    for s in 0..slots {
        let off = layout.filename_off + (slot + s) * 8;
        let chunk = region.get(off..off + 8).unwrap_or(&[]);
        name.extend_from_slice(chunk);
    }
    name.truncate(name_len);
    name
}

/// Quick plausibility check used when scanning stale blocks: does this
/// block look like a dentry block? Requires ≥1 bitmap-marked slot whose
/// dentry decodes sanely, and no insane marked slot in the first scan.
pub(crate) fn looks_like_dentry_block(b: &[u8], max_nid: u64) -> bool {
    let Some(layout) = DentryLayout::for_len(b.len()) else {
        return false;
    };
    let mut sane = 0usize;
    let mut checked = 0usize;
    for i in 0..layout.nr_slots.min(64) {
        if !bit_le(&b[..layout.bitmap_len], i as u64) {
            continue;
        }
        checked += 1;
        let de_off = layout.dentry_off + i * 11;
        let ino = le::u32(b, de_off + 4).unwrap_or(0);
        let name_len = le::u16(b, de_off + 8).unwrap_or(0) as usize;
        if (1..=255).contains(&name_len) && ino != 0 && ino as u64 <= max_nid {
            sane += 1;
        }
    }
    checked > 0 && sane == checked
}
