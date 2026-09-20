//! `$INDEX_ROOT` / `$INDEX_ALLOCATION` (INDX) decoding.
//!
//! Directory indexes are B+-tree nodes of sorted index entries. The
//! forensically interesting part is **slack**: entries deleted from an
//! index collapse the used region, but the bytes between *used* and
//! *allocated* lengths retain stale `$FILE_NAME` copies — deleted-name
//! residue that survives in otherwise live directories.

use sutram_fs::{FsError, Result};
use sutram_io::le;

/// A decoded index header (relative offsets within the node).
#[derive(Debug, Clone, Copy)]
pub(crate) struct IndexHeader {
    /// Offset of the first entry, relative to the index header start.
    pub entries_off: usize,
    /// Used length of the index (entries end), relative to header start.
    pub used_len: usize,
    /// Allocated length of the whole node region.
    pub alloc_len: usize,
}

/// One index entry. For `$I30` indexes the `body` is a `$FILE_NAME` copy.
#[derive(Debug)]
pub(crate) struct IndexEntry {
    /// File reference of the indexed child.
    pub file_ref: u64,
    /// `file_ref`'s record-number component.
    pub record_no: u64,
    /// Raw stream bytes (the `$FILE_NAME` payload for `$I30`).
    pub body_off: usize,
    pub body_len: usize,
    /// `true` = terminator entry.
    pub is_end: bool,
    /// Offset of this entry relative to the index-header start.
    pub rel_off: usize,
}

/// Decode an index header at `data[hdr_off]`.
pub(crate) fn index_header(data: &[u8], hdr_off: usize) -> Option<IndexHeader> {
    Some(IndexHeader {
        entries_off: le::u32(data, hdr_off)? as usize,
        used_len: le::u32(data, hdr_off + 4)? as usize,
        alloc_len: le::u32(data, hdr_off + 8)? as usize,
    })
}

/// Decode `$INDEX_ROOT` resident content → (index header offset in `body`,
/// indexed attribute type). The index header sits at body+0x10.
pub(crate) fn index_root(body: &[u8]) -> Option<(usize, u32)> {
    let attr_type = le::u32(body, 0)?;
    if body.len() < 0x10 + 0x10 {
        return None;
    }
    Some((0x10, attr_type))
}

/// Parse the index entries in `data[hdr_off..]` between byte-range
/// `[start, end)` (relative to `hdr_off`). Returns entries in order,
/// stopping at the terminator entry or the first malformed entry
/// (malformed slack is normal — slack parsing is best-effort).
pub(crate) fn index_entries(
    data: &[u8],
    hdr_off: usize,
    start: usize,
    end: usize,
) -> Vec<IndexEntry> {
    let mut out = Vec::new();
    let mut pos = start;
    // Entries are ≥16 bytes, 8-aligned; cap iterations.
    let cap = data.len() / 8 + 1;
    while pos + 0x10 <= end && hdr_off + pos + 0x10 <= data.len() && out.len() < cap {
        let base = hdr_off + pos;
        let size = le::u16(data, base + 8).unwrap_or(0) as usize;
        let stream_len = le::u16(data, base + 0x0A).unwrap_or(0) as usize;
        let flags = le::u16(data, base + 0x0C).unwrap_or(0);
        if size < 0x10 || pos + size > end + 8 || base + size > data.len() {
            break;
        }
        let is_end = flags & 0x02 != 0;
        let entry = IndexEntry {
            file_ref: le::u64(data, base).unwrap_or(0),
            record_no: le::u64(data, base).unwrap_or(0) & 0x0000_FFFF_FFFF_FFFF,
            body_off: base + 0x10,
            body_len: stream_len,
            is_end,
            rel_off: pos,
        };
        pos += size;
        let done = is_end;
        out.push(entry);
        if done {
            break;
        }
    }
    out
}

/// Parse an INDX record body (fixup already applied) →
/// `(vcn, index-header-offset)`; the index header is at byte 0x18.
pub(crate) fn indx_record_header(data: &[u8], offset: u64) -> Result<(u64, usize)> {
    if data.len() < 0x28 || &data[0..4] != b"INDX" {
        return Err(FsError::corrupt(offset, "bad INDX record"));
    }
    let vcn = le::u64(data, 0x10).unwrap_or(0);
    Ok((vcn, 0x18))
}
