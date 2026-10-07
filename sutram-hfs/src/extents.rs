//! Extents-overflow-file records: keys `(forkType, fileID, startBlock)` and
//! 8-descriptor extent records — the overflow spillway for fragmented files.
//!
//! Forensically interesting: records whose `fileID` no longer has a catalog
//! record point at **orphaned extents** — allocated-but-ownerless data.

use sutram_io::le;

use crate::vh::Extent;

/// `forkType` for the data fork in an extents-overflow key.
pub(crate) const FORK_DATA: u8 = 0x00;
/// `forkType` for the resource fork.
pub(crate) const FORK_RSRC: u8 = 0xFF;

/// Decoded extents-overflow key (`key_len` = 10).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExtKey {
    pub fork: u8,
    pub cnid: u32,
    /// First logical allocation block covered by this record.
    pub start_block: u32,
}

/// Parse an extents-overflow record key. `rec` starts at the `key_len` field.
pub(crate) fn parse_key(rec: &[u8]) -> Option<(ExtKey, usize)> {
    let key_len = le::u16_be(rec, 0)? as usize;
    if key_len != 10 || rec.len() < 12 {
        return None;
    }
    Some((
        ExtKey {
            fork: rec.get(2).copied()?,
            cnid: le::u32_be(rec, 4)?,
            start_block: le::u32_be(rec, 8)?,
        },
        12, // key_len field + key
    ))
}

/// Parse the record data: 8 extent descriptors (64 bytes).
pub(crate) fn parse_record(data: &[u8]) -> Option<[Extent; 8]> {
    if data.len() < 64 {
        return None;
    }
    let mut out = [Extent::default(); 8];
    for (i, e) in out.iter_mut().enumerate() {
        e.start = le::u32_be(data, i * 8)?;
        e.count = le::u32_be(data, i * 8 + 4)?;
    }
    Some(out)
}
