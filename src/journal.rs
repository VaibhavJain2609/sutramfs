//! jbd2 journal awareness.
//!
//! The journal is inode 8 (`s_journal_inum`). Its first block is the
//! **jbd2 superblock** — the only jbd2 structure stored *big-endian*:
//!
//! ```text
//! 0x00 h_magic    be32 = 0xC03B3998
//! 0x04 h_blocktype be32 (3 = superblock v1, 4 = superblock v2)
//! 0x08 h_sequence be32
//! 0x0C s_blocksize be32    0x10 s_maxlen be32 (journal blocks)
//! 0x14 s_first be32        0x18 s_sequence be32
//! 0x1C s_start be32        (0 ⇒ journal clean, no replay pending)
//! ```
//!
//! **TODO / documented limitation** — transaction replay is *not*
//! implemented. A full journal-based recovery pass would, inside the
//! `s_start..s_maxlen` circular region:
//!
//! - walk descriptor blocks (`h_blocktype` = 1): each `journal_block_tag`
//!   maps a journal block to a filesystem block — replaying them
//!   reconstructs recently-modified metadata (inode tables, dirents,
//!   bitmaps) that never reached the disk, which is the richest deleted-
//!   file source ext4 offers;
//! - honour revoke blocks (`h_blocktype` = 5) which cancel replays;
//! - stop at commit blocks (`h_blocktype` = 2) bounding each transaction;
//! - ignore incomplete tail transactions (no commit record = never
//!   happened, per jbd2 semantics).
//!
//! The superblock summary is parsed and surfaced via `FsInfo.meta` so an
//! examiner at least learns whether a replay-worthy journal exists
//! (`s_start != 0`).

use sutram_io::{le, ByteSource};

/// jbd2 superblock magic, stored big-endian.
const JBD2_MAGIC: u32 = 0xC03B_3998;

/// Decoded journal superblock (v2 layout; v1 lacks the tail fields).
#[derive(Debug, Clone)]
pub(crate) struct JournalInfo {
    /// jbd2 block size (may differ from fs block size).
    pub block_size: u32,
    /// Journal length in jbd2 blocks.
    pub maxlen: u32,
    /// Block where the log circularly begins.
    pub first: u32,
    /// Next transaction sequence number.
    pub sequence: u32,
    /// First valid log block; `0` = clean journal (nothing to replay).
    pub start: u32,
    /// Number of filesystems sharing this journal (normally 1).
    pub nr_users: u32,
    /// Absolute offset of the journal superblock (provenance).
    pub disk_offset: u64,
}

impl JournalInfo {
    /// Parse the journal superblock at `off`. `s_nr_users` lives at 0x40,
    /// so the probe window must cover at least 0x44 bytes.
    pub fn parse(src: &dyn ByteSource, off: u64) -> Option<JournalInfo> {
        let b = src.read_slice(off, 128).ok()?;
        if b.len() < 64 {
            return None;
        }
        if le::u32_be(&b, 0x00) != Some(JBD2_MAGIC) {
            return None;
        }
        let blocktype = le::u32_be(&b, 0x04).unwrap_or(0);
        if !(3..=4).contains(&blocktype) {
            return None; // not a superblock descriptor
        }
        Some(JournalInfo {
            block_size: le::u32_be(&b, 0x0C).unwrap_or(0),
            maxlen: le::u32_be(&b, 0x10).unwrap_or(0),
            first: le::u32_be(&b, 0x14).unwrap_or(0),
            sequence: le::u32_be(&b, 0x18).unwrap_or(0),
            start: le::u32_be(&b, 0x1C).unwrap_or(0),
            nr_users: le::u32_be(&b, 0x40).unwrap_or(1),
            disk_offset: off,
        })
    }
}
