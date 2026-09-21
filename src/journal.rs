//! jbd2 journal forensics.
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
//! 0x24 s_feature_compat    0x28 s_feature_incompat (v2)
//! 0x40 s_nr_users
//! ```
//!
//! The circular log region (`s_first..s_maxlen`) holds transactions:
//! descriptor blocks (type 1) carrying `journal_block_tag` entries that
//! map each journaled data block to its filesystem destination, commit
//! blocks (type 2) sealing each transaction, and revocation blocks
//! (type 5) cancelling earlier replays. Blocks without the jbd2 magic
//! are journaled data copies.
//!
//! This module **parses** the log into [`JournalEvent`]s — it does not
//! replay it. Each journaled copy is prior-state evidence: a descriptor
//! tag pointing at an inode-table block, a bitmap, or a block the
//! filesystem has since freed is a recoverable snapshot of metadata as
//! it was when the transaction committed. [`JournalTag::prior_state`]
//! marks exactly those candidates. Replay itself (applying copies to
//! their final blocks, honouring revokes and incomplete-tail discard)
//! remains a documented TODO.
//!
//! The superblock summary is parsed and surfaced via `FsInfo.meta` so an
//! examiner learns whether a replay-worthy journal exists
//! (`s_start != 0`); bounded event counts are summarised alongside it.

use std::collections::VecDeque;
use std::sync::Arc;

use sutram_fs::{FsError, Result};
use sutram_io::{le, ByteSource};

/// jbd2 superblock magic, stored big-endian.
const JBD2_MAGIC: u32 = 0xC03B_3998;

// h_blocktype values.
const BLOCK_DESCRIPTOR: u32 = 1;
const BLOCK_COMMIT: u32 = 2;
const BLOCK_SUPER_V1: u32 = 3;
const BLOCK_SUPER_V2: u32 = 4;
const BLOCK_REVOKE: u32 = 5;
const BLOCK_FAST_COMMIT: u32 = 6;

// s_feature_incompat bits (journal superblock v2).
const INCOMPAT_REVOKE: u32 = 0x01;
const INCOMPAT_64BIT: u32 = 0x02;
const INCOMPAT_ASYNC_COMMIT: u32 = 0x04;
const INCOMPAT_CSUM_V2: u32 = 0x08;
const INCOMPAT_CSUM_V3: u32 = 0x10;
const INCOMPAT_FAST_COMMIT: u32 = 0x20;

// journal_block_tag t_flags bits.
const TAG_ESCAPE: u32 = 0x1;
const TAG_SAME_UUID: u32 = 0x2;
const TAG_DELETED: u32 = 0x4;
const TAG_LAST: u32 = 0x8;

/// Bound on the journal-block summary scan run for `FsInfo.meta` counts
/// (65536 blocks ≈ 256 MiB at 4 KiB). Larger journals still stream fully
/// through [`Ext4Fs::journal_events`](crate::Ext4Fs::journal_events) —
/// only the summary is capped.
pub(crate) const MAX_SUMMARY_BLOCKS: u64 = 1 << 16;

/// Hard cap on block numbers decoded from one revocation block.
const MAX_REVOKE_BLOCKS: usize = 4096;

/// Decoded journal superblock (v2 layout; v1 lacks the tail fields).
#[derive(Debug, Clone)]
pub(crate) struct JournalInfo {
    /// jbd2 superblock version (3 = v1, 4 = v2).
    pub version: u32,
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
    /// `s_feature_compat` / `s_feature_incompat` (v2 only; 0 on v1).
    pub feature_compat: u32,
    pub feature_incompat: u32,
    /// Absolute offset of the journal superblock (provenance).
    pub disk_offset: u64,
    /// Absolute byte ranges holding the journal file's contents, in
    /// journal-file order — resolves journal block `i` to disk.
    pub ranges: Vec<(u64, u64)>,
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
            version: blocktype - 2, // 3→1, 4→2
            block_size: le::u32_be(&b, 0x0C).unwrap_or(0),
            maxlen: le::u32_be(&b, 0x10).unwrap_or(0),
            first: le::u32_be(&b, 0x14).unwrap_or(0),
            sequence: le::u32_be(&b, 0x18).unwrap_or(0),
            start: le::u32_be(&b, 0x1C).unwrap_or(0),
            nr_users: le::u32_be(&b, 0x40).unwrap_or(1),
            feature_compat: le::u32_be(&b, 0x24).unwrap_or(0),
            feature_incompat: le::u32_be(&b, 0x28).unwrap_or(0),
            disk_offset: off,
            ranges: Vec::new(),
        })
    }

    /// On-disk `journal_block_tag` size per the advertised features:
    /// 8 bytes normally, 12 with 64-bit block numbers, 16 with csum v3.
    pub(crate) fn tag_size(&self) -> usize {
        if self.feature_incompat & INCOMPAT_CSUM_V3 != 0 {
            16
        } else if self.feature_incompat & INCOMPAT_64BIT != 0 {
            12
        } else {
            8
        }
    }

    /// Absolute disk offset of journal block `i` (0-based within the
    /// journal file), or `None` when the file's extents don't reach it.
    pub(crate) fn block_offset(&self, i: u64) -> Option<u64> {
        let want = i.checked_mul(self.block_size as u64)?;
        let mut acc = 0u64;
        for &(disk, len) in &self.ranges {
            if want < acc.saturating_add(len) {
                return Some(disk + (want - acc));
            }
            acc = acc.saturating_add(len);
        }
        None
    }

    /// Human-readable names of the advertised incompat features (for
    /// `FsInfo.meta`).
    pub(crate) fn feature_names(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        for (bit, name) in [
            (INCOMPAT_REVOKE, "revoke"),
            (INCOMPAT_64BIT, "64bit"),
            (INCOMPAT_ASYNC_COMMIT, "async_commit"),
            (INCOMPAT_CSUM_V2, "csum_v2"),
            (INCOMPAT_CSUM_V3, "csum_v3"),
            (INCOMPAT_FAST_COMMIT, "fast_commit"),
        ] {
            if self.feature_incompat & bit != 0 {
                v.push(name);
            }
        }
        v
    }
}

/// What a journaled tag's target filesystem block is used for —
/// classifies whether the journaled copy is prior *metadata* state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalTarget {
    /// Ordinary data or unrecognized metadata block.
    Data,
    /// Primary or backup superblock.
    Superblock,
    /// Group descriptor table block.
    Gdt,
    /// Group block-allocation bitmap.
    BlockBitmap(u32),
    /// Group inode-allocation bitmap.
    InodeBitmap(u32),
    /// Group inode-table block.
    InodeTable(u32),
    /// Target lies past `s_blocks_count` — off-volume.
    OutOfVolume,
}

impl JournalTarget {
    /// Machine-readable name for meta values.
    pub fn name(&self) -> String {
        match self {
            JournalTarget::Data => "data".into(),
            JournalTarget::Superblock => "superblock".into(),
            JournalTarget::Gdt => "gdt".into(),
            JournalTarget::BlockBitmap(g) => format!("block_bitmap_g{g}"),
            JournalTarget::InodeBitmap(g) => format!("inode_bitmap_g{g}"),
            JournalTarget::InodeTable(g) => format!("inode_table_g{g}"),
            JournalTarget::OutOfVolume => "out_of_volume".into(),
        }
    }
}

/// Metadata-block layout used to classify tag targets: which fs blocks
/// hold inode tables, bitmaps, the GDT and superblock copies.
#[derive(Debug, Default)]
pub(crate) struct MetaLayout {
    /// `s_blocks_count` — targets at/past it are off-volume.
    pub blocks_count: u64,
    /// Primary superblock block (0 or 1).
    pub superblock: u64,
    /// Blocks holding backup superblock copies.
    pub backups: Vec<u64>,
    /// `[start, end)` blocks of the primary GDT.
    pub gdt: (u64, u64),
    /// `(group, block_bitmap, inode_bitmap, table_start, table_end)`.
    pub tables: Vec<(u32, u64, u64, u64, u64)>,
}

impl MetaLayout {
    pub(crate) fn classify(&self, fs_block: u64) -> JournalTarget {
        if fs_block >= self.blocks_count {
            return JournalTarget::OutOfVolume;
        }
        if fs_block == self.superblock || self.backups.contains(&fs_block) {
            return JournalTarget::Superblock;
        }
        if fs_block >= self.gdt.0 && fs_block < self.gdt.1 {
            return JournalTarget::Gdt;
        }
        for &(g, bbm, ibm, tstart, tend) in &self.tables {
            if fs_block == bbm {
                return JournalTarget::BlockBitmap(g);
            }
            if fs_block == ibm {
                return JournalTarget::InodeBitmap(g);
            }
            if fs_block >= tstart && fs_block < tend {
                return JournalTarget::InodeTable(g);
            }
        }
        JournalTarget::Data
    }
}

/// One `journal_block_tag` plus where its journaled copy landed.
#[derive(Debug, Clone)]
pub struct JournalTag {
    /// Filesystem block the journaled copy belongs to.
    pub fs_block: u64,
    /// Raw `t_flags` value (`TAG_*` bits).
    pub flags: u32,
    /// The copy's first word matched jbd2 magic and was zeroed on disk
    /// (the original word trails the tag in the descriptor block).
    pub escaped: bool,
    /// The transaction marked this filesystem block deleted.
    pub deleted: bool,
    /// A 16-byte journal UUID followed the tag (absent ⇒ SAME_UUID).
    pub uuid_present: bool,
    /// Absolute offset of the journaled copy, when the journal file's
    /// extents reach it.
    pub data_offset: Option<u64>,
    /// What the target filesystem block is used for today.
    pub target: JournalTarget,
    /// Whether the target block is currently allocated (`None` = the
    /// bitmap could not be consulted).
    pub target_allocated: Option<bool>,
    /// Absolute offset of this tag inside the descriptor block
    /// (provenance for the emitted record).
    pub tag_offset: u64,
}

impl JournalTag {
    /// `true` when this tag is evidence of a prior metadata state: the
    /// copy targets live metadata structures (inode tables, bitmaps,
    /// the GDT, a superblock) or a block the filesystem has freed since.
    pub fn prior_state(&self) -> bool {
        match self.target {
            JournalTarget::Superblock
            | JournalTarget::Gdt
            | JournalTarget::BlockBitmap(_)
            | JournalTarget::InodeBitmap(_)
            | JournalTarget::InodeTable(_) => true,
            _ => self.target_allocated == Some(false),
        }
    }
}

/// What one journal block turned out to be.
#[derive(Debug, Clone)]
pub enum JournalEventKind {
    /// A journal superblock (v1 or v2 dynamic copy).
    Superblock { version: u32 },
    /// A descriptor block; `tags` counts the block tags it carried.
    Descriptor { tags: usize },
    /// A commit block sealing transaction `transid`.
    Commit { sec: u64, nsec: u32 },
    /// A revocation block; `blocks` are the rescinded fs block numbers.
    Revoke { blocks: Vec<u64> },
    /// A fast-commit block (TLV log — not decoded).
    FastCommit,
    /// A recognised jbd2 header with an unknown type.
    Unknown { blocktype: u32 },
    /// A journaled copy of a filesystem block (tag + following data).
    JournaledBlock(JournalTag),
}

/// One journal structure — a parsed record of what the log holds.
#[derive(Debug, Clone)]
pub struct JournalEvent {
    /// `h_sequence` — the transaction this block belongs to.
    pub transid: u32,
    /// Index of the journal block inside the journal file.
    pub journal_block: u64,
    /// Absolute offset of the journal block on the source.
    pub disk_offset: u64,
    /// The parsed block contents.
    pub kind: JournalEventKind,
}

/// Decode one `journal_block_tag` at `pos` inside a descriptor `block`.
/// Returns `(tag, bytes consumed including any uuid and escape word)`,
/// or `None` when the tag would run past the block end.
fn tag_at(block: &[u8], pos: usize, tag_size: usize, is64: bool) -> Option<(JournalTag, usize)> {
    let t = le::get(block, pos, tag_size)?;
    let fs_block = le::u32_be(t, 0).unwrap_or(0) as u64
        | if is64 && tag_size >= 12 {
            (le::u32_be(t, 8).unwrap_or(0) as u64) << 32
        } else {
            0
        };
    let flags = le::u32_be(t, 4).unwrap_or(0);
    let mut used = tag_size;
    let uuid_present = flags & TAG_SAME_UUID == 0;
    if uuid_present {
        le::get(block, pos + used, 16)?;
        used += 16;
    }
    if flags & TAG_ESCAPE != 0 {
        le::get(block, pos + used, 4)?;
        used += 4;
    }
    Some((
        JournalTag {
            fs_block,
            flags,
            escaped: flags & TAG_ESCAPE != 0,
            deleted: flags & TAG_DELETED != 0,
            uuid_present,
            data_offset: None,
            target: JournalTarget::Data,
            target_allocated: None,
            tag_offset: 0,
        },
        used,
    ))
}

/// Streaming parse of the journal log region. One journal block is read
/// at a time; descriptor blocks queue their tag events. `Err` items mark
/// corrupt structures; scanning resynchronises at the next block. In
/// strict mode the first error ends the stream.
pub(crate) struct JournalScan<'m> {
    src: Arc<dyn ByteSource>,
    info: &'m JournalInfo,
    layout: MetaLayout,
    /// fs-block → allocated lookup (bitmap); `None` when unreadable.
    allocated: Box<dyn Fn(u64) -> Option<bool> + Send + Sync + 'm>,
    /// Next journal block index to inspect.
    idx: u64,
    pending: VecDeque<Result<JournalEvent>>,
    finished: bool,
    strict: bool,
}

impl<'m> JournalScan<'m> {
    pub(crate) fn new(
        src: Arc<dyn ByteSource>,
        info: &'m JournalInfo,
        layout: MetaLayout,
        allocated: Box<dyn Fn(u64) -> Option<bool> + Send + Sync + 'm>,
        strict: bool,
    ) -> Self {
        let mut pending = VecDeque::new();
        // The journal superblock itself is the first artefact.
        if let Some(off) = info.block_offset(0) {
            pending.push_back(Ok(JournalEvent {
                transid: info.sequence,
                journal_block: 0,
                disk_offset: off,
                kind: JournalEventKind::Superblock { version: info.version },
            }));
        }
        JournalScan {
            src,
            info,
            layout,
            allocated,
            idx: info.first.max(1) as u64,
            pending,
            finished: false,
            strict,
        }
    }

    /// Emit an error honouring strict mode: strict drops the queue and
    /// ends the stream with this error; lenient appends it so items keep
    /// their detection order.
    fn fail(&mut self, e: FsError) -> Result<JournalEvent> {
        if self.strict {
            self.finished = true;
            self.pending.clear();
            return Err(e);
        }
        self.pending.push_back(Err(e));
        // Non-empty by construction; the fallback is unreachable.
        self.pending
            .pop_front()
            .unwrap_or_else(|| Err(FsError::corrupt(0, "journal parse error")))
    }

    /// Read journal block `idx`'s raw bytes (full jbd2 block).
    fn read_journal_block(&self, idx: u64) -> Result<(u64, Vec<u8>)> {
        let off = self.info.block_offset(idx).ok_or_else(|| FsError::Corrupt {
            offset: 0,
            msg: format!("journal block {idx} beyond journal file extents"),
        })?;
        let data = self
            .src
            .read_slice(off, self.info.block_size as usize)
            .map_err(FsError::Io)?;
        if (data.len() as u64) < self.info.block_size as u64 {
            return Err(FsError::truncated(
                off,
                self.info.block_size as u64,
                data.len() as u64,
            ));
        }
        Ok((off, data))
    }

    /// Parse a descriptor block: queue the descriptor event plus one
    /// `JournaledBlock` event per tag. Returns how many following
    /// journal blocks those tags claim as data copies.
    fn descriptor(&mut self, idx: u64, off: u64, transid: u32, block: &[u8]) -> u64 {
        let tag_size = self.info.tag_size();
        let is64 = self.info.feature_incompat & INCOMPAT_64BIT != 0;
        let mut tags = Vec::new();
        let mut pos = 12usize;
        while let Some((tag, used)) = tag_at(block, pos, tag_size, is64) {
            let last = tag.flags & TAG_LAST != 0;
            tags.push((tag, pos));
            pos += used;
            if last {
                break;
            }
        }
        let claimed = tags.len() as u64;
        self.pending.push_back(Ok(JournalEvent {
            transid,
            journal_block: idx,
            disk_offset: off,
            kind: JournalEventKind::Descriptor { tags: tags.len() },
        }));
        for (i, (mut tag, tag_pos)) in tags.into_iter().enumerate() {
            tag.data_offset = self.info.block_offset(idx + 1 + i as u64);
            tag.target = self.layout.classify(tag.fs_block);
            tag.target_allocated = (self.allocated)(tag.fs_block);
            tag.tag_offset = off + tag_pos as u64;
            self.pending.push_back(Ok(JournalEvent {
                transid,
                journal_block: idx,
                disk_offset: off,
                kind: JournalEventKind::JournaledBlock(tag),
            }));
        }
        claimed
    }

    /// Queue a commit block's timestamp event.
    fn commit(&mut self, idx: u64, off: u64, transid: u32, block: &[u8]) {
        self.pending.push_back(Ok(JournalEvent {
            transid,
            journal_block: idx,
            disk_offset: off,
            kind: JournalEventKind::Commit {
                sec: le::u64_be(block, 0x30).unwrap_or(0),
                nsec: le::u32_be(block, 0x38).unwrap_or(0),
            },
        }));
    }

    /// Queue a revocation block's rescinded fs block numbers.
    fn revoke(&mut self, idx: u64, off: u64, transid: u32, block: &[u8]) {
        let wide = self.info.feature_incompat & INCOMPAT_64BIT != 0;
        let entry = if wide { 8usize } else { 4usize };
        let end = (le::u32_be(block, 0x0C).unwrap_or(0) as usize).min(block.len());
        let mut blocks = Vec::new();
        let mut pos = 0x10usize;
        while pos + entry <= end && blocks.len() < MAX_REVOKE_BLOCKS {
            blocks.push(if wide {
                le::u64_be(block, pos).unwrap_or(0)
            } else {
                le::u32_be(block, pos).unwrap_or(0) as u64
            });
            pos += entry;
        }
        self.pending.push_back(Ok(JournalEvent {
            transid,
            journal_block: idx,
            disk_offset: off,
            kind: JournalEventKind::Revoke { blocks },
        }));
    }

    fn queue(&mut self, idx: u64, off: u64, transid: u32, kind: JournalEventKind) {
        self.pending.push_back(Ok(JournalEvent {
            transid,
            journal_block: idx,
            disk_offset: off,
            kind,
        }));
    }
}

impl Iterator for JournalScan<'_> {
    type Item = Result<JournalEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.pending.pop_front() {
            return Some(item);
        }
        if self.finished {
            return None;
        }
        while self.idx < self.info.maxlen as u64 {
            let idx = self.idx;
            let (off, block) = match self.read_journal_block(idx) {
                Ok(v) => v,
                Err(e) => {
                    self.idx += 1;
                    return Some(self.fail(e));
                }
            };
            if le::u32_be(&block, 0) != Some(JBD2_MAGIC) {
                self.idx += 1; // unclaimed data block or noise — skip
                continue;
            }
            let blocktype = le::u32_be(&block, 0x04).unwrap_or(0);
            let transid = le::u32_be(&block, 0x08).unwrap_or(0);
            self.idx += 1;
            let claimed = match blocktype {
                BLOCK_DESCRIPTOR => self.descriptor(idx, off, transid, &block),
                BLOCK_COMMIT => {
                    self.commit(idx, off, transid, &block);
                    0
                }
                BLOCK_REVOKE => {
                    self.revoke(idx, off, transid, &block);
                    0
                }
                BLOCK_SUPER_V1 | BLOCK_SUPER_V2 => {
                    self.queue(idx, off, transid, JournalEventKind::Superblock { version: blocktype - 2 });
                    0
                }
                BLOCK_FAST_COMMIT => {
                    self.queue(idx, off, transid, JournalEventKind::FastCommit);
                    0
                }
                other => {
                    self.queue(idx, off, transid, JournalEventKind::Unknown { blocktype: other });
                    0
                }
            };
            // The descriptor's tags claim the following `claimed` journal
            // blocks as data copies. A claimed block that still carries
            // the jbd2 magic is a structure, not data — resynchronise.
            for i in 0..claimed {
                let data_idx = idx + 1 + i;
                if data_idx >= self.info.maxlen as u64 {
                    break;
                }
                match self.read_journal_block(data_idx) {
                    Ok((_, data)) if le::u32_be(&data, 0) == Some(JBD2_MAGIC) => {
                        self.idx = data_idx; // rescan the block as a structure
                        return Some(self.fail(FsError::corrupt(
                            self.info.block_offset(data_idx).unwrap_or(0),
                            format!("journal block {data_idx} claimed as data but carries a header"),
                        )));
                    }
                    _ => self.idx = data_idx + 1,
                }
            }
            if let Some(item) = self.pending.pop_front() {
                return Some(item);
            }
        }
        self.finished = true;
        self.pending.pop_front()
    }
}
