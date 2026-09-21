//! HFS+ journal forensics: the `journal_header` and `block_list_header`
//! transaction chain inside the journal buffer.
//!
//! The volume header's `journalInfoBlock` (a `JournalInfoBlock`, parsed
//! in `vh.rs`) points at a circular buffer that starts with a
//! `journal_header`:
//!
//! ```text
//! 0x00 u32 magic ("JNLx")   0x04 u32 endian flag (0x12345678)
//! 0x08 u64 start            0x10 u64 end      0x18 u64 size
//! 0x20 u32 blhdr_size       0x24 u32 checksum 0x28 u32 jhdr_size
//! ```
//!
//! (`start`/`end`/`size` are offsets inside the buffer; the magic's
//! byte order declares the field endianness — big-endian "JNLx" or
//! little-endian "xLNJ".)
//!
//! The rest of the buffer is a ring of `block_list_header` transactions:
//!
//! ```text
//! u16 max_blocks  u16 num_blocks  u32 bytes_used
//! u32 checksum    u32 pad         block_info binfo[num_blocks]
//! ```
//!
//! Each `block_info` is `{ u64 bnum; u64 bytes; u64 next }` — `bnum` is
//! the destination in 512-byte **sectors**, `bytes` the journaled copy's
//! length, `next` the buffer offset of the following block list (0 wraps
//! to the start of the data region). The copy's data follows the header.
//!
//! This module **parses** the ring as evidence — it does not replay it.
//! Every block copy is prior-state evidence: the sector it was destined
//! for is reported, and the journaled bytes are exposed through
//! `allocated_ranges` so an examiner can read the snapshot directly.
//! Lists outside the live `[start, end)` window are *stale* transactions
//! — overwritten but checksum-verifiable history, the forensic prize.

use std::collections::VecDeque;
use std::sync::Arc;

use sutram_fs::{FsError, Result};
use sutram_io::{le, ByteSource};

/// `journal_header.magic` ("JNLx" big-endian, "xLNJ" little-endian).
const JNL_MAGIC: u32 = 0x4A4E_4C78;
/// `journal_header.endian` sanity flag.
const JNL_ENDIAN: u32 = 0x1234_5678;
/// Bound on the journal buffer materialised for scanning.
pub(crate) const MAX_JOURNAL_BYTES: u64 = 64 << 20;
/// `block_list_header` fixed part (max_blocks..pad), before binfo[].
const BLHDR_FIXED: usize = 16;
/// One `block_info` entry.
const BINFO_SIZE: usize = 24;
/// `bnum` is denominated in 512-byte sectors.
pub const SECTOR: u64 = 512;
/// Hostile-input bound on `num_blocks`/`max_blocks`.
const MAX_BL_BLOCKS: u16 = 256;
/// Bound on chain+sweep iterations.
const MAX_ITERS: usize = 8192;
/// Sweep alignment — block lists are written at 8-byte boundaries.
const SWEEP_STEP: u64 = 8;

/// The XNU journal checksum: MSB-first CRC-32 (poly 0x04C11DB7, init 0,
/// final `!`), computed over the `block_info` array of a block list.
/// Advisory — a mismatch flags the list `checksum_ok: false` rather
/// than discarding it.
pub fn journal_checksum(data: &[u8]) -> u32 {
    // MSB-first CRC-32 table for poly 0x04C11DB7, built lazily per call —
    // the buffer is small and the table is stack-local.
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = (i as u32) << 24;
        for _ in 0..8 {
            c = if c & 0x8000_0000 != 0 {
                (c << 1) ^ 0x04C1_1DB7
            } else {
                c << 1
            };
        }
        *slot = c;
    }
    let mut cksum = 0u32;
    for chunk in data.chunks(4) {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        for &b in &word {
            cksum = (cksum << 8) ^ table[(((cksum >> 24) as u8) ^ b) as usize];
        }
    }
    !cksum
}

/// Decoded `journal_header`.
#[derive(Debug, Clone)]
pub struct JournalHeader {
    /// `true` when the magic read little-endian ("xLNJ") — all fields
    /// are then little-endian too.
    pub swapped: bool,
    /// Buffer offset where the oldest live block list begins.
    pub start: u64,
    /// Buffer offset where the next block list would be written.
    pub end: u64,
    /// Total journal buffer size.
    pub size: u64,
    /// On-disk size of a `block_list_header` (with binfo array).
    pub blhdr_size: u32,
    /// Header checksum field (stored, not verified).
    pub checksum: u32,
    /// On-disk size of the `journal_header` region — where block lists
    /// begin in the buffer.
    pub jhdr_size: u32,
}

impl JournalHeader {
    /// Parse the header at `buf[0..]`; `None` when the magic/endian flag
    /// don't validate.
    fn parse(buf: &[u8]) -> Option<JournalHeader> {
        if buf.len() < 44 {
            return None;
        }
        let swapped = le::u32(buf, 0) == Some(JNL_MAGIC);
        let be_ok = le::u32_be(buf, 0) == Some(JNL_MAGIC);
        if !swapped && !be_ok {
            return None;
        }
        let u32f = |o: usize| {
            if swapped {
                le::u32(buf, o).unwrap_or(0)
            } else {
                le::u32_be(buf, o).unwrap_or(0)
            }
        };
        let u64f = |o: usize| {
            if swapped {
                le::u64(buf, o).unwrap_or(0)
            } else {
                le::u64_be(buf, o).unwrap_or(0)
            }
        };
        if u32f(4) != JNL_ENDIAN {
            return None;
        }
        Some(JournalHeader {
            swapped,
            start: u64f(8),
            end: u64f(16),
            size: u64f(24),
            blhdr_size: u32f(32),
            checksum: u32f(36),
            jhdr_size: u32f(40),
        })
    }
}

/// One `block_info`: a journaled copy and its destination.
#[derive(Debug, Clone)]
pub struct JournalBlockCopy {
    /// Destination block in 512-byte sectors.
    pub target_sector: u64,
    /// Destination byte offset (`target_sector * 512`).
    pub target_offset: u64,
    /// Journaled copy length.
    pub bytes: u64,
    /// Buffer offset of the copy's data.
    pub data_offset: u64,
    /// Buffer offset of this `block_info` record (provenance).
    pub record_offset: u64,
    /// `next` link — buffer offset of the following block list (0 wraps).
    pub next: u64,
}

/// One decoded `block_list_header` — a transaction's metadata.
#[derive(Debug, Clone)]
pub struct BlockList {
    /// Buffer offset of this header.
    pub offset: u64,
    pub num_blocks: u16,
    pub bytes_used: u32,
    /// Whether the XNU checksum over `binfo[]` verifies.
    pub checksum_ok: bool,
    /// The journaled copies this transaction carries.
    pub blocks: Vec<JournalBlockCopy>,
}

/// What one journal artefact is.
#[derive(Debug, Clone)]
pub enum JournalEventKind {
    /// The `journal_header` itself.
    Header {
        start: u64,
        end: u64,
        size: u64,
        jhdr_size: u32,
        swapped: bool,
    },
    /// A `block_list_header` — `live` when inside the `[start, end)`
    /// window, stale overwritten history otherwise.
    Transaction {
        index: u32,
        num_blocks: u16,
        bytes_used: u32,
        checksum_ok: bool,
        live: bool,
    },
    /// One journaled block copy within a transaction.
    BlockCopy {
        tx_index: u32,
        copy: JournalBlockCopy,
        live: bool,
    },
}

/// A parsed journal artefact with absolute provenance.
#[derive(Debug, Clone)]
pub struct JournalEvent {
    /// Offset inside the journal buffer.
    pub jnl_offset: u64,
    /// Absolute disk offset of the record that produced this event.
    pub disk_offset: u64,
    pub kind: JournalEventKind,
}

/// Streaming parse of the journal buffer (materialised, bounded).
/// Phase 1 walks the live `next`-linked chain from `start` to `end`;
/// phase 2 sweeps the remaining buffer for checksum-valid stale lists.
/// `Err` items mark malformed structures; strict mode ends at the first.
pub(crate) struct JournalScan {
    buf: Vec<u8>,
    /// Absolute offset of `buf[0]` on the source.
    base: u64,
    hdr: JournalHeader,
    /// First offset of the block-list data region.
    data_start: u64,
    pos: u64,
    /// Buffer spans already claimed by the live chain — skipped by the
    /// sweep.
    visited: Vec<(u64, u64)>,
    tx_index: u32,
    pending: VecDeque<Result<JournalEvent>>,
    sweeping: bool,
    finished: bool,
    strict: bool,
    iters: usize,
}

impl JournalScan {
    /// `buf` = journal buffer bytes (already bounded), `base` = its
    /// absolute source offset. `hdr` is the validated journal header.
    pub(crate) fn new(
        buf: Vec<u8>,
        base: u64,
        hdr: JournalHeader,
        strict: bool,
    ) -> Self {
        let data_start = (hdr.jhdr_size as u64).max(44).min(hdr.size);
        let mut pending = VecDeque::new();
        pending.push_back(Ok(JournalEvent {
            jnl_offset: 0,
            disk_offset: base,
            kind: JournalEventKind::Header {
                start: hdr.start,
                end: hdr.end,
                size: hdr.size,
                jhdr_size: hdr.jhdr_size,
                swapped: hdr.swapped,
            },
        }));
        JournalScan {
            buf,
            base,
            data_start,
            pos: hdr.start,
            visited: Vec::new(),
            tx_index: 0,
            pending,
            sweeping: false,
            finished: false,
            strict,
            iters: 0,
            hdr,
        }
    }

    fn u16f(&self, o: usize) -> u16 {
        if self.hdr.swapped {
            le::u16(&self.buf, o).unwrap_or(0)
        } else {
            le::u16_be(&self.buf, o).unwrap_or(0)
        }
    }
    fn u32f(&self, o: usize) -> u32 {
        if self.hdr.swapped {
            le::u32(&self.buf, o).unwrap_or(0)
        } else {
            le::u32_be(&self.buf, o).unwrap_or(0)
        }
    }
    fn u64f(&self, o: usize) -> u64 {
        if self.hdr.swapped {
            le::u64(&self.buf, o).unwrap_or(0)
        } else {
            le::u64_be(&self.buf, o).unwrap_or(0)
        }
    }

    /// Parse the `block_list_header` at buffer offset `pos`. Returns the
    /// decoded list plus the buffer span it occupies
    /// (`blhdr + data`), or `None` when it is not plausible.
    fn block_list(&self, pos: u64) -> Option<(BlockList, u64)> {
        let p = pos as usize;
        if pos < self.data_start || pos + BLHDR_FIXED as u64 > self.buf.len() as u64 {
            return None;
        }
        let max_blocks = self.u16f(p);
        let num_blocks = self.u16f(p + 2);
        let bytes_used = self.u32f(p + 4);
        if num_blocks == 0 || num_blocks > max_blocks || max_blocks > MAX_BL_BLOCKS {
            return None;
        }
        let need = BLHDR_FIXED + num_blocks as usize * BINFO_SIZE;
        if pos + need as u64 > self.buf.len() as u64 {
            return None;
        }
        let binfo = le::get(&self.buf, p + BLHDR_FIXED, num_blocks as usize * BINFO_SIZE)?;
        let checksum_ok = journal_checksum(binfo) == self.u32f(p + 8);
        let mut blocks = Vec::with_capacity(num_blocks as usize);
        let mut data = pos + self.hdr.blhdr_size.max(need as u32) as u64;
        let mut total = 0u64;
        for i in 0..num_blocks as usize {
            let b = p + BLHDR_FIXED + i * BINFO_SIZE;
            let sector = self.u64f(b);
            let bytes = self.u64f(b + 8);
            let next = self.u64f(b + 16);
            if bytes == 0 || bytes > self.buf.len() as u64 {
                return None;
            }
            if data + bytes > self.buf.len() as u64 {
                return None;
            }
            blocks.push(JournalBlockCopy {
                target_sector: sector,
                target_offset: sector.saturating_mul(SECTOR),
                bytes,
                data_offset: data,
                record_offset: b as u64,
                next,
            });
            data += bytes;
            total += bytes;
        }
        let span = (self.hdr.blhdr_size.max(need as u32) as u64).saturating_add(total);
        Some((
            BlockList {
                offset: pos,
                num_blocks,
                bytes_used,
                checksum_ok,
                blocks,
            },
            span,
        ))
    }

    /// Queue a decoded list's transaction + block-copy events.
    fn emit_list(&mut self, list: BlockList, live: bool) {
        let idx = self.tx_index;
        self.tx_index += 1;
        self.pending.push_back(Ok(JournalEvent {
            jnl_offset: list.offset,
            disk_offset: self.base + list.offset,
            kind: JournalEventKind::Transaction {
                index: idx,
                num_blocks: list.num_blocks,
                bytes_used: list.bytes_used,
                checksum_ok: list.checksum_ok,
                live,
            },
        }));
        for copy in list.blocks {
            self.pending.push_back(Ok(JournalEvent {
                jnl_offset: copy.record_offset,
                disk_offset: self.base + copy.record_offset,
                kind: JournalEventKind::BlockCopy {
                    tx_index: idx,
                    copy,
                    live,
                },
            }));
        }
    }

    /// Advance the live chain one step; returns `false` at chain end.
    fn chain_step(&mut self) -> bool {
        if self.iters >= MAX_ITERS || self.pos >= self.buf.len() as u64 {
            return false;
        }
        self.iters += 1;
        let pos = self.pos;
        match self.block_list(pos) {
            Some((list, span)) => {
                let next = list.blocks.last().map(|b| b.next).unwrap_or(0);
                self.visited.push((pos, pos.saturating_add(span)));
                self.emit_list(list, true);
                // next == 0 wraps to the start of the data region.
                self.pos = if next == 0 { self.data_start } else { next };
                // Stop when the write head (`end`) or the tail (`start`)
                // is reached, or the chain loops back on itself.
                if self.pos == self.hdr.end
                    || self.pos == self.hdr.start
                    || self
                        .visited
                        .iter()
                        .any(|&(s, _)| s == self.pos)
                {
                    return false;
                }
                true
            }
            None => {
                self.pending.push_back(Err(FsError::corrupt(
                    self.base + pos,
                    format!("block list at journal offset {pos:#x} failed to parse"),
                )));
                if self.strict {
                    self.finished = true;
                }
                false
            }
        }
    }

    /// Sweep the buffer for checksum-valid stale block lists outside
    /// the live chain.
    fn sweep_step(&mut self) -> bool {
        while self.pos + BLHDR_FIXED as u64 <= self.buf.len() as u64 {
            let pos = self.pos;
            if self.iters >= MAX_ITERS {
                return false;
            }
            // Skip spans the live chain already claimed.
            if let Some(&(_, e)) = self
                .visited
                .iter()
                .find(|&&(s, e)| pos >= s && pos < e)
            {
                self.pos = e;
                continue;
            }
            self.pos += SWEEP_STEP;
            if let Some((list, span)) = self.block_list(pos) {
                if !list.checksum_ok {
                    continue; // sweep trusts the checksum, not the shape
                }
                self.iters += 1;
                self.visited.push((pos, pos.saturating_add(span)));
                self.emit_list(list, false);
            }
        }
        false
    }
}

impl Iterator for JournalScan {
    type Item = Result<JournalEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.pending.pop_front() {
            return Some(item);
        }
        if self.finished {
            return None;
        }
        if !self.sweeping {
            if self.chain_step() {
                return self.pending.pop_front();
            }
            // Strict mode ends the stream at the queued terminal error.
            if self.finished {
                return self.pending.pop_front();
            }
            // Switch to the sweep phase over the whole data region.
            self.sweeping = true;
            self.pos = self.data_start;
        }
        if self.sweep_step() {
            return self.pending.pop_front();
        }
        self.finished = true;
        self.pending.pop_front()
    }
}

/// Open the journal buffer: bounded read + header validation. Returns
/// `(materialised_buf, header)`; the buffer is capped at
/// `MAX_JOURNAL_BYTES` and `size`.
pub(crate) fn open(
    src: &Arc<dyn ByteSource>,
    buffer_offset: u64,
    buffer_size: u64,
) -> Result<(Vec<u8>, JournalHeader)> {
    let want = buffer_size.min(MAX_JOURNAL_BYTES) as usize;
    let buf = src.read_slice(buffer_offset, want).map_err(FsError::Io)?;
    let hdr = JournalHeader::parse(&buf).ok_or_else(|| FsError::Corrupt {
        offset: buffer_offset,
        msg: "journal buffer: bad magic or endian flag".into(),
    })?;
    if hdr.size > buffer_size.saturating_mul(4) + MAX_JOURNAL_BYTES {
        return Err(FsError::corrupt(
            buffer_offset + 0x18,
            format!("journal_header.size {} far exceeds journal buffer", hdr.size),
        ));
    }
    Ok((buf, hdr))
}
