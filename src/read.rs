//! Sequential file-content reader over resolved extents — handles holes
//! (zeros), inline data, raw extents and lazy per-extent decompression.

use std::io::{self, Read};
use std::sync::Arc;

use sutram_io::ByteSource;

use crate::decompress;
use crate::index::Extent;
use crate::ondisk::{compression, extent_ty};

/// Hard cap on a single extent's decompressed buffer.
const MAX_DECOMPRESSED: u64 = decompress::MAX_EXTENT_OUT;

/// One producible segment: `len` logical file bytes.
enum Prod {
    /// Sparse/unreachable bytes — yield zeros (live files only).
    Zeros,
    /// Uncompressed extent: physical ranges hold the file bytes directly.
    Raw { ranges: Vec<(u64, u64)> },
    /// Compressed extent: read `ranges`, decompress, skip `skip` output
    /// bytes, yield `len`.
    Blob { algo: u8, ranges: Vec<(u64, u64)>, skip: u64 },
    /// Inline extent payload (possibly compressed in place).
    Inline { data: Vec<u8>, algo: u8 },
}

struct Seg {
    /// File offset this segment starts at.
    file_off: u64,
    /// File bytes produced.
    len: u64,
    prod: Prod,
}

/// `Read` over an inode's extents.
///
/// * `live` mode: file offsets are honoured — gaps between extents yield
///   zeros (holes).
/// * deleted mode (`live == false`): segments are the *surviving* bytes
///   and are concatenated — per CONVENTIONS.md, `read_file` on a deleted
///   entry returns only recoverable bytes.
pub(crate) struct ExtentReader {
    src: Arc<dyn ByteSource>,
    segs: Vec<Seg>,
    live: bool,
    /// Current position within the (logical) file stream.
    pos: u64,
    /// Segments consumed so far.
    seg_idx: usize,
    /// Byte offset already produced inside `segs[seg_idx]`.
    seg_pos: u64,
    /// For `Raw`: index into `ranges` + offset into the current range.
    range_idx: usize,
    range_off: u64,
    /// For `Blob`/`Inline`: decompressed remainder.
    blob: Vec<u8>,
    blob_pos: usize,
    /// Whether the current segment's blob has been materialised.
    blob_done: bool,
    /// Pending zero-fill (gap before the next segment).
    zeros_left: u64,
    /// Total bytes left to produce (size cap).
    remaining: u64,
    /// Latched read error (returned once, then EOF).
    failed: Option<io::Error>,
}

impl ExtentReader {
    /// `extents` — `(extent, physical_ranges)` pairs; for deleted entries
    /// `physical_ranges` is the surviving subset.
    pub(crate) fn new(
        src: Arc<dyn ByteSource>,
        _map: &crate::chunk::ChunkMap,
        extents: Vec<(Extent, Vec<(u64, u64)>)>,
        cap: u64,
    ) -> Self {
        let live = cap != u64::MAX;
        let mut segs = Vec::new();
        for (ex, ranges) in extents {
            let prod = if ex.ty == extent_ty::INLINE {
                Prod::Inline {
                    data: ex.inline_data.clone().unwrap_or_default(),
                    algo: ex.compression,
                }
            } else if ex.is_hole() {
                Prod::Zeros
            } else if ex.compression == compression::NONE {
                Prod::Raw { ranges }
            } else {
                Prod::Blob {
                    algo: ex.compression,
                    ranges,
                    skip: ex.extent_offset,
                }
            };
            segs.push(Seg {
                file_off: ex.file_offset,
                len: ex.num_bytes,
                prod,
            });
        }
        segs.sort_by_key(|s| s.file_off);
        ExtentReader {
            src,
            segs,
            live,
            pos: 0,
            seg_idx: 0,
            seg_pos: 0,
            range_idx: 0,
            range_off: 0,
            blob: Vec::new(),
            blob_pos: 0,
            blob_done: false,
            zeros_left: 0,
            remaining: cap,
            failed: None,
        }
    }

    /// Materialise the current segment's decompressed payload.
    fn load_blob(&mut self) -> io::Result<()> {
        if self.blob_done {
            return Ok(());
        }
        self.blob_done = true;
        self.blob.clear();
        self.blob_pos = 0;
        let seg = &self.segs[self.seg_idx];
        let (compressed, algo, skip) = match &seg.prod {
            Prod::Inline { data, algo } => (data.clone(), *algo, 0u64),
            Prod::Blob { algo, ranges, skip } => {
                let mut buf = Vec::with_capacity(
                    ranges.iter().map(|(_, l)| *l).sum::<u64>().min(1 << 24) as usize,
                );
                for &(off, len) in ranges.iter() {
                    let part = self.src.read_slice(off, len as usize)?;
                    buf.extend_from_slice(&part);
                    if (part.len() as u64) < len {
                        break; // truncated source
                    }
                }
                (buf, *algo, *skip)
            }
            _ => return Ok(()),
        };
        let want = (seg.len + skip).min(MAX_DECOMPRESSED) as usize;
        let out = if algo == compression::NONE {
            compressed
        } else {
            decompress::decompress(algo, &compressed, want)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
        };
        let skip = skip.min(out.len() as u64) as usize;
        self.blob = out[skip..].to_vec();
        self.blob_pos = 0;
        Ok(())
    }

    /// Advance to the next segment (live mode zero-fills offset gaps;
    /// deleted mode skips them).
    fn advance(&mut self) {
        while self.seg_idx < self.segs.len() {
            let seg = &self.segs[self.seg_idx];
            if self.seg_pos < seg.len && self.pos >= seg.file_off {
                return; // inside an active segment
            }
            if self.pos < seg.file_off {
                if self.live {
                    self.zeros_left = seg.file_off - self.pos;
                    return; // gap → zeros
                }
                self.pos = seg.file_off; // deleted: jump to next survivor
                continue;
            }
            self.seg_idx += 1;
            self.seg_pos = 0;
            self.range_idx = 0;
            self.range_off = 0;
            self.blob.clear();
            self.blob_pos = 0;
            self.blob_done = false;
        }
    }
}

impl Read for ExtentReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = self.failed.take() {
            return Err(e);
        }
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        self.advance();
        // Zero-fill gap.
        if self.zeros_left > 0 {
            let n = (self.zeros_left.min(buf.len() as u64)).min(self.remaining) as usize;
            buf[..n].fill(0);
            self.zeros_left -= n as u64;
            self.pos += n as u64;
            self.remaining -= n as u64;
            return Ok(n);
        }
        if self.seg_idx >= self.segs.len() {
            return Ok(0);
        }
        let (len, file_off) = {
            let s = &self.segs[self.seg_idx];
            (s.len, s.file_off)
        };
        match &self.segs[self.seg_idx].prod {
            Prod::Zeros => {
                let n = (len - self.seg_pos).min(buf.len() as u64).min(self.remaining) as usize;
                buf[..n].fill(0);
                self.seg_pos += n as u64;
                self.pos += n as u64;
                self.remaining -= n as u64;
                Ok(n)
            }
            Prod::Raw { ranges } => {
                // Walk the physical ranges in order, producing min(range)
                // pieces; short physical reads surface as early EOF.
                let ranges = ranges.clone();
                let mut produced = 0usize;
                while produced < buf.len()
                    && self.seg_pos < len
                    && self.remaining > 0
                    && self.range_idx < ranges.len()
                {
                    let (off, rlen) = ranges[self.range_idx];
                    if self.range_off >= rlen {
                        self.range_idx += 1;
                        self.range_off = 0;
                        continue;
                    }
                    let want = (rlen - self.range_off)
                        .min(len - self.seg_pos)
                        .min(self.remaining)
                        .min((buf.len() - produced) as u64) as usize;
                    match self
                        .src
                        .read_at(off + self.range_off, &mut buf[produced..produced + want])
                    {
                        Ok(0) => break,
                        Ok(n) => {
                            produced += n;
                            self.range_off += n as u64;
                            self.seg_pos += n as u64;
                            self.pos += n as u64;
                            self.remaining -= n as u64;
                        }
                        Err(e) => {
                            if produced == 0 {
                                return Err(e);
                            }
                            self.failed = Some(e);
                            break;
                        }
                    }
                }
                if produced == 0 && self.range_idx >= ranges.len() && self.seg_pos < len {
                    // Physical extent shorter than declared — zero-fill the
                    // declared remainder rather than erroring mid-stream.
                    let n = (len - self.seg_pos).min(buf.len() as u64).min(self.remaining)
                        as usize;
                    buf[..n].fill(0);
                    self.seg_pos += n as u64;
                    self.pos += n as u64;
                    self.remaining -= n as u64;
                    return Ok(n);
                }
                Ok(produced)
            }
            Prod::Blob { .. } | Prod::Inline { .. } => {
                if let Err(e) = self.load_blob() {
                    self.failed = Some(e);
                    return Err(self.failed.take().unwrap());
                }
                let avail = self.blob.len() - self.blob_pos;
                let n = avail
                    .min((len - self.seg_pos) as usize)
                    .min(buf.len())
                    .min(self.remaining as usize);
                if n == 0 {
                    // Decompression yielded less than declared — pad zeros.
                    let z = (len - self.seg_pos).min(buf.len() as u64).min(self.remaining)
                        as usize;
                    if z == 0 {
                        self.seg_idx += 1;
                        self.seg_pos = 0;
                        return Ok(0);
                    }
                    buf[..z].fill(0);
                    self.seg_pos += z as u64;
                    self.pos += z as u64;
                    self.remaining -= z as u64;
                    if self.seg_pos >= len {
                        self.seg_idx += 1;
                        self.seg_pos = 0;
                    }
                    return Ok(z);
                }
                buf[..n].copy_from_slice(&self.blob[self.blob_pos..self.blob_pos + n]);
                self.blob_pos += n;
                self.seg_pos += n as u64;
                self.pos += n as u64;
                self.remaining -= n as u64;
                Ok(n)
            }
        }
        .map(|n| {
            if self.seg_pos >= len {
                self.seg_idx += 1;
                self.seg_pos = 0;
                self.range_idx = 0;
                self.range_off = 0;
                self.blob.clear();
                self.blob_pos = 0;
                self.blob_done = false;
            }
            let _ = file_off;
            n
        })
    }
}
