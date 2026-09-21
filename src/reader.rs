//! Shared streaming readers used by all three archive parsers.
//!
//! Member data in an archive is either a contiguous byte range (stored),
//! a compressed byte range (ZIP deflate), or an extent list with holes
//! (TAR sparse). All readers below are bounded-memory: fixed buffers, no
//! whole-file allocation.

use std::io::{self, Read};
use std::sync::Arc;

use sutram_io::ByteSource;

/// One logical piece of member data.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Segment {
    /// Bytes stored literally at this absolute disk offset.
    Disk(u64),
    /// A hole — yields zeroes (TAR sparse regions; used by tar.rs).
    #[allow(dead_code)] // constructed once the TAR parser lands
    Zero,
}

/// Sequential reader over logical `(Segment, len)` pieces, capped at
/// `remaining` bytes total. Used for stored members and TAR sparse files.
pub(crate) struct SegmentReader {
    src: Arc<dyn ByteSource>,
    segs: Vec<(Segment, u64)>,
    idx: usize,
    off_in: u64,
    remaining: u64,
}

impl SegmentReader {
    pub(crate) fn new(
        src: Arc<dyn ByteSource>,
        segs: Vec<(Segment, u64)>,
        logical_size: u64,
    ) -> Self {
        SegmentReader {
            src,
            segs,
            idx: 0,
            off_in: 0,
            remaining: logical_size,
        }
    }
}

impl Read for SegmentReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.remaining > 0 && self.idx < self.segs.len() {
            let (seg, len) = self.segs[self.idx];
            let avail = len.saturating_sub(self.off_in);
            if avail == 0 {
                self.idx += 1;
                self.off_in = 0;
                continue;
            }
            let want = buf.len().min(avail.min(self.remaining) as usize);
            let n = match seg {
                Segment::Zero => {
                    buf[..want].fill(0);
                    want
                }
                Segment::Disk(off) => self.src.read_at(off + self.off_in, &mut buf[..want])?,
            };
            self.off_in += n as u64;
            self.remaining -= n as u64;
            if n == 0 {
                break;
            }
            return Ok(n);
        }
        Ok(0)
    }
}

/// Streaming raw-DEFLATE decoder over a fixed `[off, off+len)` window of
/// the source, producing at most `out_limit` bytes. Memory use is two
/// fixed buffers plus `InflateState`'s internal 32 KiB window — never
/// proportional to the member.
pub(crate) struct InflateReader {
    src: Arc<dyn ByteSource>,
    /// Compressed window: `[cpos, cend)`.
    cpos: u64,
    cend: u64,
    /// Unconsumed compressed input already fetched.
    inbuf: Vec<u8>,
    in_pos: usize,
    state: Box<miniz_oxide::inflate::stream::InflateState>,
    out_remaining: u64,
    done: bool,
    failed: bool,
}

/// Compressed-input chunk size.
const IN_CHUNK: usize = 64 * 1024;
/// Decompressed-output chunk size.
const OUT_CHUNK: usize = 32 * 1024;

impl InflateReader {
    pub(crate) fn new(
        src: Arc<dyn ByteSource>,
        comp_off: u64,
        comp_len: u64,
        out_limit: u64,
    ) -> Self {
        InflateReader {
            src,
            cpos: comp_off,
            cend: comp_off.saturating_add(comp_len),
            inbuf: Vec::new(),
            in_pos: 0,
            state: miniz_oxide::inflate::stream::InflateState::new_boxed(
                miniz_oxide::DataFormat::Raw,
            ),
            out_remaining: out_limit,
            done: false,
            failed: false,
        }
    }

    /// Top up `inbuf` from the compressed window. Returns input slice.
    fn refill(&mut self) -> io::Result<()> {
        if self.in_pos < self.inbuf.len() || self.cpos >= self.cend {
            return Ok(());
        }
        let want = (self.cend - self.cpos).min(IN_CHUNK as u64) as usize;
        self.inbuf = self.src.read_slice(self.cpos, want)?;
        self.in_pos = 0;
        self.cpos += self.inbuf.len() as u64;
        Ok(())
    }
}

impl Read for InflateReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || self.failed || self.out_remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        // We fill the caller's buffer directly but cap the per-call output
        // so the decompressor always has room to report progress.
        let want = buf
            .len()
            .min(self.out_remaining.min(OUT_CHUNK as u64) as usize);
        let mut written = 0usize;
        while written < want {
            self.refill()?;
            // Note: even with input fully consumed the decompressor may
            // hold pending output in its dictionary window — always call.
            let res = miniz_oxide::inflate::stream::inflate(
                &mut self.state,
                &self.inbuf[self.in_pos..],
                &mut buf[written..want],
                miniz_oxide::MZFlush::None,
            );
            self.in_pos += res.bytes_consumed;
            written += res.bytes_written;
            self.out_remaining -= res.bytes_written as u64;
            match res.status {
                Ok(miniz_oxide::MZStatus::Ok) => {}
                Ok(miniz_oxide::MZStatus::StreamEnd) => {
                    self.done = true;
                    break;
                }
                Ok(_) => {
                    // NeedDict etc. — not reachable for raw deflate.
                    self.failed = true;
                    break;
                }
                Err(e) => {
                    self.failed = true;
                    if written == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("deflate decompression failed: {e:?}"),
                        ));
                    }
                    break;
                }
            }
            if res.bytes_consumed == 0 && res.bytes_written == 0 {
                // No progress: either we simply need more input (loop back
                // and refill) or the stream is wedged — stop rather than
                // spin on corrupt data.
                if self.in_pos >= self.inbuf.len() && self.cpos < self.cend {
                    continue;
                }
                self.done = true;
                break;
            }
        }
        Ok(written)
    }
}
