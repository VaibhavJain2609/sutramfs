//! zlib and raw-DEFLATE decompression via `miniz_oxide` (pure Rust).
//!
//! * [`decompress_zlib`] — RFC 1950 stream (2-byte header + Adler-32).
//! * [`decompress_deflate`] — bare RFC 1951 stream (e.g. inside ZIP
//!   entries or decmpfs raw payloads).
//! * [`ZlibDecoder`] / [`DeflateDecoder`] — `std::io::Read` streaming
//!   adapters over `miniz_oxide`'s low-level `InflateState`. The caller
//!   remains responsible for bounding total output (e.g. `Read::take`).

use std::io::{self, Read};

use miniz_oxide::inflate::stream::{inflate, InflateState};
use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::{DataFormat, MZFlush, MZStatus};

use crate::{CompError, Result};

/// Map a `miniz_oxide` decompress error onto [`CompError`].
fn map_err(e: miniz_oxide::inflate::DecompressError, limit: usize) -> CompError {
    match e.status {
        TINFLStatus::HasMoreOutput => CompError::OutputLimit {
            limit: limit as u64,
        },
        TINFLStatus::FailedCannotMakeProgress | TINFLStatus::NeedsMoreInput => {
            CompError::Truncated { needed: 1 }
        }
        other => CompError::corrupt(format!("inflate failed: {other:?}")),
    }
}

/// Decompress an RFC 1950 **zlib** stream, bounded to `max_out` bytes.
pub fn decompress_zlib(src: &[u8], max_out: usize) -> Result<Vec<u8>> {
    miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(src, max_out)
        .map_err(|e| map_err(e, max_out))
}

/// Decompress a bare RFC 1951 **deflate** stream, bounded to `max_out`.
pub fn decompress_deflate(src: &[u8], max_out: usize) -> Result<Vec<u8>> {
    miniz_oxide::inflate::decompress_to_vec_with_limit(src, max_out)
        .map_err(|e| map_err(e, max_out))
}

/// Streaming zlib decoder: `Read`s decompressed bytes from `src`.
///
/// This is a pull decoder over a caller-owned input buffer — the
/// "streaming" is of the *output*, not the input (the input is a slice,
/// so nothing needs to be fed incrementally). Output is not internally
/// bounded: wrap with `Read::take` or count bytes yourself when the
/// uncompressed size is untrusted.
pub struct ZlibDecoder<'a> {
    inner: StreamDecoder<'a>,
}

impl<'a> ZlibDecoder<'a> {
    /// Wrap a complete zlib stream.
    pub fn new(src: &'a [u8]) -> Self {
        ZlibDecoder {
            inner: StreamDecoder::new(src, DataFormat::Zlib),
        }
    }
}

/// Streaming raw-deflate decoder; see [`ZlibDecoder`].
pub struct DeflateDecoder<'a> {
    inner: StreamDecoder<'a>,
}

impl<'a> DeflateDecoder<'a> {
    /// Wrap a complete bare-DEFLATE stream.
    pub fn new(src: &'a [u8]) -> Self {
        DeflateDecoder {
            inner: StreamDecoder::new(src, DataFormat::Raw),
        }
    }
}

impl Read for ZlibDecoder<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Read for DeflateDecoder<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

struct StreamDecoder<'a> {
    state: Box<InflateState>,
    src: &'a [u8],
    pos: usize,
    done: bool,
}

impl<'a> StreamDecoder<'a> {
    fn new(src: &'a [u8], format: DataFormat) -> Self {
        StreamDecoder {
            state: InflateState::new_boxed(format),
            src,
            pos: 0,
            done: false,
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        let res = inflate(&mut self.state, &self.src[self.pos..], buf, MZFlush::None);
        self.pos += res.bytes_consumed;
        match res.status {
            Ok(MZStatus::StreamEnd) => {
                self.done = true;
                Ok(res.bytes_written)
            }
            Ok(MZStatus::Ok) | Ok(MZStatus::NeedDict) => {
                if res.bytes_written == 0 && res.bytes_consumed == 0 {
                    // Cannot make progress (input exhausted mid-stream):
                    // report EOF rather than looping forever.
                    self.done = true;
                }
                Ok(res.bytes_written)
            }
            Err(e) => {
                self.done = true;
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("inflate failed: {e:?}"),
                ))
            }
        }
    }
}
