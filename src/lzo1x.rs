//! LZO1X-1 decompression via [`lzokay`] — a pure-Rust, `no_std`-capable
//! port of the LZO format used by btrfs inline extents and older decmpfs
//! payloads.
//!
//! LZO streams do not carry their decompressed size, so the caller's
//! `max_out` is the bomb guard: we decode into a buffer that grows
//! geometrically toward `max_out` rather than allocating the bound up
//! front (a `max_out` of gigabytes must not cost gigabytes when the real
//! output is kilobytes). When the caller knows the expected size (btrfs
//! stores it alongside the extent), the first buffer already fits.

use crate::{CompError, Result};

/// Initial decode-buffer guess when nothing about the output is known.
const INITIAL_CAP: usize = 64 * 1024;

/// Decompress an LZO1X-1 stream, producing at most `max_out` bytes.
///
/// Errors: [`CompError::Truncated`] when the input ends mid-stream,
/// [`CompError::Corrupt`] on lookbehind overruns and unconsumed trailing
/// garbage, [`CompError::OutputLimit`] when the output does not fit in
/// `max_out`.
pub fn decompress(src: &[u8], max_out: usize) -> Result<Vec<u8>> {
    if max_out == 0 {
        return if src.is_empty() {
            Ok(Vec::new())
        } else {
            Err(CompError::OutputLimit { limit: 0 })
        };
    }
    // Grow the destination geometrically; lzokay reports OutputOverrun
    // when the stream wants more room, so we retry bounded times.
    let mut cap = (src.len().saturating_mul(4)).clamp(4096, INITIAL_CAP).min(max_out);
    loop {
        let mut buf = vec![0u8; cap];
        match lzokay::decompress::decompress(src, &mut buf) {
            Ok(n) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Err(lzokay::Error::OutputOverrun) => {
                if cap >= max_out {
                    return Err(CompError::OutputLimit {
                        limit: max_out as u64,
                    });
                }
                cap = cap.saturating_mul(2).min(max_out);
            }
            Err(lzokay::Error::InputOverrun) => return Err(CompError::Truncated { needed: 1 }),
            Err(lzokay::Error::LookbehindOverrun) => {
                return Err(CompError::corrupt(
                    "lzo1x match reaches before start of output",
                ))
            }
            Err(lzokay::Error::InputNotConsumed) => {
                return Err(CompError::corrupt(
                    "lzo1x stream has trailing unconsumed bytes",
                ))
            }
            Err(lzokay::Error::Error) => {
                return Err(CompError::corrupt("lzo1x decode failed"))
            }
        }
    }
}
