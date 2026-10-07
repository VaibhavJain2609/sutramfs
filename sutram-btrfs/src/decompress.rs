//! BTRFS compressed-extent decoding — pure-Rust codecs:
//!
//! * **zlib** (`compression=1`) — one zlib stream per extent (`flate2`,
//!   rust_backend/miniz_oxide).
//! * **lzo** (`compression=2`) — BTRFS's sub-block framing: a 4-byte LE
//!   total length header, then per-`PAGE_SIZE` chunks each prefixed by a
//!   4-byte LE compressed length, decompressed with `lzokay` (LZO1X).
//! * **zstd** (`compression=3`) — one zstd frame per extent (`ruzstd`).
//!
//! Output is always capped at the caller's expected size; a codec failure
//! produces `FsError::Corrupt`/`Unsupported`, never a panic.

use std::io::Read;

use sutram_fs::{FsError, Result};
use sutram_io::le;

use crate::ondisk::compression;

/// Cap on a single decompressed extent (BTRFS caps a compressed extent at
/// 128 KiB uncompressed; we allow generous headroom for odd images).
pub const MAX_EXTENT_OUT: u64 = 1 << 28; // 256 MiB hard sanity bound

/// LZO sub-block header (`BTRFS_LZO_HEADER_LEN` in the kernel).
const LZO_HDR: usize = 4;

/// Decompress one extent's stored bytes.
///
/// * `expected` — uncompressed bytes the caller wants (≤ `ram_bytes` of the
///   extent); decoding stops once `expected` bytes are produced.
pub fn decompress(algo: u8, input: &[u8], expected: usize) -> Result<Vec<u8>> {
    match algo {
        compression::NONE => Ok(input[..input.len().min(expected)].to_vec()),
        compression::ZLIB => decompress_zlib(input, expected),
        compression::LZO => decompress_lzo(input, expected),
        compression::ZSTD => decompress_zstd(input, expected),
        other => Err(FsError::unsupported(format!(
            "extent compression algorithm {other}"
        ))),
    }
}

/// Whether `algo` names a codec we can decode (for `meta["compressed"]` on
/// extents we still surface raw).
pub fn supported(algo: u8) -> bool {
    matches!(
        algo,
        compression::NONE | compression::ZLIB | compression::LZO | compression::ZSTD
    )
}

fn decompress_zlib(input: &[u8], expected: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(expected.min(1 << 20));
    let mut dec = flate2::read::ZlibDecoder::new(input);
    let mut chunk = [0u8; 16384];
    loop {
        let want = expected - out.len();
        if want == 0 {
            break;
        }
        let cap = want.min(chunk.len());
        let n = dec
            .read(&mut chunk[..cap])
            .map_err(|e| FsError::corrupt(0, format!("zlib stream: {e}")))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}

fn decompress_zstd(input: &[u8], expected: usize) -> Result<Vec<u8>> {
    let mut cursor = std::io::Cursor::new(input);
    let mut dec = ruzstd::decoding::StreamingDecoder::new(&mut cursor)
        .map_err(|e| FsError::corrupt(0, format!("zstd frame: {e:?}")))?;
    let mut out = Vec::with_capacity(expected.min(1 << 20));
    let mut chunk = [0u8; 16384];
    loop {
        let want = expected - out.len();
        if want == 0 {
            break;
        }
        let cap = want.min(chunk.len());
        let n = dec
            .read(&mut chunk[..cap])
            .map_err(|e| FsError::corrupt(0, format!("zstd stream: {e:?}")))?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}

/// BTRFS LZO layout (kernel `fs/btrfs/lzo.c`):
///
/// ```text
/// [0..4)   total compressed length (incl. this header)
/// then per sub-block: [4B compressed len][compressed bytes]
/// ```
///
/// Each sub-block decompresses to at most one page (4 KiB here; we allow
/// larger for non-x86 images). Sub-blocks that were incompressible are
/// stored with `in_len` equal to the page size holding raw bytes — handled
/// by the copy fallback.
fn decompress_lzo(input: &[u8], expected: usize) -> Result<Vec<u8>> {
    if input.len() < LZO_HDR {
        return Err(FsError::corrupt(0, "lzo extent shorter than header"));
    }
    let tot_len = le::u32(input, 0).unwrap_or(0) as usize;
    let mut out = Vec::with_capacity(expected.min(1 << 20));
    let mut pos = LZO_HDR;
    let end = tot_len.min(input.len());
    while pos + LZO_HDR <= end && out.len() < expected {
        let in_len = le::u32(input, pos).unwrap_or(0) as usize;
        pos += LZO_HDR;
        if in_len == 0 {
            break; // end marker
        }
        let avail = (end - pos).min(in_len);
        let sub = &input[pos..pos + avail];
        let want = expected - out.len();
        // Page-sized output buffer per sub-block (kernel uses PAGE_SIZE,
        // typically 4 KiB; we cap generously for 16K/64K-page images).
        let page_cap = want.clamp(4096, 1 << 17);
        let mut page = vec![0u8; page_cap];
        match lzokay::decompress::decompress(sub, &mut page) {
            Ok(n) => {
                out.extend_from_slice(&page[..n]);
            }
            Err(_) => {
                // Incompressible pages are stored verbatim (in_len ≥ the
                // data length) — copy raw when sizes line up.
                if avail >= want {
                    out.extend_from_slice(&sub[..want]);
                } else {
                    return Err(FsError::corrupt(
                        0,
                        format!("lzo sub-block failed to decompress (in_len={in_len})"),
                    ));
                }
            }
        }
        pos += avail;
    }
    Ok(out)
}
