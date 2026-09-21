//! LZNT1 decompression — the codec NTFS native compression uses inside
//! each compression unit (default 16 clusters).
//!
//! Format (MS-XCA §2.5): a stream of 4 KiB chunks; each chunk carries a
//! 16-bit little-endian header — bit 15 = compressed, bits 14..12 = 0b011
//! signature, bits 11..0 = payload size − 1. A compressed body is flag
//! groups: one flag byte selects LSB-first whether each of the next 8
//! tokens is a literal byte (0) or a 2-byte match (1). The match token's
//! offset/length bit split slides with the number of bytes already emitted
//! in the chunk (offset field in the *high* bits grows from 4 to 12 bits as
//! position shrinks):
//!
//! ```text
//!   emitted ≤16 → 12 offset bits / 4 length bits
//!   … halving the offset reach each time emitted doubles …
//!   emitted >2048 → 4 offset bits / 12 length bits
//!   token: offset = (t >> length_bits) + 1,  length = (t & len_mask) + 3
//! ```
//!
//! An uncompressed chunk is a raw copy of `payload_len` bytes.
//!
//! Two entry points:
//!
//! * [`decompress`] — strict; errors on malformed input.
//! * [`decompress_unit`] — forensic best-effort; returns whatever decoded
//!   cleanly plus a `fully_decoded` flag (partial reads beat hard failures
//!   for evidence recovery).

use crate::{CompError, Result};

/// One compression chunk decodes to at most this many bytes.
pub const CHUNK: usize = 0x1000;

/// Offset-bits count for a given number of already-emitted bytes
/// (position within the 4 KiB window).
fn offset_bits(emitted: usize) -> u32 {
    let mut bits = 4u32;
    let mut threshold = 0x800usize; // >2048 → 4 bits
    while emitted <= threshold && bits < 12 {
        threshold >>= 1;
        bits += 1;
    }
    bits.min(12)
}

/// Strict LZNT1 decode: one compression unit's stored bytes → up to
/// `max_out` output bytes.
///
/// Errors on truncated chunks, bad signature bits, or match offsets that
/// reach before the start of the output. For forensic callers that prefer
/// partial output over an error, use [`decompress_unit`].
pub fn decompress(src: &[u8], max_out: usize) -> Result<Vec<u8>> {
    let (out, clean, why) = decompress_inner(src, max_out);
    if clean {
        Ok(out)
    } else {
        Err(why.unwrap_or_else(|| CompError::corrupt("malformed LZNT1 stream")))
    }
}

/// Decompress one compression unit's stored bytes → up to `unit_size`
/// output bytes. `src` is the raw bytes read from the unit's data runs.
///
/// Returns `(output, fully_decoded)`. `fully_decoded == false` means the
/// stored bytes were not a clean LZNT1 stream (e.g. the unit was written
/// raw because it did not compress) — callers should then treat `src`
/// itself as the content.
pub fn decompress_unit(src: &[u8], unit_size: usize) -> (Vec<u8>, bool) {
    let (out, clean, _) = decompress_inner(src, unit_size);
    (out, clean)
}

fn decompress_inner(src: &[u8], unit_size: usize) -> (Vec<u8>, bool, Option<CompError>) {
    let mut out = Vec::with_capacity(unit_size.min(1 << 20));
    let mut pos = 0usize;
    let mut clean = true;
    let mut err = None;
    while pos + 2 <= src.len() && out.len() < unit_size {
        let hdr = u16::from_le_bytes([src[pos], src[pos + 1]]);
        pos += 2;
        if hdr == 0 {
            break; // end-of-stream marker
        }
        let compressed = hdr & 0x8000 != 0;
        let payload_len = ((hdr & 0x0FFF) as usize) + 1;
        if pos + payload_len > src.len() {
            // Truncated tail — take what exists if it is a raw chunk.
            if !compressed {
                let avail = src.len() - pos;
                out.extend_from_slice(&src[pos..pos + avail]);
            }
            clean = false;
            err = Some(CompError::Truncated {
                needed: (pos + payload_len - src.len()) as u64,
            });
            break;
        }
        let body = &src[pos..pos + payload_len];
        pos += payload_len;
        if !compressed {
            out.extend_from_slice(body);
            continue;
        }
        if (hdr & 0x7000) != 0x3000 {
            clean = false; // bad signature bits — not really a compressed chunk
            err = Some(CompError::corrupt(format!(
                "LZNT1 chunk header {hdr:#06x} lacks the 0b011 signature"
            )));
            break;
        }
        // Compressed body: flag groups.
        let base = out.len();
        let mut i = 0usize;
        while i < body.len() && out.len() - base < CHUNK {
            let flags = body[i];
            i += 1;
            for bit in 0..8 {
                if flags & (1 << bit) == 0 {
                    if i >= body.len() {
                        clean = false;
                        err = Some(CompError::Truncated { needed: 1 });
                        break;
                    }
                    out.push(body[i]);
                    i += 1;
                } else {
                    if i + 2 > body.len() {
                        clean = false;
                        err = Some(CompError::Truncated { needed: 2 });
                        break;
                    }
                    let token = u16::from_le_bytes([body[i], body[i + 1]]);
                    i += 2;
                    let emitted = out.len() - base;
                    let obits = offset_bits(emitted);
                    let lbits = 16 - obits;
                    let len = ((token as usize) & ((1 << lbits) - 1)) + 3;
                    let off = ((token as usize) >> lbits) + 1;
                    if off > emitted || emitted == 0 {
                        clean = false;
                        err = Some(CompError::corrupt(format!(
                            "LZNT1 match offset {off} exceeds emitted {emitted}"
                        )));
                        break;
                    }
                    // Overlapping copy is legal (RLE-style repetition).
                    let start = out.len() - off;
                    for k in 0..len {
                        if out.len() - base >= CHUNK {
                            break;
                        }
                        let b = out[start + k];
                        out.push(b);
                    }
                }
                if out.len() - base >= CHUNK || i >= body.len() {
                    break;
                }
            }
        }
    }
    (out, clean, err)
}

/// `true` when `src` begins with a plausible LZNT1 chunk header —
/// used to decide whether a compression unit was stored compressed or raw.
pub fn looks_compressed(src: &[u8]) -> bool {
    if src.len() < 2 {
        return false;
    }
    let hdr = u16::from_le_bytes([src[0], src[1]]);
    hdr != 0 && (hdr & 0x7000) == 0x3000
}
