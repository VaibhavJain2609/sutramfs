//! Apple LZVN decompression — the codec behind most `decmpfs`-compressed
//! files on modern HFS+/APFS volumes (compression types 7 inline, 8
//! resource-fork) and the kernel's compressed-memory format.
//!
//! LZVN is an LZ77 variant with a single-byte opcode dispatch. The opcodes:
//!
//! | Opcode byte(s)                    | Name    | Layout |
//! |-----------------------------------|---------|--------|
//! | `LLMMMDDD DDDDDDDD`               | `sml_d` | lit 0-3 + match len 3-10, dist ≤ 2047 |
//! | `101LLMMM DDDDDDMM DDDDDDDD`      | `med_d` | lit 0-3 + match len 3-34, dist ≤ 16383 |
//! | `LLMMM111 DDDDDDDD DDDDDDDD`      | `lrg_d` | lit 0-3 + match len 3-10, dist ≤ 65535 |
//! | `LLMMM110`                        | `pre_d` | lit 0-3 + match len 3-10, dist = previous |
//! | `1111MMMM`                        | `sml_m` | match len 0-15, dist = previous |
//! | `11110000 MMMMMMMM`               | `lrg_m` | match len 16-271, dist = previous |
//! | `1110LLLL LITERAL`                | `sml_l` | literal 0-15 |
//! | `11100000 LLLLLLLL LITERAL`       | `lrg_l` | literal 16-271 |
//! | `0x0E`/`0x16`                     | `nop`   | ignored |
//! | `0x06` + 7 bytes                  | `eos`   | end of stream |
//! | `0x1E,0x26,…,0x70-0x7F,0xD0-0xDF` | `udef`  | undefined → error |
//!
//! This is a faithful safe-Rust port of Apple's `lzvn_decode_base.c`
//! (lzfse reference implementation, BSD-licensed). Semantics preserved:
//! the match distance carries across opcodes (`d_prev`), every non-`eos`
//! opcode requires at least one following byte in the source, and match
//! copies with `D < M` overlap byte-by-byte (RLE expansion).

use crate::{CompError, Result};

/// Decode a complete LZVN stream, producing at most `max_out` bytes.
///
/// The stream must end with the 8-byte `eos` opcode. Errors:
/// [`CompError::Truncated`] when input ends mid-opcode or without `eos`,
/// [`CompError::Corrupt`] on undefined opcodes and invalid match
/// distances, [`CompError::OutputLimit`] when decoding would exceed
/// `max_out` (decompression-bomb guard).
pub fn decompress(src: &[u8], max_out: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(max_out.min(1 << 22));
    decompress_into(src, &mut out, max_out)?;
    Ok(out)
}

/// Decode an LZVN stream, appending to `out`. `max_out` bounds the *total*
/// length of `out` (including any pre-existing content). On success returns
/// the number of source bytes consumed, which always includes the 8-byte
/// `eos` opcode; trailing bytes after `eos` are not examined.
///
/// This is shared with the LZFSE decoder, which embeds LZVN payloads inside
/// `bvxn` blocks and must know exactly how many payload bytes were used.
pub(crate) fn decompress_into(
    src: &[u8],
    out: &mut Vec<u8>,
    max_out: usize,
) -> Result<usize> {
    let mut pos = 0usize;
    let mut d_prev = 0usize;

    if src.is_empty() {
        return Err(CompError::Truncated { needed: 8 });
    }

    // Pending op state (the C version suspends these in the decoder state
    // on dst exhaustion; we error on dst exhaustion instead, so this is
    // only loop-internal).
    loop {
        let opc = src[pos];
        let src_len = src.len() - pos;
        let sptr = &src[pos..];

        // (opcode length, literal length, match length, new distance)
        // for the literal+match family, or a control action.
        enum Act {
            /// L+M op: opc_len, L, M, D
            LitMatch(usize, usize, usize, usize),
            /// literal-only op: opc_len, L
            Lit(usize, usize),
            /// match-only op: opc_len, M (D = d_prev)
            Match(usize, usize),
            Eos,
            Nop,
            Udef,
        }

        let act = match opc {
            // eos — "0x06" followed by 7 reserved bytes.
            6 => Act::Eos,
            // nop.
            14 | 22 => Act::Nop,
            // undefined opcodes.
            30 | 38 | 46 | 54 | 62 | 112..=127 | 208..=223 => Act::Udef,
            // lrg_l: 11100000 LLLLLLLL LITERAL
            224 => {
                if src_len <= 2 {
                    return Err(CompError::Truncated { needed: 2 });
                }
                Act::Lit(2, sptr[1] as usize + 16)
            }
            // sml_l: 1110LLLL LITERAL
            225..=239 => Act::Lit(1, (opc & 0x0F) as usize),
            // lrg_m: 11110000 MMMMMMMM
            240 => {
                if src_len <= 2 {
                    return Err(CompError::Truncated { needed: 2 });
                }
                Act::Match(2, sptr[1] as usize + 16)
            }
            // sml_m: 1111MMMM
            241..=255 => Act::Match(1, (opc & 0x0F) as usize),
            // med_d: 101LLMMM DDDDDDMM DDDDDDDD LITERAL
            160..=191 => {
                let l = ((opc >> 3) & 0x03) as usize;
                if src_len <= 3 + l {
                    return Err(CompError::Truncated {
                        needed: (3 + l + 1 - src_len) as u64,
                    });
                }
                let opc23 = u16::from_le_bytes([sptr[1], sptr[2]]) as usize;
                let m = (((opc as usize & 0x07) << 2) | (opc23 & 0x03)) + 3;
                let d = opc23 >> 2;
                Act::LitMatch(3, l, m, d)
            }
            // lrg_d: LLMMM111 DDDDDDDD DDDDDDDD LITERAL
            7 | 15 | 23 | 31 | 39 | 47 | 55 | 63 | 71 | 79 | 87 | 95 | 103 | 111 | 135 | 143
            | 151 | 159 | 199 | 207 => {
                let l = (opc >> 6) as usize;
                if src_len <= 3 + l {
                    return Err(CompError::Truncated {
                        needed: (3 + l + 1 - src_len) as u64,
                    });
                }
                let m = ((opc >> 3) as usize & 0x07) + 3;
                let d = u16::from_le_bytes([sptr[1], sptr[2]]) as usize;
                Act::LitMatch(3, l, m, d)
            }
            // pre_d: LLMMM110
            70 | 78 | 86 | 94 | 102 | 110 | 134 | 142 | 150 | 158 | 198 | 206 => {
                let l = (opc >> 6) as usize;
                if src_len <= 1 + l {
                    return Err(CompError::Truncated {
                        needed: (1 + l + 1 - src_len) as u64,
                    });
                }
                let m = ((opc >> 3) as usize & 0x07) + 3;
                Act::LitMatch(1, l, m, d_prev)
            }
            // sml_d: LLMMMDDD DDDDDDDD LITERAL — every remaining value.
            _ => {
                let l = (opc >> 6) as usize;
                if src_len <= 2 + l {
                    return Err(CompError::Truncated {
                        needed: (2 + l + 1 - src_len) as u64,
                    });
                }
                let m = ((opc >> 3) as usize & 0x07) + 3;
                let d = (((opc as usize) & 0x07) << 8) | sptr[1] as usize;
                Act::LitMatch(2, l, m, d)
            }
        };

        match act {
            Act::Eos => {
                if src_len < 8 {
                    return Err(CompError::Truncated {
                        needed: (8 - src_len) as u64,
                    });
                }
                return Ok(pos + 8); // end_of_stream
            }
            Act::Nop => {
                if src_len <= 1 {
                    return Err(CompError::Truncated { needed: 1 });
                }
                pos += 1;
            }
            Act::Udef => {
                return Err(CompError::corrupt(format!(
                    "lzvn undefined opcode {opc:#04x} at input offset {pos}"
                )));
            }
            Act::Lit(opc_len, l) => {
                // src_len > opc_len + L was validated at dispatch for ops
                // that embed L; for lrg_l/sml_l the check happens here.
                if src_len <= opc_len + l {
                    return Err(CompError::Truncated {
                        needed: (opc_len + l + 1 - src_len) as u64,
                    });
                }
                if l > max_out - out.len() {
                    return Err(CompError::OutputLimit {
                        limit: max_out as u64,
                    });
                }
                let start = pos + opc_len;
                out.extend_from_slice(&src[start..start + l]);
                pos = start + l;
            }
            Act::Match(opc_len, m) => {
                let d = d_prev;
                // The C reference skips the distance check on this path
                // (a first-opcode sml_m would read unwritten output). For
                // hostile input we validate: distance must exist.
                if d == 0 || d > out.len() {
                    return Err(CompError::corrupt(format!(
                        "lzvn match distance {d} invalid ({} bytes emitted)",
                        out.len()
                    )));
                }
                pos += opc_len;
                copy_match(out, d, m, max_out)?;
            }
            Act::LitMatch(opc_len, l, m, d) => {
                // Truncation already validated: src_len > opc_len + L.
                if l > max_out - out.len() {
                    return Err(CompError::OutputLimit {
                        limit: max_out as u64,
                    });
                }
                let start = pos + opc_len;
                out.extend_from_slice(&src[start..start + l]);
                pos = start + l;
                if d == 0 || d > out.len() {
                    return Err(CompError::corrupt(format!(
                        "lzvn match distance {d} invalid ({} bytes emitted)",
                        out.len()
                    )));
                }
                d_prev = d;
                copy_match(out, d, m, max_out)?;
            }
        }
    }
}

/// Copy `m` bytes from `d` bytes back in `out`; overlapping copies
/// (`d < m`) duplicate byte-by-byte — RLE semantics, like `memset`.
fn copy_match(out: &mut Vec<u8>, d: usize, m: usize, max_out: usize) -> Result<()> {
    if m > max_out - out.len() {
        return Err(CompError::OutputLimit {
            limit: max_out as u64,
        });
    }
    let start = out.len() - d;
    for i in 0..m {
        let b = out[start + i];
        out.push(b);
    }
    Ok(())
}
