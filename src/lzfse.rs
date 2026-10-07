//! Apple LZFSE decompression — the codec behind `decmpfs` compression
//! types 11 (inline) and 12 (resource fork) on modern HFS+/APFS volumes.
//!
//! This is a safe-Rust port of the decoder half of Apple's BSD-licensed
//! reference implementation (`lzfse_decode_base.c`, `lzfse_fse.c`,
//! `lzfse_internal.h`, github.com/lzfse/lzfse — Copyright (c) 2015-2016,
//! Apple Inc.). Block layout and FSE (tANS) table construction follow the
//! reference exactly; what differs is that every read is bounds-checked and
//! every malformed stream produces [`CompError`] instead of UB.
//!
//! ## Stream layout
//!
//! A stream is a sequence of blocks, each starting with a little-endian
//! 4-byte magic:
//!
//! | Magic   | Bytes   | Block kind |
//! |---------|---------|------------|
//! | `bvx$`  | `0x24787662` | end of stream |
//! | `bvx-`  | `0x2d787662` | uncompressed block |
//! | `bvxn`  | `0x6e787662` | LZVN-compressed payload |
//! | `bvx1`  | `0x31787662` | LZFSE-compressed, raw v1 header (770 bytes) |
//! | `bvx2`  | `0x32787662` | LZFSE-compressed, packed header + compressed freq tables |
//!
//! `bvx1`/`bvx2` blocks hold two FSE-coded sections: a literal stream
//! (4 interleaved 10-bit-state tANS decoders) and an L,M,D stream
//! (literal-length / match-length / match-distance value streams, 64/64/256
//! states). The L,M,D stream is read *backwards* from the end of its payload.
//!
//! Output is bounded by `max_out` (decompression-bomb guard); corrupt
//! streams yield [`CompError::Corrupt`], short streams
//! [`CompError::Truncated`]. No panics on hostile input.

use crate::{lzvn, CompError, Result};

// ---------------------------------------------------------------------------
// Format constants (lzfse_internal.h)
// ---------------------------------------------------------------------------

/// `bvx$` — end-of-stream marker.
const EOS_MAGIC: u32 = 0x2478_7662;
/// `bvx-` — uncompressed block.
const UNCOMPRESSED_MAGIC: u32 = 0x2d78_7662;
/// `bvx1` — compressed block, uncompressed (v1) header.
const COMPRESSED_V1_MAGIC: u32 = 0x3178_7662;
/// `bvx2` — compressed block, compressed (v2) header.
const COMPRESSED_V2_MAGIC: u32 = 0x3278_7662;
/// `bvxn` — LZVN-compressed block.
const LZVN_MAGIC: u32 = 0x6e78_7662;

const L_SYMBOLS: usize = 20;
const M_SYMBOLS: usize = 20;
const D_SYMBOLS: usize = 64;
const LITERAL_SYMBOLS: usize = 256;

const L_STATES: usize = 64;
const M_STATES: usize = 64;
const D_STATES: usize = 256;
const LITERAL_STATES: usize = 1024;

const MATCHES_PER_BLOCK: usize = 10_000;
const LITERALS_PER_BLOCK: usize = 4 * MATCHES_PER_BLOCK;
/// Decoded literals buffer per block: `LZFSE_LITERALS_PER_BLOCK + 64`.
const LITERAL_BUF: usize = LITERALS_PER_BLOCK + 64;

/// Total number of frequency entries serialised in a v2 header.
const N_FREQ: usize = L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LITERAL_SYMBOLS;

/// Fixed size of a v1 block header on the wire.
const V1_HEADER_SIZE: usize = 770;
/// Fixed portion of a v2 block header (magic + n_raw_bytes + packed fields).
const V2_HEADER_FIXED: usize = 32;

// L value coding: base values + count of extra low-order bits.
const L_EXTRA_BITS: [u8; L_SYMBOLS] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8,
];
const L_BASE_VALUE: [i32; L_SYMBOLS] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60,
];
const M_EXTRA_BITS: [u8; M_SYMBOLS] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11,
];
const M_BASE_VALUE: [i32; M_SYMBOLS] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312,
];
const D_EXTRA_BITS: [u8; D_SYMBOLS] = [
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6,
    6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11,
    12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
];
const D_BASE_VALUE: [i32; D_SYMBOLS] = [
    0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52, 60, 76, 92, 108,
    124, 156, 188, 220, 252, 316, 380, 444, 508, 636, 764, 892, 1020, 1276,
    1532, 1788, 2044, 2556, 3068, 3580, 4092, 5116, 6140, 7164, 8188, 10236,
    12284, 14332, 16380, 20476, 24572, 28668, 32764, 40956, 49148, 57340,
    65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372,
];

fn trunc(needed: u64) -> CompError {
    CompError::Truncated { needed }
}

fn corrupt(msg: impl Into<String>) -> CompError {
    CompError::corrupt(msg)
}

fn limit(max_out: usize) -> CompError {
    CompError::OutputLimit {
        limit: max_out as u64,
    }
}

#[inline]
fn le16(src: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([src[off], src[off + 1]])
}

#[inline]
fn le32(src: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([src[off], src[off + 1], src[off + 2], src[off + 3]])
}

#[inline]
fn le64(src: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&src[off..off + 8]);
    u64::from_le_bytes(b)
}

// ---------------------------------------------------------------------------
// Block header (normalised v1 form; v2 headers are expanded into this shape)
// ---------------------------------------------------------------------------

struct BlockHeader {
    n_literals: usize,
    n_matches: usize,
    n_literal_payload_bytes: usize,
    n_lmd_payload_bytes: usize,
    /// Left-over bit count from the encoder, in `[-7, 0]` (v1 headers can
    /// carry out-of-range values; [`FseIn::init`] rejects them).
    literal_bits: i32,
    literal_state: [u16; 4],
    lmd_bits: i32,
    l_state: u16,
    m_state: u16,
    d_state: u16,
    l_freq: [u16; L_SYMBOLS],
    m_freq: [u16; M_SYMBOLS],
    d_freq: [u16; D_SYMBOLS],
    literal_freq: [u16; LITERAL_SYMBOLS],
}

/// Parse a fixed-layout `bvx1` block header (770 bytes, all fields
/// little-endian). `src` is the block start (pointing at the magic).
fn parse_v1_header(src: &[u8]) -> BlockHeader {
    let mut h = BlockHeader {
        n_literals: le32(src, 12) as usize,
        n_matches: le32(src, 16) as usize,
        n_literal_payload_bytes: le32(src, 20) as usize,
        n_lmd_payload_bytes: le32(src, 24) as usize,
        literal_bits: le32(src, 28) as i32,
        literal_state: [
            le16(src, 32),
            le16(src, 34),
            le16(src, 36),
            le16(src, 38),
        ],
        lmd_bits: le32(src, 40) as i32,
        l_state: le16(src, 44),
        m_state: le16(src, 46),
        d_state: le16(src, 48),
        l_freq: [0; L_SYMBOLS],
        m_freq: [0; M_SYMBOLS],
        d_freq: [0; D_SYMBOLS],
        literal_freq: [0; LITERAL_SYMBOLS],
    };
    let mut off = 50;
    for f in h
        .l_freq
        .iter_mut()
        .chain(h.m_freq.iter_mut())
        .chain(h.d_freq.iter_mut())
        .chain(h.literal_freq.iter_mut())
    {
        *f = le16(src, off);
        off += 2;
    }
    h
}

/// Decode one frequency-table value from the low bits of `bits`, returning
/// `(value, nbits_consumed)`. Port of `lzfse_decode_v1_freq_value`: a fixed
/// Huffman-style code where the position of the first set bit selects the
/// code length.
fn decode_freq_value(bits: u32) -> (u16, i32) {
    const NBITS: [i8; 32] = [
        2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, //
        2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14,
    ];
    const VALUE: [i8; 32] = [
        0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1, //
        0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1,
    ];
    let b = (bits & 31) as usize;
    let n = NBITS[b] as i32;
    if n == 8 {
        (8 + ((bits >> 4) & 0xf) as u16, n)
    } else if n == 14 {
        (24 + ((bits >> 4) & 0x3ff) as u16, n)
    } else {
        (VALUE[b] as u16, n)
    }
}

#[inline]
fn get_field(v: u64, offset: u32, nbits: u32) -> u64 {
    debug_assert!(offset + nbits < 64 && nbits <= 32);
    if nbits == 32 {
        v >> offset
    } else {
        (v >> offset) & ((1u64 << nbits) - 1)
    }
}

/// Parse a `bvx2` packed header into a [`BlockHeader`]. `src` points at the
/// block magic. Returns the header plus the total on-disk header size.
fn parse_v2_header(src: &[u8]) -> Result<(BlockHeader, usize)> {
    // Fixed portion: magic(4) n_raw_bytes(4) packed_fields[3](24).
    if src.len() < V2_HEADER_FIXED {
        return Err(trunc((V2_HEADER_FIXED - src.len()) as u64));
    }
    let v0 = le64(src, 8);
    let v1 = le64(src, 16);
    let v2 = le64(src, 24);

    let header_size = get_field(v2, 0, 32) as usize;
    if header_size > src.len() {
        return Err(trunc((header_size - src.len()) as u64));
    }

    let mut h = BlockHeader {
        n_literals: get_field(v0, 0, 20) as usize,
        n_literal_payload_bytes: get_field(v0, 20, 20) as usize,
        n_matches: get_field(v0, 40, 20) as usize,
        literal_bits: get_field(v0, 60, 3) as i32 - 7,
        literal_state: [
            get_field(v1, 0, 10) as u16,
            get_field(v1, 10, 10) as u16,
            get_field(v1, 20, 10) as u16,
            get_field(v1, 30, 10) as u16,
        ],
        n_lmd_payload_bytes: get_field(v1, 40, 20) as usize,
        lmd_bits: get_field(v1, 60, 3) as i32 - 7,
        l_state: get_field(v2, 32, 10) as u16,
        m_state: get_field(v2, 42, 10) as u16,
        d_state: get_field(v2, 52, 10) as u16,
        l_freq: [0; L_SYMBOLS],
        m_freq: [0; M_SYMBOLS],
        d_freq: [0; D_SYMBOLS],
        literal_freq: [0; LITERAL_SYMBOLS],
    };

    // Compressed frequency table: LSB-first bit-packed freq values covering
    // bytes src[32..header_size].
    let mut cur = V2_HEADER_FIXED;
    let mut accum: u32 = 0;
    let mut accum_nbits: i32 = 0;
    if header_size != V2_HEADER_FIXED {
        // Freq tables present; decode all N_FREQ entries.
        let mut i = 0;
        for f in h
            .l_freq
            .iter_mut()
            .chain(h.m_freq.iter_mut())
            .chain(h.d_freq.iter_mut())
            .chain(h.literal_freq.iter_mut())
        {
            while cur < header_size && accum_nbits + 8 <= 32 {
                accum |= (src[cur] as u32) << accum_nbits;
                accum_nbits += 8;
                cur += 1;
            }
            let (val, nbits) = decode_freq_value(accum);
            if nbits > accum_nbits {
                return Err(corrupt("lzfse v2 header: freq table underrun"));
            }
            *f = val;
            accum >>= nbits;
            accum_nbits -= nbits;
            i += 1;
        }
        debug_assert_eq!(i, N_FREQ);
        // Must land exactly at the end of the header with <8 leftover bits.
        if accum_nbits >= 8 || cur != header_size {
            return Err(corrupt("lzfse v2 header: freq table size mismatch"));
        }
    } else if header_size < V2_HEADER_FIXED {
        // header_size smaller than the fixed part: the freq start is already
        // past the declared end — corrupt (matches reference src != src_end).
        return Err(corrupt("lzfse v2 header: header_size < fixed part"));
    }
    Ok((h, header_size))
}

/// `fse_check_freq`: the sum of a frequency table may not exceed the number
/// of states of its decoder.
fn check_freq(freq: &[u16], nstates: usize) -> Result<()> {
    let sum: u64 = freq.iter().map(|&f| f as u64).sum();
    if sum > nstates as u64 {
        return Err(corrupt("lzfse header: freq table sum exceeds nstates"));
    }
    Ok(())
}

/// `lzfse_check_block_header_v1` — field plausibility checks.
fn check_header(h: &BlockHeader) -> Result<()> {
    if h.n_literals > LITERALS_PER_BLOCK {
        return Err(corrupt("lzfse header: n_literals over limit"));
    }
    if h.n_matches > MATCHES_PER_BLOCK {
        return Err(corrupt("lzfse header: n_matches over limit"));
    }
    for (i, &s) in h.literal_state.iter().enumerate() {
        if s as usize >= LITERAL_STATES {
            return Err(corrupt(format!("lzfse header: literal_state[{i}] >= {LITERAL_STATES}")));
        }
    }
    if h.l_state as usize >= L_STATES {
        return Err(corrupt("lzfse header: l_state out of range"));
    }
    if h.m_state as usize >= M_STATES {
        return Err(corrupt("lzfse header: m_state out of range"));
    }
    if h.d_state as usize >= D_STATES {
        return Err(corrupt("lzfse header: d_state out of range"));
    }
    check_freq(&h.l_freq, L_STATES)?;
    check_freq(&h.m_freq, M_STATES)?;
    check_freq(&h.d_freq, D_STATES)?;
    check_freq(&h.literal_freq, LITERAL_STATES)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// FSE input bit stream — reads *backwards* through a payload
// (fse_in_stream64 / fse_in_checked_init64 / fse_in_checked_flush64 /
//  fse_in_pull64 from lzfse_fse.h)
// ---------------------------------------------------------------------------

struct FseIn {
    accum: u64,
    accum_nbits: i32, // valid bits in accum; invariant 0..=63 after init
}

impl FseIn {
    /// Initialise reading backwards: `pos` is the index one-past the last
    /// payload byte in `src`; `floor` is the lowest index reads may reach
    /// (payload start for the L,M,D stream, 0 for the literal stream —
    /// matching the reference's `buf_start`). `nbits` is the header's
    /// `literal_bits`/`lmd_bits` field, `[-7, 0]` for valid streams.
    fn init(nbits: i32, src: &[u8], pos: &mut usize, floor: usize) -> Result<FseIn> {
        let (accum, accum_nbits) = if nbits != 0 {
            if *pos < floor + 8 {
                return Err(corrupt("lzfse fse_in_init: not enough input"));
            }
            *pos -= 8;
            (le64(src, *pos), nbits.wrapping_add(64))
        } else {
            if *pos < floor + 7 {
                return Err(corrupt("lzfse fse_in_init: not enough input"));
            }
            *pos -= 7;
            let mut b = [0u8; 8];
            b[..7].copy_from_slice(&src[*pos..*pos + 7]);
            (u64::from_le_bytes(b), 56)
        };
        // The encoder zeroes the unused top bits; a valid stream ends with
        // accum_nbits in [56, 63] and nothing above it.
        if !(56..64).contains(&accum_nbits) || (accum >> accum_nbits) != 0 {
            return Err(corrupt("lzfse fse_in_init: invalid accumulator"));
        }
        Ok(FseIn {
            accum,
            accum_nbits,
        })
    }

    /// Top the accumulator back up into [56, 63] bits by pulling whole bytes
    /// from below `pos`.
    fn flush(&mut self, src: &[u8], pos: &mut usize, floor: usize) -> Result<()> {
        let nbits = (63 - self.accum_nbits) & -8; // whole bytes, >= 0
        if nbits <= 0 {
            return Ok(());
        }
        let nbytes = (nbits >> 3) as usize;
        if *pos < floor + nbytes {
            return Err(corrupt("lzfse fse_in_flush: input exhausted"));
        }
        *pos -= nbytes;
        // Only the low `nbits` bits of the incoming word are used; reading
        // exactly `nbytes` keeps us fully inside `src` (the reference reads a
        // fixed 8 bytes and masks, which can touch bytes past the payload).
        let mut incoming = 0u64;
        for i in 0..nbytes {
            incoming |= (src[*pos + i] as u64) << (8 * i);
        }
        self.accum = (self.accum << nbits) | (incoming & ((1u64 << nbits) - 1));
        self.accum_nbits += nbits;
        Ok(())
    }

    /// Pull `n` bits from the top of the accumulator. Call sites guarantee
    /// `n <= accum_nbits` via `flush` (the decoders consume at most 54 bits
    /// per refill); the clamp is defence-in-depth so a bug can never shift
    /// the accumulator by a negative amount.
    #[inline]
    fn pull(&mut self, n: u32) -> u64 {
        let n = n.min(self.accum_nbits.max(0) as u32);
        self.accum_nbits -= n as i32;
        let res = self.accum >> self.accum_nbits;
        self.accum &= (1u64 << self.accum_nbits) - 1;
        res
    }
}

// ---------------------------------------------------------------------------
// FSE decoder tables (fse_init_decoder_table / fse_init_value_decoder_table)
// ---------------------------------------------------------------------------

/// Entry in a symbol decoder table: `delta << 16 | symbol << 8 | k`.
/// `k` bits are pulled; next state = `delta + pulled`; emitted = `symbol`.
type SymbolTable = Vec<i32>;

/// `fse_value_decoder_entry`.
#[derive(Clone, Copy, Default)]
struct ValueEntry {
    /// State bits + extra value bits pulled in one read.
    total_bits: u8,
    /// Number of low bits forming the value offset.
    value_bits: u8,
    /// Base added to the state bits to form the next state.
    delta: i32,
    /// Base value for this symbol.
    vbase: i32,
}

/// `fse_init_decoder_table`: fill `t[0..nstates]` with packed decode entries
/// for `freq[symbol]` occurrences of each symbol, in symbol order.
fn init_symbol_table(nstates: usize, freq: &[u16]) -> Result<SymbolTable> {
    let mut t = vec![0i32; nstates];
    let n_log = nstates.trailing_zeros(); // nstates is a power of two here
    let mut idx = 0usize;
    for (sym, &fq) in freq.iter().enumerate() {
        let f = fq as usize;
        if f == 0 {
            continue;
        }
        if idx + f > nstates {
            return Err(corrupt("lzfse: freq table overfills decoder table"));
        }
        // Shift so that nstates <= f<<k < 2*nstates.
        let k = n_log - ilog2(f);
        let j0 = ((2 * nstates) >> k) - f;
        for j in 0..f {
            let (kk, delta) = if j < j0 {
                (k, ((f + j) << k) - nstates)
            } else {
                // j >= j0 implies k >= 1 for any valid freq (k == 0 forces
                // j0 >= f); saturating_sub keeps hostile tables panic-free.
                (k.saturating_sub(1), (j - j0) << k.saturating_sub(1))
            };
            t[idx] = ((delta as i32) << 16) | ((sym as i32) << 8) | kk as i32;
            idx += 1;
        }
    }
    Ok(t)
}

#[inline]
fn ilog2(x: usize) -> u32 {
    usize::BITS - 1 - x.leading_zeros()
}

/// `fse_init_value_decoder_table`: same state construction, but each entry
/// also carries the symbol's extra value bits / value base.
fn init_value_table(
    nstates: usize,
    freq: &[u16],
    vbits: &[u8],
    vbase: &[i32],
) -> Vec<ValueEntry> {
    let mut t = vec![ValueEntry::default(); nstates];
    let n_log = nstates.trailing_zeros();
    let mut idx = 0usize;
    for (sym, &fq) in freq.iter().enumerate() {
        let f = fq as usize;
        if f == 0 {
            continue;
        }
        let k = n_log - ilog2(f);
        let j0 = ((2 * nstates) >> k) - f;
        for j in 0..f {
            let (kk, delta) = if j < j0 {
                (k, ((f + j) << k) - nstates)
            } else {
                (k.saturating_sub(1), (j - j0) << k.saturating_sub(1))
            };
            t[idx] = ValueEntry {
                total_bits: (kk as u8).wrapping_add(vbits[sym]),
                value_bits: vbits[sym],
                delta: delta as i32,
                vbase: vbase[sym],
            };
            idx += 1;
        }
    }
    t
}

/// `fse_decode`: emit the symbol for `state`, pull `k` bits, move to the
/// next state.
#[inline]
fn fse_decode(state: &mut u16, table: &[i32], ins: &mut FseIn) -> Result<u8> {
    let e = *table
        .get(*state as usize)
        .ok_or_else(|| corrupt("lzfse fse_decode: state out of range"))?;
    *state = ((e >> 16) as u16).wrapping_add(ins.pull((e & 0xff) as u32) as u16);
    Ok(((e >> 8) & 0xff) as u8)
}

/// `fse_value_decode`: pull `total_bits`, split into next-state bits and
/// extra value bits.
#[inline]
fn fse_value_decode(
    state: &mut u16,
    table: &[ValueEntry],
    ins: &mut FseIn,
) -> Result<i32> {
    let e = table
        .get(*state as usize)
        .ok_or_else(|| corrupt("lzfse fse_value_decode: state out of range"))?;
    let savb = ins.pull(e.total_bits as u32);
    *state = (e.delta + (savb >> e.value_bits) as i32) as u16;
    let vmask = if e.value_bits == 0 {
        0
    } else {
        (1u64 << e.value_bits) - 1
    };
    Ok(e.vbase + (savb & vmask) as i32)
}

// ---------------------------------------------------------------------------
// Block decoders
// ---------------------------------------------------------------------------

/// Decode a `bvx1`/`bvx2` compressed block. `src` is the full input; `pos`
/// indexes the block magic. Returns the index of the first byte after the
/// block's LMD payload.
fn decode_compressed_block(
    src: &[u8],
    pos: usize,
    v2: bool,
    out: &mut Vec<u8>,
    max_out: usize,
) -> Result<usize> {
    let (h, header_size) = if v2 {
        parse_v2_header(&src[pos..])?
    } else {
        if src.len() - pos < V1_HEADER_SIZE {
            return Err(trunc((V1_HEADER_SIZE - (src.len() - pos)) as u64));
        }
        (parse_v1_header(&src[pos..]), V1_HEADER_SIZE)
    };

    let after_header = pos + header_size;
    let lit_start = after_header;
    let lit_end = lit_start
        .checked_add(h.n_literal_payload_bytes)
        .ok_or_else(|| corrupt("lzfse: payload size overflow"))?;
    let lmd_end = lit_end
        .checked_add(h.n_lmd_payload_bytes)
        .ok_or_else(|| corrupt("lzfse: payload size overflow"))?;
    // The reference requires the whole encoded block resident in src.
    if lmd_end > src.len() {
        return Err(trunc((lmd_end - src.len()) as u64));
    }

    check_header(&h)?;

    // Build decoder tables.
    let literal_table = init_symbol_table(LITERAL_STATES, &h.literal_freq)?;
    let l_table = init_value_table(L_STATES, &h.l_freq, &L_EXTRA_BITS, &L_BASE_VALUE);
    let m_table = init_value_table(M_STATES, &h.m_freq, &M_EXTRA_BITS, &M_BASE_VALUE);
    let d_table = init_value_table(D_STATES, &h.d_freq, &D_EXTRA_BITS, &D_BASE_VALUE);

    // -- Literal stream ----------------------------------------------------
    // Reads backwards from the end of the literal payload; reads may reach
    // back to the start of the whole input (floor = 0), as in the reference.
    let mut literals = vec![0u8; LITERAL_BUF];
    {
        let mut bpos = lit_end;
        let mut ins = FseIn::init(h.literal_bits, src, &mut bpos, 0)?;
        let mut st = h.literal_state;
        let mut i = 0usize;
        while i < h.n_literals {
            ins.flush(src, &mut bpos, 0)?; // refill to [56,63] bits
            // Four interleaved streams; each decode pulls <= 10 bits, so one
            // flush covers all four.
            literals[i] = fse_decode(&mut st[0], &literal_table, &mut ins)?;
            literals[i + 1] = fse_decode(&mut st[1], &literal_table, &mut ins)?;
            literals[i + 2] = fse_decode(&mut st[2], &literal_table, &mut ins)?;
            literals[i + 3] = fse_decode(&mut st[3], &literal_table, &mut ins)?;
            i += 4;
        }
    }

    // -- L,M,D stream + match replay --------------------------------------
    // Reads backwards from the end of the LMD payload, bounded below by the
    // payload start (the encoder pads the payload head with 8 zero bytes).
    {
        let lmd_start = lit_end;
        let mut bpos = lmd_end;
        let mut ins = FseIn::init(h.lmd_bits, src, &mut bpos, lmd_start)?;
        let (mut l_state, mut m_state, mut d_state) =
            (h.l_state, h.m_state, h.d_state);
        let mut lit = 0usize; // cursor into `literals`
        let mut d: i64 = -1; // invalid "previous" distance, as in the reference

        for _ in 0..h.n_matches {
            // One flush covers L (<=14b) + M (<=17b) + D (<=23b) = 54b max.
            ins.flush(src, &mut bpos, lmd_start)?;
            let l = fse_value_decode(&mut l_state, &l_table, &mut ins)? as usize;
            if lit + l >= LITERAL_BUF {
                return Err(corrupt("lzfse: literal stream overruns block"));
            }
            let m = fse_value_decode(&mut m_state, &m_table, &mut ins)? as usize;
            let new_d = fse_value_decode(&mut d_state, &d_table, &mut ins)?;
            if new_d != 0 {
                d = new_d as i64;
            }

            // ExecuteMatch: D may not look back past the start of output
            // (checked against the position *after* this match's literals).
            if d < 0 || d as usize > out.len() + l {
                return Err(corrupt("lzfse: match distance out of range"));
            }
            let d = d as usize;
            if l + m > max_out - out.len() {
                return Err(limit(max_out));
            }
            out.extend_from_slice(&literals[lit..lit + l]);
            lit += l;
            // Overlapping copies (d < m) replicate RLE-style, one byte at a
            // time; disjoint copies go through extend_from_within.
            let start = out.len() - d;
            if d >= m {
                out.extend_from_within(start..start + m);
            } else {
                out.reserve(m);
                for i in 0..m {
                    let b = out[start + i];
                    out.push(b);
                }
            }
        }
    }

    Ok(lmd_end)
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Decode a complete LZFSE stream, producing at most `max_out` bytes.
///
/// The stream is a sequence of blocks terminated by the 4-byte `bvx$`
/// end-of-stream marker; trailing bytes after it are ignored (matching the
/// reference). Errors: [`CompError::Truncated`] when input ends mid-block or
/// without `bvx$`, [`CompError::Corrupt`] on bad magics, inconsistent
/// headers or invalid match distances, [`CompError::OutputLimit`] when the
/// output would exceed `max_out`.
pub fn decompress(src: &[u8], max_out: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(max_out.min(1 << 22));
    let mut pos = 0usize;

    loop {
        if pos + 4 > src.len() {
            return Err(trunc(4));
        }
        let magic = le32(src, pos);
        match magic {
            EOS_MAGIC => return Ok(out),

            UNCOMPRESSED_MAGIC => {
                if pos + 8 > src.len() {
                    return Err(trunc(8));
                }
                let n = le32(src, pos + 4) as usize;
                pos += 8;
                if n > src.len() - pos {
                    return Err(trunc((n - (src.len() - pos)) as u64));
                }
                if n > max_out - out.len() {
                    return Err(limit(max_out));
                }
                out.extend_from_slice(&src[pos..pos + n]);
                pos += n;
            }

            LZVN_MAGIC => {
                if pos + 12 > src.len() {
                    return Err(trunc(12));
                }
                let n_raw = le32(src, pos + 4) as usize;
                let n_payload = le32(src, pos + 8) as usize;
                pos += 12;
                if n_payload > src.len() - pos {
                    return Err(trunc((n_payload - (src.len() - pos)) as u64));
                }
                let payload = &src[pos..pos + n_payload];
                let before = out.len();
                // The reference bounds the LZVN block's output window at
                // n_raw bytes and requires eos + full payload consumption.
                let block_cap = before.saturating_add(n_raw).min(max_out);
                match lzvn::decompress_into(payload, &mut out, block_cap) {
                    Ok(consumed) => {
                        if consumed != n_payload {
                            return Err(corrupt(
                                "lzfse lzvn block: payload not fully consumed",
                            ));
                        }
                        if out.len() - before != n_raw {
                            return Err(corrupt(
                                "lzfse lzvn block: wrong decoded size",
                            ));
                        }
                    }
                    Err(CompError::OutputLimit { .. }) if block_cap < max_out => {
                        return Err(corrupt(
                            "lzfse lzvn block: decoded size exceeds n_raw_bytes",
                        ));
                    }
                    Err(e) => return Err(e),
                }
                pos += n_payload;
            }

            COMPRESSED_V1_MAGIC => {
                pos = decode_compressed_block(src, pos, false, &mut out, max_out)?;
            }
            COMPRESSED_V2_MAGIC => {
                pos = decode_compressed_block(src, pos, true, &mut out, max_out)?;
            }

            _ => {
                return Err(corrupt(format!(
                    "lzfse: bad block magic {magic:#010x} at offset {pos}"
                )));
            }
        }
    }
}
