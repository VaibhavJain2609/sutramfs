//! LZ4 decompression — both the raw **block** format used inside f2fs and
//! squashfs (`decompress_block`) and the self-describing **frame** format
//! produced by the `lz4` CLI (`decompress_frame`).
//!
//! Block format (LZ4 spec): a sequence of *sequences*. Each sequence is a
//! token byte — high nibble = literal length (15 → extended by bytes of
//! 255, terminated by a byte < 255), then that many literal bytes, then a
//! u16 LE match offset, then the token's low nibble = match length − 4
//! (15 → same extension scheme). The final sequence holds literals only —
//! no trailing offset. Match copies may overlap (offset < length), which
//! yields RLE-style expansion.
//!
//! Frame format: magic `0x184D2204`, FLG/BD descriptor bytes, optional
//! content size and dictionary ID, a header checksum byte (xxh32 of the
//! descriptor >> 8), then LE32-sized blocks (high bit = stored raw), a
//! zero endmark, and an optional xxh32 content checksum. Skippable frames
//! (magic `0x184D2A5*`) are skipped silently.
//!
//! An in-crate XXH32 implementation validates frame checksums — no C deps.

use crate::{CompError, Result};

/// Maximum decompressed size accepted by [`decompress_frame`] when a frame
/// omits its content size — a hard ceiling against memory exhaustion, in
/// addition to the caller's `max_out`.
const FRAME_SCAN_LIMIT: u64 = 1 << 32;

/// Decompress one LZ4 **block**, producing at most `max_out` bytes.
///
/// `src` must be exactly the block's compressed bytes. Errors:
/// [`CompError::Truncated`] when the input ends mid-sequence or the last
/// sequence carries a (forbidden) match, [`CompError::Corrupt`] on a zero
/// or out-of-range match offset, [`CompError::OutputLimit`] when decoding
/// would exceed `max_out`.
pub fn decompress_block(src: &[u8], max_out: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(max_out.min(1 << 22));
    let mut pos = 0usize;
    while pos < src.len() {
        let token = src[pos];
        pos += 1;

        // Literal length: high nibble, extended by 255-bytes.
        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            lit_len = read_extended(src, &mut pos, lit_len)?;
        }
        let lit_end = pos
            .checked_add(lit_len)
            .ok_or_else(|| CompError::corrupt("lz4 literal length overflows"))?;
        if lit_end > src.len() {
            return Err(CompError::Truncated {
                needed: (lit_end - src.len()) as u64,
            });
        }
        push_out(&mut out, &src[pos..lit_end], max_out)?;
        pos = lit_end;

        // The last sequence ends after its literals — no offset.
        if pos == src.len() {
            break;
        }
        if pos + 2 > src.len() {
            return Err(CompError::Truncated { needed: 2 });
        }
        let off = u16::from_le_bytes([src[pos], src[pos + 1]]) as usize;
        pos += 2;

        // Match length: low nibble + 4, extended by 255-bytes.
        let mut match_len = (token & 0x0F) as usize;
        if match_len == 15 {
            match_len = read_extended(src, &mut pos, match_len)?;
        }
        match_len += 4;

        if off == 0 || off > out.len() {
            return Err(CompError::corrupt(format!(
                "lz4 match offset {off} invalid ({} bytes emitted)",
                out.len()
            )));
        }
        if out.len() + match_len > max_out {
            return Err(CompError::OutputLimit {
                limit: max_out as u64,
            });
        }
        // Byte-wise copy handles the legal overlap case (off < match_len).
        let start = out.len() - off;
        for i in 0..match_len {
            let b = out[start + i];
            out.push(b);
        }
    }
    Ok(out)
}

/// Read an LZ4 extended length field (run of 255 bytes, terminator < 255).
fn read_extended(src: &[u8], pos: &mut usize, base: usize) -> Result<usize> {
    let mut len = base;
    loop {
        if *pos >= src.len() {
            return Err(CompError::Truncated { needed: 1 });
        }
        let b = src[*pos];
        *pos += 1;
        len = len
            .checked_add(b as usize)
            .ok_or_else(|| CompError::corrupt("lz4 extended length overflows"))?;
        if b != 255 {
            return Ok(len);
        }
    }
}

fn push_out(out: &mut Vec<u8>, bytes: &[u8], max_out: usize) -> Result<()> {
    if out.len() + bytes.len() > max_out {
        return Err(CompError::OutputLimit {
            limit: max_out as u64,
        });
    }
    out.extend_from_slice(bytes);
    Ok(())
}

/// LZ4 frame magic (`0x184D2204`, little-endian on disk).
pub const FRAME_MAGIC: u32 = 0x184D2204;
/// Skippable-frame magic range base (`0x184D2A50`..=`0x184D2A5F`).
pub const SKIPPABLE_MAGIC: u32 = 0x184D2A50;

/// Decompress a whole LZ4 **frame** (or a concatenation of frames),
/// producing at most `max_out` bytes.
///
/// Validates the header checksum and, when present, the content checksum
/// (both XXH32). Blocks flagged "uncompressed" are copied verbatim.
/// Concatenated and skippable frames are handled; an empty trailing region
/// is an error.
pub fn decompress_frame(src: &[u8], max_out: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut frames = 0usize;
    while pos < src.len() {
        if pos + 4 > src.len() {
            return Err(CompError::Truncated { needed: 4 });
        }
        let magic = u32::from_le_bytes([src[pos], src[pos + 1], src[pos + 2], src[pos + 3]]);
        if (SKIPPABLE_MAGIC..SKIPPABLE_MAGIC + 16).contains(&magic) {
            if pos + 8 > src.len() {
                return Err(CompError::Truncated { needed: 8 });
            }
            let len = le32(src, pos + 4) as usize;
            let end = pos
                .checked_add(8)
                .and_then(|p| p.checked_add(len))
                .ok_or_else(|| CompError::corrupt("skippable frame size overflows"))?;
            if end > src.len() {
                return Err(CompError::Truncated {
                    needed: (end - src.len()) as u64,
                });
            }
            pos = end;
            continue;
        }
        if magic != FRAME_MAGIC {
            return Err(CompError::corrupt(format!(
                "lz4 frame magic {magic:#010x} != {FRAME_MAGIC:#010x}"
            )));
        }
        pos += 4;
        pos = decode_one_frame(src, pos, &mut out, max_out)?;
        frames += 1;
    }
    if frames == 0 {
        return Err(CompError::corrupt("no lz4 frame present"));
    }
    Ok(out)
}

/// Decode one frame starting after its magic; returns the position one
/// past the frame's endmark/checksum.
fn decode_one_frame(src: &[u8], mut pos: usize, out: &mut Vec<u8>, max_out: usize) -> Result<usize> {
    // FLG | BD | [content size 8B] | [dict id 4B] | HC
    if pos + 3 > src.len() {
        return Err(CompError::Truncated { needed: 3 });
    }
    let flg = src[pos];
    if flg >> 6 != 0b01 {
        return Err(CompError::unsupported(format!(
            "lz4 frame version {} (only 1 is defined)",
            flg >> 6
        )));
    }
    let block_indep = flg & 0x20 != 0;
    let block_checksum = flg & 0x10 != 0;
    let content_size_flag = flg & 0x08 != 0;
    let content_checksum = flg & 0x04 != 0;
    let dict_id_flag = flg & 0x01 != 0;
    let bd = src[pos + 1];
    if bd & 0x83 != 0 || bd & 0x08 != 0 {
        // Reserved bits 7,1,0 and bit 3 must be zero.
        return Err(CompError::corrupt(format!("lz4 BD byte {bd:#04x} sets reserved bits")));
    }
    let mut desc_len = 2usize;
    if content_size_flag {
        desc_len += 8;
    }
    if dict_id_flag {
        desc_len += 4;
    }
    if pos + desc_len + 1 > src.len() {
        return Err(CompError::Truncated {
            needed: (desc_len + 1) as u64,
        });
    }
    // Header checksum: second-lowest byte of xxh32(descriptor).
    let hc = (xxh32(&src[pos..pos + desc_len], 0) >> 8) as u8;
    if hc != src[pos + desc_len] {
        return Err(CompError::corrupt("lz4 frame header checksum mismatch"));
    }
    let declared_size = if content_size_flag {
        Some(u64::from_le_bytes(
            src[pos + 2..pos + 10].try_into().map_err(|_| {
                CompError::corrupt("lz4 content-size field short")
            })?,
        ))
    } else {
        None
    };
    pos += desc_len + 1;

    // If the frame declares a size, reject obviously impossible requests
    // early (a bomb declaring petabytes never reaches the allocator).
    if let Some(sz) = declared_size {
        if sz > max_out as u64 || sz > FRAME_SCAN_LIMIT {
            return Err(CompError::OutputLimit {
                limit: max_out as u64,
            });
        }
    }

    let frame_start_out = out.len();
    let mut prev_end = 0usize; // block-dependent mode: window base
    loop {
        if pos + 4 > src.len() {
            return Err(CompError::Truncated { needed: 4 });
        }
        let bh = le32(src, pos);
        pos += 4;
        if bh == 0 {
            break; // endmark
        }
        let raw = bh & 0x8000_0000 != 0;
        let blen = (bh & 0x7FFF_FFFF) as usize;
        if pos.checked_add(blen).is_none_or(|e| e > src.len()) {
            return Err(CompError::Truncated { needed: blen as u64 });
        }
        let block = &src[pos..pos + blen];
        pos += blen;
        if block_checksum {
            if pos + 4 > src.len() {
                return Err(CompError::Truncated { needed: 4 });
            }
            let want = le32(src, pos);
            pos += 4;
            if xxh32(block, 0) != want {
                return Err(CompError::corrupt("lz4 block checksum mismatch"));
            }
        }
        if raw {
            push_out(out, block, max_out)?;
        } else {
            // Block-independent (the only mode encoders emit in practice)
            // or linked: a linked block may reference up to 64 KiB of the
            // previous block's output — honour it by decoding against the
            // tail of `out`.
            if block_indep || prev_end == 0 {
                let d = decompress_block(block, max_out.saturating_sub(out.len()))?;
                push_out(out, &d, max_out)?;
            } else {
                decompress_block_linked(out, prev_end, block, max_out)?;
            }
        }
        prev_end = out.len();
        if out.len() > max_out {
            return Err(CompError::OutputLimit {
                limit: max_out as u64,
            });
        }
    }
    if content_checksum {
        if pos + 4 > src.len() {
            return Err(CompError::Truncated { needed: 4 });
        }
        let want = le32(src, pos);
        pos += 4;
        let mut h = Xxh32::new(0);
        h.update(&out[frame_start_out..]);
        if h.digest() != want {
            return Err(CompError::corrupt("lz4 frame content checksum mismatch"));
        }
    }
    if let Some(sz) = declared_size {
        if (out.len() - frame_start_out) as u64 != sz {
            return Err(CompError::corrupt(
                "lz4 frame content size does not match decoded output",
            ));
        }
    }
    Ok(pos)
}

/// Decode a block in linked mode: match offsets may reach up to 64 KiB
/// into `out[window_start..]` — i.e. the previous block's output.
fn decompress_block_linked(
    out: &mut Vec<u8>,
    window_start: usize,
    src: &[u8],
    max_out: usize,
) -> Result<()> {
    let mut pos = 0usize;
    while pos < src.len() {
        let token = src[pos];
        pos += 1;
        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            lit_len = read_extended(src, &mut pos, lit_len)?;
        }
        let lit_end = pos
            .checked_add(lit_len)
            .ok_or_else(|| CompError::corrupt("lz4 literal length overflows"))?;
        if lit_end > src.len() {
            return Err(CompError::Truncated {
                needed: (lit_end - src.len()) as u64,
            });
        }
        push_out(out, &src[pos..lit_end], max_out)?;
        pos = lit_end;
        if pos == src.len() {
            break;
        }
        if pos + 2 > src.len() {
            return Err(CompError::Truncated { needed: 2 });
        }
        let off = u16::from_le_bytes([src[pos], src[pos + 1]]) as usize;
        pos += 2;
        let mut match_len = (token & 0x0F) as usize;
        if match_len == 15 {
            match_len = read_extended(src, &mut pos, match_len)?;
        }
        match_len += 4;
        // Distance is measured against the whole output since the frame
        // started, not just this block.
        if off == 0 || off > out.len() - window_start {
            return Err(CompError::corrupt(format!(
                "lz4 linked match offset {off} invalid ({} bytes in window)",
                out.len() - window_start
            )));
        }
        if out.len() + match_len > max_out {
            return Err(CompError::OutputLimit {
                limit: max_out as u64,
            });
        }
        let start = out.len() - off;
        for i in 0..match_len {
            let b = out[start + i];
            out.push(b);
        }
    }
    Ok(())
}

fn le32(src: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([src[off], src[off + 1], src[off + 2], src[off + 3]])
}

// ---------------------------------------------------------------------------
// XXH32 — small in-crate implementation for frame checksum validation.
// (Spec: https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md)
// ---------------------------------------------------------------------------

const P1: u32 = 0x9E3779B1;
const P2: u32 = 0x85EBCA77;
const P3: u32 = 0xC2B2AE3D;
const P4: u32 = 0x27D4EB2F;
const P5: u32 = 0x165667B1;

/// XXH32 digest — exposed (doc-hidden) so callers can verify or generate
/// LZ4 frame header/content checksums without a second implementation.
#[doc(hidden)]
pub fn xxh32(data: &[u8], seed: u32) -> u32 {
    let mut h = Xxh32::new(seed);
    h.update(data);
    h.digest()
}

struct Xxh32 {
    acc: [u32; 4],
    buf: [u8; 16],
    buf_len: usize,
    total: u64,
    seed: u32,
}

impl Xxh32 {
    fn new(seed: u32) -> Self {
        Xxh32 {
            acc: [
                seed.wrapping_add(P1).wrapping_add(P2),
                seed.wrapping_add(P2),
                seed,
                seed.wrapping_sub(P1),
            ],
            buf: [0; 16],
            buf_len: 0,
            total: 0,
            seed,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (16 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 16 {
                let block = self.buf;
                self.stripe(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 16 {
            let (block, rest) = data.split_at(16);
            let mut b = [0u8; 16];
            b.copy_from_slice(block);
            self.stripe(&b);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn stripe(&mut self, block: &[u8; 16]) {
        for (i, acc) in self.acc.iter_mut().enumerate() {
            let lane = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
            *acc = acc
                .wrapping_add(lane.wrapping_mul(P2))
                .rotate_left(13)
                .wrapping_mul(P1);
        }
    }

    fn digest(&self) -> u32 {
        let mut h = if self.total >= 16 {
            self.acc[0]
                .rotate_left(1)
                .wrapping_add(self.acc[1].rotate_left(7))
                .wrapping_add(self.acc[2].rotate_left(12))
                .wrapping_add(self.acc[3].rotate_left(18))
        } else {
            self.seed.wrapping_add(P5)
        };
        h = h.wrapping_add(self.total as u32);
        let mut rem = &self.buf[..self.buf_len];
        while rem.len() >= 4 {
            let lane = u32::from_le_bytes([rem[0], rem[1], rem[2], rem[3]]);
            h = h
                .wrapping_add(lane.wrapping_mul(P3))
                .rotate_left(17)
                .wrapping_mul(P4);
            rem = &rem[4..];
        }
        for &b in rem {
            h = h
                .wrapping_add((b as u32).wrapping_mul(P5))
                .rotate_left(11)
                .wrapping_mul(P1);
        }
        h ^= h >> 15;
        h = h.wrapping_mul(P2);
        h ^= h >> 13;
        h = h.wrapping_mul(P3);
        h ^ (h >> 16)
    }
}
