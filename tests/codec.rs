//! Codec test suite: hand-crafted vectors, round-trips through in-dev-dep
//! encoders, hostile-input sweeps (truncation prefixes, byte corruption,
//! PRNG garbage) — nothing may panic.

use sutram_compress::{lz4, lzfse, lznt1, lzo1x, lzvn, zlib, zstd, CompError};

/// Deterministic xorshift64 PRNG — no external `rand` dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

// ---------------------------------------------------------------------------
// LZNT1
// ---------------------------------------------------------------------------

/// Build a compression unit: uncompressed chunk + eos.
fn lznt1_raw_unit(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    let hdr = (data.len() - 1) as u16; // compressed bit clear
    v.extend_from_slice(&hdr.to_le_bytes());
    v.extend_from_slice(data);
    v.extend_from_slice(&0u16.to_le_bytes()); // eos
    v
}

#[test]
fn lznt1_uncompressed_chunk() {
    let unit = lznt1_raw_unit(b"EVIDENCE");
    let (out, clean) = lznt1::decompress_unit(&unit, 0x10000);
    assert!(clean);
    assert_eq!(out, b"EVIDENCE");
    assert_eq!(lznt1::decompress(&unit, 0x10000).unwrap(), b"EVIDENCE");
}

#[test]
fn lznt1_compressed_chunk_literals_and_match() {
    // flags 0x02: bit0 = literal 'A', bit1 = match token; token 0x0000 →
    // offset 1, len 3 → "AAAA". payload = 4 bytes; hdr = sig|comp|len-1.
    let mut unit = Vec::new();
    let body = [0x02u8, b'A', 0x00, 0x00];
    let hdr = 0x8000u16 | 0x3000 | (body.len() as u16 - 1);
    unit.extend_from_slice(&hdr.to_le_bytes());
    unit.extend_from_slice(&body);
    unit.extend_from_slice(&0u16.to_le_bytes());
    assert!(lznt1::looks_compressed(&unit));

    let (out, clean) = lznt1::decompress_unit(&unit, 0x10000);
    assert!(clean);
    assert_eq!(out, b"AAAA");
}

#[test]
fn lznt1_raw_stored_unit_passes_looks_check() {
    // A unit whose first header lacks the signature is "stored raw" —
    // decompress_unit reports clean=false so callers fall back to raw.
    let raw = b"\xAA\xBB not actually lznt1";
    let (out, clean) = lznt1::decompress_unit(raw, 0x10000);
    assert!(!clean);
    let _ = out;
    assert!(lznt1::decompress(raw, 0x10000).is_err());
}

#[test]
fn lznt1_bad_match_offset() {
    // flags 0x01: first token is a match with emitted==0 → corrupt.
    let mut unit = Vec::new();
    let body = [0x01u8, 0x10, 0x00];
    let hdr = 0x8000u16 | 0x3000 | (body.len() as u16 - 1);
    unit.extend_from_slice(&hdr.to_le_bytes());
    unit.extend_from_slice(&body);
    unit.extend_from_slice(&0u16.to_le_bytes());
    assert!(matches!(
        lznt1::decompress(&unit, 0x10000),
        Err(CompError::Corrupt { .. })
    ));
}

// ---------------------------------------------------------------------------
// LZ4
// ---------------------------------------------------------------------------

#[test]
fn lz4_block_literals_only() {
    // token 0x40: 4 literals, no match.
    let block = [0x40, b'A', b'B', b'C', b'D'];
    assert_eq!(lz4::decompress_block(&block, 1024).unwrap(), b"ABCD");
}

#[test]
fn lz4_block_match() {
    // literals "ABCD", offset 4, match len 4 → "ABCDABCD".
    let block = [0x40, b'A', b'B', b'C', b'D', 0x04, 0x00];
    assert_eq!(lz4::decompress_block(&block, 1024).unwrap(), b"ABCDABCD");
}

#[test]
fn lz4_block_rle_overlap() {
    // literal 'x', offset 1, match len 10 → 'x' * 11.
    let block = [0x16, b'x', 0x01, 0x00];
    assert_eq!(lz4::decompress_block(&block, 1024).unwrap(), b"xxxxxxxxxxx");
}

#[test]
fn lz4_block_extended_lengths() {
    // literal len 15+3=18 via extension byte; then literals only.
    let mut block = vec![0xF0, 3];
    block.extend_from_slice(&[b'Q'; 18]);
    assert_eq!(lz4::decompress_block(&block, 1024).unwrap(), vec![b'Q'; 18]);
}

#[test]
fn lz4_block_offset_zero_corrupt() {
    let block = [0x10, b'A', 0x00, 0x00];
    assert!(matches!(
        lz4::decompress_block(&block, 1024),
        Err(CompError::Corrupt { .. })
    ));
}

#[test]
fn lz4_block_output_limit() {
    let block = [0x16, b'x', 0x01, 0x00]; // decodes to 11 bytes
    assert!(matches!(
        lz4::decompress_block(&block, 5),
        Err(CompError::OutputLimit { .. })
    ));
}

/// Build a minimal lz4 frame (version 1, block-independent, no checksums)
/// containing one *raw* block.
fn lz4_frame_raw(payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&lz4::FRAME_MAGIC.to_le_bytes());
    f.push(0x60); // FLG: v1, block indep
    f.push(0x40); // BD: 64 KiB max block
    let hc = (lz4::xxh32(&[0x60, 0x40], 0) >> 8) as u8;
    f.push(hc);
    f.extend_from_slice(&(payload.len() as u32 | 0x8000_0000).to_le_bytes());
    f.extend_from_slice(payload);
    f.extend_from_slice(&0u32.to_le_bytes()); // endmark
    f
}

#[test]
fn lz4_frame_raw_block() {
    let frame = lz4_frame_raw(b"forensics!");
    assert_eq!(lz4::decompress_frame(&frame, 1024).unwrap(), b"forensics!");
}

#[test]
fn lz4_frame_compressed_block() {
    let block = [0x40, b'A', b'B', b'C', b'D', 0x04, 0x00];
    let mut f = Vec::new();
    f.extend_from_slice(&lz4::FRAME_MAGIC.to_le_bytes());
    f.push(0x60);
    f.push(0x40);
    f.push((lz4::xxh32(&[0x60, 0x40], 0) >> 8) as u8);
    f.extend_from_slice(&(block.len() as u32).to_le_bytes());
    f.extend_from_slice(&block);
    f.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(lz4::decompress_frame(&f, 1024).unwrap(), b"ABCDABCD");
}

#[test]
fn lz4_frame_content_checksum() {
    // FLG 0x64: block-indep + content checksum.
    let payload = b"checksum me";
    let mut f = Vec::new();
    f.extend_from_slice(&lz4::FRAME_MAGIC.to_le_bytes());
    f.push(0x64);
    f.push(0x40);
    f.push((lz4::xxh32(&[0x64, 0x40], 0) >> 8) as u8);
    f.extend_from_slice(&(payload.len() as u32 | 0x8000_0000).to_le_bytes());
    f.extend_from_slice(payload);
    f.extend_from_slice(&0u32.to_le_bytes());
    f.extend_from_slice(&lz4::xxh32(payload, 0).to_le_bytes());
    assert_eq!(lz4::decompress_frame(&f, 1024).unwrap(), payload);

    // Corrupt the checksum → Corrupt.
    let n = f.len();
    f[n - 1] ^= 0xFF;
    assert!(matches!(
        lz4::decompress_frame(&f, 1024),
        Err(CompError::Corrupt { .. })
    ));
}

#[test]
fn lz4_frame_bad_magic_and_hc() {
    assert!(lz4::decompress_frame(b"\xDE\xAD\xBE\xEF", 1024).is_err());
    let mut f = lz4_frame_raw(b"x");
    f[6] ^= 0xFF; // header checksum byte
    assert!(matches!(
        lz4::decompress_frame(&f, 1024),
        Err(CompError::Corrupt { .. })
    ));
}

#[test]
fn lz4_frame_skippable_then_real() {
    let mut f = Vec::new();
    f.extend_from_slice(&lz4::SKIPPABLE_MAGIC.to_le_bytes());
    f.extend_from_slice(&4u32.to_le_bytes());
    f.extend_from_slice(b"skip");
    f.extend_from_slice(&lz4_frame_raw(b"data"));
    assert_eq!(lz4::decompress_frame(&f, 1024).unwrap(), b"data");
}

// ---------------------------------------------------------------------------
// LZVN
// ---------------------------------------------------------------------------

#[test]
fn lzvn_small_literal() {
    // sml_l len 5 "HELLO", then eos.
    let mut s = vec![0xE5];
    s.extend_from_slice(b"HELLO");
    s.push(0x06);
    s.extend_from_slice(&[0; 7]);
    assert_eq!(lzvn::decompress(&s, 1024).unwrap(), b"HELLO");
}

#[test]
fn lzvn_large_literal() {
    // lrg_l: 0xE0, len-16 byte, literal, eos.
    let payload = vec![b'Z'; 200];
    let mut s = vec![0xE0, (200 - 16) as u8];
    s.extend_from_slice(&payload);
    s.push(0x06);
    s.extend_from_slice(&[0; 7]);
    assert_eq!(lzvn::decompress(&s, 1024).unwrap(), payload);
}

#[test]
fn lzvn_small_dist() {
    // sml_l "ABC"; sml_d L=0,M=3,D=3 (opc 0x00, byte 0x03); eos.
    let s = [
        0xE3, b'A', b'B', b'C', 0x00, 0x03, 0x06, 0, 0, 0, 0, 0, 0, 0,
    ];
    assert_eq!(lzvn::decompress(&s, 1024).unwrap(), b"ABCABC");
}

#[test]
fn lzvn_lit_then_match_then_previous_dist() {
    // sml_l "ABAB"; sml_d L=0 M=3 D=4 → +"ABA"; pre_d reuses D=4.
    let mut s = vec![0xE4];
    s.extend_from_slice(b"ABAB");
    // sml_d: L=0 (opc>>6), M=3 ((opc>>3)&7 = 0), D-hi bits = opc&7.
    // D=4 → opc&7=0, second byte=4 → opc = 0x00.
    s.extend_from_slice(&[0x00, 0x04]);
    // pre_d: LLMMM110 — opc 70 = L=1, M=3, D=prev(4); one literal 'C'.
    s.push(70);
    s.push(b'C');
    s.push(0x06);
    s.extend_from_slice(&[0; 7]);
    // "ABAB" + "ABA" + "C" + match 3 @ D=4 → "ABA".
    assert_eq!(lzvn::decompress(&s, 1024).unwrap(), b"ABABABACABA");
}

#[test]
fn lzvn_nop_and_eos() {
    let s = [0x0E, 0x16, 0xE1, b'Q', 0x06, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(lzvn::decompress(&s, 1024).unwrap(), b"Q");
}

#[test]
fn lzvn_undefined_opcode() {
    let s = [0x1E, 0x06, 0, 0, 0, 0, 0, 0, 0]; // 0x1E = udef
    assert!(matches!(
        lzvn::decompress(&s, 1024),
        Err(CompError::Corrupt { .. })
    ));
}

#[test]
fn lzvn_match_before_output() {
    // sml_m as the very first opcode — no previous distance.
    let s = [0xF5, 0x06, 0, 0, 0, 0, 0, 0, 0];
    assert!(matches!(
        lzvn::decompress(&s, 1024),
        Err(CompError::Corrupt { .. })
    ));
}

#[test]
fn lzvn_truncated_no_eos() {
    let s = [0xE5, b'H', b'E', b'L']; // literal claims 5, only 3 + no eos
    assert!(matches!(
        lzvn::decompress(&s, 1024),
        Err(CompError::Truncated { .. })
    ));
}

#[test]
fn lzvn_output_limit() {
    let mut s = vec![0xE5];
    s.extend_from_slice(b"HELLO");
    s.push(0x06);
    s.extend_from_slice(&[0; 7]);
    assert!(matches!(
        lzvn::decompress(&s, 3),
        Err(CompError::OutputLimit { .. })
    ));
}

// ---------------------------------------------------------------------------
// LZO1X
// ---------------------------------------------------------------------------

#[test]
fn lzo1x_round_trip() {
    let data: Vec<u8> = (0..20_000u32).map(|i| (i / 97) as u8).collect();
    let comp = lzokay::compress::compress(&data).unwrap();
    assert!(comp.len() < data.len());
    assert_eq!(lzo1x::decompress(&comp, data.len()).unwrap(), data);
}

#[test]
fn lzo1x_round_trip_with_headroom() {
    // max_out larger than the real output — reported length is exact.
    let data = b"compressible compressible compressible compressible";
    let comp = lzokay::compress::compress(data).unwrap();
    let out = lzo1x::decompress(&comp, 1 << 20).unwrap();
    assert_eq!(out, data);
}

#[test]
fn lzo1x_output_limit() {
    let data = vec![7u8; 4096];
    let comp = lzokay::compress::compress(&data).unwrap();
    assert!(matches!(
        lzo1x::decompress(&comp, 100),
        Err(CompError::OutputLimit { .. })
    ));
}

// ---------------------------------------------------------------------------
// zlib / deflate
// ---------------------------------------------------------------------------

#[test]
fn zlib_round_trip() {
    let data = b"The quick brown fox jumps over the lazy dog. ".repeat(50);
    let comp = miniz_oxide::deflate::compress_to_vec_zlib(&data, 6);
    assert_eq!(zlib::decompress_zlib(&comp, 1 << 20).unwrap(), data);
}

#[test]
fn deflate_round_trip() {
    let data = b"bare deflate stream".repeat(20);
    let comp = miniz_oxide::deflate::compress_to_vec(&data, 6);
    assert_eq!(zlib::decompress_deflate(&comp, 1 << 20).unwrap(), data);
}

#[test]
fn zlib_output_limit() {
    let data = vec![b'A'; 10_000];
    let comp = miniz_oxide::deflate::compress_to_vec_zlib(&data, 6);
    assert!(matches!(
        zlib::decompress_zlib(&comp, 5000),
        Err(CompError::OutputLimit { .. })
    ));
}

#[test]
fn zlib_streaming_reader() {
    use std::io::Read;
    let data = b"streamed zlib payload ".repeat(30);
    let comp = miniz_oxide::deflate::compress_to_vec_zlib(&data, 6);
    let mut out = Vec::new();
    zlib::ZlibDecoder::new(&comp)
        .read_to_end(&mut out)
        .unwrap();
    assert_eq!(out, data);
}

// ---------------------------------------------------------------------------
// zstd (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "zstd")]
#[test]
fn zstd_round_trip() {
    let data = b"zstd payload payload payload ".repeat(100);
    let comp = ruzstd::encoding::compress_to_vec(
        data.as_slice(),
        ruzstd::encoding::CompressionLevel::Fastest,
    );
    assert_eq!(zstd::decompress(&comp, 1 << 20).unwrap(), data);
}

#[cfg(feature = "zstd")]
#[test]
fn zstd_output_limit() {
    let data = vec![0xAB; 50_000];
    let comp = ruzstd::encoding::compress_to_vec(
        data.as_slice(),
        ruzstd::encoding::CompressionLevel::Fastest,
    );
    assert!(matches!(
        zstd::decompress(&comp, 1000),
        Err(CompError::OutputLimit { .. })
    ));
}

#[cfg(not(feature = "zstd"))]
#[test]
fn zstd_stub_unsupported() {
    assert!(matches!(
        zstd::decompress(b"anything", 1024),
        Err(CompError::Unsupported { .. })
    ));
}

// ---------------------------------------------------------------------------
// LZFSE stub
// ---------------------------------------------------------------------------

#[test]
fn lzfse_is_honest_stub() {
    assert!(matches!(
        lzfse::decompress(b"whatever", 1024),
        Err(CompError::Unsupported { .. })
    ));
}

// ---------------------------------------------------------------------------
// Hostile-input sweeps — the whole point of the crate. No panics allowed.
// ---------------------------------------------------------------------------

type DecodeFn = fn(&[u8], usize) -> sutram_compress::Result<Vec<u8>>;

fn decoders() -> Vec<(&'static str, DecodeFn)> {
    let mut v: Vec<(&'static str, DecodeFn)> = vec![
        ("lznt1", lznt1::decompress),
        ("lz4-block", lz4::decompress_block),
        ("lz4-frame", lz4::decompress_frame),
        ("lzvn", lzvn::decompress),
        ("lzo1x", lzo1x::decompress),
        ("zlib", zlib::decompress_zlib),
        ("deflate", zlib::decompress_deflate),
        ("lzfse", lzfse::decompress),
    ];
    v.push(("zstd", zstd::decompress));
    v
}

/// A battery of valid inputs, one per decoder family, to slice/corrupt.
fn valid_inputs() -> Vec<Vec<u8>> {
    let data = b"hostile input test vector, reasonably compressible".repeat(8);
    vec![
        lznt1_raw_unit(b"abcabc"),
        {
            // lz4 block
            vec![0x40, b'A', b'B', b'C', b'D', 0x04, 0x00]
        },
        lz4_frame_raw(b"lz4 frame payload"),
        {
            // lzvn
            let mut s = vec![0xE3];
            s.extend_from_slice(b"ABC");
            s.extend_from_slice(&[0x00, 0x03, 0x06, 0, 0, 0, 0, 0, 0, 0]);
            s
        },
        lzokay::compress::compress(&data).unwrap(),
        miniz_oxide::deflate::compress_to_vec_zlib(&data, 6),
        miniz_oxide::deflate::compress_to_vec(&data, 6),
    ]
}

#[test]
fn no_panic_on_truncation_prefixes() {
    for (name, f) in decoders() {
        for input in valid_inputs() {
            for end in 0..input.len() {
                // Must return Ok or Err — never panic.
                let _ = f(&input[..end], 1 << 20);
            }
        }
        let _ = name;
    }
}

#[test]
fn no_panic_on_single_byte_corruption() {
    for (_name, f) in decoders() {
        for input in valid_inputs() {
            for i in 0..input.len() {
                for delta in [1u8, 0x7F, 0xFF] {
                    let mut bad = input.clone();
                    bad[i] = bad[i].wrapping_add(delta);
                    let _ = f(&bad, 1 << 20);
                }
            }
        }
    }
}

#[test]
fn no_panic_on_prng_garbage() {
    let mut rng = Rng(0x9E3779B97F4A7C15);
    for (_name, f) in decoders() {
        for _ in 0..2048 {
            let len = (rng.next() % 512) as usize;
            let mut buf = vec![0u8; len];
            for b in &mut buf {
                *b = rng.next() as u8;
            }
            let _ = f(&buf, 1 << 16);
        }
    }
}

#[test]
fn no_panic_on_structured_garbage() {
    // Garbage seeded with valid magic/opcode bytes so decoders get deeper.
    let mut rng = Rng(0xDEADBEEFCAFEF00D);
    let seeds = [
        0x06u8, 0xE0, 0xF0, 0x40, 0x22, 0x4D, 0x18, 0xB0, 0x00, 0xFF, 0x78, 0x9C,
    ];
    for (_name, f) in decoders() {
        for _ in 0..2048 {
            let len = (rng.next() % 512) as usize;
            let mut buf = vec![0u8; len];
            for b in &mut buf {
                *b = seeds[(rng.next() as usize) % seeds.len()]
                    .wrapping_add(rng.next() as u8 & 0x1F);
            }
            let _ = f(&buf, 1 << 16);
        }
    }
}
