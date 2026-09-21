//! Unit tests for the leaf decoders (fixup, runlists, FILETIME, INDX).

use crate::attr::{
    self, decode_runlist, filetime_ts, parse_attr, parse_attr_list, parse_ea, parse_fn,
    parse_object_id, parse_reparse, parse_si, parse_volume_information, parse_volume_name,
};
use crate::lznt1;
use crate::record::{apply_fixup, apply_indx_fixup, parse_record};

#[test]
fn fixup_applies_and_verifies() {
    // 1024-byte record, 512-byte sectors: USA at 0x30.
    let mut rec = vec![0u8; 1024];
    rec[0..4].copy_from_slice(b"FILE");
    rec[4..6].copy_from_slice(&0x30u16.to_le_bytes()); // usa off
    rec[6..8].copy_from_slice(&3u16.to_le_bytes()); // usa count
    // USA: [seq, sec0_tail, sec1_tail]
    rec[0x30..0x32].copy_from_slice(&0xAAAAu16.to_le_bytes());
    rec[0x32..0x34].copy_from_slice(&0x1111u16.to_le_bytes());
    rec[0x34..0x36].copy_from_slice(&0x2222u16.to_le_bytes());
    // trailers currently hold the sequence number
    rec[510..512].copy_from_slice(&0xAAAAu16.to_le_bytes());
    rec[1022..1024].copy_from_slice(&0xAAAAu16.to_le_bytes());

    apply_fixup(&mut rec, 0x4000, 0x30, 3, 512).unwrap();
    assert_eq!(&rec[510..512], &[0x11, 0x11]);
    assert_eq!(&rec[1022..1024], &[0x22, 0x22]);
}

#[test]
fn fixup_rejects_torn_sector() {
    let mut rec = vec![0u8; 1024];
    rec[4..6].copy_from_slice(&0x30u16.to_le_bytes());
    rec[6..8].copy_from_slice(&3u16.to_le_bytes());
    rec[0x30..0x32].copy_from_slice(&0xAAAAu16.to_le_bytes());
    rec[510..512].copy_from_slice(&0xBBBBu16.to_le_bytes()); // stale trailer
    rec[1022..1024].copy_from_slice(&0xAAAAu16.to_le_bytes());
    assert!(apply_fixup(&mut rec, 0, 0x30, 3, 512).is_err());
}

#[test]
fn runlist_decodes_delta_and_sparse() {
    // run1: len 2 at LCN 0x100 → header 0x21 (1B len, 2B off), len 02, off 00 01
    // run2: sparse len 3 → header 0x01, len 03 (no offset field)
    // run3: len 1 at LCN 0x90 (delta -0x70) → header 0x11, len 01, off 0x90
    let rl = [0x21u8, 0x02, 0x00, 0x01, 0x01, 0x03, 0x11, 0x01, 0x90, 0x00];
    let runs = decode_runlist(&rl, 0, 0).unwrap();
    assert_eq!(runs.len(), 3);
    assert_eq!(runs[0].lcn, Some(0x100));
    assert_eq!(runs[0].len, 2);
    assert_eq!(runs[1].lcn, None); // sparse
    assert_eq!(runs[1].vcn, 2);
    assert_eq!(runs[2].lcn, Some(0x90));
    assert_eq!(runs[2].vcn, 5);
}

#[test]
fn runlist_rejects_garbage() {
    assert!(decode_runlist(&[0x99u8, 0x01], 0, 0).is_err()); // len_sz 9
    assert!(decode_runlist(&[0x10u8], 0, 0).is_err()); // truncated
}

#[test]
fn filetime_decode() {
    // 2024-01-15T10:30:20Z = 1_705_314_620 s since Unix epoch
    let raw: u64 = 116_444_736_000_000_000 + 1_705_314_620 * 10_000_000;
    let t = filetime_ts(raw);
    assert_eq!(t.value, Some(1_705_314_620_000_000_000));
    assert_eq!(t.raw_encoding, "ntfs-filetime");
    // zero FILETIME → unset, never fabricated
    assert_eq!(filetime_ts(0).value, None);
}

#[test]
fn fn_name_decodes_utf16() {
    let name: Vec<u16> = "HELLO.TXT".encode_utf16().collect();
    let mut body = vec![0u8; 0x42 + name.len() * 2];
    body[0..8].copy_from_slice(&5u64.to_le_bytes()); // parent = root
    body[0x40] = name.len() as u8;
    body[0x41] = 1; // WIN32
    for (i, u) in name.iter().enumerate() {
        body[0x42 + i * 2..0x42 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
    }
    let f = parse_fn(&body).unwrap();
    assert_eq!(f.name, "HELLO.TXT");
    assert_eq!(f.parent_ref, 5);
    assert_eq!(f.namespace, 1);
}

#[test]
fn lznt1_literals_only() {
    // One compressed chunk, flag byte 0x00 → 8 literal bytes.
    let payload = [0x00u8, b'H', b'E', b'L', b'L', b'O', b' ', b'W', b'D'];
    let mut unit = Vec::new();
    let hdr = 0x8000u16 | 0x3000 | ((payload.len() as u16) - 1);
    unit.extend_from_slice(&hdr.to_le_bytes());
    unit.extend_from_slice(&payload);
    let (out, clean) = lznt1::decompress_unit(&unit, 4096);
    assert!(clean);
    assert_eq!(&out[..8], b"HELLO WD");
}

#[test]
fn lznt1_backreference() {
    // flag 0x02: bit0 literal 'A', bit1 match. At emitted=1 → 12 offset
    // bits / 4 length bits: token = ((off-1)<<4)|(len-3).
    // off=1 (copy previous byte), len=5 → token = (0<<4)|2 = 0x0002.
    let payload = [0x02u8, b'A', 0x02, 0x00];
    let mut unit = Vec::new();
    let hdr = 0x8000u16 | 0x3000 | ((payload.len() as u16) - 1);
    unit.extend_from_slice(&hdr.to_le_bytes());
    unit.extend_from_slice(&payload);
    let (out, clean) = lznt1::decompress_unit(&unit, 4096);
    assert!(clean);
    assert_eq!(&out, b"AAAAAA"); // 'A' + 5 copied
}

#[test]
fn lznt1_uncompressed_chunk() {
    let mut unit = Vec::new();
    let hdr = 0x0003u16; // not compressed, payload len 4
    unit.extend_from_slice(&hdr.to_le_bytes());
    unit.extend_from_slice(b"raw!");
    let (out, _clean) = lznt1::decompress_unit(&unit, 4096);
    assert_eq!(&out, b"raw!");
}

#[test]
fn fixup_rejects_bad_usa_geometry() {
    // Record size not a multiple of the sector size.
    let mut rec = vec![0u8; 1000];
    assert!(apply_fixup(&mut rec, 0, 0x30, 3, 512).is_err());
    // USA count != sectors + 1.
    let mut rec = vec![0u8; 1024];
    assert!(apply_fixup(&mut rec, 0, 0x30, 2, 512).is_err());
    // USA extends past the end of the record.
    let mut rec = vec![0u8; 1024];
    assert!(apply_fixup(&mut rec, 0, 1020, 3, 512).is_err());
}

#[test]
fn parse_record_rejects_bad_records() {
    // Too short.
    assert!(parse_record(vec![0u8; 32], 0, 0, 512).is_err());
    // Bad signature.
    let mut rec = vec![0u8; 1024];
    rec[0..4].copy_from_slice(b"XXXX");
    assert!(parse_record(rec, 0, 0, 512).is_err());
    // Bad first-attribute offset (points inside the header).
    let mut rec = vec![0u8; 1024];
    rec[0..4].copy_from_slice(b"FILE");
    rec[4..6].copy_from_slice(&0x30u16.to_le_bytes());
    rec[6..8].copy_from_slice(&3u16.to_le_bytes());
    rec[0x30..0x32].copy_from_slice(&0xAAAAu16.to_le_bytes());
    rec[510..512].copy_from_slice(&0xAAAAu16.to_le_bytes());
    rec[1022..1024].copy_from_slice(&0xAAAAu16.to_le_bytes());
    rec[20..22].copy_from_slice(&0x10u16.to_le_bytes()); // first_attr_off too low
    assert!(parse_record(rec, 0, 0, 512).is_err());
}

#[test]
fn parse_record_accepts_baad() {
    let mut rec = vec![0u8; 1024];
    rec[0..4].copy_from_slice(b"BAAD");
    rec[4..6].copy_from_slice(&0x30u16.to_le_bytes());
    rec[6..8].copy_from_slice(&3u16.to_le_bytes());
    rec[0x30..0x32].copy_from_slice(&0xAAAAu16.to_le_bytes());
    rec[510..512].copy_from_slice(&0xAAAAu16.to_le_bytes());
    rec[1022..1024].copy_from_slice(&0xAAAAu16.to_le_bytes());
    rec[20..22].copy_from_slice(&0x38u16.to_le_bytes());
    let r = parse_record(rec, 0x8000, 7, 512).unwrap();
    assert_eq!(&r.signature, b"BAAD");
    assert_eq!(r.record_no, 7);
    assert!(!r.in_use());
    assert!(!r.is_dir());
}

#[test]
fn indx_fixup_checks_signature() {
    let mut blk = vec![0u8; 4096];
    assert!(apply_indx_fixup(&mut blk, 0, 512).is_err()); // no INDX magic
    blk[0..4].copy_from_slice(b"INDX");
    blk[4..6].copy_from_slice(&0x28u16.to_le_bytes());
    blk[6..8].copy_from_slice(&9u16.to_le_bytes());
    blk[0x28..0x2A].copy_from_slice(&0x5A5Au16.to_le_bytes());
    for i in 0..8 {
        let t = (i + 1) * 512 - 2;
        blk[t..t + 2].copy_from_slice(&0x5A5Au16.to_le_bytes());
    }
    apply_indx_fixup(&mut blk, 0, 512).unwrap();
}

#[test]
fn runlist_rejects_malformed_runs() {
    // len_sz == 0.
    assert!(decode_runlist(&[0x10u8, 0x01, 0x00], 0, 0).is_err());
    // Run truncated mid-field.
    assert!(decode_runlist(&[0x21u8, 0x02, 0x00], 0, 0).is_err());
    // Zero-length run.
    assert!(decode_runlist(&[0x11u8, 0x00, 0x05, 0x00], 0, 0).is_err());
    // Negative LCN: first run delta -4.
    assert!(decode_runlist(&[0x11u8, 0x01, 0xFC, 0x00], 0, 0).is_err());
    // VCN overflow: len = u64::MAX followed by any second run.
    let rl = [
        0x88u8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x11, 0x01, 0x01, 0x00,
    ];
    assert!(decode_runlist(&rl, 0, 0).is_err());
    // 8-byte signed offset already *is* i64 — no bogus sign extension.
    let rl = [
        0x81u8, 0x05, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let runs = decode_runlist(&rl, 0, 0).unwrap();
    assert_eq!(runs[0].lcn, Some(0x10));
}

#[test]
fn parse_attr_header_errors() {
    // Attribute length smaller than a header.
    let mut a = vec![0u8; 0x40];
    a[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    a[4..8].copy_from_slice(&0x10u32.to_le_bytes());
    assert!(parse_attr(&rec_with(&a), 0, 0).is_err());
    // Attribute length running past the record.
    a[4..8].copy_from_slice(&0xFFFFu32.to_le_bytes());
    assert!(parse_attr(&rec_with(&a), 0, 0).is_err());
    // Name out of bounds.
    let mut a = vec![0u8; 0x40];
    a[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    a[4..8].copy_from_slice(&0x40u32.to_le_bytes());
    a[9] = 4; // name_len
    a[10..12].copy_from_slice(&0xF0u16.to_le_bytes()); // name_off near record end
    assert!(parse_attr(&rec_with(&a), 0, 0).is_err());
    // Non-resident header shorter than 0x40.
    let mut a = vec![0u8; 0x28];
    a[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    a[4..8].copy_from_slice(&0x28u32.to_le_bytes());
    a[8] = 1; // non-resident
    assert!(parse_attr(&rec_with(&a), 0, 0).is_err());
    // Non-resident runlist offset beyond the attribute.
    let mut a = vec![0u8; 0x48];
    a[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    a[4..8].copy_from_slice(&0x48u32.to_le_bytes());
    a[8] = 1;
    a[32..34].copy_from_slice(&0x60u16.to_le_bytes()); // runs_off > len
    assert!(parse_attr(&rec_with(&a), 0, 0).is_err());
}

/// Helper: place `blob` at offset 0 inside a zeroed record buffer.
fn rec_with(blob: &[u8]) -> Vec<u8> {
    let mut rec = vec![0u8; 1024];
    rec[..blob.len()].copy_from_slice(blob);
    rec
}

#[test]
fn resident_content_bounds() {
    // content_off + content_len must fit inside the attribute length.
    let mut a = vec![0u8; 0x40];
    a[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    a[4..8].copy_from_slice(&0x40u32.to_le_bytes());
    a[16..20].copy_from_slice(&0x100u32.to_le_bytes()); // content_len huge
    a[20..22].copy_from_slice(&0x18u16.to_le_bytes());
    assert!(parse_attr(&rec_with(&a), 0, 0).is_err());
}

#[test]
fn payload_decoders_lenient() {
    assert!(parse_si(&[0u8; 0x20]).is_none()); // too short
    assert!(parse_fn(&[0u8; 0x20]).is_none());
    assert!(parse_object_id(&[0u8; 8]).is_none());
    assert!(parse_volume_name(&[0u8; 0]).is_none());
    assert!(parse_volume_name("OK".encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<_>>().as_slice()).is_some());
    assert_eq!(parse_volume_information(&[0u8; 8]), None);
    assert_eq!(
        parse_volume_information(&{
            let mut b = [0u8; 10];
            b[8] = 3;
            b[9] = 1;
            b
        }),
        Some((3, 1))
    );
    // Reparse: too short, non-symlink tag, and a real symlink buffer.
    assert!(parse_reparse(&[0u8; 4]).is_none());
    let mut rp = vec![0u8; 0x20];
    rp[0..4].copy_from_slice(&0xA000_0003u32.to_le_bytes()); // mount point tag
    assert_eq!(parse_reparse(&rp).unwrap().1, None);
}

#[test]
fn attr_list_and_ea_edge_cases() {
    // Empty body, terminator, and bad entry length.
    assert!(parse_attr_list(&[], 0).unwrap().is_empty());
    let mut body = vec![0u8; 0x40];
    body[0..4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    assert!(parse_attr_list(&body, 0).unwrap().is_empty());
    body[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    body[4..6].copy_from_slice(&0x08u16.to_le_bytes()); // elen < 0x1A
    assert!(parse_attr_list(&body, 0).is_err());
    // EA chain: two entries then terminator.
    let mut ea = Vec::new();
    let mut e1 = vec![0u8; 16];
    e1[0..4].copy_from_slice(&16u32.to_le_bytes());
    e1[5] = 2;
    e1[8..10].copy_from_slice(b"AB");
    ea.extend_from_slice(&e1);
    let mut e2 = vec![0u8; 16];
    e2[5] = 2;
    e2[8..10].copy_from_slice(b"CD");
    ea.extend_from_slice(&e2);
    let names: Vec<String> = parse_ea(&ea).into_iter().map(|(n, _)| n).collect();
    assert_eq!(names, ["AB", "CD"]);
    assert_eq!(attr::file_ref_rec(0x0005_0000_0000_0042), 0x42);
}

#[test]
fn lznt1_malformed_bodies() {
    // EOS marker (zero header) ends the stream cleanly.
    let unit = vec![0u8; 4];
    let (out, clean) = lznt1::decompress_unit(&unit, 4096);
    assert!(out.is_empty() && clean);
    // Truncated raw chunk: salvage what exists.
    let mut unit = Vec::new();
    unit.extend_from_slice(&0x00FFu16.to_le_bytes()); // raw chunk, 256 B claimed
    unit.extend_from_slice(b"partial");
    let (out, clean) = lznt1::decompress_unit(&unit, 4096);
    assert!(!clean);
    assert_eq!(&out, b"partial");
    // Bad signature bits on a compressed chunk.
    let mut unit = Vec::new();
    unit.extend_from_slice(&0x9000u16.to_le_bytes()); // compressed, sig != 0b011
    unit.extend_from_slice(&[0u8; 8]);
    let (out, clean) = lznt1::decompress_unit(&unit, 4096);
    assert!(!clean && out.is_empty());
    // Match token before any literal → not clean.
    let payload = [0x01u8, 0x00, 0x00]; // flag bit0 = match at emitted 0
    let mut unit = Vec::new();
    let hdr = 0x8000u16 | 0x3000 | ((payload.len() as u16) - 1);
    unit.extend_from_slice(&hdr.to_le_bytes());
    unit.extend_from_slice(&payload);
    let (_out, clean) = lznt1::decompress_unit(&unit, 4096);
    assert!(!clean);
    // looks_compressed heuristic.
    assert!(lznt1::looks_compressed(&[0xFF, 0xB0]));
    assert!(!lznt1::looks_compressed(&[0xFF, 0x10]));
    assert!(!lznt1::looks_compressed(&[0x00]));
}

#[test]
fn lznt1_offset_bits_slide() {
    // Build a chunk that emits >16 bytes then a back-reference: the
    // offset/length split must have slid to 11/5 bits at emitted ≥17.
    // flag 0x00 → 8 literals ×2 groups (16 bytes), then flag 0x01 → match.
    let mut body = vec![0x00u8];
    body.extend_from_slice(b"ABCDEFGH");
    body.push(0x00);
    body.extend_from_slice(b"IJKLMNOP");
    // At emitted=16 → still 12 offset bits? emitted <= 16 → 12/4.
    // off=16 (back to 'A'), len=6 → token = (15<<4)|(6-3) = 0x00F3.
    body.push(0x01);
    body.extend_from_slice(&0x00F3u16.to_le_bytes());
    let mut unit = Vec::new();
    let hdr = 0x8000u16 | 0x3000 | ((body.len() as u16) - 1);
    unit.extend_from_slice(&hdr.to_le_bytes());
    unit.extend_from_slice(&body);
    let (out, clean) = lznt1::decompress_unit(&unit, 4096);
    assert!(clean);
    assert_eq!(&out[..16], b"ABCDEFGHIJKLMNOP");
    assert_eq!(&out[16..22], b"ABCDEF");
}
