//! Unit tests for the leaf decoders (fixup, runlists, FILETIME, INDX).

use crate::attr::{decode_runlist, filetime_ts, parse_fn};
use crate::lznt1;
use crate::record::apply_fixup;

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
