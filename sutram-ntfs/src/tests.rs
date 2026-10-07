//! Unit tests for the leaf decoders (fixup, runlists, FILETIME, INDX).

use crate::attr::{
    self, decode_runlist, filetime_ts, parse_attr, parse_attr_list, parse_ea, parse_fn,
    parse_object_id, parse_reparse, parse_si, parse_volume_information, parse_volume_name,
};
use sutram_compress::lznt1;
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
    // ≥2^63 FILETIME → unset (would wrap to a fabricated pre-epoch value)
    assert_eq!(filetime_ts(u64::MAX).value, None);
    assert_eq!(filetime_ts(i64::MAX as u64).value, None); // ×100 overflows
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

#[test]
fn hostile_runlist_readers_never_panic() {
    // VCN/LCN values whose byte offsets overflow u64 must not panic the
    // sparse/compressed readers (saturating arithmetic).
    use crate::attr::DataRun;
    use crate::fs::{CompressedReader, SparseReader, Stream};
    use std::io::Read;
    use std::sync::Arc;
    use sutram_io::ByteSource;

    let src: Arc<dyn ByteSource> = Arc::new(vec![0u8; 4096]);
    let mk = |compressed: bool| Stream {
        name: None,
        resident: None,
        runs: vec![
            DataRun {
                vcn: u64::MAX - 8,
                len: 4,
                lcn: Some(0x0020_0000_0000_0000), // lcn*4096 overflows u64
            },
            DataRun {
                vcn: 0,
                len: 16,
                lcn: Some(i64::MAX as u64), // saturates too
            },
            DataRun {
                vcn: 16,
                len: 4,
                lcn: None,
            },
        ],
        real_size: 16 * 4096,
        alloc_size: 16 * 4096,
        init_size: 0,
        compressed,
        sparse: true,
        encrypted: false,
        comp_shift: 4,
        attr_offsets: vec![],
    };
    // Sparse: must not panic — yields zeros/errors, never a crash.
    let mut r = SparseReader::new(src.clone(), mk(false), 4096);
    let mut buf = [0u8; 8192];
    let _ = r.read(&mut buf);
    // Compressed: unit read with a saturating LCN offset must not panic.
    let mut r = CompressedReader::new(src, mk(true), 4096);
    let _ = r.read(&mut buf);
}

// ---- $LogFile record interpretation ----------------------------------------

use crate::journal::{JournalEvent, JournalOp, LogOp, LogRecord};

/// Minimal LOG_RECORD for interpret() tests — only the fields the
/// interpreter reads are meaningful.
fn logrec(redo_op: u16, undo_op: u16, mft_cluster: u64, client_data: Vec<u8>) -> LogRecord {
    LogRecord {
        this_lsn: 0x1000,
        client_prev_lsn: 0,
        client_undo_next_lsn: 0,
        client_data_len: client_data.len() as u16,
        record_type: 1,
        transaction_id: 1,
        flags: 0,
        redo_op,
        undo_op,
        redo_offset: 0,
        redo_len: client_data.len() as u16,
        undo_offset: 0,
        undo_len: 0,
        target_attribute: 0,
        lcns_to_follow: 0,
        record_offset: 0,
        attr_list_offset: 0,
        mft_cluster_index: mft_cluster,
        client_data,
        disk_offset: None,
        extent: 0,
    }
}

/// INDEX_ENTRY payload: child ref + $FILE_NAME stream.
fn index_entry(child: u64, parent: u64, name: &str) -> Vec<u8> {
    let nb: Vec<u16> = name.encode_utf16().collect();
    let mut b = vec![0u8; 0x10 + 0x42 + nb.len() * 2];
    let entry_len = b.len() as u16;
    b[0..8].copy_from_slice(&child.to_le_bytes());
    b[8..10].copy_from_slice(&entry_len.to_le_bytes()); // entry_len
    b[0x0A..0x0C].copy_from_slice(&((0x42 + nb.len() * 2) as u16).to_le_bytes()); // stream_len
    b[0x10..0x18].copy_from_slice(&parent.to_le_bytes());
    b[0x50] = nb.len() as u8; // $FILE_NAME name_len
    for (i, u) in nb.iter().enumerate() {
        b[0x52 + i * 2..0x54 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    b
}

#[test]
fn logop_table_covers_documented_codes() {
    assert_eq!(LogOp::from_code(0x00), LogOp::Noop);
    assert_eq!(LogOp::from_code(0x02), LogOp::InitializeFileRecordSegment);
    assert_eq!(LogOp::from_code(0x0E), LogOp::AddIndexEntryAllocation);
    assert_eq!(LogOp::from_code(0x19), LogOp::CommitTransaction);
    assert_eq!(LogOp::from_code(0x21), LogOp::UpdateRecordDataAllocation);
    assert_eq!(LogOp::from_code(0x99), LogOp::Unknown(0x99));
    assert_eq!(LogOp::Unknown(0x99).name(), "unknown");
    assert_eq!(LogOp::HotFix.name(), "hot_fix");
}

#[test]
fn interpret_index_entry_recovers_filename() {
    let payload = index_entry(0x1_0000_0000_0011, 5, "BIG.BIN");
    let lr = logrec(0x0E, 0x0F, 0, payload);
    let it = lr.interpret(4096, 1024);
    assert_eq!(it.redo_op, LogOp::AddIndexEntryAllocation);
    assert_eq!(it.file_name.as_deref(), Some("BIG.BIN"));
    assert_eq!(it.child_ref, Some(0x1_0000_0000_0011));
    assert_eq!(it.parent_ref, Some(5));
    assert_eq!(it.attr_type, Some(0x30));
    assert!(it.detail.contains("BIG.BIN"));
}

#[test]
fn interpret_delete_ops_prefer_undo_payload() {
    // For a delete the removed state lives in the undo buffer.
    let mut lr = logrec(0x0D, 0x0C, 0, Vec::new());
    let undo_payload = index_entry(0x2_0000_0000_0014, 5, "GONE.TXT");
    lr.undo_len = undo_payload.len() as u16;
    lr.client_data = undo_payload;
    lr.client_data_len = lr.undo_len;
    let it = lr.interpret(4096, 1024);
    assert_eq!(it.file_name.as_deref(), Some("GONE.TXT"));
    assert_eq!(it.child_ref, Some(0x2_0000_0000_0014));
}

#[test]
fn interpret_cluster_floor_is_a_bound() {
    // mft_cluster_index=5, 4 records/cluster → floor record 20.
    let lr = logrec(0x03, 0x02, 5, Vec::new());
    let it = lr.interpret(4096, 1024);
    assert_eq!(it.mft_record, Some(20));
    assert!(it.record_is_bound);
}

#[test]
fn interpret_init_segment_reads_exact_record() {
    // Redo payload = new FILE record header; NTFS ≥3 stores the record
    // number at +0x2C — an exact target, not a bound.
    let mut payload = vec![0u8; 0x40];
    payload[0..4].copy_from_slice(b"FILE");
    payload[0x2C..0x30].copy_from_slice(&42u32.to_le_bytes());
    let lr = logrec(0x02, 0x03, 5, payload);
    let it = lr.interpret(4096, 1024);
    assert_eq!(it.mft_record, Some(42));
    assert!(!it.record_is_bound);
}

#[test]
fn interpret_update_filename_recovers_name() {
    // $FILE_NAME body payload: parent ref + length-prefixed UTF-16 name.
    let mut payload = vec![0u8; 0x42 + 8];
    payload[0..8].copy_from_slice(&5u64.to_le_bytes());
    payload[0x40] = 3; // "A.B" = 3 UTF-16 units
    for (i, u) in "A.B".encode_utf16().enumerate() {
        payload[0x42 + i * 2..0x44 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    let lr = logrec(0x12, 0x13, 0, payload);
    let it = lr.interpret(4096, 1024);
    assert_eq!(it.file_name.as_deref(), Some("A.B"));
    assert_eq!(it.parent_ref, Some(5));
}

#[test]
fn interpret_create_attribute_reads_type_and_name() {
    // Attribute header payload: type code + named-attribute fields.
    let mut payload = vec![0u8; 0x30];
    payload[0..4].copy_from_slice(&0x80u32.to_le_bytes()); // $DATA
    payload[0x09] = 3; // name_len
    payload[0x0A..0x0C].copy_from_slice(&0x18u16.to_le_bytes()); // name_off
    for (i, u) in "ADS".encode_utf16().enumerate() {
        payload[0x18 + i * 2..0x1A + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    let mut lr = logrec(0x05, 0x06, 0, payload);
    lr.target_attribute = 0x48;
    let it = lr.interpret(4096, 1024);
    assert_eq!(it.attr_type, Some(0x80));
    assert_eq!(it.attr_name.as_deref(), Some("ADS"));
    assert!(it.detail.contains("0x80"));
}

#[test]
fn interpret_garbage_payloads_do_not_panic() {
    // Truncated/absurd payloads degrade to a generic detail line.
    let lr = logrec(0x0E, 0x0F, 0, vec![0xAA; 3]);
    let it = lr.interpret(4096, 1024);
    assert!(it.file_name.is_none());
    assert!(it.detail.contains("unparsed"));
    // redo_len beyond the retained client data → no payload slice.
    let mut lr = logrec(0x12, 0x13, 0, vec![0u8; 4]);
    lr.redo_len = 0xFFFF;
    let it = lr.interpret(4096, 1024);
    assert!(it.file_name.is_none());
}

#[test]
fn journal_event_op_classification() {
    use crate::journal::UsnRecord;
    let usn = JournalEvent::Usn(UsnRecord {
        record_len: 0,
        major_version: 2,
        minor_version: 0,
        file_ref: 0,
        parent_ref: 0,
        usn: 0,
        filetime: 0,
        reason: 0,
        source_info: 0,
        security_id: 0,
        file_attributes: 0,
        name: String::new(),
        stream_offset: 0,
        disk_offset: Some(0),
    });
    assert_eq!(usn.op(), JournalOp::UsnChange);
    let lr = JournalEvent::LogRecord(logrec(0x19, 0x00, 0, Vec::new()));
    assert_eq!(lr.op(), JournalOp::Log(LogOp::CommitTransaction));
    let torn = JournalEvent::TornPage { disk_offset: 0 };
    assert_eq!(torn.op(), JournalOp::TornPage);
}

// ---- journal decoder coverage: USN v3, LFS pages, op tables -----------------

use crate::journal::{LogEvent, LogIter, RestartArea, UsnIter};

fn w16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// 4 KiB LFS page with a valid fixup USA (mirrors tests/common::lfs_page).
fn lfs_page(sig: &[u8; 4], patches: &[(usize, Vec<u8>)]) -> Vec<u8> {
    const SEQ: u16 = 0xA5A5;
    let mut page = vec![0u8; 0x1000];
    page[0..4].copy_from_slice(sig);
    let sectors = 0x1000 / 512;
    let usa_off = 8usize;
    w16(&mut page, 4, usa_off as u16);
    w16(&mut page, 6, (sectors + 1) as u16);
    for (off, bytes) in patches {
        page[*off..*off + bytes.len()].copy_from_slice(bytes);
    }
    w16(&mut page, usa_off, SEQ);
    for i in 0..sectors {
        let trailer = (i + 1) * 512 - 2;
        let orig = u16::from_le_bytes([page[trailer], page[trailer + 1]]);
        w16(&mut page, usa_off + 2 + i * 2, orig);
        w16(&mut page, trailer, SEQ);
    }
    page
}

/// USN_RECORD_V2 body (record_len, major=2 header + UTF-16 name at 0x3C).
fn usn_v2(file_ref: u64, usn: i64, reason: u32, name: &str) -> Vec<u8> {
    let nb = utf16le(name);
    let len = (0x3C + nb.len() + 7) & !7;
    let mut r = vec![0u8; len];
    w32(&mut r, 0, len as u32);
    w16(&mut r, 4, 2); // major
    w64(&mut r, 8, file_ref);
    w64(&mut r, 0x10, 5);
    w64(&mut r, 0x18, usn as u64);
    w64(&mut r, 0x20, 0x01D8_0000_0000_0000); // filetime
    w32(&mut r, 0x28, reason);
    w32(&mut r, 0x34, 0x20); // file_attributes
    w16(&mut r, 0x38, nb.len() as u16);
    w16(&mut r, 0x3A, 0x3C);
    r[0x3C..0x3C + nb.len()].copy_from_slice(&nb);
    r
}

/// USN_RECORD_V3 body — 128-bit refs (parser keeps the low 64 bits).
fn usn_v3(file_ref_low: u64, name: &str) -> Vec<u8> {
    let nb = utf16le(name);
    let len = (0x4C + nb.len() + 7) & !7;
    let mut r = vec![0u8; len];
    w32(&mut r, 0, len as u32);
    w16(&mut r, 4, 3); // major
    w64(&mut r, 8, file_ref_low); // file_ref low 64
    w64(&mut r, 0x10, 0xDEAD_BEEF); // file_ref high 64 (ignored)
    w64(&mut r, 0x18, 5); // parent_ref low 64
    w64(&mut r, 0x28, 0x2000); // usn
    w64(&mut r, 0x30, 0x01D8_0000_0000_0000); // filetime
    w32(&mut r, 0x38, 0x100); // reason: file_create
    w32(&mut r, 0x44, 0x20); // file_attributes
    w16(&mut r, 0x48, nb.len() as u16);
    w16(&mut r, 0x4A, 0x4C);
    r[0x4C..0x4C + nb.len()].copy_from_slice(&nb);
    r
}

#[test]
fn logop_every_documented_code_decodes() {
    // Every code in the ntfsdoc table maps to a named op; off-table codes
    // are Unknown and still carry their raw value.
    let expected = [
        (0x00, "noop"),
        (0x01, "compensation_log_record"),
        (0x02, "initialize_file_record_segment"),
        (0x03, "deallocate_file_record_segment"),
        (0x04, "write_end_of_file_record_segment"),
        (0x05, "create_attribute"),
        (0x06, "delete_attribute"),
        (0x07, "update_resident_value"),
        (0x08, "update_nonresident_value"),
        (0x09, "update_mapping_pairs"),
        (0x0A, "delete_dirty_clusters"),
        (0x0B, "set_new_attribute_sizes"),
        (0x0C, "add_index_entry_root"),
        (0x0D, "delete_index_entry_root"),
        (0x0E, "add_index_entry_allocation"),
        (0x0F, "delete_index_entry_allocation"),
        (0x10, "set_index_entry_vcn_root"),
        (0x11, "set_index_entry_vcn_allocation"),
        (0x12, "update_file_name_root"),
        (0x13, "update_file_name_allocation"),
        (0x14, "set_bits_in_nonresident_bitmap"),
        (0x15, "clear_bits_in_nonresident_bitmap"),
        (0x16, "hot_fix"),
        (0x17, "end_top_level_action"),
        (0x18, "prepare_transaction"),
        (0x19, "commit_transaction"),
        (0x1A, "forget_transaction"),
        (0x1B, "open_nonresident_attribute"),
        (0x1C, "open_attribute_table_dump"),
        (0x1D, "attribute_name_dump"),
        (0x1E, "dirty_page_table_dump"),
        (0x1F, "transaction_table_dump"),
        (0x20, "update_record_data_root"),
        (0x21, "update_record_data_allocation"),
    ];
    for (code, name) in expected {
        let op = LogOp::from_code(code);
        assert_eq!(op.name(), name, "code {code:#x}");
        assert!(!matches!(op, LogOp::Unknown(_)));
    }
    for code in [0x22u16, 0x50, 0xFFFF] {
        assert!(matches!(LogOp::from_code(code), LogOp::Unknown(c) if c == code));
    }
}

#[test]
fn interpret_remaining_op_families() {
    // UpdateResidentValue reports the resident rewrite.
    let lr = logrec(0x07, 0x00, 0, vec![0u8; 4]);
    assert!(lr.interpret(4096, 1024).detail.contains("resident attribute"));
    // UpdateMappingPairs reports a runlist rewrite.
    let lr = logrec(0x09, 0x00, 0, vec![0u8; 4]);
    assert!(lr.interpret(4096, 1024).detail.contains("runlist rewrite"));
    // SetNewAttributeSizes decodes the new size pair.
    let mut sizes = vec![0u8; 0x10];
    w64(&mut sizes, 0, 0x2000);
    w64(&mut sizes, 8, 0x1800);
    let lr = logrec(0x0B, 0x00, 0, sizes);
    let it = lr.interpret(4096, 1024);
    assert!(it.detail.contains("alloc=8192"));
    assert!(it.detail.contains("real=6144"));
    // Short size payload degrades to the generic detail.
    let lr = logrec(0x0B, 0x00, 0, vec![0u8; 4]);
    assert!(lr.interpret(4096, 1024).detail.contains("set_new_attribute_sizes"));
    // Bitmap set/clear ops report the bit span.
    let mut bits = vec![0u8; 8];
    w32(&mut bits, 0, 40);
    w32(&mut bits, 4, 3);
    let lr = logrec(0x14, 0x15, 0, bits);
    assert!(lr.interpret(4096, 1024).detail.contains("bitmap bits 40..+3"));
    // DeallocateFileRecordSegment.
    let lr = logrec(0x03, 0x02, 0, Vec::new());
    assert!(lr
        .interpret(4096, 1024)
        .detail
        .contains("deallocate file record segment"));
    // DeleteAttribute prefers the undo buffer and uses the "delete" verb.
    let mut hdr = vec![0u8; 0x30];
    w32(&mut hdr, 0, 0x80);
    let mut lr = logrec(0x06, 0x05, 0, Vec::new());
    lr.undo_len = hdr.len() as u16;
    lr.client_data = hdr;
    lr.client_data_len = lr.undo_len;
    let it = lr.interpret(4096, 1024);
    assert_eq!(it.attr_type, Some(0x80));
    assert!(it.detail.contains("delete attr 0x80"));
    // Ops with no dedicated decoder fall through to the generic detail.
    let lr = logrec(0x19, 0x00, 0, Vec::new());
    assert_eq!(
        lr.interpret(4096, 1024).detail,
        "commit_transaction (undo noop)"
    );
}

#[test]
fn interpret_short_payloads_degrade() {
    // $FILE_NAME body too short → no name, generic detail.
    let lr = logrec(0x12, 0x13, 0, vec![0u8; 8]);
    let it = lr.interpret(4096, 1024);
    assert!(it.file_name.is_none());
    // Index-entry payload with an impossible header → unparsed.
    let mut bad = vec![0u8; 0x60];
    w16(&mut bad, 8, 0x08); // entry_len < 0x10
    let lr = logrec(0x0C, 0x0D, 0, bad);
    let it = lr.interpret(4096, 1024);
    assert!(it.file_name.is_none());
    assert!(it.detail.contains("unparsed"));
    // Attribute header too short / implausible type → not decoded.
    let lr = logrec(0x05, 0x06, 0, vec![0u8; 8]);
    assert!(lr.interpret(4096, 1024).attr_type.is_none());
    let mut hdr = vec![0u8; 0x30];
    w32(&mut hdr, 0, 0xFFFF_FFFF);
    let lr = logrec(0x05, 0x06, 0, hdr);
    assert!(lr.interpret(4096, 1024).attr_type.is_none());
}

#[test]
fn journal_event_op_covers_restart_and_checkpoint() {
    let ra = RestartArea {
        current_lsn: 0x4A00,
        log_clients: 1,
        client_free_lsn_idx: 0,
        client_inuse_lsn_idx: 0,
        seq_nr_bits: 34,
        restart_area_len: 0x36,
        file_size: 0x4000,
        last_lsn_data_len: 0x48,
        record_page_len: 0x1000,
        disk_offset: 0,
    };
    assert_eq!(JournalEvent::Restart(ra).op(), JournalOp::LogRestart);
    let chk = JournalEvent::Checkpoint {
        lsn: 0x4A00,
        disk_offset: 0,
    };
    assert_eq!(chk.op(), JournalOp::LogCheckpoint);
}

#[test]
fn usn_iter_decodes_v3_records() {
    let mut buf = usn_v3(0x0042_0000_0000_0017, "WIDE.DAT");
    // A v4 record follows — same 128-bit layout.
    let mut v4 = usn_v3(0x18, "V4.TXT");
    w16(&mut v4, 4, 4);
    buf.extend_from_slice(&v4);
    let it = UsnIter::new(buf, vec![], false);
    let recs: Vec<_> = it.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].major_version, 3);
    assert_eq!(recs[0].file_ref, 0x0042_0000_0000_0017);
    assert_eq!(recs[0].name, "WIDE.DAT");
    assert_eq!(recs[1].major_version, 4);
    // No allocated regions were supplied → no disk provenance.
    assert_eq!(recs[0].disk_offset, None);
}

#[test]
fn usn_iter_maps_stream_to_disk_offsets() {
    let buf = usn_v2(17, 0x1000, 0x100, "MAPPED.TXT");
    let len = buf.len() as u64;
    // The $J run starts at disk offset 0x100_000.
    let it = UsnIter::new(buf, vec![(0, 0x100_000, len)], false);
    let recs: Vec<_> = it.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(recs[0].disk_offset, Some(0x100_000));
    // A region that ends before the record leaves disk_offset unset.
    let buf = usn_v2(17, 0x1000, 0x100, "MAPPED.TXT");
    let it = UsnIter::new(buf, vec![(0, 0x100_000, 8)], false);
    let recs: Vec<_> = it.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(recs[0].disk_offset, None);
}

#[test]
fn usn_iter_resynchronises_and_strict_stops() {
    // record_len < USN_MIN → Corrupt item; the scan resyncs at +8 and
    // finds the following valid record.
    let mut buf = Vec::new();
    buf.extend_from_slice(&8u32.to_le_bytes()); // len=8, rest zeros
    buf.extend_from_slice(&[0u8; 4]);
    buf.extend_from_slice(&usn_v2(18, 0x1080, 0x200, "AFTER.TXT"));
    let items: Vec<_> = UsnIter::new(buf.clone(), vec![], false).collect();
    assert!(items[0].is_err());
    assert_eq!(
        items[1].as_ref().unwrap().name,
        "AFTER.TXT",
        "lenient scan must resynchronise"
    );
    // Strict mode: the first error ends the stream.
    let items: Vec<_> = UsnIter::new(buf, vec![], true).collect();
    assert_eq!(items.len(), 1);
    assert!(items[0].is_err());
}

#[test]
fn usn_iter_reports_hostile_records() {
    // Unsupported major version → Corrupt.
    let mut bad = usn_v2(1, 1, 0, "X");
    w16(&mut bad, 4, 9);
    let items: Vec<_> = UsnIter::new(bad, vec![], false).collect();
    let e = items[0].as_ref().unwrap_err();
    assert!(format!("{e}").contains("major version"));
    // name_len escaping the record → Corrupt.
    let mut bad = usn_v2(1, 1, 0, "X");
    w16(&mut bad, 0x38, 0x4000);
    let items: Vec<_> = UsnIter::new(bad, vec![], false).collect();
    let e = items[0].as_ref().unwrap_err();
    assert!(format!("{e}").contains("filename escapes"));
}

#[test]
fn logiter_decodes_rcrd_chkd_baad_and_skips_garbage() {
    // One valid LOG_RECORD (commit) at the RCRD data offset.
    let mut rec = vec![0u8; 0x50];
    w64(&mut rec, 0x00, 0x5000); // this_lsn
    w16(&mut rec, 0x18, 8); // client_data_len
    w32(&mut rec, 0x1C, 1); // record_type
    w32(&mut rec, 0x20, 7); // transaction_id
    w16(&mut rec, 0x28, 0x19); // redo_op = commit
    rec[0x48..0x50].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    // Two bogus candidates: absurd LCN count, then an extent that would
    // overflow the page — both are probed past, never emitted.
    let mut bogus1 = vec![0u8; 0x48];
    w64(&mut bogus1, 0, 0x6000);
    w16(&mut bogus1, 0x36, 100); // lcns_to_follow — implausible
    let mut bogus2 = vec![0u8; 0x48];
    w64(&mut bogus2, 0, 0x6001);
    w16(&mut bogus2, 0x18, 0xF000); // extent runs off the page
    let rcrd = lfs_page(
        b"RCRD",
        &[(0x40, rec), (0x90, bogus1), (0x98, bogus2)],
    );
    let baad = lfs_page(b"BAAD", &[]);
    let chkd = lfs_page(b"CHKD", &[(0x30, 0x4A00u64.to_le_bytes().to_vec())]);
    let garbage = vec![0xEEu8; 0x1000]; // non-LFS page — skipped silently
    let mut buf = Vec::new();
    for p in [&rcrd, &baad, &chkd, &garbage] {
        buf.extend_from_slice(p);
    }
    let it = LogIter::new(buf, vec![(0, 0x200_000, 4 * 0x1000)], 512, false);
    let evs: Vec<_> = it.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(evs.len(), 3, "{evs:?}");
    match &evs[0] {
        LogEvent::Record(r) => {
            assert_eq!(r.this_lsn, 0x5000);
            assert_eq!(r.redo_op, 0x19);
            assert_eq!(r.disk_offset, Some(0x200_000 + 0x40));
            assert_eq!(r.client_data.len(), 8);
        }
        other => panic!("expected record, got {other:?}"),
    }
    assert!(matches!(evs[1], LogEvent::Torn { .. }));
    assert!(matches!(evs[2], LogEvent::Checkpoint { lsn: 0x4A00, .. }));
}

#[test]
fn logiter_without_regions_has_no_disk_provenance() {
    let mut rec = vec![0u8; 0x50];
    w64(&mut rec, 0, 0x5000);
    let page = lfs_page(b"RCRD", &[(0x40, rec)]);
    let it = LogIter::new(page, vec![], 512, false);
    let evs: Vec<_> = it.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(evs.len(), 1);
    match &evs[0] {
        LogEvent::Record(r) => assert_eq!(r.disk_offset, None),
        other => panic!("expected record, got {other:?}"),
    }
}

#[test]
fn logiter_fixup_failure_lenient_and_strict() {
    // A torn RSTR page (sector-trailer/USA mismatch) followed by a clean
    // CHKD page: lenient yields the error then keeps scanning.
    let mut torn = lfs_page(b"RSTR", &[(0x30, vec![0u8; 0x36])]);
    torn[510] ^= 0xFF;
    let chkd = lfs_page(b"CHKD", &[(0x30, 0x4A00u64.to_le_bytes().to_vec())]);
    let mut buf = torn.clone();
    buf.extend_from_slice(&chkd);
    let items: Vec<_> = LogIter::new(buf.clone(), vec![], 512, false).collect();
    assert!(items[0].is_err());
    assert!(matches!(items[1], Ok(LogEvent::Checkpoint { .. })));
    // Strict: the error is terminal.
    let items: Vec<_> = LogIter::new(buf, vec![], 512, true).collect();
    assert_eq!(items.len(), 1);
    assert!(items[0].is_err());
}

#[test]
fn logiter_restart_and_torn_disk_offsets() {
    let rstr = lfs_page(b"RSTR", &[(0x30, {
        let mut a = vec![0u8; 0x36];
        w64(&mut a, 0, 0x4A00);
        w16(&mut a, 0x1E, 0x36);
        a
    })]);
    let it = LogIter::new(rstr, vec![(0, 0x300_000, 0x1000)], 512, false);
    let evs: Vec<_> = it.collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(evs.len(), 1);
    match &evs[0] {
        LogEvent::Restart(ra) => {
            assert_eq!(ra.current_lsn, 0x4A00);
            assert_eq!(ra.disk_offset, 0x300_000);
        }
        other => panic!("expected restart area, got {other:?}"),
    }
}

#[test]
fn metafile_names_cover_reserved_slots() {
    let names = [
        "$MFT", "$MFTMirr", "$LogFile", "$Volume", "$AttrDef", ".", "$Bitmap", "$Boot",
        "$BadClus", "$Secure", "$UpCase", "$Extend",
    ];
    for (i, want) in names.iter().enumerate() {
        assert_eq!(crate::walk::metafile_name(i as u64), Some(*want));
    }
    assert_eq!(crate::walk::metafile_name(12), None);
    assert_eq!(crate::walk::metafile_name(16), None);
}
