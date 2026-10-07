//! Integration tests for the ZIP parser over synthetic archives.
//!
//! The corpus covers: stored + deflated members, a hidden (unreferenced)
//! local file header, a local↔central anomaly, an archive comment,
//! a data-descriptor member, a self-extracting stub, truncation, and
//! magic verdicts (masquerade + container-consistent).

mod common;

use std::io::Read;
use std::sync::Arc;

use common::zip::{crc32, ZipBuilder, DOS_DATE, DOS_TIME, FLAG_DD, METHOD_DEFLATE, METHOD_STORE};
use sutram_archive::ZipParser;
use sutram_fs::{DetectConfidence, FsEntry, FsEntryStatus, FsParser, MountOptions, RecoveryState};
use sutram_io::ByteSource;
use sutram_magic::{MagicType, Severity};

fn src(bytes: Vec<u8>) -> Arc<dyn ByteSource> {
    Arc::new(bytes)
}

fn clean_zip() -> Vec<u8> {
    let mut b = ZipBuilder::new();
    b.add_member("hello.txt", b"hello world!", METHOD_STORE, 0, &[], &[]);
    b.add_member(
        "dir/more.txt",
        b"deflated deflate deflate deflate deflate!",
        METHOD_DEFLATE,
        0,
        &[],
        b"entry comment",
    );
    b.add_member("dir/", b"", METHOD_STORE, 0, &[], &[]);
    b.finish(b"archive comment")
}

fn entries(img: Vec<u8>) -> Vec<FsEntry> {
    let fs = ZipParser.mount(src(img)).unwrap();
    fs.walk()
        .collect::<Result<Vec<_>, _>>()
        .expect("clean corpus walks without errors")
}

fn find<'a>(es: &'a [FsEntry], path: &str) -> &'a FsEntry {
    es.iter().find(|e| e.path == path).unwrap_or_else(|| {
        panic!(
            "{path} not found; got {:?}",
            es.iter().map(|e| &e.path).collect::<Vec<_>>()
        )
    })
}

#[test]
fn detects_clean_zip() {
    assert_eq!(
        ZipParser.detect(src(clean_zip()).as_ref()),
        DetectConfidence::Certain
    );
}

#[test]
fn rejects_garbage() {
    assert_eq!(
        ZipParser.detect(&vec![0u8; 4096].as_slice()),
        DetectConfidence::None
    );
    assert_eq!(
        ZipParser.detect(&b"PK\x99\x99 nonsense".to_vec().as_slice()),
        DetectConfidence::None
    );
}

#[test]
fn detect_streaming_zip_without_eocd() {
    let img = ZipBuilder::new().finish_no_eocd();
    // No members at all → no LFH at 0 → None.
    assert_eq!(ZipParser.detect(&img.as_slice()), DetectConfidence::None);
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"data", METHOD_STORE, 0, &[], &[]);
    let img = b.finish_no_eocd();
    assert_eq!(ZipParser.detect(&img.as_slice()), DetectConfidence::High);
}

#[test]
fn walks_live_members() {
    let es = entries(clean_zip());
    let paths: Vec<&str> = es.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"/"));
    assert!(paths.contains(&"/hello.txt"));
    assert!(paths.contains(&"/dir/more.txt"));
    assert!(paths.contains(&"/dir"));
}

#[test]
fn read_file_stored_and_deflated() {
    let fs = ZipParser.mount(src(clean_zip())).unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let hello = find(&es, "/hello.txt");
    let mut r = fs.read_file(hello).unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"hello world!");

    let deflated = find(&es, "/dir/more.txt");
    let mut r = fs.read_file(deflated).unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"deflated deflate deflate deflate deflate!");
    assert_eq!(deflated.meta["compression_method"], "deflate");
    assert_eq!(deflated.size, 41);
}

#[test]
fn hidden_member_is_deleted_intact() {
    let mut b = ZipBuilder::new();
    b.add_member("visible.txt", b"shown", METHOD_STORE, 0, &[], &[]);
    let hidden_off = b.add_hidden("secret.txt", b"suppressed evidence", METHOD_STORE);
    let img = b.finish(b"");

    let fs = ZipParser.mount(src(img)).unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let hidden = find(&es, "/secret.txt");
    assert_eq!(
        hidden.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    );
    assert_eq!(hidden.meta["hidden_entry"], "true");
    assert_eq!(hidden.disk_offset, hidden_off);
    // …and the data really reads back.
    let mut r = fs.read_file(hidden).unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"suppressed evidence");
}

#[test]
fn central_local_mismatch_flags_anomaly() {
    let mut b = ZipBuilder::new();
    b.add_member("mismatch.bin", b"0123456789", METHOD_STORE, 0, &[], &[]);
    // Tamper: central directory claims deflate + different CRC.
    {
        let cd = b.last_cd_mut();
        cd.method = METHOD_DEFLATE;
        cd.crc32 = 0xDEAD_BEEF;
    }
    let img = b.finish(b"");
    let es = entries(img);
    let e = find(&es, "/mismatch.bin");
    let anomaly = &e.meta["anomaly"];
    assert!(anomaly.contains("method"), "anomaly={anomaly}");
    assert!(anomaly.contains("crc32"), "anomaly={anomaly}");
    assert_eq!(e.meta["compression_method"], "deflate");
}

#[test]
fn comments_propagate() {
    let img = clean_zip();
    let fs = ZipParser.mount(src(img)).unwrap();
    assert_eq!(fs.info().meta["comment"], "archive comment");
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    assert_eq!(find(&es, "/dir/more.txt").meta["comment"], "entry comment");
}

#[test]
fn dos_timestamp_decodes() {
    let es = entries(clean_zip());
    let e = find(&es, "/hello.txt");
    let m = e.timestamps.modified.as_ref().unwrap();
    assert_eq!(m.raw_encoding, "dos-datetime");
    assert_eq!(m.raw_value, ((DOS_DATE as u64) << 16) | DOS_TIME as u64);
    // 2024-01-15 12:30:00 UTC = 1705321800 s → ns.
    assert_eq!(m.value, Some(1_705_321_800_000_000_000));
}

#[test]
fn data_descriptor_member_roundtrips() {
    let mut b = ZipBuilder::new();
    b.add_member(
        "streamed.txt",
        b"written before sizes known",
        METHOD_STORE,
        FLAG_DD,
        &[],
        &[],
    );
    let img = b.finish(b"");
    let es = entries(img);
    let e = find(&es, "/streamed.txt");
    // LFH zero-sizes under bit 3 are expected — not an anomaly.
    assert!(!e.meta.contains_key("anomaly"), "{:?}", e.meta);
    assert_eq!(e.meta["data_descriptor"], "true");
    assert_eq!(e.size, 26);
}

#[test]
fn sfx_stub_members_still_found() {
    let mut b = ZipBuilder::new();
    b.add_member(
        "payload.exe",
        b"MZ but not really",
        METHOD_STORE,
        0,
        &[],
        &[],
    );
    let inner = b.finish(b"");
    // Prepend a stub *without* fixing recorded offsets — the classic SFX.
    let stub: Vec<u8> = (0..64)
        .map(|i| if i % 2 == 0 { 0x4D } else { 0x5A })
        .collect();
    let mut img = stub.clone();
    img.extend_from_slice(&inner);

    let fs = ZipParser.mount(src(img)).unwrap();
    assert_eq!(fs.info().meta["archive_base"], "0x40");
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/payload.exe");
    let mut r = fs.read_file(e).unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"MZ but not really");
}

#[test]
fn no_eocd_lenient_lists_hidden_members() {
    let mut b = ZipBuilder::new();
    b.add_member("only.txt", b"orphaned", METHOD_STORE, 0, &[], &[]);
    let img = b.finish_no_eocd();
    let fs = ZipParser.mount(src(img)).unwrap();
    let mut saw_err = false;
    let mut found = false;
    for item in fs.walk() {
        match item {
            Err(_) => saw_err = true,
            Ok(e) if e.path == "/only.txt" => {
                found = true;
                assert!(e.is_deleted());
                assert_eq!(e.meta["hidden_entry"], "true");
            }
            _ => {}
        }
    }
    assert!(saw_err && found);
}

#[test]
fn no_eocd_strict_mount_fails() {
    let mut b = ZipBuilder::new();
    b.add_member("only.txt", b"x", METHOD_STORE, 0, &[], &[]);
    let img = b.finish_no_eocd();
    let r = ZipParser.mount_with(src(img), &MountOptions::strict());
    assert!(r.is_err());
}

#[test]
fn truncated_member_data_flagged() {
    let mut b = ZipBuilder::new();
    b.add_member("short.bin", b"1234567890", METHOD_STORE, 0, &[], &[]);
    // CD claims 20 stored bytes but only 10 exist.
    b.last_cd_mut().comp_size = 20;
    b.last_cd_mut().uncomp_size = 20;
    let img = b.finish(b"");
    let es = entries(img);
    let e = find(&es, "/short.bin");
    assert_eq!(e.meta["data_truncated"], "true");
}

#[test]
fn magic_verdicts() {
    let mut b = ZipBuilder::new();
    // PNG content under .png — consistent.
    let png = b"\x89PNG\r\n\x1a\nfakepngbody".to_vec();
    b.add_member("ok.png", &png, METHOD_STORE, 0, &[], &[]);
    // MZ content under .docx — masquerade, Severity::High.
    let mz = b"MZ\x90\x00not-a-document".to_vec();
    b.add_member("evil.docx", &mz, METHOD_STORE, 0, &[], &[]);
    // Deflated PNG — verdict must work through decompression.
    b.add_member("packed.png", &png, METHOD_DEFLATE, 0, &[], &[]);
    let es = entries(b.finish(b""));

    let ok = find(&es, "/ok.png").magic.as_ref().unwrap();
    assert_eq!(ok.detected, Some(MagicType::Png));
    assert!(!ok.mismatch);

    let evil = find(&es, "/evil.docx").magic.as_ref().unwrap();
    assert_eq!(evil.severity, Severity::High);
    assert!(evil.mismatch);

    let packed = find(&es, "/packed.png").magic.as_ref().unwrap();
    assert_eq!(packed.detected, Some(MagicType::Png));
}

#[test]
fn unicode_and_cp437_names() {
    let mut b = ZipBuilder::new();
    b.add_member("ünïcödé.txt", b"u", METHOD_STORE, 0x0800, &[], &[]);
    let es = entries(b.finish(b""));
    let e = find(&es, "/ünïcödé.txt");
    assert_eq!(e.meta["utf8_name"], "true");
}

#[test]
fn zip_slip_name_sanitised() {
    let mut b = ZipBuilder::new();
    b.add_member("../escape.txt", b"zip slip", METHOD_STORE, 0, &[], &[]);
    let es = entries(b.finish(b""));
    let e = find(&es, "/__/escape.txt");
    assert_eq!(e.meta["raw_name"], "../escape.txt");
}

#[test]
fn encrypted_member_flagged_and_unreadable() {
    let mut b = ZipBuilder::new();
    // Header lies about encryption (flag only) — data is plaintext bytes;
    // the parser must flag it and refuse reads rather than emit garbage.
    b.add_member(
        "locked.zip",
        b"pretend-ciphertext",
        METHOD_STORE,
        0x0001,
        &[],
        &[],
    );
    let img = b.finish(b"");
    let fs = ZipParser.mount(src(img)).unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/locked.zip");
    assert_eq!(e.meta["encrypted"], "true");
    assert!(fs.read_file(e).is_err());
}

#[test]
fn info_reports_geometry() {
    let fs = ZipParser.mount(src(clean_zip())).unwrap();
    let info = fs.info();
    assert_eq!(info.fs_type, "ZIP");
    assert_eq!(info.meta["entries"], "3");
    assert_eq!(info.meta["hidden_entries"], "0");
    assert_eq!(info.meta["eocd_found"], "true");
}

#[test]
fn unallocated_ranges_cover_gaps() {
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"data", METHOD_STORE, 0, &[], &[]);
    let img = b.finish(b"");
    let fs = ZipParser.mount(src(img)).unwrap();
    // A fully-packed archive leaves no unallocated slack.
    assert_eq!(
        fs.unallocated_ranges().iter().map(|(_, l)| l).sum::<u64>(),
        0
    );
}

#[test]
fn slack_gap_between_members_is_unallocated() {
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"data", METHOD_STORE, 0, &[], &[]);
    b.buf.extend_from_slice(&[0u8; 37]); // unreferenced gap
    b.add_member("b.txt", b"data2", METHOD_STORE, 0, &[], &[]);
    let img = b.finish(b"");
    let fs = ZipParser.mount(src(img)).unwrap();
    let gaps: Vec<(u64, u64)> = fs.unallocated_ranges();
    assert!(gaps.iter().any(|(_, l)| *l == 37), "{gaps:?}");
}

#[test]
fn corrupt_central_record_is_lenient_error_item() {
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"data", METHOD_STORE, 0, &[], &[]);
    b.add_member("b.txt", b"data2", METHOD_STORE, 0, &[], &[]);
    let mut img = b.finish(b"");
    // Corrupt the *second* central record's signature.
    let cd_off = {
        // find EOCD: last 22 bytes
        let n = img.len();
        u32::from_le_bytes([img[n - 6], img[n - 5], img[n - 4], img[n - 3]]) as usize
    };
    // second CD record offset = cd_off + 46 + name_len(5)
    let second = cd_off + 46 + 5;
    img[second] = 0xFF;
    let fs = ZipParser.mount(src(img)).unwrap();
    let mut paths = Vec::new();
    let mut saw_err = false;
    for item in fs.walk() {
        match item {
            Ok(e) => paths.push(e.path),
            Err(_) => saw_err = true,
        }
    }
    assert!(paths.contains(&"/a.txt".to_string()));
    assert!(saw_err, "corrupt CD record should surface as an Err item");
}

#[test]
fn walk_terminates_on_garbage_no_panic() {
    // Garbage that merely happens to end in an EOCD-like tail.
    let mut img = vec![0xABu8; 512];
    img.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
    img.extend_from_slice(&[0u8; 18]);
    let _ = ZipParser.detect(&img.as_slice());
    if let Ok(fs) = ZipParser.mount(src(img)) {
        let _: Vec<_> = fs.walk().take(10_000).collect();
    }
}

#[test]
fn crc_helper_selfcheck() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
}
