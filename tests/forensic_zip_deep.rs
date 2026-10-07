//! Deep-coverage integration tests for the ZIP parser.
//!
//! Complements `forensic_zip.rs` with: ZIP64 end-of-central-directory
//! discovery, extra-field decoders (UT/NTFS/uid-gid), unix-mode kinds,
//! the full anomaly matrix, hidden-member recovery (data-descriptor
//! bounded, next-signature bounded, unbounded, truncated, directory,
//! encrypted), SFX detection, central-directory edge cases (wrong offset,
//! early end, slack tail, loop-guard cap, record-length overflow),
//! read-side error paths, and the decompression-ratio cap.

mod common;

use std::io::{self, Read};
use std::sync::Arc;

use common::zip::{
    extra_field, zip64_extra, EocdPatch, ZipBuilder, FLAG_DD, FLAG_ENCRYPTED, FLAG_UTF8,
    METHOD_DEFLATE, METHOD_STORE,
};
use sutram_archive::ZipParser;
use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsParser, MountOptions, RecoveryState,
};
use sutram_io::ByteSource;

fn src(bytes: Vec<u8>) -> Arc<dyn ByteSource> {
    Arc::new(bytes)
}

fn entries(img: Vec<u8>) -> Vec<FsEntry> {
    let fs = ZipParser.mount(src(img)).unwrap();
    fs.walk()
        .collect::<Result<Vec<_>, _>>()
        .expect("corpus walks without errors")
}

fn find<'a>(es: &'a [FsEntry], path: &str) -> &'a FsEntry {
    es.iter().find(|e| e.path == path).unwrap_or_else(|| {
        panic!(
            "{path} not found; got {:?}",
            es.iter().map(|e| &e.path).collect::<Vec<_>>()
        )
    })
}

// ---------------------------------------------------------------- EOCD / ZIP64

#[test]
fn parser_names() {
    assert_eq!(ZipParser.name(), "zip");
    assert_eq!(sutram_archive::TarParser.name(), "tar");
    assert_eq!(sutram_archive::CpioParser.name(), "cpio");
    assert_eq!(sutram_archive::SutramArchiveParser.name(), "archive");
}

#[test]
fn zip64_eocd_locator_and_member_extras() {
    let mut b = ZipBuilder::new();
    b.add_member_zip64("big.bin", b"zip64 payload here", METHOD_STORE);
    b.add_member_zip64("packed.bin", b"deflated zip64 payload!!", METHOD_DEFLATE);
    let img = b.finish_zip64(b"z64 comment");

    let fs = ZipParser.mount(src(img)).unwrap();
    let info = fs.info();
    assert_eq!(info.meta["zip64"], "true");
    assert_eq!(info.meta["comment"], "z64 comment");
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/big.bin");
    assert_eq!(e.size, 18);
    assert_eq!(e.meta["extra_fields"], "0x0001");
    let mut r = fs.read_file(e).unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"zip64 payload here");
    // Detect sees the saturated EOCD and upgrades via the locator.
    assert_eq!(
        ZipParser.detect(src(b_finish_zip64_again()).as_ref()),
        DetectConfidence::Certain
    );
}

fn b_finish_zip64_again() -> Vec<u8> {
    let mut b = ZipBuilder::new();
    b.add_member_zip64("x.bin", b"y", METHOD_STORE);
    b.finish_zip64(b"")
}

#[test]
fn zip64_locator_absent_falls_back_to_eocd() {
    // Saturated EOCD but *no* locator — the parser must not explode; it
    // keeps the (bogus) EOCD values and reports the CD error leniently.
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"data", METHOD_STORE, 0, &[], &[]);
    let mut img = b.finish(b"");
    // Saturate the EOCD's cd_offset/cd_size fields (offsets 12 and 16
    // from the EOCD start = len-22).
    let n = img.len();
    img[n - 6..n - 2].copy_from_slice(&u32::MAX.to_le_bytes()); // cd_off
    img[n - 10..n - 6].copy_from_slice(&u32::MAX.to_le_bytes()); // cd_size
    let fs = ZipParser.mount(src(img)).unwrap();
    // Lenient: an error item surfaces; the hidden LFH is still catalogued.
    let mut saw_err = false;
    let mut found = false;
    for item in fs.walk() {
        match item {
            Err(_) => saw_err = true,
            Ok(e) if e.path == "/a.txt" => found = true,
            _ => {}
        }
    }
    assert!(saw_err && found);
}

#[test]
fn eocd_signature_inside_comment_is_skipped() {
    // A comment containing "PK\x05\x06" must not fool the EOCD scan: the
    // inner candidate's comment length won't cover the tail exactly.
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"data", METHOD_STORE, 0, &[], &[]);
    let mut comment = b"note PK\x05\x06".to_vec();
    comment.extend_from_slice(&[0u8; 18]); // fake body after the sig
    let img = b.finish(&comment);
    assert_eq!(
        ZipParser.detect(src(img).as_ref()),
        DetectConfidence::Certain
    );
}

#[test]
fn tiny_source_and_garbage_are_not_zips() {
    // Shorter than an EOCD: detect finds nothing, mount refuses.
    let tiny = vec![0x50u8; 10];
    assert_eq!(ZipParser.detect(&tiny.as_slice()), DetectConfidence::None);
    assert!(ZipParser.mount(src(tiny)).is_err());
    // No EOCD and no LFH anywhere: lenient mount still refuses.
    let junk = vec![0xABu8; 2048];
    assert!(ZipParser.mount(src(junk)).is_err());
}

#[test]
fn detect_medium_for_sfx_stub_without_eocd() {
    // Stub bytes then a valid LFH stream with no EOCD: no parseable LFH
    // at offset 0, so the signature scan earns Medium.
    let mut b = ZipBuilder::new();
    b.add_stub(&[0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00]); // "MZ" stub
    b.add_member("payload.exe", b"mz", METHOD_STORE, 0, &[], &[]);
    let img = b.finish_no_eocd();
    assert_eq!(
        ZipParser.detect(&img.as_slice()),
        DetectConfidence::Medium
    );
}

// ---------------------------------------------------------- central directory

#[test]
fn multi_disk_archive_flagged() {
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"data", METHOD_STORE, 0, &[], &[]);
    let img = b.finish_patched(
        b"",
        EocdPatch {
            disk: 1,
            cd_start_disk: 1,
            ..Default::default()
        },
    );
    let fs = ZipParser.mount(src(img)).unwrap();
    let mut saw_unsupported = false;
    for item in fs.walk() {
        if let Err(e) = item {
            if e.to_string().contains("multi-disk") {
                saw_unsupported = true;
            }
        }
    }
    assert!(saw_unsupported, "multi-disk error should be a walk item");
}

#[test]
fn central_directory_wrong_offset_is_error_item() {
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"data", METHOD_STORE, 0, &[], &[]);
    let mut img = b.finish(b"");
    // Point the EOCD's cd_off at the LFH and shrink cd_size so the
    // SFX-stub fallback (eocd_off - cd_size) also lands off the CD —
    // the walk must then report a corrupt catalog.
    let n = img.len();
    img[n - 6..n - 2].copy_from_slice(&0u32.to_le_bytes()); // cd_off = 0
    img[n - 10..n - 6].copy_from_slice(&4u32.to_le_bytes()); // cd_size = 4
    let fs = ZipParser.mount(src(img)).unwrap();
    assert!(fs.walk().any(|i| i.is_err()));
}

#[test]
fn central_directory_ends_early_is_error() {
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"data", METHOD_STORE, 0, &[], &[]);
    // EOCD claims 2 entries; the second CD slot is zero padding.
    let img = b.finish_patched(
        b"",
        EocdPatch {
            entries: Some(2),
            cd_tail: vec![0u8; 46],
            ..Default::default()
        },
    );
    let fs = ZipParser.mount(src(img)).unwrap();
    let mut early = false;
    for item in fs.walk() {
        if let Err(e) = item {
            if e.to_string().contains("ends early") {
                early = true;
            }
        }
    }
    assert!(early);
}

#[test]
fn central_directory_slack_after_claimed_entries_ok() {
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"data", METHOD_STORE, 0, &[], &[]);
    // EOCD claims exactly 1 entry but cd_size covers trailing junk —
    // an unused-CD-entry region the walk should tolerate.
    let img = b.finish_patched(
        b"",
        EocdPatch {
            entries: Some(1),
            cd_tail: vec![0xEEu8; 64],
            ..Default::default()
        },
    );
    let fs = ZipParser.mount(src(img)).unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    find(&es, "/a.txt");
}

#[test]
fn cd_record_length_overflow_is_truncated_error() {
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"data", METHOD_STORE, 0, &[], &[]);
    let mut img = b.finish(b"");
    // Patch the CD record's name_len (cd_off + 28) to overflow the file.
    let n = img.len();
    let cd_off = u32::from_le_bytes([img[n - 6], img[n - 5], img[n - 4], img[n - 3]]) as usize;
    img[cd_off + 28..cd_off + 30].copy_from_slice(&u16::MAX.to_le_bytes());
    let fs = ZipParser.mount(src(img)).unwrap();
    let mut saw_truncated = false;
    for item in fs.walk() {
        if let Err(e) = item {
            if e.to_string().contains("truncated") || e.to_string().contains("runs") {
                saw_truncated = true;
            }
        }
    }
    assert!(saw_truncated);
}

#[test]
fn cd_walk_loop_guard_caps_entry_count() {
    // EOCD claims 0 entries but 70 records follow: the walk's hard cap
    // (64) stops the fan-out; the remainder surface as hidden LFHs.
    let mut b = ZipBuilder::new();
    for i in 0..70 {
        b.add_member(&format!("m{i}.bin"), b"x", METHOD_STORE, 0, &[], &[]);
    }
    let img = b.finish_patched(
        b"",
        EocdPatch {
            entries: Some(0),
            entries_this_disk: Some(0),
            ..Default::default()
        },
    );
    let fs = ZipParser.mount(src(img)).unwrap();
    let mut live = 0usize;
    let mut deleted = 0usize;
    for item in fs.walk().flatten() {
        match item.status {
            FsEntryStatus::Live if item.kind == EntryKind::File => live += 1,
            FsEntryStatus::Deleted { .. } => deleted += 1,
            _ => {}
        }
    }
    assert_eq!(live, 64, "CD walk must stop at the hard cap");
    assert_eq!(deleted, 6, "unparsed LFHs should surface as hidden");
}

#[test]
fn strict_mount_fails_on_bad_central_signature() {
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"data", METHOD_STORE, 0, &[], &[]);
    let mut img = b.finish(b"");
    let n = img.len();
    let cd_off = u32::from_le_bytes([img[n - 6], img[n - 5], img[n - 4], img[n - 3]]) as usize;
    img[cd_off] = 0xFF;
    assert!(ZipParser
        .mount_with(src(img), &MountOptions::strict())
        .is_err());
}

// ------------------------------------------------------------- extra fields

fn ut_extra() -> Vec<u8> {
    // Extended timestamp 0x5455: flags 0x07, then mtime/atime/ctime u32s.
    let mut body = vec![0x07u8];
    body.extend_from_slice(&1_700_000_000u32.to_le_bytes());
    body.extend_from_slice(&1_700_000_001u32.to_le_bytes());
    body.extend_from_slice(&1_700_000_002u32.to_le_bytes());
    extra_field(0x5455, &body)
}

fn ntfs_extra() -> Vec<u8> {
    // NTFS 0x000a: u32 reserved, attr tag 1, len 24, three FILETIMEs.
    let mut body = vec![0u8; 4];
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&24u16.to_le_bytes());
    let ft = 133_500_000_000_000_000u64; // plausible FILETIME
    for _ in 0..3 {
        body.extend_from_slice(&ft.to_le_bytes());
    }
    extra_field(0x000a, &body)
}

fn uidgid_extra() -> Vec<u8> {
    // Unix uid/gid 0x7875: ver=1, uid_len=1, uid, gid_len=1, gid.
    extra_field(0x7875, &[1, 1, 5, 1, 100])
}

#[test]
fn ut_ntfs_uidgid_and_unknown_extras_decode() {
    let mut extra = ut_extra();
    let e = find(
        &entries({
            let mut b = ZipBuilder::new();
            b.add_member("ut.txt", b"d", METHOD_STORE, 0, &extra, &[]);
            b.finish(b"")
        }),
        "/ut.txt",
    );
    assert_eq!(e.timestamps.accessed.as_ref().unwrap().raw_value, 1_700_000_001);
    assert_eq!(e.timestamps.changed.as_ref().unwrap().raw_value, 1_700_000_002);
    assert_eq!(e.meta["ut_mtime_unix"], "1700000000");
    assert!(e.meta["extra_fields"].contains("0x5455"));

    // NTFS extra: accessed/changed come from FILETIMEs.
    let e = find(
        &entries({
            let mut b = ZipBuilder::new();
            b.add_member("ntfs.txt", b"d", METHOD_STORE, 0, &ntfs_extra(), &[]);
            b.finish(b"")
        }),
        "/ntfs.txt",
    );
    assert!(e.timestamps.accessed.is_some());
    assert!(e.timestamps.changed.is_some());
    assert!(e.meta.contains_key("ntfs_mtime_filetime"));

    // uid/gid + unknown tag + truncated tail field.
    extra = uidgid_extra();
    extra.extend_from_slice(&extra_field(0xCAFE, b"xy"));
    extra.extend_from_slice(&0x9999u16.to_le_bytes()); // truncated tag
    extra.extend_from_slice(&300u16.to_le_bytes()); // claims 300, has ~0
    let e = find(
        &entries({
            let mut b = ZipBuilder::new();
            b.add_member("ids.txt", b"d", METHOD_STORE, 0, &extra, &[]);
            b.finish(b"")
        }),
        "/ids.txt",
    );
    assert_eq!(e.meta["uid"], "5");
    assert_eq!(e.meta["gid"], "100");
    assert!(e.meta["extra_fields"].contains("0x7875"));
    assert!(e.meta["extra_fields"].contains("0xcafe"));
}

// ----------------------------------------------------------------- unix modes

#[test]
fn unix_mode_attributes_drive_kinds() {
    let mut b = ZipBuilder::new();
    let cases: [(&str, u32); 4] = [
        ("adir/", 0o040755),
        ("link.txt", 0o120777),
        ("fifo", 0o010644),
        ("reg.txt", 0o100644),
    ];
    for (name, mode) in cases {
        b.add_member(name, b"d", METHOD_STORE, 0, &[], &[]);
        let cd = b.last_cd_mut();
        cd.made_by = (3 << 8) | 20; // unix host
        cd.ext_attrs = mode << 16;
    }
    let es = entries(b.finish(b""));
    assert_eq!(find(&es, "/adir").kind, EntryKind::Directory);
    assert_eq!(find(&es, "/link.txt").kind, EntryKind::Symlink);
    assert_eq!(find(&es, "/fifo").kind, EntryKind::Other);
    let reg = find(&es, "/reg.txt");
    assert_eq!(reg.kind, EntryKind::File);
    assert_eq!(reg.meta["mode"], "0o100644");
    assert!(reg.meta.contains_key("external_attrs"));
    assert!(reg.meta["made_by"].contains("unix"));
}

#[test]
fn method_and_host_tables_cover_names() {
    let mut b = ZipBuilder::new();
    let methods = [0u16, 1, 6, 9, 12, 14, 93, 98, 99];
    for (i, &m) in methods.iter().enumerate() {
        b.add_member(&format!("m{i}.bin"), b"data", 0, 0, &[], &[]);
        b.last_cd_mut().method = m;
    }
    let hosts = [0u16, 10, 11, 19, 99];
    for (i, &h) in hosts.iter().enumerate() {
        b.add_member(&format!("h{i}.bin"), b"data", 0, 0, &[], &[]);
        b.last_cd_mut().made_by = (h << 8) | 20;
    }
    let es = entries(b.finish(b""));
    let get = |p: &str| find(&es, p).meta["compression_method"].clone();
    assert_eq!(get("/m1.bin"), "shrink");
    assert_eq!(get("/m2.bin"), "implode");
    assert_eq!(get("/m3.bin"), "deflate64");
    assert_eq!(get("/m4.bin"), "bzip2");
    assert_eq!(get("/m5.bin"), "lzma");
    assert_eq!(get("/m6.bin"), "zstd");
    assert_eq!(get("/m7.bin"), "ppmd");
    assert_eq!(get("/m8.bin"), "unknown");
    for h in ["/h0.bin", "/h1.bin", "/h2.bin", "/h3.bin", "/h4.bin"] {
        assert!(find(&es, h).meta.contains_key("made_by"));
    }
}

// ------------------------------------------------------------------ anomalies

#[test]
fn anomaly_flags_name_and_extra_drift() {
    let mut b = ZipBuilder::new();
    b.add_member("orig.txt", b"data", METHOD_STORE, 0, &ut_extra(), &[]);
    {
        let cd = b.last_cd_mut();
        cd.flags = FLAG_UTF8; // LFH has flags=0
        cd.name = b"renamed.txt".to_vec();
        cd.extra = extra_field(0x9999, b"zz").to_vec(); // differs from LFH
    }
    let es = entries(b.finish(b""));
    let e = find(&es, "/renamed.txt");
    let anomaly = &e.meta["anomaly"];
    assert!(anomaly.contains("flags"), "{anomaly}");
    assert!(anomaly.contains("name"), "{anomaly}");
    assert_eq!(e.meta["extra_differs"], "true");
}

#[test]
fn anomaly_crc32_mismatch_under_data_descriptor() {
    let mut b = ZipBuilder::new();
    b.add_member(
        "dd.bin",
        b"payload-bytes",
        METHOD_STORE,
        FLAG_DD,
        &[],
        &[],
    );
    // Write a nonzero (wrong) CRC into the LFH — legal under bit 3, and
    // the parser flags the disagreement with the CD.
    let lfh = b.member_offsets[0] as usize;
    b.buf[lfh + 14..lfh + 18].copy_from_slice(&0x1111_1111u32.to_le_bytes());
    let es = entries(b.finish(b""));
    let e = find(&es, "/dd.bin");
    assert!(e.meta["anomaly"].contains("crc32"), "{:?}", e.meta);
}

#[test]
fn local_header_missing_and_corrupt_anomalies() {
    let mut b = ZipBuilder::new();
    b.add_member("gone.txt", b"data", METHOD_STORE, 0, &[], &[]);
    // Point the CD at a non-LFH offset.
    b.last_cd_mut().local_off = 5;
    let es = entries(b.finish(b""));
    let e = find(&es, "/gone.txt");
    assert!(e.meta["anomaly"].contains("local_header_missing"));
    // Reads of such a member fail with a corruption error, not a panic.
    let fs = ZipParser
        .mount(src({
            let mut b = ZipBuilder::new();
            b.add_member("gone.txt", b"data", METHOD_STORE, 0, &[], &[]);
            b.last_cd_mut().local_off = 5;
            b.finish(b"")
        }))
        .unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/gone.txt");
    assert!(fs.read_file(e).is_err());

    // Truncated LFH → local_header_corrupt.
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"d", METHOD_STORE, 0, &[], &[]);
    let lfh_off = b.add_lfh_truncated_name(0x00F0);
    // Catalogue it: reuse the CD record, repoint local_off.
    b.cds[0].local_off = lfh_off as u32;
    let es = entries(b.finish(b""));
    let e = find(&es, "/a.txt");
    assert!(e.meta["anomaly"].contains("local_header_corrupt"));
}

// ------------------------------------------------------------- hidden members

#[test]
fn hidden_dd_member_size_recovered_from_descriptor() {
    let mut b = ZipBuilder::new();
    b.add_member("live.txt", b"ok", METHOD_STORE, 0, &[], &[]);
    // Hidden streaming member: bit 3 set, zero sizes, real descriptor.
    b.add_hidden_opts(
        "ghost.bin",
        b"hidden streamed data!",
        METHOD_STORE,
        FLAG_DD,
        &[],
        true,
        true,
    );
    let img = b.finish(b"");
    let es = entries(img);
    let e = find(&es, "/ghost.bin");
    assert_eq!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    );
    assert!(e.meta["size_note"].contains("data descriptor"));
}

#[test]
fn hidden_dd_member_bounded_by_next_signature() {
    let mut b = ZipBuilder::new();
    // Hidden bit-3 member with zero sizes and *no* descriptor — the data
    // is bounded by the following live member's LFH.
    b.add_hidden_opts(
        "vague.bin",
        b"unbounded-looking data",
        METHOD_STORE,
        FLAG_DD,
        &[],
        true,
        false,
    );
    b.add_member("live.txt", b"ok", METHOD_STORE, 0, &[], &[]);
    let img = b.finish(b"");
    let es = entries(img);
    let e = find(&es, "/vague.bin");
    assert_eq!(e.size, 0); // LFH declared nothing
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    ));
}

#[test]
fn hidden_dd_member_unbounded_is_unknown() {
    let mut b = ZipBuilder::new();
    // Only member: bit-3 + zero sizes + no descriptor + nothing after.
    b.add_hidden_opts(
        "abyss.bin",
        b"where does it end?",
        METHOD_STORE,
        FLAG_DD,
        &[],
        true,
        false,
    );
    let img = b.finish_no_eocd();
    let fs = ZipParser.mount(src(img)).unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/abyss.bin");
    assert_eq!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unknown
        }
    );
    assert!(e.meta["size_note"].contains("unbounded"));
}

#[test]
fn hidden_truncated_member_is_partially_overwritten() {
    let mut b = ZipBuilder::new();
    b.add_member("live.txt", b"ok", METHOD_STORE, 0, &[], &[]);
    b.add_hidden("big.bin", b"0123456789", METHOD_STORE);
    // Inflate the hidden LFH's declared compressed size beyond the bytes
    // present (patch comp_size at lfh+18).
    let lfh = b.member_offsets[1] as usize;
    b.buf[lfh + 18..lfh + 22].copy_from_slice(&500u32.to_le_bytes());
    let img = b.finish(b"");
    let es = entries(img);
    let e = find(&es, "/big.bin");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::PartiallyOverwritten { .. }
        }
    ));
    assert_eq!(e.meta["data_truncated"], "true");
}

#[test]
fn hidden_directory_and_encrypted_extra_member() {
    let mut b = ZipBuilder::new();
    b.add_member("live.txt", b"ok", METHOD_STORE, 0, &[], &[]);
    b.add_hidden("ghostdir/", b"", METHOD_STORE);
    b.add_hidden_opts(
        "vault.bin",
        b"cipher?",
        METHOD_STORE,
        FLAG_ENCRYPTED,
        &ut_extra(),
        false,
        false,
    );
    let img = b.finish(b"");
    let es = entries(img);
    let d = find(&es, "/ghostdir");
    assert_eq!(d.kind, EntryKind::Directory);
    assert!(d.is_deleted());
    let v = find(&es, "/vault.bin");
    assert_eq!(v.meta["encrypted"], "true");
    assert!(v.meta["extra_fields"].contains("0x5455"));
}

#[test]
fn truncated_lfh_name_surfaces_in_hidden_scan() {
    // A trailing LFH claiming a huge name hits the truncation branch in
    // parse_lfh and is skipped by the hidden scan without panic.
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"d", METHOD_STORE, 0, &[], &[]);
    b.add_lfh_truncated_name(0x7F00);
    let img = b.finish(b"");
    let fs = ZipParser.mount(src(img)).unwrap();
    let n = fs.walk().count();
    assert!(n >= 2, "walk should still emit root + member");
}

// --------------------------------------------------------------- read paths

#[test]
fn data_descriptor_without_signature_member() {
    let mut b = ZipBuilder::new();
    b.add_member_dd_no_sig("old.bin", b"twelve byte trailer", METHOD_STORE);
    b.add_member("next.txt", b"after", METHOD_STORE, 0, &[], &[]);
    let img = b.finish(b"");
    let es = entries(img);
    let e = find(&es, "/old.bin");
    let fs = ZipParser
        .mount(src({
            let mut b = ZipBuilder::new();
            b.add_member_dd_no_sig("old.bin", b"twelve byte trailer", METHOD_STORE);
            b.finish(b"")
        }))
        .unwrap();
    let es2: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e2 = find(&es2, "/old.bin");
    let mut r = fs.read_file(e2).unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"twelve byte trailer");
    let _ = e;
}

#[test]
fn read_file_rejects_nonfile_and_foreign_entries() {
    let mut b = ZipBuilder::new();
    b.add_member("dir/", b"", METHOD_STORE, 0, &[], &[]);
    b.add_member("f.txt", b"x", METHOD_STORE, 0, &[], &[]);
    let fs = ZipParser.mount(src(b.finish(b""))).unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let dir = find(&es, "/dir");
    assert!(fs.read_file(dir).is_err());
    // A fabricated entry id that isn't a member.
    let mut fake = dir.clone();
    fake.kind = EntryKind::File;
    fake.entry_id = 9999;
    fake.path = "/nope".into();
    assert!(fs.read_file(&fake).is_err());
}

#[test]
fn unsupported_compression_method_errors_on_read() {
    let mut b = ZipBuilder::new();
    b.add_member("packed.bz2", b"not really bzip2", METHOD_STORE, 0, &[], &[]);
    b.last_cd_mut().method = 12;
    let fs = ZipParser.mount(src(b.finish(b""))).unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/packed.bz2");
    assert_eq!(e.meta["compression_method"], "bzip2");
    let err = fs.read_file(e).unwrap_err();
    assert!(err.to_string().contains("bzip2"), "{err}");
}

#[test]
fn deflate_output_is_capped_at_declared_size() {
    // Zip-bomb guard: the CD declares 4 uncompressed bytes; the deflate
    // stream would produce far more — the reader stops at the cap.
    let data = vec![b'Z'; 4096];
    let mut b = ZipBuilder::new();
    b.add_member("bomb.bin", &data, METHOD_DEFLATE, 0, &[], &[]);
    b.last_cd_mut().uncomp_size = 4;
    let fs = ZipParser.mount(src(b.finish(b""))).unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/bomb.bin");
    let mut r = fs.read_file(e).unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 4, "reader must honour the declared-size cap");
}

#[test]
fn corrupt_deflate_stream_reports_error() {
    let mut b = ZipBuilder::new();
    b.add_member("bad.bin", b"whatever", METHOD_DEFLATE, 0, &[], &[]);
    let img = {
        let mut v = b.finish(b"");
        // Corrupt the compressed payload (first member's data starts
        // right after its 30-byte LFH + name).
        let lfh = 0usize;
        let name_len = u16::from_le_bytes([v[lfh + 26], v[lfh + 27]]) as usize;
        let data_off = lfh + 30 + name_len;
        for i in 0..8 {
            v[data_off + i] = 0xDE;
        }
        v
    };
    let fs = ZipParser.mount(src(img)).unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/bad.bin");
    let mut r = fs.read_file(e).unwrap();
    let mut buf = Vec::new();
    assert!(r.read_to_end(&mut buf).is_err());
}

#[test]
fn truncated_deflate_stream_terminates_cleanly() {
    let data = b"some decent amount of data to compress".to_vec();
    let mut b = ZipBuilder::new();
    b.add_member("cut.bin", &data, METHOD_DEFLATE, 0, &[], &[]);
    // Shrink the stored stream to just its first two bytes.
    {
        let lfh = 0usize;
        let name_len = 7usize; // "cut.bin"
        let data_off = lfh + 30 + name_len;
        b.buf.truncate(data_off + 2);
        b.last_cd_mut().comp_size = 2;
    }
    let fs = ZipParser.mount(src(b.finish(b""))).unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/cut.bin");
    let mut r = fs.read_file(e).unwrap();
    let mut buf = Vec::new();
    // Either an immediate error or a short read — never a hang/panic.
    let _ = r.read_to_end(&mut buf);
}

// ------------------------------------------------------- walk / info extras

#[test]
fn implied_parent_dirs_emit_for_deep_paths() {
    let mut b = ZipBuilder::new();
    b.add_member("a/b/c/deep.txt", b"d", METHOD_STORE, 0, &[], &[]);
    let es = entries(b.finish(b""));
    for p in ["/a", "/a/b", "/a/b/c", "/a/b/c/deep.txt"] {
        let e = find(&es, p);
        if p != "/a/b/c/deep.txt" {
            assert_eq!(e.kind, EntryKind::Directory);
            assert_eq!(e.meta["implied"], "true");
        }
    }
}

#[test]
fn source_roundtrips_and_unallocated_tail_without_eocd() {
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"data", METHOD_STORE, 0, &[], &[]);
    let img = b.finish_no_eocd();
    let total = img.len() as u64;
    let fs = ZipParser.mount(src(img)).unwrap();
    assert_eq!(fs.source().len(), total);
    // The stray CD bytes after the last member are unallocated tail.
    let unalloc = fs.unallocated_ranges();
    assert!(unalloc.iter().any(|(s, l)| s + l == total), "{unalloc:?}");
}

#[test]
fn empty_and_slashy_member_names_do_not_panic() {
    let mut b = ZipBuilder::new();
    b.add_member("/", b"", METHOD_STORE, 0, &[], &[]);
    b.add_member("./", b"", METHOD_STORE, 0, &[], &[]);
    b.add_member("a.txt", b"d", METHOD_STORE, 0, &[], &[]);
    let es = entries(b.finish(b""));
    find(&es, "/a.txt");
}

#[test]
fn eocd_sig_in_final_bytes_breaks_backward_scan() {
    // If the last 22 bytes happen to contain "PK\x05\x06", the backward
    // scan hits a candidate too short to be an EOCD and bails — the
    // archive then looks like a headerless stream (LFH at 0 → High).
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"d", METHOD_STORE, 0, &[], &[]);
    let mut img = b.finish(b"");
    // Append bytes so the real EOCD no longer reaches EOF exactly, then
    // end with the EOCD signature itself.
    img.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
    let c = ZipParser.detect(&img.as_slice());
    assert!(
        c == DetectConfidence::High || c == DetectConfidence::Medium,
        "got {c:?}"
    );
}

// -------------------------------------------------------------- I/O faults

/// ByteSource that returns `Err` for any read touching `fail_at`+.
struct FaultSource {
    inner: Vec<u8>,
    fail_at: u64,
}

impl ByteSource for FaultSource {
    fn len(&self) -> u64 {
        self.inner.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.fail_at {
            return Err(io::Error::new(io::ErrorKind::Other, "injected read fault"));
        }
        let avail = (self.fail_at - offset).min(buf.len() as u64) as usize;
        let have = self.inner.len().saturating_sub(offset as usize);
        let n = avail.min(have);
        buf[..n].copy_from_slice(&self.inner[offset as usize..offset as usize + n]);
        Ok(n)
    }
}

#[test]
fn read_faults_become_error_items_not_panics() {
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"data", METHOD_STORE, 0, &[], &[]);
    b.add_member("b.txt", b"more data", METHOD_STORE, 0, &[], &[]);
    let img = b.finish(b"");
    // Fault at half the image: EOCD scan fails, the hidden scan partially
    // succeeds before hitting the dead region.
    let half = img.len() as u64 / 2;
    let fs = ZipParser
        .mount(Arc::new(FaultSource {
            inner: img,
            fail_at: half,
        }))
        .unwrap();
    let mut errs = 0;
    let mut oks = 0;
    for item in fs.walk().take(1000) {
        match item {
            Ok(_) => oks += 1,
            Err(_) => errs += 1,
        }
    }
    assert!(errs >= 1, "read faults should surface as Err items");
    assert!(oks >= 1);
}

#[test]
fn read_fault_during_eocd_scan_is_lenient() {
    let mut b = ZipBuilder::new();
    b.add_member("a.txt", b"data", METHOD_STORE, 0, &[], &[]);
    let img = b.finish(b"");
    // Fault only in the EOCD region (tail) — the CD is dead too, but the
    // early LFHs parse and appear as hidden members.
    let tail = img.len() as u64 - 40;
    let fs = ZipParser
        .mount(Arc::new(FaultSource {
            inner: img,
            fail_at: tail,
        }))
        .unwrap();
    let mut found_hidden = false;
    let mut saw_err = false;
    for item in fs.walk() {
        match item {
            Err(_) => saw_err = true,
            Ok(e) if e.meta.contains_key("hidden_entry") => found_hidden = true,
            _ => {}
        }
    }
    assert!(saw_err && found_hidden);
}
