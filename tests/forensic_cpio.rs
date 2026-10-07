//! Integration tests for the CPIO parser over synthetic archives.
//!
//! Corpus: newc/odc/binary dialects, directories, symlinks, hardlinks,
//! the `TRAILER!!!` marker, post-trailer slack as carving candidates,
//! truncation and garbage.

mod common;

use std::io::Read;
use std::sync::Arc;

use common::cpio::{CpioBuilder, MODE_DIR, MODE_FILE, MODE_SYMLINK, MTIME};
use sutram_archive::CpioParser;
use sutram_fs::{DetectConfidence, FsEntry, FsEntryStatus, FsParser, MountOptions, RecoveryState};
use sutram_io::ByteSource;
use sutram_magic::MagicType;

fn src(bytes: Vec<u8>) -> Arc<dyn ByteSource> {
    Arc::new(bytes)
}

fn newc_archive() -> Vec<u8> {
    let mut b = CpioBuilder::new();
    b.add_newc("dir", b"", MODE_DIR, MTIME, 2, None, 0);
    b.add_newc("dir/hello.txt", b"hello cpio", MODE_FILE, MTIME, 1, None, 0);
    b.add_newc("dir/link", b"hello.txt", MODE_SYMLINK, MTIME, 1, None, 0);
    b.trailer_newc();
    b.finish_bare()
}

fn entries(img: Vec<u8>) -> Vec<FsEntry> {
    let fs = CpioParser.mount(src(img)).unwrap();
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
fn detects_all_dialects() {
    assert_eq!(
        CpioParser.detect(src(newc_archive()).as_ref()),
        DetectConfidence::Certain
    );
    let mut b = CpioBuilder::new();
    b.add_odc("a.txt", b"x", MODE_FILE, MTIME);
    assert_eq!(
        CpioParser.detect(&b.finish_bare().as_slice()),
        DetectConfidence::Certain
    );
    let mut b = CpioBuilder::new();
    b.add_bin("a.txt", b"x", MODE_FILE, MTIME, true);
    assert_eq!(
        CpioParser.detect(&b.finish_bare().as_slice()),
        DetectConfidence::High
    );
    let mut b = CpioBuilder::new();
    b.add_bin("a.txt", b"x", MODE_FILE, MTIME, false);
    assert_eq!(
        CpioParser.detect(&b.finish_bare().as_slice()),
        DetectConfidence::High
    );
    assert_eq!(
        CpioParser.detect(&vec![0u8; 256].as_slice()),
        DetectConfidence::None
    );
}

#[test]
fn newc_walks_members() {
    let es = entries(newc_archive());
    let paths: Vec<&str> = es.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"/dir"));
    assert!(paths.contains(&"/dir/hello.txt"));
    assert!(paths.contains(&"/dir/link"));
    // TRAILER!!! is a terminator, not an entry.
    assert!(!paths.iter().any(|p| p.contains("TRAILER")));
}

#[test]
fn newc_read_file_and_meta() {
    let fs = CpioParser.mount(src(newc_archive())).unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/dir/hello.txt");
    let mut r = fs.read_file(e).unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"hello cpio");
    assert_eq!(e.meta["format"], "newc");
    assert_eq!(e.meta["uid"], "1000");
    assert_eq!(e.meta["mode"], "0o100644");
    let m = e.timestamps.modified.as_ref().unwrap();
    assert_eq!(m.raw_encoding, "unix-sec");
    assert_eq!(m.value, Some(MTIME as i64 * 1_000_000_000));
    let link = find(&es, "/dir/link");
    assert_eq!(link.kind, sutram_fs::EntryKind::Symlink);
    assert_eq!(link.meta["symlink_target"], "hello.txt");
}

#[test]
fn odc_dialect() {
    let mut b = CpioBuilder::new();
    b.add_odc("old.txt", b"portable ascii", MODE_FILE, MTIME);
    b.trailer_odc();
    let fs = CpioParser.mount(src(b.finish_bare())).unwrap();
    assert_eq!(fs.info().meta["format"], "odc");
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/old.txt");
    let mut r = fs.read_file(e).unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"portable ascii");
}

#[test]
fn binary_dialect_both_endians() {
    for le in [true, false] {
        let mut b = CpioBuilder::new();
        b.add_bin("bin.txt", b"binary member data", MODE_FILE, MTIME, le);
        b.trailer_bin(le);
        let fs = CpioParser.mount(src(b.finish_bare())).unwrap();
        let want = if le { "bin-le" } else { "bin-be" };
        assert_eq!(fs.info().meta["format"], want);
        let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
        let e = find(&es, "/bin.txt");
        let mut r = fs.read_file(e).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"binary member data");
        assert_eq!(
            e.timestamps.modified.as_ref().unwrap().value,
            Some(MTIME as i64 * 1_000_000_000)
        );
    }
}

#[test]
fn slack_after_trailer_is_carve_candidate() {
    let mut b = CpioBuilder::new();
    b.add_newc("a.txt", b"live", MODE_FILE, MTIME, 1, None, 0);
    b.trailer_newc();
    // Slack hiding an embedded PNG signature.
    let mut slack = vec![0u8; 40];
    slack[8..16].copy_from_slice(b"\x89PNG\r\n\x1a\n");
    let img = b.with_slack(&slack);
    let fs = CpioParser.mount(src(img)).unwrap();
    assert_eq!(fs.info().meta["trailer_found"], "true");
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/$ORPHANED/archive_slack");
    assert_eq!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unknown
        }
    );
    assert_eq!(e.meta["carve_candidate"], "true");
    assert_eq!(e.meta["slack_len"], "40");
    // The slack is real, readable, carvable bytes.
    assert_eq!(fs.unallocated_ranges(), vec![e.allocated_ranges[0]]);
    let hits: Vec<_> = fs
        .carve_region(e.allocated_ranges[0].0, e.allocated_ranges[0].1, 1)
        .unwrap()
        .collect();
    assert!(hits
        .iter()
        .any(|h| matches!(h, Ok(h) if h.kind == MagicType::Png)));
}

#[test]
fn truncated_member_is_partially_overwritten() {
    let mut b = CpioBuilder::new();
    b.add_newc("ok.txt", b"fine", MODE_FILE, MTIME, 1, None, 0);
    // Craft a header claiming 4096 bytes but write only 64.
    let off = {
        let name = "cut.txt";
        let namesize = name.len() + 1;
        let h =
            format!(
            "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
            200u64, MODE_FILE, 1000u64, 1000u64, 1u64, MTIME, 4096u64, 3u64, 1u64, 0u64, 0u64,
            namesize as u64, 0u64,
        );
        let off = b.buf.len() as u64;
        b.buf.extend_from_slice(h.as_bytes());
        b.buf.extend_from_slice(name.as_bytes());
        b.buf.push(0);
        while b.buf.len() % 4 != 0 {
            b.buf.push(0);
        }
        b.buf.extend_from_slice(&[0xDD; 64]);
        off
    };
    let img = b.finish_bare();
    let fs = CpioParser.mount(src(img)).unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/cut.txt");
    assert_eq!(e.disk_offset, off);
    assert_eq!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::PartiallyOverwritten {
                recovered_bytes: 64,
                total_bytes: 4096
            }
        }
    );
}

#[test]
fn truncated_mid_header_is_error_item() {
    let mut b = CpioBuilder::new();
    b.add_newc("ok.txt", b"fine", MODE_FILE, MTIME, 1, None, 0);
    // Append a partial header (40 of 110 bytes).
    let mut img = b.finish_bare();
    img.extend_from_slice(b"07070100000000000000000000000000");
    let fs = CpioParser.mount(src(img)).unwrap();
    let mut errs = 0;
    let mut paths = Vec::new();
    for item in fs.walk() {
        match item {
            Ok(e) => paths.push(e.path),
            Err(_) => errs += 1,
        }
    }
    assert!(paths.contains(&"/ok.txt".to_string()));
    assert!(errs >= 1);
}

#[test]
fn hardlinks_annotated() {
    let mut b = CpioBuilder::new();
    let ino = 555;
    b.add_newc("orig.txt", b"content", MODE_FILE, MTIME, 2, Some(ino), 0);
    b.add_newc("alias.txt", b"", MODE_FILE, MTIME, 2, Some(ino), 0);
    b.trailer_newc();
    let es = entries(b.finish_bare());
    let a = find(&es, "/alias.txt");
    assert_eq!(a.meta["hardlink_of"], "/orig.txt");
    assert_eq!(a.meta["ino"], "555");
    assert_eq!(a.meta["nlink"], "2");
}

#[test]
fn garbage_mount_fails() {
    assert!(CpioParser.mount(src(vec![0xAAu8; 512])).is_err());
    // Magic alone isn't enough — an unparseable first header fails too.
    let mut img = b"070701".to_vec();
    img.extend_from_slice(&[0xFF; 200]);
    assert!(CpioParser.mount(src(img)).is_err());
}

#[test]
fn strict_aborts_on_corrupt() {
    let mut b = CpioBuilder::new();
    b.add_newc("a.txt", b"x", MODE_FILE, MTIME, 1, None, 0);
    let mut img = b.finish_bare();
    img.extend_from_slice(b"070701garbagegarbagegarbage");
    let r = CpioParser.mount_with(src(img), &MountOptions::strict());
    assert!(r.is_err());
}

#[test]
fn crc_variant_detected() {
    // 070702 = newc with check field.
    let mut b = CpioBuilder::new();
    b.add_newc("c.txt", b"data", MODE_FILE, MTIME, 1, None, 0xABCD);
    let mut img = b.finish_bare();
    img[0..6].copy_from_slice(b"070702");
    assert_eq!(
        CpioParser.detect(&img.as_slice()),
        DetectConfidence::Certain
    );
    let es = entries(img);
    assert_eq!(find(&es, "/c.txt").meta["check"], "0x0000abcd");
    assert_eq!(find(&es, "/c.txt").meta["format"], "crc");
}

#[test]
fn magic_verdict_on_member() {
    let mut b = CpioBuilder::new();
    b.add_newc(
        "pic.png",
        b"\x89PNG\r\n\x1a\npngdata",
        MODE_FILE,
        MTIME,
        1,
        None,
        0,
    );
    b.trailer_newc();
    let es = entries(b.finish_bare());
    assert_eq!(
        find(&es, "/pic.png").magic.as_ref().unwrap().detected,
        Some(MagicType::Png)
    );
}

#[test]
fn walk_terminates_no_panic_on_junk() {
    let mut img = b"070701".to_vec();
    img.extend_from_slice(&(0..200u32).map(|i| (i % 256) as u8).collect::<Vec<_>>());
    let _ = CpioParser.detect(&img.as_slice());
    if let Ok(fs) = CpioParser.mount(src(img)) {
        let _: Vec<_> = fs.walk().take(10_000).collect();
    }
}
