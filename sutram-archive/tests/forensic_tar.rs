//! Integration tests for the TAR parser over synthetic archives.
//!
//! Corpus: ustar + v7 members, directories, symlinks/hardlinks, GNU
//! longname, pax extended headers (incl. fractional timestamps), pax and
//! GNU sparse members, duplicate-path supersession, truncated tails,
//! post-archive slack, checksum corruption.

mod common;

use std::io::Read;
use std::sync::Arc;

use common::tar::{TarBuilder, MTIME};
use sutram_archive::TarParser;
use sutram_fs::{DetectConfidence, FsEntry, FsEntryStatus, FsParser, MountOptions, RecoveryState};
use sutram_io::ByteSource;
use sutram_magic::{MagicType, Severity};

fn src(bytes: Vec<u8>) -> Arc<dyn ByteSource> {
    Arc::new(bytes)
}

fn clean_tar() -> Vec<u8> {
    let mut b = TarBuilder::new();
    b.add_dir("dir");
    b.add_file("dir/hello.txt", b"hello tar");
    b.add_file("top.bin", b"\x01\x02\x03\x04");
    b.add_symlink("dir/link", "hello.txt");
    b.finish()
}

fn entries(img: Vec<u8>) -> Vec<FsEntry> {
    let fs = TarParser.mount(src(img)).unwrap();
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

fn find_all<'a>(es: &'a [FsEntry], path: &str) -> Vec<&'a FsEntry> {
    es.iter().filter(|e| e.path == path).collect()
}

#[test]
fn detects_ustar() {
    assert_eq!(
        TarParser.detect(src(clean_tar()).as_ref()),
        DetectConfidence::Certain
    );
}

#[test]
fn detects_v7_as_medium() {
    let mut b = TarBuilder::new();
    b.add_v7("oldfile.txt", b"v7 data");
    let img = b.finish();
    assert_eq!(TarParser.detect(&img.as_slice()), DetectConfidence::Medium);
}

#[test]
fn rejects_garbage_and_zeros() {
    assert_eq!(
        TarParser.detect(&vec![0u8; 4096].as_slice()),
        DetectConfidence::None
    );
    assert_eq!(
        TarParser.detect(&vec![0xAAu8; 4096].as_slice()),
        DetectConfidence::None
    );
}

#[test]
fn walks_members_and_implied_dirs() {
    let es = entries(clean_tar());
    let paths: Vec<&str> = es.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"/"));
    assert!(paths.contains(&"/dir"));
    assert!(paths.contains(&"/dir/hello.txt"));
    assert!(paths.contains(&"/top.bin"));
    assert!(paths.contains(&"/dir/link"));
    let dir = find(&es, "/dir");
    assert_eq!(dir.kind, sutram_fs::EntryKind::Directory);
    let link = find(&es, "/dir/link");
    assert_eq!(link.kind, sutram_fs::EntryKind::Symlink);
    assert_eq!(link.meta["symlink_target"], "hello.txt");
}

#[test]
fn read_file_roundtrip() {
    let fs = TarParser.mount(src(clean_tar())).unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/dir/hello.txt");
    let mut r = fs.read_file(e).unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"hello tar");
    // Provenance: data starts 512 after the header.
    assert_eq!(e.allocated_ranges, vec![(e.disk_offset + 512, 9)]);
}

#[test]
fn octal_mtime_decodes() {
    let es = entries(clean_tar());
    let e = find(&es, "/top.bin");
    let m = e.timestamps.modified.as_ref().unwrap();
    assert_eq!(m.raw_encoding, "octal-unix-sec");
    assert_eq!(m.raw_value, MTIME);
    assert_eq!(m.value, Some(MTIME as i64 * 1_000_000_000));
}

#[test]
fn superseded_duplicate_paths() {
    let mut b = TarBuilder::new();
    b.add_file("same.txt", b"old version");
    b.add_file("same.txt", b"new version!");
    let img = b.finish();
    let es = entries(img);
    let both = find_all(&es, "/same.txt");
    assert_eq!(both.len(), 2);
    assert_eq!(both[0].meta["superseded"], "true");
    assert!(!both[1].meta.contains_key("superseded"));
    // Both versions remain readable.
    let fs = TarParser
        .mount(src({
            let mut b = TarBuilder::new();
            b.add_file("same.txt", b"old version");
            b.add_file("same.txt", b"new version!");
            b.finish()
        }))
        .unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let both: Vec<&FsEntry> = es.iter().filter(|e| e.path == "/same.txt").collect();
    let mut r = fs.read_file(both[0]).unwrap();
    let mut v0 = Vec::new();
    r.read_to_end(&mut v0).unwrap();
    let mut r = fs.read_file(both[1]).unwrap();
    let mut v1 = Vec::new();
    r.read_to_end(&mut v1).unwrap();
    assert_eq!(v0, b"old version");
    assert_eq!(v1, b"new version!");
}

#[test]
fn truncated_tail_member_is_partially_overwritten() {
    let mut b = TarBuilder::new();
    b.add_file("intact.txt", b"fine");
    // Header claims 2048 bytes but the image ends after 256.
    b.header(
        "cut.bin", 0o644, 0, 0, 2048, MTIME, b'0', "", b"ustar\0", "",
    );
    b.buf.extend_from_slice(&vec![0xCCu8; 256]);
    let img = b.finish_bare();
    let fs = TarParser.mount(src(img)).unwrap();
    let mut saw_err = false;
    let mut cut = None;
    for item in fs.walk() {
        match item {
            Err(_) => saw_err = true,
            Ok(e) if e.name == "cut.bin" => cut = Some(e),
            _ => {}
        }
    }
    let e = cut.expect("cut.bin missing");
    assert_eq!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::PartiallyOverwritten {
                recovered_bytes: 256,
                total_bytes: 2048
            }
        }
    );
    assert_eq!(e.allocated_ranges[0].1, 256);
    // Read returns only the surviving bytes.
    let mut r = fs.read_file(&e).unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 256);
    assert!(saw_err, "the truncated tail should surface an Err item too");
}

#[test]
fn gnu_longname_applies() {
    let long = format!(
        "{}/{}",
        "d".repeat(60),
        "very-long-name-exceeding-100-chars-total-yes-it-does".repeat(2)
    );
    let mut b = TarBuilder::new();
    b.add_longname(&long, b"long data");
    let img = b.finish();
    let es = entries(img);
    let e = find(&es, &format!("/{long}"));
    assert_eq!(e.size, 9);
}

#[test]
fn pax_path_and_timestamps() {
    let mut b = TarBuilder::new();
    b.add_pax(
        "ignored-name",
        b"pax data",
        &[
            ("path", "real/deep/name.txt"),
            ("mtime", "1700000000.5"),
            ("atime", "1700000001.25"),
            ("comment", "test"),
        ],
    );
    let img = b.finish();
    let es = entries(img);
    let e = find(&es, "/real/deep/name.txt");
    assert_eq!(e.meta["pax_keys"], "atime,comment,mtime,path");
    let m = e.timestamps.modified.as_ref().unwrap();
    assert_eq!(m.raw_encoding, "pax-unix-sec");
    assert_eq!(m.value, Some(1_700_000_000_500_000_000));
    let a = e.timestamps.accessed.as_ref().unwrap();
    assert_eq!(a.value, Some(1_700_000_001_250_000_000));
}

#[test]
fn pax_sparse_reads_zeros_in_holes() {
    // Map: bytes 0..5 and 1024..1029 are real; the rest is hole.
    let stored: Vec<u8> = b"AAAAABBBBB".to_vec();
    let mut b = TarBuilder::new();
    b.add_pax_sparse("sparse.bin", &[(0, 5), (1024, 5)], &stored, 1029);
    let img = b.finish();
    let fs = TarParser.mount(src(img)).unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/sparse.bin");
    assert_eq!(e.meta["sparse"], "true");
    assert_eq!(e.size, 1029);
    // allocated_ranges hold only the physically stored extents.
    assert_eq!(e.allocated_ranges.iter().map(|(_, l)| l).sum::<u64>(), 10);
    let mut r = fs.read_file(e).unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 1029);
    assert_eq!(&buf[0..5], b"AAAAA");
    assert!(buf[5..1024].iter().all(|&b| b == 0));
    assert_eq!(&buf[1024..1029], b"BBBBB");
}

#[test]
fn gnu_sparse_header_map() {
    let stored: Vec<u8> = b"HEADTAIL".to_vec();
    let mut b = TarBuilder::new();
    b.add_gnu_sparse("gsparse.bin", &[(0, 4), (508, 4)], &stored, 512);
    let img = b.finish();
    let fs = TarParser.mount(src(img)).unwrap();
    let es: Vec<FsEntry> = fs.walk().filter_map(|r| r.ok()).collect();
    let e = find(&es, "/gsparse.bin");
    assert_eq!(e.meta["sparse"], "true");
    let mut r = fs.read_file(e).unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 512);
    assert_eq!(&buf[0..4], b"HEAD");
    assert_eq!(&buf[508..512], b"TAIL");
}

#[test]
fn post_archive_slack_is_unallocated() {
    let mut b = TarBuilder::new();
    b.add_file("a.txt", b"x");
    let img = b.finish_with_slack(&vec![0xEEu8; 300]);
    let fs = TarParser.mount(src(img)).unwrap();
    let gaps = fs.unallocated_ranges();
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].1, 300);
}

#[test]
fn bad_checksum_lenient_error() {
    let mut b = TarBuilder::new();
    b.add_file("good.txt", b"ok");
    b.add_file("bad.txt", b"broken");
    let mut img = b.finish();
    // Corrupt the second member's header (offset 1024).
    img[1024 + 100] = 0xFF;
    let fs = TarParser.mount(src(img)).unwrap();
    let mut paths = Vec::new();
    let mut errs = 0;
    for item in fs.walk() {
        match item {
            Ok(e) => paths.push(e.path),
            Err(_) => errs += 1,
        }
    }
    assert!(paths.contains(&"/good.txt".to_string()));
    assert!(errs >= 1);
}

#[test]
fn strict_mount_aborts_on_bad_checksum() {
    let mut b = TarBuilder::new();
    b.add_file("a.txt", b"ok");
    b.add_file("b.txt", b"broken");
    let mut img = b.finish();
    img[1024 + 100] = 0xFF;
    // Strict mode: the header-stream scan at mount hits the checksum
    // failure and aborts the mount entirely.
    let r = TarParser.mount_with(src(img.clone()), &MountOptions::strict());
    assert!(r.is_err());
}

#[test]
fn garbage_mount_fails() {
    let img = vec![0xAAu8; 2048];
    assert!(TarParser.mount(src(img)).is_err());
}

#[test]
fn magic_verdict_on_member() {
    let mut b = TarBuilder::new();
    b.add_file("pic.png", b"\x89PNG\r\n\x1a\nmorepng");
    b.add_file("evil.txt", b"MZ\x90\x00definitely-not-text");
    let img = b.finish();
    let es = entries(img);
    assert_eq!(
        find(&es, "/pic.png").magic.as_ref().unwrap().detected,
        Some(MagicType::Png)
    );
    assert_eq!(
        find(&es, "/evil.txt").magic.as_ref().unwrap().severity,
        Severity::High
    );
}

#[test]
fn hardlink_and_metadata() {
    let mut b = TarBuilder::new();
    b.add_file("orig.txt", b"content");
    b.add_hardlink("alias.txt", "orig.txt");
    let img = b.finish();
    let es = entries(img);
    let e = find(&es, "/alias.txt");
    assert_eq!(e.meta["hardlink_of"], "orig.txt");
    assert_eq!(e.meta["uid"], "1000");
    assert_eq!(e.meta["uname"], "user");
}

#[test]
fn ustar_prefix_paths() {
    let mut b = TarBuilder::new();
    b.add_prefixed("a/really/long/prefix/path", "file.txt", b"data");
    let img = b.finish();
    let es = entries(img);
    find(&es, "/a/really/long/prefix/path/file.txt");
}

#[test]
fn walk_terminates_no_panic_on_junk() {
    // Random-ish blocks that pass no checksum but might confuse parsers.
    let mut img = vec![0u8; 4096];
    for (i, b) in img.iter_mut().enumerate() {
        *b = (i * 31 + 7) as u8;
    }
    let _ = TarParser.detect(&img.as_slice());
    if let Ok(fs) = TarParser.mount(src(img)) {
        let _: Vec<_> = fs.walk().take(10_000).collect();
    }
}
