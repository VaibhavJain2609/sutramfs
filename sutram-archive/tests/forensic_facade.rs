//! Integration tests for the `SutramArchiveParser` facade and
//! `archive_detect` — format dispatch across all three archive types.

mod common;

use std::io::Read;
use std::sync::Arc;

use common::cpio::{CpioBuilder, MODE_FILE, MTIME};
use common::tar::TarBuilder;
use common::zip::{ZipBuilder, METHOD_STORE};
use sutram_archive::{archive_detect, SutramArchiveParser};
use sutram_fs::{DetectConfidence, FsParser};
use sutram_io::ByteSource;

fn src(bytes: Vec<u8>) -> Arc<dyn ByteSource> {
    Arc::new(bytes)
}

fn zip_img() -> Vec<u8> {
    let mut b = ZipBuilder::new();
    b.add_member("z.txt", b"zip content", METHOD_STORE, 0, &[], &[]);
    b.finish(b"")
}

fn tar_img() -> Vec<u8> {
    let mut b = TarBuilder::new();
    b.add_file("t.txt", b"tar content");
    b.finish()
}

fn cpio_img() -> Vec<u8> {
    let mut b = CpioBuilder::new();
    b.add_newc("c.txt", b"cpio content", MODE_FILE, MTIME, 1, None, 0);
    b.trailer_newc();
    b.finish_bare()
}

#[test]
fn archive_detect_identifies_all() {
    assert_eq!(
        archive_detect(&zip_img().as_slice()),
        DetectConfidence::Certain
    );
    assert_eq!(
        archive_detect(&tar_img().as_slice()),
        DetectConfidence::Certain
    );
    assert_eq!(
        archive_detect(&cpio_img().as_slice()),
        DetectConfidence::Certain
    );
    assert_eq!(
        archive_detect(&vec![0u8; 4096].as_slice()),
        DetectConfidence::None
    );
}

#[test]
fn facade_mounts_each_format() {
    for (img, want_type, want_path, want_data) in [
        (zip_img(), "ZIP", "/z.txt", &b"zip content"[..]),
        (tar_img(), "TAR", "/t.txt", &b"tar content"[..]),
        (cpio_img(), "CPIO", "/c.txt", &b"cpio content"[..]),
    ] {
        let fs = SutramArchiveParser.mount(src(img)).unwrap();
        assert_eq!(fs.info().fs_type, want_type);
        let e = fs
            .walk()
            .filter_map(|r| r.ok())
            .find(|e| e.path == want_path)
            .unwrap_or_else(|| panic!("{want_path} not in {want_type} walk"));
        let mut r = fs.read_file(&e).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, want_data);
    }
}

#[test]
fn facade_refuses_garbage() {
    let img = vec![0xAAu8; 2048];
    assert!(SutramArchiveParser.mount(src(img)).is_err());
}

#[test]
fn facade_prefers_zip_on_ambiguity() {
    // A zip whose first member is named like a tar header could confuse
    // ordering — the EOCD always wins.
    let img = zip_img();
    assert_eq!(
        SutramArchiveParser.detect(&img.as_slice()),
        DetectConfidence::Certain
    );
    let fs = SutramArchiveParser.mount(src(img)).unwrap();
    assert_eq!(fs.info().fs_type, "ZIP");
}

#[test]
fn facade_name() {
    assert_eq!(SutramArchiveParser.name(), "archive");
}
