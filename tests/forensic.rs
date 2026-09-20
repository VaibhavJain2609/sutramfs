//! Integration tests over a synthetic two-checkpoint APFS container.
//!
//! `tests/common/mod.rs` documents the image layout: generation xid 1 holds
//! `old.txt` (deleted by xid 2), the live generation has `docs/`,
//! `photo.png` (+ hardlink `docs/alias.png`), an xattr, a snapshot name and
//! a snapshot-metadata record.

mod common;

use std::io::Read;
use std::sync::Arc;

use sutram_apfs::ApfsParser;
use sutram_fs::{
    DetectConfidence, EntryKind, FsEntryStatus, FsParser, FileSystem, MountOptions, RecoveryState,
};
use sutram_io::ByteSource;

fn mount(img: Vec<u8>) -> Box<dyn FileSystem> {
    let src: Arc<dyn ByteSource> = Arc::new(img);
    ApfsParser.mount(src).expect("mount should succeed")
}

fn entries(fs: &dyn FileSystem) -> Vec<sutram_fs::FsEntry> {
    fs.walk()
        .filter_map(|r| match r {
            Ok(e) => Some(e),
            Err(e) => panic!("walk error: {e}"),
        })
        .collect()
}

#[test]
fn detects_apfs_container() {
    let img = common::build_image(false);
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let c = ApfsParser.detect(src.as_ref());
    assert!(c >= DetectConfidence::High, "detect = {c:?}");
    assert_eq!(ApfsParser.name(), "apfs");
}

#[test]
fn detects_rejects_non_apfs() {
    let src: Arc<dyn ByteSource> = Arc::new(vec![0u8; 8192]);
    assert_eq!(ApfsParser.detect(src.as_ref()), DetectConfidence::None);
}

#[test]
fn mounts_and_walks_live_tree() {
    let img = common::build_image(false);
    let fs = mount(img);
    let info = fs.info();
    assert_eq!(info.fs_type, "APFS");
    assert_eq!(info.label.as_deref(), Some("TestVol"));
    assert_eq!(info.block_size, 4096);
    assert_eq!(info.meta["encrypted"], "false");
    assert_eq!(info.meta["checkpoint_xid"], "2");

    let es = entries(fs.as_ref());
    let by_path: std::collections::HashMap<_, _> =
        es.iter().map(|e| (e.path.as_str(), e)).collect();

    let root_docs = by_path["/docs"];
    assert_eq!(root_docs.kind, EntryKind::Directory);
    assert_eq!(root_docs.entry_id, 300);

    let photo = by_path["/photo.png"];
    assert_eq!(photo.kind, EntryKind::File);
    assert_eq!(photo.size, 8192);
    assert_eq!(photo.allocated_ranges.len(), 2);
    assert_eq!(photo.allocated_ranges[0], (30 * 4096, 4096));
    assert_eq!(photo.allocated_ranges[1], (32 * 4096, 4096));
    assert!(photo.disk_offset > 0, "provenance offset required");
    assert_eq!(photo.meta["xattr_com.apple.quarantine"], "4");
    assert_eq!(photo.meta["nlink"], "2");
    // Nanosecond timestamps decoded.
    assert!(photo.timestamps.created.as_ref().unwrap().value.is_some());

    // Second name of the same inode via a sibling link (hardlink).
    let alias = by_path["/docs/alias.png"];
    assert_eq!(alias.entry_id, 200);
    assert_eq!(alias.meta["hardlink"], "true");
    assert_eq!(alias.meta["sibling_id"], "0x1f4");

    // The drec for inner.txt points at oid 200 — it lives under docs/.
    let inner = by_path["/docs/inner.txt"];
    assert_eq!(inner.entry_id, 200);
}

#[test]
fn reads_file_contents() {
    let img = common::build_image(false);
    let fs = mount(img);
    let photo = entries(fs.as_ref())
        .into_iter()
        .find(|e| e.path == "/photo.png")
        .unwrap();
    let mut r = fs.read_file(&photo).unwrap();
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 8192);
    assert_eq!(&buf[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(&buf[4096..4104], b"PNGDATA2");

    // Bounded random access.
    let mut tail = [0u8; 8];
    let n = fs.read_file_at(&photo, 4096, &mut tail).unwrap();
    assert_eq!((n, &tail), (8, b"PNGDATA2"));
}

#[test]
fn magic_verdict_on_file() {
    let img = common::build_image(false);
    let fs = mount(img);
    let photo = entries(fs.as_ref())
        .into_iter()
        .find(|e| e.path == "/photo.png")
        .unwrap();
    let v = photo.magic.expect("check_magic default on");
    assert!(v.detected.is_some(), "PNG header should be detected");
}

#[test]
fn deleted_inode_recovered_from_prior_checkpoint() {
    let img = common::build_image(false);
    let fs = mount(img);
    let es = entries(fs.as_ref());
    let old = es
        .iter()
        .find(|e| e.path == "/old.txt")
        .expect("deleted entry must be emitted");
    match old.status {
        FsEntryStatus::Deleted { recovery } => {
            // old.txt used blocks 31 + 32; block 32 was reallocated to the
            // live file → the first 4 KiB survives.
            match recovery {
                RecoveryState::PartiallyOverwritten {
                    recovered_bytes,
                    total_bytes,
                } => {
                    assert_eq!(total_bytes, 8192);
                    assert_eq!(recovered_bytes, 4096);
                }
                other => panic!("expected partial recovery, got {other:?}"),
            }
        }
        other => panic!("expected Deleted status, got {other:?}"),
    }
    assert_eq!(old.allocated_ranges, vec![(31 * 4096, 4096)]);
    assert_eq!(old.meta["recovered_from_xid"], "1");
    // Recoverable extent is actually the old data.
    let mut r = fs.read_file(old).unwrap();
    let mut head = [0u8; 12];
    r.read_exact(&mut head).unwrap();
    assert_eq!(&head, b"deleted-data");
}

#[test]
fn snapshots_enumerated_and_mountable() {
    let img = common::build_image(false);
    let fs = mount(img);
    let info = fs.info();
    assert_eq!(info.meta["snapshot_count"], "1");
    assert_eq!(info.meta["snapshot_0_name"], "test-snap");
    assert_eq!(info.meta["snapshot_0_xid"], "1");

    // Mount the snapshot view: object resolution bounded to xid 1 → the
    // old generation's fs tree, where old.txt is still live.
    let src = fs.source();
    let snap = ApfsParser
        .mount_snapshot(src, &MountOptions::default(), 1)
        .expect("snapshot mount");
    let es = entries(snap.as_ref());
    let old = es.iter().find(|e| e.path == "/old.txt").unwrap();
    assert_eq!(old.status, FsEntryStatus::Live);
    assert_eq!(
        snap.info().meta["snapshot_view_xid"],
        "1"
    );
}

#[test]
fn encrypted_volume_detected_not_decrypted() {
    let img = common::build_image(true);
    let fs = mount(img);
    let info = fs.info();
    assert_eq!(info.meta["encrypted"], "true");
    let es = entries(fs.as_ref());
    let photo = es.iter().find(|e| e.path == "/photo.png").unwrap();
    assert_eq!(photo.meta["volume_encrypted"], "true");
}

#[test]
fn corrupt_block0_still_mounts_via_descriptor_area() {
    let mut img = common::build_image(false);
    common::corrupt_block(&mut img, 0);
    let fs = mount(img);
    let info = fs.info();
    assert_eq!(info.meta["block0_checksum_ok"], "false");
    assert_eq!(info.meta["checkpoint_xid"], "2");
    assert!(entries(fs.as_ref()).iter().any(|e| e.path == "/photo.png"));
}

#[test]
fn corrupt_latest_checkpoint_falls_back() {
    let mut img = common::build_image(false);
    // Kill the xid-2 container omap object → its checkpoint can't load;
    // lenient mount rolls back to xid 1 and reports the failure as a
    // walk-stream warning (the corruption is evidence, not hidden).
    common::corrupt_block(&mut img, 15);
    let fs = mount(img);
    let info = fs.info();
    assert_eq!(info.meta["checkpoint_xid"], "1");
    let mut saw_warning = false;
    let es: Vec<_> = fs
        .walk()
        .filter_map(|r| match r {
            Ok(e) => Some(e),
            Err(_) => {
                saw_warning = true;
                None
            }
        })
        .collect();
    assert!(saw_warning, "fallback must surface a warning in the stream");
    assert!(es.iter().any(|e| e.path == "/old.txt" && !e.is_deleted()));
}

#[test]
fn strict_mode_aborts_on_corruption() {
    let mut img = common::build_image(false);
    common::corrupt_block(&mut img, 15);
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let r = ApfsParser.mount_with(src, &MountOptions::strict());
    assert!(r.is_err());
}

#[test]
fn unallocated_ranges_cover_free_blocks() {
    let img = common::build_image(false);
    let fs = mount(img);
    let free = fs.unallocated_ranges();
    assert!(!free.is_empty());
    // Block 40 is untouched → inside a free range.
    let b40 = 40u64 * 4096;
    assert!(free.iter().any(|(o, l)| *o <= b40 && b40 < o + l));
    // Block 30 (live extent) must not be free.
    let b30 = 30u64 * 4096;
    assert!(!free.iter().any(|(o, l)| *o <= b30 && b30 < o + l));
}

#[test]
fn provenance_offsets_are_block_offsets() {
    let img = common::build_image(false);
    let fs = mount(img);
    for e in entries(fs.as_ref()) {
        assert!(e.disk_offset > 0);
        assert!(e.disk_offset < img_len() || e.is_deleted());
    }
    fn img_len() -> u64 {
        common::BLOCKS * 4096
    }
}

#[test]
fn truncated_image_errors_cleanly() {
    let img = common::build_image(false);
    let truncated = img[..3 * 4096].to_vec();
    let src: Arc<dyn ByteSource> = Arc::new(truncated);
    // Descriptor area is cut short → mount must fail, not panic.
    assert!(ApfsParser.mount(src).is_err());
}

#[test]
fn garbage_image_errors() {
    let src: Arc<dyn ByteSource> = Arc::new(vec![0xAAu8; 64 * 4096]);
    assert!(ApfsParser.mount(src).is_err());
}
