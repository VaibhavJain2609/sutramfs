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
    DetectConfidence, EntryKind, FileSystem, FsEntryStatus, FsParser, MountOptions, RecoveryState,
};
use sutram_io::ByteSource;

fn mount(img: Vec<u8>) -> Box<dyn FileSystem> {
    let src: Arc<dyn ByteSource> = Arc::new(img);
    ApfsParser.mount(src).expect("mount should succeed")
}

fn entries(fs: &dyn FileSystem) -> Vec<sutram_fs::FsEntry> {
    fs.walk()
        .map(|r| match r {
            Ok(e) => e,
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
    assert_eq!(info.meta["snapshot_count"], "2");
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
    assert_eq!(snap.info().meta["snapshot_view_xid"], "1");
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

#[test]
fn sparse_file_reads_holes_as_zeros() {
    let img = common::build_image(false);
    let fs = mount(img);
    let e = entries(fs.as_ref())
        .into_iter()
        .find(|e| e.path == "/sparse.bin")
        .expect("sparse.bin entry");
    assert_eq!(e.size, 12288);
    let mut buf = Vec::new();
    fs.read_file(&e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 12288);
    assert_eq!(&buf[0..8], b"SPARSE-1");
    assert!(
        buf[4096..8192].iter().all(|&b| b == 0),
        "logical hole must read as zeros, not next extent's bytes"
    );
    assert_eq!(&buf[8192..8200], b"SPARSE-2");
    // Random access across the hole boundary.
    let mut tail = [0u8; 8];
    fs.read_file_at(&e, 8192, &mut tail).unwrap();
    assert_eq!(&tail, b"SPARSE-2");
}

#[test]
fn descriptor_area_beyond_image_mounts_error_not_hang() {
    let mut img = common::build_image(false);
    // Point the block-0 label's descriptor base past the image tail.
    // Block 0 is parsed leniently → geometry is trusted; the scan must
    // clamp to device size and fail cleanly rather than hang/error at IO.
    img[112..120].copy_from_slice(&(u64::MAX / 2).to_le_bytes());
    let src: Arc<dyn ByteSource> = Arc::new(img);
    assert!(ApfsParser.mount(src).is_err());
}

#[test]
fn hostile_checkpoint_sizes_do_not_hang_mount() {
    let mut img = common::build_image(false);
    // Absurd xp_desc_blocks in block-0 label (high bit = contiguous flag
    // clear) — the scan is bounded by device size either way.
    img[104..108].copy_from_slice(&(u32::MAX / 2).to_le_bytes());
    let fs = mount(img);
    // Mount still succeeds (descriptor area clamps to the real 8 blocks).
    assert_eq!(fs.info().meta["checkpoint_xid"], "2");
}

#[test]
fn misc_meta_fixtures() {
    let img = common::build_image(false);
    let fs = mount(img);
    let es = entries(fs.as_ref());
    let by_path: std::collections::HashMap<_, _> =
        es.iter().map(|e| (e.path.as_str(), e)).collect();

    // Slack: 100 bytes in a 4K extent.
    let tiny = by_path["/tiny.txt"];
    assert_eq!(tiny.meta["slack_len"], "3996");
    assert!(tiny.meta.contains_key("slack_offset"));

    // Crypto-state record + per-extent crypto ids → flagged, never decrypted.
    let photo = by_path["/photo.png"];
    assert_eq!(photo.meta["extent_encrypted"], "true");
    assert_eq!(
        photo.meta["xattr_com.apple.ResourceFork_stream_oid"],
        "0xbeef"
    );
    let sparse = by_path["/sparse.bin"];
    assert_eq!(sparse.meta["extent_1_crypto_id"], "0x99");

    // Symlink target lifted from the embedded xattr.
    let link = by_path["/link"];
    assert_eq!(link.kind, EntryKind::Symlink);
    assert_eq!(link.meta["symlink_target"], "docs/target");

    // Inode xfields.
    let docs = by_path["/docs"];
    assert_eq!(docs.meta["finder_info"], "true");
    assert_eq!(docs.meta["document_id"], "77");
    assert_eq!(docs.meta["prev_fsize"], "9999");
    assert_eq!(docs.meta["sparse_bytes"], "128");
    assert_eq!(docs.meta["rdev"], "0x1020304");
    assert_eq!(docs.meta["inode_snap_xid"], "85");

    // Unhandled record types + phys-extent claims.
    let info = fs.info();
    assert_eq!(info.meta["phys_extent_records"], "1");
    assert!(info.meta["unhandled_jrec_types"].contains("0x6"));
}

#[test]
fn mount_volume_by_index() {
    let img = common::build_image(false);
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = ApfsParser
        .mount_volume(src, &MountOptions::default(), 0)
        .expect("mount_volume");
    assert_eq!(fs.info().meta["volume_index"], "0");
}

#[test]
fn orphans_and_broken_chains() {
    let img = common::build_image(false);
    let fs = mount(img);
    let es = entries(fs.as_ref());
    // Inode with no drec → orphan bucket.
    let orphan = es
        .iter()
        .find(|e| e.path.contains("$ORPHANED") && e.entry_id == 404)
        .expect("orphan inode entry");
    assert_eq!(orphan.meta["orphan"], "true");
    // drec whose parent chain is broken → orphan path + note.
    let stray = es.iter().find(|e| e.entry_id == 403).expect("stray entry");
    assert!(stray.meta["note"].contains("parent directory chain"));
    // Sibling-map mismatch: alias3 maps to a different oid.
    let a3 = es
        .iter()
        .find(|e| e.path.ends_with("alias3.png"))
        .expect("alias3 entry");
    assert!(a3.meta["note"].contains("sibling map"));
    let a2 = es
        .iter()
        .find(|e| e.path.ends_with("alias2.png"))
        .expect("alias2 entry");
    assert_eq!(a2.meta["note"], "sibling map entry missing");
}

#[test]
fn deleted_fixture_variants() {
    let img = common::build_image(false);
    let fs = mount(img);
    let es = entries(fs.as_ref());
    // Lost.txt: deleted and its old-generation parent chain is broken.
    let lost = es
        .iter()
        .find(|e| e.entry_id == 500 && e.is_deleted())
        .expect("lost.txt deleted entry");
    assert!(lost.path.contains("$ORPHANED"));
    // empty.bin: size but no extents → Unrecoverable.
    let empty = es
        .iter()
        .find(|e| e.entry_id == 501 && e.is_deleted())
        .expect("empty.bin deleted entry");
    match empty.status {
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unrecoverable,
        } => {}
        other => panic!("expected Unrecoverable, got {other:?}"),
    }
}

#[test]
fn directory_read_rejected() {
    let img = common::build_image(false);
    let fs = mount(img);
    let docs = entries(fs.as_ref())
        .into_iter()
        .find(|e| e.path == "/docs")
        .unwrap();
    assert!(fs.read_file(&docs).is_err());
}

#[test]
fn all_checkpoints_corrupt_fails_mount() {
    let mut img = common::build_image(false);
    common::corrupt_block(&mut img, 15); // container omap @xid2
    common::corrupt_block(&mut img, 9); // container omap @xid1
    let src: Arc<dyn ByteSource> = Arc::new(img);
    assert!(ApfsParser.mount(src).is_err());
}

#[test]
fn noncontiguous_descriptor_area_rejected() {
    let mut img = common::build_image(false);
    // High bit of nx_xp_desc_blocks = descriptor B-tree, unsupported.
    img[104..108].copy_from_slice(&0x8000_0008u32.to_le_bytes());
    let src: Arc<dyn ByteSource> = Arc::new(img);
    assert!(ApfsParser.mount(src).is_err());
}

#[test]
fn corrupt_volume_superblock_rolls_back_checkpoint() {
    let mut img = common::build_image(false);
    common::corrupt_block(&mut img, 17); // apsb @xid2
    let fs = mount(img);
    // xid2 can't load its volume → fall back to the xid-1 generation, with
    // the failure surfaced as a walk-stream warning.
    assert_eq!(fs.info().meta["checkpoint_xid"], "1");
    let mut warned = false;
    let es: Vec<_> = fs
        .walk()
        .filter_map(|r| match r {
            Ok(e) => Some(e),
            Err(_) => {
                warned = true;
                None
            }
        })
        .collect();
    assert!(warned, "rollback must surface the xid-2 failure");
    assert!(es.iter().any(|e| e.path == "/old.txt" && !e.is_deleted()));
}

#[test]
fn all_volumes_corrupt_fails_mount() {
    let mut img = common::build_image(false);
    common::corrupt_block(&mut img, 17); // apsb @xid2
    common::corrupt_block(&mut img, 11); // apsb @xid1
    let src: Arc<dyn ByteSource> = Arc::new(img);
    assert!(ApfsParser.mount(src).is_err());
}

#[test]
fn checkpoint_map_count_clamped_to_block() {
    let mut img = common::build_image(false);
    // Absurd cpm_count in the xid-2 checkpoint map; entries past the block
    // end are ignored — mount still succeeds.
    img[4 * 4096 + 36..4 * 4096 + 40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    common::seal(&mut img[4 * 4096..5 * 4096]);
    let fs = mount(img);
    assert_eq!(fs.info().meta["checkpoint_xid"], "2");
}

#[test]
fn sealed_volume_flag_reported() {
    let mut img = common::build_image(false);
    // apfs_incompatible_features @apsb+56: add SEALED_VOLUME (0x20).
    let off = 17 * 4096 + 56;
    let mut v = u64::from_le_bytes(img[off..off + 8].try_into().unwrap());
    v |= 0x20;
    img[off..off + 8].copy_from_slice(&v.to_le_bytes());
    common::seal(&mut img[17 * 4096..18 * 4096]);
    let fs = mount(img);
    assert_eq!(fs.info().meta["sealed"], "true");
}

#[test]
fn hardlink_broken_parent_orphaned() {
    let img = common::build_image(false);
    let fs = mount(img);
    let a4 = entries(fs.as_ref())
        .into_iter()
        .find(|e| e.name == "alias4.png")
        .expect("alias4 entry");
    assert!(a4.path.contains("$ORPHANED"));
    assert!(a4.meta["note"].contains("hardlink parent chain"));
}

#[test]
fn snapshot_meta_without_name_record() {
    // A snap-meta record whose xid has no SNAP_NAME record still yields a
    // report entry (unnamed snapshot).
    assert_eq!(
        mount(common::build_image(false)).info().meta["snapshot_count"],
        "2"
    );
}

#[test]
fn read_file_unknown_entry_uses_ranges_fallback() {
    let img = common::build_image(false);
    let fs = mount(img);
    // Fabricated entry not present in the record tables → reader falls back
    // to treating allocated_ranges as a contiguous stream.
    let fake = sutram_fs::FsEntry {
        path: "/fake".into(),
        name: "fake".into(),
        entry_id: 0x00FF_FFFF,
        kind: EntryKind::File,
        size: 8,
        disk_offset: 0,
        allocated_ranges: vec![(32 * 4096, 4096)],
        timestamps: Default::default(),
        status: FsEntryStatus::Live,
        meta: Default::default(),
        magic: None,
    };
    let mut head = [0u8; 8];
    fs.read_file(&fake).unwrap().read_exact(&mut head).unwrap();
    assert_eq!(&head, b"PNGDATA2");
}
