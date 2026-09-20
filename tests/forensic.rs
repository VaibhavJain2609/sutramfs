//! Integration tests over the synthetic HFS+ corpus — `sutram-fat` style:
//! mount the byte-exact image, assert on the `FsEntry` stream.

mod common;

use std::io::Read;
use std::sync::{Arc, OnceLock};

use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsParser, MountOptions, RecoveryState,
};
use sutram_hfs::HfsParser;
use sutram_io::ByteSource;
use sutram_magic::{MagicType, Severity};

fn image() -> Arc<dyn ByteSource> {
    static IMG: OnceLock<Arc<dyn ByteSource>> = OnceLock::new();
    IMG.get_or_init(|| Arc::new(common::build_hfsplus()))
        .clone()
}

fn mount() -> Box<dyn sutram_fs::FileSystem> {
    HfsParser.mount(image()).unwrap()
}

fn all_entries() -> Vec<FsEntry> {
    mount()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .expect("walk should not error on the clean corpus")
}

fn find<'a>(entries: &'a [FsEntry], name: &str) -> &'a FsEntry {
    entries.iter().find(|e| e.name == name).unwrap_or_else(|| {
        panic!(
            "entry {name} not found; got {:?}",
            entries.iter().map(|e| &e.path).collect::<Vec<_>>()
        )
    })
}

#[test]
fn detects_hfsplus() {
    assert!(HfsParser.detect(image().as_ref()) >= DetectConfidence::High);
}

#[test]
fn detects_wrapped_hfsplus() {
    let img: Arc<dyn ByteSource> = Arc::new(common::build_wrapped());
    assert!(HfsParser.detect(img.as_ref()) >= DetectConfidence::High);
    let fs = HfsParser.mount(img).unwrap();
    let info = fs.info();
    assert_eq!(info.meta["wrapped"], "true");
    assert_eq!(info.meta["wrapper_label"], "HFSWrapper ");
}

#[test]
fn rejects_garbage_and_pure_hfs() {
    assert_eq!(
        HfsParser.detect(&vec![0u8; 4096].as_slice()),
        DetectConfidence::None
    );
    // Pure HFS: BD signature without an embedded H+ volume → not mountable.
    let mut img = vec![0u8; 8192];
    img[1024..1026].copy_from_slice(&0x4244u16.to_be_bytes());
    let src: Arc<dyn ByteSource> = Arc::new(img);
    assert!(HfsParser.detect(src.as_ref()) <= DetectConfidence::Medium);
    assert!(HfsParser.mount(src).is_err());
}

#[test]
fn info_reports_volume() {
    let info = mount().info();
    assert_eq!(info.fs_type, "HFS+");
    assert_eq!(info.label.as_deref(), Some("TestVol"));
    assert_eq!(info.block_size, 4096);
    assert_eq!(info.total_blocks, 80);
    assert_eq!(info.meta["journaled"], "true");
    assert_eq!(info.meta["journal_magic"], "0x4a4e4c78");
    assert!(info.meta.contains_key("journal_replay")); // TODO documented
}

#[test]
fn live_tree_walks() {
    let entries = all_entries();
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"/"));
    assert!(paths.contains(&"/hello.txt"));
    assert!(paths.contains(&"/subdir"));
    assert!(paths.contains(&"/subdir/inner.bin"));
    assert!(paths.contains(&"/Uniçødé Nåme.txt"));
    assert!(paths.iter().any(|p| p.contains("HFS+ Private Data")));
}

#[test]
fn timestamps_decode_1904_epoch() {
    let entries = all_entries();
    let e = find(&entries, "hello.txt");
    let c = e.timestamps.created.as_ref().unwrap();
    // createDate raw = 1705314620 + 2082844800; value = 2024-01-15T10:30:20Z.
    assert_eq!(c.raw_value, 1_705_314_620u64 + 2_082_844_800);
    assert_eq!(c.value, Some(1_705_314_620_000_000_000));
    assert_eq!(c.raw_encoding, "hfs+-u32-1904-local");
    assert_eq!(c.granularity, std::time::Duration::from_secs(1));
    assert!(e.timestamps.modified.is_some());
    assert!(e.timestamps.changed.is_some()); // attrMod → changed slot
}

#[test]
fn provenance_offsets() {
    let entries = all_entries();
    let e = find(&entries, "hello.txt");
    // Record lives in catalog node 1 (block 7 + 4096) — offsets vary with
    // record position; assert the region rather than a magic number.
    let cat_node1 = common::block_off(common::CAT_BLOCK) + common::NODE_SIZE;
    assert!(e.disk_offset >= cat_node1 as u64);
    assert!(e.disk_offset < (cat_node1 + common::NODE_SIZE) as u64);
    assert_eq!(
        e.allocated_ranges,
        vec![(common::block_off(14) as u64, 12)] // clipped to logical size
    );
}

#[test]
fn read_file_live() {
    let entries = all_entries();
    let e = find(&entries, "hello.txt");
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"hello world!");
}

#[test]
fn overflow_extents_merge() {
    let entries = all_entries();
    let e = find(&entries, "BIGFILE.BIN");
    assert_eq!(e.size, 9 * 4096);
    // 8 inline blocks + 1 overflow block via the extents file.
    assert_eq!(e.allocated_ranges.len(), 3);
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    // Tail byte range is the overflow extent at block 30.
    let tail = &buf[8 * 4096..8 * 4096 + 16];
    assert_eq!(tail, b"BIGFILE-BLOCK-30");
}

#[test]
fn resource_fork_and_xattr_entries() {
    let entries = all_entries();
    let r = find(&entries, "RICHES.TXT:rsrc");
    assert_eq!(r.size, 18);
    assert_eq!(r.meta["fork"], "rsrc");
    let mut buf = Vec::new();
    mount().read_file(r).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"RESOURCE-FORK-DATA");
    // xattr pseudo-entry + meta listing.
    let x = find(&entries, "hello.txt:xattr:com.apple.FinderInfo");
    assert_eq!(x.meta["xattr_storage"], "inline");
    assert_eq!(x.size, 32);
    let mut buf = Vec::new();
    mount().read_file(x).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, vec![0xABu8; 32]);
    let hello = find(&entries, "hello.txt");
    assert!(hello.meta["xattr_com.apple.FinderInfo"].contains("32 bytes"));
}

#[test]
fn hardlink_resolves_inode() {
    let entries = all_entries();
    let e = find(&entries, "hardlink.txt");
    assert_eq!(e.meta["hardlink"], "true");
    assert_eq!(e.meta["inode_ref"], "iNode50");
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"HARDLINK-DATA-HERE");
    // The inode itself is also enumerated under the private dir.
    let inode = find(&entries, "iNode50");
    assert!(inode.path.contains("HFS+ Private Data"));
}

#[test]
fn symlink_target() {
    let entries = all_entries();
    let e = find(&entries, "LINK");
    assert_eq!(e.kind, EntryKind::Symlink);
    assert_eq!(e.meta["symlink_target"], "/hello.txt");
}

#[test]
fn decmpfs_inline_zlib_decompresses() {
    let entries = all_entries();
    let e = find(&entries, "COMPRESSED.BIN");
    assert_eq!(e.meta["compressed"], "decmpfs");
    assert_eq!(e.meta["decmpfs_codec"], "zlib-inline");
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"decmpfs compressed payload hello hello hello");
}

#[test]
fn deleted_residue_leaf_free_space() {
    let entries = all_entries();
    let e = find(&entries, "DELETED.TXT");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    ));
    assert_eq!(e.meta["residue"], "leaf_free_space");
    assert_eq!(e.path, "/DELETED.TXT");
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"DELETED-BYTES!");
}

#[test]
fn deleted_residue_dead_node_partial_overwrite() {
    let entries = all_entries();
    let e = find(&entries, "OLDFILE.TXT");
    match e.status {
        FsEntryStatus::Deleted {
            recovery:
                RecoveryState::PartiallyOverwritten {
                    recovered_bytes,
                    total_bytes,
                },
        } => assert_eq!((recovered_bytes, total_bytes), (4096, 5000)),
        other => panic!("expected partial overwrite, got {other:?}"),
    }
    assert_eq!(e.meta["residue"], "dead_node");
    // Surviving extent is block 32 only.
    assert_eq!(
        e.allocated_ranges,
        vec![(common::block_off(32) as u64, 4096)]
    );
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.starts_with(b"OLDFILE-TAIL-SURVIVES"));
}

#[test]
fn deleted_residue_unrecoverable() {
    let entries = all_entries();
    let e = find(&entries, "GONE.BIN");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unrecoverable
        }
    ));
    assert!(e.allocated_ranges.is_empty());
    // Deleted folder residue from the same dead node.
    let d = find(&entries, "OLDDIR");
    assert!(d.is_deleted());
    assert_eq!(d.kind, EntryKind::Directory);
}

#[test]
fn orphan_extents_emitted() {
    let entries = all_entries();
    let o = entries
        .iter()
        .find(|e| e.path.starts_with("/$ORPHANED/") && e.name == "extents_99")
        .expect("orphan extents for cnid 99 not emitted");
    assert_eq!(o.meta["orphan"], "true");
    let mut buf = Vec::new();
    mount().read_file(o).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.starts_with(b"ORPHAN-EXTENT-DATA"));
}

#[test]
fn magic_verdicts() {
    let entries = all_entries();
    let e = find(&entries, "EVIL.DOC");
    let v = e.magic.as_ref().unwrap();
    assert!(v.mismatch);
    assert_eq!(v.severity, Severity::High);
    assert_eq!(v.detected, Some(MagicType::Pe));
    let e = find(&entries, "RESUME.DOCX");
    assert!(!e.magic.as_ref().unwrap().mismatch, "{:?}", e.magic);
    let e = find(&entries, "Uniçødé Nåme.txt");
    let v = e.magic.as_ref().unwrap();
    assert!(v.mismatch); // PNG bytes under .txt
    assert_eq!(v.detected, Some(MagicType::Png));
}

#[test]
fn deleted_entries_view() {
    let deleted: Vec<_> = mount()
        .deleted_entries()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let names: Vec<&str> = deleted.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"DELETED.TXT"));
    assert!(names.contains(&"OLDFILE.TXT"));
    assert!(names.contains(&"GONE.BIN"));
    assert!(!names.contains(&"hello.txt"));
}

#[test]
fn unallocated_ranges_from_bitmap() {
    let ranges = mount().unallocated_ranges();
    assert!(!ranges.is_empty());
    // Block 31 is free — its byte range must be covered.
    let t = common::block_off(31) as u64;
    assert!(ranges.iter().any(|(o, l)| *o <= t && t < o + l));
    // Block 14 (hello.txt) is allocated — must not appear.
    let used = common::block_off(14) as u64;
    assert!(!ranges.iter().any(|(o, l)| *o <= used && used < o + l));
}

#[test]
fn lenient_walk_survives_corruption() {
    let mut img = common::build_hfsplus();
    // Corrupt catalog node 2's descriptor: insane record count.
    let n2 = common::block_off(common::CAT_BLOCK) + 2 * common::NODE_SIZE;
    img[n2 + 10..n2 + 12].copy_from_slice(&5000u16.to_be_bytes());
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = HfsParser.mount(src).unwrap();
    let items: Vec<_> = fs.walk().collect();
    assert!(items.iter().any(|i| i.is_ok()));
}

#[test]
fn strict_mode_aborts() {
    let mut img = common::build_hfsplus();
    let n2 = common::block_off(common::CAT_BLOCK) + 2 * common::NODE_SIZE;
    img[n2 + 10..n2 + 12].copy_from_slice(&5000u16.to_be_bytes());
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = HfsParser.mount_with(src, &MountOptions::strict()).unwrap();
    let mut saw_err = false;
    let mut ok_after_err = 0;
    for item in fs.walk() {
        match item {
            Err(_) => saw_err = true,
            Ok(_) if saw_err => ok_after_err += 1,
            _ => {}
        }
    }
    assert!(saw_err);
    assert_eq!(ok_after_err, 0);
}
