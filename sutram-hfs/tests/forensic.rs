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
fn alternate_volume_header_fallback() {
    // TN1150: the alternate volume header starts 1024 bytes before the
    // end of the volume. Copy the primary there, then destroy the primary.
    let mut img = common::build_hfsplus();
    let alt = img.len() - 1024;
    img.copy_within(1024..1536, alt);
    // 1) Bad signature at 1024 → mount via the alternate copy.
    img[1024..1026].copy_from_slice(&0xDEADu16.to_be_bytes());
    let src: Arc<dyn ByteSource> = Arc::new(img.clone());
    let fs = HfsParser.mount(src).unwrap();
    let info = fs.info();
    assert_eq!(info.fs_type, "HFS+");
    assert_eq!(info.meta["alt_volume_header"], "true");
    assert!(fs.walk().any(|e| e.is_ok()));

    // 2) Primary decodes as H+ but fails validation → also falls back.
    let mut img = common::build_hfsplus();
    let alt = img.len() - 1024;
    img.copy_within(1024..1536, alt);
    img[1024 + 40..1024 + 44].copy_from_slice(&4097u32.to_be_bytes()); // bad block size
    let src: Arc<dyn ByteSource> = Arc::new(img);
    assert!(HfsParser.mount(src).is_ok());

    // 3) Both copies destroyed → mount must fail.
    let mut img = common::build_hfsplus();
    let alt = img.len() - 1024;
    img.copy_within(1024..1536, alt);
    for b in &mut img[1024..1536] {
        *b = 0;
    }
    img[alt..alt + 2].copy_from_slice(&0xDEADu16.to_be_bytes());
    let src: Arc<dyn ByteSource> = Arc::new(img);
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
    // Journal buffer parsed: header + 2 live transactions + 1 stale +
    // 4 journaled block copies.
    assert_eq!(info.meta["journal_start"], "0x200");
    assert_eq!(info.meta["journal_end"], "0x880");
    assert_eq!(info.meta["journal_endian"], "big");
    assert_eq!(info.meta["journal_transactions"], "2");
    assert_eq!(info.meta["journal_stale_transactions"], "1");
    assert_eq!(info.meta["journal_block_copies"], "4");
    assert_eq!(info.meta["journal_parse_errors"], "0");
}

#[test]
fn journal_entries_surface_transactions() {
    let fs = mount();
    let entries: Vec<FsEntry> = fs
        .journal_entries()
        .collect::<Result<Vec<_>, _>>()
        .expect("journal parse should not error on the corpus");
    // 3 transactions + 4 block copies (header is meta-only).
    assert_eq!(
        entries.len(),
        7,
        "{:?}",
        entries.iter().map(|e| &e.path).collect::<Vec<_>>()
    );

    let tx0 = find(&entries, "tx_0");
    assert_eq!(tx0.path, "/$JOURNAL/tx_0");
    assert_eq!(tx0.meta["journal"], "hfs+");
    assert_eq!(tx0.meta["num_blocks"], "2");
    assert_eq!(tx0.meta["checksum_ok"], "true");
    assert_eq!(tx0.meta["live"], "true");

    // Each journaled copy reads back its payload via allocated_ranges.
    let c = find(&entries, "sector_100");
    assert_eq!(c.path, "/$JOURNAL/tx_0/sector_100");
    assert_eq!(c.meta["hfs_journal_tx"], "0");
    assert_eq!(c.meta["target_sector"], "100");
    assert_eq!(c.meta["target_offset"], "0xc800"); // 100 × 512
    assert_eq!(
        c.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    );
    assert_eq!(c.allocated_ranges.len(), 1);
    let mut buf = Vec::new();
    fs.read_file(c).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.starts_with(b"JOURNALED-SECTOR-100"));

    // The stale transaction is flagged as overwritten history.
    let stale = find(&entries, "tx_2");
    assert_eq!(stale.meta["live"], "false");
    assert_eq!(stale.meta["checksum_ok"], "true");
    assert!(stale.meta["note"].contains("stale"));
    let s400 = find(&entries, "sector_400");
    assert_eq!(s400.meta["hfs_journal_tx"], "2");

    // Journal evidence must not leak into the normal walk.
    let walked = all_entries();
    assert!(!walked.iter().any(|e| e.path.starts_with("/$JOURNAL/")));
}

#[test]
fn journal_events_typed_stream() {
    use sutram_hfs::{HfsFs, JournalEventKind};
    let fs = HfsFs::mount(image(), MountOptions::default()).unwrap();
    let events = fs.journal_events().collect::<Result<Vec<_>, _>>().unwrap();
    // header + 2 live tx (2+1 copies) + 1 stale tx (1 copy) = 8 events.
    assert_eq!(events.len(), 8);
    let JournalEventKind::Header { start, end, .. } = events[0].kind else {
        panic!("first event should be the journal header: {:?}", events[0])
    };
    assert_eq!((start, end), (512, 2176));
    let JournalEventKind::Transaction { live, num_blocks, .. } = &events[1].kind else {
        panic!("event 1 should be a transaction: {:?}", events[1].kind)
    };
    assert!(*live && *num_blocks == 2);
    let JournalEventKind::BlockCopy { copy, .. } = &events[2].kind else {
        panic!("event 2 should be a block copy: {:?}", events[2].kind)
    };
    assert_eq!(copy.target_sector, 100);
    assert_eq!(copy.bytes, 512);
    let JournalEventKind::Transaction { live, .. } = &events[6].kind else {
        panic!("event 6 should be the stale transaction: {:?}", events[6].kind)
    };
    assert!(!*live);
}

#[test]
fn journal_corruption_lenient_and_strict() {
    // Corrupt the live chain: overwrite tx1's block_list_header magic
    // fields so its num_blocks is implausible — the chain reports the
    // break, then the sweep still finds the stale list.
    let mut img = common::build_hfsplus();
    let jb = common::block_off(common::JOURNAL_BLOCK);
    img[jb + 1600 + 2..jb + 1600 + 4].copy_from_slice(&0x00FFu16.to_be_bytes());
    let fs = HfsParser.mount(Arc::new(img.clone())).unwrap();
    let items: Vec<_> = fs.journal_entries().collect();
    assert!(items.iter().any(|i| i.is_err()));
    // Stale transaction still recovered via the checksum sweep.
    let names: Vec<String> = items
        .iter()
        .filter_map(|i| i.as_ref().ok().map(|e| e.name.clone()))
        .collect();
    assert!(names.contains(&"tx_1".to_string()), "{names:?}");

    // Strict: the corrupt header is terminal.
    let fs = HfsParser
        .mount_with(Arc::new(img), &MountOptions::strict())
        .unwrap();
    let items: Vec<_> = fs.journal_entries().collect();
    assert!(items.last().unwrap().is_err());
}

#[test]
fn journal_bad_magic_is_error_not_panic() {
    let mut img = common::build_hfsplus();
    let jb = common::block_off(common::JOURNAL_BLOCK);
    img[jb] = 0; // break 'JNLx'
    let fs = HfsParser.mount(Arc::new(img)).unwrap();
    let items: Vec<_> = fs.journal_entries().collect();
    assert_eq!(items.len(), 1);
    assert!(items[0].is_err());
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
fn decmpfs_rsrc_table_decompresses() {
    // decmpfs compression_type 4: zlib payload chunked through the
    // CmpfRsrcHead block table in the resource fork.
    let entries = all_entries();
    let e = find(&entries, "RSRCCOMP.BIN");
    assert_eq!(e.meta["compressed"], "decmpfs");
    assert_eq!(e.meta["decmpfs_type"], "4");
    assert_eq!(e.meta["decmpfs_codec"], "zlib-resource-fork");
    assert_eq!(e.size, 44); // uncompressed size, not the stored table size
    // No `:rsrc` pseudo-entry — the rsrc is compressed payload.
    assert!(!entries.iter().any(|x| x.name == "RSRCCOMP.BIN:rsrc"));
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"resource fork compressed payload hello hello");
}

#[test]
fn unreachable_records_become_orphans() {
    // Records keyed to a parent CNID with no folder record are live
    // catalog records that the tree walk can't reach → /$ORPHANED/.
    let entries = all_entries();
    let o = entries
        .iter()
        .find(|e| e.name == "ORPHAN.TXT")
        .expect("orphan file not emitted");
    assert!(o.path.starts_with("/$ORPHANED/"));
    assert_eq!(o.meta["orphan"], "true");
    assert!(o.is_deleted());
    let mut buf = Vec::new();
    mount().read_file(o).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.starts_with(b"ORPHANED-FILE-DATA"));
    let d = entries
        .iter()
        .find(|e| e.name == "ORPHDIR")
        .expect("orphan dir not emitted");
    assert!(d.path.starts_with("/$ORPHANED/"));
    assert_eq!(d.kind, EntryKind::Directory);
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
fn orphans_disabled_by_option() {
    // MountOptions::include_orphans = false → OrphanLive / OrphanExtents
    // 两个阶段整体跳过，no /$ORPHANED/ entries at all.
    let src: Arc<dyn ByteSource> = Arc::new(common::build_hfsplus());
    let opts = MountOptions {
        include_orphans: false,
        ..Default::default()
    };
    let fs = HfsParser.mount_with(src, &opts).unwrap();
    let entries: Vec<_> = fs.walk().filter_map(|i| i.ok()).collect();
    assert!(!entries.iter().any(|e| e.path.contains("$ORPHANED")));
    // Live tree + residue still emit.
    assert!(entries.iter().any(|e| e.name == "hello.txt"));
    assert!(entries.iter().any(|e| e.name == "DELETED.TXT"));
}

#[test]
fn strict_walk_dies_on_mount_note() {
    // Corrupt the attributes-tree header node → build_trees records a
    // mount_note → strict walk replays it as the FIRST item then ends.
    let mut img = common::build_hfsplus();
    let attr0 = common::block_off(common::ATTR_BLOCK);
    img[attr0 + 8] = 0xFF; // kind: header → leaf, invalid
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = HfsParser.mount_with(src, &MountOptions::strict()).unwrap();
    let mut items = fs.walk();
    assert!(items.next().unwrap().is_err());
    assert!(items.next().is_none());
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
