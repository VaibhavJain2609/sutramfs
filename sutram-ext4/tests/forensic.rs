//! Integration tests over the synthetic ext4/ext2 corpora.

mod common;

use std::io::Read;
use std::sync::Arc;
use std::sync::OnceLock;

use sutram_ext4::Ext4Parser;
use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsParser, MountOptions, RecoveryState,
};
use sutram_io::ByteSource;
use sutram_magic::{MagicType, Severity};

fn image() -> Arc<dyn ByteSource> {
    static IMG: OnceLock<Arc<dyn ByteSource>> = OnceLock::new();
    IMG.get_or_init(|| Arc::new(common::build_ext4())).clone()
}

fn mount() -> Box<dyn sutram_fs::FileSystem> {
    Ext4Parser.mount(image()).unwrap()
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
fn detects_ext4() {
    assert!(Ext4Parser.detect(image().as_ref()) >= DetectConfidence::High);
    // Garbage and zeroed images must not detect.
    assert_eq!(
        Ext4Parser.detect(&vec![0u8; 8192].as_slice()),
        DetectConfidence::None
    );
    assert_eq!(
        Ext4Parser.detect(&vec![0xABu8; 8192].as_slice()),
        DetectConfidence::None
    );
    // Truncated before the superblock → None.
    assert_eq!(
        Ext4Parser.detect(&vec![0u8; 1024].as_slice()),
        DetectConfidence::None
    );
}

#[test]
fn info_reports_volume() {
    let info = mount().info();
    assert_eq!(info.fs_type, "EXT4");
    assert_eq!(info.label.as_deref(), Some("EXT4TEST"));
    assert_eq!(
        info.uuid.as_deref(),
        Some("00112233-4455-6677-8899-aabbccddeeff")
    );
    assert_eq!(info.block_size, 1024);
    assert_eq!(info.total_blocks, common::TOTAL_BLOCKS as u64);
    assert_eq!(info.total_nodes, Some(common::IPG as u64));
    assert!(info.free_blocks.unwrap() > 0);
    // Feature flags surfaced in meta.
    assert_eq!(info.meta["incompat_extents"], "true");
    assert_eq!(info.meta["compat_has_journal"], "true");
    assert_eq!(info.meta["incompat_64bit"], "false");
    assert_eq!(info.meta["incompat_encrypt"], "false");
    assert_eq!(info.meta["journal_inode"], "8");
    assert_eq!(info.meta["last_orphan"], "26");
    // jbd2 awareness: s_start != 0 → replay pending, parsed log counts.
    assert_eq!(info.meta["jbd2_needs_replay"], "true");
    assert_eq!(info.meta["jbd2_journal_blocks"], "8");
    assert_eq!(info.meta["jbd2_feature_incompat"], "0x1");
    assert_eq!(info.meta["jbd2_features"], "revoke");
    // Log contents: 2 descriptors, 1 commit, 1 revoke, 3 journaled copies.
    assert_eq!(info.meta["jbd2_descriptor_blocks"], "2");
    assert_eq!(info.meta["jbd2_commit_blocks"], "1");
    assert_eq!(info.meta["jbd2_revoke_blocks"], "1");
    assert_eq!(info.meta["jbd2_revoked_blocks"], "1");
    assert_eq!(info.meta["jbd2_journaled_blocks"], "3");
    assert_eq!(info.meta["jbd2_transactions"], "1");
    assert_eq!(info.meta["jbd2_parse_errors"], "0");
    assert_eq!(info.meta["jbd2_last_transid"], "258"); // 0x102 (superblock sequence)
    // Prior-metadata copies: inode table (5), freed data (43), bitmap (3).
    assert_eq!(info.meta["jbd2_prior_metadata_copies"], "3");
}

#[test]
fn live_tree_walks() {
    let entries = all_entries();
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    for p in [
        "/",
        "/hello.txt",
        "/hello2.txt",
        "/subdir",
        "/subdir/inner.txt",
        "/newfile.bin",
        "/shadow.bin",
        "/docs.docx",
        "/evil.doc",
        "/link",
        "/big.dat",
        "/big2.dat",
        "/café.txt",
        "/tiny",
        "/slowlink",
        "/x",
    ] {
        assert!(paths.contains(&p), "missing {p}: {paths:?}");
    }
    // Reserved/deleted inodes are not live paths.
    assert!(!paths.iter().any(|p| p.ends_with("/gone.dat")));
}

#[test]
fn live_file_reads_back() {
    let entries = all_entries();
    let e = find(&entries, "hello.txt");
    assert_eq!(e.kind, EntryKind::File);
    assert_eq!(e.entry_id, 11);
    // dirent provenance: hello.txt is the 3rd dirent in block 40
    // (".", ".." at 0,12 → hello.txt at 24).
    assert_eq!(e.disk_offset, common::dirent_off(40, 24) as u64);
    assert_eq!(e.allocated_ranges, vec![(common::blk_off(41) as u64, 1024)]);
    assert_eq!(e.meta["inode"], "11");
    assert_eq!(e.meta["mapping"], "extents");
    let mut buf = Vec::new();
    mount()
        .read_file(e)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    assert_eq!(buf, b"hello ext4!\n");
    // Random access.
    let mut b = [0u8; 4];
    let n = mount().read_file_at(e, 6, &mut b).unwrap();
    assert_eq!(&b[..n], b"ext4");
}

#[test]
fn nsec_and_crtime_timestamps() {
    let entries = all_entries();
    let e = find(&entries, "hello.txt");
    let m = e.timestamps.modified.as_ref().unwrap();
    assert_eq!(m.value, Some(1_705_314_620_500_000_000));
    assert_eq!(m.raw_encoding, "ext4-sec+nsec");
    assert_eq!(m.granularity, std::time::Duration::from_nanos(1));
    let c = e.timestamps.created.as_ref().unwrap();
    assert_eq!(c.value, Some(1_705_310_000_250_000_000));
    // dtime unset → slot present, value None.
    let d = e.timestamps.deleted.as_ref().unwrap();
    assert_eq!(d.value, None);
    // Second-resolution inode (subdir) → 1 s granularity.
    let s = find(&entries, "subdir");
    let sm = s.timestamps.modified.as_ref().unwrap();
    assert_eq!(sm.granularity, std::time::Duration::from_secs(1));
}

#[test]
fn hardlink_and_symlink() {
    let entries = all_entries();
    let h2 = find(&entries, "hello2.txt");
    assert_eq!(h2.meta["hardlink_of"], "/hello.txt");
    assert_eq!(h2.meta["links_count"], "2");
    let link = find(&entries, "link");
    assert_eq!(link.kind, EntryKind::Symlink);
    assert_eq!(link.meta["symlink_target"], "hello.txt");
    // Slow symlink: target lives in the data block, not i_block.
    let slow = find(&entries, "slowlink");
    assert_eq!(slow.kind, EntryKind::Symlink);
    assert_eq!(slow.meta["symlink_target"], "/hello.txt");
}

#[test]
fn inline_data_file_reads() {
    let entries = all_entries();
    let e = find(&entries, "tiny");
    assert_eq!(e.meta["inline_data"], "true");
    assert_eq!(e.meta["mapping"], "inline");
    // Provenance points inside the inode itself: the 60-byte i_block
    // payload plus the 15-byte "system.data" xattr spillover.
    assert_eq!(e.allocated_ranges.len(), 2);
    assert_eq!(
        e.allocated_ranges[0],
        (common::inode_off(30) as u64 + 0x28, 60)
    );
    assert_eq!(
        e.allocated_ranges[1],
        (common::inode_off(30) as u64 + 241, 15)
    );
    let mut buf = Vec::new();
    mount()
        .read_file(e)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    let mut want = Vec::new();
    for i in 0..60 {
        want.push(b'A' + (i % 26) as u8);
    }
    want.extend_from_slice(b"SPILLOVER-TAIL!");
    assert_eq!(buf, want);
    assert_eq!(e.size, 75);
}

#[test]
fn xattrs_listed() {
    let entries = all_entries();
    let e = find(&entries, "hello.txt");
    let names = &e.meta["xattrs"];
    assert!(names.contains("security.selinux"), "{names}");
    assert!(names.contains("user.comment"), "{names}");
}

#[test]
fn depth1_extent_tree_reads() {
    let entries = all_entries();
    let e = find(&entries, "big2.dat");
    // depth-1 tree: idx → leaf block 54 → extents 55,56.
    let mut buf = Vec::new();
    mount()
        .read_file(e)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    assert_eq!(buf.len(), 1500);
    assert!(buf.starts_with(b"BIG2-FIRST"));
    assert_eq!(&buf[1024..1034], b"BIG2-SECON");
}

#[test]
fn slack_carve_recovers_deleted_name() {
    let entries = all_entries();
    let e = find(&entries, "notes.txt");
    assert_eq!(e.path, "/notes.txt");
    assert_eq!(e.meta["carved_dirent"], "true");
    assert_eq!(e.meta["inode"], "24");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    ));
    // carved dirent offset: root dir block 40, slack after "x" (pos 308).
    assert_eq!(e.disk_offset, common::dirent_off(40, 320) as u64);
    // deleted-time populated.
    let d = e.timestamps.deleted.as_ref().unwrap();
    assert_eq!(d.value, Some(1_705_320_300_000_000_000));
    // data survives and reads back.
    let mut buf = Vec::new();
    mount()
        .read_file(e)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    assert_eq!(buf, b"NOTESDATA");
}

#[test]
fn carved_dirent_with_cleared_inode() {
    let entries = all_entries();
    let e = find(&entries, "buried.tmp");
    assert_eq!(e.path, "/subdir/buried.tmp");
    assert_eq!(e.meta["inode_cleared"], "true");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unrecoverable
        }
    ));
}

#[test]
fn deleted_inode_intact() {
    let entries = all_entries();
    let e = find(&entries, "ino_13");
    assert_eq!(e.path, "/$ORPHANED/0xd");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    ));
    let mut buf = Vec::new();
    mount()
        .read_file(e)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    assert_eq!(buf, b"deadbeef42");
}

#[test]
fn deleted_inode_partially_overwritten() {
    let entries = all_entries();
    let e = find(&entries, "ino_15");
    match e.status {
        FsEntryStatus::Deleted {
            recovery:
                RecoveryState::PartiallyOverwritten {
                    recovered_bytes,
                    total_bytes,
                },
        } => {
            // block 45 was reallocated; block 46 survives with the tail.
            assert_eq!((recovered_bytes, total_bytes), (376, 1400));
        }
        other => panic!("expected partial overwrite, got {other:?}"),
    }
    assert_eq!(e.allocated_ranges, vec![(common::blk_off(46) as u64, 1024)]);
    // The recovery notes name the thief.
    let notes: Vec<&String> = e
        .meta
        .iter()
        .filter(|(k, _)| k.starts_with("recovery_note_"))
        .map(|(_, v)| v)
        .collect();
    assert!(notes.iter().any(|n| n.contains("/newfile.bin")));
    let mut buf = Vec::new();
    mount()
        .read_file(e)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    assert!(buf.starts_with(b"OLD LOG TAIL"));
}

#[test]
fn deleted_inode_unrecoverable() {
    let entries = all_entries();
    let e = find(&entries, "ino_19");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unrecoverable
        }
    ));
    assert!(e.allocated_ranges.is_empty());
}

#[test]
fn orphan_inodes_and_journal() {
    let entries = all_entries();
    // Orphan inode 20: allocated, unreferenced.
    let o = find(&entries, "ino_20");
    assert_eq!(o.path, "/$ORPHANED/0x14");
    assert_eq!(o.meta["orphan"], "true");
    let mut buf = Vec::new();
    mount()
        .read_file(o)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    assert!(buf.starts_with(b"ORPHAN-INODE-DATA"));
    // Orphan-list head (s_last_orphan = 26).
    let o = find(&entries, "ino_26");
    assert_eq!(o.meta["orphan_list"], "true");
    // Journal inode 8.
    let j = find(&entries, "ino_8");
    assert_eq!(j.meta["journal"], "true");
}

#[test]
fn journal_entries_surface_prior_state() {
    let fs = mount();
    let entries: Vec<FsEntry> = fs
        .journal_entries()
        .collect::<Result<Vec<_>, _>>()
        .expect("journal parse should not error on the corpus");
    // 3 journaled copies + 1 revoke + 1 commit = 5 entries.
    assert_eq!(entries.len(), 5, "{:?}", entries.iter().map(|e| &e.path).collect::<Vec<_>>());

    // The inode-table copy (fs block 5) is prior metadata state — its
    // payload reads back the journaled bytes.
    let it = find(&entries, "block_5");
    assert_eq!(it.path, "/$JOURNAL/tx_256/block_5");
    assert_eq!(it.kind, EntryKind::Other);
    assert!(it.is_deleted());
    assert_eq!(it.meta["journal"], "jbd2");
    assert_eq!(it.meta["jbd2_transid"], "256");
    assert_eq!(it.meta["jbd2_target"], "inode_table_g0");
    assert_eq!(it.meta["jbd2_tag_uuid"], "true");
    assert_eq!(
        it.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    );
    assert_eq!(it.disk_offset, common::blk_off(31) as u64 + 12); // tag offset
    assert_eq!(it.allocated_ranges, vec![(common::blk_off(32) as u64, 1024)]);
    let mut buf = Vec::new();
    fs.read_file(it).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.starts_with(b"JOURNALED-INODE-TABLE-BLOCK-5"));

    // The freed data block (fs 43) is also prior-state evidence.
    let freed = find(&entries, "block_43");
    assert_eq!(freed.meta["jbd2_target"], "data");
    assert_eq!(freed.meta["jbd2_target_allocated"], "false");

    // The block-bitmap copy from the uncommitted tail transaction.
    let bbm = find(&entries, "block_3");
    assert_eq!(bbm.path, "/$JOURNAL/tx_257/block_3");
    assert_eq!(bbm.meta["jbd2_target"], "block_bitmap_g0");

    // Revoke + commit records are metadata-only evidence.
    let rv = find(&entries, "revoke_4");
    assert_eq!(rv.meta["jbd2_revoked_blocks"], "44");
    let cm = find(&entries, "commit_256");
    assert_eq!(cm.meta["jbd2_commit_time"], "1705315000.123456789");
    assert!(cm.timestamps.changed.as_ref().unwrap().value.is_some());

    // Journal evidence must not leak into the normal walk.
    let walked = all_entries();
    assert!(!walked.iter().any(|e| e.path.starts_with("/$JOURNAL/")));
}

#[test]
fn journal_events_typed_stream() {
    use sutram_ext4::{Ext4Fs, JournalEventKind};
    let fs = Ext4Fs::mount(image(), MountOptions::default()).unwrap();
    let events = fs
        .journal_events()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    // superblock + desc + 2 tags + revoke + commit + desc + 1 tag = 8.
    assert_eq!(events.len(), 8);
    assert!(matches!(
        events[0].kind,
        JournalEventKind::Superblock { version: 2 }
    ));
    assert!(matches!(
        events[1].kind,
        JournalEventKind::Descriptor { tags: 2 }
    ));
    let JournalEventKind::JournaledBlock(tag) = &events[2].kind else {
        panic!("event 2 should be a journaled block: {:?}", events[2].kind)
    };
    assert_eq!(tag.fs_block, 5);
    assert!(tag.prior_state());
    let JournalEventKind::Revoke { blocks } = &events[4].kind else {
        panic!("event 4 should be a revoke: {:?}", events[4].kind)
    };
    assert_eq!(blocks, &[44]);
}

#[test]
fn journal_corruption_lenient_and_strict() {
    let mut img = common::build_ext4();
    // Overwrite the data copy at journal block 37 with a valid header:
    // descriptor 36's tag claims it as data, so the scan must flag the
    // collision and resynchronise onto the block as a structure.
    let b = common::blk_off(37);
    img[b..b + 4].copy_from_slice(&0xC03B_3998u32.to_be_bytes());
    img[b + 4..b + 8].copy_from_slice(&2u32.to_be_bytes()); // commit
    img[b + 8..b + 12].copy_from_slice(&0x101u32.to_be_bytes());

    // Lenient: one error record interleaved; parsing continues.
    let fs = Ext4Parser.mount(Arc::new(img.clone())).unwrap();
    let items: Vec<_> = fs.journal_entries().collect();
    assert_eq!(items.iter().filter(|i| i.is_err()).count(), 1);
    assert!(items.iter().any(|i| i.is_ok()));

    // Strict: the first error is terminal — the stream ends on it.
    let fs = Ext4Parser
        .mount_with(Arc::new(img), &MountOptions::strict())
        .unwrap();
    let items: Vec<_> = fs.journal_entries().collect();
    assert!(items.last().unwrap().is_err());
    assert_eq!(items.iter().filter(|i| i.is_err()).count(), 1);
}

#[test]
fn magic_verdicts() {
    let entries = all_entries();
    let e = find(&entries, "evil.doc");
    let v = e.magic.as_ref().unwrap();
    assert!(v.mismatch);
    assert_eq!(v.severity, Severity::High);
    assert_eq!(v.detected, Some(MagicType::Pe));
    let e = find(&entries, "docs.docx");
    let v = e.magic.as_ref().unwrap();
    assert!(!v.mismatch, "{:?}", v.reasons);
}

#[test]
fn deleted_entries_view() {
    let deleted: Vec<_> = mount()
        .deleted_entries()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let names: Vec<&str> = deleted.iter().map(|e| e.name.as_str()).collect();
    for n in ["notes.txt", "buried.tmp", "ino_13", "ino_15", "ino_19", "ino_20"] {
        assert!(names.contains(&n), "missing {n} in {names:?}");
    }
    assert!(!names.contains(&"hello.txt"));
}

#[test]
fn unallocated_ranges_cover_free_blocks() {
    let ranges = mount().unallocated_ranges();
    assert!(!ranges.is_empty());
    // Block 43 (deleted file data) is free → must appear.
    let t = common::blk_off(43) as u64;
    assert!(ranges.iter().any(|(o, l)| *o <= t && t < o + l));
    // Block 41 (live file) is allocated → must not appear.
    let u = common::blk_off(41) as u64;
    assert!(!ranges.iter().any(|(o, l)| *o <= u && u < o + l));
    // Metadata blocks (superblock at 1024) are not unallocated.
    assert!(!ranges.iter().any(|(o, l)| *o <= 1024 && 1024 < o + l));
}

#[test]
fn slack_meta_on_live_file() {
    let entries = all_entries();
    let e = find(&entries, "hello.txt");
    // 12-byte file in a 1024-byte block → 1012 bytes of tail slack.
    assert_eq!(e.meta["slack_len"], "1012");
}

#[test]
fn lenient_walk_survives_corruption() {
    let mut img = common::build_ext4();
    // Corrupt the first dirent's rec_len in the root dir → parse error
    // but the walk must continue (and not panic).
    let o = common::dirent_off(40, 0);
    img[o + 4] = 0xFF;
    img[o + 5] = 0xFF; // rec_len = 0xFFFF → invalid
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = Ext4Parser.mount(src).unwrap();
    let items: Vec<_> = fs.walk().collect();
    assert!(items.iter().any(|i| i.is_err()));
    // Deleted-inode scan still runs after dir failure.
    let ok_names: Vec<String> = items
        .iter()
        .filter_map(|i| i.as_ref().ok().map(|e| e.name.clone()))
        .collect();
    assert!(ok_names.iter().any(|n| n == "ino_13"));
}

#[test]
fn strict_mode_aborts() {
    let mut img = common::build_ext4();
    let o = common::dirent_off(40, 0);
    img[o + 4] = 0xFF;
    img[o + 5] = 0xFF;
    let fs = Ext4Parser
        .mount_with(Arc::new(img) as Arc<dyn ByteSource>, &MountOptions::strict())
        .unwrap();
    let mut seen_err = false;
    for item in fs.walk() {
        if seen_err {
            panic!("strict walk emitted items after first error");
        }
        if item.is_err() {
            seen_err = true;
        }
    }
    assert!(seen_err);
}

#[test]
fn ext2_indirect_fallback() {
    let src: Arc<dyn ByteSource> = Arc::new(common::build_ext2());
    assert!(Ext4Parser.detect(src.as_ref()) >= DetectConfidence::Medium);
    let fs = Ext4Parser.mount(src).unwrap();
    assert_eq!(fs.info().fs_type, "EXT2");
    let entries: Vec<_> = fs.walk().collect::<Result<Vec<_>, _>>().unwrap();
    let find = |n: &str| {
        entries
            .iter()
            .find(|e| e.name == n)
            .unwrap_or_else(|| panic!("{n} missing: {:?}", entries.iter().map(|e| &e.path).collect::<Vec<_>>()))
    };
    // Direct blocks.
    let d = find("data.txt");
    assert_eq!(d.meta["mapping"], "indirect");
    let mut buf = Vec::new();
    fs.read_file(d).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.starts_with(b"EXT2-DIRECT-DATA"));
    assert_eq!(buf.len(), 2500);
    // Single-indirect blocks.
    let b = find("big.bin");
    let mut buf = Vec::new();
    fs.read_file(b).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(&buf[12 * 1024..12 * 1024 + 17], b"BIGBIN-INDIRECT-0");
    // Deleted inode under ext2: block pointers survive → Intact.
    let del = find("ino_13");
    assert!(matches!(
        del.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    ));
    let mut buf = Vec::new();
    fs.read_file(del).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.starts_with(b"EXT2-DELETED-DATA"));
}

#[test]
fn two_groups_backup_superblock() {
    let src: Arc<dyn ByteSource> = Arc::new(common::build_ext4_two_groups());
    assert!(Ext4Parser.detect(src.as_ref()) >= DetectConfidence::High);
    let fs = Ext4Parser.mount(src).unwrap();
    let info = fs.info();
    assert_eq!(info.meta["block_groups"], "2");
    // sparse_super: groups 0 and 1 both hold backup superblocks.
    assert_eq!(info.meta["backup_superblock_count"], "2");
    assert_eq!(info.meta["inodes_per_group"], "64");
    let g1 = fs
        .walk()
        .find(|e| e.as_ref().map(|x| x.entry_id == 65).unwrap_or(false));
    let e = g1.unwrap().unwrap();
    assert_eq!(e.path, "/g1file.txt");
    // disk_offset = the dirent (block 40, offset 24); inode_offset points
    // at group 1's inode table (block 133).
    assert_eq!(e.disk_offset, 40 * 1024 + 24);
    assert_eq!(e.meta["inode_offset"], "0x21400");
    let mut buf = Vec::new();
    fs.read_file(&e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"GROUP-ONE-FILE");
}

#[test]
fn mount_rejects_garbage() {
    let src: Arc<dyn ByteSource> = Arc::new(vec![0u8; 8192]);
    assert!(Ext4Parser.mount(src).is_err());
}

#[test]
fn inline_dir_walks() {
    let entries = all_entries();
    let dir = find(&entries, "inlinedir");
    assert_eq!(dir.kind, EntryKind::Directory);
    assert_eq!(dir.meta["mapping"], "inline");
    assert_eq!(dir.meta["inline_data"], "true");
    // Dirents decoded from i_block[4..60].
    let inner = entries
        .iter()
        .find(|e| e.path == "/inlinedir/inner.txt")
        .expect("/inlinedir/inner.txt missing");
    let mut buf = Vec::new();
    mount()
        .read_file(inner)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    assert_eq!(buf, b"INNR");
}

#[test]
fn sparse_file_reads_zeros_then_data() {
    let entries = all_entries();
    let e = find(&entries, "sparse.bin");
    assert_eq!(e.size, 3072);
    let mut buf = Vec::new();
    mount()
        .read_file(e)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    assert_eq!(buf.len(), 3072);
    assert!(buf[..2048].iter().all(|&b| b == 0), "hole must read as zeros");
    assert_eq!(&buf[2048..2060], b"SPARSE-DATA!");
}

#[test]
fn phantom_dirent_flags_unallocated_inode() {
    let entries = all_entries();
    let e = find(&entries, "phantom.txt");
    assert_eq!(e.status, FsEntryStatus::Live);
    assert_eq!(e.meta["inode_unallocated"], "true");
}

#[test]
fn carved_dirent_into_reused_inode() {
    let entries = all_entries();
    let e = find(&entries, "stale.lnk");
    assert_eq!(e.meta["carved_dirent"], "true");
    assert_eq!(e.meta["inode_reused"], "true");
    assert!(e.meta["recovery_note_1"].contains("reallocated"));
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unrecoverable
        }
    ));
}

#[test]
fn carved_dirent_into_zeroed_inode() {
    let entries = all_entries();
    let e = find(&entries, "zeroed.de");
    assert_eq!(e.meta["carved_dirent"], "true");
    assert!(matches!(e.status, FsEntryStatus::Deleted { .. }));
}

#[test]
fn deleted_inline_inode_recovers_from_iblock() {
    let entries = all_entries();
    let e = entries
        .iter()
        .find(|e| e.meta.get("inode").map(|s| s == "35").unwrap_or(false))
        .expect("ino 35 artefact missing");
    assert_eq!(e.meta["orphan"], "true");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    ));
    let mut buf = Vec::new();
    mount()
        .read_file(e)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    assert_eq!(buf, b"GONE-INLINE-DATA-123");
}

#[test]
fn orphan_dir_artefact() {
    let entries = all_entries();
    let e = entries
        .iter()
        .find(|e| e.meta.get("inode").map(|s| s == "36").unwrap_or(false))
        .expect("ino 36 artefact missing");
    assert_eq!(e.kind, EntryKind::Directory);
    assert_eq!(e.meta["orphan"], "true");
    assert_eq!(e.allocated_ranges.len(), 1);
}

#[test]
fn carve_region_finds_pk() {
    let fs = mount();
    let hits: Vec<_> = fs
        .carve_region(
            common::blk_off(51) as u64 - 512,
            2048,
            common::BLK as u64,
        )
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(hits
        .iter()
        .any(|h| h.offset == common::blk_off(51) as u64 && h.kind == MagicType::Zip));
}

#[test]
fn carve_region_rejects_zero_align() {
    let fs = mount();
    assert!(fs.carve_region(0, 4096, 0).is_err());
}

#[test]
fn read_file_rejects_directories() {
    let entries = all_entries();
    let dir = find(&entries, "subdir");
    assert!(mount().read_file(dir).is_err());
}

#[test]
fn carved_metadata_only_entry_reads_empty() {
    // "zeroed.de" carved dirent has entry_id pointing at a zeroed inode
    // slot — read_file falls back to the (empty) recorded ranges.
    let entries = all_entries();
    let e = find(&entries, "zeroed.de");
    let mut buf = Vec::new();
    mount()
        .read_file(e)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    assert!(buf.is_empty());
}

#[test]
fn unallocated_ranges_tolerate_bitmap_failure() {
    let mut img = common::build_ext4();
    // Point group 0's block bitmap beyond the image → bitmap read fails;
    // unallocated_ranges must treat the group as fully allocated.
    let gdt = common::blk_off(common::GDT_BLK);
    common::w32(&mut img, gdt, 4096); // bg_block_bitmap_lo → block 4096
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = Ext4Parser.mount(src).unwrap();
    assert!(fs.unallocated_ranges().is_empty());
}

#[test]
fn truncated_image_walks_without_panic() {
    // Image cut mid-inode-table — reads fail, walk emits errors, no panic.
    let img = common::build_ext4();
    let src: Arc<dyn ByteSource> = Arc::new(img[..8 * 1024].to_vec());
    let fs = Ext4Parser.mount(src);
    // Mount itself may fail (GDT/inode table unreadable) — both are fine;
    // the contract is only "no panic".
    if let Ok(fs) = fs {
        let _: Vec<_> = fs.walk().collect();
    }
}

#[test]
fn deleted_entry_partial_ranges_cap_read() {
    // old.log (ino 15): block 0 reallocated (lost), block 1 free —
    // read_file must yield only the surviving extent (the full freed
    // block, incl. tail slack), never the live file's block.
    let entries = all_entries();
    let e = find(&entries, "ino_15");
    let mut buf = Vec::new();
    mount()
        .read_file(e)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    assert_eq!(buf.len(), 1024);
    assert!(buf.starts_with(b"OLD LOG TAIL SURVIVES HERE"));
    assert!(!buf.windows(7).any(|w| w == b"NEWFILE"));
}

#[test]
fn dir_with_short_isize_still_walks() {
    // A corrupt directory i_size must not hide the block's dirents or
    // residue: shrink subdir (ino 12) i_size to 16 bytes — live dirents
    // start at offset 24, so a naive size-capped read finds nothing.
    let mut img = common::build_ext4();
    common::w32(&mut img, common::inode_off(12) + 4, 16);
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = Ext4Parser.mount(src).unwrap();
    let paths: Vec<String> = fs
        .walk()
        .filter_map(|r| r.ok())
        .map(|e| e.path)
        .collect();
    assert!(
        paths.iter().any(|p| p == "/subdir/inner.txt"),
        "short i_size hid /subdir/inner.txt: {paths:?}"
    );
}

// ---------------------------------------------------------------------------
// Coverage-oriented tests: feature flags, recovery-note paths and hostile
// mutations of the synthetic corpus.
// ---------------------------------------------------------------------------

#[test]
fn parser_name_and_source() {
    assert_eq!(Ext4Parser.name(), "ext4");
    let img = common::build_ext4();
    let len = img.len() as u64;
    let fs = Ext4Parser.mount(Arc::new(img) as Arc<dyn ByteSource>).unwrap();
    assert_eq!(fs.source().len(), len);
}

#[test]
fn ext3_variant_without_extents() {
    // Journal but no INCOMPAT_EXTENTS → the volume reports as ext3.
    let mut img = common::build_ext4();
    common::w32(&mut img, 1024 + 0x60, 0x0002); // incompat = filetype only
    let fs = Ext4Parser.mount(Arc::new(img) as Arc<dyn ByteSource>).unwrap();
    assert_eq!(fs.info().fs_type, "EXT3");
    assert_eq!(fs.info().meta["ext_variant"], "ext3");
}

#[test]
fn htree_dir_flag_surfaced() {
    // Set EXT4_INDEX_FL on /subdir — leaf blocks still store linear
    // dirents so the walk is unaffected, but `htree` must be flagged.
    let mut img = common::build_ext4();
    let o = common::inode_off(12) + 0x20;
    common::w32(&mut img, o, common::EXT4_EXTENTS_FL | 0x1000);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let d = find(&entries, "subdir");
    assert_eq!(d.meta["htree"], "true");
    // Contents still walked linearly.
    assert!(entries.iter().any(|e| e.path == "/subdir/inner.txt"));
}

#[test]
fn encrypt_casefold_flags_surfaced() {
    let mut img = common::build_ext4();
    let o = common::inode_off(11) + 0x20;
    common::w32(&mut img, o, common::EXT4_EXTENTS_FL | 0x0000_0800 | 0x4000_0000);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let e = find(&entries, "hello.txt");
    assert_eq!(e.meta["encrypted"], "true");
    assert_eq!(e.meta["casefold"], "true");
}

#[test]
fn orphan_special_inode_is_other() {
    // An allocated, unreferenced socket inode → orphan artefact of kind
    // Other (not File/Dir/Symlink).
    let mut img = common::build_ext4();
    common::put_inode(
        &mut img, 50, 0o140777, 0, 0, 0, 0, [0; 60], 0, 1_705_314_620, 0, None, 0,
    );
    common::set_inode_bit(&mut img, 50);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let e = find(&entries, "ino_50");
    assert_eq!(e.kind, EntryKind::Other);
    assert_eq!(e.meta["orphan"], "true");
}

#[test]
fn deleted_inode_map_unreadable_is_unknown() {
    // Trash the deleted inode's extent magic: the block map cannot be
    // parsed → RecoveryState::Unknown with an explanatory note.
    let mut img = common::build_ext4();
    common::w16(&mut img, common::inode_off(13) + 0x28, 0xBEEF);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let e = find(&entries, "ino_13");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unknown
        }
    ));
    assert!(e
        .meta
        .values()
        .any(|v| v.contains("block map unreadable")));
}

#[test]
fn deleted_inode_extent_hole_partial() {
    // ino 13 declares two blocks but its surviving extent only maps the
    // first → partial recovery plus an "extent info lost" note.
    let mut img = common::build_ext4();
    let o = common::inode_off(13);
    common::w32(&mut img, o + 4, 2000); // size → 2 blocks expected
    common::w32(&mut img, o + 0x6C, 0);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let e = find(&entries, "ino_13");
    match e.status {
        FsEntryStatus::Deleted {
            recovery: RecoveryState::PartiallyOverwritten { .. },
        } => {}
        other => panic!("expected partial, got {other:?}"),
    }
    assert!(e
        .meta
        .values()
        .any(|v| v.contains("extent info lost")));
}

#[test]
fn group_flag_notes_on_recovery() {
    // (a) BG_BLOCK_UNINIT → allocation-status disclaimer note.
    let mut img = common::build_ext4();
    common::w16(&mut img, common::blk_off(common::GDT_BLK) + 0x12, 0x0002);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let e = find(&entries, "ino_13");
    assert!(e
        .meta
        .values()
        .any(|v| v.contains("block bitmap marked uninitialised")));

    // (b) block bitmap unreadable → "bitmap read failed" note.
    let mut img = common::build_ext4();
    common::w32(&mut img, common::blk_off(common::GDT_BLK), 9000);
    let items: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect();
    let ok: Vec<FsEntry> = items.into_iter().filter_map(|i| i.ok()).collect();
    let e = find(&ok, "ino_13");
    assert!(e
        .meta
        .values()
        .any(|v| v.contains("block bitmap read failed")));
}

#[test]
fn inode_uninit_group_skips_deleted_scan() {
    // BG_INODE_UNINIT|BG_INODE_ZEROED guarantees unallocated inode slots
    // are zeroed — the deleted-inode scan must skip them entirely.
    let mut img = common::build_ext4();
    common::w16(&mut img, common::blk_off(common::GDT_BLK) + 0x12, 0x0005);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(!entries.iter().any(|e| e.name == "ino_13"));
    // Carved dirents and allocated orphans are unaffected.
    assert!(entries.iter().any(|e| e.name == "notes.txt"));
    assert!(entries.iter().any(|e| e.name == "ino_20"));
}

#[test]
fn dirent_ino_beyond_table_errors_leniently() {
    // Point hello.txt's dirent at inode 200 (past s_inodes_count) —
    // read_inode fails → Err item, walk continues.
    let mut img = common::build_ext4();
    common::w32(&mut img, common::dirent_off(40, 24), 200);
    let items: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect();
    assert!(items.iter().any(|i| i.is_err()));
    let names: Vec<String> = items
        .iter()
        .filter_map(|i| i.as_ref().ok().map(|e| e.name.clone()))
        .collect();
    assert!(names.iter().any(|n| n == "hello2.txt"));
    assert!(!names.iter().any(|n| n == "hello.txt"));
}

#[test]
fn dead_dirent_ino_zero_skipped() {
    // A live-scanned dirent with inode 0 is a dead slot — never emitted.
    let mut img = common::build_ext4();
    common::w32(&mut img, common::dirent_off(40, 140), 0); // "evil.doc" slot
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(!entries.iter().any(|e| e.name == "evil.doc"));
}

#[test]
fn carved_duplicate_ino_suppressed() {
    // Second carved dirent pointing at an already-emitted deleted inode
    // must be suppressed (dedup via deleted_seen).
    let mut img = common::build_ext4();
    // subdir block 42: "inner.txt" rec_len covers the rest; slack carving
    // scans it. Add "dup.txt" → ino 24 (same as notes.txt's inode).
    let inner_pos = 24usize; // ".", ".." entries occupy 0..24
    common::put_dirent(&mut img, 42, inner_pos + 44, 24, 20, b"dup.txt", common::FT_REG);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(!entries.iter().any(|e| e.name == "dup.txt"));
    assert_eq!(
        entries.iter().filter(|e| e.name == "notes.txt").count(),
        1
    );
}

#[test]
fn carved_dirent_odd_filetypes() {
    // ino-0 carved dirents: file_type DIR → Directory; an unusual type
    // (socket=5) → Other.
    let mut img = common::build_ext4();
    let inner_pos = 24usize;
    common::put_dirent(&mut img, 42, inner_pos + 44, 0, 20, b"gone.d", common::FT_DIR);
    common::put_dirent(&mut img, 42, inner_pos + 64, 0, 20, b"sock.s", 5);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(find(&entries, "gone.d").kind, EntryKind::Directory);
    assert_eq!(find(&entries, "sock.s").kind, EntryKind::Other);
}

#[test]
fn corrupt_dir_extent_map_lenient() {
    // Corrupt subdir's extent magic: its dirent read errors (lenient),
    // the dir's children are unreachable, everything else still walks.
    let mut img = common::build_ext4();
    common::w16(&mut img, common::inode_off(12) + 0x28, 0xBEEF);
    let items: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect();
    assert!(items.iter().any(|i| i.is_err()));
    let names: Vec<String> = items
        .iter()
        .filter_map(|i| i.as_ref().ok().map(|e| e.path.clone()))
        .collect();
    assert!(names.iter().any(|p| p == "/subdir"));
    assert!(!names.iter().any(|p| p == "/subdir/inner.txt"));
    assert!(names.iter().any(|p| p == "/hello.txt"));
}

#[test]
fn corrupt_extent_live_file_read_errors() {
    // Corrupt hello.txt's extent magic: emit_live flags the map error;
    // read_file must then fail cleanly rather than panic.
    let mut img = common::build_ext4();
    common::w16(&mut img, common::inode_off(11) + 0x28, 0xBEEF);
    let fs = Ext4Parser.mount(Arc::new(img) as Arc<dyn ByteSource>).unwrap();
    let items: Vec<_> = fs.walk().collect();
    assert!(items.iter().any(|i| i.is_err()));
    let e = items
        .iter()
        .filter_map(|i| i.as_ref().ok())
        .find(|e| e.name == "hello.txt")
        .expect("hello.txt entry still emitted with empty ranges");
    assert!(fs.read_file(e).is_err());
}

#[test]
fn sparse_dir_reads_across_hole() {
    // subdir's extent maps only logical block 1 (a hole at logical 0):
    // the read must pad the hole so dirents keep their offsets.
    let mut img = common::build_ext4();
    let o = common::inode_off(12) + 0x28;
    common::w32(&mut img, o + 12, 1); // extent logical = 1 (hole at 0)
    let items: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect();
    let paths: Vec<String> = items
        .iter()
        .filter_map(|i| i.as_ref().ok().map(|e| e.path.clone()))
        .collect();
    // Logical block 0 is a zeroed hole → corrupt dirent header → Err item.
    assert!(items.iter().any(|i| i.is_err()));
    assert!(
        paths.iter().any(|p| p == "/subdir/inner.txt"),
        "hole padding shifted dirents: {paths:?}"
    );
}

#[test]
fn mount_without_orphans_skips_inode_scan() {
    let opts = MountOptions {
        include_orphans: false,
        ..Default::default()
    };
    let entries: Vec<_> = Ext4Parser
        .mount_with(
            Arc::new(common::build_ext4()) as Arc<dyn ByteSource>,
            &opts,
        )
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    // The unallocated-inode / orphan scan is skipped.
    assert!(!entries.iter().any(|e| e.name.starts_with("ino_")));
    // Live tree and slack carving are unaffected.
    assert!(entries.iter().any(|e| e.name == "hello.txt"));
    assert!(entries.iter().any(|e| e.name == "notes.txt"));
}

#[test]
fn unallocated_second_group_bitmap_fails() {
    // Corrupt group 1's block-bitmap pointer: its space is conservatively
    // treated as allocated; group 0's free ranges still enumerate.
    let mut img = common::build_ext4_two_groups();
    common::w32(&mut img, common::blk_off(common::GDT_BLK) + 32, 9000);
    let fs = Ext4Parser.mount(Arc::new(img) as Arc<dyn ByteSource>).unwrap();
    let ranges = fs.unallocated_ranges();
    assert!(!ranges.is_empty());
    // Nothing reported inside group 1 (blocks ≥ 128).
    assert!(ranges.iter().all(|(o, _)| *o < 128 * 1024));
    // Group 0's data area is still free.
    let t = common::blk_off(100) as u64;
    assert!(ranges.iter().any(|(o, l)| *o <= t && t < o + l));
}

#[test]
fn inode_reader_eof_on_short_source() {
    // Truncate so big2.dat's second data block is gone — the reader hits
    // a zero-length source read and stops instead of erroring.
    let mut img = common::build_ext4();
    img.truncate(common::blk_off(56));
    let fs = Ext4Parser.mount(Arc::new(img) as Arc<dyn ByteSource>).unwrap();
    let entries: Vec<_> = fs.walk().collect::<Result<Vec<_>, _>>().unwrap();
    let e = find(&entries, "big2.dat");
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut fs.read_file(e).unwrap(), &mut buf).unwrap();
    assert_eq!(buf.len(), 1024);
    assert_eq!(&buf[..10], b"BIG2-FIRST");
}

#[test]
fn carve_region_honours_large_alignment() {
    let fs = mount();
    // align = 2048 (a multiple of the 1 KiB block size) → step 2048.
    let hits: Vec<_> = fs
        .carve_region(0, 128 * 1024, 2048)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(hits.iter().all(|h| h.offset % 2048 == 0));
}

#[test]
fn inline_deleted_missing_spillover_partial() {
    // ino 35 (deleted inline file): claim a size beyond the 60-byte
    // i_block payload without the system.data xattr → partial recovery
    // plus a spillover-lost note.
    let mut img = common::build_ext4();
    let o = common::inode_off(35);
    common::w32(&mut img, o + 4, 75);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let e = entries
        .iter()
        .find(|e| e.meta.get("inode").map(|s| s == "35").unwrap_or(false))
        .expect("ino 35 artefact missing");
    match e.status {
        FsEntryStatus::Deleted {
            recovery:
                RecoveryState::PartiallyOverwritten {
                    recovered_bytes,
                    total_bytes,
                },
        } => assert_eq!((recovered_bytes, total_bytes), (60, 75)),
        other => panic!("expected partial inline recovery, got {other:?}"),
    }
    assert!(e
        .meta
        .values()
        .any(|v| v.contains("system.data xattr missing")));
}

#[test]
fn deleted_empty_and_zeroed_map_inodes() {
    // ino 37: plausible mode + size but no map survives → Unrecoverable.
    // ino 38: plausible mode + dtime, size 0 → Intact (nothing to lose).
    let mut img = common::build_ext4();
    common::put_inode(
        &mut img, 37, 0o100644, 500, 0, 0, 0, [0; 60], 1_705_320_500, 1_705_314_620, 0, None, 0,
    );
    common::put_inode(
        &mut img, 38, 0o100644, 0, 0, 0, 0, [0; 60], 1_705_320_600, 1_705_314_620, 0, None, 0,
    );
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let e37 = find(&entries, "ino_37");
    assert!(matches!(
        e37.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unrecoverable
        }
    ));
    assert!(e37
        .meta
        .values()
        .any(|v| v.contains("no block map survives")));
    let e38 = find(&entries, "ino_38");
    assert!(matches!(
        e38.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    ));
}

#[test]
fn multi_extent_slack_points_into_second_run() {
    // big.dat (1500 B over two extents): slack begins inside the second
    // extent at block 48 + 476.
    let entries = all_entries();
    let e = find(&entries, "big.dat");
    assert_eq!(e.meta["slack_len"], "548");
    assert_eq!(
        e.meta["slack_offset"],
        format!("{:#x}", common::blk_off(48) + 476)
    );
}

#[test]
fn inode_bitmap_failure_surfaces_errors() {
    // Corrupt the inode-bitmap pointer: allocation checks fail; lenient
    // mode emits Err items and still produces entries.
    let mut img = common::build_ext4();
    common::w32(&mut img, common::blk_off(common::GDT_BLK) + 4, 9000);
    let items: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect();
    assert!(items.iter().any(|i| i.is_err()));
    assert!(items.iter().any(|i| i.is_ok()));
}

#[test]
fn slow_symlink_with_corrupt_map_lacks_target() {
    let mut img = common::build_ext4();
    common::w16(&mut img, common::inode_off(31) + 0x28, 0xBEEF);
    let items: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect();
    let e = items
        .iter()
        .filter_map(|i| i.as_ref().ok())
        .find(|e| e.name == "slowlink")
        .expect("slowlink entry missing");
    assert!(!e.meta.contains_key("symlink_target"));
}

#[test]
fn orphan_chain_marks_deleted_member() {
    // Extend the orphan chain: ino 26's i_dtime links to deleted ino 13,
    // which then carries orphan_list evidence in its notes/meta.
    let mut img = common::build_ext4();
    common::w32(&mut img, common::inode_off(26) + 0x14, 13);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let e = find(&entries, "ino_13");
    assert_eq!(e.meta["orphan_list"], "true");
    assert!(e
        .meta
        .values()
        .any(|v| v.contains("orphan inode list")));
}

#[test]
fn dir_trailing_partial_record_skipped() {
    // Shrink inner.txt's rec_len by 4: the tail < 8 bytes of the block
    // must be skipped as a partial record, not an error.
    let mut img = common::build_ext4();
    let pos = common::dirent_off(42, 24);
    let cur = u16::from_le_bytes([img[pos + 4], img[pos + 5]]);
    common::w16(&mut img, pos + 4, cur - 4);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(entries.iter().any(|e| e.path == "/subdir/inner.txt"));
}

#[test]
fn orphan_with_unreadable_map_noted() {
    // Allocated orphan inode with corrupt extents → the artefact is
    // emitted with a "block map unreadable" note and Unknown recovery.
    let mut img = common::build_ext4();
    common::w16(&mut img, common::inode_off(20) + 0x28, 0xBEEF);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let e = find(&entries, "ino_20");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unknown
        }
    ));
    assert!(e
        .meta
        .values()
        .any(|v| v.contains("block map unreadable")));
}

#[test]
fn inline_dir_xattr_spill_ranges() {
    // Give inlinedir a system.data ibody xattr — the spill region counts
    // as a second provenance range for the directory artefact.
    let mut img = common::build_ext4();
    let o = common::inode_off(32) + 160;
    common::w32(&mut img, o, 0xEA02_0000);
    img[o + 4] = 11; // name_len
    img[o + 5] = 7; // system index
    common::w16(&mut img, o + 6, 241); // value_offs (inode-relative)
    common::w32(&mut img, o + 12, 20); // value_size
    img[o + 20..o + 31].copy_from_slice(b"system.data");
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let e = find(&entries, "inlinedir");
    assert_eq!(e.allocated_ranges.len(), 2, "{:?}", e.allocated_ranges);
}

#[test]
fn empty_dir_map_walks() {
    // A directory inode with no extents flag and no blocks → Empty map;
    // the dir is emitted, nothing inside, no error.
    let mut img = common::build_ext4();
    let o = common::inode_off(12);
    common::w32(&mut img, o + 0x20, 0); // clear EXT4_EXTENTS_FL
    common::w32(&mut img, o + 0x1C, 0); // i_blocks = 0
    let items: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect();
    let paths: Vec<String> = items
        .iter()
        .filter_map(|i| i.as_ref().ok().map(|e| e.path.clone()))
        .collect();
    assert!(paths.iter().any(|p| p == "/subdir"));
    assert!(!paths.iter().any(|p| p == "/subdir/inner.txt"));
}

#[test]
fn duplicate_dir_dirent_not_rewalked() {
    // A second dirent naming the same dir inode: the entry is emitted but
    // the directory is not re-queued or re-walked.
    let mut img = common::build_ext4();
    // Root dir "x" entry at pos 304 has rec_len 720. Shrink to 300 and
    // insert "subdir2" → ino 12 at pos 604 covering the block tail.
    let x = common::dirent_off(40, 304);
    common::w16(&mut img, x + 4, 300);
    common::put_dirent(&mut img, 40, 604, 12, (1024 - 604) as u16, b"subdir2", common::FT_DIR);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(entries.iter().any(|e| e.path == "/subdir2"));
    assert_eq!(
        entries.iter().filter(|e| e.path == "/subdir2/inner.txt").count(),
        0,
        "directory must not be walked twice"
    );
    assert_eq!(
        entries.iter().filter(|e| e.path == "/subdir/inner.txt").count(),
        1
    );
}

#[test]
fn deleted_zero_size_extent_inode_intact() {
    // Unallocated inode: extents flag set, size 0 → nothing to lose.
    let mut img = common::build_ext4();
    common::put_inode(
        &mut img, 37, 0o100644, 0, 0, 2, common::EXT4_EXTENTS_FL,
        common::extent_root(&[(0, 1, 43)]), 1_705_320_500, 1_705_314_620, 0, None, 0,
    );
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let e = find(&entries, "ino_37");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    ));
}

#[test]
fn flex_bg_and_empty_label_meta() {
    let mut img = common::build_ext4();
    // Enable flex_bg + set log_groups_per_flex; clear the volume label.
    common::w32(&mut img, 1024 + 0x60, 0x0002 | 0x0040 | 0x0200);
    img[1024 + 0x174] = 4;
    img[1024 + 0x78..1024 + 0x88].fill(0);
    let fs = Ext4Parser.mount(Arc::new(img) as Arc<dyn ByteSource>).unwrap();
    let info = fs.info();
    assert_eq!(info.meta["incompat_flex_bg"], "true");
    assert_eq!(info.meta["groups_per_flex"], "16");
    assert_eq!(info.label, None);
}

#[test]
fn carve_region_surfaces_io_errors() {
    // A source that errors past a cutoff: the carver must yield Err items.
    struct Flaky(Vec<u8>, u64);
    impl ByteSource for Flaky {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, off: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            if off >= self.1 {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "read fault"));
            }
            let n = buf.len().min(self.0.len().saturating_sub(off as usize));
            buf[..n].copy_from_slice(&self.0[off as usize..off as usize + n]);
            Ok(n)
        }
    }
    let img = common::build_ext4();
    let src: Arc<dyn ByteSource> = Arc::new(Flaky(img, common::blk_off(50) as u64));
    let fs = Ext4Parser.mount(src).unwrap();
    let items: Vec<_> = fs.carve_region(0, 200 * 1024, 1024).unwrap().collect();
    assert!(items.iter().any(|i| i.is_err()));
}

#[test]
fn mount_fails_on_truncated_gdt() {
    // Cut inside the GDT (offset 2048..2080): mount must fail Truncated.
    let img = common::build_ext4();
    let src: Arc<dyn ByteSource> = Arc::new(img[..2060].to_vec());
    assert!(Ext4Parser.mount(src).is_err());
}

#[test]
fn detect_certain_on_volume_sized_image() {
    // The corpus' declared block count exceeds the padded image by one
    // block; append it so the detect() length check fires → Certain.
    let mut img = common::build_ext4();
    img.resize(img.len() + 1024, 0);
    assert_eq!(
        Ext4Parser.detect(&img as &dyn ByteSource),
        DetectConfidence::Certain
    );
}

#[test]
fn orphan_cycle_terminates() {
    // ino 26's i_dtime links to itself → the chain walk must terminate.
    let mut img = common::build_ext4();
    common::w32(&mut img, common::inode_off(26) + 0x14, 26);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(find(&entries, "ino_26").meta["orphan_list"], "true");
}

#[test]
fn carved_dirent_into_out_of_range_inode() {
    // A carved dirent pointing past s_inodes_count counts as "allocated"
    // (conservative) → the reuse branch, not a crash.
    let mut img = common::build_ext4();
    let inner_pos = 24usize;
    common::put_dirent(&mut img, 42, inner_pos + 44, 200, 20, b"far.out", common::FT_REG);
    let entries: Vec<_> = Ext4Parser
        .mount(Arc::new(img) as Arc<dyn ByteSource>)
        .unwrap()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let e = find(&entries, "far.out");
    assert_eq!(e.meta["inode_reused"], "true");
}
