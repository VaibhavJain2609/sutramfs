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
    // jbd2 awareness: clean journal (s_start == 0).
    assert_eq!(info.meta["jbd2_needs_replay"], "false");
    assert_eq!(info.meta["jbd2_journal_blocks"], "4");
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
