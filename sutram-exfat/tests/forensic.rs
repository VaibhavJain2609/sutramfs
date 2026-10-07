//! Integration tests over the synthetic exFAT corpus.
//!
//! Pattern from `sutram-fat`: `common::build_exfat()` constructs the image
//! byte-exact; mount and assert on the `FsEntry` stream — live, deleted,
//! orphan, slack, timestamps, magic verdicts, provenance offsets.

mod common;

use std::io::Read;
use std::sync::Arc;
use std::sync::OnceLock;

use sutram_exfat::ExFatParser;
use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsParser, MountOptions, RecoveryState,
};
use sutram_io::ByteSource;
use sutram_magic::{MagicType, Severity};

fn image() -> Arc<dyn ByteSource> {
    static IMG: OnceLock<Arc<dyn ByteSource>> = OnceLock::new();
    IMG.get_or_init(|| Arc::new(common::build_exfat())).clone()
}

fn mount() -> Box<dyn sutram_fs::FileSystem> {
    ExFatParser.mount(image()).unwrap()
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
fn detects_exfat() {
    assert!(ExFatParser.detect(image().as_ref()) >= DetectConfidence::High);
}

#[test]
fn detect_rejects_foreign_and_garbage() {
    // all-zero → None
    let zeros: Arc<dyn ByteSource> = Arc::new(vec![0u8; 4096]);
    assert_eq!(ExFatParser.detect(zeros.as_ref()), DetectConfidence::None);
    // FAT32-style sector → None (OEM differs)
    let mut fat = vec![0u8; 4096];
    fat[0] = 0xEB;
    fat[3..11].copy_from_slice(b"MSWIN4.1");
    fat[510] = 0x55;
    fat[511] = 0xAA;
    assert_eq!(ExFatParser.detect(&fat.as_slice()), DetectConfidence::None);
}

#[test]
fn info_reports_exfat() {
    let info = mount().info();
    assert_eq!(info.fs_type, "exFAT");
    assert_eq!(info.label.as_deref(), Some("SUTRAMEXFAT"));
    assert_eq!(info.uuid.as_deref(), Some("1BAD-B002"));
    assert_eq!(info.block_size, 512);
    assert_eq!(info.total_blocks, 200);
    assert_eq!(info.free_blocks, Some(169)); // 200 − 31 allocated
    assert_eq!(info.meta["boot_checksum_ok"], "true");
    assert_eq!(info.meta["backup_boot_ok"], "true");
    assert_eq!(info.meta["bitmap_present"], "true");
    assert_eq!(info.meta["cluster_count"], "200");
}

#[test]
fn live_tree_walks() {
    let entries = all_entries();
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"/"));
    assert!(paths.contains(&"/HELLO.TXT"));
    assert!(paths.contains(&"/DIR1"));
    assert!(paths.contains(&"/DIR1/INNER.TXT"));
    assert!(paths.contains(&"/A Very Long File Name.TXT"));
    for i in 0..12 {
        assert!(
            paths.contains(&format!("/BIGDIR/FILE{i:02}.DAT").as_str()),
            "missing FILE{i:02}.DAT"
        );
    }
    // metadata entries are not emitted as files
    assert!(!paths.iter().any(|p| p.contains("bitmap")));
}

#[test]
fn long_name_recovers() {
    let entries = all_entries();
    let e = find(&entries, "A Very Long File Name.TXT");
    assert_eq!(e.path, "/A Very Long File Name.TXT");
    assert_eq!(e.meta["checksum_ok"], "true");
    assert_eq!(e.meta["no_fat_chain"], "true");
    // contiguous extent → single merged range
    assert_eq!(
        e.allocated_ranges,
        vec![(common::clus_off(8) as u64, 1024)]
    );
}

#[test]
fn timestamps_decode_with_tz() {
    let entries = all_entries();
    let e = find(&entries, "HELLO.TXT");
    let m = e.timestamps.modified.as_ref().unwrap();
    // local 2024-01-15 10:30:20 +0.5 s at UTC+2 → 08:30:20.5Z
    assert_eq!(
        m.value,
        Some((1_705_314_620 - 7200) * 1_000_000_000 + 500_000_000)
    );
    assert_eq!(m.raw_encoding, "exfat-datetime");
    assert_eq!(e.meta["modified_utc_offset"], "+02:00");
    assert_eq!(e.meta["accessed_utc_offset"], "utc");
    let a = e.timestamps.accessed.as_ref().unwrap();
    // 2024-01-16T00:00:00Z — accessed has no 10 ms field (2 s granularity)
    assert_eq!(a.value, Some(1_705_363_200_000_000_000));
    assert_eq!(a.granularity, std::time::Duration::from_secs(2));
}

#[test]
fn provenance_offsets() {
    let entries = all_entries();
    let e = find(&entries, "HELLO.TXT");
    // HELLO.TXT's primary entry is slot 3 of the root dir (cluster 2).
    assert_eq!(e.disk_offset, common::doff(&common::ROOT_CLUSTERS, 3) as u64);
    // fragmented chain 5→30: two ranges
    assert_eq!(
        e.allocated_ranges,
        vec![
            (common::clus_off(5) as u64, 512),
            (common::clus_off(30) as u64, 512)
        ]
    );
    // slack: 700-byte file in 1024 allocated bytes
    assert_eq!(e.meta["slack_len"], "324");
}

#[test]
fn fragmented_file_reads() {
    let entries = all_entries();
    let e = find(&entries, "HELLO.TXT");
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 700);
    assert!(buf.starts_with(b"hello, fragmented world"));
    assert!(buf[512..].starts_with(b"the tail of hello".as_slice()));
}

#[test]
fn deleted_intact_contiguous() {
    let entries = all_entries();
    let e = find(&entries, "DELETED1.TXT");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    ));
    assert_eq!(e.meta["deleted_marker"], "entry_type_inuse_cleared");
    // name survives intact (unlike FAT's clobbered lead byte)
    assert_eq!(e.meta["checksum_ok"], "true");
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 600);
    assert!(buf.starts_with(b"DELETED-INTACT-HEAD"));
}

#[test]
fn deleted_partially_overwritten() {
    let entries = all_entries();
    let e = find(&entries, "OLDPARTIAL.BIN");
    match e.status {
        FsEntryStatus::Deleted {
            recovery:
                RecoveryState::PartiallyOverwritten {
                    recovered_bytes,
                    total_bytes,
                },
        } => assert_eq!((recovered_bytes, total_bytes), (512, 700)),
        other => panic!("expected partial overwrite, got {other:?}"),
    }
    // surviving extent = cluster 13 only (12 reallocated to NEWFILE.TXT)
    assert_eq!(e.allocated_ranges, vec![(common::clus_off(13) as u64, 512)]);
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(&buf[..26], b"oldpartial tail survives!!");
}

#[test]
fn deleted_unrecoverable() {
    let entries = all_entries();
    let e = find(&entries, "GONE.BIN");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unrecoverable
        }
    ));
    assert!(e.allocated_ranges.is_empty());
}

#[test]
fn deleted_fat_chain_survives() {
    let entries = all_entries();
    let e = find(&entries, "DELCHAIN.BIN");
    assert_eq!(e.path, "/DIR1/DELCHAIN.BIN");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    ));
    assert_eq!(
        e.allocated_ranges,
        vec![(common::clus_off(23) as u64, 1024)] // 23,24 contiguous → merged
    );
}

#[test]
fn deleted_beyond_eod_marker() {
    let entries = all_entries();
    let e = find(&entries, "GHOST.TMP");
    assert_eq!(e.meta["beyond_eod"], "true");
    assert!(e.is_deleted());
}

#[test]
fn stray_secondaries_salvaged() {
    let entries = all_entries();
    let e = find(&entries, "STRAYBIN");
    assert_eq!(e.path, "/BIGDIR/STRAYBIN");
    assert!(e.is_deleted());
    assert_eq!(e.meta["orphan"], "true");
    assert!(e.meta["note"].contains("without a primary"));
}

#[test]
fn orphans_emitted() {
    let entries = all_entries();
    let orphans: Vec<_> = entries
        .iter()
        .filter(|e| e.path.starts_with("/$ORPHANED/"))
        .collect();
    // chain_18 (linked), chain_35 (unlinked FAT-free), chain_44 (BAD link).
    assert_eq!(orphans.len(), 3, "{:?}", orphans);
    let o = orphans
        .iter()
        .copied()
        .find(|e| e.name == "chain_18")
        .expect("chain_18 orphan");
    // clusters 18,19 contiguous → one merged 1024 B range
    assert_eq!(
        o.allocated_ranges,
        vec![(common::clus_off(18) as u64, 1024)]
    );
    assert_eq!(o.meta["orphan"], "true");
    assert!(matches!(
        o.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unknown
        }
    ));
    let mut buf = Vec::new();
    mount().read_file(o).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.starts_with(b"ORPHANED-CHAIN-START"));
}

#[test]
fn magic_verdicts() {
    let entries = all_entries();
    // EVIL.DOC — MZ content under .doc → High masquerade
    let e = find(&entries, "EVIL.DOC");
    let v = e.magic.as_ref().unwrap();
    assert!(v.mismatch);
    assert_eq!(v.severity, Severity::High);
    assert_eq!(v.detected, Some(MagicType::Pe));
    // RESUME.DOCX — PK under .docx → container-consistent
    let e = find(&entries, "RESUME.DOCX");
    assert!(!e.magic.as_ref().unwrap().mismatch);
    // long-name .txt containing PNG magic → Suspicious
    let e = find(&entries, "A Very Long File Name.TXT");
    let v = e.magic.as_ref().unwrap();
    assert!(v.mismatch);
    assert_eq!(v.severity, Severity::Suspicious);
}

#[test]
fn read_file_live() {
    let entries = all_entries();
    let e = find(&entries, "NEWFILE.TXT");
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 100);
    assert!(buf.starts_with(b"newfile owns cluster twelve"));
    let mut b = [0u8; 4];
    let n = mount().read_file_at(e, 1, &mut b).unwrap();
    assert_eq!(n, 4);
    assert_eq!(&b, b"ewfi");
}

#[test]
fn deleted_entries_view() {
    let deleted: Vec<_> = mount()
        .deleted_entries()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let names: Vec<&str> = deleted.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"DELETED1.TXT"));
    assert!(names.contains(&"OLDPARTIAL.BIN"));
    assert!(names.contains(&"GONE.BIN"));
    assert!(names.contains(&"DELCHAIN.BIN"));
    assert!(names.contains(&"GHOST.TMP"));
    assert!(!names.contains(&"HELLO.TXT"));
}

#[test]
fn unallocated_ranges_from_bitmap() {
    let ranges = mount().unallocated_ranges();
    assert!(!ranges.is_empty());
    // cluster 40 is free; its byte range must appear inside some range
    let target = common::clus_off(40) as u64;
    assert!(ranges.iter().any(|(off, len)| *off <= target && target < off + len));
    // allocated cluster 3 (bitmap) must NOT be unallocated
    let used = common::clus_off(3) as u64;
    assert!(!ranges.iter().any(|(off, len)| *off <= used && used < off + len));
    // deleted file's cluster 10 IS free space (carving ground)
    let del = common::clus_off(10) as u64;
    assert!(ranges.iter().any(|(off, len)| *off <= del && del < off + len));
}

#[test]
fn corrupt_image_walks_leniently() {
    let mut img = common::build_exfat();
    // Corrupt BIGDIR's FAT link: chain ends after cluster 20.
    common::set_fat(&mut img, 20, 0);
    // Clobber HELLO.TXT's secondary_count to something absurd.
    img[common::doff(&common::ROOT_CLUSTERS, 3) + 1] = 200;
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = ExFatParser.mount(src).unwrap();
    let items: Vec<_> = fs.walk().collect();
    // still yields real entries; never panics
    assert!(items.iter().any(|i| matches!(i, Ok(e) if e.name == "HELLO.TXT")));
    assert!(items.iter().any(|i| matches!(i, Ok(e) if e.path == "/")));
}

#[test]
fn strict_mount_fails_on_bad_boot_checksum() {
    let mut img = common::build_exfat();
    // Flip a byte inside an extended boot sector → checksum mismatch.
    img[5 * 512 + 100] = 0xAA;
    let src: Arc<dyn ByteSource> = Arc::new(img);
    // lenient mount still works (checksum failure reported in meta)
    let fs = ExFatParser.mount(src.clone()).unwrap();
    assert_eq!(fs.info().meta["boot_checksum_ok"], "false");
    // strict mount refuses
    assert!(ExFatParser
        .mount_with(src, &MountOptions::strict())
        .is_err());
}

#[test]
fn no_bitmap_degrades_gracefully() {
    let mut img = common::build_exfat();
    // Mark the bitmap entry deleted → no allocation bitmap.
    img[common::doff(&common::ROOT_CLUSTERS, 1)] = 0x01;
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = ExFatParser.mount(src).unwrap();
    assert_eq!(fs.info().meta["bitmap_present"], "false");
    assert!(fs.unallocated_ranges().is_empty());
    let entries: Vec<_> = fs.walk().collect::<Result<Vec<_>, _>>().unwrap();
    // Recovery falls back to the live map: cluster 12 is claimed by
    // NEWFILE.TXT (lost), 13 is unclaimed (survives) → still partial.
    let e = find(&entries, "OLDPARTIAL.BIN");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::PartiallyOverwritten { .. }
        }
    ));
    // Orphans still found via FAT-nonzero fallback.
    assert!(entries.iter().any(|e| e.path.starts_with("/$ORPHANED/")));
}

#[test]
fn contiguous_dir_walks() {
    let entries = all_entries();
    let e = find(&entries, "CFDIR");
    assert_eq!(e.kind, EntryKind::Directory);
    assert_eq!(e.meta["no_fat_chain"], "true");
    let e = find(&entries, "COFILE.TXT");
    assert_eq!(e.path, "/CFDIR/COFILE.TXT");
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.starts_with(b"file inside a contiguous directory"));
}

#[test]
fn attr_flag_meta() {
    let entries = all_entries();
    let e = find(&entries, "ATTRFLG.BIN");
    assert_eq!(e.meta["readonly"], "true");
    assert_eq!(e.meta["hidden"], "true");
    assert_eq!(e.meta["system"], "true");
    assert_eq!(e.meta["archive"], "true");
}

#[test]
fn valid_exceeds_data_length_noted() {
    let entries = all_entries();
    let e = find(&entries, "WEIRDSZ.BIN");
    assert_eq!(
        e.meta["size_note"],
        "valid_data_length exceeds data_length (corrupt)"
    );
}

#[test]
fn vendor_secondary_skipped() {
    let entries = all_entries();
    let e = find(&entries, "VENDORX.BIN");
    assert_eq!(e.meta["checksum_ok"], "true");
    assert_eq!(e.name, "VENDORX.BIN");
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.starts_with(b"vendor secondary file"));
}

#[test]
fn bad_cluster_link_yields_empty_ranges() {
    let entries = all_entries();
    let e = find(&entries, "BADCLUS.BIN");
    // FAT[44] = 0xFFFFFFF7 → the chain is empty; the file reports no extents.
    assert!(e.allocated_ranges.is_empty());
}

#[test]
fn duplicate_dir_first_cluster_scanned_once() {
    let entries = all_entries();
    // DUPFC claims DIR1's cluster — it is emitted but not re-scanned.
    let e = find(&entries, "DUPFC");
    assert_eq!(e.kind, EntryKind::Directory);
    let inner: Vec<_> = entries.iter().filter(|e| e.path.contains("INNER.TXT")).collect();
    assert_eq!(inner.len(), 1);
    assert_eq!(inner[0].path, "/DIR1/INNER.TXT");
}

#[test]
fn deleted_truncated_chain_extends_contiguous() {
    let entries = all_entries();
    let e = find(&entries, "TRUNCBIN.BIN");
    // Declared 3 clusters, FAT chain has 1 → truncation note + contiguous
    // tail assumption; all three are bitmap-free → Intact.
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    ));
    let notes: Vec<String> = e
        .meta
        .iter()
        .filter(|(k, _)| k.starts_with("recovery_note"))
        .map(|(_, v)| v.clone())
        .collect();
    assert!(
        notes.iter().any(|n| n.contains("truncated")),
        "notes: {notes:?}"
    );
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 1500);
}

#[test]
fn deleted_no_start_cluster_unrecoverable() {
    let entries = all_entries();
    let e = find(&entries, "ZEROFC.BIN");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unrecoverable
        }
    ));
    assert!(e.allocated_ranges.is_empty());
    assert!(e
        .meta
        .values()
        .any(|v| v.contains("no usable start cluster")));
}

#[test]
fn deleted_without_stream_unknown() {
    let entries = all_entries();
    // Without the stream extension, NameLength is unknown — the entry is
    // emitted under the conservative NONAME_<offset> fallback.
    let e = entries
        .iter()
        .find(|e| e.meta.get("note").map(|n| n.as_str())
            == Some("no stream extension survives"))
        .expect("deleted set without a stream");
    assert!(e.name.starts_with("NONAME_"));
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unknown
        }
    ));
}

#[test]
fn stray_chained_and_noname_salvage() {
    let entries = all_entries();
    // Stray run with a FAT-chained (not contiguous) stream.
    let e = find(&entries, "STRAYCHN");
    assert_eq!(e.path, "/BIGDIR/STRAYCHN");
    assert!(e.is_deleted());
    // Stray stream entry with no name → NONAME_<offset> inside BIGDIR.
    let noname: Vec<_> = entries
        .iter()
        .filter(|e| e.name.starts_with("NONAME_") && e.path.starts_with("/BIGDIR/"))
        .collect();
    assert_eq!(noname.len(), 1);
    assert_eq!(noname[0].size, 17);
}

#[test]
fn unlinked_allocated_cluster_orphaned() {
    let entries = all_entries();
    let o = entries
        .iter()
        .find(|e| e.name == "chain_35")
        .expect("unlinked orphan cluster 35");
    // FAT[35] = 0 → chain has just this cluster.
    assert_eq!(
        o.allocated_ranges,
        vec![(common::clus_off(35) as u64, 512)]
    );
}

#[test]
fn include_orphans_disabled() {
    let opts = MountOptions {
        include_orphans: false,
        ..MountOptions::default()
    };
    let fs = ExFatParser.mount_with(image(), &opts).unwrap();
    let entries: Vec<_> = fs.walk().collect::<Result<Vec<_>, _>>().unwrap();
    assert!(!entries.iter().any(|e| e.path.starts_with("/$ORPHANED/")));
}

#[test]
fn mount_rejects_corrupt_bpb() {
    type Mut = fn(&mut Vec<u8>);
    let cases: [(&str, Mut); 16] = [
        ("bad name", |i: &mut Vec<u8>| i[3] = b'X'),
        ("mustbezero nonzero", |i: &mut Vec<u8>| i[0x0B] = 1),
        ("bad bps shift", |i: &mut Vec<u8>| i[0x6C] = 8),
        ("cluster too big", |i: &mut Vec<u8>| i[0x6D] = 20),
        ("missing 55AA", |i: &mut Vec<u8>| i[510] = 0),
        ("bad fat count", |i: &mut Vec<u8>| i[0x6E] = 3),
        ("zero volume", |i: &mut Vec<u8>| common::w64_pub(i, 0x48, 0)),
        ("fat offset low", |i: &mut Vec<u8>| common::w32_pub(i, 0x50, 10)),
        ("fat len zero", |i: &mut Vec<u8>| common::w32_pub(i, 0x54, 0)),
        ("fat too short", |i: &mut Vec<u8>| common::w32_pub(i, 0x54, 1)),
        ("heap overlaps fat", |i: &mut Vec<u8>| common::w32_pub(i, 0x58, 10)),
        ("zero clusters", |i: &mut Vec<u8>| common::w32_pub(i, 0x5C, 0)),
        ("cluster count max", |i: &mut Vec<u8>| common::w32_pub(i, 0x5C, 0xFFFF_FFF6)),
        ("heap beyond volume", |i: &mut Vec<u8>| common::w64_pub(i, 0x48, 100)),
        ("root cluster 0", |i: &mut Vec<u8>| common::w32_pub(i, 0x60, 0)),
        ("root cluster high", |i: &mut Vec<u8>| common::w32_pub(i, 0x60, 202)),
    ];
    for (name, mutate) in cases {
        let mut img = common::build_exfat();
        mutate(&mut img);
        let src: Arc<dyn ByteSource> = Arc::new(img);
        assert!(
            ExFatParser.mount(src).is_err(),
            "mount should reject: {name}"
        );
    }
}

#[test]
fn parser_metadata_and_source() {
    assert_eq!(ExFatParser.name(), "exfat");
    let fs = mount();
    // source() hands back the mounted byte source unchanged.
    assert_eq!(fs.source().len(), image().len());
}

#[test]
fn read_file_rejects_directories() {
    let entries = all_entries();
    let dir = find(&entries, "DIR1");
    assert!(matches!(
        mount().read_file(dir),
        Err(sutram_fs::FsError::InvalidInput { .. })
    ));
    let root = find(&entries, "/");
    assert!(matches!(
        mount().read_file(root),
        Err(sutram_fs::FsError::InvalidInput { .. })
    ));
}

/// ByteSource that fails reads overlapping one byte range — simulates a
/// failing region of media mid-walk.
struct FailAt {
    inner: Arc<dyn ByteSource>,
    off: u64,
    len: u64,
}

impl ByteSource for FailAt {
    fn len(&self) -> u64 {
        self.inner.len()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset < self.off + self.len && offset + buf.len() as u64 > self.off {
            return Err(std::io::Error::other("injected media error"));
        }
        self.inner.read_at(offset, buf)
    }
}

/// Byte offset of the FAT entry for cluster `c`.
fn fat_off(c: u32) -> u64 {
    (common::FAT_SECTOR * common::BPS) as u64 + c as u64 * 4
}

#[test]
fn walk_error_lenient_continues() {
    // Break the FAT read for cluster 20: BIGDIR's chain (20→21→33) cannot
    // be read, so activating the directory must yield an Err *item* in
    // lenient mode — and the walk must carry on.
    let src: Arc<dyn ByteSource> = Arc::new(FailAt {
        inner: image(),
        off: fat_off(20),
        len: 4,
    });
    let fs = ExFatParser.mount(src).expect("lenient mount");
    let items: Vec<_> = fs.walk().collect();
    assert!(
        items.iter().any(|i| i.is_err()),
        "expected an Err item for the unreadable directory"
    );
    assert!(
        items.iter().any(|i| matches!(i, Ok(e) if e.name == "HELLO.TXT")),
        "walk should still deliver live entries"
    );
    // The orphan pass also fails to follow the broken chain (Err item)
    // but still finds cluster 21's surviving tail as an orphan.
    assert!(items.iter().any(|i| matches!(
        i,
        Ok(e) if e.path.starts_with("/$ORPHANED/")
    )));
}

#[test]
fn walk_error_strict_is_terminal() {
    let src: Arc<dyn ByteSource> = Arc::new(FailAt {
        inner: image(),
        off: fat_off(20),
        len: 4,
    });
    let fs = ExFatParser
        .mount_with(src, &MountOptions::strict())
        .expect("strict mount (boot checksums intact)");
    let items: Vec<_> = fs.walk().collect();
    let first_err = items.iter().position(|i| i.is_err());
    // Exactly one Err, and it is the last thing the stream produces.
    assert_eq!(
        first_err,
        Some(items.len() - 1),
        "strict walk must terminate at the first error"
    );
    // Live entries scanned before the failure were still delivered.
    assert!(items.iter().any(|i| matches!(i, Ok(e) if e.name == "HELLO.TXT")));
}

#[test]
fn truncated_dir_chain_walks_partial() {
    // Cut the image 256 B into root's third cluster (32): the directory
    // read emits the present extent then stops — no panic, partial walk.
    let mut img = common::build_exfat();
    img.truncate(common::clus_off(32) + 256);
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = ExFatParser.mount(src).unwrap();
    let entries: Vec<_> = fs.walk().collect::<Result<Vec<_>, _>>().unwrap();
    assert!(entries.iter().any(|e| e.name == "HELLO.TXT"));
    // Slots in the unread tail (e.g. ATTRFLG.BIN at slot 41) are gone.
    assert!(!entries.iter().any(|e| e.name == "ATTRFLG.BIN"));
}

#[test]
fn short_bitmap_falls_back_to_fat() {
    // A bitmap that covers only the first ~40 clusters: allocation queries
    // beyond it fall back to the FAT-nonzero heuristic (documented).
    let mut img = common::build_exfat();
    let off = common::doff(&common::ROOT_CLUSTERS, 1);
    img[off + 24..off + 32].copy_from_slice(&5u64.to_le_bytes()); // 5 bytes
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = ExFatParser.mount(src).unwrap();
    let entries: Vec<_> = fs.walk().collect::<Result<Vec<_>, _>>().unwrap();
    // Clusters 18/19 are bitmap-covered and allocated → orphan found.
    assert!(entries.iter().any(|e| e.name == "chain_18"));
    // Cluster 44 is beyond the bitmap: FAT[44]=0xFFFFFFF7 → allocated →
    // the unlinked orphan is still surfaced via the FAT fallback.
    assert!(entries.iter().any(|e| e.name == "chain_44"));
    // Free-space enumeration still works for the covered prefix.
    assert!(!fs.unallocated_ranges().is_empty());
}

#[test]
fn stray_name_unusable_falls_back_to_noname() {
    // A stray secondary run whose name units are all '/' — sanitised to
    // empty, so the NONAME_<offset> fallback must kick in.
    let mut img = common::build_exfat();
    let bd = &common::BIGDIR_CLUSTERS;
    common::stray_stream_only(&mut img, bd, 37, 37, 64, 512);
    let noff = common::doff(bd, 38);
    img[noff] = 0x41;
    img[noff + 2..noff + 32].fill(0x2F); // 15 UTF-16 '/' units
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = ExFatParser.mount(src).unwrap();
    let entries: Vec<_> = fs.walk().collect::<Result<Vec<_>, _>>().unwrap();
    let noname: Vec<_> = entries
        .iter()
        .filter(|e| e.name.starts_with("NONAME_") && e.path.starts_with("/BIGDIR/"))
        .collect();
    // The '/'-name stray plus the original no-name stray.
    assert_eq!(noname.len(), 2, "{noname:?}");
}

#[test]
fn mount_truncated_image() {
    // Image cut before the cluster heap → truncated, not a panic.
    let img = common::build_exfat()[..common::HEAP_SECTOR * common::BPS - 1].to_vec();
    let src: Arc<dyn ByteSource> = Arc::new(img);
    assert!(ExFatParser.mount(src).is_err());
    // Tiny image → truncated boot read.
    let src: Arc<dyn ByteSource> = Arc::new(vec![0u8; 100]);
    assert!(ExFatParser.mount(src).is_err());
    // BPB claims 4096-byte sectors but the image ends at 600 B → the
    // full-sector re-read is reported Truncated, not a panic.
    let mut img = common::build_exfat()[..600].to_vec();
    img[0x6C] = 12;
    let src: Arc<dyn ByteSource> = Arc::new(img);
    assert!(matches!(
        ExFatParser.mount(src),
        Err(sutram_fs::FsError::Truncated { .. })
    ));
}

#[test]
fn truncated_heap_walks_partial() {
    // Cut the image mid-way through HELLO's second cluster: directory
    // parsing still works, reads emit what is present.
    let mut img = common::build_exfat();
    img.truncate(common::clus_off(30) + 256);
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = ExFatParser.mount(src).unwrap();
    let entries: Vec<_> = fs.walk().collect::<Result<Vec<_>, _>>().unwrap();
    let e = find(&entries, "HELLO.TXT");
    let mut buf = Vec::new();
    fs.read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    // The surviving 256 bytes of cluster 30 still serve the 700-byte file.
    assert_eq!(buf.len(), 700);
    assert!(buf[512..].starts_with(b"the tail of hello".as_slice()));
}

#[test]
fn oversized_bitmap_entry_capped() {
    let mut img = common::build_exfat();
    // Bitmap DataLength claims 1 GiB — the loader must cap it.
    let off = common::doff(&common::ROOT_CLUSTERS, 1);
    img[off + 24..off + 32].copy_from_slice(&1_000_000_000u64.to_le_bytes());
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = ExFatParser.mount(src).unwrap();
    assert_eq!(fs.info().meta["bitmap_present"], "true");
}

#[test]
fn bitmap_extension_via_fat_damage() {
    let mut img = common::build_exfat();
    // Bitmap claims 2 clusters but FAT[3] = EOC → contiguous extension.
    let off = common::doff(&common::ROOT_CLUSTERS, 1);
    img[off + 24..off + 32].copy_from_slice(&1024u64.to_le_bytes());
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = ExFatParser.mount(src).unwrap();
    assert_eq!(fs.info().meta["bitmap_present"], "true");
    // Cluster 4 (upcase) is bitmap-marked allocated in the "extension" —
    // read whatever the loader produced without panicking.
    let _ = fs.unallocated_ranges();
}

#[test]
fn detect_handles_degenerate_inputs() {
    // EXFAT name but truncated before the checksum sector.
    let img = common::build_exfat()[..11 * common::BPS + 100].to_vec();
    let _ = ExFatParser.detect(&img.as_slice());
    // EXFAT name, valid bps shift, but no 0x55AA → weak score.
    let mut img = common::build_exfat();
    img[510] = 0;
    let c = ExFatParser.detect(&img.as_slice());
    assert!(c < DetectConfidence::Certain);
}

#[test]
fn percent_in_use_unavailable_reported() {
    // 0xFF means "not available" per spec — must not be clamped to 100.
    let mut img = common::build_exfat();
    img[0x70] = 0xFF;
    img[12 * common::BPS + 0x70] = 0xFF; // backup copy (not checksummed field)
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = ExFatParser.mount(src).unwrap();
    assert_eq!(fs.info().meta["percent_in_use"], "unavailable");
}

#[test]
fn directory_length_cap_holds() {
    // DIR1's stream DataLength inflated to absurdity — the read must be
    // capped, not balloon into a whole-image allocation.
    let mut img = common::build_exfat();
    // DIR1 set starts at root slot 6; stream secondary at slot 7,
    // DataLength at +24.
    let off = common::doff(&common::ROOT_CLUSTERS, 7);
    img[off + 24..off + 32].copy_from_slice(&u64::MAX.to_le_bytes());
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = ExFatParser.mount(src).unwrap();
    let entries: Vec<_> = fs.walk().collect::<Result<Vec<_>, _>>().unwrap();
    let e = find(&entries, "INNER.TXT");
    let mut buf = Vec::new();
    fs.read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"TEST");
}
