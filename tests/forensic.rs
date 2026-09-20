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
    DetectConfidence, FsEntry, FsEntryStatus, FsParser, MountOptions, RecoveryState,
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
    assert_eq!(info.free_blocks, Some(180)); // 200 − 20 allocated
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
    assert_eq!(orphans.len(), 1, "{:?}", orphans);
    let o = orphans[0];
    assert_eq!(o.name, "chain_18");
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
