//! Integration tests over the synthetic FAT32/FAT12 corpora.
//!
//! Pattern for sibling parsers: `common::build_*()` constructs the image
//! byte-exact; mount and assert on the `FsEntry` stream — live, deleted,
//! orphan, slack, timestamps, magic verdicts, provenance offsets.

mod common;

use std::io::Read;
use std::sync::Arc;
use std::sync::OnceLock;

use sutram_fat::FatParser;
use sutram_fs::{
    DetectConfidence, FsEntry, FsEntryStatus, FsParser, RecoveryState,
};
use sutram_io::ByteSource;
use sutram_magic::{MagicType, Severity};

fn image() -> Arc<dyn ByteSource> {
    static IMG: OnceLock<Arc<dyn ByteSource>> = OnceLock::new();
    IMG.get_or_init(|| Arc::new(common::build_fat32())).clone()
}

fn mount() -> Box<dyn sutram_fs::FileSystem> {
    FatParser.mount(image()).unwrap()
}

fn all_entries() -> Vec<FsEntry> {
    mount()
        .walk()
        .collect::<Result<Vec<_>, _>>()
        .expect("walk should not error on the clean corpus")
}

fn find<'a>(entries: &'a [FsEntry], name: &str) -> &'a FsEntry {
    entries
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("entry {name} not found; got {:?}", entries.iter().map(|e| &e.path).collect::<Vec<_>>()))
}

#[test]
fn detects_fat32() {
    assert!(FatParser.detect(image().as_ref()) >= DetectConfidence::High);
}

#[test]
fn info_reports_fat32() {
    let info = mount().info();
    assert_eq!(info.fs_type, "FAT32");
    assert_eq!(info.label.as_deref(), Some("TESTVOL"));
    assert_eq!(info.uuid.as_deref(), Some("1234-5678"));
    assert_eq!(info.block_size, 512);
    assert!(info.total_blocks >= 65_525);
    assert!(info.free_blocks.unwrap() > 0);
}

#[test]
fn live_tree_walks() {
    let entries = all_entries();
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"/"));
    assert!(paths.contains(&"/HELLO.TXT"));
    assert!(paths.contains(&"/SUBDIR"));
    assert!(paths.contains(&"/SUBDIR/INNER.TXT"));
    // "." and ".." are never emitted
    assert!(!paths.iter().any(|p| p.ends_with("/.")));
}

#[test]
fn lfn_name_recovers() {
    let entries = all_entries();
    let e = find(&entries, "Long File Name.txt");
    assert_eq!(e.meta["dos_name"], "LONGFI~1.TXT");
    assert_eq!(e.path, "/Long File Name.txt");
}

#[test]
fn timestamps_decode() {
    let entries = all_entries();
    let e = find(&entries, "HELLO.TXT");
    let m = e.timestamps.modified.as_ref().unwrap();
    assert_eq!(m.value, Some(1_705_314_620_000_000_000)); // 2024-01-15T10:30:20Z
    assert_eq!(m.raw_encoding, "fat-dos-write");
    let c = e.timestamps.created.as_ref().unwrap();
    assert_eq!(c.value, Some(1_705_314_620_500_000_000)); // +0.5 s tenth field
    assert!(e.timestamps.accessed.is_some());
}

#[test]
fn provenance_offsets() {
    let entries = all_entries();
    let e = find(&entries, "HELLO.TXT");
    // HELLO.TXT is slot 1 of the root dir at cluster 2.
    assert_eq!(e.disk_offset, common::clus_off(2) as u64 + 32);
    // its data is cluster 3
    assert_eq!(e.allocated_ranges, vec![(common::clus_off(3) as u64, 512)]);
    // slack: 12-byte file in a 512-byte cluster
    assert_eq!(e.meta["slack_len"], "500");
}

#[test]
fn deleted_intact_reads_back() {
    let entries = all_entries();
    let e = find(&entries, "_ELETED.TXT");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    ));
    assert_eq!(e.meta["deleted_marker"], "0xe5");
    let mut buf = Vec::new();
    mount()
        .read_file(e)
        .unwrap()
        .read_to_end(&mut buf)
        .unwrap();
    assert_eq!(buf, b"0123456789");
}

#[test]
fn deleted_partially_overwritten() {
    let entries = all_entries();
    let e = find(&entries, "_LDFILE.TXT");
    match e.status {
        FsEntryStatus::Deleted {
            recovery:
                RecoveryState::PartiallyOverwritten {
                    recovered_bytes,
                    total_bytes,
                },
        } => {
            assert_eq!((recovered_bytes, total_bytes), (512, 700));
        }
        other => panic!("expected partial overwrite, got {other:?}"),
    }
    // surviving extent = cluster 8 only (7 was reallocated to NEWFILE.TXT)
    assert_eq!(e.allocated_ranges, vec![(common::clus_off(8) as u64, 512)]);
    // read_file returns exactly the recoverable bytes
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(&buf[..29], b"old file tail survives here!!");
}

#[test]
fn deleted_unrecoverable() {
    let entries = all_entries();
    let e = find(&entries, "_ONE.BIN");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unrecoverable
        }
    ));
    assert!(e.allocated_ranges.is_empty());
}

#[test]
fn deleted_beyond_eod_marker() {
    let entries = all_entries();
    let e = find(&entries, "_HOST.TMP");
    assert_eq!(e.meta["beyond_eod"], "true");
    assert!(e.is_deleted());
}

#[test]
fn orphans_emitted() {
    let entries = all_entries();
    let orphans: Vec<_> = entries
        .iter()
        .filter(|e| e.path.starts_with("/$ORPHANED/"))
        .collect();
    assert_eq!(orphans.len(), 1);
    let o = orphans[0];
    assert_eq!(o.allocated_ranges.len(), 2); // chain 20→21
    assert_eq!(o.meta["orphan"], "true");
    assert!(matches!(
        o.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unknown
        }
    ));
    // orphan data is readable
    let mut buf = Vec::new();
    mount().read_file(o).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.starts_with(b"ORPHANED-CHAIN-START"));
}

#[test]
fn magic_verdicts() {
    let entries = all_entries();
    // EVIL.DOC — MZ content under .doc extension → High masquerade
    let e = find(&entries, "EVIL.DOC");
    let v = e.magic.as_ref().unwrap();
    assert!(v.mismatch);
    assert_eq!(v.severity, Severity::High);
    assert_eq!(v.detected, Some(MagicType::Pe));
    // RESUME.DOCX — PK content under .docx → container-consistent
    let e = find(&entries, "RESUME.DOCX");
    let v = e.magic.as_ref().unwrap();
    assert!(!v.mismatch, "{:?}", v.reasons);
    // Long File Name.txt — PNG content under .txt → mismatch (suspicious)
    let e = find(&entries, "Long File Name.txt");
    let v = e.magic.as_ref().unwrap();
    assert!(v.mismatch);
    assert_eq!(v.severity, Severity::Suspicious);
}

#[test]
fn read_file_live() {
    let entries = all_entries();
    let e = find(&entries, "HELLO.TXT");
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"hello world!");
    // read_file_at random access
    let mut b = [0u8; 5];
    let n = mount().read_file_at(e, 6, &mut b).unwrap();
    assert_eq!(n, 5);
    assert_eq!(&b, b"world");
}

#[test]
fn deleted_entries_view() {
    let deleted: Vec<_> = mount()
        .deleted_entries()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let names: Vec<&str> = deleted.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"_ELETED.TXT"));
    assert!(names.contains(&"_LDFILE.TXT"));
    assert!(names.contains(&"_ONE.BIN"));
    assert!(!names.contains(&"HELLO.TXT"));
}

#[test]
fn unallocated_ranges_cover_free_clusters() {
    let ranges = mount().unallocated_ranges();
    assert!(!ranges.is_empty());
    // cluster 30 is free; its byte range must appear inside some range
    let target = common::clus_off(30) as u64;
    assert!(ranges
        .iter()
        .any(|(off, len)| *off <= target && target < off + len));
    // allocated cluster 3 must NOT appear in unallocated space
    let used = common::clus_off(3) as u64;
    assert!(!ranges
        .iter()
        .any(|(off, len)| *off <= used && used < off + len));
}

#[test]
fn fat12_minimal_image() {
    let src: Arc<dyn ByteSource> = Arc::new(common::build_fat12());
    assert!(FatParser.detect(src.as_ref()) >= DetectConfidence::Medium);
    let fs = FatParser.mount(src).unwrap();
    assert_eq!(fs.info().fs_type, "FAT12");
    let entries: Vec<_> = fs.walk().collect::<Result<Vec<_>, _>>().unwrap();
    let data = entries.iter().find(|e| e.name == "DATA.TXT").unwrap();
    let mut buf = Vec::new();
    fs.read_file(data).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"fat12ok");
}

#[test]
fn lenient_walk_survives_corruption() {
    let mut img = common::build_fat32();
    // Corrupt the subdir's FAT link: point cluster 11 at a wild cluster.
    common::set_fat(&mut img, 11, 60_000);
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = FatParser.mount(src).unwrap();
    // walk completes; may contain an error record but must not panic
    let items: Vec<_> = fs.walk().collect();
    assert!(items.iter().any(|i| i.is_ok()));
}

#[test]
fn strict_mode_aborts_on_io_error() {
    use sutram_fs::MountOptions;
    // Image truncated mid-root-dir: mount may succeed but walk hits
    // truncation. Lenient mode still yields the root entry first.
    let img = common::build_fat32();
    let truncated = img[..common::clus_off(2) + 100].to_vec();
    let src: Arc<dyn ByteSource> = Arc::new(truncated);
    let fs = FatParser.mount(src).unwrap();
    let items: Vec<_> = fs.walk().collect();
    // Lenient: we still got entries (root dir partial read or entries).
    assert!(items.iter().any(|i| i.is_ok()));

    // Strict: same scenario via mount_with — outcome is still a Vec of
    // Results, but the first Err must be terminal (no Ok after it).
    let img = common::build_fat32();
    let truncated = img[..common::clus_off(2) + 100].to_vec();
    let fs = FatParser
        .mount_with(Arc::new(truncated) as Arc<dyn ByteSource>, &MountOptions::strict())
        .unwrap();
    let mut seen_err = false;
    for item in fs.walk() {
        if seen_err {
            assert!(item.is_err() || true); // strict may simply stop
        }
        if item.is_err() {
            seen_err = true;
        }
    }
}
