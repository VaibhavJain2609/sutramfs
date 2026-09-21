//! End-to-end tests: analysis functions over a real mounted filesystem
//! (tiny synthetic FAT16 image via `sutram_fat::FatParser`).

mod common;

use std::sync::Arc;

use sutram_analyze::entropy::entry_entropy;
use sutram_analyze::grep::{search, Pattern, SearchOptions};
use sutram_analyze::hash::hash_entry;
use sutram_analyze::suspicion::{assess, Signals};
use sutram_analyze::timeline::Timeline;
use sutram_fs::{DetectConfidence, EntryKind, FsParser};
use sutram_io::{into_arc, ByteSource};

use common::{build_fat16, FatFile};

fn mount() -> Box<dyn sutram_fs::FileSystem> {
    let img = build_fat16(&[
        FatFile::new(b"HELLO   TXT", b"hello world!"),
        FatFile::new(b"DELETED TXT", b"0123456789").deleted(),
    ]);
    let src: Arc<dyn ByteSource> = into_arc(img);
    let parser = sutram_fat::FatParser;
    assert!(parser.detect(src.as_ref()) >= DetectConfidence::Medium);
    parser.mount(src).unwrap()
}

#[test]
fn timeline_over_real_fat() {
    let fs = mount();
    let tl = Timeline::build(fs.as_ref());
    assert_eq!(tl.errors, 0);
    // HELLO.TXT + _DELETED.TXT, each with at least a modified time.
    assert!(tl.len() >= 2);
    let csv = tl.to_csv();
    assert!(csv.contains("/HELLO.TXT"), "{csv}");
    assert!(csv.contains("2024-01-15,10:30:20"), "{csv}");
    let deleted: Vec<_> = tl
        .events()
        .iter()
        .filter(|e| e.path.contains("ELETED.TXT"))
        .collect();
    assert!(!deleted.is_empty());
    assert!(
        deleted
            .iter()
            .all(|e| matches!(e.status, sutram_fs::FsEntryStatus::Deleted { .. }))
    );
    // JSONL + bodyfile render without panic
    assert!(tl.to_jsonl().contains("\"path\":\"/HELLO.TXT\""));
    assert!(tl.to_bodyfile().contains("|/HELLO.TXT|"));
}

#[test]
fn hash_entry_over_real_fat() {
    let fs = mount();
    let entries: Vec<_> = fs.walk().collect::<Result<_, _>>().unwrap();
    let hello = entries.iter().find(|e| e.path == "/HELLO.TXT").unwrap();
    let h = hash_entry(fs.as_ref(), hello).unwrap();
    assert_eq!(
        h.sha256,
        "7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9"
    );
    assert_eq!(h.bytes_read, 12);
    assert!(!h.partial);

    // deleted-intact file hashes to its surviving bytes
    let del = entries
        .iter()
        .find(|e| e.path.contains("ELETED.TXT"))
        .unwrap();
    let hd = hash_entry(fs.as_ref(), del).unwrap();
    assert_eq!(hd.md5, "781e5e245d69b566979b86e28d23f2c7"); // md5("0123456789")
    assert!(!hd.partial); // intact: size == bytes read
}

#[test]
fn entropy_over_real_fat() {
    let fs = mount();
    let hello = fs
        .walk()
        .filter_map(|i| i.ok())
        .find(|e| e.path == "/HELLO.TXT")
        .unwrap();
    let v = entry_entropy(fs.as_ref(), &hello).unwrap();
    assert!(v.entropy < 6.0);
    assert!(v.suspicion.is_none());
    assert_eq!(v.sampled, 12);
}

#[test]
fn grep_over_real_fat() {
    let fs = mount();
    let hits: Vec<_> = search(
        fs.as_ref(),
        &[Pattern::literal("0123"), Pattern::case_insensitive("HELLO")],
        &SearchOptions::default(),
    )
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    assert_eq!(hits.len(), 2);
    let by_path: Vec<_> = hits.iter().map(|h| h.entry_path.as_str()).collect();
    assert!(by_path.contains(&"/HELLO.TXT"));
    // the deleted file's surviving bytes are searched too
    assert!(by_path.iter().any(|p| p.contains("ELETED.TXT")));
    let hello_hit = hits.iter().find(|h| h.entry_path == "/HELLO.TXT").unwrap();
    assert_eq!(hello_hit.offset, 0);
}

#[test]
fn assess_over_real_fat() {
    // EVIL.DOC containing a PE header → magic mismatch on a real parser.
    let mut mz = b"MZ\x90\0\x03\0\0\0".to_vec();
    mz.resize(64, 0);
    let img = build_fat16(&[
        FatFile::new(b"GOOD    TXT", b"plain text, nothing to see"),
        FatFile::new(b"EVIL    DOC", &mz),
    ]);
    let src: Arc<dyn ByteSource> = into_arc(img);
    let fs = sutram_fat::FatParser.mount(src).unwrap();
    let a = assess(fs.as_ref());
    assert_eq!(a.errors, 0);
    assert!(a.files_examined >= 2);
    let top = &a.scored[0];
    assert!(top.entry.path.contains("EVIL"), "{:?}", top.entry.path);
    assert!(top.suspicion.score >= 50);
    assert!(
        top.suspicion
            .reasons
            .iter()
            .any(|r| r.contains("magic severity High"))
    );
    // clean file scores 0 → absent from findings
    assert!(!a.scored.iter().any(|e| e.entry.path.contains("GOOD")));

    // score_entry accepts signals directly
    let evil = fs
        .walk()
        .filter_map(|i| i.ok())
        .find(|e| e.path.contains("EVIL"))
        .unwrap();
    assert_eq!(evil.kind, EntryKind::File);
    let s = sutram_analyze::suspicion::score_entry(&evil, &Signals::default());
    assert!(s.score >= 50);
}
