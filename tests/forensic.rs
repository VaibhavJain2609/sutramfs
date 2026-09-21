//! End-to-end tests: analysis functions over a real mounted filesystem
//! (tiny synthetic FAT16 image via `sutram_fat::FatParser`).

mod common;

use std::sync::Arc;

use sutram_analyze::timeline::Timeline;
use sutram_fs::{DetectConfidence, FsParser};
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
