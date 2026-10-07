//! Integration tests: diff two synthetic FAT12 images differing by known
//! ops (see `tests/common/mod.rs`).

mod common;

use std::sync::Arc;

use sutram_fs::{FileSystem, FsParser};
use sutram_report::{diff, DiffOptions};

fn mount(img: Vec<u8>) -> Box<dyn FileSystem> {
    sutram_fat::FatParser
        .mount(Arc::new(img))
        .expect("synthetic FAT12 must mount")
}

fn differ() -> sutram_report::ImageDiff {
    let a = mount(common::image_a());
    let b = mount(common::image_b());
    diff(a.as_ref(), b.as_ref(), &DiffOptions::default())
}

#[test]
fn added_removed_detected() {
    let d = differ();
    assert!(
        d.added.contains(&"/NEWFILE.TXT".to_string()),
        "added: {:?}",
        d.added
    );
    assert!(
        d.removed.contains(&"/SUBDIR/INNER.TXT".to_string()),
        "removed: {:?}",
        d.removed
    );
    assert!(!d.is_clean());
}

#[test]
fn modified_compares_size_and_content() {
    let d = differ();
    let m = d
        .modified
        .iter()
        .find(|m| m.path == "/HELLO.TXT")
        .expect("HELLO.TXT must be modified");
    assert!(
        m.changes.iter().any(|c| c.starts_with("size: 12 -> 14")),
        "changes: {:?}",
        m.changes
    );
    assert!(
        m.changes.iter().any(|c| c.contains("content hash")),
        "same-path content change must be hashed: {:?}",
        m.changes
    );
}

#[test]
fn recovery_transition_reported() {
    let d = differ();
    let t = d
        .deleted_changes
        .iter()
        .find(|t| t.path == "/_DELETED.TXT")
        .expect("un-deletion must be a deleted_change");
    assert!(t.from.starts_with("deleted"), "from={}", t.from);
    assert_eq!(t.to, "live");
}

#[test]
fn identical_images_clean() {
    let a = mount(common::image_a());
    let b = mount(common::image_a());
    let d = diff(a.as_ref(), b.as_ref(), &DiffOptions::default());
    assert!(d.is_clean(), "clean diff expected: {}", d.to_text());
    assert_eq!(d.errors_a + d.errors_b, 0);
}

#[test]
fn json_and_text_outputs() {
    let d = differ();
    let j = d.to_json();
    for needle in [
        "\"added\":[",
        "\"/NEWFILE.TXT\"",
        "\"/SUBDIR/INNER.TXT\"",
        "\"from\":\"deleted",
        "\"to\":\"live\"",
    ] {
        assert!(j.contains(needle), "missing {needle} in {j}");
    }
    let t = d.to_text();
    assert!(t.contains("added (1):"), "{t}");
    assert!(t.contains("removed (1):"));
    assert!(t.contains("/_DELETED.TXT: deleted"));
}
