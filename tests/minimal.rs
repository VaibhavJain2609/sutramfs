//! Tests over the *minimal* synthetic image (`common::minimal_image`) —
//! a ~104 KiB volume with non-default geometry (2 blocks/segment) that
//! still exercises mount, the live walk, stale-NAT recovery and the
//! free-segment scan. Also regenerates the fuzz seed corpus when asked.

mod common;

use std::sync::Arc;

use common::*;
use sutram_f2fs::F2fsParser;
use sutram_fs::{DetectConfidence, FsEntry, FsEntryStatus, FsParser, RecoveryState};

fn mount_minimal() -> Box<dyn sutram_fs::FileSystem> {
    let src: Arc<dyn sutram_io::ByteSource> = minimal_image();
    F2fsParser.mount(src).unwrap()
}

#[test]
fn minimal_image_detects_and_mounts() {
    let img = minimal_image();
    assert_eq!(F2fsParser.detect(img.as_ref()), DetectConfidence::Certain);
    let fs = mount_minimal();
    let info = fs.info();
    assert_eq!(info.fs_type, "F2FS");
    assert_eq!(info.block_size, BLK as u64);
}

#[test]
fn minimal_image_walks_and_recovers() {
    let fs = mount_minimal();
    let entries: Vec<FsEntry> = fs.walk().map(|r| r.expect("walk error")).collect();
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"/"));
    assert!(paths.contains(&"/file.txt"));
    assert!(
        paths.contains(&"/old.txt"),
        "dentry residue name expected: {paths:?}"
    );
    // file.txt is live and readable.
    let file = entries.iter().find(|e| e.path == "/file.txt").unwrap();
    assert_eq!(file.status, FsEntryStatus::Live);
    let mut r = fs.read_file(file).unwrap();
    let mut buf = String::new();
    std::io::Read::read_to_string(&mut r, &mut buf).unwrap();
    assert_eq!(buf, "hello fuzz");
    // old.txt resolves via the stale NAT copy → deleted with intact data.
    let old = entries.iter().find(|e| e.path == "/old.txt").unwrap();
    match old.status {
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact,
        } => {}
        other => panic!("old.txt should be Deleted/Intact, got {other:?}"),
    }
    let mut r = fs.read_file(old).unwrap();
    let mut buf = String::new();
    std::io::Read::read_to_string(&mut r, &mut buf).unwrap();
    assert_eq!(buf, "stale deleted data");
}

#[test]
fn minimal_image_truncated_tail_is_lenient() {
    // Cut the image mid-main-area: mount + walk must not panic.
    let img = minimal_image();
    let cut = 20 * BLK; // keep sb+cp+sit+nat+ssa+seg0, drop the rest
    let src: Arc<dyn sutram_io::ByteSource> = Arc::new(img[..cut].to_vec());
    let fs = F2fsParser.mount(src).unwrap();
    let _: Vec<_> = fs.walk().collect();
}

/// Regenerate the fuzz seed corpus:
/// `F2FS_SEED_DIR=fuzz/corpus/parse_image cargo test --test minimal`
#[test]
fn dump_fuzz_seeds() {
    let Ok(dir) = std::env::var("F2FS_SEED_DIR") else {
        return;
    };
    let img = minimal_image();
    std::fs::write(format!("{dir}/f2fs_min.img"), img.as_slice()).unwrap();
    // Prefix-truncated variant: reads past the cut hit the lenient path.
    let cut = 20 * BLK;
    std::fs::write(format!("{dir}/f2fs_trunc.img"), &img[..cut]).unwrap();
    // First-segment-only variant: superblock + checkpoint, nothing else.
    std::fs::write(
        format!("{dir}/f2fs_head.img"),
        &img[..6 * BLK],
    )
    .unwrap();
}
