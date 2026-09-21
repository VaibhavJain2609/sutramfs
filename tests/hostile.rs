//! Hostile-input tests: detection and strict mounting must return promptly
//! on every input — never panic, never hang, never loop on garbage.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use sutram_apfs::ApfsParser;
use sutram_fs::{DetectConfidence, FsParser, MountOptions};
use sutram_io::ByteSource;

const LIMIT: Duration = Duration::from_secs(10);

fn detect(img: &[u8]) -> (DetectConfidence, Duration) {
    let t = Instant::now();
    let c = ApfsParser.detect(&img.to_vec());
    (c, t.elapsed())
}

fn try_mount(img: Vec<u8>) {
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let opts = MountOptions {
        strict: true,
        ..MountOptions::default()
    };
    if let Ok(fs) = ApfsParser.mount_with(src.clone(), &opts) {
        let _ = fs.info();
        let _ = fs.unallocated_ranges();
        for (i, r) in fs.walk().enumerate() {
            if i >= 500 {
                break;
            }
            if let Ok(e) = r {
                let mut f = fs.read_file(&e);
                if let Ok(ref mut r) = f {
                    let mut buf = [0u8; 512];
                    let _ = r.read(&mut buf);
                }
            }
        }
    }
}

fn run_bounded(img: Vec<u8>) -> Duration {
    let t = Instant::now();
    let _ = detect(&img);
    try_mount(img);
    t.elapsed()
}

#[test]
fn empty_and_tiny() {
    assert!(run_bounded(vec![]) < LIMIT);
    assert!(run_bounded(vec![0u8; 8]) < LIMIT);
    assert!(run_bounded(b"NXSB".to_vec()) < LIMIT);
}

#[test]
fn zeroed_and_filled() {
    assert!(run_bounded(vec![0u8; 64 * 4096]) < LIMIT);
    assert!(run_bounded(vec![0xFFu8; 64 * 4096]) < LIMIT);
}

#[test]
fn random_garbage() {
    // Deterministic xorshift pseudo-random data — no RNG dependency.
    let mut s = 0x9E3779B97F4A7C15u64;
    let mut img = vec![0u8; 64 * 4096];
    for b in img.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = s as u8;
    }
    let (c, _) = detect(&img);
    assert_eq!(c, DetectConfidence::None);
    assert!(run_bounded(img) < LIMIT);
}

#[test]
fn magic_with_garbage_geometry() {
    let mut img = vec![0xABu8; 64 * 4096];
    img[32..36].copy_from_slice(b"NXSB");
    // Absurd block size/count and descriptor geometry.
    img[36..40].copy_from_slice(&0xFFFF_FFFDu32.to_le_bytes());
    img[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
    img[104..108].copy_from_slice(&u32::MAX.to_le_bytes());
    img[112..120].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(run_bounded(img) < LIMIT);
}

#[test]
fn valid_magic_bad_descriptor_area() {
    let mut img = common::build_image(false);
    // Point the descriptor area far past the image tail.
    img[112..120].copy_from_slice(&0xFFFFu64.to_le_bytes());
    common::seal(&mut img[..common::BS]);
    assert!(run_bounded(img) < LIMIT);
}

#[test]
fn truncated_valid_image() {
    let img = common::build_image(false);
    for n in [8 * common::BS, 15 * common::BS, 19 * common::BS, 30 * common::BS] {
        let mut t = img.clone();
        t.truncate(n);
        assert!(run_bounded(t) < LIMIT, "truncated at {n}");
    }
}

#[test]
fn corrupted_valid_image() {
    let img = common::build_image(false);
    for b in [0u64, 1, 3, 16, 19, 20, 21] {
        let mut t = img.clone();
        common::corrupt_block(&mut t, b);
        assert!(run_bounded(t) < LIMIT, "corrupt block {b}");
    }
}

#[test]
fn mass_corruption_of_metadata() {
    let mut img = common::build_image(false);
    for b in 9..23u64 {
        common::corrupt_block(&mut img, b);
    }
    assert!(run_bounded(img) < LIMIT);
}

#[test]
fn detect_valid_container_is_fast() {
    let img = common::build_image(false);
    let (c, t) = detect(&img);
    assert!(c >= DetectConfidence::High);
    assert!(t < LIMIT);
}
