//! Hostile-input hardening: every input shape must fail (or degrade)
//! gracefully — never panic, never hang. `detect()` must return promptly
//! on anything thrown at it.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::image;
use sutram_f2fs::F2fsParser;
use sutram_fs::{DetectConfidence, FsParser, MountOptions};
use sutram_io::{into_arc, ByteSource};

fn src(v: Vec<u8>) -> Arc<dyn ByteSource> {
    into_arc(v)
}

/// Deterministic pseudo-random bytes (xorshift64).
fn prng(mut seed: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        out.push((seed & 0xFF) as u8);
    }
    out
}

fn detect_quick(v: Vec<u8>) -> DetectConfidence {
    let t = Instant::now();
    let c = F2fsParser.detect(src(v).as_ref());
    assert!(t.elapsed() < Duration::from_secs(2), "detect too slow");
    c
}

#[test]
fn empty_input() {
    assert_eq!(detect_quick(Vec::new()), DetectConfidence::None);
}

#[test]
fn tiny_inputs() {
    for n in [1usize, 8, 512, 0x400, 0x404] {
        assert_eq!(detect_quick(vec![0u8; n]), DetectConfidence::None, "len {n}");
    }
}

#[test]
fn truncated_superblock() {
    // Magic present but the sb region is cut short → High confidence, no panic.
    let mut v = vec![0u8; 0x400 + 16];
    v[0x400..0x404].copy_from_slice(&0xF2F5_2010u32.to_le_bytes());
    assert_eq!(detect_quick(v), DetectConfidence::High);
}

#[test]
fn all_ones_and_zeros() {
    assert_eq!(detect_quick(vec![0xFFu8; 1 << 20]), DetectConfidence::None);
    assert_eq!(detect_quick(vec![0u8; 1 << 20]), DetectConfidence::None);
}

#[test]
fn random_garbage() {
    for seed in [1u64, 42, 0xDEAD_BEEF] {
        let v = prng(seed, 2 << 20);
        let _ = detect_quick(v.clone());
        // Mount must fail cleanly (or — astronomically unlikely — succeed).
        if let Ok(fs) = F2fsParser.mount(src(v)) {
            for r in fs.walk().take(100) {
                let _ = r;
            }
        }
    }
}

#[test]
fn magic_but_garbage_geometry() {
    let mut v = prng(7, 0x400 + 0xC00);
    v[0x400..0x404].copy_from_slice(&0xF2F5_2010u32.to_le_bytes());
    // Detect grades by parseability — Medium or High, never a panic.
    let c = detect_quick(v);
    assert!(matches!(c, DetectConfidence::Medium | DetectConfidence::High));
}

#[test]
fn magic_at_wrong_offset_is_ignored() {
    let mut v = vec![0u8; 8192];
    v[0..4].copy_from_slice(&0xF2F5_2010u32.to_le_bytes());
    v[4096..4100].copy_from_slice(&0xF2F5_2010u32.to_le_bytes());
    assert_eq!(detect_quick(v), DetectConfidence::None);
}

#[test]
fn corrupted_valid_image() {
    // Flip bytes across every region of a valid image — mount may fail,
    // but walking whatever mounts must never panic or hang.
    let base = (*image()).clone();
    for (i, &off) in [
        0x400usize,          // primary sb magic
        0x1400,              // backup sb magic
        512 * 4096,          // checkpoint pack 0
        1024 * 4096,         // checkpoint pack 1
        1536 * 4096,         // SIT copy A
        2048 * 4096,         // SIT copy B
        2560 * 4096,         // NAT copy A
        3072 * 4096,         // NAT copy B
        3584 * 4096,         // SSA
        4608 * 4096,         // root inode
        4609 * 4096 + 30,    // root dentry records
        4610 * 4096 + 4072,  // hello inode footer
        2560 * 4096 + 3 * 9, // root NAT entry
    ]
    .iter()
    .enumerate()
    {
        let mut v = base.clone();
        // Smear a few bytes at each offset.
        for j in 0..8 {
            v[off + j] ^= 0xFF;
        }
        let t = Instant::now();
        let res = std::panic::catch_unwind(|| {
            if let Ok(fs) = F2fsParser.mount(src(v)) {
                for r in fs.walk().take(500) {
                    let _ = r;
                }
            }
        });
        assert!(res.is_ok(), "case {i}: panic");
        assert!(t.elapsed() < Duration::from_secs(10), "case {i}: too slow");
    }
}

#[test]
fn truncated_valid_image() {
    let base = (*image()).clone();
    // Cut the image at every structure boundary — mount/walk must
    // degrade without panic.
    for blocks in [0u64, 2, 512, 513, 1024, 1536, 1537, 2560, 2561, 3072, 3584, 4608, 4609, 5000, 12800] {
        let keep = (blocks as usize * 4096).min(base.len());
        let v = base[..keep].to_vec();
        let _ = detect_quick(v.clone());
        if let Ok(fs) = F2fsParser.mount(src(v)) {
            for r in fs.walk().take(500) {
                let _ = r;
            }
        }
    }
}

#[test]
fn strict_mode_hostile() {
    let opts = MountOptions { strict: true, check_magic: false, include_orphans: true };
    let base = (*image()).clone();
    for blocks in [513u64, 1536, 2560, 4608, 5000] {
        let v = base[..blocks as usize * 4096].to_vec();
        if let Ok(fs) = F2fsParser.mount_with(src(v), &opts) {
            for r in fs.walk().take(100) {
                let _ = r;
            }
        }
    }
}

#[test]
fn detect_on_valid_image() {
    assert!(detect_quick((*image()).clone()) >= DetectConfidence::High);
}
