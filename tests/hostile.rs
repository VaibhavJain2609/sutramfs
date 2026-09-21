//! Hostile-input tests: analyze() must return promptly on every input —
//! never panic, never hang, never loop on garbage.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use common::*;
use sutram_io::ByteSource;
use sutram_part::*;
use sutram_part::fbe::find_crypt_footer;

const LIMIT: Duration = Duration::from_secs(10);

fn run_bounded(img: Vec<u8>) -> Duration {
    let t = Instant::now();
    let src: Arc<dyn ByteSource> = Arc::new(img);
    // Every public entry point gets the input.
    let _ = analyze(src.clone());
    let _ = read_geometry(src.as_ref());
    let _ = read_metadata(src.as_ref());
    let _ = logical_partitions(src.clone());
    let _ = inspect_sparse(src.clone());
    let _ = find_vbmeta(src.as_ref());
    let _ = find_crypt_footer(src.as_ref());
    t.elapsed()
}

#[test]
fn empty_and_tiny() {
    assert!(run_bounded(vec![]) < LIMIT);
    assert!(run_bounded(vec![0u8; 8]) < LIMIT);
    assert!(run_bounded(b"EFI PART".to_vec()) < LIMIT);
}

#[test]
fn zeroed_and_filled() {
    assert!(run_bounded(vec![0u8; 1 << 20]) < LIMIT);
    assert!(run_bounded(vec![0xFFu8; 1 << 20]) < LIMIT);
}

#[test]
fn random_garbage() {
    let mut s = 0x9E3779B97F4A7C15u64;
    let mut img = vec![0u8; 1 << 20];
    for b in img.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = s as u8;
    }
    assert!(run_bounded(img) < LIMIT);
}

#[test]
fn magic_with_garbage_geometry() {
    // Sparse magic + absurd fields.
    let mut img = vec![0xAAu8; 1 << 20];
    img[0..4].copy_from_slice(&0xED26_FF3Au32.to_le_bytes());
    w32(&mut img[8..], 0, u16::MAX as u32);
    w32(&mut img[12..], 0, u32::MAX);
    w32(&mut img[16..], 0, u32::MAX);
    w32(&mut img[20..], 0, u32::MAX);
    assert!(run_bounded(img) < LIMIT);
    // LP geometry magic + absurd fields at both copy offsets.
    let mut img = vec![0xAAu8; 1 << 20];
    for off in [0x1000usize, 0x2000] {
        img[off..off + 4].copy_from_slice(&0x616C_4467u32.to_le_bytes());
        w32(&mut img[off + 4..], 0, u32::MAX);
        w32(&mut img[off + 40..], 0, u32::MAX);
        w32(&mut img[off + 44..], 0, u32::MAX);
    }
    assert!(run_bounded(img) < LIMIT);
    // LP header magic + absurd table descriptors.
    let mut img = vec![0xAAu8; 1 << 20];
    img[0x1000..0x1000 + 4].copy_from_slice(&0x616C_4467u32.to_le_bytes());
    w32(&mut img[0x1004..], 0, 52);
    w32(&mut img[0x1028..], 0, 65536);
    w32(&mut img[0x102C..], 0, 64);
    w32(&mut img[0x1030..], 0, 4096);
    img[0x3000..0x3004].copy_from_slice(&0x414C_5030u32.to_le_bytes());
    w16(&mut img[0x3004..], 0, 10);
    w32(&mut img[0x3008..], 0, 256);
    w32(&mut img[0x302C..], 0, 0xFFFF);
    assert!(run_bounded(img) < LIMIT);
    // vbmeta magic + absurd sizes.
    let mut img = vec![0xAAu8; 1 << 20];
    img[0..4].copy_from_slice(b"AVB0");
    for off in [12usize, 20, 32, 40, 48, 56, 96, 104] {
        img[off..off + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    }
    assert!(run_bounded(img) < LIMIT);
    // GPT signature + absurd entry table geometry.
    let mut img = vec![0xAAu8; 1 << 20];
    img[0x1FE] = 0x55;
    img[0x1FF] = 0xAA;
    img[0x1BE + 4] = 0xEE;
    img[512..520].copy_from_slice(b"EFI PART");
    w32(&mut img[512 + 80..], 0, u32::MAX);
    w32(&mut img[512 + 84..], 0, u32::MAX);
    w64(&mut img[512 + 72..], 0, u64::MAX);
    assert!(run_bounded(img) < LIMIT);
}

#[test]
fn truncated_valid_images() {
    let sup = super_img(
        &[SuperPart {
            name: "system_a",
            group: "system",
            attrs: 0,
            data: vec![0u8; 8192],
        }],
        None,
    );
    for n in [0x1000, 0x3000, 0x3100, 0x23000] {
        let mut t = sup.clone();
        t.truncate(n);
        assert!(run_bounded(t) < LIMIT, "truncated super at {n:#x}");
    }
    let gpt = gpt_img(&[GptPart {
        name: "boot",
        type_guid: test_guid(1),
        data: vec![0u8; 8192],
    }]);
    for n in [256, 512, 1024, 4096] {
        let mut t = gpt.clone();
        t.truncate(n);
        assert!(run_bounded(t) < LIMIT, "truncated gpt at {n:#x}");
    }
    let sp = as_sparse(&[0x42u8; 8192], 4096);
    for n in [10, 28, 40, 1000] {
        let mut t = sp.clone();
        t.truncate(n);
        assert!(run_bounded(t) < LIMIT, "truncated sparse at {n:#x}");
    }
}

#[test]
fn corrupted_valid_images() {
    let sup = super_img(
        &[SuperPart {
            name: "system_a",
            group: "system",
            attrs: 0,
            data: vec![0u8; 8192],
        }],
        None,
    );
    for off in [0x1000usize, 0x2000, 0x3000, 0x13000, 0x23000, 0x33000] {
        let mut t = sup.clone();
        t[off] ^= 0xFF;
        t[off + 32] ^= 0xFF;
        assert!(run_bounded(t) < LIMIT, "corrupt at {off:#x}");
    }
    let gpt = gpt_img(&[GptPart {
        name: "boot",
        type_guid: test_guid(1),
        data: vec![0u8; 8192],
    }]);
    for off in [0usize, 446, 512, 1024, 2048] {
        let mut t = gpt.clone();
        t[off] ^= 0xFF;
        t[off + 64] ^= 0xFF;
        assert!(run_bounded(t) < LIMIT, "corrupt gpt at {off:#x}");
    }
}

#[test]
fn valid_images_analyze_fast() {
    let sup = super_img(
        &[SuperPart {
            name: "system_a",
            group: "system",
            attrs: 0,
            data: vec![0u8; 8192],
        }],
        None,
    );
    let t = Instant::now();
    let layout = analyze(Arc::new(sup)).unwrap();
    assert!(!layout.partitions.is_empty());
    assert!(t.elapsed() < LIMIT);
}
