//! Hostile-input sweep: every parser must reject garbage quickly and
//! without panicking. Shared shapes used across the SUTRAM-FS family:
//! empty, single-sector, just-under-the-superblock, 0xFF-filled, and
//! deterministic pseudo-random images, plus a 4K-sector superblock.

mod common;

use std::sync::Arc;

use sutram_fs::{DetectConfidence, FsParser, FileSystem, MountOptions};
use sutram_io::{into_arc, ByteSource};
use sutram_xfs::XfsParser;

fn src(img: Vec<u8>) -> Arc<dyn ByteSource> {
    into_arc(img)
}

fn mount_lenient(img: Vec<u8>) -> Result<Box<dyn FileSystem>, sutram_fs::FsError> {
    XfsParser.mount(src(img))
}

/// xorshift64* — deterministic "random" bytes so tests are stable.
pub fn pseudo_random(n: usize, mut x: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        v.push((x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8);
    }
    v
}

fn walk_does_not_panic(img: Vec<u8>) {
    // detect must answer quickly; mount may fail — both fine, no panic.
    let _ = XfsParser.detect(src(img.clone()).as_ref());
    if let Ok(fs) = mount_lenient(img) {
        let _ = fs.walk().count();
        let _ = fs.info();
        let _ = fs.unallocated_ranges();
    }
}

#[test]
fn empty_image() {
    walk_does_not_panic(Vec::new());
    assert_eq!(
        XfsParser.detect(src(Vec::new()).as_ref()),
        DetectConfidence::None
    );
}

#[test]
fn single_sector_image() {
    walk_does_not_panic(vec![0u8; 512]);
    assert_eq!(
        XfsParser.detect(src(vec![0u8; 512]).as_ref()),
        DetectConfidence::None
    );
}

#[test]
fn just_under_superblock() {
    // 512 B minus one byte — the magic fits but the CRC/geometry don't.
    let img = common::Img::new().finish();
    let short = img[..511].to_vec();
    walk_does_not_panic(short);
    // And the superblock truncated mid-field.
    let shorter = img[..256].to_vec();
    assert_eq!(
        XfsParser.detect(src(shorter).as_ref()),
        DetectConfidence::None
    );
}

#[test]
fn ff_filled_image() {
    let img = vec![0xFFu8; 1 << 20];
    assert_eq!(
        XfsParser.detect(src(img.clone()).as_ref()),
        DetectConfidence::None
    );
    walk_does_not_panic(img);
}

#[test]
fn random_filled_image() {
    let img = pseudo_random(1 << 20, 0x9E37_79B9_7F4A_7C15);
    // Astronomically unlikely to carry an XFSB magic; if it does, the
    // geometry checks must still reject cleanly.
    walk_does_not_panic(img);
}

#[test]
fn magic_only_is_rejected_at_mount() {
    let mut img = vec![0u8; 4096];
    img[0..4].copy_from_slice(&0x5846_5342u32.to_be_bytes());
    assert!(XfsParser.detect(src(img.clone()).as_ref()) <= DetectConfidence::Low);
    assert!(mount_lenient(img).is_err());
}

#[test]
fn valid_sb_but_truncated_image() {
    // Whole sb sector valid; the rest of the image missing — mount reads
    // AG headers at sector offsets and must error (or mount-and-error),
    // never panic.
    let img = common::Img::new().finish();
    let short = img[..512].to_vec();
    let r = mount_lenient(short);
    if let Ok(fs) = r {
        let _ = fs.walk().count();
    }
}

#[test]
fn four_k_sector_variant() {
    // Patch the superblock to a 4 KiB sector device: AG headers then live
    // at 4 KiB offsets where the builder put btree blocks — the parser
    // must surface decode errors, not crash.
    let mut img = common::Img::new().finish();
    img[102..104].copy_from_slice(&4096u16.to_be_bytes());
    img[121] = 12; // sectlog
    // Re-checksum so the sb itself still verifies.
    img[224..228].fill(0);
    let c = common::crc32c(0xFFFF_FFFF, 0, &img[..512]);
    img[224..228].copy_from_slice(&(!c).to_le_bytes());
    walk_does_not_panic(img);
}

#[test]
fn random_image_is_safe_in_strict_mode() {
    let img = pseudo_random(64 * 1024, 0xDEAD_BEEF);
    let r = XfsParser.mount_with(
        src(img),
        &MountOptions {
            strict: true,
            check_magic: true,
            include_orphans: true,
        },
    );
    if let Ok(fs) = r {
        let _ = fs.walk().count();
    }
}
