//! Adversarial robustness sweeps for the FAT parser.
//!
//! Deterministic hostile-input coverage with no fuzzer dependency:
//!
//! * **Truncation sweep** — every byte offset for the first 8 KiB of the
//!   FAT32 corpus image (zero-copy via `OffsetView`), then every 512 B
//!   stride to 1 MiB, then a coarse stride to the end; lighter sweeps over
//!   the FAT16/FAT12 builders.
//! * **Byte-flip sweep** — every byte of the first 4 KiB mutated through
//!   `0x00`, `0xFF` and `!b` (zero-copy via `Patched`), then strided flips
//!   deeper into the image.
//! * **Garbage images** — empty, all-zero, all-`0xFF` and seeded-PRNG
//!   buffers at several sizes, plus "structured garbage" (valid header
//!   prefix, PRNG tail).
//!
//! Every input goes through detect → mount (lenient *and* strict) →
//! info/walk/journal/read in a watchdog thread: a panic or a >10 s stall
//! is reported as a failure, never silently absorbed.

mod common;

use std::io::{self, Read};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use sutram_fat::FatParser;
use sutram_fs::{FsParser, MountOptions};
use sutram_io::{into_arc, ByteSource, OffsetView};

/// Bound on walk/journal items consumed per image — a hostile image must
/// not be able to keep the entry stream producing forever.
const MAX_WALK: usize = 8_192;
/// Per-file read cap during the sweep.
const READ_CAP: usize = 64 * 1024;
/// Watchdog bound for one input's whole exercise run.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// xorshift64* — deterministic "random" bytes so tests are stable.
fn pseudo_random(n: usize, mut x: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        v.push((x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8);
    }
    v
}

/// Zero-copy byte-mutation view: reads pass through to `inner`, then the
/// patched positions are overwritten. Lets the flip sweep mutate a 34 MiB
/// image thousands of times without copying it.
struct Patched {
    inner: Arc<dyn ByteSource>,
    patches: Vec<(u64, u8)>,
}

impl ByteSource for Patched {
    fn len(&self) -> u64 {
        self.inner.len()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read_at(offset, buf)?;
        for &(p, v) in &self.patches {
            if p >= offset && (p - offset) < n as u64 {
                buf[(p - offset) as usize] = v;
            }
        }
        Ok(n)
    }
}

/// Run the whole public surface over one image: detect, mount lenient and
/// strict, info, unallocated map, bounded walk with bounded per-file reads,
/// journal stream. All failures are `Err` values — panics are bugs.
fn exercise(src: &Arc<dyn ByteSource>) {
    let _ = FatParser.detect(src.as_ref());
    for opts in [MountOptions::default(), MountOptions::strict()] {
        let Ok(fs) = FatParser.mount_with(src.clone(), &opts) else {
            continue;
        };
        let _ = fs.info();
        let _ = fs.unallocated_ranges();
        for item in fs.walk().take(MAX_WALK) {
            if let Ok(e) = item {
                if let Ok(mut r) = fs.read_file(&e) {
                    let mut buf = [0u8; 8192];
                    let mut left = READ_CAP;
                    while left > 0 {
                        let want = left.min(buf.len());
                        match r.read(&mut buf[..want]) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => left -= n,
                        }
                    }
                }
                let mut probe = [0u8; 128];
                let _ = fs.read_file_at(&e, 0, &mut probe);
                let _ = fs.read_file_at(&e, u64::MAX / 2, &mut probe);
            }
        }
        for item in fs.journal_entries().take(MAX_WALK) {
            let _ = item;
        }
    }
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Clean,
    Panic,
    Timeout,
}

/// Exercise one input on a watchdog thread: catches panics via
/// `catch_unwind` and flags stalls via a receive timeout.
fn probe(src: Arc<dyn ByteSource>) -> Outcome {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let panicked = catch_unwind(AssertUnwindSafe(|| exercise(&src))).is_err();
        let _ = tx.send(panicked);
    });
    match rx.recv_timeout(PROBE_TIMEOUT) {
        Ok(true) => Outcome::Panic,
        Ok(false) | Err(mpsc::RecvTimeoutError::Disconnected) => Outcome::Clean,
        Err(mpsc::RecvTimeoutError::Timeout) => Outcome::Timeout,
    }
}

fn probe_vec(img: Vec<u8>) -> Outcome {
    probe(into_arc(img))
}

fn probe_prefix(img: &Arc<dyn ByteSource>, n: usize) -> Outcome {
    let view = OffsetView::new(img.clone(), 0, n as u64).expect("offset 0 view");
    probe(Arc::new(view))
}

fn probe_patches(img: &Arc<dyn ByteSource>, patches: &[(u64, u8)]) -> Outcome {
    probe(Arc::new(Patched {
        inner: img.clone(),
        patches: patches.to_vec(),
    }))
}

fn report(kind: &str, failures: Vec<String>) {
    assert!(
        failures.is_empty(),
        "{kind}: {} hostile input(s) crashed or hung:\n{}",
        failures.len(),
        failures
            .iter()
            .take(32)
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ---------------------------------------------------------------------------
// Truncation sweeps
// ---------------------------------------------------------------------------

#[test]
fn truncation_sweep_fat32() {
    let img = into_arc(common::build_fat32());
    let len = img.len() as usize;
    let mut failures = Vec::new();
    let mut record = |n: usize, out: Outcome| {
        if out != Outcome::Clean {
            failures.push(format!("truncate@{n} → {out:?}"));
        }
    };

    // Every byte for the first 8 KiB.
    for n in 0..=8192.min(len) {
        let out = probe_prefix(&img, n);
        record(n, out);
    }
    // Every 512 B to 1 MiB.
    let mut n = 8192 + 512;
    let mid = len.min(1 << 20);
    while n < mid {
        let out = probe_prefix(&img, n);
        record(n, out);
        n += 512;
    }
    // Coarse stride to the end (~512 more samples).
    let stride = (len / 512).max(4096);
    while n < len {
        let out = probe_prefix(&img, n);
        record(n, out);
        n += stride;
    }
    let out = probe_prefix(&img, len);
    record(len, out);

    report("fat32 truncation", failures);
}

#[test]
fn truncation_sweep_fat16_fat12() {
    for (name, img) in [
        ("fat16", into_arc(common::build_fat16())),
        ("fat12", into_arc(common::build_fat12())),
    ] {
        let len = img.len() as usize;
        let mut failures = Vec::new();
        // Every byte for the first 2 KiB, then every 512 B to the end.
        for n in 0..=2048.min(len) {
            let out = probe_prefix(&img, n);
            if out != Outcome::Clean {
                failures.push(format!("{name} truncate@{n} → {out:?}"));
            }
        }
        let mut n = 2048 + 512;
        while n < len {
            let out = probe_prefix(&img, n);
            if out != Outcome::Clean {
                failures.push(format!("{name} truncate@{n} → {out:?}"));
            }
            n += 512;
        }
        report("fat16/fat12 truncation", failures);
    }
}

// ---------------------------------------------------------------------------
// Byte-flip sweeps
// ---------------------------------------------------------------------------

/// Flip `pos` through {0x00, 0xFF, !orig} plus a ^0xFF; record failures.
fn flip_at(
    img: &Arc<dyn ByteSource>,
    pos: u64,
    failures: &mut Vec<String>,
    label: &str,
) {
    let orig = img.read_slice(pos, 1).map(|b| b[0]).unwrap_or(0);
    for v in [0x00u8, 0xFF, !orig, orig ^ 0xFF] {
        if v == orig {
            continue;
        }
        let out = probe_patches(img, &[(pos, v)]);
        if out != Outcome::Clean {
            failures.push(format!("{label} flip@{pos:#x}={v:#04x} → {out:?}"));
        }
    }
}

#[test]
fn byteflip_sweep_fat32_head() {
    let img = into_arc(common::build_fat32());
    let mut failures = Vec::new();
    // Every byte of the first 2 KiB (boot sector, FSInfo, backup area).
    for pos in 0..2048u64 {
        flip_at(&img, pos, &mut failures, "fat32-head");
    }
    report("fat32 head flips", failures);
}

#[test]
fn byteflip_sweep_fat32_fat_region() {
    let img = into_arc(common::build_fat32());
    let mut failures = Vec::new();
    // Bytes 2..4 KiB every byte (FAT #0 head), then every 64 B through the
    // rest of the 4 KiB window and strided through the FATs and data area.
    for pos in 2048u64..4096 {
        flip_at(&img, pos, &mut failures, "fat32-fat");
    }
    let mut pos = 4096u64;
    while pos < img.len() {
        flip_at(&img, pos, &mut failures, "fat32-body");
        pos += if pos < 64 * 1024 { 512 } else { 8192 };
    }
    report("fat32 fat/data flips", failures);
}

#[test]
fn byteflip_sweep_fat16_fat12_head() {
    for (name, img) in [
        ("fat16", into_arc(common::build_fat16())),
        ("fat12", into_arc(common::build_fat12())),
    ] {
        let mut failures = Vec::new();
        for pos in 0..1024u64 {
            flip_at(&img, pos, &mut failures, name);
        }
        let mut pos = 1024u64;
        while pos < img.len().min(64 * 1024) {
            flip_at(&img, pos, &mut failures, name);
            pos += 512;
        }
        report("fat16/fat12 flips", failures);
    }
}

// ---------------------------------------------------------------------------
// Garbage / structured-garbage images
// ---------------------------------------------------------------------------

#[test]
fn garbage_images() {
    let mut failures = Vec::new();
    for size in [0usize, 64, 512, 4096, 64 * 1024, 1 << 20] {
        for (fill, label) in [(0x00u8, "zero"), (0xFF, "ff")] {
            let out = probe_vec(vec![fill; size]);
            if out != Outcome::Clean {
                failures.push(format!("{label} image size {size} → {out:?}"));
            }
        }
        let out = probe_vec(pseudo_random(size, 0x9E37_79B9_7F4A_7C15 ^ size as u64));
        if out != Outcome::Clean {
            failures.push(format!("random image size {size} → {out:?}"));
        }
    }
    report("garbage images", failures);
}

#[test]
fn structured_garbage() {
    // Valid header prefix, PRNG tail — reaches deeper than pure garbage
    // because detect() and the mount-time geometry checks pass.
    let good = common::build_fat32();
    let mut failures = Vec::new();
    for keep in [512usize, 1024, 2048, 4096, 8192, 64 * 1024] {
        let total = good.len().min(8 << 20);
        let mut img = pseudo_random(total, 0xB529_7A4D ^ keep as u64);
        img[..keep].copy_from_slice(&good[..keep]);
        // Keep the boot signature so the boot-sector path proceeds.
        if total > 511 {
            img[510] = 0x55;
            img[511] = 0xAA;
        }
        let out = probe_vec(img);
        if out != Outcome::Clean {
            failures.push(format!("keep {keep}B + random tail → {out:?}"));
        }
    }
    // Random tail on the FAT16/FAT12 builders too.
    for (name, good) in [
        ("fat16", common::build_fat16()),
        ("fat12", common::build_fat12()),
    ] {
        for keep in [512usize, 2048, 8192] {
            let mut img = pseudo_random(good.len(), 0x1B2C_3D4E ^ keep as u64);
            img[..keep].copy_from_slice(&good[..keep]);
            img[510] = 0x55;
            img[511] = 0xAA;
            let out = probe_vec(img);
            if out != Outcome::Clean {
                failures.push(format!("{name} keep {keep}B + random tail → {out:?}"));
            }
        }
    }
    report("structured garbage", failures);
}
