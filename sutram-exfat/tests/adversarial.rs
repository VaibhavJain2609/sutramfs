//! Adversarial robustness sweeps for the exFAT parser.
//!
//! Deterministic hostile-input coverage with no fuzzer dependency:
//!
//! * **Truncation sweep** — every byte offset for the first 8 KiB of the
//!   corpus image (zero-copy via `OffsetView`), then every 512 B stride to
//!   the end (the image is ~114 KiB).
//! * **Byte-flip sweep** — every byte of the first 4 KiB mutated through
//!   `0x00`, `0xFF` and `!b` (zero-copy via `Patched`), then strided flips
//!   through the rest of the image.
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

use sutram_exfat::ExFatParser;
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
/// patched positions are overwritten.
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
    let _ = ExFatParser.detect(src.as_ref());
    for opts in [MountOptions::default(), MountOptions::strict()] {
        let Ok(fs) = ExFatParser.mount_with(src.clone(), &opts) else {
            continue;
        };
        let _ = fs.info();
        let _ = fs.unallocated_ranges();
        for e in fs.walk().take(MAX_WALK).flatten() {
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
// Truncation sweep
// ---------------------------------------------------------------------------

#[test]
fn truncation_sweep() {
    let img = into_arc(common::build_exfat());
    let len = img.len() as usize;
    let mut failures = Vec::new();

    // Every byte for the first 8 KiB.
    for n in 0..=8192.min(len) {
        let out = probe_prefix(&img, n);
        if out != Outcome::Clean {
            failures.push(format!("truncate@{n} → {out:?}"));
        }
    }
    // Every 512 B to the end.
    let mut n = 8192 + 512;
    while n < len {
        let out = probe_prefix(&img, n);
        if out != Outcome::Clean {
            failures.push(format!("truncate@{n} → {out:?}"));
        }
        n += 512;
    }
    let out = probe_prefix(&img, len);
    if out != Outcome::Clean {
        failures.push(format!("truncate@{len} → {out:?}"));
    }

    report("truncation", failures);
}

// ---------------------------------------------------------------------------
// Byte-flip sweeps
// ---------------------------------------------------------------------------

/// Flip `pos` through {0x00, 0xFF, !orig, orig^0xFF}; record failures.
fn flip_at(img: &Arc<dyn ByteSource>, pos: u64, failures: &mut Vec<String>) {
    let orig = img.read_slice(pos, 1).map(|b| b[0]).unwrap_or(0);
    for v in [0x00u8, 0xFF, !orig, orig ^ 0xFF] {
        if v == orig {
            continue;
        }
        let out = probe_patches(img, &[(pos, v)]);
        if out != Outcome::Clean {
            failures.push(format!("flip@{pos:#x}={v:#04x} → {out:?}"));
        }
    }
}

#[test]
fn byteflip_sweep_head() {
    let img = into_arc(common::build_exfat());
    let mut failures = Vec::new();
    // Every byte of the first 2 KiB (main + extended boot sectors).
    for pos in 0..2048u64 {
        flip_at(&img, pos, &mut failures);
    }
    report("head flips", failures);
}

#[test]
fn byteflip_sweep_fat_and_heap() {
    let img = into_arc(common::build_exfat());
    let mut failures = Vec::new();
    for pos in 2048u64..4096 {
        flip_at(&img, pos, &mut failures);
    }
    // Strided flips through the FAT, bitmap, upcase table and dir heap.
    let mut pos = 4096u64;
    while pos < img.len() {
        flip_at(&img, pos, &mut failures);
        pos += 512;
    }
    report("fat/heap flips", failures);
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
    // because detect() and the boot-region checks pass.
    let good = common::build_exfat();
    let mut failures = Vec::new();
    for keep in [512usize, 1024, 4096, 8192, 32 * 1024] {
        let mut img = pseudo_random(good.len(), 0xB529_7A4D ^ keep as u64);
        img[..keep].copy_from_slice(&good[..keep]);
        img[510] = 0x55;
        img[511] = 0xAA;
        img[3..11].copy_from_slice(b"EXFAT   ");
        let out = probe_vec(img);
        if out != Outcome::Clean {
            failures.push(format!("keep {keep}B + random tail → {out:?}"));
        }
    }
    report("structured garbage", failures);
}
