//! Shannon entropy analysis over byte ranges and file entries.
//!
//! Entropy is the classic quick triage for "does this look packed,
//! encrypted, or compressed": ordinary text and code sit around
//! 4–6 bits/byte, compressed data ~7.5+, well-encrypted data
//! indistinguishable from random at ~8.0. Alongside the entropy figure
//! this module reports a **chi-square uniformity statistic** — truly
//! random (well-encrypted) data distributes almost uniformly over the
//! 256 byte values (χ² ≈ 255), while packed/compressed data is often
//! measurably skewed.
//!
//! * [`shannon_entropy`] / [`chi_square`] / [`entropy_bytes`] — pure
//!   slice functions;
//! * [`range_entropy`] — entropy of an arbitrary byte range of a
//!   [`ByteSource`] (slack space, unallocated extents, carved blobs);
//! * [`entry_entropy`] — entropy of an [`FsEntry`]'s contents, streamed
//!   through [`FileSystem::read_file`] and capped at [`SAMPLE_CAP`]
//!   bytes for large files.
//!
//! All of them return [`EntropyVerdict`], whose `suspicion` field is
//! `Some(reason)` when the measurement crosses a forensic threshold.

use std::io::Read;

use sutram_fs::{EntryKind, FileSystem, FsEntry, FsError, Result};
use sutram_io::ByteSource;

/// Maximum bytes examined for one entropy measurement (8 MiB). Entropy
/// is a statistic — the first few MiB are representative enough, and an
/// unbounded read of a 40 GB file buys nothing.
pub const SAMPLE_CAP: u64 = 8 << 20;

/// Read chunk size for streaming measurements.
const CHUNK: usize = 256 << 10;

/// Entropy above this threshold (bits/byte) is flagged — compressed,
/// packed or encrypted content all land here.
pub const HIGH_ENTROPY: f64 = 7.5;

/// Chi-square above this on a high-entropy sample means the byte
/// distribution is far from uniform — more consistent with packing or
/// compression than with strong encryption (expected ≈ 255 for random
/// data, df = 255).
pub const NONUNIFORM_CHI2: f64 = 600.0;

/// Entropy measurement plus its forensic interpretation.
#[derive(Debug, Clone, PartialEq)]
pub struct EntropyVerdict {
    /// Shannon entropy of the sampled bytes, in bits/byte (0.0–8.0).
    /// `0.0` for an empty sample.
    pub entropy: f64,
    /// Pearson chi-square over the 256 byte bins. ≈255 means "looks
    /// uniform/random"; much larger means skewed. `0.0` for an empty
    /// sample.
    pub chi_square: f64,
    /// Bytes actually examined.
    pub sampled: u64,
    /// Bytes the target claims to hold (entry size / requested range).
    pub total: u64,
    /// `true` when `sampled < total` — the measurement is partial
    /// (capped by [`SAMPLE_CAP`], short read, or truncated source).
    pub truncated: bool,
    /// `Some(reason)` when the measurement deserves attention.
    pub suspicion: Option<&'static str>,
}

/// Shannon entropy of `data` in bits/byte (0.0–8.0).
///
/// ```
/// use sutram_analyze::entropy::shannon_entropy;
/// assert_eq!(shannon_entropy(&[]), 0.0);
/// assert_eq!(shannon_entropy(&[0xAA; 4096]), 0.0);
/// let uniform: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
/// assert_eq!(shannon_entropy(&uniform), 8.0);
/// ```
pub fn shannon_entropy(data: &[u8]) -> f64 {
    let counts = byte_counts(data);
    entropy_from_counts(&counts, data.len() as u64)
}

/// Pearson chi-square uniformity statistic over the 256 byte bins:
/// χ² = Σ (observed − n/256)² / (n/256). Perfectly uniform data → 0;
/// random data → ≈255 (degrees of freedom); skewed data → much larger.
/// Returns 0.0 for an empty sample.
pub fn chi_square(data: &[u8]) -> f64 {
    let counts = byte_counts(data);
    chi2_from_counts(&counts, data.len() as u64)
}

/// Measure entropy of a slice.
pub fn entropy_bytes(data: &[u8]) -> EntropyVerdict {
    let counts = byte_counts(data);
    verdict(&counts, data.len() as u64, data.len() as u64)
}

/// Measure entropy of `[offset, offset + len)` on a [`ByteSource`].
///
/// At most [`SAMPLE_CAP`] bytes are read; `truncated` in the verdict
/// records whether the sample covers the whole requested range.
/// Short reads at the end of a source are tolerated — `sampled` shows
/// what was really measured.
pub fn range_entropy(src: &dyn ByteSource, offset: u64, len: u64) -> Result<EntropyVerdict> {
    let mut counts = [0u64; 256];
    let mut sampled = 0u64;
    let want = len.min(SAMPLE_CAP);
    let mut buf = vec![0u8; CHUNK];
    while sampled < want {
        let ask = (want - sampled).min(buf.len() as u64) as usize;
        let n = src
            .read_at(offset.saturating_add(sampled), &mut buf[..ask])
            .map_err(FsError::Io)?;
        if n == 0 {
            break;
        }
        for &b in &buf[..n] {
            counts[b as usize] += 1;
        }
        sampled += n as u64;
    }
    Ok(verdict(&counts, sampled, len))
}

/// Measure entropy of an [`FsEntry`]'s contents.
///
/// Streams `read_file` in fixed chunks, examining at most
/// [`SAMPLE_CAP`] bytes. Non-`File` kinds return
/// [`FsError::InvalidInput`]. `truncated` covers both the cap and
/// short reads (e.g. partially-overwritten deleted files).
pub fn entry_entropy(fs: &dyn FileSystem, entry: &FsEntry) -> Result<EntropyVerdict> {
    if entry.kind != EntryKind::File {
        return Err(FsError::InvalidInput {
            msg: format!(
                "entry_entropy: {} is a {:?}, not a file",
                entry.path, entry.kind
            ),
        });
    }
    let mut counts = [0u64; 256];
    let mut sampled = 0u64;
    let want = entry.size.min(SAMPLE_CAP);
    let mut r = fs.read_file(entry)?;
    let mut buf = vec![0u8; CHUNK];
    while sampled < want {
        let ask = (want - sampled).min(buf.len() as u64) as usize;
        let n = r.read(&mut buf[..ask]).map_err(FsError::Io)?;
        if n == 0 {
            break;
        }
        for &b in &buf[..n] {
            counts[b as usize] += 1;
        }
        sampled += n as u64;
    }
    Ok(verdict(&counts, sampled, entry.size))
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

fn byte_counts(data: &[u8]) -> [u64; 256] {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    counts
}

fn entropy_from_counts(counts: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let n = total as f64;
    let mut h = 0.0f64;
    for &c in counts {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

fn chi2_from_counts(counts: &[u64; 256], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let expected = total as f64 / 256.0;
    let mut chi2 = 0.0f64;
    for &c in counts {
        let d = c as f64 - expected;
        chi2 += d * d / expected;
    }
    chi2
}

fn verdict(counts: &[u64; 256], sampled: u64, total: u64) -> EntropyVerdict {
    let entropy = entropy_from_counts(counts, sampled);
    let chi_square = chi2_from_counts(counts, sampled);
    let suspicion = if sampled >= 64 && entropy > HIGH_ENTROPY {
        if chi_square > NONUNIFORM_CHI2 {
            Some(
                "high entropy (>7.5 bits/byte) with non-uniform bytes — \
                 likely packed/compressed rather than encrypted",
            )
        } else {
            Some(
                "high entropy (>7.5 bits/byte) with uniform bytes — \
                 packed, encrypted, or compressed content",
            )
        }
    } else {
        None
    };
    EntropyVerdict {
        entropy,
        chi_square,
        sampled,
        total,
        truncated: sampled < total,
        suspicion,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::sync::Arc;

    use sutram_fs::{FsEntryStatus, FsInfo, FsTimestamp, Timestamps};

    /// PRNG-ish byte filler (deterministic, high-entropy-ish but skewed
    /// enough to keep chi² honest — it cycles a 256-symbol permutation).
    fn pseudo_random(n: usize) -> Vec<u8> {
        // xorshift-ish generator over a large prime-ish period
        let mut out = Vec::with_capacity(n);
        let mut x: u32 = 0x9E3779B9;
        while out.len() < n {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            out.push((x & 0xff) as u8);
        }
        out
    }

    #[test]
    fn entropy_of_extremes() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0u8; 8192]), 0.0);
        // exactly uniform: every byte value equally often → 8.0
        let uniform: Vec<u8> = (0..=255u8).cycle().take(256 * 64).collect();
        assert_eq!(shannon_entropy(&uniform), 8.0);
        assert_eq!(chi_square(&uniform), 0.0);
        // two symbols → 1.0
        let two: Vec<u8> = (0..8192).map(|i| (i % 2) as u8).collect();
        assert!((shannon_entropy(&two) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn entropy_of_text_is_low() {
        let text = b"the quick brown fox jumps over the lazy dog. ".repeat(200);
        let v = entropy_bytes(&text);
        assert!(v.entropy < 6.0, "entropy {}", v.entropy);
        assert!(v.suspicion.is_none());
        assert_eq!(v.sampled, text.len() as u64);
        assert!(!v.truncated);
    }

    #[test]
    fn entropy_flags_high_entropy() {
        // near-uniform pseudo-random → flagged
        let rnd = pseudo_random(64 * 1024);
        let v = entropy_bytes(&rnd);
        assert!(v.entropy > HIGH_ENTROPY, "entropy {}", v.entropy);
        assert!(v.suspicion.is_some());
    }

    #[test]
    fn chi_square_distinguishes_skewed_high_entropy() {
        // High entropy but strongly skewed: all 256 symbols present with
        // exponential weights — entropy ~7.5-8, chi² far above uniform.
        let mut skewed = Vec::with_capacity(1 << 20);
        for sym in 0..256u32 {
            let count = 1usize << (sym % 13);
            skewed.extend(std::iter::repeat_n(sym as u8, count));
        }
        let v = entropy_bytes(&skewed);
        assert!(v.chi_square > NONUNIFORM_CHI2, "chi2 {}", v.chi_square);
        if v.entropy > HIGH_ENTROPY {
            assert!(v.suspicion.unwrap().contains("packed/compressed"));
        }
    }

    #[test]
    fn range_entropy_reads_windows() {
        let mut src = vec![0u8; 4096];
        src.extend(pseudo_random(8192));
        src.extend(vec![0u8; 4096]);
        let low = range_entropy(&src.as_slice(), 0, 4096).unwrap();
        assert_eq!(low.entropy, 0.0);
        let high = range_entropy(&src.as_slice(), 4096, 8192).unwrap();
        assert!(high.entropy > HIGH_ENTROPY);
        // range longer than the source tail: short read → truncated
        let t = range_entropy(&src.as_slice(), 16_000, 4096).unwrap();
        assert_eq!(t.sampled, 384);
        assert!(t.truncated);
    }

    // -- entry_entropy via a canned FileSystem ---------------------------

    struct MemFs {
        data: HashMap<u64, Vec<u8>>,
        src: Arc<Vec<u8>>,
    }

    impl FileSystem for MemFs {
        fn info(&self) -> FsInfo {
            FsInfo {
                fs_type: "mem".into(),
                ..Default::default()
            }
        }
        fn source(&self) -> Arc<dyn ByteSource> {
            self.src.clone()
        }
        fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
            Box::new(std::iter::empty())
        }
        fn read_file(&self, entry: &FsEntry) -> Result<Box<dyn Read + Send>> {
            match self.data.get(&entry.entry_id) {
                Some(d) => Ok(Box::new(Cursor::new(d.clone()))),
                None => Err(FsError::NotFound {
                    path: entry.path.clone(),
                }),
            }
        }
    }

    fn file_entry(id: u64, path: &str, size: u64) -> FsEntry {
        FsEntry {
            path: path.into(),
            name: path.rsplit('/').next().unwrap_or(path).into(),
            entry_id: id,
            kind: EntryKind::File,
            size,
            disk_offset: 0,
            allocated_ranges: vec![],
            timestamps: Timestamps {
                modified: Some(FsTimestamp {
                    value: Some(0),
                    raw_value: 0,
                    raw_encoding: "test",
                    granularity: std::time::Duration::from_secs(1),
                }),
                ..Default::default()
            },
            status: FsEntryStatus::Live,
            meta: HashMap::new(),
            magic: None,
        }
    }

    #[test]
    fn entry_entropy_flags_and_caps() {
        let mut data = HashMap::new();
        let big: Vec<u8> = pseudo_random((SAMPLE_CAP + 4096) as usize);
        data.insert(1u64, big.clone());
        let fs = MemFs {
            data,
            src: Arc::new(Vec::new()),
        };
        let e = file_entry(1, "/blob.bin", big.len() as u64);
        let v = entry_entropy(&fs, &e).unwrap();
        assert_eq!(v.sampled, SAMPLE_CAP);
        assert_eq!(v.total, big.len() as u64);
        assert!(v.truncated);
        assert!(v.entropy > HIGH_ENTROPY);
        assert!(v.suspicion.is_some());
    }

    #[test]
    fn entry_entropy_rejects_dirs() {
        let fs = MemFs {
            data: HashMap::new(),
            src: Arc::new(Vec::new()),
        };
        let mut d = file_entry(2, "/dir", 0);
        d.kind = EntryKind::Directory;
        assert!(matches!(
            entry_entropy(&fs, &d),
            Err(FsError::InvalidInput { .. })
        ));
    }
}
