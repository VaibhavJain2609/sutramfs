//! # sutram-analyze
//!
//! The **analysis layer** of the SUTRAM-FS forensic family. Where the
//! parser crates (`sutram-fat`, `sutram-ntfs`, …) turn disk images into
//! `FsEntry` streams, this crate turns those streams into examiner
//! answers: content hashing, entropy analysis, MACB timelines,
//! aggregate suspicion scoring and binary-safe keyword search.
//!
//! Everything obeys the same contract as the parsers: read-only access,
//! bounded memory (per-entry streaming, capped reads), no panics on
//! untrusted input, and every claim carries the signal that produced it.

#![forbid(unsafe_code)]

pub mod entropy;
pub mod hash;
pub mod suspicion;
pub mod timeline;

pub use entropy::{
    chi_square, entry_entropy, entropy_bytes, range_entropy, shannon_entropy, EntropyVerdict,
    HIGH_ENTROPY, NONUNIFORM_CHI2, SAMPLE_CAP,
};
pub use hash::{
    hash_entry, hash_reader, hash_source, verify_acquisition, verify_ewf, verify_source,
    AcqVerification, Digests, HashMismatch, HashResult, Md5, MediaHashes, Sha1, Sha256,
};
pub use suspicion::{
    assess, assess_with, score_entry, Assessment, EntrySuspicion, Signals, Suspicion,
};
pub use timeline::{Timeline, TimelineEvent, TimelineOptions};
