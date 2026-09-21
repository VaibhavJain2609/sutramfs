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

pub mod hash;

pub use hash::{
    hash_entry, hash_reader, hash_source, verify_acquisition, verify_ewf, verify_source,
    AcqVerification, Digests, HashMismatch, HashResult, Md5, MediaHashes, Sha1, Sha256,
};
