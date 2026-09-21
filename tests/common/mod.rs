//! Synthetic archive construction for tests — the SUTRAM-FS test-corpus
//! pattern: build the archive byte-by-byte in a `Vec<u8>`, mount it via
//! `Arc<Vec<u8>>` as the `ByteSource`, assert on the emitted `FsEntry`
//! stream. No fixture files, no network; corruption cases are produced by
//! deliberately writing bad bytes.

// Each test binary only uses the builders it needs.
#![allow(dead_code)]

pub mod tar;
pub mod zip;
