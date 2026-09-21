//! # sutram-artifacts
//!
//! Pure-`std`, `#![forbid(unsafe_code)]` forensic parsers for individual
//! **artifact files** — the contents of a single file, not a filesystem.
//!
//! Each parser takes a `&[u8]` (or a `Read` via `from_reader`) and returns a
//! typed artifact struct. Every extracted record carries an `offset`
//! provenance field: the absolute byte offset within the input buffer that
//! produced it, so a court can ask "which bytes produced this" and get an
//! answer.
//!
//! ## Error contract
//!
//! All parsers share [`Error`]/[`Result`], mirroring the sutram error
//! taxonomy: `Corrupt` for malformed structures, `Truncated` for short
//! input, `Unsupported` for recognised-but-unhandled variants. No parser
//! ever panics on untrusted input — malformed data yields `Err`, and
//! decoders are lenient by default (a corrupt optional block is skipped,
//! not fatal).

#![forbid(unsafe_code)]

pub mod common;
pub mod lnk;
pub mod recycle;

pub use common::{ArtifactTimestamp as FsTimestamp, Error, Result};
