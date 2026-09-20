//! # sutram-io
//!
//! Read-only byte-source abstraction and container/partition plumbing for the
//! SUTRAM-FS family of filesystem-forensics parsers.
//!
//! Everything in this crate is built around one contract:
//!
//! * **Read-only** — [`ByteSource`] exposes `read_at`/`read_exact_at` only.
//!   There is deliberately no write API; forensic parsers must never mutate
//!   the evidence.
//! * **Random access** — every read carries an absolute `u64` byte offset so
//!   emitted records can always be traced back to the bytes that produced
//!   them (provenance).
//! * **Bounded memory** — callers pull bytes into fixed buffers; nothing in
//!   this crate buffers a whole source.
//!
//! Layers provided here:
//!
//! * [`ByteSource`] + impls for `Vec<u8>`, `&[u8]`, [`File`], `Arc`, `Box`.
//! * Views: [`OffsetView`] (a sub-range, e.g. one partition), [`ConcatSource`]
//!   (several sources glued end-to-end), [`SparseFile`] (extent-mapped image
//!   with zero/fill holes — the representation Android sparse images and
//!   qcow-style containers eventually decode into).
//! * Partition tables: [`partitions`] parses MBR and GPT and returns
//!   [`Partition`] records with byte offsets; [`open_partitions`] returns
//!   ready-to-mount [`PartitionSource`]s.
//! * [`EwfSource`] — a documented stub for the planned pure-Rust EWF (E01)
//!   reader. No FFI to libewf.
//!
//! Endianness is never implicit: all multi-byte reads in this crate use the
//! explicit `*_le` helpers in [`le`], and parser crates are expected to do the
//! same.

#![forbid(unsafe_code)]

mod error;
pub mod le;
mod partition;
mod source;
mod views;

/// Planned pure-Rust EWF (Expert Witness Format / E01) reader.
///
/// EWF segment files (`*.E01`, `*.Ex01`, …) are self-describing containers:
/// a `EVF` file header, section descriptors and `table`/`table2` block maps
/// pointing at zlib/deflate-compressed 32 KiB chunks. A pure-Rust reader is
/// planned on top of [`ByteSource`] + [`SparseFile`]; **it is intentionally
/// not implemented via FFI to libewf** so the crate graph stays portable.
///
/// Until then, [`EwfSource::open`] returns [`Error::Unsupported`] so callers
/// can probe for the capability without `#[cfg]` gates.
pub mod ewf;

pub use error::{Error, Result};
pub use partition::{
    open_partitions, partitions, Partition, PartitionSource, TableKind,
};
pub use source::{into_arc, ByteSource, FileSource, SourceReader};
pub use views::{ConcatSource, OffsetView, SparseExtent, SparseFile, SparseKind};

#[cfg(test)]
mod tests;
