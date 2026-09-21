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
//! * [`ewf::EwfSource`] — pure-Rust EWF (E01) reader exposing the image as
//!   a `ByteSource` plus acquisition hashes and error ranges. No FFI to
//!   libewf.
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

/// Pure-Rust EWF (Expert Witness Format / E01) reader.
///
/// EWF segment files (`*.E01`, `*.E02`, …) are self-describing
/// containers: an `EVF` file header, framed section descriptors and
/// `table`/`table2` block maps pointing at zlib/deflate-compressed
/// chunks. [`ewf::EwfSource`] opens single- and multi-segment images and
/// exposes them as a [`ByteSource`] alongside the stored acquisition
/// hashes and error ranges. EWF2 (`*.Ex01`) and logical (`.L01`) images
/// are detected and reported as [`Error::Unsupported`]. No FFI to
/// libewf — decompression is pure Rust via `miniz_oxide`.
pub mod ewf;

/// Read-only VHD (`*.vhd`) and VHDX (`*.vhdx`) virtual-disk readers.
///
/// [`vhd::VhdSource`] auto-detects the format and exposes fixed and
/// dynamic VHD (sector-bitmap blocks, BAT of sector offsets) and
/// non-differencing VHDX (region table + u64 BAT) as a [`ByteSource`].
/// Differencing images — which need a parent file to resolve blocks —
/// are reported as [`Error::Unsupported`].
pub mod vhd;

/// Pure-Rust QCOW2 (`*.qcow2`) image reader.
///
/// [`qcow2::Qcow2Source`] walks the two-level L1/L2 cluster map and
/// exposes the virtual disk as a [`ByteSource`], including raw-deflate
/// compressed clusters. Backing-file (differencing) and encrypted
/// (AES/LUKS) images are reported as [`Error::Unsupported`]; refcount
/// tables are ignored — this reader never writes.
pub mod qcow2;

pub use error::{Error, Result};
pub use partition::{
    open_partitions, partitions, Partition, PartitionSource, TableKind,
};
pub use source::{into_arc, ByteSource, FileSource, SourceReader};
pub use views::{ConcatSource, OffsetView, SparseExtent, SparseFile, SparseKind};

#[cfg(test)]
mod tests;
