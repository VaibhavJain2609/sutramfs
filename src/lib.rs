//! # sutram-fs
//!
//! Core traits and types shared by every SUTRAM-FS parser crate
//! (`sutram-fat`, `sutram-ntfs`, `sutram-ext4`, …).
//!
//! ## The contract
//!
//! A parser crate exposes one [`FsParser`] value:
//!
//! ```text
//! let parser = sutram_fat::FatParser;
//! if parser.detect(src) >= DetectConfidence::Medium {
//!     let fs = parser.mount(src)?;          // -> Box<dyn FileSystem>
//!     for entry in fs.walk() {              // streaming, bounded memory
//!         match entry {
//!             Ok(e)  => println!("{} {} {:?}", e.path, e.size, e.status),
//!             Err(e) => log_corruption(e),  // lenient: errors are records
//!         }
//!     }
//! }
//! ```
//!
//! Forensic requirements baked into these types:
//!
//! * **Read-only** — parsers only ever see [`sutram_io::ByteSource`].
//! * **Bounded memory / streaming** — [`FileSystem::walk`] yields one
//!   [`FsEntry`] at a time; nothing buffers the whole filesystem.
//! * **No panics on untrusted input** — corruption surfaces as
//!   [`FsError::Corrupt`] (with the byte offset that produced it); parsers
//!   are lenient by default and emit what they could parse plus error
//!   records. Strict mode is opt-in via [`MountOptions::strict`].
//! * **Provenance** — every [`FsEntry`] carries `disk_offset` (the on-disk
//!   metadata record) and `allocated_ranges` (the data extents).
//! * **Deleted & recoverable** — [`FsEntry::status`] is
//!   [`FsEntryStatus::Live`] or `Deleted { recovery: RecoveryState }`;
//!   orphans/slack are emitted as entries or ranges, never dropped silently.
//! * **Timestamps** — MACB-style [`Timestamps`] of structured
//!   [`FsTimestamp`]s preserving the raw encoding and granularity.
//! * **Magic checking** — parsers fill [`FsEntry::magic`] by handing file
//!   headers to [`sutram_magic`], so callers get a per-file
//!   [`MagicVerdict`] (extension↔content masquerade detection).

#![forbid(unsafe_code)]

pub mod carve;
mod error;
mod traits;
mod types;
pub mod util;

pub use carve::CarveOptions;
pub use error::{FsError, Result};
pub use traits::{FileSystem, FsParser, MountOptions};
pub use types::{
    CarveHit, DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsInfo, FsTimestamp,
    RecoveryReport, RecoveryState, Timestamps,
};

// Re-exported so downstream crates name one dependency for the vocabulary.
pub use sutram_io::ByteSource;
pub use sutram_magic::{MagicType, MagicVerdict, Severity};

#[cfg(test)]
mod tests;
