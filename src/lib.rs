//! # sutram-fat
//!
//! FAT12/16/32 forensic parser — the **reference implementation** for the
//! SUTRAM-FS contract (`sutram-fs`).
//!
//! Forensic features:
//!
//! * Streaming `walk()` — one [`FsEntry`] at a time, directories buffered a
//!   table at a time, never the whole filesystem.
//! * **Deleted entries** — `0xE5`-marked dir entries (including entries past
//!   the `0x00` end-of-directory marker), deleted LFN fragments, and
//!   *orphaned cluster chains* emitted under `/$ORPHANED/…`.
//! * **Recovery assessment** — deleted-file cluster chains are compared
//!   against the live allocation map: clusters reallocated to a live file
//!   are reported lost, yielding `Intact` / `PartiallyOverwritten` /
//!   `Unrecoverable` / `Unknown` per entry with byte-exact
//!   `allocated_ranges`.
//! * **Provenance** — `FsEntry::disk_offset` is the dir-entry's absolute
//!   offset; `allocated_ranges` are cluster byte extents; file slack is
//!   reported via `slack_offset`/`slack_len` meta keys.
//! * **Timestamps** — DOS create (10 ms), write (2 s) and access (1 day)
//!   times decoded into `FsTimestamp`s with `raw_value` preserved.
//! * **Magic checking** — every file entry gets a `MagicVerdict` from
//!   `sutram-magic` (bounded 4 KiB header read).
//! * Lenient by default: corrupt structures yield `Err(FsError)` records
//!   inside the walk stream; `MountOptions::strict` aborts instead.

#![forbid(unsafe_code)]

mod boot;
mod dirent;
mod fs;
mod walk;

pub use boot::FatType;
pub use fs::{FatFs, FatParser};

#[cfg(test)]
mod tests;
