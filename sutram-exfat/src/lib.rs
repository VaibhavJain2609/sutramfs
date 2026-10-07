//! # sutram-exfat
//!
//! exFAT forensic filesystem parser, following the SUTRAM-FS contract
//! (`sutram-fs` traits over `sutram-io` sources); `sutram-fat` is the
//! reference implementation this crate pattern-matches.
//!
//! Forensic features:
//!
//! * Streaming `walk()` — one [`FsEntry`] at a time, one directory buffered
//!   at a time, never the whole filesystem.
//! * **Boot region** — validates the boot sector, the backup boot sector
//!   (sector 12), and the boot-region checksum (sector 11); `detect()`
//!   scores all of them.
//! * **Deleted entry sets** — exFAT deletion only clears the in-use bit of
//!   every entry-type byte (`0x85 → 0x05`, `0xC0 → 0x40`, `0xC1 → 0x41`);
//!   names, timestamps and extents survive intact. Deleted sets are decoded
//!   wherever they appear — including directory slack past the `0x00`
//!   end-of-directory marker (`meta["beyond_eod"]`). Stray secondary runs
//!   whose primary was overwritten are salvaged (`meta["orphan"]`).
//! * **Recovery assessment** — expected clusters (FAT chain or contiguous
//!   `NoFatChain` extent) are checked against the allocation bitmap:
//!   a set bit means the cluster was reallocated → `Intact` /
//!   `PartiallyOverwritten{recovered, total}` / `Unrecoverable` /
//!   `Unknown`, with `allocated_ranges` narrowed to surviving extents.
//! * **Orphan chains** — bitmap-allocated clusters no entry claims are
//!   emitted under `/$ORPHANED/chain_N`.
//! * **Provenance** — `disk_offset` is the primary entry's absolute offset;
//!   `allocated_ranges` are cluster byte extents; file slack is reported
//!   via `slack_offset`/`slack_len`.
//! * **Timestamps** — create/modify (10 ms increments) and access (2 s),
//!   DOS-style packing with per-timestamp UTC-offset fields applied;
//!   `FsTimestamp` keeps `raw_value`/`raw_encoding`/`granularity`.
//! * **Magic checking** — every file entry gets a `MagicVerdict` from
//!   `sutram-magic` (bounded 4 KiB header read).
//! * Lenient by default: corrupt structures yield `Err(FsError)` records
//!   inside the walk stream; `MountOptions::strict` aborts instead (and
//!   makes boot-checksum mismatch fatal at mount).

#![forbid(unsafe_code)]

mod boot;
mod dirent;
mod fs;
mod walk;

pub use fs::{ExFatFs, ExFatParser};

#[cfg(test)]
mod tests;
