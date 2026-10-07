//! # sutram-btrfs
//!
//! BTRFS forensic parser — a Rust port (and superset) of the pure-Python
//! `btrfsparser` tool, built on the SUTRAM-FS contract (`sutram-fs` traits
//! over `sutram-io` byte sources).
//!
//! BTRFS is a copy-on-write filesystem: every commit writes *new* tree
//! blocks and extents rather than overwriting in place. That makes it a
//! forensic goldmine — previous filesystem generations often survive
//! intact on disk. This parser exploits that:
//!
//! * **Superblock** at `0x10000` with mirror fallback (64 MiB, 256 GiB
//!   copies), CRC32C-verified, plus the four embedded **backup roots** —
//!   the entry points into COW history.
//! * **Chunk map** (`sys_chunk_array` → chunk tree) translating logical
//!   to physical addresses, including striped RAID0/RAID10 geometry
//!   (parity RAID5/6 recognised but reported unsupported).
//! * **B-tree traversal** with per-node checksum verification and
//!   generation-consistency checks (a stale keyptr flags a COW remnant or
//!   torn write rather than failing the walk).
//! * **Deleted / prior-version recovery** — old-generation FS trees
//!   reached through the superblock's backup roots are diffed against the
//!   live trees: inodes that vanished are `Deleted` entries, inodes whose
//!   items changed yield prior versions at `path@v<generation>`.
//! * **Orphan items** (`BTRFS_ORPHAN_OBJECTID`) — unlinked-but-not-reaped
//!   inodes emitted as `Deleted` artefacts.
//! * **Extent backrefs** (EXTENT_ITEM / EXTENT_DATA_REF / SHARED_*) give
//!   per-extent provenance and drive the recoverability verdict:
//!   freed-but-residual vs reallocated (overwritten).
//! * **Compressed extents** are decompressed (zlib/zstd/LZO — pure-Rust
//!   codecs) so content and magic verdicts see real bytes.
//! * **Timestamps** — all four BTRFS timespecs (atime/mtime/ctime/otime,
//!   1 ns granularity) become `FsTimestamp`s.
//! * **Provenance** — `disk_offset` is the inode item's physical offset;
//!   `allocated_ranges` are absolute physical extents; `meta` records the
//!   logical addresses too.
//! * Lenient by default: corrupt structures yield `Err(FsError)` items
//!   inside the walk stream; `MountOptions::strict` aborts at the first.

#![forbid(unsafe_code)]

mod btree;
mod chunk;
mod decompress;
mod fs;
mod index;
mod ondisk;
mod read;
mod superblock;
mod walk;

pub use fs::{unique_inode, BtrfsFs, BtrfsParser};

#[cfg(test)]
mod tests;
