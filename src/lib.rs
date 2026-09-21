//! # sutram-ext4
//!
//! ext2/3/4 forensic filesystem parser for the SUTRAM-FS contract
//! (`sutram-fs` traits over `sutram-io` sources).
//!
//! Forensic features:
//!
//! * **Streaming `walk()`** — one [`FsEntry`] at a time: the live tree,
//!   then dirent-slack carves, then the unallocated-inode / orphan pass.
//!   Memory stays proportional to one directory or one bitmap block.
//! * **Block maps** — ext4 extent trees (any depth) plus the legacy
//!   ext2/3 direct/single/double/triple-indirect fallback; inline-data
//!   inodes and fast/slow symlinks decoded.
//! * **Deleted recovery** — three sources: (1) directory slack carving
//!   inside `rec_len` gaps for deleted names, (2) unallocated inodes that
//!   still carry extent data, (3) the `s_last_orphan` orphan list.
//!   Recovery assessment compares each expected block against the block
//!   bitmap and the live-claim map → `Intact` / `PartiallyOverwritten` /
//!   `Unrecoverable` / `Unknown`.
//! * **Timestamps** — ext4 nanosecond extension fields (`i_*_extra`,
//!   30-bit ns + 2-bit epoch extension) and `i_crtime` birth time, plus
//!   `i_dtime` deletion time; raw encodings preserved.
//! * **Journal forensics** — the jbd2 journal (inode 8) is parsed into
//!   [`JournalEvent`]s: superblock, descriptor, commit and revocation
//!   blocks plus one record per journaled metadata copy. `journal_events()`
//!   streams the typed records; `FileSystem::journal_entries()` emits them
//!   as pseudo-entries whose `allocated_ranges` read back the journaled
//!   payload — prior-state evidence for inode tables, bitmaps and freed
//!   blocks. `FsInfo.meta` carries `jbd2_*` counts; transaction replay is
//!   a documented TODO (see `journal` module).
//! * **Provenance** — `disk_offset` = dirent or inode offset;
//!   `allocated_ranges` = absolute byte extents; slack and xattrs are
//!   surfaced in `meta`.
//! * Lenient by default: corruption yields `Err(FsError)` records inside
//!   the walk stream; `MountOptions::strict` aborts on the first error.
//!
//! Checksums (`metadata_csum`, `metadata_csum_seed`, GDT/inode/journal
//! crc32c) are **not verified** — they're reported as feature flags only;
//! see README "Known limitations".

#![forbid(unsafe_code)]

mod dirent;
mod extent;
mod fs;
mod gdt;
mod inode;
mod journal;
mod superblock;
mod walk;

pub use fs::{Ext4Fs, Ext4Parser};
pub use journal::{JournalEvent, JournalEventKind, JournalTag, JournalTarget};

#[cfg(test)]
mod tests;
