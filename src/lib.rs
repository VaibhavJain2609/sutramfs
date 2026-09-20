#![forbid(unsafe_code)]
//! `sutram-apfs` — a clean-room, read-only, pure-Rust forensic parser for
//! Apple's APFS containers and volumes.
//!
//! ## Mount pipeline
//!
//! Block 0's `nx_superblock_t` is read as a *discovery label* (it is often
//! stale or damaged — the spec treats it as a pointer to the real metadata).
//! The authoritative container state comes from scanning the checkpoint
//! descriptor area for the checksum-valid `nx_superblock_t` with the highest
//! transaction id, plus its `checkpoint_map_phys_t` blocks. The container
//! object map resolves volume superblocks, the volume object map resolves
//! the file-system B-tree, and the tree's leaf records carry inodes,
//! directory records, extents, xattrs, hardlinks and snapshot names.
//!
//! Fletcher-64 checksums are verified on **every** object read (APFS's
//! integrity model). Block 0 is the single documented exception.
//!
//! ## Forensic behaviour
//!
//! * Deleted files: prior checkpoints' fs trees are diffed against the live
//!   generation; absent inodes are emitted as `Deleted` with a
//!   block-granular recovery assessment.
//! * Snapshots: `mount_snapshot` bounds omap lookups to the snapshot's xid.
//! * Encryption is detected and reported (`encrypted` / `extent_encrypted`
//!   metadata) but never decrypted.
//! * Lenient by default: corruption surfaces as `Err` items inside the
//!   walk stream rather than aborting the mount.
//!
//! See `README.md` for spec coverage and limitations.

mod apsb;
mod btree;
mod checksum;
mod fs;
mod jrec;
mod nx;
mod object;
mod omap;
mod spaceman;
mod walk;

pub use fs::{ApfsFs, ApfsParser, SnapshotInfo, VolumeInfo};

#[cfg(test)]
mod tests;
