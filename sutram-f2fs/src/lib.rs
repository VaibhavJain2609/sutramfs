//! # sutram-f2fs
//!
//! F2FS (Flash-Friendly File System) forensic parser — the filesystem used
//! on modern Android userdata partitions. Implements the SUTRAM-FS
//! contract (`sutram-fs` traits over `sutram-io` sources).
//!
//! Forensic features:
//!
//! * Streaming `walk()` — one [`FsEntry`] at a time; directories are read a
//!   dentry block at a time, never the whole filesystem.
//! * **Log-structured recovery** — F2FS never overwrites in place, so old
//!   copies persist: the *stale* SIT/NAT copies (previous checkpoint) still
//!   map deleted nids and earlier node versions; free segments still hold
//!   old node blocks. The walk scans all three sources.
//! * **Deleted artefacts** — dentry residue (bitmap-clear slots), stale-NAT
//!   nids, checkpoint orphan inodes, and inode nodes found in SIT-free
//!   segments are all emitted with `RecoveryState` assessment per extent
//!   (`Intact` / `PartiallyOverwritten` / `Unrecoverable` / `Unknown`).
//! * **Prior versions** — node blocks superseded by a newer checkpoint are
//!   emitted under `/$ORPHANED/` when their old block survives.
//! * **Provenance** — `disk_offset` is the dentry slot / node block that
//!   produced the entry; `allocated_ranges` are absolute byte extents.
//! * **Timestamps** — nsec-granularity atime/ctime/mtime plus `crtime`
//!   (when `EXTRA_ATTR` covers it) → `FsTimestamp`.
//! * **fscrypt awareness** — encrypted inodes/dirs are flagged
//!   (`meta["encrypted"]`, `meta["fscrypt_context"]`); names under
//!   encrypted directories are marked `encrypted_name`. No decryption.
//! * **Magic verdicts** — bounded 4 KiB header check via `sutram-magic`.
//! * Lenient by default; `MountOptions::strict` aborts on first error.

#![forbid(unsafe_code)]

mod checkpoint;
mod crc32;
mod dentry;
mod fs;
mod node;
mod sb;
mod tables;
mod walk;

pub use fs::{F2fsFs, F2fsParser};

#[cfg(test)]
mod tests;
