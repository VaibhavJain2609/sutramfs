//! # sutram-xfs
//!
//! Forensic, read-only **XFS** parser for the SUTRAM-FS ecosystem.
//!
//! ## Scope
//!
//! * XFS v5 (CRC-enabled) superblocks, AGF/AGI/AGFL allocation-group
//!   headers, v4 structures recognised where the layout is stable.
//! * Per-AG **inobt**/**finobt** walks — allocated, free and
//!   recently-freed inode chunks; freed inode slots with residual content
//!   become deleted entries.
//! * Inode cores (v3 + legacy), `local`/`extents`/`btree` forks,
//!   BMBT extent decode (with unwritten-extent flags).
//! * Directories: shortform, block (`XD2B`/`XDB3`), multi-block data
//!   (`XD2D`/`XDD3`) with leaf/node/btree layouts — data blocks are
//!   scanned directly so freed-region residue is recovered.
//! * Remote symlinks (`XSLM`), local + leaf extended attributes (`XARM`
//!   remote values), free-space trees (`bnobt`) → `unallocated_ranges`.
//! * v5 metadata **CRC32C** validation on every CRC-bearing block.
//!
//! ## Endianness
//!
//! XFS on-disk metadata is **big-endian**. Every field is decoded through
//! explicit `u16_be`/`u32_be`/`u64_be` reads — no host-order assumptions,
//! no unsafe code. The one exception is the CRC field itself, which is
//! little-endian even on disk (see `xfs_cksum.h`).
//!
//! ## Known limitations
//!
//! * **Journal (log) replay is not implemented** — the log's presence and
//!   location are reported via `FsInfo::meta["log"]`, but recovery does
//!   not replay transactions. Documented TODO.
//! * v4 filesystems parse core structures; v5 dir3/attr3 CRC blocks are
//!   validated, v4 variants are decoded without CRC.
//! * Leaf/btree directory index blocks are skipped in favour of scanning
//!   data blocks directly (equivalent content, plus residue).
//! * Realtime files, reflink/shared extents and quota inodes are noted
//!   but not fully interpreted.
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use sutram_fs::{FileSystem, FsParser, MountOptions};
//! use sutram_io::into_arc;
//! use sutram_io::FileSource;
//! use sutram_xfs::XfsParser;
//!
//! let src = into_arc(FileSource::open("image.raw").unwrap());
//! let parser = XfsParser;
//! let fs = parser.mount(src).unwrap();
//! for entry in fs.walk().flatten() {
//!     println!("{} {} deleted={}", entry.path, entry.size, entry.is_deleted());
//! }
//! ```

#![forbid(unsafe_code)]

mod attr;
mod btree;
mod crc;
mod dir;
mod extent;
mod fs;
mod inode;
mod sb;
mod walk;

pub use fs::{XfsFs, XfsParser};

#[cfg(test)]
mod tests;
