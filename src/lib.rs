//! # sutram-hfs
//!
//! HFS+ / HFSX forensic filesystem parser for the SUTRAM-FS contract
//! (`sutram-fs` traits over `sutram-io` sources). Pure HFS (`"BD"` without an
//! embedded HFS+ volume) is detected but mount returns `Unsupported`.
//!
//! All HFS+ metadata is **big-endian** — decoded via `sutram_io::le::*_be`.
//!
//! Forensic features:
//!
//! * **Catalog B-tree** — node descriptors, offset tables, thread/leaf
//!   enumeration without recursion (the leaf chain is followed by `fLink`,
//!   bounded by `total_nodes`).
//! * **Extents** — inline `HFSPlusForkData` extents merged with
//!   extents-overflow-file records keyed `(forkType, fileID, startBlock)`;
//!   data *and* resource forks exposed (rsrc as `name:rsrc` pseudo-entries).
//! * **Hard links / symlinks** — `hlnk`/`hfs+` Finder types resolve through
//!   `iNode<N>` files under the `"HFS+ Private Data"` metadata folder;
//!   `slnk`/`rhap` symlinks read their target from the data fork.
//! * **Extended attributes** — attributes-file records become
//!   `name:xattr:<attr>` pseudo-entries + `xattr_*` meta keys.
//! * **decmpfs** — `com.apple.decmpfs` files get `compressed`/`decmpfs_*`
//!   meta; zlib types (3 inline, 4 resource-fork block table, 1/9/10 raw)
//!   and LZVN types (7 inline, 8 resource-fork) decompress transparently
//!   in `read_file`; LZFSE/LZBITMAP are flagged `Unsupported` via
//!   `compression_note`.
//! * **Deleted & recoverable** — three residue sources: live leaf nodes'
//!   free space, dead B-tree nodes (freed by compaction), and orphaned
//!   extents-overflow records (`/$ORPHANED/extents_<cnid>`). Recovery state
//!   is computed against the live allocation-block map: blocks reallocated
//!   to live files are reported lost.
//! * **Timestamps** — the five HFS+ u32 dates (create/contentMod/attrMod/
//!   access/backup) decoded as `hfs+-u32-1904-local`; raw values preserved.
//! * **Journal forensics** — `journalInfoBlock` locates the journal
//!   buffer; its `journal_header` + `block_list_header` chain is parsed
//!   into [`JournalEvent`]s (`HfsFs::journal_events()`), emitted as
//!   `/$JOURNAL/` pseudo-entries via `journal_entries()` — each journaled
//!   block copy keeps its payload readable and its destination sector in
//!   meta. Live-chain and stale overwritten transactions are both
//!   surfaced; replay is a documented TODO.
//! * **Provenance** — `disk_offset` = the catalog record's absolute offset;
//!   `allocated_ranges` = absolute extent byte ranges.
//! * Lenient by default: corrupt nodes/records yield `Err(FsError)` items;
//!   `MountOptions::strict` aborts on the first error.

#![forbid(unsafe_code)]

mod attrs;
mod btree;
mod catalog;
mod extents;
mod fs;
mod journal;
mod vh;
mod walk;

pub use fs::{HfsFs, HfsParser};
pub use journal::{
    journal_checksum, JournalEvent, JournalEventKind, JournalHeader,
};

#[cfg(test)]
mod tests;
