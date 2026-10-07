//! # sutram-ntfs
//!
//! NTFS forensic parser for the SUTRAM-FS contract (`sutram-fs` traits
//! over `sutram-io` sources) — the dominant Windows filesystem and the
//! richest target in the family.
//!
//! Forensic features:
//!
//! * **Fixup done right** — every FILE and INDX record gets its
//!   update-sequence-array applied and verified before any field is
//!   trusted; a trailer/sequence mismatch surfaces as a `Corrupt` error
//!   record (torn-write evidence), never as silently bad data.
//! * **Streaming `walk()`** — linear scan of the $MFT (located via record
//!   0's own data runs) plus a per-directory INDX pass; one `FsEntry` at
//!   a time, no whole-filesystem buffering.
//! * **Dual timestamp sets** — `$STANDARD_INFORMATION` and `$FILE_NAME`
//!   MACB times are both decoded and both emitted (`si_*` / `fn_*` meta
//!   keys), with a `timestomp_suspect` flag when SI predates FN — the
//!   signature of tools that rewrite SI and forget FN.
//! * **Deleted records** — in-use-flag-clear FILE records are emitted with
//!   an honest `RecoveryState`: extents are subtracted against a live
//!   cluster map built at mount (`Intact` / `PartiallyOverwritten` /
//!   `Unrecoverable`), and `allocated_ranges` lists exactly what survives.
//! * **MFT slack carving** — FILE-record fragments beyond $MFT's used size
//!   (`mft_slack`), `BAAD` records, and unparseable slots as error items.
//! * **INDX residue** — entries in the slack region of `$INDEX_ROOT` /
//!   `$INDEX_ALLOCATION` nodes, and live-region entries dangling to
//!   inactive/reused records, are emitted as `Deleted{Unknown}` artefacts.
//! * **ADS** — every named `$DATA` stream is its own entry
//!   (`file:stream`); `$UsnJrnl`'s `$J` is exposed the same way.
//! * **$ATTRIBUTE_LIST** — multi-record files merge extension-record
//!   attributes, so split runlists and far-flung extents are followed.
//! * **Compression/sparse** — flagged in meta; LZNT1 decompression is
//!   implemented for `read_file` on live compressed streams (one
//!   compression unit at a time, bounded memory); sparse holes read as
//!   zeros at their true logical offsets.
//! * **Provenance** — `disk_offset` is the MFT record's absolute offset;
//!   `meta["mft_record"]`, `attr_offsets`, and `allocated_ranges` (absolute
//!   byte extents, resident content included) pin every byte.
//! * **Journal forensics** — `$UsnJrnl:$J` USN change records (filename,
//!   file/parent references, reason flags, timestamp) and `$LogFile`
//!   LFS pages (RSTR restart areas, RCRD log-record headers, CHKD
//!   checkpoints, BAAD torn pages) stream via `NtfsFs::journal_events()`
//!   and `FileSystem::journal_entries()` under `/$USN_JRNL/` and
//!   `/$LOGFILE/`. Parsed, never replayed.
//! * Lenient by default; `MountOptions::strict` makes the first error
//!   terminal. No panics on untrusted input.

#![forbid(unsafe_code)]

mod attr;
mod boot;
mod fs;
mod indx;
mod journal;
pub mod rebuild;
mod record;
pub mod remnants;
mod walk;

pub use fs::{NtfsFs, NtfsParser};
pub use journal::{
    JournalEvent, JournalOp, LogInterpret, LogOp, LogRecord, RestartArea, UsnRecord,
};
pub use remnants::{
    live_mft_extents, probe_geometry, scan_remnants, scan_to_jsonl, to_jsonl, Remnant, RemnantData,
    RemnantIndex, RemnantIndexEntry, RemnantName, RemnantRecord, RemnantScanOpts,
    RemnantStats,
};
pub use rebuild::{
    match_live, parse_remnant_line, LiveFile, OldMember, RemnantNode, RemnantTree, RestoredEntry,
    RestorePlan, ROOT_REC,
};

#[cfg(test)]
mod tests;
