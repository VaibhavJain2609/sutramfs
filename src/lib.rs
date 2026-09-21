//! # sutram-report
//!
//! Forensic report generator for the SUTRAM-FS parser family. Feed it any
//! mounted [`sutram_fs::FileSystem`] and get a [`Report`] covering:
//!
//! * **Volume summary** — `FsInfo` + image size.
//! * **Entry census** — counts by kind / live-deleted status / recovery
//!   state, plus byte totals and walk-error count.
//! * **Deleted-recovery table** — every deleted entry with intact /
//!   partial / lost classification and recoverable byte totals.
//! * **Magic-mismatch table** — extension↔content verdicts, worst
//!   severity first, with the verdict's reasons.
//! * **Anomalies** — orphans (`/$ORPHANED/*`, orphan meta flags),
//!   suspicious metadata (`beyond_eod`, `lfn_checksum_ok=false`,
//!   carved/reused inodes, …), and walk errors.
//! * **Per-file detail** — path, size, SHA-256 of recoverable content
//!   (inline hasher — `sutram-analyze` doesn't exist yet), MAC times, and
//!   full `disk_offset`/`allocated_ranges` provenance.
//! * **Examiner notes** — free text carried verbatim.
//!
//! Outputs: [`Report::to_json`] (hand-rolled, no serde),
//! [`Report::to_markdown`], [`Report::to_html`] (self-contained, no JS,
//! escaped).
//!
//! Inherits the forensic contract from the parser layer: read-only,
//! lenient (walk errors become anomaly records, not panics), and every
//! number cites the bytes that produced it via `disk_offset`/extents.

#![forbid(unsafe_code)]

mod html;
pub(crate) mod json;
mod json_render;
mod markdown;
pub mod report;
mod sha256;

pub use report::{
    generate, Anomaly, Census, DeletedRow, DeletedSection, FileDetail, MagicMismatch, Report,
    ReportOptions, VolumeSummary,
};
