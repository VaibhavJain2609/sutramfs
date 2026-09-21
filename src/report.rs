//! [`generate`]: walk a mounted filesystem once and produce a [`Report`]
//! covering volume summary, entry census, deleted-recovery table,
//! magic-mismatch table, anomalies, and per-file detail — renderable as
//! JSON, Markdown, or self-contained HTML.

use std::io::Read;
use std::time::SystemTime;

use sutram_fs::{
    EntryKind, FileSystem, FsEntry, FsEntryStatus, FsInfo, RecoveryState, Severity,
};

use crate::sha256::{to_hex, Sha256};

/// Meta keys whose *value* makes an entry anomalous: `(key, trigger,
/// human-readable reason)`.
const SUSPICIOUS_VALUES: &[(&str, &str, &str)] = &[
    (
        "beyond_eod",
        "true",
        "dirent lies beyond the directory end-of-directory marker",
    ),
    (
        "lfn_checksum_ok",
        "false",
        "LFN checksum mismatch — long name may be misattached to this entry",
    ),
    (
        "lfn_partial",
        "true",
        "LFN fragment incomplete — name only partially reconstructed",
    ),
];

/// Meta keys whose mere *presence* is anomalous: `(key, reason)`.
const SUSPICIOUS_KEYS: &[(&str, &str)] = &[
    (
        "carved_dirent",
        "dirent recovered by carving, not via the live directory tree",
    ),
    ("inode_cleared", "inode was cleared on disk"),
    (
        "inode_reused",
        "inode number reused — dirent may alias an older file",
    ),
    (
        "inode_unallocated",
        "dirent references an unallocated inode",
    ),
];

/// Knobs for [`generate`]. Defaults are examiner-friendly: hash every
/// readable file up to 64 MiB, full per-file detail, 1M-entry walk cap.
#[derive(Debug, Clone)]
pub struct ReportOptions {
    /// Report title (header of every output format).
    pub title: String,
    /// Free-text description of the source image (path, case ref, …).
    pub image_desc: String,
    /// Examiner notes, appended verbatim to the report.
    pub examiner_notes: String,
    /// SHA-256 readable file content (recoverable bytes for deleted).
    /// Default `true`.
    pub hash_files: bool,
    /// Per-file hashing cap — a file larger than this contributes only its
    /// first `hash_max_bytes` to the digest (`hashed_bytes` records how
    /// much was hashed). Default 64 MiB.
    pub hash_max_bytes: u64,
    /// Include the per-file detail section. Default `true`.
    pub include_file_details: bool,
    /// Walk cap — defence against runaway/cyclic walks on hostile images.
    /// Exceeding it is reported as an anomaly, not a panic. Default 1M.
    pub max_entries: usize,
}

impl Default for ReportOptions {
    fn default() -> Self {
        ReportOptions {
            title: "SUTRAM-FS forensic report".into(),
            image_desc: String::new(),
            examiner_notes: String::new(),
            hash_files: true,
            hash_max_bytes: 64 * 1024 * 1024,
            include_file_details: true,
            max_entries: 1_000_000,
        }
    }
}

/// Volume-level summary — `FsInfo` with its meta map sorted for stable
/// output.
#[derive(Debug, Clone, Default)]
pub struct VolumeSummary {
    /// e.g. `"FAT32"`, `"NTFS"`.
    pub fs_type: String,
    /// Volume label.
    pub label: Option<String>,
    /// Volume UUID/serial.
    pub uuid: Option<String>,
    /// Allocation unit in bytes.
    pub block_size: u64,
    /// Total allocation units.
    pub total_blocks: u64,
    /// Free allocation units, when computable.
    pub free_blocks: Option<u64>,
    /// Total metadata slots, when known.
    pub total_nodes: Option<u64>,
    /// Format extras, sorted by key.
    pub meta: Vec<(String, String)>,
    /// Total source image size in bytes.
    pub image_size: u64,
}

/// Aggregate counts over the whole walk.
#[derive(Debug, Clone, Default)]
pub struct Census {
    /// Every `Ok` entry seen.
    pub total_entries: usize,
    /// `status == Live`.
    pub live: usize,
    /// `status == Deleted{..}`.
    pub deleted: usize,
    /// By kind.
    pub files: usize,
    /// By kind.
    pub directories: usize,
    /// By kind.
    pub symlinks: usize,
    /// By kind.
    pub other: usize,
    /// Deleted + `Intact`.
    pub recovery_intact: usize,
    /// Deleted + `PartiallyOverwritten`.
    pub recovery_partial: usize,
    /// Deleted + `Unrecoverable`.
    pub recovery_unrecoverable: usize,
    /// Deleted + `Unknown`.
    pub recovery_unknown: usize,
    /// Sum of `size` over live entries.
    pub live_bytes: u64,
    /// Sum of `size` over deleted entries.
    pub deleted_bytes: u64,
    /// `Err` records emitted by the walk (lenient-mode corruption).
    pub walk_errors: usize,
}

/// One row of the deleted-recovery table.
#[derive(Debug, Clone)]
pub struct DeletedRow {
    /// Entry path.
    pub path: String,
    /// Logical size.
    pub size: u64,
    /// `"intact"` / `"partially_overwritten"` / `"unrecoverable"` / `"unknown"`.
    pub recovery: String,
    /// Bytes still recoverable.
    pub recovered_bytes: u64,
    /// Original file size (same as `size`).
    pub total_bytes: u64,
    /// Metadata-record offset — provenance.
    pub disk_offset: u64,
}

/// The deleted-recovery section: rows + intact/partial/lost counts + bytes.
#[derive(Debug, Clone, Default)]
pub struct DeletedSection {
    /// One row per deleted entry.
    pub rows: Vec<DeletedRow>,
    /// Fully recoverable.
    pub intact: usize,
    /// Some bytes survive.
    pub partial: usize,
    /// Metadata only (`Unrecoverable` + `Unknown`).
    pub lost: usize,
    /// Sum of `recovered_bytes`.
    pub recovered_bytes: u64,
    /// Sum of `total_bytes`.
    pub total_bytes: u64,
}

/// One extension↔content mismatch, severity-sorted in the report.
#[derive(Debug, Clone)]
pub struct MagicMismatch {
    /// Entry path.
    pub path: String,
    /// Type implied by the extension.
    pub declared: Option<String>,
    /// Type detected from content.
    pub detected: Option<String>,
    /// Worst severity (`Info` < `Suspicious` < `High`).
    pub severity: Severity,
    /// Verdict's explanations — court-ready text.
    pub reasons: Vec<String>,
    /// File size.
    pub size: u64,
    /// Whether the entry is deleted.
    pub deleted: bool,
}

/// An anomaly: orphan artefact, suspicious metadata, or a walk error.
#[derive(Debug, Clone)]
pub struct Anomaly {
    /// Affected path (`""` for walk-level errors).
    pub path: String,
    /// `"orphan"` | `"suspicious-meta"` | `"walk-error"`.
    pub kind: String,
    /// Human-readable detail.
    pub detail: String,
}

/// Per-file detail row: identity, hash, timestamps, provenance.
#[derive(Debug, Clone)]
pub struct FileDetail {
    /// Entry path.
    pub path: String,
    /// `"file"` | `"symlink"` | `"other"` — the section is files-first but
    /// non-directory kinds are included.
    pub kind: String,
    /// `"live"` | `"deleted"`.
    pub status: String,
    /// Recovery label for deleted entries (`""` when live).
    pub recovery: String,
    /// Logical size.
    pub size: u64,
    /// Lowercase hex SHA-256 of the bytes `read_file` yielded, when
    /// hashing was on and the read succeeded.
    pub sha256: Option<String>,
    /// Bytes actually fed to the digest (≤ `size`; < `size` when the
    /// `hash_max_bytes` cap or a partial-recovery boundary was hit).
    pub hashed_bytes: u64,
    /// Metadata-record offset.
    pub disk_offset: u64,
    /// Data extents — absolute `(offset, len)` provenance.
    pub allocated_ranges: Vec<(u64, u64)>,
    /// MAC times as unix nanos (`None` = not stored/unset).
    pub modified_ns: Option<i64>,
    /// MAC times.
    pub accessed_ns: Option<i64>,
    /// MAC times.
    pub created_ns: Option<i64>,
    /// Format extras, sorted by key.
    pub meta: Vec<(String, String)>,
}

/// The whole report — in-memory tree before rendering.
#[derive(Debug, Clone)]
pub struct Report {
    /// From [`ReportOptions::title`].
    pub title: String,
    /// `sutram-report` version string.
    pub tool: String,
    /// Generation time, unix seconds.
    pub generated_unix_secs: i64,
    /// From [`ReportOptions::image_desc`].
    pub image_desc: String,
    /// Volume summary.
    pub volume: VolumeSummary,
    /// Aggregate census.
    pub census: Census,
    /// Deleted-recovery table.
    pub deleted: DeletedSection,
    /// Magic mismatches, worst severity first.
    pub magic_mismatches: Vec<MagicMismatch>,
    /// Orphans, suspicious metadata, walk errors.
    pub anomalies: Vec<Anomaly>,
    /// Per-file detail (empty when `include_file_details` is off).
    pub files: Vec<FileDetail>,
    /// From [`ReportOptions::examiner_notes`].
    pub examiner_notes: String,
}

/// `EntryKind` → lowercase label.
pub fn kind_label(k: EntryKind) -> &'static str {
    match k {
        EntryKind::File => "file",
        EntryKind::Directory => "directory",
        EntryKind::Symlink => "symlink",
        EntryKind::Other => "other",
    }
}

/// `FsEntryStatus`/`RecoveryState` → labels used across all outputs.
pub fn status_label(s: FsEntryStatus) -> &'static str {
    match s {
        FsEntryStatus::Live => "live",
        FsEntryStatus::Deleted { .. } => "deleted",
    }
}

/// Recovery label (`""` for live entries).
pub fn recovery_label(s: FsEntryStatus) -> &'static str {
    match s {
        FsEntryStatus::Live => "",
        FsEntryStatus::Deleted { recovery } => match recovery {
            RecoveryState::Intact => "intact",
            RecoveryState::PartiallyOverwritten { .. } => "partially_overwritten",
            RecoveryState::Unrecoverable => "unrecoverable",
            RecoveryState::Unknown => "unknown",
        },
    }
}

/// Severity → lowercase label.
pub fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Suspicious => "suspicious",
        Severity::High => "high",
    }
}

fn ts_value(t: &Option<sutram_fs::FsTimestamp>) -> Option<i64> {
    t.as_ref().and_then(|t| t.value)
}

/// Hash the (recoverable) content of `e`, capped at `max_bytes`. Returns
/// `(digest, bytes_hashed)`; `None` when the read fails.
fn hash_entry(fs: &dyn FileSystem, e: &FsEntry, max_bytes: u64) -> (Option<String>, u64) {
    let mut reader = match fs.read_file(e) {
        Ok(r) => r,
        Err(_) => return (None, 0),
    };
    let mut h = Sha256::new();
    let mut buf = [0u8; 8192];
    let mut hashed = 0u64;
    loop {
        let want = (max_bytes - hashed).min(buf.len() as u64) as usize;
        if want == 0 {
            break;
        }
        match reader.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => {
                h.update(&buf[..n]);
                hashed += n as u64;
            }
            Err(_) => return (None, hashed),
        }
    }
    (Some(to_hex(&h.finish())), hashed)
}

/// Is `e` an orphan artefact? Convention: `/$ORPHANED/`/`/$LOST/` paths or
/// an explicit `orphan`/`orphan_list` meta flag.
fn orphan_detail(e: &FsEntry) -> Option<String> {
    if e.path.contains("/$ORPHANED/") || e.path.contains("/$LOST/") {
        return Some("unreferenced artefact placed under $ORPHANED/$LOST".into());
    }
    if e.meta.get("orphan").map(|v| v == "true").unwrap_or(false) {
        return Some("meta flag: orphan".into());
    }
    if let Some(v) = e.meta.get("orphan_list") {
        return Some(format!("on the filesystem orphan list ({v})"));
    }
    None
}

/// Suspicious-meta anomalies for `e` (key registry in CONVENTIONS.md).
fn suspicious_meta(e: &FsEntry) -> Vec<Anomaly> {
    let mut out = Vec::new();
    for &(key, trigger, reason) in SUSPICIOUS_VALUES {
        if e.meta.get(key).map(|v| v == trigger).unwrap_or(false) {
            out.push(Anomaly {
                path: e.path.clone(),
                kind: "suspicious-meta".into(),
                detail: format!("{key}={trigger}: {reason}"),
            });
        }
    }
    for &(key, reason) in SUSPICIOUS_KEYS {
        if let Some(v) = e.meta.get(key) {
            out.push(Anomaly {
                path: e.path.clone(),
                kind: "suspicious-meta".into(),
                detail: format!("{key}={v}: {reason}"),
            });
        }
    }
    out
}

/// Walk `fs` once and build the report. Never fails: corruption lands in
/// `anomalies`/`walk_errors` like the lenient contract dictates.
pub fn generate(fs: &dyn FileSystem, opts: &ReportOptions) -> Report {
    let info: FsInfo = fs.info();
    let mut census = Census::default();
    let mut deleted = DeletedSection::default();
    let mut mismatches = Vec::new();
    let mut anomalies = Vec::new();
    let mut files = Vec::new();

    let mut seen = 0usize;
    for item in fs.walk() {
        let e = match item {
            Ok(e) => e,
            Err(err) => {
                census.walk_errors += 1;
                anomalies.push(Anomaly {
                    path: String::new(),
                    kind: "walk-error".into(),
                    detail: err.to_string(),
                });
                continue;
            }
        };
        seen += 1;
        if seen > opts.max_entries {
            anomalies.push(Anomaly {
                path: String::new(),
                kind: "walk-error".into(),
                detail: format!(
                    "walk truncated at {} entries (max_entries cap)",
                    opts.max_entries
                ),
            });
            break;
        }

        census.total_entries += 1;
        match e.kind {
            EntryKind::File => census.files += 1,
            EntryKind::Directory => census.directories += 1,
            EntryKind::Symlink => census.symlinks += 1,
            EntryKind::Other => census.other += 1,
        }
        match e.status {
            FsEntryStatus::Live => {
                census.live += 1;
                census.live_bytes += e.size;
            }
            FsEntryStatus::Deleted { recovery } => {
                census.deleted += 1;
                census.deleted_bytes += e.size;
                let (recovered, total) = match recovery {
                    RecoveryState::Intact => {
                        census.recovery_intact += 1;
                        deleted.intact += 1;
                        (e.size, e.size)
                    }
                    RecoveryState::PartiallyOverwritten {
                        recovered_bytes,
                        total_bytes,
                    } => {
                        census.recovery_partial += 1;
                        deleted.partial += 1;
                        (recovered_bytes, total_bytes)
                    }
                    RecoveryState::Unrecoverable => {
                        census.recovery_unrecoverable += 1;
                        deleted.lost += 1;
                        (0, e.size)
                    }
                    RecoveryState::Unknown => {
                        census.recovery_unknown += 1;
                        deleted.lost += 1;
                        (0, e.size)
                    }
                };
                deleted.recovered_bytes += recovered;
                deleted.total_bytes += total;
                deleted.rows.push(DeletedRow {
                    path: e.path.clone(),
                    size: e.size,
                    recovery: recovery_label(e.status).to_string(),
                    recovered_bytes: recovered,
                    total_bytes: total,
                    disk_offset: e.disk_offset,
                });
            }
        }

        if let Some(v) = &e.magic {
            if v.mismatch {
                mismatches.push(MagicMismatch {
                    path: e.path.clone(),
                    declared: v.declared.map(|t| t.name().to_string()),
                    detected: v.detected.map(|t| t.name().to_string()),
                    severity: v.severity,
                    reasons: v.reasons.clone(),
                    size: e.size,
                    deleted: e.is_deleted(),
                });
            }
        }

        if let Some(detail) = orphan_detail(&e) {
            anomalies.push(Anomaly {
                path: e.path.clone(),
                kind: "orphan".into(),
                detail,
            });
        }
        anomalies.extend(suspicious_meta(&e));

        if opts.include_file_details && e.kind != EntryKind::Directory {
            let (sha256, hashed_bytes) = if opts.hash_files && e.kind == EntryKind::File {
                hash_entry(fs, &e, opts.hash_max_bytes)
            } else {
                (None, 0)
            };
            let mut meta: Vec<_> = e
                .meta
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            meta.sort();
            files.push(FileDetail {
                path: e.path.clone(),
                kind: kind_label(e.kind).to_string(),
                status: status_label(e.status).to_string(),
                recovery: recovery_label(e.status).to_string(),
                size: e.size,
                sha256,
                hashed_bytes,
                disk_offset: e.disk_offset,
                allocated_ranges: e.allocated_ranges.clone(),
                modified_ns: ts_value(&e.timestamps.modified),
                accessed_ns: ts_value(&e.timestamps.accessed),
                created_ns: ts_value(&e.timestamps.created),
                meta,
            });
        }
    }

    // Worst severity first; ties by path for stable output.
    mismatches.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.path.cmp(&b.path))
    });

    let mut meta: Vec<_> = info
        .meta
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    meta.sort();

    Report {
        title: opts.title.clone(),
        tool: concat!("sutram-report ", env!("CARGO_PKG_VERSION")).to_string(),
        generated_unix_secs: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        image_desc: opts.image_desc.clone(),
        volume: VolumeSummary {
            fs_type: info.fs_type,
            label: info.label,
            uuid: info.uuid,
            block_size: info.block_size,
            total_blocks: info.total_blocks,
            free_blocks: info.free_blocks,
            total_nodes: info.total_nodes,
            meta,
            image_size: fs.source().len(),
        },
        census,
        deleted,
        magic_mismatches: mismatches,
        anomalies,
        files,
        examiner_notes: opts.examiner_notes.clone(),
    }
}

impl Report {
    /// Compact JSON (hand-rolled — no serde dependency).
    pub fn to_json(&self) -> String {
        crate::json_render::report_json(self).to_string()
    }

    /// Pretty-printed JSON.
    pub fn to_json_pretty(&self) -> String {
        crate::json_render::report_json(self).to_string_pretty()
    }

    /// Markdown report — tables render in GitHub/examiner tooling.
    pub fn to_markdown(&self) -> String {
        crate::markdown::render(self)
    }

    /// Self-contained HTML — inline CSS, no JS, every field escaped.
    pub fn to_html(&self) -> String {
        crate::html::render(self)
    }
}
