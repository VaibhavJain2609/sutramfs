//! Image diffing: compare two mounted filesystems entry-by-entry, keyed by
//! path.
//!
//! ```text
//! diff(fs_a, fs_b, &opts) -> ImageDiff {
//!     added,            // paths only in B
//!     removed,          // paths only in A
//!     modified,         // same path+status, differing size/ts/content
//!     deleted_changes,  // same path, status/recovery transition
//! }
//! ```
//!
//! `modified` compares size → MAC timestamps → content hash (SHA-256 over
//! recoverable bytes, capped by [`DiffOptions::hash_max_bytes`]). A
//! live→deleted flip, or an intact→partially_overwritten drift, lands in
//! `deleted_changes` rather than `modified` — it is the forensically
//! louder event.

use std::collections::HashMap;
use std::fmt::Write as _;

use sutram_analyze::Sha256;
use sutram_fs::{EntryKind, FileSystem, FsEntry, FsEntryStatus};

use crate::json::Json;
use crate::report::{kind_label, recovery_label};

/// Knobs for [`diff`].
#[derive(Debug, Clone)]
pub struct DiffOptions {
    /// Hash readable file content when sizes+timestamps agree, to catch
    /// same-size overwrites. Default `true`.
    pub hash_content: bool,
    /// Per-file hashing cap. Default 64 MiB.
    pub hash_max_bytes: u64,
    /// Per-side entry cap — defence against runaway walks. Exceeding it is
    /// counted in `errors` and the diff is marked `truncated`. Default 1M.
    pub max_entries: usize,
}

impl Default for DiffOptions {
    fn default() -> Self {
        DiffOptions {
            hash_content: true,
            hash_max_bytes: 64 * 1024 * 1024,
            max_entries: 1_000_000,
        }
    }
}

/// One same-path entry whose bytes/metadata changed.
#[derive(Debug, Clone)]
pub struct ModifiedEntry {
    /// The path.
    pub path: String,
    /// Human-readable change list, e.g. `"size: 12 -> 14"`,
    /// `"content hash differs (same size, same mtime)"`.
    pub changes: Vec<String>,
}

/// A recovery-state transition at one path.
#[derive(Debug, Clone)]
pub struct DeletedChange {
    /// The path.
    pub path: String,
    /// Label in A, e.g. `"live"`, `"deleted(intact)"`.
    pub from: String,
    /// Label in B.
    pub to: String,
}

/// The whole diff.
#[derive(Debug, Clone, Default)]
pub struct ImageDiff {
    /// Paths present only in B (sorted).
    pub added: Vec<String>,
    /// Paths present only in A (sorted).
    pub removed: Vec<String>,
    /// Same-path changes (sorted by path).
    pub modified: Vec<ModifiedEntry>,
    /// Status/recovery transitions (sorted by path).
    pub deleted_changes: Vec<DeletedChange>,
    /// Walk errors seen on side A.
    pub errors_a: usize,
    /// Walk errors seen on side B.
    pub errors_b: usize,
    /// Either side hit `max_entries`.
    pub truncated: bool,
}

impl ImageDiff {
    /// `true` when nothing differed.
    pub fn is_clean(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.modified.is_empty()
            && self.deleted_changes.is_empty()
    }

    /// Compact JSON, same stable key order as reports.
    pub fn to_json(&self) -> String {
        self.as_json().to_string()
    }

    /// Pretty JSON.
    pub fn to_json_pretty(&self) -> String {
        self.as_json().to_string_pretty()
    }

    fn as_json(&self) -> Json {
        Json::Obj(vec![
            (
                "added".into(),
                Json::Arr(self.added.iter().map(|p| Json::s(p.clone())).collect()),
            ),
            (
                "removed".into(),
                Json::Arr(self.removed.iter().map(|p| Json::s(p.clone())).collect()),
            ),
            (
                "modified".into(),
                Json::Arr(
                    self.modified
                        .iter()
                        .map(|m| {
                            Json::Obj(vec![
                                ("path".into(), Json::s(m.path.clone())),
                                (
                                    "changes".into(),
                                    Json::Arr(
                                        m.changes.iter().map(|c| Json::s(c.clone())).collect(),
                                    ),
                                ),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "deleted_changes".into(),
                Json::Arr(
                    self.deleted_changes
                        .iter()
                        .map(|d| {
                            Json::Obj(vec![
                                ("path".into(), Json::s(d.path.clone())),
                                ("from".into(), Json::s(d.from.clone())),
                                ("to".into(), Json::s(d.to.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("errors_a".into(), Json::Num(self.errors_a as u64)),
            ("errors_b".into(), Json::Num(self.errors_b as u64)),
            ("truncated".into(), Json::Bool(self.truncated)),
        ])
    }

    /// Plain-text rendering — one section per bucket.
    pub fn to_text(&self) -> String {
        let mut o = String::new();
        let _ = writeln!(o, "image diff ({})", if self.is_clean() { "clean" } else { "changes found" });
        if self.truncated {
            let _ = writeln!(o, "TRUNCATED: max_entries cap hit — diff is partial");
        }
        for (name, items) in [
            ("added", &self.added),
            ("removed", &self.removed),
        ] {
            let _ = writeln!(o, "{name} ({}):", items.len());
            for p in items {
                let _ = writeln!(o, "  {p}");
            }
        }
        let _ = writeln!(o, "modified ({}):", self.modified.len());
        for m in &self.modified {
            let _ = writeln!(o, "  {}", m.path);
            for c in &m.changes {
                let _ = writeln!(o, "    - {c}");
            }
        }
        let _ = writeln!(o, "deleted_changes ({}):", self.deleted_changes.len());
        for d in &self.deleted_changes {
            let _ = writeln!(o, "  {}: {} -> {}", d.path, d.from, d.to);
        }
        if self.errors_a + self.errors_b > 0 {
            let _ = writeln!(
                o,
                "walk errors: A={} B={}",
                self.errors_a, self.errors_b
            );
        }
        o
    }
}

/// Status + recovery as one label: `"live"`, `"deleted(intact)"`, …
fn state_label(s: FsEntryStatus) -> String {
    match s {
        FsEntryStatus::Live => "live".into(),
        FsEntryStatus::Deleted { .. } => format!("deleted({})", recovery_label(s)),
    }
}

/// Walk `fs` into a path→entry map. Returns `(map, errors, truncated)`.
fn collect(
    fs: &dyn FileSystem,
    max: usize,
) -> (HashMap<String, FsEntry>, usize, bool) {
    let mut map = HashMap::new();
    let mut errors = 0usize;
    let mut truncated = false;
    for item in fs.walk() {
        match item {
            Ok(e) => {
                if map.len() >= max {
                    truncated = true;
                    break;
                }
                // Duplicate paths (it happens on hostile images): keep the
                // first, which is the live-tree ordering's winner.
                map.entry(e.path.clone()).or_insert(e);
            }
            Err(_) => errors += 1,
        }
    }
    (map, errors, truncated)
}

/// SHA-256 of an entry's recoverable content, capped at `max` bytes.
/// `None` when unreadable — a `None`/`None` pair is *not* evidence of
/// equality, so callers treat unhashable as "unknown" and skip.
fn content_hash(fs: &dyn FileSystem, e: &FsEntry, max: u64) -> Option<String> {
    if e.kind != EntryKind::File {
        return None;
    }
    let mut r = fs.read_file(e).ok()?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 8192];
    let mut got = 0u64;
    loop {
        let want = (max - got).min(buf.len() as u64) as usize;
        if want == 0 {
            break;
        }
        match std::io::Read::read(&mut r, &mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => {
                h.update(&buf[..n]);
                got += n as u64;
            }
            Err(_) => return None,
        }
    }
    Some(h.finalize_hex())
}

/// Field-by-field comparison of two same-status entries → change strings.
fn compare(a: &FsEntry, fa: &dyn FileSystem, b: &FsEntry, fb: &dyn FileSystem, o: &DiffOptions) -> Vec<String> {
    let mut changes = Vec::new();
    if a.kind != b.kind {
        changes.push(format!(
            "kind: {} -> {}",
            kind_label(a.kind),
            kind_label(b.kind)
        ));
    }
    if a.size != b.size {
        changes.push(format!("size: {} -> {}", a.size, b.size));
    }
    let ts = [
        ("modified", &a.timestamps.modified, &b.timestamps.modified),
        ("accessed", &a.timestamps.accessed, &b.timestamps.accessed),
        ("created", &a.timestamps.created, &b.timestamps.created),
    ];
    for (name, ta, tb) in ts {
        let va = ta.as_ref().and_then(|t| t.value);
        let vb = tb.as_ref().and_then(|t| t.value);
        if va != vb {
            changes.push(format!("{name}: {:?} -> {:?}", va, vb));
        }
    }
    // Content hash: only when both are files and both readable. Hash even
    // when size/ts agree — same-size overwrite is the case it catches.
    if o.hash_content && a.kind == EntryKind::File && b.kind == EntryKind::File {
        match (content_hash(fa, a, o.hash_max_bytes), content_hash(fb, b, o.hash_max_bytes)) {
            (Some(ha), Some(hb)) if ha != hb => changes.push(format!(
                "content hash: {ha} -> {hb}"
            )),
            _ => {}
        }
    }
    changes
}

/// Diff two mounted filesystems, keyed by entry path.
pub fn diff(a: &dyn FileSystem, b: &dyn FileSystem, opts: &DiffOptions) -> ImageDiff {
    let (map_a, errors_a, trunc_a) = collect(a, opts.max_entries);
    let (map_b, errors_b, trunc_b) = collect(b, opts.max_entries);

    let mut out = ImageDiff {
        errors_a,
        errors_b,
        truncated: trunc_a || trunc_b,
        ..Default::default()
    };

    for path in map_a.keys() {
        if !map_b.contains_key(path) {
            out.removed.push(path.clone());
        }
    }
    for (path, eb) in &map_b {
        let ea = match map_a.get(path) {
            Some(e) => e,
            None => {
                out.added.push(path.clone());
                continue;
            }
        };
        let sa = state_label(ea.status);
        let sb = state_label(eb.status);
        if sa != sb {
            // Recovery-state transition — forensically louder than a byte
            // change, so it gets its own bucket.
            out.deleted_changes.push(DeletedChange {
                path: path.clone(),
                from: sa,
                to: sb,
            });
            continue;
        }
        let changes = compare(ea, a, eb, b, opts);
        if !changes.is_empty() {
            out.modified.push(ModifiedEntry {
                path: path.clone(),
                changes,
            });
        }
    }

    out.added.sort();
    out.removed.sort();
    out.modified.sort_by(|x, y| x.path.cmp(&y.path));
    out.deleted_changes.sort_by(|x, y| x.path.cmp(&y.path));
    out
}
