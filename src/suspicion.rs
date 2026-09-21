//! Aggregate suspicion scoring — the triage layer.
//!
//! [`score_entry`] folds every cheap signal the `FsEntry` already
//! carries (plus optional [`EntropyVerdict`] and reputation input) into
//! one 0–100 score with **court-explainable reasons** — each reason
//! names the signal that fired and the points it contributed.
//!
//! Signal schedule (sum capped at 100):
//!
//! | signal                                              | points |
//! |-----------------------------------------------------|--------|
//! | magic mismatch, [`Severity::High`] (code masquerade) |   +50  |
//! | magic mismatch, [`Severity::Suspicious`]             |   +25  |
//! | entropy > 7.5 bits/byte (packed/encrypted)           |   +20  |
//! | double extension on an executable (`invoice.pdf.exe`)|   +20  |
//! | executable content/name in a user-writable path      |   +15  |
//! | deleted-but-recoverable with a suspicious name       |   +15  |
//! | `hidden`/`system` meta flag                          |   +10  |
//! | orphan artefact (`$ORPHANED/` or `meta["orphan"]`)   |   +10  |
//! | reputation [`RepVerdict::Malicious`]                 |   +60  |
//! | reputation [`RepVerdict::Suspicious`]                |   +30  |
//!
//! This is a **triage score**, not a verdict — an examiner reads
//! `reasons` to see exactly why the number is what it is.
//!
//! [`assess`] walks a whole filesystem, computing entropy inline, and
//! returns every scored entry sorted by score descending.

use sutram_fs::{
    EntryKind, FileSystem, FsEntry, FsEntryStatus, MagicVerdict, RecoveryState, Severity,
};
use sutram_reputation::RepVerdict;

use crate::entropy::{entry_entropy, EntropyVerdict, HIGH_ENTROPY};

/// Optional side-signals for [`score_entry`].
#[derive(Debug, Default)]
pub struct Signals<'a> {
    /// Content entropy measurement for this entry (see
    /// [`entry_entropy`]). `None` when unmeasured — the entropy rule
    /// simply doesn't fire.
    pub entropy: Option<&'a EntropyVerdict>,
    /// Hash-reputation verdict from `sutram-reputation`, when the
    /// file's hash was looked up.
    pub reputation: Option<RepVerdict>,
}

/// The aggregate risk assessment for one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suspicion {
    /// 0–100. 0 = no signal fired.
    pub score: u32,
    /// Human-readable explanations, each citing the signal and the
    /// points it contributed — suitable for a report/court exhibit.
    pub reasons: Vec<String>,
}

/// Extensions treated as executable content for the filename rules.
const EXEC_EXTS: &[&str] = &[
    "exe", "dll", "scr", "com", "pif", "cpl", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf",
    "wsh", "msi", "msp", "gadget", "elf", "sh", "run",
];

/// Extensions that look like benign documents/media — the decoy half of
/// a double-extension name (`report.pdf.exe`).
const DECOY_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "odt", "jpg", "jpeg", "png",
    "gif", "bmp", "mp3", "mp4", "avi", "mov", "zip", "rar", "7z", "csv", "xml", "html", "htm",
];

/// Path fragments (lowercase, `/`-separated) considered user-writable —
/// locations malware drops and executes from.
const USER_WRITABLE: &[&str] = &[
    "/tmp/", "/var/tmp/", "/dev/shm/", "/downloads/", "/download/", "/desktop/", "/appdata/",
    "/temp/", "/tmp", "$recycle", "/users/public/", "/programdata/", "/perflogs/",
];

/// Lowercase final extension of `name` (without dot), `None` for
/// dotfiles and extensionless names.
pub fn extension(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let (stem, ext) = base.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// `true` when the name ends in a known-executable extension.
pub fn is_exec_name(name: &str) -> bool {
    extension(name).is_some_and(|e| EXEC_EXTS.contains(&e.as_str()))
}

/// `true` when `name` carries a decoy extension followed by an
/// executable one (`invoice.pdf.exe`, `photo.jpg.scr`).
pub fn has_double_extension(name: &str) -> bool {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let mut parts: Vec<&str> = base.split('.').collect();
    // need stem + decoy + exec
    if parts.len() < 3 {
        return false;
    }
    let last = parts.pop().map(|e| e.to_ascii_lowercase());
    let prev = parts.pop().map(|e| e.to_ascii_lowercase());
    match (last, prev) {
        (Some(l), Some(p)) => {
            EXEC_EXTS.contains(&l.as_str()) && DECOY_EXTS.contains(&p.as_str())
        }
        _ => false,
    }
}

/// `true` when `path` sits in a classically user-writable location.
pub fn in_user_writable_path(path: &str) -> Option<&'static str> {
    let p = path.to_ascii_lowercase();
    USER_WRITABLE
        .iter()
        .find(|tok| p.contains(**tok))
        .copied()
}

/// Whether the entry's content is executable — magic `detected` type
/// wins when present, else the extension says so.
fn looks_executable(entry: &FsEntry) -> bool {
    if let Some(m) = &entry.magic {
        if m.detected.is_some_and(|t| t.is_code()) {
            return true;
        }
    }
    is_exec_name(&entry.name)
}

fn magic_points(m: &MagicVerdict) -> (u32, &'static str) {
    match m.severity {
        Severity::High => (50, "High"),
        Severity::Suspicious => (25, "Suspicious"),
        Severity::Info => (0, "Info"),
    }
}

/// Score one entry. See the module table for the point schedule; the
/// result's `reasons` cite exactly which signals fired.
pub fn score_entry(entry: &FsEntry, signals: &Signals) -> Suspicion {
    let mut score: u32 = 0;
    let mut reasons = Vec::new();
    let mut add = |points: u32, reason: String| {
        if points > 0 {
            score = score.saturating_add(points);
            reasons.push(format!("{reason} (+{points})"));
        }
    };

    // -- magic mismatch severity ---------------------------------------
    if let Some(m) = &entry.magic {
        let (pts, sev) = magic_points(m);
        if pts > 0 {
            let detail = m
                .reasons
                .first()
                .cloned()
                .unwrap_or_else(|| "extension/content mismatch".into());
            add(pts, format!("magic severity {sev}: {detail}"));
        }
    }

    // -- high entropy ---------------------------------------------------
    if let Some(ev) = signals.entropy {
        if ev.sampled >= 64 && ev.entropy > HIGH_ENTROPY {
            add(
                20,
                format!(
                    "entropy {:.2} bits/byte over {} sampled bytes — {}",
                    ev.entropy,
                    ev.sampled,
                    ev.suspicion.unwrap_or("packed/encrypted-looking content")
                ),
            );
        }
    }

    // -- filename evasion ------------------------------------------------
    let double_ext = has_double_extension(&entry.name);
    if double_ext {
        add(
            20,
            format!(
                "double extension '{}' — decoy document/media extension in front of an executable",
                entry.name
            ),
        );
    }

    // -- executable in a user-writable path ------------------------------
    if looks_executable(entry) {
        if let Some(tok) = in_user_writable_path(&entry.path) {
            add(
                15,
                format!(
                    "executable content/name in user-writable path '{tok}' — \
                     common malware drop-and-run location"
                ),
            );
        }
    }

    // -- deleted but recoverable, suspicious name -------------------------
    if let FsEntryStatus::Deleted { recovery } = entry.status {
        let recoverable = matches!(
            recovery,
            RecoveryState::Intact | RecoveryState::PartiallyOverwritten { .. }
        );
        if recoverable && (double_ext || is_exec_name(&entry.name)) {
            add(
                15,
                format!(
                    "deleted-but-recoverable ({recovery}) executable-style name — \
                     possible drop-then-delete behaviour"
                ),
            );
        }
    }

    // -- hidden / orphan meta ---------------------------------------------
    if entry.meta.get("hidden").is_some_and(|v| v == "true")
        || entry.meta.get("system").is_some_and(|v| v == "true")
    {
        add(10, "hidden/system attribute flag set".to_string());
    }
    if entry.path.starts_with("/$ORPHANED/")
        || entry.path.starts_with("/$LOST/")
        || entry.meta.get("orphan").is_some_and(|v| v == "true")
    {
        add(
            10,
            "orphan artefact — unreferenced by any live directory".to_string(),
        );
    }

    // -- reputation -------------------------------------------------------
    match signals.reputation {
        Some(RepVerdict::Malicious) => add(
            60,
            "reputation verdict: malicious (engine detections above threshold)".to_string(),
        ),
        Some(RepVerdict::Suspicious) => add(
            30,
            "reputation verdict: suspicious (low-confidence engine hits)".to_string(),
        ),
        _ => {}
    }

    Suspicion {
        score: score.min(100),
        reasons,
    }
}

/// One scored entry inside an [`Assessment`].
#[derive(Debug)]
pub struct EntrySuspicion {
    /// The entry that was scored.
    pub entry: FsEntry,
    /// Its aggregate score + reasons.
    pub suspicion: Suspicion,
}

/// Result of [`assess`] over a whole filesystem.
#[derive(Debug, Default)]
pub struct Assessment {
    /// Scored file entries, highest score first. Only entries with
    /// `score > 0` are listed — a clean file is not a finding.
    pub scored: Vec<EntrySuspicion>,
    /// Files examined (all `EntryKind::File` entries walked).
    pub files_examined: usize,
    /// Walk/read errors encountered (lenient — never fatal).
    pub errors: usize,
}

/// Walk `fs`, compute entropy for each file (bounded by
/// [`crate::entropy::SAMPLE_CAP`]), and score every entry. Reputation
/// verdicts are not fetched here — use [`assess_with`] to inject them.
pub fn assess(fs: &dyn FileSystem) -> Assessment {
    assess_with(fs, &|_| None)
}

/// Like [`assess`], but `rep` may return a [`RepVerdict`] per entry
/// (e.g. a `sutram_reputation::ReputationService` lookup keyed on the
/// entry's hash — the caller decides how to obtain it).
pub fn assess_with(fs: &dyn FileSystem, rep: &dyn Fn(&FsEntry) -> Option<RepVerdict>) -> Assessment {
    let mut out = Assessment::default();
    for item in fs.walk() {
        let entry = match item {
            Ok(e) => e,
            Err(_) => {
                out.errors += 1;
                continue;
            }
        };
        if entry.kind != EntryKind::File {
            continue;
        }
        out.files_examined += 1;
        // Entropy is the only signal needing reads; tolerate failure.
        let ev = entry_entropy(fs, &entry).ok();
        let signals = Signals {
            entropy: ev.as_ref(),
            reputation: rep(&entry),
        };
        let suspicion = score_entry(&entry, &signals);
        if suspicion.score > 0 {
            out.scored.push(EntrySuspicion { entry, suspicion });
        }
    }
    out.scored
        .sort_by_key(|e| std::cmp::Reverse(e.suspicion.score));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Read;
    use std::sync::Arc;

    use sutram_fs::{FsError, FsInfo, Result, Timestamps};
    use sutram_io::ByteSource;
    use sutram_magic::check_entry;

    struct MemFs {
        entries: Vec<FsEntry>,
        data: HashMap<u64, Vec<u8>>,
        src: Arc<Vec<u8>>,
    }

    impl FileSystem for MemFs {
        fn info(&self) -> FsInfo {
            FsInfo {
                fs_type: "mem".into(),
                ..Default::default()
            }
        }
        fn source(&self) -> Arc<dyn ByteSource> {
            self.src.clone()
        }
        fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
            Box::new(self.entries.clone().into_iter().map(Ok))
        }
        fn read_file(&self, entry: &FsEntry) -> Result<Box<dyn Read + Send>> {
            match self.data.get(&entry.entry_id) {
                Some(d) => Ok(Box::new(std::io::Cursor::new(d.clone()))),
                None => Err(FsError::NotFound {
                    path: entry.path.clone(),
                }),
            }
        }
    }

    fn entry(id: u64, path: &str) -> FsEntry {
        FsEntry {
            path: path.into(),
            name: path.rsplit('/').next().unwrap_or(path).into(),
            entry_id: id,
            kind: EntryKind::File,
            size: 100,
            disk_offset: 0,
            allocated_ranges: vec![],
            timestamps: Timestamps::default(),
            status: FsEntryStatus::Live,
            meta: HashMap::new(),
            magic: None,
        }
    }

    fn no_signals() -> Signals<'static> {
        Signals::default()
    }

    #[test]
    fn clean_file_scores_zero() {
        let e = entry(1, "/docs/readme.txt");
        let s = score_entry(&e, &no_signals());
        assert_eq!(s.score, 0);
        assert!(s.reasons.is_empty());
    }

    #[test]
    fn magic_mismatch_scores() {
        // EVIL.DOC containing MZ → Severity::High
        let mut mz = b"MZ\x90\0\x03\0\0\0".to_vec();
        mz.resize(60, 0);
        let v = check_entry("EVIL.DOC", &mz);
        assert_eq!(v.severity, Severity::High);
        let mut e = entry(1, "/docs/EVIL.DOC");
        e.magic = Some(v);
        let s = score_entry(&e, &no_signals());
        assert!(s.score >= 50, "{}", s.score);
        assert!(s.reasons.iter().any(|r| r.contains("magic severity High")));
    }

    #[test]
    fn entropy_signal_scores() {
        let e = entry(1, "/blob.bin");
        let ev = EntropyVerdict {
            entropy: 7.9,
            chi_square: 260.0,
            sampled: 4096,
            total: 4096,
            truncated: false,
            suspicion: Some("high entropy"),
        };
        let s = score_entry(
            &e,
            &Signals {
                entropy: Some(&ev),
                reputation: None,
            },
        );
        assert_eq!(s.score, 20);
        assert!(s.reasons[0].contains("entropy 7.90"));
    }

    #[test]
    fn double_extension_scores() {
        let e = entry(1, "/home/u/invoice.pdf.exe");
        let s = score_entry(&e, &no_signals());
        assert!(s.score >= 20);
        assert!(s.reasons.iter().any(|r| r.contains("double extension")));
        assert!(!has_double_extension("readme.txt"));
        assert!(!has_double_extension("archive.tar.gz")); // gz not exec
        assert!(has_double_extension("photo.jpg.scr"));
    }

    #[test]
    fn exec_in_user_writable_scores() {
        let e = entry(1, "/tmp/runme.sh");
        let s = score_entry(&e, &no_signals());
        assert!(s.reasons.iter().any(|r| r.contains("user-writable")));
        // A .txt in /tmp: no exec signal → no points.
        let e2 = entry(2, "/tmp/notes.txt");
        let s2 = score_entry(&e2, &no_signals());
        assert_eq!(s2.score, 0);
        // An .exe in a normal path → location rule doesn't fire.
        let e3 = entry(3, "/Program Files/app/tool.exe");
        let s3 = score_entry(&e3, &no_signals());
        assert!(!s3.reasons.iter().any(|r| r.contains("user-writable")));
    }

    #[test]
    fn deleted_intact_suspicious_name_scores() {
        let mut e = entry(1, "/_evil.exe");
        e.status = FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact,
        };
        let s = score_entry(&e, &no_signals());
        assert!(s.reasons.iter().any(|r| r.contains("deleted-but-recoverable")));
        // unrecoverable → no signal (nothing recoverable to worry about)
        let mut e2 = entry(2, "/_evil.exe");
        e2.status = FsEntryStatus::Deleted {
            recovery: RecoveryState::Unrecoverable,
        };
        let s2 = score_entry(&e2, &no_signals());
        assert_eq!(s2.score, 0);
    }

    #[test]
    fn meta_flags_score() {
        let mut e = entry(1, "/.hidden.dat");
        e.meta.insert("hidden".into(), "true".into());
        let s = score_entry(&e, &no_signals());
        assert_eq!(s.score, 10);
        let mut o = entry(2, "/$ORPHANED/0x14");
        o.meta.insert("orphan".into(), "true".into());
        let s2 = score_entry(&o, &no_signals());
        assert_eq!(s2.score, 10);
    }

    #[test]
    fn reputation_scores() {
        let e = entry(1, "/f.bin");
        let s = score_entry(
            &e,
            &Signals {
                entropy: None,
                reputation: Some(RepVerdict::Malicious),
            },
        );
        assert_eq!(s.score, 60);
        let s = score_entry(
            &e,
            &Signals {
                entropy: None,
                reputation: Some(RepVerdict::Suspicious),
            },
        );
        assert_eq!(s.score, 30);
        for v in [RepVerdict::Clean, RepVerdict::Unknown, RepVerdict::NotQueried] {
            let s = score_entry(
                &e,
                &Signals {
                    entropy: None,
                    reputation: Some(v),
                },
            );
            assert_eq!(s.score, 0, "{v}");
        }
    }

    #[test]
    fn score_caps_at_100() {
        // High magic + malicious + double ext + user-writable + hidden:
        // way over 100 → clamped, all reasons preserved.
        let mut mz = b"MZ\x90\0\x03\0\0\0".to_vec();
        mz.resize(60, 0);
        let mut e = entry(1, "/tmp/invoice.pdf.exe");
        e.magic = Some(check_entry("invoice.pdf.exe", &mz));
        e.meta.insert("hidden".into(), "true".into());
        let ev = EntropyVerdict {
            entropy: 7.9,
            chi_square: 255.0,
            sampled: 4096,
            total: 4096,
            truncated: false,
            suspicion: Some("x"),
        };
        let s = score_entry(
            &e,
            &Signals {
                entropy: Some(&ev),
                reputation: Some(RepVerdict::Malicious),
            },
        );
        assert_eq!(s.score, 100);
        assert!(s.reasons.len() >= 5);
    }

    #[test]
    fn assess_walks_and_sorts() {
        let mut fs = MemFs {
            entries: vec![],
            data: HashMap::new(),
            src: Arc::new(Vec::new()),
        };
        let clean = entry(1, "/readme.txt");
        let mut evil = entry(2, "/tmp/evil.pdf.exe");
        evil.meta.insert("hidden".into(), "true".into());
        let dir = {
            let mut d = entry(3, "/sub");
            d.kind = EntryKind::Directory;
            d
        };
        fs.data.insert(1, b"plain text file, low entropy".to_vec());
        fs.data.insert(2, vec![0u8; 128]);
        fs.entries = vec![clean, evil, dir];
        let a = assess(&fs);
        assert_eq!(a.files_examined, 2);
        assert_eq!(a.errors, 0);
        assert_eq!(a.scored.len(), 1);
        assert_eq!(a.scored[0].entry.path, "/tmp/evil.pdf.exe");
        assert!(a.scored[0].suspicion.score >= 20);
    }
}
