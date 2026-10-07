//! Masquerade analysis — turn a [`MagicVerdict`] into an actionable
//! [`SuspicionReport`].
//!
//! `sutram-magic` decides *whether* a file's content disagrees with its
//! extension; this layer decides *what to do about it*. The headline rule:
//! **code-carrying content under a non-executable extension** (a `.docx`
//! that is really a PE, a `.jpg` that is a shell script) auto-escalates to
//! `Severity::High` and recommends a hash reputation check plus sandbox
//! detonation.

use sutram_fs::FsEntry;
use sutram_magic::{MagicVerdict, Severity};

/// Suspicious-file assessment for one entry.
#[derive(Debug, Clone)]
pub struct SuspicionReport {
    /// Path of the assessed entry (echoed for reports).
    pub entry_path: String,
    /// `true` when extension and content disagree (from the magic verdict).
    pub magic_mismatch: bool,
    /// Worst severity after escalation rules.
    pub severity: Severity,
    /// Human-readable, court-explainable reasons.
    pub reasons: Vec<String>,
    /// Recommended next steps for the examiner.
    pub recommended_actions: Vec<String>,
}

/// Build a [`SuspicionReport`] from an entry and its magic verdict.
///
/// Escalation rules, in order:
///
/// 1. `mismatch && detected.is_code()` → **High**: classic masquerade.
///    Recommends reputation check, sandbox detonation, preserve-don't-run.
/// 2. `mismatch && !is_code()` → **Suspicious**: e.g. `.png` that is a ZIP.
///    Recommends manual/container inspection.
/// 3. Multiple signatures / polyglot note (severity ≥ Suspicious without
///    a mismatch) → **Suspicious**: recommends appended-payload carving.
/// 4. Deleted entries get a recovery caveat appended to the reasons.
pub fn analyze_masquerade(entry: &FsEntry, magic: &MagicVerdict) -> SuspicionReport {
    let mut severity = magic.severity;
    let mut reasons: Vec<String> = magic.reasons.clone();
    let mut actions: Vec<String> = Vec::new();
    let path = &entry.path;

    let detected_code = magic.detected.map(|t| t.is_code()).unwrap_or(false);
    let declared_code = magic.declared.map(|t| t.is_code()).unwrap_or(false);

    if magic.mismatch && detected_code && !declared_code {
        // Content is executable, the name claims otherwise.
        severity = Severity::High;
        let detected = magic.detected.map(|t| t.name()).unwrap_or("code");
        reasons.push(format!(
            "executable content ({detected}) masquerading under a non-executable \
             extension — classic evasion pattern"
        ));
        actions.push(
            "submit SHA-256 to a reputation service (hash-only — never upload \
             evidence contents by default)"
                .to_string(),
        );
        actions.push(
            "detonate in an isolated sandbox (Cuckoo/CAPE or equivalent) under \
             feature `sandbox`; never execute on the analysis host"
                .to_string(),
        );
        actions.push(
            "preserve original bytes with provenance (allocated_ranges); hash \
             the file before any further handling"
                .to_string(),
        );
        actions.push("scan with YARA ruleset and triage strings".to_string());
    } else if magic.mismatch {
        if severity < Severity::Suspicious {
            severity = Severity::Suspicious;
        }
        actions.push(
            "manually inspect: extension and content disagree (possible \
             accidental rename, corruption, or deliberate disguise)"
                .to_string(),
        );
        if let Some(d) = magic.detected {
            if matches!(d.category(), sutram_magic::Category::Archive) {
                actions.push(
                    "enumerate container members — disguised archives may \
                     conceal embedded payloads"
                        .to_string(),
                );
            }
        }
    } else if severity >= Severity::Suspicious {
        // No mismatch but sutram-magic already raised the floor — the
        // only current cause is a polyglot signature set.
        actions.push(
            "possible polyglot: carve/verify each matched signature region; \
             appended archives or merged formats may hide a payload"
                .to_string(),
        );
    } else if detected_code && magic.declared.is_none() {
        // Code with no declared extension — not a masquerade, but worth a
        // line on the timeline when triaging a whole filesystem.
        reasons.push(
            "code-carrying content with no declared extension (no masquerade, \
             but executable material present)"
                .to_string(),
        );
    }

    if let sutram_fs::FsEntryStatus::Deleted { recovery } = entry.status {
        reasons.push(format!(
            "deleted artefact — recoverability: {recovery}; partial data may \
             explain an apparent mismatch"
        ));
    }

    SuspicionReport {
        entry_path: path.clone(),
        magic_mismatch: magic.mismatch,
        severity,
        reasons,
        recommended_actions: actions,
    }
}
