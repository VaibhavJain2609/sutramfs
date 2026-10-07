//! The pipeline combiner: one call per file produces a
//! [`FileAssessment`] merging magic verdict, reputation, masquerade
//! analysis, and rule-scanner hits into a single severity plus
//! court-explainable reasons and recommended actions.
//!
//! ```text
//! for entry in fs.walk() {
//!     let entry = entry?;
//!     if entry.kind != EntryKind::File { continue; }
//!     let header = read_header(&fs, &entry, 4096);
//!     let sha256 = hash_file(&fs, &entry);
//!     let a = analyze_file(&entry, &header, &sha256, &cfg);
//!     if a.severity >= Severity::Suspicious { report(&a); }
//! }
//! ```

use sutram_fs::FsEntry;
use sutram_magic::{check_entry, MagicVerdict, Severity};

use crate::masquerade::{analyze_masquerade, SuspicionReport};
use crate::report::{RepVerdict, ReputationReport};
use crate::sandbox::{SandboxProvider, SandboxVerdict};
use crate::scanner::{RuleHit, RuleScanner};
use crate::vt::ReputationService;

/// Everything `analyze_file` may consult. All optional — with all `None`
/// it still produces magic + masquerade analysis.
#[derive(Default)]
pub struct AnalysisConfig<'a> {
    /// Reputation service for hash lookups. `None` → `reputation` field
    /// of the assessment is `None` (distinct from a `NotQueried` report:
    /// "not configured" vs "configured but didn't ask").
    pub reputation: Option<&'a ReputationService>,
    /// Rule scanner (YARA hook).
    pub scanner: Option<&'a dyn RuleScanner>,
    /// Sandbox provider. Consulted via `submit_hash` **only**, and only
    /// when this crate is built with feature `sandbox`. File detonation
    /// is never automatic.
    pub sandbox: Option<&'a dyn SandboxProvider>,
}

/// The merged per-file assessment — the forensic pipeline's unit of
/// record.
#[derive(Debug)]
pub struct FileAssessment {
    /// Extension↔content verdict (from `entry.magic` when the parser
    /// already computed it, else `check_entry` on the header).
    pub magic: MagicVerdict,
    /// Reputation outcome, when a service was configured.
    pub reputation: Option<ReputationReport>,
    /// Masquerade/suspicion analysis.
    pub suspicion: SuspicionReport,
    /// Rule-scanner hits (YARA plug point).
    pub rule_hits: Vec<RuleHit>,
    /// Sandbox hash lookup, when a provider was consulted (feature
    /// `sandbox` only).
    pub sandbox_verdict: Option<SandboxVerdict>,
    /// Combined worst severity across all signals.
    pub severity: Severity,
    /// Merged, deduplicated recommended actions.
    pub recommended_actions: Vec<String>,
    /// One-line, court-explainable summary, e.g.
    /// `"/docs/invoice.docx: declared OOXML document; content is
    ///  PE/COFF Windows executable; VT 41/72 engines flag trojan.x →
    ///  High suspicion"`.
    pub summary: String,
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Info => "Info",
        Severity::Suspicious => "Suspicious",
        Severity::High => "High",
    }
}

/// The single per-file call a forensic pipeline makes.
///
/// * `entry` — the `FsEntry` under examination (uses `entry.magic` when
///   the parser already computed it, else computes `check_entry` from
///   `entry.name` + `header`).
/// * `header` — bounded leading bytes (≤ 4 KiB is what the parsers read).
/// * `sha256` — the file's content hash, computed by the caller.
/// * `cfg` — optional reputation service / rule scanner / sandbox.
///
/// Never fails: every error mode degrades into the assessment's reasons.
pub fn analyze_file(
    entry: &FsEntry,
    header: &[u8],
    sha256: &str,
    cfg: &AnalysisConfig,
) -> FileAssessment {
    // 1. Magic: reuse the parser's verdict if present.
    let magic = entry
        .magic
        .clone()
        .unwrap_or_else(|| check_entry(&entry.name, header));

    // 2. Masquerade analysis.
    let suspicion = analyze_masquerade(entry, &magic);
    let mut severity = suspicion.severity;
    let mut actions = suspicion.recommended_actions.clone();

    // 3. Reputation (hash-only; never uploads content).
    let reputation = cfg.reputation.map(|svc| svc.lookup(sha256));
    if let Some(rep) = &reputation {
        match rep.verdict {
            RepVerdict::Malicious => {
                severity = Severity::High;
                push_unique(
                    &mut actions,
                    "VT flags malicious — treat as hostile: preserve, escalate, \
                     do not execute; correlate against case IOC list",
                );
            }
            RepVerdict::Suspicious => {
                if severity < Severity::Suspicious {
                    severity = Severity::Suspicious;
                }
                push_unique(
                    &mut actions,
                    "low-confidence VT detections — review flagging engines and \
                     threat label before trusting",
                );
            }
            RepVerdict::Clean => {}
            RepVerdict::Unknown => {
                push_unique(
                    &mut actions,
                    "hash unknown to reputation service — novel or rare file; \
                     prioritise sandbox/YARA analysis",
                );
            }
            RepVerdict::NotQueried => {
                push_unique(
                    &mut actions,
                    "reputation not queried (offline) — hash queued; run \
                     export_pending on a connected host and re-import",
                );
            }
        }
    }

    // 4. Rule scanner (YARA hook point). Errors become reasons.
    let mut rule_hits = Vec::new();
    let mut extra_reasons: Vec<String> = Vec::new();
    if let Some(scanner) = cfg.scanner {
        match scanner.scan(&entry.path, header) {
            Ok(hits) => {
                for h in &hits {
                    extra_reasons.push(format!(
                        "rule '{}' matched (tags: {})",
                        h.rule,
                        if h.tags.is_empty() {
                            "none".to_string()
                        } else {
                            h.tags.join(",")
                        }
                    ));
                    let hit_sev = h.severity.unwrap_or(Severity::Suspicious);
                    if hit_sev > severity {
                        severity = hit_sev;
                    }
                }
                if !hits.is_empty() {
                    push_unique(
                        &mut actions,
                        "rule-scanner hits — review matched rules against the \
                         case ruleset version",
                    );
                }
                rule_hits = hits;
            }
            Err(e) => extra_reasons.push(format!("rule scanner failed: {e}")),
        }
    }

    // 5. Sandbox — hash lookup only, gated on the `sandbox` feature.
    #[cfg(feature = "sandbox")]
    let sandbox_verdict = if let Some(sb) = cfg.sandbox {
        match sb.submit_hash(sha256) {
            Ok(v) => {
                if v.malicious == Some(true) {
                    severity = Severity::High;
                }
                Some(v)
            }
            Err(e) => {
                extra_reasons.push(format!("sandbox query failed: {e}"));
                None
            }
        }
    } else {
        None
    };
    #[cfg(not(feature = "sandbox"))]
    let sandbox_verdict: Option<SandboxVerdict> = {
        if cfg.sandbox.is_some() {
            extra_reasons.push(
                "sandbox provider configured but crate built without feature \
                 `sandbox` — not queried (detonation is never automatic)"
                    .to_string(),
            );
        }
        None
    };

    // 6. Court-explainable one-line summary.
    let declared = magic
        .declared
        .map(|d| d.name())
        .unwrap_or("no declared type");
    let detected = magic
        .detected
        .map(|d| d.name())
        .unwrap_or("unrecognised content");
    let rep_phrase = reputation.as_ref().map(|r| match r.verdict {
        RepVerdict::Malicious | RepVerdict::Suspicious => match r.tally() {
            Some(t) => format!(
                "; VT {t} engines flag{}",
                match r.vt.as_ref().and_then(|v| v.threat_label.as_ref()) {
                    Some(l) => format!(" {l}"),
                    None => String::new(),
                }
            ),
            None => "; VT flagged".to_string(),
        },
        RepVerdict::Clean => "; VT clean".to_string(),
        RepVerdict::Unknown => "; hash unknown to VT".to_string(),
        RepVerdict::NotQueried => "; reputation not queried".to_string(),
    });
    let summary = format!(
        "{}: declared {declared}; content is {detected}{} → {} suspicion",
        entry.path,
        rep_phrase.unwrap_or_default(),
        severity_label(severity)
    );

    // Fold scanner/sandbox reasons into the suspicion report tail so a
    // reader sees them with the masquerade reasoning.
    let mut suspicion = suspicion;
    suspicion.reasons.extend(extra_reasons);

    FileAssessment {
        magic,
        reputation,
        suspicion,
        rule_hits,
        sandbox_verdict,
        severity,
        recommended_actions: actions,
        summary,
    }
}

fn push_unique(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}
