//! Reputation report types: [`RepVerdict`], [`VtResult`],
//! [`ReputationReport`], and the configurable verdict thresholds.

use std::fmt;

use serde::{Deserialize, Serialize};

/// What a reputation lookup concluded about a hash.
///
/// Ordering matters: `NotQueried` and `Unknown` are deliberately distinct —
/// `NotQueried` means *we never asked* (offline, disabled, transport
/// failure), `Unknown` means *we asked and the service has no record*.
/// A court must be able to tell those apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RepVerdict {
    /// Looked up; zero engines flagged it (and ≥1 engine scanned it).
    Clean,
    /// Looked up; a small number of engines flagged it, or only
    /// low-confidence "suspicious" hits — below the malicious threshold.
    Suspicious,
    /// Looked up; engine detections ≥ configured threshold.
    Malicious,
    /// Looked up; the service has no record of this hash (VT 404).
    Unknown,
    /// No lookup was performed: offline mode, no transport, transport
    /// failure, or the hash was queued for a later sneaker-net sync.
    NotQueried,
}

impl fmt::Display for RepVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RepVerdict::Clean => write!(f, "clean"),
            RepVerdict::Suspicious => write!(f, "suspicious"),
            RepVerdict::Malicious => write!(f, "malicious"),
            RepVerdict::Unknown => write!(f, "unknown"),
            RepVerdict::NotQueried => write!(f, "not queried"),
        }
    }
}

/// One engine's detection inside a [`VtResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineDetection {
    /// Engine/vendor name (e.g. `"Microsoft"`).
    pub engine: String,
    /// VT category string (`"malicious"`, `"suspicious"`, …).
    pub category: String,
    /// Detection name when the engine gave one (e.g. `"Trojan:Win32/X"`).
    pub result: Option<String>,
}

/// A parsed VirusTotal `files/{hash}` report — the fields a forensic
/// report actually cites, extracted from the (much larger) VT v3 JSON.
///
/// Serialisable so it can round-trip through the cache and the air-gap
/// bridge ([`ReputationService::export_pending`](crate::ReputationService::export_pending)
/// / `import_results`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtResult {
    /// SHA-256 VT keyed on (echoed back; also the `id` field).
    pub sha256: String,
    /// MD5 when VT knows it.
    pub md5: Option<String>,
    /// Engines voting "harmless".
    pub harmless: u32,
    /// Engines voting "suspicious" (low confidence).
    pub suspicious: u32,
    /// Engines voting "malicious".
    pub malicious: u32,
    /// Engines that saw the file and detected nothing.
    pub undetected: u32,
    /// Engines that timed out / failed.
    pub timeout: u32,
    /// Total engines in `last_analysis_stats`.
    pub total_engines: u32,
    /// `popular_threat_classification.suggested_threat_label`, when present.
    pub threat_label: Option<String>,
    /// `meaningful_name` — the most common submitted filename.
    pub meaningful_name: Option<String>,
    /// VT's own community reputation score, when present.
    pub reputation_score: Option<i64>,
    /// `first_submission_date` (unix seconds).
    pub first_submission: Option<i64>,
    /// `last_analysis_date` (unix seconds).
    pub last_analysis: Option<i64>,
    /// Per-engine detections — **only engines that flagged the file**
    /// (malicious/suspicious); the full undetected list is noise for a
    /// report. Bounded by engine count (~70).
    pub detections: Vec<EngineDetection>,
}

/// How many engine hits move a hash to `Suspicious` / `Malicious`.
///
/// Defaults follow common triage convention: ≥ 5 malicious engines →
/// `Malicious`; 1–4 malicious or ≥ 1 suspicious engine → `Suspicious`;
/// 0 flags on a known file → `Clean`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerdictThresholds {
    /// `malicious` engine count at/above which the verdict is `Malicious`.
    pub malicious_at: u32,
    /// `suspicious` engine count at/above which the verdict is at least
    /// `Suspicious` even with zero `malicious` votes.
    pub suspicious_at: u32,
}

impl Default for VerdictThresholds {
    fn default() -> Self {
        VerdictThresholds {
            malicious_at: 5,
            suspicious_at: 1,
        }
    }
}

impl VerdictThresholds {
    /// Map a parsed VT result to a [`RepVerdict`].
    pub fn classify(&self, vt: &VtResult) -> RepVerdict {
        if self.malicious_at > 0 && vt.malicious >= self.malicious_at {
            RepVerdict::Malicious
        } else if vt.malicious > 0
            || (self.suspicious_at > 0 && vt.suspicious >= self.suspicious_at)
        {
            RepVerdict::Suspicious
        } else if vt.total_engines > 0 {
            RepVerdict::Clean
        } else {
            RepVerdict::Unknown
        }
    }
}

/// The full reputation outcome for one hash, with court-explainable
/// reasons.
#[derive(Debug, Clone)]
pub struct ReputationReport {
    /// The hash that was queried (lowercased hex).
    pub sha256: String,
    /// MD5 when known (from the VT record).
    pub md5: Option<String>,
    /// The parsed VT record, when a lookup succeeded and the hash exists.
    pub vt: Option<VtResult>,
    /// Combined verdict.
    pub verdict: RepVerdict,
    /// Human-readable explanations — suitable for a report/court exhibit
    /// ("VT 41/72 engines flag trojan.x", "offline — queued for sync").
    pub reasons: Vec<String>,
}

impl ReputationReport {
    /// Short "41/72"-style engine tally for embedding in summaries.
    pub fn tally(&self) -> Option<String> {
        self.vt
            .as_ref()
            .map(|v| format!("{}/{}", v.malicious, v.total_engines))
    }
}
