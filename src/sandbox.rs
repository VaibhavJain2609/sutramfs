//! Sandbox provider interface — behavioural verdicts and IOCs.
//!
//! This crate ships **no** sandbox implementation. [`NullSandbox`] is the
//! configured-by-default stub; reference backends (Cuckoo Sandbox, CAPE)
//! are deferred and should implement [`SandboxProvider`] in a separate
//! crate.
//!
//! ## Safety boundary
//!
//! * `submit_hash` — a *lookup* of prior detonation results; the pipeline
//!   (`analyze_file`) may consult it, and only under feature `sandbox`.
//! * `submit_file` — uploads/detonates file **content**. This crate never
//!   calls it; providers should additionally require explicit enablement
//!   (like [`RepConfig::allow_uploads`](crate::RepConfig::allow_uploads)).
//!   Detonating unknown evidence uploads its bytes to the sandbox host —
//!   for a remote service that is an evidence-disclosure decision.

use std::collections::HashMap;

use crate::error::RepError;

/// Outcome of a sandbox query/submission.
#[derive(Debug, Clone)]
pub struct SandboxVerdict {
    /// Provider name (e.g. `"cuckoo"`).
    pub provider: String,
    /// `Some(true)` malicious, `Some(false)` clean, `None` undetermined
    /// (still queued, no prior run, …).
    pub malicious: Option<bool>,
    /// Provider's numeric score when it has one (CAPE/Cuckoo malscore).
    pub score: Option<f64>,
    /// Indicators of compromise observed (mutexes, domains, dropped
    /// hashes, …) — free-form strings for the report.
    pub iocs: Vec<String>,
    /// URL/id of the full detonation report.
    pub report_ref: Option<String>,
    /// Human-readable notes.
    pub notes: Vec<String>,
    /// Provider-specific extras.
    pub meta: HashMap<String, String>,
}

/// Behavioural-analysis backend.
pub trait SandboxProvider: Send + Sync {
    /// Short provider name (`"cuckoo"`, `"cape"`, `"null"`).
    fn name(&self) -> &str;

    /// Look up prior detonation results for a hash — safe to call from
    /// the pipeline (no content leaves the host).
    fn submit_hash(&self, sha256: &str) -> Result<SandboxVerdict, RepError>;

    /// **OPT-IN.** Upload and detonate file content. This crate never
    /// calls this method; implementations should require their own
    /// explicit enable flag and document their disclosure implications.
    fn submit_file(&self, filename: &str, data: &[u8]) -> Result<SandboxVerdict, RepError>;
}

/// No-op provider — the default. Every call returns
/// [`RepError::Unsupported`] with a clear reason, so a pipeline that
/// wires it in degrades to a documented "not configured" rather than a
/// silent skip.
#[derive(Debug, Default)]
pub struct NullSandbox;

impl SandboxProvider for NullSandbox {
    fn name(&self) -> &str {
        "null"
    }

    fn submit_hash(&self, _sha256: &str) -> Result<SandboxVerdict, RepError> {
        Err(RepError::Unsupported(
            "no sandbox provider configured (NullSandbox); Cuckoo/CAPE \
             reference impls are deferred — implement SandboxProvider"
                .to_string(),
        ))
    }

    fn submit_file(&self, _filename: &str, _data: &[u8]) -> Result<SandboxVerdict, RepError> {
        Err(RepError::Unsupported(
            "no sandbox provider configured (NullSandbox); file detonation \
             is never automatic"
                .to_string(),
        ))
    }
}
