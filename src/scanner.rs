//! Rule-scanner hook — the YARA plug point.
//!
//! This crate deliberately does **not** depend on a YARA engine (the
//! `yara`/`yara-x` crates pull in native code, and the platform stays
//! pure-Rust). Instead, the forensic platform implements [`RuleScanner`]
//! over whatever engine it ships — YARA, a signature DB, a custom
//! matcher — and the pipeline consults it via the trait.

use std::collections::HashMap;

use sutram_magic::Severity;

use crate::error::RepError;

/// One rule hit on a file.
#[derive(Debug, Clone)]
pub struct RuleHit {
    /// Rule identifier (e.g. `"MALW_TrojanX_Jan2024"`).
    pub rule: String,
    /// Rule tags (e.g. `["trojan", "ransomware"]`).
    pub tags: Vec<String>,
    /// Rule metadata (author, reference, date, …).
    pub meta: HashMap<String, String>,
    /// Severity asserted by the ruleset for this rule, when it maps one.
    /// `None` → treated as `Suspicious`.
    pub severity: Option<Severity>,
}

/// A pluggable byte-matching scanner.
///
/// Contract: `scan` receives the entry path plus a **bounded header**
/// (the same ≤ 4 KiB the magic check saw) — enough for header rules.
/// Full-file scanning is the caller's job: `analyze_file` does not read
/// the filesystem. Implementations must be thread-safe.
///
/// YARA adapter sketch:
///
/// ```text
/// struct YaraScanner { rules: yara_x::Rules }
/// impl RuleScanner for YaraScanner {
///     fn scan(&self, path, header) -> Result<Vec<RuleHit>, RepError> {
///         // rules.scan_mem(header) → map matches → RuleHit
///     }
/// }
/// ```
pub trait RuleScanner: Send + Sync {
    /// Scanner name for reports (`"yara-x v0.9 ruleset 2024-05"`).
    fn name(&self) -> &str;

    /// Scan a file header; return every matching rule. Errors are
    /// surfaced to the assessment's reasons rather than aborting.
    fn scan(&self, entry_path: &str, header: &[u8]) -> Result<Vec<RuleHit>, RepError>;
}
