//! # sutram-reputation
//!
//! File reputation and suspicious-file analysis for the SUTRAM-FS
//! forensic parser family. Sits on top of `sutram-fs` ([`FsEntry`]) and
//! `sutram-magic` ([`MagicVerdict`]): given an entry, its header bytes,
//! and its content hash, [`analyze_file`] produces one court-explainable
//! [`FileAssessment`].
//!
//! ## Air-gap first
//!
//! The forensic platform is **offline by default**, and so is this crate:
//!
//! * Default features compile **no networking, no TLS, no C code**.
//!   Without a transport, [`ReputationService::lookup`] returns
//!   [`RepVerdict::NotQueried`] and records the hash in a pending queue —
//!   `export_pending()` carries it to a connected host,
//!   `import_results()` brings answers back (the sneaker-net bridge).
//! * Feature **`net`** adds a thin `ureq` transport (pulls rustls/ring —
//!   a documented exception to the pure-Rust rule, compiled only on
//!   request). Or implement [`HttpTransport`] yourself.
//! * Feature **`cache`** adds a persistent SQLite lookup cache
//!   (rusqlite/bundled — second documented exception). The in-memory
//!   cache works without it.
//! * Feature **`sandbox`** lets the pipeline *query* a
//!   [`SandboxProvider`] by hash. Detonation of file content is never
//!   automatic.
//!
//! ## Opt-in boundaries (non-negotiable)
//!
//! * **Hash-first only.** The default VT path is `GET files/{sha256}` —
//!   one request, no file bytes. [`ReputationService::submit_file`]
//!   uploads evidence contents and requires `RepConfig::allow_uploads`
//!   plus an explicit call. Uploading seized evidence is a legal/
//!   confidentiality decision, not a default.
//! * **Never auto-detonate.** `analyze_file` may consult a sandbox by
//!   hash (feature `sandbox`); it never submits file contents.
//!
//! ## Optimizations
//!
//! * In-memory (+ optional sqlite) cache keyed by hash with TTL —
//!   negative results (404s) cached too.
//! * Concurrent lookups of the same hash dedup onto one request.
//! * Token-bucket limiter honours VT's 4 req/min public tier.
//! * [`ReputationService::lookup_many`] parallelises batch prefetch
//!   within the rate limit.

#![forbid(unsafe_code)]

mod cache;
mod error;
mod masquerade;
mod pipeline;
mod ratelimit;
mod report;
mod sandbox;
mod scanner;
mod transport;
pub mod util;
mod vt;

pub use error::RepError;
pub use masquerade::{analyze_masquerade, SuspicionReport};
pub use pipeline::{analyze_file, AnalysisConfig, FileAssessment};
pub use ratelimit::{RateLimiter, TokenBucket};
pub use report::{EngineDetection, RepVerdict, ReputationReport, VerdictThresholds, VtResult};
pub use sandbox::{NullSandbox, SandboxProvider, SandboxVerdict};
pub use scanner::{RuleHit, RuleScanner};
pub use transport::{HttpMethod, HttpResponse, HttpTransport};
pub use vt::{
    decode_pending, decode_results, encode_pending, encode_results, parse_vt_file_report,
    RepConfig, ReputationService, PENDING_FORMAT, RESULTS_FORMAT, VT_API_BASE,
};

#[cfg(feature = "cache")]
pub use cache::SqliteCache;
#[cfg(feature = "net")]
pub use transport::UreqTransport;

// Vocabulary re-exports so callers name one crate.
pub use sutram_fs::FsEntry;
pub use sutram_magic::{check_entry, MagicVerdict, Severity};

#[cfg(test)]
mod tests;
