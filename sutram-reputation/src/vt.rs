//! VirusTotal hash-first client and the [`ReputationService`].
//!
//! ## Opt-in boundaries (forensic)
//!
//! * **Hash-first, always.** The default lookup path is exactly one
//!   request: `GET /api/v3/files/{sha256}`. File *contents* are never
//!   transmitted by any default code path.
//! * **`submit_file` is the deliberate exception.** Uploading seized
//!   evidence to a third-party service is a legal and confidentiality
//!   decision — it leaks the fact that *you* hold *this* file. It
//!   therefore requires BOTH `RepConfig::allow_uploads = true` AND an
//!   explicit call. `analyze_file` never calls it.
//! * **Offline is the default deployment.** With no transport (no `net`
//!   feature, or `RepConfig::offline`), lookups return
//!   [`RepVerdict::NotQueried`] and the hash is recorded in the pending
//!   set — export it, query on a connected host, re-import
//!   (`export_pending`/`import_results`, the sneaker-net bridge).

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use serde::{Deserialize, Serialize};

#[cfg(feature = "cache")]
use crate::cache::SqliteCache;
use crate::cache::{Cached, MemCache};
use crate::error::RepError;
use crate::ratelimit::RateLimiter;
use crate::report::{EngineDetection, RepVerdict, ReputationReport, VerdictThresholds, VtResult};
use crate::transport::{HttpMethod, HttpTransport};
use crate::util::{normalize_hash, unix_now};

/// VirusTotal v3 API base.
pub const VT_API_BASE: &str = "https://www.virustotal.com/api/v3";

/// Format tag for the pending-hash export (sneaker-net bridge, outbound).
pub const PENDING_FORMAT: &str = "sutram-rep-pending/1";
/// Format tag for the VT-results import (sneaker-net bridge, inbound).
pub const RESULTS_FORMAT: &str = "sutram-rep-results/1";

/// Cap on response bodies we keep — VT file records are ~20–60 KiB.
const MAX_BODY: usize = 4 * 1024 * 1024;

/// Service configuration.
#[derive(Debug, Clone)]
pub struct RepConfig {
    /// VirusTotal API key. `None` is legal in offline mode (pending-set
    /// recording still works); a live query without a key gets a 401.
    pub api_key: Option<String>,
    /// Cache TTL for positive AND negative (404) results. VT verdicts
    /// drift slowly; default 7 days suits multi-week examinations.
    pub ttl: Duration,
    /// Requests per minute. VT public tier = **4**. Set 0 to disable the
    /// limiter (private keys with no quota).
    pub requests_per_minute: u32,
    /// Worker threads used by `lookup_many`. The rate limiter, not this
    /// number, enforces quota — extra workers only overlap HTTP latency
    /// and JSON parsing. Default 4.
    pub max_workers: usize,
    /// Force offline behaviour even when a transport is configured:
    /// every lookup is `NotQueried` + recorded pending.
    pub offline: bool,
    /// Master switch for [`ReputationService::submit_file`]. Default
    /// `false`; uploading seized evidence is a legal decision, not a
    /// default. See the method's documentation.
    pub allow_uploads: bool,
    /// Engine-count thresholds for verdict mapping.
    pub thresholds: VerdictThresholds,
}

impl Default for RepConfig {
    fn default() -> Self {
        RepConfig {
            api_key: None,
            ttl: Duration::from_secs(7 * 24 * 3600),
            requests_per_minute: 4,
            max_workers: 4,
            offline: false,
            allow_uploads: false,
            thresholds: VerdictThresholds::default(),
        }
    }
}

/// Shared slot for deduplicating concurrent lookups of the same hash.
struct InFlight {
    done: Mutex<Option<ReputationReport>>,
    cv: Condvar,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The reputation service: cache → (dedup) → rate-limited VT GET.
///
/// Construct via [`ReputationService::new`] (offline / custom transport
/// later) or [`ReputationService::with_transport`]. Thread-safe; share
/// via `&` across pipeline threads.
pub struct ReputationService {
    cfg: RepConfig,
    transport: Option<Box<dyn HttpTransport>>,
    limiter: RateLimiter,
    mem: Mutex<MemCache>,
    #[cfg(feature = "cache")]
    disk: Option<SqliteCache>,
    in_flight: Mutex<HashMap<String, Arc<InFlight>>>,
    pending: Mutex<BTreeSet<String>>,
}

impl ReputationService {
    /// A service with no transport — every lookup is `NotQueried` and
    /// recorded in the pending set. This is the air-gapped default.
    pub fn new(cfg: RepConfig) -> Self {
        ReputationService {
            limiter: RateLimiter::new(cfg.requests_per_minute),
            cfg,
            transport: None,
            mem: Mutex::new(MemCache::default()),
            #[cfg(feature = "cache")]
            disk: None,
            in_flight: Mutex::new(HashMap::new()),
            pending: Mutex::new(BTreeSet::new()),
        }
    }

    /// A service with an injected transport (a real one under `net`, or a
    /// mock). `cfg.offline` still wins: set it to dry-run a configured
    /// deployment.
    pub fn with_transport(cfg: RepConfig, transport: Box<dyn HttpTransport>) -> Self {
        let mut s = Self::new(cfg);
        s.transport = Some(transport);
        s
    }

    /// ureq-backed VirusTotal client — feature `net`.
    #[cfg(feature = "net")]
    pub fn virustotal(api_key: &str) -> Self {
        let cfg = RepConfig {
            api_key: Some(api_key.to_string()),
            ..RepConfig::default()
        };
        Self::with_transport(cfg, Box::new(crate::transport::UreqTransport::new()))
    }

    /// Attach a persistent sqlite cache — feature `cache`.
    #[cfg(feature = "cache")]
    pub fn with_disk_cache(mut self, cache: SqliteCache) -> Self {
        self.disk = Some(cache);
        self
    }

    /// Hashes we wanted to query but couldn't (offline / transport
    /// failure / rate-limited) — the sneaker-net queue.
    pub fn pending_hashes(&self) -> Vec<String> {
        lock(&self.pending).iter().cloned().collect()
    }

    /// `true` when this service will never reach a network (no transport
    /// configured, or `cfg.offline`).
    pub fn is_offline(&self) -> bool {
        self.cfg.offline || self.transport.is_none()
    }

    fn ttl_secs(&self) -> i64 {
        self.cfg.ttl.as_secs() as i64
    }

    fn cache_get(&self, hash: &str) -> Option<Cached> {
        let now = unix_now();
        if let Some(c) = lock(&self.mem).get(hash, self.ttl_secs(), now) {
            return Some(c.clone());
        }
        #[cfg(feature = "cache")]
        if let Some(disk) = &self.disk {
            if let Some(c) = disk.get(hash, now - self.ttl_secs()) {
                lock(&self.mem).put(hash, c.clone(), now);
                return Some(c);
            }
        }
        None
    }

    fn cache_put(&self, hash: &str, entry: Cached) {
        lock(&self.mem).put(hash, entry.clone(), unix_now());
        #[cfg(feature = "cache")]
        if let Some(disk) = &self.disk {
            // A failed disk write loses persistence, not correctness.
            let _ = disk.put(hash, &entry);
        }
    }

    fn record_pending(&self, hash: &str) {
        lock(&self.pending).insert(hash.to_string());
    }

    /// Drop expired memory-cache entries. TTL expiry already makes them
    /// misses; this reclaims memory between case runs.
    pub fn evict_expired(&self) {
        lock(&self.mem).evict_expired(self.ttl_secs(), unix_now());
    }

    /// Look up one hash. Infallible — every failure mode folds into the
    /// report's `verdict`/`reasons` so a batch pipeline never aborts on
    /// one bad hash, and the record stays court-explainable.
    ///
    /// Path: validate → mem cache → disk cache → (offline? pending) →
    /// dedup → rate-limited `GET files/{hash}` → cache → classify.
    pub fn lookup(&self, hash: &str) -> ReputationReport {
        let Some(hash) = normalize_hash(hash) else {
            return ReputationReport {
                sha256: hash.trim().to_string(),
                md5: None,
                vt: None,
                verdict: RepVerdict::NotQueried,
                reasons: vec![format!(
                    "not a valid MD5/SHA-1/SHA-256 hex string — never queried"
                )],
            };
        };

        if let Some(cached) = self.cache_get(&hash) {
            return self.report_from_cache(&hash, cached);
        }

        if self.is_offline() {
            self.record_pending(&hash);
            return ReputationReport {
                sha256: hash,
                md5: None,
                vt: None,
                verdict: RepVerdict::NotQueried,
                reasons: vec!["offline mode — hash recorded for later lookup \
                     (export_pending / import_results bridge)"
                    .to_string()],
            };
        }

        // --- dedup concurrent lookups of the same hash ---------------
        let (leader, slot) = {
            let mut map = lock(&self.in_flight);
            match map.get(&hash) {
                Some(slot) => (false, Arc::clone(slot)),
                None => {
                    let slot = Arc::new(InFlight {
                        done: Mutex::new(None),
                        cv: Condvar::new(),
                    });
                    map.insert(hash.clone(), Arc::clone(&slot));
                    (true, slot)
                }
            }
        };
        if !leader {
            let mut g = lock(&slot.done);
            while g.is_none() {
                g = slot.cv.wait(g).unwrap_or_else(|e| e.into_inner());
            }
            return match g.as_ref() {
                Some(r) => {
                    let mut r = r.clone();
                    r.reasons
                        .push("deduplicated concurrent lookup for this hash".to_string());
                    r
                }
                None => self.unqueried(&hash, "internal: in-flight slot lost"),
            };
        }

        let report = self.fetch_and_classify(&hash);

        {
            *lock(&slot.done) = Some(report.clone());
            slot.cv.notify_all();
        }
        lock(&self.in_flight).remove(&hash);
        report
    }

    /// Batch prefetch: dedup the input, then fan out across
    /// `cfg.max_workers` threads. All workers share the one rate limiter,
    /// so total request rate stays within `requests_per_minute` no matter
    /// the worker count. Returns one report per input hash, in order.
    pub fn lookup_many(&self, hashes: &[&str]) -> Vec<ReputationReport> {
        // Dedup while preserving first-seen order.
        let mut seen = HashSet::new();
        let unique: Vec<String> = hashes
            .iter()
            .filter_map(|h| normalize_hash(h))
            .filter(|h| seen.insert(h.clone()))
            .collect();

        // No early return on empty `unique`: the contract is one report
        // per input hash, so all-invalid input must still yield a
        // `NotQueried` report per input via the merge below. An empty
        // queue simply means the workers exit immediately.
        let workers = if self.is_offline() {
            1
        } else {
            self.cfg.max_workers.clamp(1, 8).min(unique.len())
        };

        let queue: Mutex<VecDeque<String>> = Mutex::new(unique.iter().cloned().collect());
        let results: Mutex<HashMap<String, ReputationReport>> = Mutex::new(HashMap::new());

        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    let next = lock(&queue).pop_front();
                    match next {
                        None => return,
                        Some(h) => {
                            let r = self.lookup(&h);
                            lock(&results).insert(h, r);
                        }
                    }
                });
            }
        });

        let map = lock(&results);
        hashes
            .iter()
            .map(|h| match normalize_hash(h).and_then(|n| map.get(&n)) {
                Some(r) => r.clone(),
                None => self.unqueried(h, "invalid hash string — never queried"),
            })
            .collect()
    }

    /// Leader path: rate-limit → GET → classify → cache.
    fn fetch_and_classify(&self, hash: &str) -> ReputationReport {
        let Some(transport) = &self.transport else {
            self.record_pending(hash);
            return self.unqueried(hash, "no transport configured");
        };

        self.limiter.acquire();

        let url = format!("{VT_API_BASE}/files/{hash}");
        let key = self.cfg.api_key.clone().unwrap_or_default();
        let resp = transport.request(
            HttpMethod::Get,
            &url,
            &[("x-apikey", key.as_str()), ("accept", "application/json")],
            None,
        );

        // Normalise: some transports (ureq) surface 4xx/5xx as
        // `Err(RepError::Http)` rather than `Ok(response)` — the status is
        // what matters either way.
        let (status, body) = match resp {
            Ok(r) => (r.status, r.body),
            Err(RepError::Http { status, body }) => (status, body),
            Err(e) => {
                self.record_pending(hash);
                return self.report(
                    hash,
                    None,
                    RepVerdict::NotQueried,
                    vec![format!("VT query failed ({e}) — queued for retry")],
                );
            }
        };

        match status {
            200 => match parse_vt_file_report(bounded(&body)) {
                Ok(vt) => {
                    self.cache_put(hash, Cached::Found(Box::new(vt.clone())));
                    let verdict = self.cfg.thresholds.classify(&vt);
                    self.report(hash, Some(vt), verdict, Vec::new())
                }
                Err(e) => {
                    // Got a 200 we couldn't parse — the record exists but
                    // is unusable. Not pending-worthy; the query ran.
                    self.report(
                        hash,
                        None,
                        RepVerdict::Unknown,
                        vec![format!("VT response did not parse: {e}")],
                    )
                }
            },
            404 => {
                self.cache_put(hash, Cached::NotFound);
                self.report(
                    hash,
                    None,
                    RepVerdict::Unknown,
                    vec!["VT has no record of this hash (HTTP 404)".to_string()],
                )
            }
            401 | 403 => {
                // Auth failure won't fix itself by re-try — not pending.
                self.report(
                    hash,
                    None,
                    RepVerdict::NotQueried,
                    vec![format!(
                        "VT API key rejected (HTTP {status}) — check RepConfig::api_key"
                    )],
                )
            }
            _ => {
                self.record_pending(hash);
                self.report(
                    hash,
                    None,
                    RepVerdict::NotQueried,
                    vec![format!(
                        "VT query failed (HTTP {status}){} — queued for retry",
                        if status == 429 { " rate limit" } else { "" }
                    )],
                )
            }
        }
    }

    fn report_from_cache(&self, hash: &str, cached: Cached) -> ReputationReport {
        match cached {
            Cached::Found(vt) => {
                let verdict = self.cfg.thresholds.classify(&vt);
                self.report(hash, Some(*vt), verdict, vec!["cached result".to_string()])
            }
            Cached::NotFound => self.report(
                hash,
                None,
                RepVerdict::Unknown,
                vec!["VT has no record of this hash (cached negative result)".to_string()],
            ),
        }
    }

    fn unqueried(&self, hash: &str, why: &str) -> ReputationReport {
        self.report(hash, None, RepVerdict::NotQueried, vec![why.to_string()])
    }

    fn report(
        &self,
        hash: &str,
        vt: Option<VtResult>,
        verdict: RepVerdict,
        mut reasons: Vec<String>,
    ) -> ReputationReport {
        if let Some(v) = &vt {
            let tally = format!("VT {}/{} engines flag", v.malicious, v.total_engines);
            reasons.push(match (&v.threat_label, verdict) {
                (Some(label), _) => format!("{tally} ({label})"),
                (None, RepVerdict::Malicious) => format!("{tally} malicious"),
                (None, RepVerdict::Suspicious) => format!("{tally} (below malicious threshold)"),
                (None, _) => format!("{tally} — clean"),
            });
            if v.suspicious > 0 {
                reasons.push(format!(
                    "additionally {} engine(s) report 'suspicious'",
                    v.suspicious
                ));
            }
        }
        ReputationReport {
            sha256: hash.to_string(),
            md5: vt.as_ref().and_then(|v| v.md5.clone()),
            vt,
            verdict,
            reasons,
        }
    }

    /// Export the pending-hash queue as JSON for transfer to a connected
    /// host (`sneaker-net` bridge, outbound leg).
    ///
    /// ```json
    /// {"format":"sutram-rep-pending/1","hashes":["<sha256>", …]}
    /// ```
    pub fn export_pending(&self) -> String {
        encode_pending(&self.pending_hashes())
    }

    /// Import VT results produced on a connected host, populating the
    /// caches and clearing satisfied pending entries. Returns how many
    /// results were imported. Format:
    ///
    /// ```json
    /// {"format":"sutram-rep-results/1","results":[<VtResult>, …]}
    /// ```
    pub fn import_results(&self, json: &str) -> Result<usize, RepError> {
        let results = decode_results(json)?;
        let mut n = 0;
        for vt in &results {
            let Some(hash) = normalize_hash(&vt.sha256) else {
                continue; // skip malformed rows rather than fail the batch
            };
            self.cache_put(&hash, Cached::Found(Box::new(vt.clone())));
            lock(&self.pending).remove(&hash);
            n += 1;
        }
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// Sneaker-net bridge encoders/decoders (shared by both legs).
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct PendingFile {
    format: String,
    hashes: Vec<String>,
}

/// Encode the pending-hash list (outbound leg). Free function so a
/// companion tool can use it without owning a service.
pub fn encode_pending(hashes: &[String]) -> String {
    let f = PendingFile {
        format: PENDING_FORMAT.to_string(),
        hashes: hashes.to_vec(),
    };
    serde_json::to_string_pretty(&f).unwrap_or_else(|_| "{}".to_string())
}

/// Decode a pending-hash export (inbound leg, on the connected host).
pub fn decode_pending(json: &str) -> Result<Vec<String>, RepError> {
    let f: PendingFile =
        serde_json::from_str(json).map_err(|e| RepError::Parse(format!("pending file: {e}")))?;
    if f.format != PENDING_FORMAT {
        return Err(RepError::Parse(format!(
            "expected format {PENDING_FORMAT:?}, got {:?}",
            f.format
        )));
    }
    Ok(f.hashes)
}

#[derive(Serialize, Deserialize)]
struct ResultsFile {
    format: String,
    results: Vec<VtResult>,
}

/// Encode VT results for re-import (inbound leg producer — run this on
/// the connected host after `lookup_many`).
pub fn encode_results(results: &[VtResult]) -> String {
    let f = ResultsFile {
        format: RESULTS_FORMAT.to_string(),
        results: results.to_vec(),
    };
    serde_json::to_string_pretty(&f).unwrap_or_else(|_| "{}".to_string())
}

/// Decode a results file (air-gapped side).
pub fn decode_results(json: &str) -> Result<Vec<VtResult>, RepError> {
    let f: ResultsFile =
        serde_json::from_str(json).map_err(|e| RepError::Parse(format!("results file: {e}")))?;
    if f.format != RESULTS_FORMAT {
        return Err(RepError::Parse(format!(
            "expected format {RESULTS_FORMAT:?}, got {:?}",
            f.format
        )));
    }
    Ok(f.results)
}

// ---------------------------------------------------------------------------
// Opt-in file submission — the ONLY code path that transmits file bytes.
// ---------------------------------------------------------------------------

impl ReputationService {
    /// **OPT-IN — uploads file content to VirusTotal.**
    ///
    /// Submitting seized evidence to a third-party service is a legal and
    /// confidentiality decision: it discloses that your investigation
    /// holds this file, may violate jurisdictional handling rules, and
    /// shares the bytes with every VT subscriber. VT itself recommends
    /// hash-first lookups for sensitive material — which is why this
    /// method requires `RepConfig::allow_uploads = true` *and* an
    /// explicit call. `analyze_file` never calls it.
    ///
    /// Returns the VT analysis id on acceptance (HTTP 200).
    pub fn submit_file(&self, filename: &str, data: &[u8]) -> Result<String, RepError> {
        if !self.cfg.allow_uploads {
            return Err(RepError::Unsupported(
                "file upload refused: RepConfig::allow_uploads is false — \
                 uploading evidence contents is an explicit legal decision"
                    .to_string(),
            ));
        }
        let Some(transport) = &self.transport else {
            return Err(RepError::Unsupported(
                "file upload needs a network transport (feature `net` or a \
                 custom HttpTransport); this service is offline"
                    .to_string(),
            ));
        };

        const BOUNDARY: &str = "sutramrep-boundary-4c2f9a1e";
        let mut body = Vec::with_capacity(data.len() + 256);
        body.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; \
                 filename=\"{fname}\"\r\nContent-Type: application/octet-stream\r\n\r\n",
                fname = sanitize_filename(filename)
            )
            .as_bytes(),
        );
        body.extend_from_slice(data);
        body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());

        self.limiter.acquire();
        let key = self.cfg.api_key.clone().unwrap_or_default();
        let resp = transport.request(
            HttpMethod::Post,
            &format!("{VT_API_BASE}/files"),
            &[
                ("x-apikey", key.as_str()),
                (
                    "content-type",
                    "multipart/form-data; boundary=sutramrep-boundary-4c2f9a1e",
                ),
            ],
            Some(&body),
        )?;

        if resp.status != 200 {
            return Err(RepError::Http {
                status: resp.status,
                body: crate::util::truncate(&resp.body, 2048),
            });
        }
        let v: serde_json::Value = serde_json::from_str(bounded(&resp.body))
            .map_err(|e| RepError::Parse(format!("upload response: {e}")))?;
        v.get("data")
            .and_then(|d| d.get("id"))
            .and_then(|i| i.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| RepError::Parse("upload response missing data.id".to_string()))
    }
}

/// Multipart filenames must not leak path structure or break the header.
fn sanitize_filename(name: &str) -> String {
    name.rsplit(['/', '\\'])
        .next()
        .unwrap_or("file")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ' '))
        .collect()
}

fn bounded(body: &str) -> &str {
    // get() honours char boundaries — a byte-index slice could panic on
    // multi-byte UTF-8 in upstream text.
    body.get(..MAX_BODY).unwrap_or(body)
}

// ---------------------------------------------------------------------------
// VirusTotal v3 response parsing — pure, offline-testable.
// ---------------------------------------------------------------------------

fn as_u32(v: &serde_json::Value, key: &str) -> u32 {
    v.get(key)
        .and_then(|x| x.as_u64())
        .map(|x| x.min(u32::MAX as u64) as u32)
        .unwrap_or(0)
}

/// Parse a VT `GET /api/v3/files/{hash}` body into a [`VtResult`].
/// Lenient: missing optional fields degrade to `None`/0 rather than
/// failing — VT's schema is wide and shifts over time. Fails only when
/// the body isn't JSON with a `data.attributes` object.
pub fn parse_vt_file_report(body: &str) -> Result<VtResult, RepError> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| RepError::Parse(format!("VT JSON: {e}")))?;
    if let Some(err) = v.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown VT error");
        return Err(RepError::Parse(format!("VT error envelope: {msg}")));
    }
    let data = v
        .get("data")
        .ok_or_else(|| RepError::Parse("missing 'data' object".to_string()))?;
    let attrs = data
        .get("attributes")
        .ok_or_else(|| RepError::Parse("missing 'data.attributes'".to_string()))?;

    let stats = attrs
        .get("last_analysis_stats")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let harmless = as_u32(&stats, "harmless");
    let suspicious = as_u32(&stats, "suspicious");
    let malicious = as_u32(&stats, "malicious");
    let undetected = as_u32(&stats, "undetected");
    // Saturating: hostile JSON can set each counter to u32::MAX — plain
    // `+` overflows (debug panic / release wrap).
    let timeout = as_u32(&stats, "timeout")
        .saturating_add(as_u32(&stats, "failure"))
        .saturating_add(as_u32(&stats, "type-unsupported"))
        .saturating_add(as_u32(&stats, "confirmed-timeout"));

    let mut detections = Vec::new();
    if let Some(obj) = attrs
        .get("last_analysis_results")
        .and_then(|r| r.as_object())
    {
        for (engine, res) in obj {
            let category = res
                .get("category")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            // Keep only flagging engines — the clean list is noise.
            if category == "malicious" || category == "suspicious" {
                detections.push(EngineDetection {
                    engine: engine.clone(),
                    category,
                    result: res
                        .get("result")
                        .and_then(|r| r.as_str())
                        .map(|s| s.to_string()),
                });
            }
        }
        detections.sort_by(|a, b| a.engine.cmp(&b.engine));
    }

    let threat_label = attrs
        .get("popular_threat_classification")
        .and_then(|p| p.get("suggested_threat_label"))
        .and_then(|l| l.as_str())
        .map(|s| s.to_string());

    let sha256 = attrs
        .get("sha256")
        .and_then(|s| s.as_str())
        .or_else(|| data.get("id").and_then(|s| s.as_str()))
        .unwrap_or("")
        .to_string();

    Ok(VtResult {
        sha256,
        md5: attrs
            .get("md5")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string()),
        harmless,
        suspicious,
        malicious,
        undetected,
        timeout,
        total_engines: harmless
            .saturating_add(suspicious)
            .saturating_add(malicious)
            .saturating_add(undetected)
            .saturating_add(timeout),
        threat_label,
        meaningful_name: attrs
            .get("meaningful_name")
            .and_then(|s| s.as_str())
            .map(|s| s.to_string()),
        reputation_score: attrs.get("reputation").and_then(|r| r.as_i64()),
        first_submission: attrs.get("first_submission_date").and_then(|r| r.as_i64()),
        last_analysis: attrs.get("last_analysis_date").and_then(|r| r.as_i64()),
        detections,
    })
}
