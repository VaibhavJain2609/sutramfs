//! Offline unit tests — every test here runs with default features and
//! no network. The `net` feature's only untestable-offline piece is
//! `UreqTransport` itself; all VT logic is exercised through a mock
//! [`HttpTransport`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sutram_fs::{EntryKind, FsEntry, FsEntryStatus, RecoveryState};
use sutram_magic::{check_entry, Severity};

use crate::*;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn vt_json(sha: &str, malicious: u32, suspicious: u32, harmless: u32, undetected: u32) -> String {
    format!(
        r#"{{
        "data": {{
            "id": "{sha}",
            "type": "file",
            "attributes": {{
                "md5": "44d88612fea8a8f36de82e1278abb02f",
                "sha256": "{sha}",
                "meaningful_name": "evil.exe",
                "reputation": -42,
                "first_submission_date": 1600000000,
                "last_analysis_date": 1700000000,
                "last_analysis_stats": {{
                    "harmless": {harmless},
                    "malicious": {malicious},
                    "suspicious": {suspicious},
                    "undetected": {undetected},
                    "timeout": 0
                }},
                "popular_threat_classification": {{
                    "suggested_threat_label": "trojan.x/dloader"
                }},
                "last_analysis_results": {{
                    "EngineA": {{"category": "malicious", "result": "Trojan.X"}},
                    "EngineB": {{"category": "undetected", "result": null}},
                    "EngineC": {{"category": "suspicious", "result": "Suspicious.X"}}
                }}
            }}
        }}
    }}"#
    )
}

fn vt_clean_json(sha: &str) -> String {
    vt_json(sha, 0, 0, 60, 12)
}

/// Mock transport: canned `status -> body` responses keyed by URL suffix,
/// counting requests and optionally sleeping to expose races.
struct MockTransport {
    responses: HashMap<String, (u16, String)>,
    calls: std::sync::Arc<AtomicUsize>,
    delay: Option<Duration>,
    default: (u16, String),
}

impl MockTransport {
    fn new(default: (u16, String)) -> Self {
        MockTransport {
            responses: HashMap::new(),
            calls: std::sync::Arc::new(AtomicUsize::new(0)),
            delay: None,
            default,
        }
    }

    fn with_delay(mut self, d: Duration) -> Self {
        self.delay = Some(d);
        self
    }

    fn counter(&self) -> std::sync::Arc<AtomicUsize> {
        std::sync::Arc::clone(&self.calls)
    }
}

impl HttpTransport for MockTransport {
    fn request(
        &self,
        _method: HttpMethod,
        url: &str,
        _headers: &[(&str, &str)],
        _body: Option<&[u8]>,
    ) -> Result<HttpResponse, RepError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(d) = self.delay {
            std::thread::sleep(d);
        }
        let (status, body) = self
            .responses
            .iter()
            .find(|(k, _)| url.ends_with(k.as_str()))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| self.default.clone());
        Ok(HttpResponse { status, body })
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}

fn service_with(mock: MockTransport) -> ReputationService {
    let mut cfg = RepConfig::default();
    cfg.api_key = Some("test-key".to_string());
    cfg.requests_per_minute = 0; // unlimited — tests shouldn't sleep
    ReputationService::with_transport(cfg, Box::new(mock))
}

fn file_entry(name: &str) -> FsEntry {
    FsEntry {
        path: format!("/docs/{name}"),
        name: name.to_string(),
        entry_id: 42,
        kind: EntryKind::File,
        size: 4096,
        disk_offset: 0x4000,
        allocated_ranges: vec![(0x8000, 4096)],
        timestamps: Default::default(),
        status: FsEntryStatus::Live,
        meta: HashMap::new(),
        magic: None,
    }
}

// ---------------------------------------------------------------------------
// VT response parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_vt_report_happy() {
    let vt = parse_vt_file_report(&vt_json(SHA, 41, 1, 30, 0)).unwrap();
    assert_eq!(vt.sha256, SHA);
    assert_eq!(vt.md5.as_deref(), Some("44d88612fea8a8f36de82e1278abb02f"));
    assert_eq!(vt.malicious, 41);
    assert_eq!(vt.suspicious, 1);
    assert_eq!(vt.total_engines, 72);
    assert_eq!(vt.threat_label.as_deref(), Some("trojan.x/dloader"));
    assert_eq!(vt.meaningful_name.as_deref(), Some("evil.exe"));
    assert_eq!(vt.reputation_score, Some(-42));
    // Only flagging engines kept.
    assert_eq!(vt.detections.len(), 2);
    assert!(vt
        .detections
        .iter()
        .any(|d| d.engine == "EngineA" && d.result.as_deref() == Some("Trojan.X")));
    assert!(vt.detections.iter().all(|d| d.engine != "EngineB"));
}

#[test]
fn parse_vt_report_rejects_garbage() {
    assert!(parse_vt_file_report("not json").is_err());
    assert!(parse_vt_file_report("{}").is_err());
    assert!(parse_vt_file_report(r#"{"data":{}}"#).is_err());
    assert!(parse_vt_file_report(r#"{"error":{"message":"QuotaExceeded"}}"#).is_err());
}

#[test]
fn parse_vt_report_lenient_on_missing_stats() {
    // A minimal record with no analysis stats parses to zeros, not error.
    let body =
        format!(r#"{{"data":{{"id":"{SHA}","type":"file","attributes":{{"sha256":"{SHA}"}}}}}}"#);
    let vt = parse_vt_file_report(&body).unwrap();
    assert_eq!(vt.total_engines, 0);
    assert!(vt.detections.is_empty());
}

// ---------------------------------------------------------------------------
// Verdict classification
// ---------------------------------------------------------------------------

#[test]
fn verdict_thresholds() {
    let t = VerdictThresholds::default();
    let mk = |m, s, h, u| parse_vt_file_report(&vt_json(SHA, m, s, h, u)).unwrap();
    assert_eq!(t.classify(&mk(41, 1, 30, 0)), RepVerdict::Malicious);
    assert_eq!(t.classify(&mk(5, 0, 60, 7)), RepVerdict::Malicious);
    assert_eq!(t.classify(&mk(2, 0, 60, 10)), RepVerdict::Suspicious);
    assert_eq!(t.classify(&mk(0, 3, 60, 9)), RepVerdict::Suspicious);
    assert_eq!(t.classify(&mk(0, 0, 60, 12)), RepVerdict::Clean);
    assert_eq!(t.classify(&mk(0, 0, 0, 0)), RepVerdict::Unknown);
    // Configurable: stricter threshold demotes 4 detections to Suspicious.
    let strict = VerdictThresholds {
        malicious_at: 10,
        suspicious_at: 1,
    };
    assert_eq!(strict.classify(&mk(4, 0, 60, 8)), RepVerdict::Suspicious);
}

// ---------------------------------------------------------------------------
// Service: lookup / cache / dedup / offline / bridge
// ---------------------------------------------------------------------------

#[test]
fn lookup_malicious_via_mock() {
    let svc = service_with(MockTransport::new((200, vt_json(SHA, 41, 1, 30, 0))));
    let rep = svc.lookup(SHA);
    assert_eq!(rep.verdict, RepVerdict::Malicious);
    assert_eq!(rep.tally().as_deref(), Some("41/72"));
    assert!(rep
        .reasons
        .iter()
        .any(|r| r.contains("41/72") && r.contains("trojan.x/dloader")));
}

#[test]
fn lookup_404_is_unknown_not_failure() {
    let svc = service_with(MockTransport::new((404, "{}".to_string())));
    let rep = svc.lookup(SHA);
    assert_eq!(rep.verdict, RepVerdict::Unknown);
    assert!(rep.reasons.iter().any(|r| r.contains("404")));
}

#[test]
fn invalid_hash_never_queries() {
    let mock = MockTransport::new((200, vt_clean_json(SHA)));
    let svc = service_with(mock);
    let rep = svc.lookup("not-a-hash");
    assert_eq!(rep.verdict, RepVerdict::NotQueried);
    // The mock was consumed by the service; assert via a fresh lookup count…
    // simpler: pending set must not contain it.
    assert!(svc.pending_hashes().is_empty());
}

#[test]
fn mem_cache_serves_second_lookup() {
    let svc = service_with(MockTransport::new((200, vt_json(SHA, 41, 1, 30, 0))));
    let a = svc.lookup(SHA);
    let b = svc.lookup(SHA);
    assert_eq!(a.verdict, RepVerdict::Malicious);
    assert_eq!(b.verdict, RepVerdict::Malicious);
    assert!(b.reasons.iter().any(|r| r.contains("cached")));
}

#[test]
fn mem_cache_only_hits_transport_once() {
    let mock = MockTransport::new((200, vt_json(SHA, 41, 1, 30, 0)));
    let counter = mock.counter();
    let svc = service_with(mock);
    svc.lookup(SHA);
    svc.lookup(SHA);
    svc.lookup(&SHA.to_uppercase()); // case-insensitive normalisation
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "cache should have served lookups 2 and 3"
    );
}

#[test]
fn mem_cache_ttl_expiry() {
    let now = crate::util::unix_now();
    let mut cache = crate::cache::MemCache::default();
    let vt = parse_vt_file_report(&vt_clean_json(SHA)).unwrap();
    cache.put(SHA, crate::cache::Cached::Found(Box::new(vt)), now);
    // Within TTL → hit.
    assert!(cache.get(SHA, 3600, now + 100).is_some());
    // Past TTL → miss.
    assert!(cache.get(SHA, 3600, now + 3601).is_none());
}

#[test]
fn negative_404_is_cached() {
    let svc = service_with(MockTransport::new((404, "{}".to_string())));
    let a = svc.lookup(SHA);
    let b = svc.lookup(SHA);
    assert_eq!(a.verdict, RepVerdict::Unknown);
    assert_eq!(b.verdict, RepVerdict::Unknown);
    assert!(b.reasons.iter().any(|r| r.contains("cached")));
}

#[test]
fn concurrent_lookup_dedups_to_one_request() {
    let mock = MockTransport::new((200, vt_json(SHA, 41, 1, 30, 0)))
        .with_delay(Duration::from_millis(150));
    let counter = mock.counter();
    let svc = service_with(mock);
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..4).map(|_| s.spawn(|| svc.lookup(SHA))).collect();
        for h in handles {
            assert_eq!(h.join().unwrap().verdict, RepVerdict::Malicious);
        }
    });
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "4 concurrent lookups must collapse to 1 HTTP request"
    );
    // Followers share the leader's result; reasons mark the dedup.
    let rep = svc.lookup(SHA);
    assert_eq!(rep.verdict, RepVerdict::Malicious);
}

#[test]
fn http_error_status_still_classified() {
    // ureq surfaces 4xx as Err(RepError::Http) rather than Ok — a 404 must
    // still map to Unknown, not NotQueried.
    struct ErrStatus(u16);
    impl HttpTransport for ErrStatus {
        fn request(
            &self,
            _m: HttpMethod,
            _u: &str,
            _h: &[(&str, &str)],
            _b: Option<&[u8]>,
        ) -> Result<HttpResponse, RepError> {
            Err(RepError::Http {
                status: self.0,
                body: String::new(),
            })
        }
        fn name(&self) -> &'static str {
            "err-status"
        }
    }
    let mut cfg = RepConfig::default();
    cfg.requests_per_minute = 0;
    let svc = ReputationService::with_transport(cfg, Box::new(ErrStatus(404)));
    assert_eq!(svc.lookup(SHA).verdict, RepVerdict::Unknown);
    // And it was negatively cached.
    assert!(svc.lookup(SHA).reasons.iter().any(|r| r.contains("cached")));
}

#[test]
fn transport_failure_records_pending() {
    struct Failing;
    impl HttpTransport for Failing {
        fn request(
            &self,
            _m: HttpMethod,
            _u: &str,
            _h: &[(&str, &str)],
            _b: Option<&[u8]>,
        ) -> Result<HttpResponse, RepError> {
            Err(RepError::Transport("connection refused".to_string()))
        }
        fn name(&self) -> &'static str {
            "failing"
        }
    }
    let mut cfg = RepConfig::default();
    cfg.requests_per_minute = 0;
    let svc = ReputationService::with_transport(cfg, Box::new(Failing));
    let rep = svc.lookup(SHA);
    assert_eq!(rep.verdict, RepVerdict::NotQueried);
    assert!(svc.pending_hashes().contains(&SHA.to_string()));
}

#[test]
fn offline_mode_queues_pending() {
    let svc = ReputationService::new(RepConfig::default());
    assert!(svc.is_offline());
    let rep = svc.lookup(SHA);
    assert_eq!(rep.verdict, RepVerdict::NotQueried);
    assert!(rep.reasons.iter().any(|r| r.contains("offline")));
    assert_eq!(svc.pending_hashes(), vec![SHA.to_string()]);
}

#[test]
fn sneaker_net_bridge_roundtrip() {
    // Air-gapped side: queue hashes.
    let airgap = ReputationService::new(RepConfig::default());
    airgap.lookup(SHA);
    let exported = airgap.export_pending();
    let hashes = decode_pending(&exported).unwrap();
    assert_eq!(hashes, vec![SHA.to_string()]);

    // Connected side: fetch and encode results.
    let online = service_with(MockTransport::new((200, vt_json(SHA, 41, 1, 30, 0))));
    let reports = online.lookup_many(&[SHA]);
    let vts: Vec<VtResult> = reports.iter().filter_map(|r| r.vt.clone()).collect();
    let results_json = encode_results(&vts);

    // Back on the air-gapped side: import answers the queued hash.
    let n = airgap.import_results(&results_json).unwrap();
    assert_eq!(n, 1);
    assert!(airgap.pending_hashes().is_empty());
    let rep = airgap.lookup(SHA);
    assert_eq!(
        rep.verdict,
        RepVerdict::Malicious,
        "imported result must answer the lookup offline"
    );
}

#[test]
fn import_results_rejects_wrong_format() {
    let svc = ReputationService::new(RepConfig::default());
    assert!(svc
        .import_results(r#"{"format":"bogus","results":[]}"#)
        .is_err());
    assert!(svc.import_results("not json").is_err());
}

#[test]
fn lookup_many_dedups_and_preserves_order() {
    let other = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    let svc = service_with(MockTransport::new((200, vt_clean_json(SHA))));
    let reports = svc.lookup_many(&[SHA, other, SHA]);
    assert_eq!(reports.len(), 3);
    assert_eq!(reports[0].sha256, SHA);
    assert_eq!(reports[1].sha256, other);
    assert_eq!(reports[2].sha256, SHA);
    assert!(reports.iter().all(|r| r.verdict == RepVerdict::Clean));
}

#[test]
fn lookup_many_offline_records_all_pending() {
    let svc = ReputationService::new(RepConfig::default());
    let reports = svc.lookup_many(&[
        SHA,
        "b3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ]);
    assert!(reports.iter().all(|r| r.verdict == RepVerdict::NotQueried));
    assert_eq!(svc.pending_hashes().len(), 2);
}

// ---------------------------------------------------------------------------
// Rate limiter math (clock-injected, no sleeping)
// ---------------------------------------------------------------------------

#[test]
fn token_bucket_burst_then_refill() {
    let mut b = TokenBucket::new(4); // VT public tier
    let t0 = Instant::now();
    // Fresh bucket: a burst of 4 is allowed.
    for _ in 0..4 {
        assert!(b.try_take(t0));
    }
    // 5th is denied; next token in ~15 s (60/4).
    assert!(!b.try_take(t0));
    let wait = b.time_until_ready(t0);
    assert!(
        wait >= Duration::from_secs(10) && wait <= Duration::from_secs(20),
        "expected ~15 s wait, got {wait:?}"
    );
    // 15 s later the token has refilled.
    assert!(b.try_take(t0 + Duration::from_secs(16)));
    // …but not two in a row.
    assert!(!b.try_take(t0 + Duration::from_secs(16)));
    // 30 s more → two tokens available (4/min = 1/15s).
    assert!(b.try_take(t0 + Duration::from_secs(46)));
    assert!(b.try_take(t0 + Duration::from_secs(61)));
}

#[test]
fn token_bucket_unlimited() {
    let mut b = TokenBucket::unlimited();
    let t0 = Instant::now();
    for _ in 0..100 {
        assert!(b.try_take(t0));
    }
}

// ---------------------------------------------------------------------------
// Masquerade analysis
// ---------------------------------------------------------------------------

#[test]
fn docx_with_pe_content_escalates_high() {
    let entry = file_entry("invoice.docx");
    let magic = check_entry(&entry.name, b"MZ\x90\x00\x03\x00\x00\x00PE\0\0");
    assert!(magic.mismatch);
    let sus = analyze_masquerade(&entry, &magic);
    assert_eq!(sus.severity, Severity::High);
    assert!(sus.magic_mismatch);
    assert!(sus
        .recommended_actions
        .iter()
        .any(|a| a.contains("sandbox")));
    assert!(sus
        .recommended_actions
        .iter()
        .any(|a| a.contains("reputation")));
}

#[test]
fn docx_with_zip_content_is_consistent() {
    let entry = file_entry("report.docx");
    // Real OOXML: PK zip.
    let magic = check_entry(&entry.name, b"PK\x03\x04\x14\x00\x00\x00");
    assert!(!magic.mismatch);
    let sus = analyze_masquerade(&entry, &magic);
    assert_eq!(sus.severity, Severity::Info);
    assert!(sus.recommended_actions.is_empty());
}

#[test]
fn png_that_is_zip_is_suspicious_not_high() {
    let entry = file_entry("photo.png");
    let magic = check_entry(&entry.name, b"PK\x03\x04\x14\x00\x00\x00");
    assert!(magic.mismatch);
    let sus = analyze_masquerade(&entry, &magic);
    assert_eq!(sus.severity, Severity::Suspicious);
    assert!(sus
        .recommended_actions
        .iter()
        .any(|a| a.contains("container") || a.contains("inspect")));
}

#[test]
fn deleted_entry_notes_recovery_state() {
    let mut entry = file_entry("gone.exe");
    entry.status = FsEntryStatus::Deleted {
        recovery: RecoveryState::PartiallyOverwritten {
            recovered_bytes: 100,
            total_bytes: 4096,
        },
    };
    let magic = check_entry(&entry.name, b"MZ\x90\x00");
    let sus = analyze_masquerade(&entry, &magic);
    assert!(sus
        .reasons
        .iter()
        .any(|r| r.contains("partially overwritten")));
}

// ---------------------------------------------------------------------------
// Pipeline combiner
// ---------------------------------------------------------------------------

#[test]
fn analyze_file_merges_magic_and_reputation() {
    let svc = service_with(MockTransport::new((200, vt_json(SHA, 41, 1, 30, 0))));
    let cfg = AnalysisConfig {
        reputation: Some(&svc),
        ..Default::default()
    };
    let entry = file_entry("invoice.docx");
    let a = analyze_file(&entry, b"MZ\x90\x00\x03PE\0\0", SHA, &cfg);
    assert_eq!(a.severity, Severity::High);
    assert!(a.magic.mismatch);
    assert_eq!(
        a.reputation.as_ref().unwrap().verdict,
        RepVerdict::Malicious
    );
    // Court-explainable one-liner.
    assert!(a.summary.contains("declared OOXML document"));
    assert!(a.summary.contains("PE/COFF"));
    assert!(a.summary.contains("VT 41/72"));
    assert!(a.summary.contains("High suspicion"));
}

#[test]
fn analyze_file_offline_notes_not_queried() {
    let svc = ReputationService::new(RepConfig::default());
    let cfg = AnalysisConfig {
        reputation: Some(&svc),
        ..Default::default()
    };
    let entry = file_entry("invoice.docx");
    let a = analyze_file(&entry, b"MZ\x90\x00\x03PE\0\0", SHA, &cfg);
    assert_eq!(
        a.reputation.as_ref().unwrap().verdict,
        RepVerdict::NotQueried
    );
    assert!(a.summary.contains("not queried"));
    assert_eq!(a.severity, Severity::High, "masquerade alone is High");
    assert!(svc.pending_hashes().contains(&SHA.to_string()));
}

#[test]
fn analyze_file_clean_consistent_file() {
    let svc = service_with(MockTransport::new((200, vt_clean_json(SHA))));
    let cfg = AnalysisConfig {
        reputation: Some(&svc),
        ..Default::default()
    };
    let entry = file_entry("report.docx");
    let a = analyze_file(&entry, b"PK\x03\x04\x14\x00\x00\x00", SHA, &cfg);
    assert_eq!(a.severity, Severity::Info);
    assert_eq!(a.reputation.as_ref().unwrap().verdict, RepVerdict::Clean);
    assert!(a.summary.contains("VT clean"));
}

#[test]
fn analyze_file_uses_parser_magic_when_present() {
    let mut entry = file_entry("pre.docx");
    entry.magic = Some(check_entry(&entry.name, b"MZ\x90\x00"));
    let cfg = AnalysisConfig::default();
    // Empty header would give "no magic" — the pre-set verdict must win.
    let a = analyze_file(&entry, b"", SHA, &cfg);
    assert!(a.magic.mismatch);
}

#[test]
fn rule_scanner_hit_raises_severity() {
    struct TestScanner;
    impl RuleScanner for TestScanner {
        fn name(&self) -> &str {
            "test-yara"
        }
        fn scan(&self, _p: &str, _h: &[u8]) -> Result<Vec<RuleHit>, RepError> {
            Ok(vec![RuleHit {
                rule: "MALW_Test_Rule".to_string(),
                tags: vec!["trojan".to_string()],
                meta: HashMap::new(),
                severity: Some(Severity::High),
            }])
        }
    }
    let cfg = AnalysisConfig {
        scanner: Some(&TestScanner),
        ..Default::default()
    };
    let entry = file_entry("boring.txt");
    let a = analyze_file(&entry, b"just text", SHA, &cfg);
    assert_eq!(a.rule_hits.len(), 1);
    assert_eq!(a.severity, Severity::High);
    assert!(a
        .suspicion
        .reasons
        .iter()
        .any(|r| r.contains("MALW_Test_Rule")));
}

// ---------------------------------------------------------------------------
// Opt-in boundary: file upload
// ---------------------------------------------------------------------------

#[test]
fn submit_file_refused_without_allow_uploads() {
    // Even WITH a transport configured, the default config refuses.
    let svc = service_with(MockTransport::new((
        200,
        r#"{"data":{"id":"a1"}}"#.to_string(),
    )));
    let err = svc.submit_file("evil.exe", b"MZ").unwrap_err();
    assert!(matches!(err, RepError::Unsupported(_)));
}

#[test]
fn submit_file_refused_offline_even_when_allowed() {
    let mut cfg = RepConfig::default();
    cfg.allow_uploads = true;
    let svc = ReputationService::new(cfg); // no transport
    let err = svc.submit_file("evil.exe", b"MZ").unwrap_err();
    assert!(matches!(err, RepError::Unsupported(_)));
}

#[test]
fn submit_file_happy_path_with_explicit_opt_in() {
    let mock = MockTransport::new((
        200,
        r#"{"data":{"id":"analysis-42","type":"analysis"}}"#.to_string(),
    ));
    let mut cfg = RepConfig::default();
    cfg.allow_uploads = true;
    cfg.requests_per_minute = 0;
    let svc = ReputationService::with_transport(cfg, Box::new(mock));
    let id = svc.submit_file("evil.exe", b"MZ").unwrap();
    assert_eq!(id, "analysis-42");
}

// ---------------------------------------------------------------------------
// sqlite cache (feature `cache`)
// ---------------------------------------------------------------------------

#[cfg(feature = "cache")]
#[test]
fn sqlite_cache_roundtrip_and_ttl() {
    let c = SqliteCache::in_memory().unwrap();
    let vt = parse_vt_file_report(&vt_json(SHA, 41, 1, 30, 0)).unwrap();
    c.put(SHA, &crate::cache::Cached::Found(Box::new(vt)))
        .unwrap();
    // min_fetched = 0 accepts anything stored.
    match c.get(SHA, 0) {
        Some(crate::cache::Cached::Found(v)) => assert_eq!(v.malicious, 41),
        _ => panic!("expected cached Found"),
    }
    // A min_fetched in the future = expired → miss.
    assert!(c.get(SHA, i64::MAX).is_none());
    // Negative rows round-trip too.
    c.put(SHA, &crate::cache::Cached::NotFound).unwrap();
    assert!(matches!(
        c.get(SHA, 0),
        Some(crate::cache::Cached::NotFound)
    ));
}

#[cfg(feature = "cache")]
#[test]
fn service_uses_disk_cache() {
    let svc = service_with(MockTransport::new((200, vt_json(SHA, 41, 1, 30, 0))))
        .with_disk_cache(SqliteCache::in_memory().unwrap());
    let a = svc.lookup(SHA);
    assert_eq!(a.verdict, RepVerdict::Malicious);
    // Second lookup hits a cache layer (mem mirrors disk).
    let b = svc.lookup(SHA);
    assert_eq!(b.verdict, RepVerdict::Malicious);
}
