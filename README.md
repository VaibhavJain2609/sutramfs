# sutram-reputation

File reputation and suspicious-file analysis for the SUTRAM-FS forensic
parser family. Given a filesystem entry, its header bytes, and its content
hash, `analyze_file` produces one `FileAssessment`: the `sutram-magic`
extension↔content verdict, a VirusTotal reputation report, masquerade
escalation, optional rule-scanner hits, a combined severity, merged
recommended actions, and a one-line court-explainable summary such as:

```text
/docs/invoice.docx: declared OOXML document; content is PE/COFF Windows
executable; VT 41/72 engines flag trojan.x/dloader → High suspicion
```

## Forensic design

* **Air-gap first.** The default build has **no networking, no TLS, no C
  code** — `serde`/`serde_json` plus `sutram-fs`/`sutram-magic` only.
  Offline lookups return `RepVerdict::NotQueried` and record the hash in a
  pending queue; `export_pending()`/`import_results()` carry that queue to
  a connected host and back (the sneaker-net bridge).
* **Hash-first only.** The default VT path is exactly one request,
  `GET /api/v3/files/{sha256}` — no file bytes ever leave the host.
* **`NotQueried` ≠ `Unknown`.** "We never asked" and "the service has no
  record" are different evidentiary statements and stay distinct.
* **Reasons are court-explainable.** Every report carries human-readable
  `reasons` strings, not just enum values.

## Opt-in boundaries (non-negotiable)

| Action | Default | How to enable |
|---|---|---|
| Hash lookup (`files/{sha256}`) | OFF — no transport | feature `net` or a custom `HttpTransport` |
| File-content upload | **Never** via `analyze_file` | `RepConfig::allow_uploads = true` **and** an explicit `submit_file()` call |
| Sandbox hash query | OFF | feature `sandbox` + a `SandboxProvider` |
| Sandbox detonation (uploads content) | **Never** | implement `SandboxProvider::submit_file`; this crate never calls it |
| Persistent cache | in-memory only | feature `cache` (`SqliteCache`) |

Uploading seized evidence to VirusTotal (or detonating it in a remote
sandbox) discloses that your investigation holds the file and shares its
bytes with every subscriber — that is a legal/confidentiality decision,
not a library default.

## Features

```toml
[features]
default = []       # pure Rust, offline
net     = []       # ureq HTTP transport → ReputationService::virustotal(key)
cache   = []       # rusqlite persistent cache → SqliteCache
sandbox = []       # allow the pipeline to consult SandboxProvider::submit_hash
```

> **Documented dependency exceptions.** CONVENTIONS.md mandates pure-Rust
> deps. Two features break that rule *by design* and are off by default:
> `net` (ureq → rustls → ring, contains asm/C) and `cache` (rusqlite
> bundled → libsqlite3-sys, C). The default build is pure Rust.

## Optimizations

* **In-memory + optional SQLite cache** keyed by hash with a TTL
  (default 7 days). Negative results (VT 404s) are cached too — re-walking
  an image doesn't burn quota on hashes already known to be absent.
* **Concurrent dedup** — simultaneous lookups of the same hash collapse
  onto one in-flight request; followers share the leader's report.
* **Token-bucket rate limiter** honouring VT's 4 req/min public tier
  (`RepConfig::requests_per_minute`; `0` disables for private keys).
* **`lookup_many(hashes)`** batch prefetch: dedups input, fans out across
  `max_workers` threads, all funnelled through the one limiter.

## Usage

```rust,ignore
use sutram_reputation::*;

// Air-gapped examiner host — no transport.
let rep = ReputationService::new(RepConfig::default());

for entry in fs.walk().flatten() {
    if entry.kind != EntryKind::File { continue; }
    let header = read_header(&entry);          // ≤ 4 KiB
    let sha256 = sha256_file(&entry);          // caller hashes
    let a = analyze_file(&entry, &header, &sha256,
                         &AnalysisConfig { reputation: Some(&rep),
                                           ..Default::default() });
    if a.severity >= Severity::Suspicious {
        println!("{}", a.summary);
    }
}

// Later, on a connected host:
//   let pending = rep.export_pending();               // → JSON file → USB
//   let hashes = decode_pending(&pending).unwrap();
//   let refs: Vec<&str> = hashes.iter().map(String::as_str).collect();
//   let online = ReputationService::virustotal(&key); // feature `net`
//   let reports = online.lookup_many(&refs);
//   let vts: Vec<VtResult> =
//       reports.iter().filter_map(|r| r.vt.clone()).collect();
//   let results = encode_results(&vts);               // → USB back
//   rep.import_results(&results).unwrap();            // fills the cache,
//                                                     // clears pending
```

The `RuleScanner` trait is the YARA hook point — implement it over
`yara-x` (or any matcher) in your platform crate; `sutram-reputation`
never depends on YARA itself. `SandboxProvider` is the Cuckoo/CAPE hook;
only `NullSandbox` ships here.

## Known limitations

* **Hash reputation is not innocence.** `Clean` means "no engine flagged
  this hash at lookup time"; `Unknown` means "VT has no record" — a novel
  payload scores `Unknown`, not `Malicious`. Read the reasons.
* **Public-tier quota.** At 4 req/min a large image takes a while; the
  cache, dedup, and negative-cache exist for exactly this reason. Private
  keys should raise `requests_per_minute`.
* **VT schema drift.** Parsing is lenient (missing fields → `None`/0),
  but a renamed field silently degrades rather than errors.
* **No full-file scanning.** `RuleScanner::scan` sees the same bounded
  header the magic check did — full-file rule scans are the caller's job.
* **`lookup_many` latency.** Workers overlap HTTP latency but the limiter
  serialises requests; batch of *n* uncached hashes ≈ *n*/4 minutes at
  public tier.
* **`sandbox` feature is advisory gating**, not enforcement — a provider
  impl could still upload bytes in `submit_hash`; vet your providers.

## License

Dual-licensed under MIT OR Apache-2.0. See `LICENSE-MIT` and
`LICENSE-APACHE`.
