# sutram-report

Forensic report generator and image differ for the SUTRAM-FS parser
family. Feed it any mounted `sutram_fs::FileSystem` — FAT, NTFS, ext4,
APFS, whatever `detect` found — and it walks the volume once, producing a
structured `Report` renderable as JSON, Markdown, or self-contained HTML.
`diff` compares two mounted images path-by-path.

No third-party dependencies: only the SUTRAM-FS family crates
(`sutram-io`/`sutram-fs`, plus `sutram-analyze` whose pure-Rust `Sha256`
provides the content hashing — reports/diffs hash real bytes with no
`*-sys` or digest-crate dependency).

## What a report contains

- **Volume summary** — fs type, label, UUID, geometry, image size, format
  extras.
- **Entry census** — counts by kind / live-vs-deleted / recovery state,
  byte totals, walk-error count.
- **Deleted-recovery table** — every deleted entry with intact / partial /
  lost classification and recovered/total bytes.
- **Magic-mismatch table** — extension↔content verdicts sorted worst
  severity first, with the parser's human-readable reasons.
- **Anomalies** — orphans (`/$ORPHANED/*`, orphan meta flags), suspicious
  metadata (`beyond_eod`, `lfn_checksum_ok=false`, carved/reused/unallocated
  inodes), and walk errors.
- **Per-file detail** — path, size, SHA-256 over *recoverable* bytes (with
  `hashed_bytes` so partial recovery/caps are explicit), MAC timestamps,
  and `disk_offset` + `allocated_ranges` provenance.
- **Examiner notes** — free text carried through verbatim.

## Usage

```rust
use std::sync::Arc;
use sutram_fs::FsParser;
use sutram_report::{generate, diff, ReportOptions, DiffOptions};

let fs = sutram_fat::FatParser.mount(Arc::new(image_bytes))?;
let report = generate(fs.as_ref(), &ReportOptions {
    title: "Case 2024-001".into(),
    examiner_notes: "…".into(),
    ..Default::default()
});
std::fs::write("report.json", report.to_json_pretty())?;
std::fs::write("report.md", report.to_markdown())?;
std::fs::write("report.html", report.to_html())?;

// Image diff:
let other = sutram_fat::FatParser.mount(Arc::new(other_bytes))?;
let d = diff(fs.as_ref(), other.as_ref(), &DiffOptions::default());
println!("{}", d.to_text());
```

`ImageDiff` buckets: `added` / `removed` (paths), `modified` (same path +
status; size, MAC times, then content hash — catches same-size
overwrites), `deleted_changes` (status/recovery transitions, e.g.
`live → deleted(intact)`). Both JSON and plain-text renderings.

## Deleted / recovery semantics

Inherited verbatim from the parser layer — the report *classifies*, it
does not re-judge: `allocated_ranges` for a deleted entry already lists
only surviving extents, so `recovered_bytes`/`total_bytes` and the
`intact`/`partial`/`lost` split are exactly what the parser proved.

## Known limitations

- Only SHA-256 is emitted (`sutram-analyze` also ships SHA-1/MD5 hashers
  for callers that need them); `hash_max_bytes` (default 64 MiB) caps
  per-file reads.
- `generate`/`diff` buffer the walk into memory — bounded by
  `max_entries` (default 1M); hitting the cap is an anomaly/truncation
  flag, not a panic.
- Path is the diff key: a rename reads as remove+add, and a FAT
  deleted-marker flip reads as a transition only when the rendered name
  is unchanged.
- `sutram-fat` is a dev-dependency (test corpus only); the library itself
  is parser-agnostic over `dyn FileSystem`.

## License

Dual-licensed under MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
