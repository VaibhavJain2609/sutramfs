# sutram-analyze

Forensic **analysis layer** for the SUTRAM-FS family. The parser crates
(`sutram-fat`, `sutram-ntfs`, `sutram-ext4`, …) mount disk images and stream
`FsEntry` records; `sutram-analyze` consumes those streams (and the raw
`ByteSource` beneath them) to answer examiner questions: *what is this
file's hash, does this image verify, when did things happen, which files
look evil, where does this string occur?*

## Features

- **`hash`** — pure-Rust streaming SHA-256, SHA-1 and MD5 (no ring/openssl,
  verified against the FIPS/RFC test vectors). `hash_entry` digests one
  `FsEntry` in a single pass; `verify_acquisition` / `verify_source` hash an
  EWF (`E01`) image's decoded media bytes and compare them against the
  acquisition hashes stored in the image (`Verified` / `Mismatch` /
  `NotAvailable`).
- **`entropy`** — Shannon entropy over arbitrary byte ranges
  (`range_entropy`) and file entries (`entry_entropy`, reads capped at
  8 MiB for large files), plus a chi-square uniformity statistic.
  Entropy > 7.5 bits/byte is flagged as packed/encrypted/compressed.
- **`timeline`** — MACB timeline built from a `walk()` stream
  (`Timeline::build`), sorted, capped, and renderable as CSV
  (`date,time,MACB,path`), JSONL, or a TSK bodyfile. Deletion timestamps
  (`dtime`-style fields) are emitted as `d` events.
- **`suspicion`** — aggregate 0–100 risk scoring (`score_entry`) combining
  magic-mismatch severity, high entropy, deleted-but-recoverable files with
  suspicious names, double extensions, executables in user-writable paths,
  hidden/orphan meta flags, and optional reputation verdicts from
  `sutram-reputation`. Every point is explained in `reasons`.
- **`grep`** — binary-safe keyword search (`search`): literal,
  case-insensitive, and hex patterns (with `??` wildcard bytes) over
  `read_file` streams, capped per entry, yielding `SearchHit`s with ±32 B
  of context. Directories and symlinks are skipped.

## Usage

```rust,no_run
use std::sync::Arc;
use sutram_fs::{FileSystem, FsParser, DetectConfidence};
use sutram_io::{into_arc, FileSource};
use sutram_analyze::{hash, entropy, timeline, suspicion, grep};

let src = into_arc(FileSource::open("image.E01")?);
let parser = sutram_fat::FatParser;
if parser.detect(src.as_ref()) >= DetectConfidence::Medium {
    let fs = parser.mount(src)?;
    for item in fs.walk() {
        let entry = item?;
        let h = hash::hash_entry(fs.as_ref(), &entry)?;
        let e = entropy::entry_entropy(fs.as_ref(), &entry)?;
        let s = suspicion::score_entry(&entry, &suspicion::Signals {
            entropy: Some(&e),
            reputation: None,
        });
        println!("{} sha256={} H={:.2} score={}", entry.path, h.sha256, e.entropy, s.score);
    }
    let tl = timeline::Timeline::build(fs.as_ref());
    print!("{}", tl.to_csv());
}
# Ok::<(), sutram_fs::FsError>(())
```

## Design rules

Same contract as the parsers (see `CONVENTIONS.md`):

- **Read-only.** Everything works through `&dyn FileSystem` /
  `&dyn ByteSource`; there is no write path.
- **Bounded memory.** Entry contents are streamed in fixed-size chunks;
  per-entry reads are capped (`hash` reads everything by design — hashing
  *is* a full read; `entropy` caps at 8 MiB; `grep` caps per entry;
  `Timeline` caps total events).
- **No panics on untrusted input** — errors are `sutram_fs::FsError`
  values; corrupt walk items become error records, not aborts.
- **Explainable output.** `Suspicion::reasons` and `AcqVerification`
  mismatches name the exact signal and values that fired.

## Known limitations

- `verify_acquisition` supports single-segment EWF (E01) images only —
  the `EwfSource` limit. Raw `dd` images carry no stored hash, so they
  always report `NotAvailable`.
- `entry_entropy` samples at most the first 8 MiB of a file — entropy of
  a sparse tail (e.g. appended encrypted blob) can be missed.
- `grep` is a single-pass substring scan — no regex, no UTF-16 transcoding
  (search for UTF-16 text via hex patterns like `6f 00 6f 00`).
- `suspicion` scoring is a heuristic triage aid, not a verdict — the
  point schedule is documented in `suspicion.rs` and every point is
  attributed in `reasons`.
- Bodyfile output has no slot for deletion time (`dtime`); deleted
  entries still emit their M/A/C/B times. Use CSV/JSONL for `d` events.

## License

Dual-licensed under MIT or Apache-2.0, at your option.
