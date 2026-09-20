# sutram-fs

Core forensic filesystem-parser traits and types for the **SUTRAM-FS**
family of Rust crates. Every parser (`sutram-fat`, `sutram-ntfs`,
`sutram-ext4`, `sutram-apfs`, …) implements the surface defined here.

Part of the SUTRAM-FS project — see `CONVENTIONS.md` at the repository root
for the contract every crate follows.

## What this crate is

The contract layer. It defines:

- `trait FsParser` — `detect(&dyn ByteSource) -> DetectConfidence` and
  `mount`/`mount_with` producing a `Box<dyn FileSystem>`.
- `trait FileSystem` — `info()`, `source()`, streaming `walk()`,
  `read_file`/`read_file_at`, `deleted_entries()`, `unallocated_ranges()`
  and `carve_region()` (default magic-scan implementation included).
- `FsEntry` — the evidence record: path, kind, size, `disk_offset` +
  `allocated_ranges` provenance, MACB `Timestamps`, `status`
  (`Live | Deleted { recovery: RecoveryState }`), format-specific `meta`,
  and a per-file `MagicVerdict` from `sutram-magic`.
- `FsError` — `Corrupt{offset,msg}`, `Truncated{offset,needed,available}`,
  `Unsupported`, `Io`, `NotFound`, `InvalidInput`. Offsets everywhere, so
  every error is citable.
- `RecoveryState` (`Intact | PartiallyOverwritten{recovered_bytes,
  total_bytes} | Unrecoverable | Unknown`), `RecoveryReport`, `CarveHit`.
- `util` — path joining/sanitising, orphan paths, civil→Unix-nanos
  timestamp math.

## Forensic guarantees (enforced by the trait design)

- **Read-only** — parsers see only `ByteSource`; no write API exists.
- **Bounded memory** — `walk()` is a streaming iterator; `read_file`
  returns a `Read`, not a `Vec`.
- **No panics on untrusted input** — corruption is an `FsError` item in
  the walk stream (lenient by default; `MountOptions::strict` opts out).
- **Provenance** — `disk_offset` and `allocated_ranges` cite the exact
  bytes behind every record.
- **Deleted-data first-class** — deleted entries, orphans and slack are
  emitted, not filtered.

## Usage

```rust,no_run
use std::sync::Arc;
use sutram_fs::{FsParser, DetectConfidence, FsEntryStatus};
use sutram_io::{ByteSource, FileSource};

fn run(parser: &dyn FsParser, image: &str) -> sutram_fs::Result<()> {
    let src = Arc::new(FileSource::open(image)?) as Arc<dyn ByteSource>;
    if parser.detect(src.as_ref()) >= DetectConfidence::Medium {
        let fs = parser.mount(src)?;
        for item in fs.walk() {
            match item {
                Ok(e) => println!("{}\t{}\t{:?}", e.path, e.size, e.status),
                Err(e) => eprintln!("corruption: {e}"),
            }
        }
    }
    Ok(())
}
```

## Deleted / recovery semantics

`FsEntry::status` is `Live` or `Deleted { recovery }`. `recovery` is a
`RecoveryState` quantifying data survival; `allocated_ranges` narrows to
the still-recoverable extents for partially overwritten files, and
`read_file` returns exactly those bytes. Orphans are emitted under
`/$ORPHANED/…`.

## Known limitations

This crate defines traits/types only — it parses no filesystem itself.
See the per-parser crates for format coverage.

## License

Dual-licensed under MIT or Apache-2.0, at your option. See `LICENSE-MIT`
and `LICENSE-APACHE`.
