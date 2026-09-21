# sutram-archive

Forensic parsers for archive/container formats — **ZIP**, **TAR** and
**CPIO** — implementing the SUTRAM-FS contract (`sutram-fs` traits over
`sutram-io` byte sources). An archive is evidence: members become
`FsEntry` records with per-record `disk_offset` provenance, deleted and
hidden members are recovered, and every file's content gets a
`sutram-magic` verdict.

Part of the SUTRAM-FS project — see `CONVENTIONS.md` at the repository
root for the contract every crate follows.

## What these formats are

Archive formats are the oldest "filesystems in a file": a sequential
stream of per-member metadata records followed by member data. TAR (1979)
is a tape format — 512-byte header blocks, ustar/pax/GNU dialects. CPIO
(System III) has three on-disk dialects (newc, odc, binary). ZIP (1989)
stores a per-member *local header* inline and a *central directory* at
EOF — the discrepancy between the two is itself forensically interesting.

## Forensic features

- **ZIP** — EOCD scan (≤ 64 KiB + 22 B back from EOF), ZIP64, central
  directory walk, store/deflate decompression, self-extracting stubs,
  DOS timestamps + extra-field timestamps (`0x5455`, `0x000a`), archive
  and per-entry comments, local↔central anomaly flags, and *hidden
  members*: local file headers unreferenced by the central directory are
  emitted as `Deleted{Intact}` with `meta["hidden_entry"]=true`.
- **TAR** — ustar/v7/pax header validation via checksum, GNU `L`/`K`
  longname records, chained pax extended headers, GNU/pax sparse maps
  (holes read as zeros), duplicate-path supersession
  (`meta["superseded"]`), and members truncated by a cut archive tail →
  `Deleted{PartiallyOverwritten}`.
- **CPIO** — newc (070701/070702), odc (070707 ASCII) and binary
  (0x71C7, LE/BE) dialects; archive slack after `TRAILER!!!` is emitted
  as a carving-candidate deleted entry.

## Usage

```rust,no_run
use std::sync::Arc;
use sutram_archive::SutramArchiveParser;
use sutram_fs::{FsParser, DetectConfidence};
use sutram_io::{ByteSource, FileSource};

let src = Arc::new(FileSource::open("evidence.zip")?) as Arc<dyn ByteSource>;
if SutramArchiveParser.detect(src.as_ref()) >= DetectConfidence::Medium {
    let fs = SutramArchiveParser.mount(src)?;
    for item in fs.walk() {
        match item {
            Ok(e) => println!("{}\t{} B\t{:?}", e.path, e.size, e.status),
            Err(e) => eprintln!("corruption: {e}"),
        }
    }
}
# Ok::<(), sutram_fs::FsError>(())
```

Or mount a specific format directly: `ZipParser`, `TarParser`,
`CpioParser`.

## Deleted / recovery semantics

Archive "deletion" is structural, not flag-based: a member is recoverable
when its bytes survive inside the archive but no live record claims them.
ZIP local headers absent from the central directory are `Intact` when
their data span is fully present. A TAR member whose declared size runs
past the end of the image is `PartiallyOverwritten` with
`allocated_ranges` clamped to what exists. CPIO slack after `TRAILER!!!`
is `Unknown` — the bytes are carving ground, not a named member.

## Known limitations

- ZIP: only store (0) and deflate (8) decompression; bzip2/LZMA/zstd
  members are listed but `read_file` returns `Unsupported`. Encrypted
  members are flagged, not decrypted. Multi-disk archives are rejected.
- TAR: GNU `S` sparse headers and pax `GNU.sparse.*` maps are honoured;
  exotic typeflags (contiguous '7', dump 'D', …) degrade to `Other`.
- CPIO: the `070702` CRC variant's check field is recorded
  (`meta["check"]`) but not verified; the obsolete "PWB" binary variant
  shares the `0x71C7` magic and is parsed as binary.
- Archive members are not directories in the container sense; implied
  parent directories are emitted as synthetic `Directory` entries where
  the format stores only full paths.

## License

Dual-licensed under MIT or Apache-2.0, at your option. See `LICENSE-MIT`
and `LICENSE-APACHE`.
