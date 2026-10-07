# sutram-fat

FAT12/16/32 forensic filesystem parser — the **reference implementation**
of the SUTRAM-FS contract (`sutram-fs` traits over `sutram-io` sources).

Part of the SUTRAM-FS project — see `CONVENTIONS.md` at the repository root
for the contract every crate follows.

## What this filesystem is

FAT (File Allocation Table) — the simplest widely-deployed filesystem.
Directories are tables of 32-byte entries; file data lives in cluster
chains linked by the FAT. Deletion only flips the first name byte to
`0xE5` — the cluster chain and data usually survive until reallocated,
which is why FAT is the canonical deleted-file-recovery teaching format.

## Forensic features

- **Deleted entries** — `0xE5` dirents decoded with their surviving name
  (`_ELETED.TXT`), DOS timestamps and start cluster; entries *past* the
  `0x00` end-of-directory marker are still emitted (`meta["beyond_eod"]`).
- **LFN recovery** — long-name slots assembled and checksum-verified
  against their 8.3 alias (`meta["lfn_checksum_ok"]`); deleted LFN
  fragments flag `meta["lfn_partial"]`.
- **Recovery assessment** — a deleted file's expected cluster chain is
  compared against the live allocation map; clusters reallocated to a live
  file are counted lost → `Intact` / `PartiallyOverwritten{recovered,
  total}` / `Unrecoverable` / `Unknown`, with `allocated_ranges` narrowed
  to the surviving extents and `read_file` returning only those bytes.
- **Orphan chains** — allocated clusters no directory entry claims are
  emitted under `/$ORPHANED/chain_N` (`meta["orphan"]="true"`).
- **Slack space** — per-file `slack_offset`/`slack_len` meta keys;
  `unallocated_ranges()` enumerates all free-cluster byte ranges for
  carving (`carve_region` signature-scans them via `sutram-magic`).
- **Timestamps** — DOS write (2 s), create (10 ms via `crt_tenth`) and
  access (1 day) → `FsTimestamp { value, raw_value, raw_encoding,
  granularity }`.
- **Magic verdicts** — each file's first ≤ 4 KiB is checked by
  `sutram-magic`; `FsEntry.magic` carries the `MagicVerdict` (masquerade
  detection, e.g. `.doc` containing `MZ` → `Severity::High`).
- **Provenance** — `disk_offset` = the dirent's absolute offset;
  `allocated_ranges` = absolute byte extents.

## Usage

```rust,no_run
use std::sync::Arc;
use sutram_fat::FatParser;
use sutram_fs::{FsParser, DetectConfidence, FsEntryStatus};
use sutram_io::{ByteSource, FileSource};

let src = Arc::new(FileSource::open("flash.raw")?) as Arc<dyn ByteSource>;
if FatParser.detect(src.as_ref()) >= DetectConfidence::Medium {
    let fs = FatParser.mount(src)?;
    for item in fs.walk() {
        match item {
            Ok(e) => println!("{}\t{} B\t{:?}", e.path, e.size, e.status),
            Err(e) => eprintln!("corruption: {e}"),
        }
    }
}
# Ok::<(), sutram_fs::FsError>(())
```

## Deleted / recovery semantics

Deletion never touches the FAT chain or data — so `recovery_for` maps
*expected* clusters (from `size`) against the live-claimed set built at
mount: every expected cluster still unclaimed is a surviving extent.
Freed chains degrade to `Unknown`; fully reallocated files are
`Unrecoverable`; a live cluster inside a deleted chain is reported
per-cluster in `recovery_note_*` meta keys.

## Known limitations

- ExFAT is a different format (see `sutram-exfat`).
- Volume-label and `.`/`..` slots are parsed but not emitted as entries.
- FAT12/16 fixed-root and FAT32 chain-root layouts are both handled;
  FSInfo/backup-boot verification is not enforced.
- Orphan chains cannot recover their original names/sizes (size reported
  is the allocation span).

## License

Dual-licensed under MIT or Apache-2.0, at your option. See `LICENSE-MIT`
and `LICENSE-APACHE`.
