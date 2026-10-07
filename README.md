# sutram-exfat

exFAT forensic filesystem parser for the SUTRAM-FS project (`sutram-fs`
traits over `sutram-io` sources). `sutram-fat` is the reference
implementation; this crate follows its patterns for exFAT's different
on-disk model.

See `CONVENTIONS.md` at the repository root for the contract every crate
follows.

## What this filesystem is

exFAT (Extended File Allocation Table, Microsoft 2006/SDXC-mandated) is
the lightweight filesystem of SDXC cards and removable media ≥ 32 GiB.
Unlike FAT it uses 64-bit file sizes, an **allocation bitmap** (one bit
per cluster) instead of relying on the FAT for free space, optional
contiguous (`NoFatChain`) extents that skip FAT chain walking, and
*directory entry sets*: a primary file entry (`0x85`) plus secondaries —
stream extension (`0xC0`: size/extent/flags) and file-name entries
(`0xC1`: 15 UTF-16 units each) — bound by a 16-bit set checksum. Deletion
only clears the *in-use bit* of each entry type (`0x85→0x05`, `0xC0→0x40`,
`0xC1→0x41`) and frees the bitmap bits — names, timestamps and extent
metadata survive wholesale.

## Forensic features

- **Boot region** — validates JumpBoot + `"EXFAT   "` + MustBeZero, the
  BPB geometry, the backup boot sector (sector 12), and both boot-region
  checksums (sector 11/23). `meta["boot_checksum_ok"]`,
  `backup_boot_ok`, `backup_checksum_ok` report the outcome; strict mode
  refuses a mismatched main checksum.
- **Deleted entry sets** — decoded wherever they appear in a directory,
  including slack past the `0x00` end-of-directory marker
  (`meta["beyond_eod"]`). Set checksums are verified with in-use bits
  restored → `meta["checksum_ok"]` proves the set is internally whole.
  Deleted directories are recursed into.
- **Stray secondary salvage** — stream/name runs whose primary entry was
  overwritten are still emitted (`meta["orphan"]="true"`, `note`).
- **Recovery assessment** — expected clusters (FAT chain, or the
  contiguous `NoFatChain` extent; truncated chains are extended
  contiguously per exFAT's default allocator) are checked against the
  allocation bitmap: a set bit means reallocated → `Intact` /
  `PartiallyOverwritten{recovered_bytes,total_bytes}` / `Unrecoverable` /
  `Unknown`. `allocated_ranges` narrows to surviving extents;
  `recovery_note_*` meta keys name the live files that took the clusters.
- **Orphan chains** — bitmap-allocated clusters claimed by no entry are
  emitted under `/$ORPHANED/chain_N` (`meta["orphan"]="true"`).
- **Slack** — per-file `slack_offset`/`slack_len`;
  `unallocated_ranges()` enumerates bitmap-free byte ranges for carving
  (`carve_region` signature-scans them via `sutram-magic`).
- **Timestamps** — create/modify (10 ms increment fields) and access
  (2 s), DOS-style packing; the three UTC-offset bytes (bit 7 = valid,
  15-minute units) are applied so `value` is a true epoch instant, and
  the offsets are also reported in `meta["*_utc_offset"]`.
  `FsTimestamp` keeps `raw_value`/`raw_encoding`/`granularity`.
- **Magic verdicts** — each file's first ≤ 4 KiB goes to `sutram-magic`;
  `FsEntry.magic` carries the `MagicVerdict`.
- **Provenance** — `disk_offset` = the primary entry's absolute offset;
  `entry_id` = that offset (stable even for cluster-less files);
  `allocated_ranges` = absolute byte extents.

## Usage

```rust,no_run
use std::sync::Arc;
use sutram_exfat::ExFatParser;
use sutram_fs::{FsParser, DetectConfidence};
use sutram_io::{ByteSource, FileSource};

let src = Arc::new(FileSource::open("sdcard.raw")?) as Arc<dyn ByteSource>;
if ExFatParser.detect(src.as_ref()) >= DetectConfidence::Medium {
    let fs = ExFatParser.mount(src)?;
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

exFAT deletion clears in-use bits and bitmap bits but normally leaves the
stream extension (extent pointer + lengths) and the FAT chain intact.
`recovery_for` therefore reconstructs the *expected* cluster list —
contiguous when `NoFatChain` was set, FAT chain otherwise (short chains
extended contiguously, flagged in `recovery_note_*`) — then asks the
bitmap which clusters were reallocated. Set bit = lost (with the new
owner named when known); clear bit = surviving extent. Without a bitmap,
the live-allocation map is the fallback and the result is correspondingly
weaker. `read_file` on a deleted entry returns only surviving extents.

## Known limitations

- The **up-case table is located but not applied or verified** — name
  hashes (`meta["name_hash"]`) are reported raw, not recomputed.
- TexFAT (transactional, `NumberOfFats = 2` / FAT1+FAT2 active-clean) is
  parsed with FAT0 only; the second FAT and padding entries are ignored.
- Without a readable allocation bitmap, `unallocated_ranges()` returns
  empty and the orphan scan falls back to "nonzero FAT entry", which can
  surface metadata clusters (e.g. the bitmap itself) as orphans.
- Files whose entry sets lose their stream extension get
  `RecoveryState::Unknown` (no extent information survives).
- `read_file` returns surviving extents concatenated — for a
  partially-overwritten file the byte *positions* of lost holes are not
  re-padded (cluster-granular recovery, same as `sutram-fat`).
- `slack_offset`/`slack_len` are computed for *live* files only — a
  deleted entry's surviving extents are already its recovery story.
- Orphan chain pseudo-entries are `EntryKind::Other`, so they carry no
  `magic` verdict; carve their bytes via `read_file` or
  `unallocated_ranges()` + `carve_region`.
- Strict mode makes a *main* boot-region checksum mismatch fatal at
  mount; a bad backup-region checksum is reported
  (`meta["backup_checksum_ok"]`) but never fatal.
- Volume GUID (`0xA0`), vendor and padding entries are parsed past but
  not emitted.

## License

Dual-licensed under MIT or Apache-2.0, at your option. See `LICENSE-MIT`
and `LICENSE-APACHE`.
