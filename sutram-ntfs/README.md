# sutram-ntfs

NTFS forensic filesystem parser — part of the SUTRAM-FS project (see
`CONVENTIONS.md` at the repository root for the contract every crate
follows).

## What this filesystem is

NTFS is the dominant Windows filesystem and the richest forensic target in
the family. Everything is a file — including the metadata itself — and the
Master File Table ($MFT) is an array of fixup-protected FILE records (1 KiB
by default) that describe every object on the volume. Attributes come in
two flavours: *resident* (content lives inside the record) and
*non-resident* (content lives in clusters described by a compressed
runlist). Because records survive deletion with their runlists intact,
NTFS offers unusually good deleted-file recovery — and because it keeps
*two* timestamp sets per file, it is the classic timestomp-detection
battleground.

## Forensic features

- **Fixup / update-sequence-array verification** — mandatory before any
  record field is trusted. A sector-trailer/sequence mismatch yields a
  `Corrupt` error record with the absolute offset (torn-write evidence),
  never silently-bad data. Same for INDX index records.
- **Dual timestamp sets** — `$STANDARD_INFORMATION` *and* `$FILE_NAME`
  MACB times are both decoded. `FsEntry::timestamps` carries the SI set
  (with MFT-changed mapped to `changed`); `meta["si_*"]` and `meta["fn_*"]`
  carry all eight values as nanoseconds. `meta["timestomp_suspect"]` flags
  files where SI predates FN — impossible under normal operation and the
  signature of SI-only timestomping tools.
- **Deleted records** — in-use-flag-clear FILE records emit as
  `Deleted{recovery}` entries. Recovery is computed by subtracting the
  record's data runs against a live-cluster map built at mount:
  `Intact` (all extents survive, incl. resident data), `PartiallyOverwritten`
  (byte-exact `allocated_ranges` of what survives), `Unrecoverable`
  (metadata only), `Unknown`. `recovery_note_*` meta keys explain the
  verdict; `mft_bitmap_inuse` flags slots still marked allocated in $MFT's
  own bitmap (uncommitted deletion).
- **MFT slack carving** — FILE/BAAD record fragments in the allocated but
  unused tail of $MFT emit as `Deleted{Unknown}` with `mft_slack`/`baad`
  meta flags.
- **INDX residue** — per-directory pass over `$INDEX_ROOT` and
  `$INDEX_ALLOCATION` nodes: entries beyond the used region are deleted-name
  slack (`source=indx_slack`); used-region entries pointing at inactive or
  sequence-reused records are dangling residue (`source=indx_dangling`).
  Both emit as `Deleted{Unknown}` under the directory's real path.
- **ADS** — every named `$DATA` stream is its own entry
  (`/file.txt:stream`); `$UsnJrnl:$J`/`$Max` are exposed the same way and
  `$LogFile`/`$UsnJrnl` presence is flagged in `FsInfo::meta`.
- **Journal forensics** — the change journal and LFS log are parsed as
  evidence: `$UsnJrnl:$J` USN records (filename, file/parent references,
  reason flags with decoded names, event timestamp) stream under
  `/$USN_JRNL/<usn>/`, and `$LogFile` 4 KiB LFS pages are decoded as
  restart areas (`RSTR`), log-record headers (`RCRD`), checkpoints
  (`CHKD`) and torn-write evidence (`BAAD`) under `/$LOGFILE/`.
  `NtfsFs::journal_events()` gives the typed stream;
  `journal_entries()` the `FsEntry` view; `FsInfo::meta` carries
  `usn_records`, `logfile_records`, `logfile_torn_pages`, etc. Journals
  are **parsed, never replayed** — a USN record says a file changed, a
  log record witnesses a transaction; neither modifies the walk.
- **$ATTRIBUTE_LIST** — extension records are merged into their base
  record, so split runlists produce one coherent extent list;
  `meta["extension_records"]` lists the contributors.
- **Compression & sparse** — `meta["compressed"]="lznt1"` +
  `compression_unit_clusters`, `sparse`, `encrypted` flags. `read_file`
  decompresses LZNT1 one compression unit at a time (bounded memory);
  sparse holes read as zeros at true logical offsets.
- **Hardlinks** — each non-DOS `$FILE_NAME` attribute emits an entry at
  its own path; `hardlink`/`link_count`/`dos_name` meta recorded.
- **$EA / $OBJECT_ID / reparse points** — `ea_names`, `object_id`,
  `reparse_tag`; symlink reparse points yield `EntryKind::Symlink` +
  `symlink_target`.
- **$BITMAP** → `unallocated_ranges()` (coalesced free-cluster byte
  ranges) and `FsInfo::free_blocks`.
- **Provenance** — `disk_offset` = MFT record offset; `meta["mft_record"]`,
  `mft_offset`, `attr_offsets`; `allocated_ranges` are absolute byte
  extents (resident content points inside the record itself).
- Per-file `MagicVerdict` via `sutram-magic` (skipped for
  compressed/encrypted streams — the bytes on disk are not the plaintext).
- Lenient by default: corrupt records produce `Err` items inside the walk
  stream; `MountOptions::strict` makes the first error terminal.

## Usage

```rust,no_run
use std::sync::Arc;
use sutram_fs::{FsParser, FileSystem, DetectConfidence};
use sutram_io::FileSource;
use sutram_ntfs::NtfsParser;

let src: Arc<dyn sutram_io::ByteSource> = Arc::new(FileSource::open("disk.img")?);
if NtfsParser.detect(src.as_ref()) >= DetectConfidence::Medium {
    let fs = NtfsParser.mount(src)?;
    println!("{} {:?}", fs.info().fs_type, fs.info().label);
    for item in fs.walk() {
        match item {
            Ok(e) => println!("{} {} bytes {:?}", e.path, e.size, e.status),
            Err(err) => eprintln!("corrupt: {err}"),
        }
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Deleted / recovery semantics

Deletion in NTFS clears the record's in-use flag and frees its clusters in
$BITMAP, but the record — including its runlists and often its resident
data — survives until the slot is reused. At mount we build a map of all
clusters claimed by *live* records; a deleted record's extents are judged
against it:

- **Intact** — every expected cluster survives (or the data was resident
  in the record). `read_file` returns the full content.
- **PartiallyOverwritten** — some clusters reallocated to live files;
  `allocated_ranges` lists exactly the surviving extents and `read_file`
  returns only those bytes, in cluster order (logical gaps are *not*
  re-zeroed for deleted entries — the contract is "recoverable bytes").
- **Unrecoverable** — metadata only, no surviving extents.
- **Unknown** — INDX residue, BAAD records, fragments.

Cross-checks reported in meta: `mft_bitmap_inuse` (record slot still
marked allocated in $MFT's bitmap), $BITMAP-allocated surviving clusters
("deletion not committed"), truncated runlists.

## Known limitations

- **Journal contents are parsed, not replayed.** `$UsnJrnl:$J` USN
  records (v2 fully, v3/v4 with low-64-bit file references) and
  `$LogFile` LFS pages (restart areas, log-record headers, checkpoints,
  `BAAD` torn pages) stream via `journal_events()`/`journal_entries()`
  as evidence. Log-record *payloads* (redo/undo buffers) are located via
  computed extents but not interpreted; each journal stream is scanned
  over at most 64 MiB of materialised bytes (`*_scan_truncated` meta
  notes larger streams). The streams also remain ordinary files in the
  walk (`$LogFile`, `$UsnJrnl:$J`) for raw extraction.
- **Non-resident $ATTRIBUTE_LIST is untested territory** — resident lists
  (the common case) merge correctly; a fragmented attribute *list* is
  read via its runs but multi-level pathologies may truncate.
- **LZNT1** decompression is implemented for `read_file`, but edge cases
  (units split across many runs, corruption mid-unit) degrade to raw
  bytes rather than hard errors. `magic` checks are skipped on
  compressed/encrypted streams.
- **EFS encryption** is detected and flagged (`encrypted`) but never
  decrypted — `read_file` yields ciphertext.
- **Directory enumeration is MFT-driven**, not B-tree-walked: INDX is
  parsed for *residue*, not as the primary enumeration — a record with no
  surviving `$FILE_NAME` gets a synthesized `$RECORD_<n>` name, and a
  deleted parent dir may leave children under `/$ORPHANED/`.
- **$BITMAP and the live-cluster map are held in memory** — one bit per
  volume cluster plus live metadata extents. The format fundamentally
  requires this for free-space and overwrite analysis.
- Sequence-number reuse is checked for INDX residue but not for direct
  parent links (a reused parent slot could misplace a deleted child's
  path).
- No `$Secure`/ACL decoding, no resident→non-resident attribute type
  coercion beyond $DATA/$INDEX_ALLOCATION/$BITMAP, no journaling replay.

## License

Dual-licensed under MIT or Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
