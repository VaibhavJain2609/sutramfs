# sutram-hfs

HFS+/HFSX forensic filesystem parser — implements the SUTRAM-FS contract
(`sutram-fs` traits over `sutram-io` sources), following `sutram-fat` as
the reference implementation.

Part of the SUTRAM-FS project — see `CONVENTIONS.md` at the repository
root for the contract every crate follows.

## What this filesystem is

HFS+ ("Mac OS Extended") was Apple's primary filesystem from 1998 to
2017. The volume header sits at byte offset 1024 (signature `H+`, or
`HX` for case-sensitive HFSX); all on-disk metadata is **big-endian**.
Files and folders live in a catalog B-tree keyed by `(parentID, name)`;
a second B-tree holds extents-overflow records for files fragmented past
their eight inline extents, and a third holds extended attributes.

HFS+ may also be *wrapped*: a pure-HFS volume (`BD` master directory
block) embeds an HFS+ volume at `drEmbedExtent.startBlock`. `sutram-hfs`
detects the wrapper and mounts the embedded volume transparently.
Pure HFS is detected but not mounted (`FsError::Unsupported`).

## Forensic features

- **Volume header** — all fields decoded explicitly big-endian
  (`sutram_io::le::*_be`); `H+` and `HX` accepted; HFS wrappers located
  via `drEmbedExtent`. `FsInfo::meta` carries raw volume dates, Finder
  info, encoding bitmap, clump sizes, `last_mounted` fourcc and B-tree
  shape (depth, node size, leaf/root counts, max key length).
- **Catalog B-tree** — header/index/leaf/map node kinds; the leaf chain
  is followed by `fLink`, bounded by `total_nodes` with cycle detection.
  File, folder, and thread records are decoded; CNID→parent maps and
  thread records drive non-recursive path reconstruction.
- **Extents** — inline `HFSPlusForkData` extents merged with
  extents-overflow records keyed `(forkType, fileID, startBlock)`, for
  both data forks and resource forks (`name:rsrc` pseudo-entries).
- **Hard links / symlinks** — `hlnk`/`hfs+` files resolve through
  `iNode<N>` records under the `HFS+ Private Data` metadata folder;
  `slnk`/`rhap` symlink targets are read from the data fork.
- **Extended attributes** — inline, fork-backed and extent-backed
  attribute records become `name:xattr:<attr>` pseudo-entries with
  `xattr_*` meta keys (`xattr_storage` = `inline`/`fork`/`extents`/
  `unknown:<type>`).
- **decmpfs compression** — `com.apple.decmpfs` headers parsed
  (`decmpfs_type`, `decmpfs_uncompressed_size` meta). Types 1/9/10
  (uncompressed) and 3/4 (zlib inline / zlib resource-fork block table)
  decompress transparently in `read_file` via pure-Rust `miniz_oxide`.
  LZVN (7/8) and LZFSE (11/12) are flagged `compression_note=unsupported`.
- **Deleted & recoverable entries** — three residue sources:
  1. free space inside live catalog leaf nodes,
  2. dead B-tree nodes freed by compaction (still descriptor-valid),
  3. extents-overflow records for CNIDs no catalog record claims
     (`/$ORPHANED/...` entries).

  Recovery state compares each deleted file's expected allocation blocks
  against the live-claimed set and the allocation bitmap: blocks
  reallocated to live files are reported lost → `Intact` /
  `PartiallyOverwritten` / `Unrecoverable` / `Unknown`, with
  `allocated_ranges` narrowed to surviving extents and
  `recovery_note_*` meta explaining the assessment.
- **Unallocated space** — the allocation bitmap is parsed;
  `unallocated_ranges()` yields free-block byte ranges and
  `carve_region` signature-scans them via `sutram-magic`.
- **Timestamps** — all five HFS+ u32 dates (create, contentMod, attrMod,
  access, backup) decode as `hfs+-u32-1904-local` (seconds since
  1904-01-01, 1 s granularity); raw values are preserved and HFS+'s
  local-time-zone convention is documented in meta.
- **Journal awareness** — `journalInfoBlock` locates the JIB and journal
  buffer; `journal_flags`/`journal_offset`/`journal_size`/`journal_magic`
  land in `FsInfo::meta`. Transaction replay is **not** implemented —
  `meta["journal_replay"]` says so.
- **Magic verdicts** — each file's first ≤ 4 KiB is checked by
  `sutram-magic`; `FsEntry.magic` carries the `MagicVerdict`
  (masquerade detection, e.g. `.doc` containing `MZ` → `Severity::High`).
- **Provenance** — `disk_offset` = the catalog record's absolute offset;
  `allocated_ranges` = absolute extent byte ranges; residue entries keep
  the offset of the free-space bytes they were sniffed from.
- **Lenient by default** — corrupt nodes/records emit `Err(FsError)`
  items in the walk stream and parsing continues; `MountOptions::strict`
  aborts at the first error.

## Usage

```rust,no_run
use std::sync::Arc;
use sutram_hfs::HfsParser;
use sutram_fs::{FsParser, DetectConfidence, FsEntryStatus};
use sutram_io::{ByteSource, FileSource};

let src = Arc::new(FileSource::open("disk.raw")?) as Arc<dyn ByteSource>;
if HfsParser.detect(src.as_ref()) >= DetectConfidence::Medium {
    let fs = HfsParser.mount(src)?;
    for item in fs.walk() {
        match item {
            Ok(e) => println!("{}\t{} B\t{:?}", e.path, e.size, e.status),
            Err(e) => eprintln!("corruption: {e}"),
        }
    }
    // Deleted view + free-space carving (offset/len byte tuples,
    // block-size alignment).
    for e in fs.deleted_entries() {
        println!("deleted: {} {:?}", e.path, e.status);
    }
    for (off, len) in fs.unallocated_ranges() {
        let hits = fs.carve_region(off, len.min(1 << 20), 4096)?;
        for h in hits {
            println!("carve hit: {h:?}");
        }
    }
}
# Ok::<(), sutram_fs::FsError>(())
```

## Deleted / recovery semantics

Catalog deletion in HFS+ removes the leaf record *and* its key from the
B-tree, but the record bytes usually remain in the node's free-space
region until the node is repacked; nodes freed by B-tree compaction keep
entire record sets. `sutram-hfs` re-reads both regions with a
conservative record sniffer (key length/name consistency checks) and
cross-checks each expected allocation block against the live-claimed
block map *and* the allocation bitmap:

- every expected block still unclaimed → surviving extent,
- blocks now claimed by a live file → lost (`recovery_note_*` meta
  names the claimer),
- blocks unclaimed but still marked allocated in the bitmap → flagged
  (bitmap/live-map disagreement).

`allocated_ranges` is narrowed to surviving extents, so `read_file` on a
deleted entry returns only recoverable bytes.

## Known limitations

- **Pure HFS** (`BD` without an embedded HFS+ volume) is detected but
  mount returns `Unsupported` — the catalog format differs enough that
  it is out of scope for this crate.
- **Journal replay is not implemented** — JIB/buffer metadata is
  reported; transactions pending at acquisition are not applied.
- **Compression** — only decmpfs types 1/3/4/9/10 decompress; LZVN
  (types 7/8) and LZFSE (types 11/12) surface `compression_note` =
  `unsupported` and read back the stored (compressed) bytes.
- **Encrypted volumes** (FileVault/CoreStorage) and **compressed
  resource-fork codecs** beyond zlib are not handled.
- **Free-space residue** cannot always recover full key context (e.g.
  parent CNID of a key whose surrounding bytes were overwritten); such
  entries appear under `/$DELETED`/`/$ORPHANED` with `residue` meta.
- Orphaned extents report allocation size, not logical size
  (`meta["note"]` documents this).

## License

Dual-licensed under MIT or Apache-2.0 — see `LICENSE-MIT` and
`LICENSE-APACHE`.
