# sutram-btrfs

Forensic BTRFS parser for the SUTRAM-FS toolkit — a pure-Rust port (and
superset) of the Python [`btrfsparser`](../btrfsparser) tool.

BTRFS is copy-on-write: every commit writes *new* tree blocks and extents
instead of overwriting in place. Generations of filesystem metadata
therefore coexist on disk, which makes BTRFS unusually rich for forensic
recovery. This parser exploits that deliberately — see
[Recovery semantics](#recovery-semantics).

## Features

- **Superblock** at `0x10000` with mirror fallback (64 MiB / 256 GiB
  copies), CRC32C verification, label/FSID/geometry, and the four embedded
  **backup roots** — the entry points into COW history.
- **Chunk map** built from `sys_chunk_array` then the full chunk tree;
  translates logical→physical addresses including striped RAID0/RAID10
  geometry. Parity RAID5/6 layouts are recognised and reported as
  unsupported rather than mistranslated.
- **B-tree traversal** — internal nodes and leaves, per-node CRC32C
  verification, keyptr generation-consistency checks (a stale pointer is
  reported as a COW remnant, not fatal), cycle guards and node-count caps.
- **Root tree** — `ROOT_ITEM`/`ROOT_REF`/`ROOT_BACKREF` discovery of
  subvolumes and snapshots; unique inode IDs as `subvol << 48 | ino`.
- **FS trees** — `INODE_ITEM`, `INODE_REF`/`EXTREF`, `DIR_ITEM`,
  `DIR_INDEX`, `XATTR`, `EXTENT_DATA` (regular, prealloc, inline, hole);
  paths rebuilt through parent chains with DIR_ITEM fallback for name
  residue.
- **All four timestamps** — atime, mtime, ctime *and* otime (birth),
  nanosecond granularity, as `FsTimestamp`s with raw provenance.
- **Deleted/COW recovery** — see below.
- **Compressed extents** — zlib (`flate2`/miniz), zstd (`ruzstd`), LZO
  (`lzokay`); all pure Rust. Decompressed bytes feed both `read_file` and
  the magic check.
- **Magic verdicts** via `sutram-magic` — extension↔content mismatch
  detection (e.g. a PE named `.doc`), container-aware (ZIP-based OOXML).
- **Free space** — `unallocated_ranges()` from the extent tree (chunk
  coverage minus allocations), cross-checked against the free-space tree
  (v2 extents *and* bitmaps) when present.
- **uid/gid name resolution** — `/etc/passwd` and `/etc/group` (plus the
  `/root/etc/…` alternates) are read during mount and surfaced as
  `meta["user"]`/`meta["group"]`, matching the Python tool.
- **Streaming walk** — one `FsEntry` at a time; corruption yields
  `Err(FsError)` records inline (lenient) or aborts (strict).

## Usage

```rust
use std::sync::Arc;
use sutram_btrfs::BtrfsParser;
use sutram_fs::{FsParser, MountOptions, FileSystem};
use sutram_io::FileSource;

let src: Arc<dyn sutram_io::ByteSource> =
    Arc::new(FileSource::open("disk.img")?);

if BtrfsParser.detect(src.as_ref()) >= sutram_fs::DetectConfidence::High {
    let fs = BtrfsParser.mount_with(src, &MountOptions::default())?;
    for item in fs.walk() {
        match item {
            Ok(e) => println!("{} {} {:?}", e.path, e.size, e.status),
            Err(e) => eprintln!("corrupt: {e}"),
        }
    }
}
```

For whole-disk images, `detect()` probes MBR/GPT partitions itself;
mounting uses `sutram_io::views::OffsetView` (or
`sutram_io::open_partitions`) to scope the source to the partition.

## Recovery semantics

Deleted recovery combines three BTRFS-specific sources:

1. **Backup roots / old-generation trees.** The superblock's four
   `btrfs_root_backup` slots point at earlier root trees; each is walked
   to find that generation's FS trees. Old trees are diffed against the
   live trees by `(transid, size, extent-layout)`:

   - inode absent live → **deleted** entry at its original path;
   - inode present but changed → **prior version** at `path@v<gen>`,
     with `meta["prior_version_of"]` naming the live path;
   - identical → skipped (deduplicated across backup generations,
     newest first, capped at 64 old trees).

2. **Orphan items** (`BTRFS_ORPHAN_OBJECTID`, objectid −48) mark inodes
   unlinked but not yet reaped — emitted as `Deleted` even inside live
   trees, with `meta["orphan"] = "true"`.

3. **Extent backrefs** (`EXTENT_ITEM`/`METADATA_ITEM` +
   `EXTENT_DATA_REF`/`SHARED_*`) drive the per-extent verdict:

   - no extent record → allocation was freed; residual bytes presumed
     on disk → **surviving**;
   - extent record exists, backref still names this inode → surviving
     (pending-delete or snapshot-shared);
   - record's generation is newer than the file extent's and the backref
     names a *different* inode → **reallocated/overwritten** → lost;
   - a live inode references the same logical extent → shared, surviving.

   The aggregate becomes `RecoveryState::{Intact, PartiallyOverwritten{
   recovered,total}, Unrecoverable}`; `read_file` on a deleted entry
   streams only the surviving extents, and `allocated_ranges` lists them.

Entries whose names survive only as DIR_ITEM residue (inode item gone)
are emitted as name-only deleted stubs with an explanatory
`meta["note"]`.

## Provenance

- `disk_offset` — absolute source offset of the inode item (or dir item
  for name-only stubs).
- `meta["data_logical"]` / `meta["data_physical"]` — extent addresses in
  both address spaces.
- `meta["inode_item_physical"]` / `meta["inode_item_logical"]` —
  dual-space metadata citation.
- `meta["tree_root"]`, `tree_generation`, `cow_generation`, `cow_root`,
  `transid`, `generation` — temporal provenance.

## Port fidelity vs the Python parser

Faithfully ported: superblock (+ mirrors, which Python lacks), system
chunk array, chunk-tree translation, B-tree walk, root tree / subvolume
discovery with the `subvol << 48 | ino` id scheme, inode/dir/extent/xattr
records, path building, four timestamps, compressed extents, and
passwd/group name resolution.

Extended beyond Python: CRC32C verification of superblock and every tree
node, keyptr generation checks, COW-history (backup-root) recovery,
orphan items, extent-backref provenance and recoverability verdicts,
unallocated-range enumeration, magic verdicts, streaming `walk()`, and
strict/lenient modes.

Not ported: per-file MD5/SHA256 hashing (Python's output nicety; no
suitable crates in the offline registry — hash upstream of this crate if
needed), the checksum tree's per-extent csum counts, and the GUI/CLI
report formatters (`output.py`, `statistics.py`).

## Limitations

- **RAID5/6/parity and RAID1C3/4** chunk profiles are recognised but
  cannot be translated — trees/extents living only on such chunks are
  reported as errors.
- **Multi-device** images: the primary device is parsed; stripes map to
  their own device offsets but only device 0's source is mounted.
- **Compressed extents**: LZO follows the standard page-framed layout;
  exotic inline-LZO variants may fail decompression (data is then exposed
  raw and `meta["compression_unsupported"]` may be set).
- **csum tree / log tree** are not walked for content (log replay is out
  of scope — the committed state is authoritative).
- Deleted recovery assumes freed extents are not yet reallocated —
  recoverability verdicts are best-effort assessments, not guarantees.
- Other checksum types (xxhash/sha256/blake2b superblocks) mount but skip
  checksum verification.

## License

Dual-licensed under MIT OR Apache-2.0.
