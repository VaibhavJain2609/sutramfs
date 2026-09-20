# sutram-xfs

Forensic, read-only **XFS** parser for the
[SUTRAM-FS](../CONVENTIONS.md) parser ecosystem. Implements the shared
`sutram_fs::FsParser` / `FileSystem` traits: bounded streaming `walk()`,
`read_file`/`read_file_at`, `deleted_entries()`, `unallocated_ranges()`
and `carve_region()` — all evidence bytes are treated read-only.

XFS on-disk metadata is **big-endian**. Every field is decoded through
explicit `u16_be`/`u32_be`/`u64_be` helpers (`sutram_io::le`); there are
no host-order reads, no `transmute`, and the crate is `#![forbid(unsafe_code)]`.
Unit tests feed BE-encoded structures on a little-endian host and assert
decoded values, including a negative case proving an LE-encoded inode is
rejected.

## Supported

| Area | Coverage |
|------|----------|
| Superblock | v5 primary (CRC32C verified); v4 parsed (no CRC) |
| AGs | AGF/AGI/AGFL headers per AG, multi-AG geometry |
| Inode indexes | `inobt` (+ `finobt` on v5), sparse-inode (`spinodes`) chunk hole masks |
| Inodes | v3 core (CRC, `di_ino`, `crtime`) and legacy v1/v2 cores; `bigtime` timestamps |
| Extents | `local` / `extents` / `btree` (BMBT) data forks; unwritten-extent flags |
| Directories | shortform, block (`XD2B`/`XDB3`), leaf/node (`XD2D`/`XDD3` data blocks scanned directly; leaf-space index blocks skipped) |
| Symlinks | local (inline) + remote (`XSLM`) |
| xattrs | local fork + attr leaf (`XARM` remote values fetched, bounded) |
| Free space | `bnobt` walk → `unallocated_ranges()` (carving ground) |
| Deleted files | free-inode residue scan, stale dirent recovery from freed runs, `agi_unlinked` chains, orphan scan (`include_orphans`) |
| Journal | **flagged** in `FsInfo.meta["log"]` (internal fsblock, observed magic); replay not implemented |

## Recovery semantics

Deleted entries get a `RecoveryState` computed by comparing stale extent
records against two allocation maps:

* extent block claimed by a **live** inode → overwritten (noted with the
  new owner's inode number);
* block still in the **bnobt free set** → surviving;
* block allocated but unclaimed → counted surviving with an
  `allocated-but-unclaimed` note (leaked allocation or metadata reuse).

`allocated_ranges` on a deleted entry lists only surviving extents, and
`read_file` packs them contiguously (the usual SUTRAM convention).

Walk phases: mount errors → live tree (BFS, one entry at a time) →
inobt free-bitmap residue → `agi_unlinked` chains → unreachable
allocated inodes (`/$ORPHANED/…`).

## Metadata keys (per-entry `meta`)

`inode`, `inode_offset`, `mode`, `uid`, `gid`, `nlink`, `generation`,
`inode_version`, `di_format`, `nblocks`, `flags`, `inode_crc_ok`,
`dirent_offset`, `dirent_ftype`, `slack_offset`/`slack_len`,
`symlink_target`, `xattr_<name>`/`xattr_count`, `unwritten_extents`,
`stale_residue`, `ino_truncated`, `inode_source`
(`inobt` / `inobt+finobt` / `agi_unlinked`), `orphan`,
`recovery_note_<n>`.

`FsInfo.meta` carries feature words (`features_incompat`, `finobt`,
`spinodes`, `bigtime`), `sb_crc_ok`, AG cross-checks
(`agf_freeblks_total`, `agi_freecount_total`), `sb_lsn`, `meta_uuid`
when it differs, and the `log` flagging described above.

## Usage

```rust
use std::sync::Arc;
use sutram_fs::{FileSystem, FsParser, MountOptions};
use sutram_io::{into_arc, FileSource};
use sutram_xfs::XfsParser;

let src = into_arc(FileSource::open("image.raw")?);
let fs = XfsParser.mount(src)?;            // lenient defaults
for r in fs.walk() {
    match r {
        Ok(e) => println!("{} {} deleted={}", e.path, e.size, e.is_deleted()),
        Err(e) => eprintln!("{e}"),        // corruption → error record
    }
}
```

`MountOptions`: `strict` (abort walk on first error, fail mount on bad
superblock CRC), `check_magic` (per-file `MagicVerdict` via
`sutram-magic`), `include_orphans` (emit unreachable allocated inodes).

## Testing

`sutram-xfs/tests/common/` contains a synthetic XFS v5 image builder —
hand-packed big-endian structures with correct CRC32C, real AGF/AGI/
AGFL headers, `AB3B`/`IAB3`/`FIB3` btree blocks, `XDB3` directory
blocks and v3 inode cores. Integration tests cover: detect/mount, live
tree + `read_file`, deleted-inode recovery (`Intact`/`Unrecoverable`),
freed-run dirent residue, unlinked chains, orphans, free-space ranges,
journal flagging, lenient-vs-strict corruption handling, truncation, and
a two-level inobt walk (node → leaf pointer-area layout).

## Known limitations

* **Journal replay is not implemented.** The log's location, extent and
  observed record magic are reported (`FsInfo.meta["log"]`) but dirty
  metadata transactions are not replayed — a documented TODO.
* Directory leaf/node/freeindex index blocks are skipped in favour of
  scanning data blocks directly — same content, plus residue.
* cntbt is not walked (bnobt alone carries the free-space map);
  rmapbt/refcountbt blocks are skipped (reflink/shared extents noted
  via feature flags but not interpreted).
* Realtime files and quota inodes are flagged but not decoded.
* Truncated stale dirents lose the high 32 bits of the inode number
  (the free-run header overwrites them) — flagged via `ino_truncated`.
* v4 filesystems parse; v4 CRC variants and mixed-version metadata
  combinations are exercised only lightly.
