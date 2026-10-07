# sutram-apfs

A pure-Rust, no-`unsafe` forensic parser for **APFS** (Apple File System)
containers and volumes, implementing the [`sutram-fs`](../sutram-fs) parser
contract. It reads raw container images — nothing is mounted and nothing is
written — and is designed for DFIR workflows: every structural anomaly is
surfaced with provenance rather than silently skipped, and deleted data is
recovered from superseded checkpoints where the media still holds it.

Existing open-source coverage of APFS (e.g. libfsapfs) is experimental;
this crate aims to be a dependable clean-room implementation of the
publicly documented format (the *Apple File System Reference*).

## Feature coverage

### Container layer

- **`nx_superblock_t` detection** — magic, geometry, and Fletcher-64
  verification; `detect()` reports `None`/`Low`/`Medium`/`High`/`Certain`
  depending on how much of the structure validates.
- **Block geometry validation** — power-of-two block size ≥ 512, sanity
  bounds on descriptor/data areas, `block_count` vs. image length.
- **Checkpoint descriptor scan** — the contiguous descriptor ring is walked,
  every slot Fletcher-64-verified, superblocks paired with their
  `checkpoint_map_phys_t` objects by `o_xid`, and checkpoints sorted.
- **Newest-valid-checkpoint mount** — checkpoints are tried newest → oldest;
  in lenient mode a torn latest checkpoint falls back to an older one and
  the failure is reported as a walk-stream warning. In `strict()` mode any
  structural failure aborts the mount.
- **Fletcher-64 on every object** — no object is trusted without a valid
  checksum; checksum failures carry absolute byte offsets.
- **Container OMAP** — ephemeral omap object + omap B-tree resolved through
  the checkpoint map; `omap_val_t.size` is honoured when claiming multi-block
  objects; `OMAP_VAL_ENCRYPTED` entries are flagged.

### Volume layer

- **`apfs_superblock_t` enumeration** — all `nx_fs_oid[]` volumes are probed;
  `mount_volume(i)` selects among them. Feature/incompat flags, counters,
  UUID, name, and `apsb` provenance land in `FsInfo.meta`.
- **Volume OMAP + fs-tree** — virtual fs-tree nodes resolved through the
  volume object map with `xid ≤ bound` lookups (this is what makes snapshot
  and prior-checkpoint views correct).
- **jrecords** — inodes (Unix mode/uid/gid, nanosecond create/modify/change/
  access times, xfields: dstream, name, finder-info presence, document-id,
  sparse bytes, prev-fsize, snap-xid, rdev), hashed *and* plain directory
  records (auto-detected, `CASE_INSENSITIVE` aware), file extents →
  `allocated_ranges`, embedded and stream xattrs, sibling links + sibling
  map (hardlinks), directory stats, crypto-state records, physical extent
  records. Unknown record types are counted and reported via
  `meta.unhandled_jrec_types`.
- **Streaming walk** — `walk()` is an iterator; mount warnings are yielded
  as `Err` items once, then entries stream (directories before contents is
  not guaranteed — paths are materialised from parent chains, and orphans
  land under `/orphans/`).

### Forensic features

- **Deleted-file recovery from prior checkpoints** — up to 8 superseded
  checkpoints are re-mounted as *generations*; inodes present in an old
  fs-tree but absent live are emitted as
  `FsEntryStatus::Deleted { recovery }`. Recovery state is computed by
  intersecting the file's old extents against the live allocation set:
  `Intact` (all blocks still free), `PartiallyOverwritten` (some blocks
  reallocated — surviving ranges stay in `allocated_ranges`),
  `Unrecoverable` (all reused). Old paths are reconstructed from the old
  generation's drecs, and `meta.recovered_from_xid` records the source
  checkpoint.
- **Snapshots** — `snapshots()` merges `j_snap_name` and `j_snap_metadata`
  records (name, snap-xid, times, sealed apsb block). `mount_snapshot(xid)`
  produces a read-only `FileSystem` view resolving every virtual object at
  `xid ≤ snap_xid` — the volume exactly as the snapshot saw it.
- **Free-space / carving map** — `unallocated_ranges()` reports every block
  not claimed by the live object graph. Superseded-generation objects are
  deliberately *not* claimed, so deleted data is reachable in the free map.
  Spaceman counters (`sm_dev_free_count`, chunk/CIB geometry) are parsed
  into `FsInfo`.
- **Encryption awareness without decryption** — `fs_flags` lacking
  `UNENCRYPTED` marks the volume encrypted (`meta.encrypted=true`); extents
  with `crypto_id ≠ 0` and inodes with crypto-state records are flagged
  (`meta.extent_encrypted`). Reads return raw ciphertext — this crate never
  attempts decryption. Sealed volumes are flagged (`meta.sealed=true`).
- **Per-file magic verdicts** — `MountOptions::check_magic` (on by default)
  runs `sutram-magic` over the first ≤4 KiB of each file's data extents.
- **Provenance** — `FsEntry.disk_offset` is the absolute byte offset of the
  inode/drec/sibling record inside the image; per-extent record offsets land
  in `meta.extent_<i>_record_off`.
- **Compression awareness without decompression** — inodes carrying a
  `com.apple.decmpfs` xattr are flagged (`meta.compressed=decmpfs`, plus a
  `note`); `read_file` still yields the stored bytes.

## Usage

```rust,no_run
use std::sync::Arc;
use sutram_apfs::ApfsParser;
use sutram_fs::{FsParser, DetectConfidence, FsEntryStatus};
use sutram_io::{ByteSource, FileSource};

let src = Arc::new(FileSource::open("container.raw")?) as Arc<dyn ByteSource>;
if ApfsParser.detect(src.as_ref()) >= DetectConfidence::Medium {
    let fs = ApfsParser.mount(src)?;
    for item in fs.walk() {
        match item {
            Ok(e) => println!("{}\t{} B\t{:?}", e.path, e.size, e.status),
            Err(e) => eprintln!("corruption: {e}"), // lenient-mode warnings
        }
    }
}
# Ok::<(), sutram_fs::FsError>(())
```

`ApfsParser` also offers `mount_volume(src, opts, i)` to select among the
container's `nx_fs_oid[]` volumes, and `mount_snapshot(src, opts, snap_xid)`
for a read-only view of the volume bounded at a snapshot's transaction id.
A mounted `ApfsFs` exposes `snapshots()`, `volumes()`, `checkpoint_xid()`
and `xid_bound()`.

## Deleted / recovery semantics

APFS never overwrites metadata in place — every commit writes a new
checkpoint of new object versions. This parser exploits that: up to 8
superseded checkpoints are re-mounted as *generations* and their fs trees
are diffed against the live generation. An inode present in an old tree but
absent live is emitted as `FsEntryStatus::Deleted` with a `RecoveryState`
computed by intersecting the file's old extents against the blocks claimed
by the live object graph:

- `Intact` — every extent block is still unclaimed;
- `PartiallyOverwritten { recovered_bytes, total_bytes }` — some blocks were
  reallocated; `allocated_ranges` lists only the surviving ranges and
  `read_file` returns only those bytes;
- `Unrecoverable` — all blocks reused, or the inode had no extents;
- `Unknown` — the recovery assessment could not be made.

The old path is reconstructed from the old generation's directory records
(broken parent chains fall back to `/$ORPHANED/<id>`), and
`meta.recovered_from_xid` names the source checkpoint. Limits: recovery is
block-granular (a partially reused block counts as lost), generations beyond
the 8 scanned checkpoints are not searched, and data on trimmed or
physically overwritten media is unrecoverable by definition.

## Known limitations

- **Contiguous checkpoint descriptor areas only.** When
  `xp_desc_blocks` high bit is set (descriptor area lives in a B-tree), the
  mount fails with `Unsupported`. This covers all shipping macOS containers;
  B-tree descriptor areas are a documented but rarely used option.
- **Spaceman is header-level.** Free count and geometry are parsed; CIB/CAB
  bitmaps and free queues are not walked (free space is instead derived from
  the live-object complement, which is the forensically interesting map
  anyway).
- **No decryption.** FileVault/crypto-state contents are flagged, not
  decrypted. Keys are never read from the keybag area.
- **No decompression.** Files whose data fork is stored via the
  `com.apple.decmpfs` mechanism (LZFSE/ZLIB/LZ4, HFS+-style compression
  carried into APFS) are flagged `meta.compressed=decmpfs` but the stored
  bytes are returned as-is. LZFSE decompression depends on the sibling
  `sutram-compress` crate, which is still in progress; until it lands,
  treating compressed forks as opaque is the honest behaviour.
- **Sealed volumes stay sealed.** `APFS_INCOMPATIBLE_SEALED_VOLUME` is
  reported (`meta.sealed=true`); the seal is never verified and the volume
  is parsed structurally anyway — a torn seal is not validated against.
- **Extent-reference tree** (`extentref_tree_oid`) and inode-delta trees are
  not interpreted; their oids are reported in `meta`.
- **Single fs-tree per volume generation** — the file tree is the B-tree at
  `root_tree_oid`; special records (`DSTREAM_ID`, extent-list, unknown types)
  are counted rather than interpreted.

## Corruption semantics

- `MountOptions::strict()` — first structural failure aborts the mount.
- Default (lenient) — the newest *fully valid* checkpoint wins; per-object
  failures during mount become warnings delivered once at the head of the
  `walk()` stream; per-record failures skip that record and continue.
  `FsInfo.meta.malformed_desc_slots` and `checkpoint_count` report what the
  descriptor scan saw.

## Layout

| Module | Role |
|---|---|
| `checksum.rs` | Fletcher-64 (the ZFS-style variant APFS uses) |
| `object.rs` | `obj_phys_t` header, type/storage-class decode |
| `nx.rs` | `nx_superblock_t`, descriptor-area checkpoint scan, `detect()` |
| `btree.rs` | B-tree node/ToC decode, leaf iteration, internal-node descent |
| `omap.rs` | `omap_phys_t`, omap B-tree index with xid-bounded lookup |
| `apsb.rs` | `apfs_superblock_t` |
| `jrec.rs` | fs-tree jrecord decode (inodes, drecs, extents, xattrs, links, snaps) |
| `spaceman.rs` | `spaceman_phys_t` header |
| `fs.rs` | mount chain, checkpoint fallback, prior-generation diffing, `FileSystem` impl |
| `walk.rs` | streaming entry walk: live, hardlink, orphan, and deleted entries |

## Tests

`cargo test` runs 37 unit tests (Fletcher-64, object header, NXSB, B-tree
ToC/descent, xid-bounded omap lookup, jrecord decoding, snapshot metadata)
plus 63 integration tests across `forensic.rs`, `robustness.rs` and
`hostile.rs` that mount a synthetic two-checkpoint container built in
`tests/common/mod.rs` — exercising live walk, file reads, hardlinks,
xattrs, decmpfs flagging, snapshot mounting, deleted-file recovery
(`Intact`/`PartiallyOverwritten`/`Unrecoverable`), corrupted-block-0
tolerance, checkpoint fallback and rollback, strict-mode abort, truncation,
mass corruption, and the free-space map.

## License

MIT OR Apache-2.0
