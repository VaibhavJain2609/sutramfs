# sutram-ext4

ext2/3/4 forensic filesystem parser for the SUTRAM-FS contract
(`sutram-fs` traits over `sutram-io` sources, `sutram-magic` verdicts).

Part of the SUTRAM-FS project — see `CONVENTIONS.md` at the repository root
for the contract every crate follows.

## What this filesystem is

ext4 is the default Linux filesystem family (ext2 → ext3 → ext4 evolved
the same on-disk structures). Space is divided into **block groups**, each
with a block bitmap, an inode bitmap, and an inode table; the superblock
lives at offset `0x400` with backups in sparse groups. Files map logical
blocks to physical blocks either through an **extent tree** (ext4) or the
legacy **direct/single/double/triple-indirect** map (ext2/3). Directories
are linear lists of `ext4_dir_entry_2` records (optionally HTree-indexed);
journalling lives in a separate jbd2 stream inside inode 8.

Deletion is forensically rich: dirents are merged into the previous
entry's `rec_len` (name bytes survive as *slack*), inode bitmap bits are
cleared but inode bodies — including the extent tree root inside
`i_block` — often survive until reuse, and `i_dtime` records deletion time.

## Forensic features

- **Superblock + GDT** — validation firmer than `detect()`, all feature
  flags surfaced (`extents`, `64bit`, `flex_bg`, `metadata_csum`,
  `encrypt`, `casefold`, `inline_data`, `bigalloc`, `has_journal`, …) in
  `FsInfo.meta`, backup-superblock group enumeration (sparse_super aware).
- **Block maps** — extent trees of any depth (cycle-guarded,
  `MAX_EXTENT_NODES` cap) plus the full ext2/3 indirect fallback; inline
  data (`EXT4_INLINE_DATA_FL`, in-inode portion) and fast/slow symlinks
  (`meta["symlink_target"]`).
- **Deleted-name carving** — every live dirent's `rec_len` slack is scanned
  at 4-byte alignment for surviving deleted dirents
  (`meta["carved_dirent"]`); entries whose `inode` field was zeroed on
  delete still recover the *name* (`meta["inode_cleared"]`).
- **Deleted-inode scan** — unallocated inode slots that still carry a mode
  plus extents/`i_dtime` are emitted under `/$ORPHANED/ino_<n>`; allocated
  but unreferenced inodes (incl. the journal inode 8 and the
  `s_last_orphan` chain via `i_dtime` links) are emitted as orphans with
  `meta["orphan"]` / `meta["orphan_list"]` / `meta["journal"]`.
- **Recovery assessment** — each expected logical block is checked against
  the block bitmap and the live-claim map: free + unclaimed → survives
  (`Intact`), allocated/reallocated → lost (`PartiallyOverwritten` names
  the thief in `recovery_note_<n>`), extent info absent → `Unrecoverable`;
  `allocated_ranges` narrows to surviving extents and `read_file` streams
  only recoverable bytes.
- **Timestamps** — `mtime`/`atime`/`ctime` plus the ext4 `i_*_extra`
  nanosecond fields (30-bit ns + 2-bit epoch extension → 1 ns granularity),
  `i_crtime` birth time, and `i_dtime` deletion time; `FsTimestamp`
  carries `raw_value`/`raw_encoding`/`granularity`, unset fields are
  `value: None` — never fabricated.
- **xattrs** — in-inode body region and `i_file_acl` block names listed in
  `meta["xattrs"]` (SELinux, ACLs, `user.*`, `trusted.*`).
- **jbd2 awareness** — the journal superblock is parsed into
  `FsInfo.meta` (`jbd2_needs_replay`, `jbd2_sequence`, `jbd2_journal_blocks`,
  …); the journal inode itself is emitted as an orphan artefact.
- **Hardlinks** — `links_count` > 1 aliases get `meta["hardlink_of"]`
  pointing at the first-seen path.
- **Provenance** — `disk_offset` is the dirent (live/carved) or inode
  offset; `meta["inode_offset"]` gives the inode; `allocated_ranges` are
  absolute byte extents; file-tail slack via `slack_offset`/`slack_len`.
- **Streaming + lenient** — `walk()` buffers one directory (capped) or one
  bitmap block at a time; corruption yields `Err(FsError)` records and the
  walk continues; `MountOptions::strict` aborts on the first error.
- **Carving** — `unallocated_ranges()` enumerates free-block byte ranges
  from the bitmaps; `carve_region()` probes at block alignment.

## Usage

```rust,no_run
use std::sync::Arc;
use sutram_ext4::Ext4Parser;
use sutram_fs::{FsParser, DetectConfidence, FsEntryStatus};
use sutram_io::{ByteSource, FileSource};

let src = Arc::new(FileSource::open("disk.raw")?) as Arc<dyn ByteSource>;
if Ext4Parser.detect(src.as_ref()) >= DetectConfidence::Medium {
    let fs = Ext4Parser.mount(src)?;
    println!("{} {:?}", fs.info().fs_type, fs.info().meta.get("jbd2_needs_replay"));
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

A deleted artefact is judged by walking its surviving block map against two
ground truths: the **block bitmap** (is the block still free?) and the
**live-claim map** built at mount (which live file owns it now?).

- `Intact` — every logical block `0..ceil(size/block_size)` maps to a
  block that is free in the bitmap and unclaimed by live files.
- `PartiallyOverwritten{recovered_bytes,total_bytes}` — some blocks
  survive; `allocated_ranges` lists exactly the surviving extents and
  `read_file` yields only those bytes. Reallocated blocks are named in
  `recovery_note_<n>` (`"block 45 reallocated to /newfile.bin"`).
- `Unrecoverable` — no surviving extent maps to recoverable data (all
  reallocated, `i_block` zeroed, or the inode slot wiped); metadata-only
  entries (carved dirents with cleared/reused inodes) land here too.
- `Unknown` — the block map itself could not be parsed, or bitmap reads
  failed.

Honest limits: a block marked free whose contents were *overwritten in
place* without reallocation cannot be detected — `Intact` means "the map
says nobody claimed it", not "the bytes are provably the original file's".
Groups flagged `BLOCK_UNINIT` produce a note that allocation status is
unreliable.

## Known limitations

- **No checksum verification** — `metadata_csum`/`metadata_csum_seed`,
  GDT, inode and journal crc32c checksums are reported as feature flags but
  never verified (no crc32c dependency; intentional).
- **jbd2 transaction replay is not implemented** — the journal superblock
  is parsed and `jbd2_needs_replay` reported, but descriptor/revoke/commit
  blocks are not walked. A future pass over the `s_start..s_maxlen` region
  would recover recently-modified inodes/dirents that never hit the disk —
  the richest deleted-file source ext4 offers (see `src/journal.rs` TODO).
- **HTree directories are parsed linearly** — hash-indexed directories
  still store dirents linearly inside leaf blocks, so results are correct,
  just not accelerated; `dx_node` interior blocks are skipped. Deleted
  names *inside* `dx` index blocks are not carved.
- **Inline data** — only the in-inode `i_block` payload is read; the
  `system.data` xattr spillover region is not appended (the xattr itself is
  listed, so the presence is visible).
- **Encrypted (fscrypt) / casefold volumes** — flags are surfaced
  (`meta["encrypted"]`); ciphertext bytes are returned as stored, names are
  reported raw.
- **`bigalloc`** is detected but cluster-vs-block accounting is
  approximated at block granularity.
- Deleted *directories* are emitted as artefacts but their stale dirent
  blocks are not re-walked for children.
- Backup superblocks are enumerated, not validated or used for repair.

## License

Dual-licensed under MIT or Apache-2.0, at your option. See `LICENSE-MIT`
and `LICENSE-APACHE`.
