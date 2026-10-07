# sutram-f2fs

An F2FS (Flash-Friendly File System) forensic parser in pure Rust. Part of
the SUTRAM-FS toolkit — it plugs into the shared `sutram-fs` /
`sutram-io` / `sutram-magic` traits, so anything that speaks those APIs
(file-source probing, `mount`, `walk`, `read_file`, carving) works on F2FS
images out of the box.

## Why F2FS matters forensically

F2FS is the standard filesystem for **modern Android `userdata`
partitions** (and ChromeOS / embedded Linux). Its log-structured,
copy-on-write design is a forensic gift: **it never overwrites data in
place**. Every file update lands in a fresh block; the old copy just gets
its validity bit cleared in the SIT. Until the segment is reused, the old
inode *and* the old file contents are still sitting on the flash.

This crate exploits exactly that:

* **Dual checkpoints** — two checkpoint packs; the parser validates both
  (version agreement + CRC) and mounts the newest.
* **Stale NAT copies** — the Node Address Table is double-buffered. The
  *previous* checkpoint's copy still maps nids that have since been freed:
  deleted inodes resolve to their old node blocks, and live nids whose
  blocks moved reveal **prior versions** of those inodes.
* **SIT free segments** — blocks the SIT marks invalid are scanned for
  surviving node footers and dentry blocks, recovering files no table
  still references.
* **Dentry residue** — deleting a name only clears bitmap bits; the dirent
  and filename bytes persist in the dentry block. Bitmap-clear slots with
  plausible contents are emitted as deleted-name evidence.
* **Orphan inodes** — files unlinked while open are recorded in the
  checkpoint's orphan list and are still NAT-allocated.

## Usage

```rust
use std::sync::Arc;
use sutram_f2fs::F2fsParser;
use sutram_fs::{FsParser, MountOptions, FileSystem};
use sutram_io::FileSource;

let src = FileSource::open("userdata.img")?;           // or any ByteSource
assert!(F2fsParser.detect(&src) >= sutram_fs::DetectConfidence::High);

let fs = F2fsParser.mount(Arc::new(src))?;
println!("{}", fs.info().fs_type);                     // "F2FS"

for item in fs.walk() {
    match item {
        Ok(entry) => {
            println!("{:>12?} {:>10} {}", entry.kind, entry.size, entry.path);
            if entry.is_deleted() {
                println!("    recovery: {:?}", entry.status);
            }
        }
        Err(e) => eprintln!("corruption note: {e}"),    // lenient mode
    }
}
```

`MountOptions::strict()` aborts the walk on the first corrupt structure;
the default is lenient — errors arrive as `Err` items interleaved with
entries.

## Recovery semantics

Every entry carries `FsEntryStatus`:

* `Live` — reachable from the live dentry tree via the current NAT.
* `Deleted { recovery }` — `RecoveryState` is assessed **per extent**
  using the SIT: a deleted file's block survives iff SIT does not mark it
  valid (a valid bit means the block was reallocated to live data).
  - `Intact` — every recorded extent still points at surviving bytes.
  - `PartiallyOverwritten { recovered_bytes, total_bytes }` — some
    extents were reallocated; `allocated_ranges` lists only the surviving
    byte ranges, and `read_file` yields just those bytes.
  - `Unrecoverable` — inode metadata survives but no extent does.
  - `Unknown` — the name/record survives but its node could not be read
    (e.g. nid reused by a live inode, noted as `nid_reused`).

`meta` keys flag provenance: `recovery_source` (`dentry-residue`,
`stale-nat`, `checkpoint-orphan`, `free-segment-scan`,
`prior-version-*`), `dentry_residue`, `stale_dentry_block`, `orphan`,
`prior_version`, `nid_reused`, `seg_mtime`, plus structural detail
(`nid`, `mode`, `uid`/`gid`, `flags`, `node_cp_ver`, `ext_cache`,
`inline_data`, `inline_dentry`, …).

Prior inode versions appear under `/$ORPHANED/nid_<N>_v<cp_ver>` and
unnamed recovered inodes under `/$ORPHANED/`; recovered names keep their
original path when the dentry residue provides one.

## Also supported

* Full MACB + `crtime` timestamps at nanosecond granularity
  (`f2fs-sec-nsec` encoding), including `EXTRA_ATTR` inodes.
* Direct / indirect / double-indirect node chains, inline data, inline
  dentries, xattr blocks and inline xattrs, symlinks.
* **fscrypt awareness** — encrypted files/dirs get `meta["encrypted"] =
  "fscrypt"` and the parsed context (`fscrypt_context`, `fscrypt_modes`);
  children of encrypted dirs get `encrypted_name`. **No decryption is
  performed** — ciphertext names surface sanitised.
* `unallocated_ranges()` — SIT-free main-area blocks (the carving
  ground).
* Magic/extension verdicts via `sutram-magic` (`MountOptions.check_magic`,
  bounded 4 KiB header reads).
* Superblock and checkpoint CRC validation (`SB_CHKSUM`, per-pack CRC).

## Known limitations

* **No decryption** — fscrypt filenames and contents are reported as
  ciphertext with metadata flags only.
* **No compression support** — compressed extents (`COMPRESS_ADDR`
  clusters, `F2FS_FEATURE_COMPRESSION`) are flagged
  (`meta["compressed"]`) but not decompressed.
* **SSA** is consulted for provenance notes on reallocated blocks;
  `PACKED_SSA` images fall back to SIT-only recovery.
* Orphan/NAT scan covers allocated-and-stale nids; node blocks with no
  surviving NAT copy are found only by the free-segment scan (inode nodes
  and dentry blocks — bare dnode/indirect blocks are noted, not emitted).
* Roll-forward data (post-checkpoint fsync chains) is not replayed; the
  view is as of the newest valid checkpoint pack.
* `i_addr`/`i_nid` layout is computed for the mounted block size; the
  common 4 KiB layout is fully exercised in tests.

## Testing

`cargo test` — the suite builds a complete synthetic F2FS image in memory
(superblock, dual checkpoint packs, SIT/NAT/SSA, live tree, deleted nid,
prior-version node, orphan inode, partially and fully overwritten files)
and exercises detection, walking, reading, recovery classification,
timestamps, encryption flags, magic verdicts, unallocated ranges, and
strict/lenient walking.

## License

Dual-licensed under MIT or Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
