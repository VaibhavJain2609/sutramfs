# SUTRAM-FS Conventions

**Every parser crate in this project MUST follow this document.** The
reference implementation is `sutram-fat` — read it first; when in doubt,
pattern-match it. The foundation crates are `sutram-io` (byte sources,
partitions, sparse images) and `sutram-fs` (traits/types). `sutram-magic`
provides signature verdicts.

## 1. Crate layout

Each filesystem parser is an independent repo/crate named `sutram-<fs>`
(never a cargo workspace member — these become separate public crates):

```
sutram-<fs>/
├── Cargo.toml
├── LICENSE-MIT / LICENSE-APACHE      # both files, verbatim
├── README.md
├── .gitignore                        # /target, Cargo.lock, *.rs.bk
├── .github/workflows/ci.yml          # matrix CI (§7)
├── src/
│   ├── lib.rs                        # #![forbid(unsafe_code)], docs, re-exports
│   ├── boot.rs / superblock.rs       # on-disk structure parsing + detect
│   ├── <format structs>.rs           # dirent/inode/record decoding
│   ├── fs.rs                         # the FileSystem impl
│   ├── walk.rs                       # the streaming iterator
│   └── tests.rs                      # unit tests
└── tests/
    ├── common/mod.rs                 # synthetic image builders (§6)
    └── forensic.rs                   # integration tests
```

`Cargo.toml` must be exactly:

```toml
[package]
name = "sutram-<fs>"
version = "0.1.0"
edition = "2021"
rust-version = "1.85"          # MSRV — stable 1.96 must build it
license = "MIT OR Apache-2.0"
description = "<FS> forensic filesystem parser (…)"

[dependencies]
sutram-io    = { path = "../sutram-io",    version = "0.1" }
sutram-fs    = { path = "../sutram-fs",    version = "0.1" }
sutram-magic = { path = "../sutram-magic", version = "0.1" }
```

Rules:

- **Pure-Rust deps only.** No C dependencies, no `*-sys`, no x86-only
  crates. Zero-dependency is preferred; justify any addition.
- **`#![forbid(unsafe_code)]` at the top of every `lib.rs`.** If a crate
  genuinely needs unsafe (it shouldn't — mmap is optional and can live in
  a leaf impl), document the exception in the README and this file.
- Everything is little-endian unless the format says otherwise — decode
  with `sutram_io::le::*` or `from_le_bytes` on copied arrays. **Never**
  `transmute`, pointer-cast, or read with host-endian assumptions.
- Public parser type: `pub struct <Fs>Parser;` + `pub struct <Fs>Fs`
  re-exported from `lib.rs`. Internal machinery stays `pub(crate)`.

## 2. The forensic contract (non-negotiable)

1. **Read-only.** Parsers receive `Arc<dyn ByteSource>`/`&dyn ByteSource`.
   There is no write path. Ever.
2. **Bounded memory / streaming.** `walk()` yields one `FsEntry` at a
   time. Per-directory or per-record buffering is fine; the whole FS is
   not. Metadata indexes built at mount (e.g. live-allocation maps) must
   be proportional to *live metadata*, not raw image bytes, unless the
   format fundamentally requires it (document it).
3. **No panics on untrusted input.** No `unwrap`/`expect`/unchecked
   indexing on parsed data (tests may). Malformed input → `FsError`.
   Guard every allocation by a plausibility bound (see `MAX_GPT_ENTRIES`
   in sutram-io).
4. **Lenient by default.** `MountOptions::strict` is the opt-in. In
   lenient mode a corrupt region yields `Err(FsError)` items *inside* the
   walk stream and the walk continues; in strict mode the first error is
   terminal.
5. **Provenance.** Every `FsEntry` sets `disk_offset` (offset of the
   metadata record that produced it) and `allocated_ranges` (absolute
   `(offset,len)` data extents). A court must be able to ask "which bytes
   produced this" and get an answer.
6. **Deleted & recoverable.** `status` is `Live` or
   `Deleted{recovery}`. Compute `RecoveryState` honestly:
   - `Intact` — all expected extents survive;
   - `PartiallyOverwritten{recovered_bytes,total_bytes}` — some survive;
     `allocated_ranges` lists exactly what; `read_file` returns only
     recoverable bytes;
   - `Unrecoverable` — metadata only;
   - `Unknown` — cannot determine.
   Emit orphans/lost artefacts under `/$ORPHANED/<id>`
   (`util::orphan_path`) where the format permits.
7. **Timestamps.** Populate every MACB slot the format stores via
   `FsTimestamp{value:Option<i64> /*ns since epoch*/, raw_value,
   raw_encoding, granularity}`. Never fabricate: unset fields →
   `value: None`; unstored slots → `None`. Use `util::unix_nanos`.
8. **Magic.** For every `EntryKind::File` with readable data, read a
   bounded header (≤4 KiB) and set `entry.magic =
   Some(sutram_magic::check_entry(&entry.name, &header))` when
   `opts.check_magic` is on. Do not reimplement signature tables.

## 3. Error taxonomy usage

| Situation                                   | Variant                          |
|---------------------------------------------|----------------------------------|
| Malformed on-disk structure                 | `Corrupt{offset,msg}`            |
| Image shorter than a structure needs        | `Truncated{offset,needed,available}` |
| Recognised but unsupported (version/crypto) | `Unsupported{msg}`               |
| Source read failure                         | `Io` (via `From`)                |
| Path/entry lookup miss                      | `NotFound{path}`                 |
| Bad caller argument                         | `InvalidInput{msg}`              |

`offset` is always absolute bytes on the mounted source. Convert
`sutram_io::Error` via `From`. Walk-stream errors are `Err` *items*;
mount failures are `Err` *returns*.

## 4. `FsParser`/`FileSystem` implementation checklist

- [ ] `name()` — short lowercase: `"ntfs"`, `"ext4"`, …
- [ ] `detect()` — reads only a few KiB at fixed offsets; checks the
      format's signature *and* excludes lookalikes; returns the honest
      `DetectConfidence` (`None`…`Certain`).
- [ ] `mount_with()` — validates the superblock (firmer than detect;
      `Corrupt` on nonsense), builds whatever live-allocation metadata the
      recovery analysis needs.
- [ ] `info()` — `fs_type`, `label`, `uuid`, `block_size`,
      `total_blocks`, `free_blocks`, format extras in `meta`.
- [ ] `walk()` — live tree **and** deleted entries **and** orphans;
      `Err` records on corruption; terminates.
- [ ] `read_file()` — returns a `Read` over `allocated_ranges` capped at
      `size`; `InvalidInput` for non-files.
- [ ] `unallocated_ranges()` — free-space byte ranges.
- [ ] `carve_region()` — default trait impl is acceptable; override when
      the format knows better alignment (clusters, inode tables).
- [ ] Loop guards on **every** chain/extent/b-tree walk (visited-set or
      hard cap). Untrusted images contain cycles.
- [ ] Tests build synthetic images in `tests/common/mod.rs` (§6).

### `meta` key registry (use these names; add new ones here)

`attributes`, `dos_name`, `lfn`, `lfn_checksum_ok`, `lfn_partial`,
`deleted_marker`, `beyond_eod`, `hidden`, `system`, `readonly`,
`symlink_target`, `orphan`, `slack_offset`, `slack_len`,
`recovery_note_<n>`, `size_note`, `note`.

ext4 keys: `inode`, `inode_offset`, `mode`, `uid`, `gid`, `generation`,
`links_count`, `file_type`, `mapping` (`extents`/`indirect`/`inline`),
`htree`, `encrypted`, `casefold`, `inline_data`, `xattr_count`, `xattrs`,
`hardlink_of`, `carved_dirent`, `inode_cleared`, `inode_reused`,
`inode_unallocated`, `orphan_list`, `journal`.

`FsInfo.meta`: `fat_variant`, `oem`, `num_fats`, `media`,
`sectors_per_cluster`, `reserved_sectors`, `root_entries`,
`bytes_per_sector`, `fat_size_sectors`, `total_sectors`,
`ext_variant`, `feature_compat`, `feature_incompat`, `feature_ro_compat`,
`incompat_*`, `compat_*`, `rocompat_*` (per-feature booleans),
`inode_size`, `block_groups`, `blocks_per_group`, `inodes_per_group`,
`desc_size`, `mount_count`, `fs_state`, `errors_policy`, `rev_level`,
`free_inodes_count`, `mount_time_raw`, `write_time_raw`, `mkfs_time_raw`,
`last_orphan`, `journal_inode`, `backup_superblock_count`,
`groups_per_flex`, `gdt_offset`, `jbd2_superblock_offset`,
`jbd2_block_size`, `jbd2_journal_blocks`, `jbd2_first_block`,
`jbd2_sequence`, `jbd2_start`, `jbd2_nr_users`, `jbd2_needs_replay`, …

Journal-forensic keys (pseudo-entries are tagged `journal` = `jbd2` /
`ntfs` / `hfs+`):

- `FsEntry.meta` (ext4/jbd2): `jbd2_transid`, `jbd2_fs_block`,
  `jbd2_journal_block`, `jbd2_target`, `jbd2_target_allocated`,
  `jbd2_tag_flags`, `jbd2_tag_uuid`, `jbd2_tag_deleted`, `jbd2_escaped`,
  `jbd2_commit_time`, `jbd2_revoked_blocks`, `jbd2_revoked_count`.
- `FsEntry.meta` (NTFS): `usn`, `usn_reason`, `usn_reason_names`,
  `file_ref`, `parent_ref`, `parent_name`, `usn_version`,
  `source_info`, `security_id`, `file_attributes`,
  `usn_stream_offset`; `$LogFile`: `current_lsn`, `log_clients`,
  `seq_nr_bits`, `restart_area_len`, `logfile_size`, `record_page_len`,
  `lsn`, `client_prev_lsn`, `client_undo_next_lsn`, `record_type`,
  `transaction_id`, `flags`, `redo_op`, `undo_op`, `redo_len`,
  `undo_len`, `client_data_len`.
- `FsEntry.meta` (HFS+): `hfs_journal_tx`, `num_blocks`, `bytes_used`,
  `checksum_ok`, `live`, `target_sector`, `target_offset`.
- `FsInfo.meta` (journal counts): `jbd2_feature_compat`,
  `jbd2_feature_incompat`, `jbd2_features`, `jbd2_last_transid`,
  `jbd2_descriptor_blocks`, `jbd2_commit_blocks`, `jbd2_revoke_blocks`,
  `jbd2_journaled_blocks`, `jbd2_transactions`,
  `jbd2_prior_metadata_copies`, `jbd2_target_allocated_blocks`,
  `jbd2_summary`, `jbd2_parse_errors`; `usn_journal_present`,
  `logfile_present`, `usn_stream_size`, `logfile_size`,
  `usn_scan_truncated`, `logfile_scan_truncated`, `usn_records`,
  `logfile_restart_areas`, `logfile_records`, `logfile_checkpoints`,
  `logfile_torn_pages`; `journal_start`, `journal_end`,
  `journal_buffer_len`, `journal_jhdr_size`, `journal_endian`,
  `journal_transactions`, `journal_stale_transactions`,
  `journal_block_copies`; `journal_parse_errors` (all three).

## 5. Naming & display conventions

- Deleted FAT-style names: lead byte shown as `_` (`_ELETED.TXT`) +
  `meta["deleted_marker"]`.
- Orphans: `/$ORPHANED/chain_<n>`-style names via `util::orphan_path`.
- Sanitise all on-disk names through `util::sanitize_name` (strips `/`,
  `\`, control chars) — dirents are hostile input.
- Hex in `meta` values: `0x`-prefixed lowercase.

## 6. The test-corpus pattern (MANDATORY)

Every parser's tests **construct the filesystem in memory** — no fixture
files, no network, no external corpora. `sutram-fat`'s
`tests/common/mod.rs` is the template:

- Write the boot sector/superblock byte-by-byte with `w16`/`w32` helpers
  (little-endian encoders).
- Write allocation tables, directory tables, and file data at computed
  offsets; expose `clus_off()`/`inode_off()` helpers so tests can assert
  `disk_offset`/`allocated_ranges` provenance.
- The corpus must include at minimum: a live file, a deleted-intact file,
  a **partially overwritten** deleted file (cluster/extent reallocated to
  a live file), a fully-overwritten one, a long/unicode name, a
  subdirectory, an orphan artefact, a masquerade file (e.g. `MZ` content
  under a document extension → assert `Severity::High`), and a
  container-consistent file (e.g. `.docx` containing `PK` → no mismatch).
- Keep corpora small: pad geometry constants, or use a `OnceLock<Vec<u8>>`
  shared image if the format mandates a large minimum size.
- Also test: `detect()` on the corpus and on garbage/foreign signatures;
  `read_file` round-trips; `deleted_entries()`; `unallocated_ranges()`;
  lenient walk over a deliberately corrupted image (no panic, partial
  results); strict-mode behaviour.
- Unit tests for each decoder (name parsing, timestamp math, chain
  walking) live in `src/tests.rs`.

## 7. CI & repo hygiene

- `.github/workflows/ci.yml` — copy the matrix from `sutram-io`: native
  `cargo test` on `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`,
  `x86_64-pc-windows-msvc`; cross test on `aarch64-unknown-linux-gnu` via
  `cross`; cross *build* for `x86_64-apple-darwin` and
  `aarch64-pc-windows-msvc`. `RUSTFLAGS: -D warnings`.
- License: `LICENSE-MIT` + `LICENSE-APACHE` verbatim copies; `license =
  "MIT OR Apache-2.0"` in Cargo.toml.
- `.gitignore`: `/target`, `Cargo.lock`, `*.rs.bk`.
- Commits: short imperative subject (`"Add GPT partition parsing"`,
  `"Handle deleted LFN fragments"`). Commit working, tested states only.
- `cargo test` green and `cargo build --release` warning-free before
  committing.

## 8. README template

Every parser README follows this skeleton (see `sutram-fat/README.md`):

1. **What this filesystem is** — one paragraph for a forensic examiner
   who hasn't seen the format.
2. **Forensic features** — bulleted: deleted/orphan/slack handling,
   timestamps (with granularities), provenance, magic verdicts, quirks.
3. **Usage** — `FileSource` → `detect` → `mount` → `walk` example.
4. **Deleted / recovery semantics** — how this parser decides
   `RecoveryState`, honestly, including its limits.
5. **Known limitations** — be blunt; examiners rely on this.
6. **License** — dual MIT/Apache-2.0 note.

## 9. Deferred / shared backlog (coordinate before duplicating work)

- `sutram-io::ewf::EwfSource` — pure-Rust EWF reader (miniz_oxide +
  extent mapping); interface defined, implementation open.
- qcow2/VMDK/VHD decoders → emit `SparseFile` extents.
- `sutram-part` may absorb deeper table types (BSD, APM); MBR/GPT live
  in `sutram-io`.
- WhatsApp crypt12/14/15 and PKCS#12 are declared-by-extension types in
  sutram-magic (no reliable magic) — structural validators are out of
  scope for the magic layer.
