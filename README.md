# sutram-artifacts

Pure-`std` forensic parsers for individual **artifact files** — the
content of one file, not a filesystem. Each parser takes a `&[u8]` (or a
`Read` via `from_reader`, bounded at 256 MiB) and returns a typed
artifact struct in which every record carries an absolute `offset`
provenance field naming the exact bytes that produced it.

Part of the [sutramfs](../README.md) toolkit; conventions in
[../CONVENTIONS.md](../CONVENTIONS.md). Dependency-free —
`#![forbid(unsafe_code)]`, MSRV 1.85.

## Parsers

| Module      | Artifact                                        | Entry point               |
|-------------|-------------------------------------------------|---------------------------|
| `lnk`       | Windows `.lnk` shortcut (MS-SHLLINK)            | `lnk::LnkFile`            |
| `reg`       | Windows registry hive (`regf` / hbin cells)     | `reg::Hive`               |
| `recycle`   | Windows `$I*` recycle-bin metadata (v1 + v2)    | `recycle::RecycledItem`   |
| `plist`     | Apple binary property list (`bplist00`)         | `plist::Plist`            |
| `prefetch`  | Windows Prefetch (`SCCA` v17–31, `MAM` detect)  | `prefetch::Prefetch`      |

## Error contract

All parsers share `Error`/`Result`, mirroring the sutram taxonomy:

- `Corrupt { offset, msg }` — malformed structure
- `Truncated { offset, needed, available }` — input too short
- `Unsupported { msg }` — recognised variant we do not decode
- `Io` — `from_reader` source failure
- `InvalidInput { msg }` — bad caller argument / size cap

No parser panics on untrusted input. Fixed headers are strict (a bad
signature means "not this format"); optional substructures are lenient —
corruption is recorded in a `warnings` field or `Err` stream items and
parsing continues where the format permits.

Timestamps use `ArtifactTimestamp` (re-exported as `FsTimestamp`), a
field-for-field mirror of `sutram_fs::FsTimestamp`: decoded `value` in
nanoseconds since the Unix epoch (`None` when unset/unrepresentable —
never fabricated), plus `raw_value`, `raw_encoding`, and `granularity`
for byte-level citation.

## Forensic features

- **LNK** — target MAC FILETIMEs + size, LinkInfo volume serial & paths,
  StringData (args, working dir, icon location), and the
  **TrackerDataBlock**: NetBIOS machine name plus droid GUIDs whose v1
  UUIDs decode to the **MAC address and creation timestamp** of the
  machine that wrote the link. All other ExtraData blocks (console,
  property store, shim, …) are enumerated with offset/size/signature.
- **Registry hive** — streaming `HiveWalker` over the nk/vk/sk/lf/lh/ri
  cell graph, `all_keys()` convenience, FILETIME last-write per key,
  typed value decode, and a **deleted-forensics pass** that scans
  unallocated hbin cells for orphan nk/vk records (`deleted_keys()`).
- **$I recycle-bin** — version 1 (Vista/7) and version 2 (Win10+)
  layouts → original path, size, deletion FILETIME.
- **bplist** — full object model (`Plist` enum), UID/real/date/data
  types, `to_json()` serialisation, cycle-safe.
- **Prefetch** — versions 17/23/26/30/31, executable name, run count,
  last-run FILETIME array (8 slots on v26+); `MAM\x04` XPRESS-wrapped
  Win10/11 files are detected and reported `compressed: true` (body
  returns `Unsupported` — no decompressor shipped).

## Usage

```rust
use sutram_artifacts::lnk::LnkFile;

let data = std::fs::read("suspicious.lnk")?;
let lnk = LnkFile::parse(&data)?;
if let Some(t) = &lnk.tracker {
    println!("wrote on machine {} (mac {:?})", t.machine_id, t.mac);
}
println!("target mtime: {:?}", lnk.target_mtime.value);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Known limitations

- **Prefetch**: XPRESS-Huffman (`MAM`) bodies are detected, not decoded.
  Version-30 "variant 2" run-count placement is handled via the metrics
  offset heuristic and flagged in `warnings`.
- **Registry**: `sk` security descriptors and `db` big-data cells are
  enumerated but not decoded; li/lh/lf hash bytes are not validated.
- **LNK**: `CommonNetworkRelativeLink`, `DarwinDataBlock`, property-store
  internals are skipped (offsets recorded).
- **$I**: only the documented v1/v2 layouts; unknown versions return
  `Unsupported`.
- **bplist**: 128-bit integers and open-step/XML plists are unsupported.

## License

Dual-licensed under MIT or Apache-2.0 (`LICENSE-MIT` / `LICENSE-APACHE`).
