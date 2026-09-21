# sutram-io

Read-only byte-source abstractions, partition-table parsing and sparse-image
plumbing for the **SUTRAM-FS** family of Rust filesystem-forensics crates.

Part of the SUTRAM-FS project — see `CONVENTIONS.md` at the repository root
for the contract every crate follows.

## What this crate is

The I/O foundation layer. It defines `ByteSource` — a read-only, randomly
addressable view of evidence bytes — plus the container machinery that sits
between a raw acquisition and a filesystem parser:

- `ByteSource` impls for `Vec<u8>`, `&[u8]`, `std::fs::File` (positioned
  reads; no mmap, no `unsafe`), and `Arc`/`Box` forwarding.
- `OffsetView` — a bounds-checked window into a source (partition views).
- `ConcatSource` — glues split images (`disk.001`, `.002`, …) end-to-end.
- `SparseFile` — extent-mapped image (data / zero / fill-pattern extents),
  including `SparseFile::from_android_sparse` for Android sparse images.
- MBR + GPT partition parsing (`partitions`, `open_partitions`) producing
  partitions with absolute byte offsets.
- `ewf::EwfSource` — pure-Rust EWF (Expert Witness Format / `.E01`)
  reader: single- and multi-segment (`.E02`+) images, zlib-compressed and
  raw chunks, `table`/`table2` chunk maps, `error2` acquisition-error
  ranges, and stored MD5/SHA-1 integrity hashes. Never FFI to libewf.
- `vhd::VhdSource` — VHD and VHDX virtual-disk reader: fixed and
  dynamic VHD (BAT + sector bitmaps), non-differencing VHDX (region
  table + u64 BAT, CRC-32C-checked headers).
- `qcow2::Qcow2Source` — QCOW2 reader: two-level L1/L2 cluster map,
  raw-deflate compressed clusters, zero/unallocated cluster handling.

## Forensic guarantees

- **Read-only** — there is no write API on `ByteSource`.
- **Provenance** — all offsets are absolute `u64` byte offsets;
  `OffsetView::base_offset` recovers the position inside the parent image.
- **Bounded memory** — readers pull into caller buffers; sparse images are
  O(extents), never O(image size).
- **No panics on untrusted input** — corrupt partition tables and malformed
  sparse headers return `Error::Corrupt`/`Unsupported`/`Truncated`.
- **Explicit endianness** — the `le` module provides non-panicking
  little-endian decoders; host order is never assumed.

## Usage

```rust,no_run
use std::sync::Arc;
use std::fs::File;
use sutram_io::{open_partitions, ByteSource, FileSource};

let disk = Arc::new(FileSource::open("disk.raw")?) as Arc<dyn ByteSource>;
for part in open_partitions(disk)? {
    println!(
        "partition {}: offset={:#x} size={} label={:?}",
        part.partition.index, part.partition.offset,
        part.partition.size, part.partition.label
    );
    // part.source is a ByteSource ready for a filesystem parser.
}
# Ok::<(), sutram_io::Error>(())
```

## EWF (E01) support

`ewf::EwfSource::open` turns an EnCase/FTK `.E01` image into a
`ByteSource`, so every parser built on this crate can mount forensic
images directly. Multi-segment images pass all segments in order (or use
`open_segments` with paths):

```rust,no_run
use std::sync::Arc;
use sutram_io::{into_arc, ByteSource, FileSource};
use sutram_io::ewf::EwfSource;

// Single segment:
let seg = into_arc(FileSource::open("case01.E01")?);
let img = EwfSource::open(vec![seg])?;

// Multi-segment (.E01 + .E02 + …) by path:
let img2 = EwfSource::open_segments(&["case02.E01", "case02.E02"])?;
println!("{} bytes over {} segments", img2.len(), img2.info().segment_count);

println!("{} bytes, chunk size {}", img.len(), img.info().chunk_size);
if let Some(h) = img.acquisition_hash() {
    println!("stored MD5: {:?}", h.md5_hex());
}
for w in img.warnings() { eprintln!("ewf: {w}"); }
// `img` is a ByteSource: read_at / read_slice / partitions(&img)/…
# Ok::<(), sutram_io::Error>(())
```

- Chunks are zlib-deflate or raw (auto-detected per table-entry flag bit);
  reads are served through a bounded 8-chunk LRU cache.
- Multi-segment images share one logical chunk table; each table entry
  addresses bytes inside the segment file that declared it. Chunk order
  follows the supplied segment order — a last segment that still declares
  `next` is a clear `InvalidInput` error, not a silent zero tail.
- `error2` acquisition-error ranges read as zeros (what the acquisition
  tool stored) and are listed via `error_ranges()`.
- Stored `hash`/`digest` MD5 + SHA-1 are exposed via `acquisition_hash()` —
  they are the acquisition tool's *claims*, verify them yourself.
- Non-fatal anomalies (checksum mismatches, table/count mismatches,
  degraded entries, segment-number mismatches) are collected in
  `warnings()`, never panics.
- `table2` mirrors are used automatically when a `table` section is
  missing or yields fewer entries.

### EWF limitations

- EWF2 (`.Ex01`), logical evidence files (`.L01` / media type `0x0e`) and
  SMART `.s01` layouts return `Error::Unsupported`.
- Segment ordering is the caller's responsibility; a segment whose
  declared number disagrees with its position earns a warning, not a
  re-ordering.
- A chunk whose zlib stream is corrupt yields `io::Error(InvalidData)` on
  reads touching it — corrupt stored data is never silently replaced with
  zeros. Missing/out-of-range *table entries* do zero-fill (documented
  leniency) plus a warning.
- `session`, `ltree`, `xheader` and other metadata sections are skipped,
  not interpreted. Section-internal checksums beyond the descriptor's are
  recorded but not yet verified.

## VHD / VHDX support

`vhd::VhdSource::open` auto-detects the format (`vhdxfile` signature →
VHDX, else the `conectix` footer) and exposes the virtual disk as a
`ByteSource`:

```rust,no_run
use sutram_io::{into_arc, ByteSource, FileSource};
use sutram_io::vhd::VhdSource;

let file = into_arc(FileSource::open("disk.vhd")?);
let img = VhdSource::open(file)?;
println!("{:?} {} bytes", img.info().format, img.len());
for w in img.warnings() { eprintln!("vhd: {w}"); }
# Ok::<(), sutram_io::Error>(())
```

- VHD: fixed (type 2) and dynamic (type 3) disks. Dynamic blocks are
  dispatched through the BAT (u32 sector offsets, `0xFFFFFFFF` =
  unallocated → zeros); each block's sector bitmap is honoured so
  unwritten sectors read as zeros. A footer hidden behind trailing
  garbage is recovered by a bounded tail scan.
- VHDX: the checksum-valid header and region-table copies are picked per
  the format's redundancy rules; BAT states `NOT_PRESENT`/`UNDEFINED`/
  `ZERO`/`UNMAPPED` read as zeros, `FULLY_PRESENT` reads payload.
- Differencing images (VHD type 4, VHDX `HasParent`/parent-locator) need
  their parent to resolve blocks → `Error::Unsupported`.

### VHD / VHDX limitations

- **No differencing chains** — supply the flattened/base image.
- VHDX log regions are not replayed (a non-empty log produces a warning;
  the view may be slightly stale).
- Corrupt stored payload is returned as-is or zero-filled where the
  allocation map says unallocated; CRC failures on VHDX headers/region
  tables fail open only if the redundant copy validates.

## QCOW2 support

`qcow2::Qcow2Source::open` exposes a QCOW2 virtual disk as a
`ByteSource`:

```rust,no_run
use sutram_io::{into_arc, FileSource};
use sutram_io::qcow2::Qcow2Source;

let img = Qcow2Source::open(into_arc(FileSource::open("disk.qcow2")?))?;
println!("v{} {} bytes, {}-byte clusters",
    img.info().version, img.len(), img.info().cluster_size);
# Ok::<(), sutram_io::Error>(())
```

- Versions 2 and 3; unallocated, zero-flagged and compressed clusters all
  handled (compressed clusters are raw deflate — QEMU's "zlib" mode has
  no zlib wrapper — decoded via `miniz_oxide`).
- Unallocated clusters and out-of-range host offsets read as zeros; a
  corrupt deflate stream yields `io::Error(InvalidData)` on reads
  touching it.
- Refcount tables are ignored — the reader never writes.
- Decoded clusters are served through a bounded LRU cache; L2 tables are
  cached raw.

### QCOW2 limitations

- **No backing files** (differencing), no AES/LUKS encryption, no
  external-data-file / extended-L2 / non-deflate-compression
  incompatible features — all return `Error::Unsupported`.
- `dirty`/`corrupt` incompatible flags and unknown feature bits produce
  warnings, not failures.
- Snapshots are not exposed (the active image is what you read).

## Deleted / recovery semantics

This crate is below the filesystem layer and therefore reports no file
records itself; it guarantees that deleted-data recovery in the parser crates
has a faithful, offset-exact view of the medium (including unallocated
regions — nothing is filtered).

## Known limitations

- EWF support covers E01 segments (single- and multi-segment `.E02`+);
  EWF2 (`.Ex01`), L01 and SMART `.s01` variants return `Unsupported`.
- VHD/VHDX and QCOW2: no differencing/backing-file chains, no encrypted
  qcow2; VMDK is not yet decoded.
- Partition parsing assumes 512-byte sectors, probing 4096 only for GPT.
- BSD disklabels, APM and dynamic (LDM) disks are not parsed.

## License

Dual-licensed under MIT or Apache-2.0, at your option. See `LICENSE-MIT`
and `LICENSE-APACHE`.
