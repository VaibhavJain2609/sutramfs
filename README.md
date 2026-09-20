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
- `ewf::EwfSource` — documented stub for the planned pure-Rust EWF (E01)
  reader. Never FFI to libewf.

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

## Deleted / recovery semantics

This crate is below the filesystem layer and therefore reports no file
records itself; it guarantees that deleted-data recovery in the parser crates
has a faithful, offset-exact view of the medium (including unallocated
regions — nothing is filtered).

## Known limitations

- EWF (E01) and other compressed forensic containers are stubbed; only raw
  images and Android sparse are readable today.
- Partition parsing assumes 512-byte sectors, probing 4096 only for GPT.
- BSD disklabels, APM and dynamic (LDM) disks are not parsed.

## License

Dual-licensed under MIT or Apache-2.0, at your option. See `LICENSE-MIT`
and `LICENSE-APACHE`.
