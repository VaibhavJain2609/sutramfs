# sutram-part

Android partition-layer parser for the SUTRAM-FS project — the layer that
turns a seized device image (or a single `*.img` from a factory package)
into mountable `ByteSource` views that `sutram-f2fs`, `sutram-ext4` and the
other filesystem parsers can run on.

Part of the SUTRAM-FS project — see `CONVENTIONS.md` at the repository root
for the contract every crate follows. This crate is a *container* layer
(like `sutram-io`), not an `FsParser`: it produces partition views, not a
file walk.

## What this layer is

Modern Android images are not raw filesystems. `fastboot` artifacts are
`img2simg` *sparse* files; Android 10+ devices keep their logical
partitions inside a physical `super` partition described by `liblp`
metadata; verified boot state lives in AVB `vbmeta` blobs; and the whole
device carries a GPT whose names (`boot_a`, `vendor`, `userdata`,
`metadata`, `persist`, …) carry the forensic meaning. This crate unwinds
all of that into named, mountable partition sources.

## Forensic features

- **Android sparse (`simg`)** — `0xED26FF3A` detection; decoding delegated
  to `sutram-io`'s `SparseFile` (RAW/FILL/DONT_CARE extents). Extra
  validation: data extents must lie inside the backing source (truncated
  dumps fail at open, not mid-walk), and the decoded size is cross-checked
  against `total_blks * blk_sz`.
- **Dynamic partitions (`liblp`)** — `LpMetadataGeometry` at `0x1000`
  (backup at `0x2000`), metadata slots at `0x3000 + n·max_size` (backups
  follow the primaries). Header and table SHA-256 checksums are **verified**
  — a mismatch is a warning, not a refusal: tampering is a finding.
  Partition/extent/group/block-device tables are decoded; each logical
  partition becomes an extent-mapped `SparseFile` over the image (LINEAR →
  data extents, ZERO → holes). Slot fallback order: slot 0 primary →
  backup → slot 1 → …
- **A/B slots** — `LP_PARTITION_ATTR_SLOT_SUFFIXED` names get the metadata
  slot's suffix applied (`_a` for slot 0, `_b` for slot 1); GPT names keep
  their own suffix and are still classified on the de-suffixed base.
- **AVB vbmeta** — 256-byte big-endian header (algorithm, rollback index,
  `HASHTREE_DISABLED`/`VERIFICATION_DISABLED` flags → `dm_verity` state),
  descriptor walk (property, hashtree, hash, kernel cmdline, chain
  partition), and the 64-byte `AVBf` footer that embeds vbmeta inside boot
  partitions.
- **Encryption flags** — `crypt_ftr` (`0xD0B5B1C4` at `end-0x4000`) on
  userdata, and the `metadata` partition as the FBE metadata-encryption
  keyblob store. Flagged in `AndroidLayout.crypto` + `warnings`;
  **never decrypted**.
- **Name heuristics** — `classify_name` maps Android partition names to
  roles (boot, vbmeta, super, system/vendor/product/odm/dlkm, userdata,
  metadata, persist, modem, bootloader chains, …).
- **Provenance** — `NamedSource.meta` carries absolute offsets, table
  GUIDs, extent counts, the LP slot used and whether a backup copy was
  needed.

## Usage

```rust,no_run
use std::sync::Arc;
use sutram_io::{ByteSource, FileSource};
use sutram_part::{analyze, ContainerKind};

let src = Arc::new(FileSource::open("flash.raw")?) as Arc<dyn ByteSource>;
let layout = analyze(src)?;
println!("container: {}", layout.container.as_str());
for p in &layout.partitions {
    println!("{:<24} role={:<10} {:#x} B  meta={:?}",
             p.name, p.role.as_str(), p.source.len(), p.meta);
    // mount p.source with sutram-f2fs / sutram-ext4 / …
}
for w in &layout.warnings { eprintln!("note: {w}"); }
# Ok::<(), sutram_fs::FsError>(())
```

Lower-level entry points: `open_sparse`, `read_geometry`,
`read_metadata`, `logical_partitions` (super only), `parse_vbmeta`,
`find_vbmeta`, `find_crypt_footer`.

## Recovery semantics

This layer doesn't undelete files, but it preserves the truth:

- Checksum failures are surfaced as warnings (`LP slot N: tables SHA-256
  mismatch`) while parsing continues — a tampered table is still read.
- Extents pointing at other physical block devices (multi-LUN supers) are
  mapped as zero-filled holes and flagged `meta["external_extents"]` —
  never silently mapped to wrong bytes.
- A super image whose geometry is intact but whose metadata slots are all
  unreadable still reports `container: Super` with a warning, rather than
  degrading to `Raw` and hiding the classification.
- `container` reports the **outermost** layer: a sparse-wrapped
  `super.img` reports `Sparse` (partitions still come from the decoded
  inner image; `warnings` describe the nesting).

## Known limitations

- Sparse `image_checksum` (CRC32) is reported, not verified — the CRC
  chunks are skipped by `SparseFile`.
- vbmeta signatures/hashes are parsed for metadata only; cryptographic
  verification is out of scope.
- LP extents on non-zero block-device indices (multi-LUN devices) cannot
  be resolved from a single super image — flagged, mapped as holes.
- FBE/FDE content is flagged, never decrypted; the `metadata` partition's
  keyblobs are files inside an ext4 filesystem, below this layer's reach.
- MBR-only tables yield `ContainerKind::Mbr` (with an
  "unusual — GPT expected" warning) rather than `Raw`, so a report never
  claims "no partition layer" for a table that produced partitions —
  but no MBR-specific attributes (boot flags, CHS) are surfaced.
- Partition role classification is heuristic — OEM-specific names fall to
  `PartitionRole::Other`.

## License

Dual-licensed under MIT or Apache-2.0, at your option. See `LICENSE-MIT`
and `LICENSE-APACHE`.
