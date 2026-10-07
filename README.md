# SUTRAM-FS

A family of **open-source Rust filesystem-forensics parsers** — standalone crates
usable by anyone (dual MIT/Apache-2.0), and the evidence-parsing layer of the
SUTRAM digital-forensics framework.

Every parser is **read-only**, **streaming** (bounded memory), **panic-free on
hostile input** (lenient-by-default, strict mode opt-in), and forensic-first:
deleted/recoverable/partially-overwritten entry detection, per-record
disk-offset provenance, raw timestamp encodings, and extension↔magic
masquerade verdicts on every file.

## Crates

| Crate | Purpose | Status |
|---|---|---|
| `sutram-io` | ByteSource abstraction, MBR/GPT, offset/concat/sparse views, Android sparse, EWF (planned) | ✅ |
| `sutram-fs` | Core traits (`FsParser`/`FileSystem`), `FsEntry`, `RecoveryState`, timestamps | ✅ |
| `sutram-magic` | File-signature DB + extension↔content mismatch verdicts with reasons | ✅ |
| `sutram-fat` | FAT12/16/32 — deleted entries, orphan chains, slack, LFN | ✅ verified |
| `sutram-exfat` | exFAT — deleted entry sets, bitmap-driven recovery | ✅ verified |
| `sutram-ext4` | ext2/3/4 — extents+indirect, deleted-inode carving, jbd2 awareness | ✅ verified |
| `sutram-btrfs` | BTRFS — subvolumes/snapshots, COW tree-history recovery, orphan items | ✅ verified |
| `sutram-f2fs` | F2FS (Android userdata) — stale-segment/NAT recovery, orphan inodes, fscrypt flags | ✅ verified |
| `sutram-xfs` | XFS v5 — big-endian, inobt/finobt, deleted inodes, BMBT | ✅ verified |
| `sutram-hfs` | HFS+ — catalog B-tree, extents overflow, decmpfs, deleted residue | ✅ verified |
| `sutram-ntfs` | NTFS — $MFT+fixup, SI-vs-FN dual timestamps, ADS, INDX slack, deleted records | ✅ verified |
| `sutram-apfs` | APFS — Fletcher-64, checkpoint diffing, snapshots, deleted via prior checkpoints | ✅ verified |
| `sutram-part` | Android layer — sparse `simg`, `super.img` liblp, vbmeta, crypt_ftr | ✅ verified |
| `sutram-reputation` | Magic→suspicion→hash-first VirusTotal (opt-in upload) + sandbox trait | ✅ verified |
| `sutram-compress` | Shared codecs: LZNT1, LZ4, LZVN, LZO1X, zlib/deflate, zstd (feature) | ✅ |
| `sutram-capi` | C FFI (`sutram.h`, cdylib) + PyO3 Python bindings | ✅ |
| `sutram-cli` | `sutramfs` binary — detect/parts/android/info/ls/cat/carve | ✅ |

## Usage

```bash
# Per-crate library usage
cd sutram-fat && cargo build

# Unified CLI
cd sutram-cli && cargo build --release
./target/release/sutramfs detect image.dd
./target/release/sutramfs ls image.dd -p 2 -d -o json
./target/release/sutramfs cat image.dd /path/to/file --recover
./target/release/sutramfs carve image.dd --unallocated
```

## Conventions

See `CONVENTIONS.md` — crate layout, error taxonomy, forensic requirements
(deleted/recovery semantics, provenance, lenient parsing), test-corpus pattern
(synthetic image builders in `tests/common`), CI matrix (x86_64 + aarch64 ×
Linux/macOS/Windows).

## Roadmap

- ~~Pure-Rust EWF/E01 reader~~ ✅ (single-segment; E02+/EWF2 planned)
- ~~Journal forensics~~ ✅ jbd2, $UsnJrnl/$LogFile, HFS+ journal buffer — parsed as evidence, never replayed
- ~~`sutram-compress`~~ ✅ (LZFSE stub; zstd behind feature)
- ~~`sutram-capi`~~ ✅ C FFI + PyO3
- cargo-fuzz targets: scaffolded in all 10 parser repos; corpus runs pending
- Differential testing vs TSK/plaso on real images
- crates.io publication
- LZFSE decoder, EWF multi-segment, AFF4

## Planned: acquisition & device intelligence

Application-level features for `sutramfs` when the input is a live block device
(not an image file):

- **Device/transport diagnostics** — the application itself should enumerate and
  report what it is reading: vendor/product/serial, protocol (USB, Thunderbolt,
  NVMe, SATA), negotiated link speed vs. device capability (480 Mbps vs.
  5/10/20/40 Gbps), bus topology (which hub/port the device sits behind),
  capacity, sector size, and current mount state. This surfaces real-world
  conditions an examiner cares about — e.g. "drive is a USB-3 device negotiated
  down to USB-2 through a dongle; reads will cap at ~40 MB/s" — without leaving
  the tool.
- **Write-blocker-mode prompt** — when the target is a block device, `sutramfs`
  should ask up front whether to attach it write-protected, the way a hardware
  write blocker would: check whether the volume is mounted, offer to unmount it,
  warn that the OS may auto-mount or write metadata, and open the device
  read-only. The user confirms the protection posture before a single byte is
  read — no silent reliance on "the tool happens to be read-only."
