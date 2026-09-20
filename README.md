# sutram-magic

File-signature detection and extension↔content **masquerade checking** for
the **SUTRAM-FS** family of Rust filesystem-forensics crates.

Part of the SUTRAM-FS project — see `CONVENTIONS.md` at the repository root
for the contract every crate follows.

## What this crate is

A pure-Rust, zero-dependency, `no_std`-shaped signature database and verdict
engine:

- `detect(&[u8]) -> Option<MagicType>` — identify a buffer from its leading
  bytes; trailer-aware (DMG `koly`, VHD `conectix`, appended-ZIP `EOCD`).
- `detect_all(&[u8]) -> Vec<MagicType>` — all matching types; >1 flags a
  possible **polyglot** file (GIFAR, SFX stub, …).
- `check_entry(name, header) -> MagicVerdict` — compares the type *declared*
  by the extension with the type *detected* in content:
  - `resume.docx` containing `MZ` → `mismatch: true`, `Severity::High`
    ("extension implies OOXML/ZIP container; magic MZ → Windows executable —
    possible masquerade/evasion").
  - `report.docx` containing `PK` → **not** a mismatch: the expected-
    container table knows docx/xlsx/pptx/jar/apk/odt/epub *are* ZIP, and
    doc/xls/ppt/msg *are* OLE2/CFB.
  - Unknown extension or no signature → `Severity::Info`, never silent.
- `has_trailer(kind, buf)` — footer verification (PNG `IEND`, PDF `%%EOF`).

The DB (`SIGNATURES`) covers ≥80 signatures: PE/ELF/Mach-O (all magics +
fat/class disambiguation), WASM, dex, ZIP & OOXML, PNG/JPEG/GIF/BMP/TIFF/
WebP/HEIC/AVIF/PSD, PDF/RTF/PostScript/OneNote/PST/OLE2, MP3/WAV/AVI/MP4/
MOV/3GP/MKV/FLV/Ogg/FLAC, gzip/bzip2/xz/7z/RAR4+5/tar/zstd/lz4/cab/ar,
SQLite3/WAL/journal, EVTX/regf/prefetch (SCCA+MAM)/LNK/bplist/SDB,
pcap/pcapng, EWF/AFF/DMG/VHD/VMDK/VDI/qcow/ISO9660/UDF, LUKS1+2/BitLocker/
BitLocker-To-Go, FAT/exFAT/NTFS/ext/btrfs/F2FS/APFS/HFS+/XFS/MFT records,
PEM/OpenSSL-salted, and ext-declared types for WhatsApp crypt12/14/15 and
PKCS#12 (no reliable magic — declared by extension only).

## Forensic guarantees

- No `unsafe`, no network, no allocation during `detect` (const table).
- Detection never fails — it returns `Option`; verdicts carry
  human-readable `reasons` suitable for reports.
- Polyglot and missing-trailer anomalies are surfaced as reasons, not hidden.

## Usage

```rust
use sutram_magic::{check_entry, detect, MagicType, Severity};

assert_eq!(detect(b"\x89PNG\x0D\x0A\x1A\x0A"), Some(MagicType::Png));

let v = check_entry("evil.docx", b"MZ\x90\x00");
assert!(v.mismatch);
assert_eq!(v.severity, Severity::High);
```

## Known limitations

- Signature hits are prefix/trailer based; ambiguous short magics
  (`BM`, `#!`) can produce weak identifications — `detect_all` exposes the
  ambiguity.
- Format *validation* (e.g. "is this zip well-formed") is out of scope;
  parsers layer on top.

## License

Dual-licensed under MIT or Apache-2.0, at your option. See `LICENSE-MIT`
and `LICENSE-APACHE`.
