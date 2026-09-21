# sutram-compress

Pure-Rust decompression codecs for the SUTRAM-FS forensic filesystem
parser family. Every decoder treats its input as **hostile evidence**:
output is bounded by a caller-supplied `max_out` (the decompression-bomb
guard), malformed input yields `CompError`, and nothing panics — the test
suite sweeps truncation prefixes, single-byte corruptions and PRNG
garbage over every codec to prove it.

`#![forbid(unsafe_code)]`, no C dependencies, MSRV 1.85.

## Codecs

| Module  | Format | Used by | Implementation |
|---------|--------|---------|----------------|
| `lznt1` | NTFS native compression units (MS-XCA §2.5) | `sutram-ntfs` | in-crate decoder + best-effort `decompress_unit` for forensic partial reads |
| `lzo1x` | LZO1X-1 | btrfs inline extents, legacy decmpfs | `lzokay` (pure Rust, MIT) |
| `lzvn`  | Apple LZVN | HFS+/APFS decmpfs types 7/8 | in-crate safe port of Apple's `lzvn_decode_base.c` (BSD) |
| `lzfse` | Apple LZFSE | decmpfs types 11/12 | **stub** — see Limitations |
| `lz4`   | LZ4 block + LZ4 frame (with XXH32 checksums) | f2fs, squashfs | in-crate decoder incl. linked-block frames and skippable frames |
| `zlib`  | RFC 1950 zlib / RFC 1951 raw deflate | decmpfs types 3/4, ZIP, EWF | `miniz_oxide` + `std::io::Read` streaming adapters |
| `zstd`  | Zstandard frames | btrfs, squashfs | `ruzstd` (feature `zstd`, default on) |

## API shape

Every codec exposes the same one-shot entry point:

```rust
let plain = sutram_compress::lz4::decompress_block(&block, 16 * 1024 * 1024)?;
```

`decompress(src, max_out) -> Result<Vec<u8>, CompError>`:

- `CompError::Truncated` — input ended mid-stream;
- `CompError::Corrupt` — structurally invalid input;
- `CompError::OutputLimit` — decoded output would exceed `max_out`;
- `CompError::Unsupported` — codec recognised but unavailable
  (`lzfse` today, `zstd` when the feature is off).

Streaming `std::io::Read` adapters exist where the upstream codec
supports them: `zlib::ZlibDecoder`, `zlib::DeflateDecoder`,
`zstd::ZstdDecoder`. Bound streamed output yourself (`Read::take`).

LZO1X is a special case: the format carries no output size, so the
decode buffer grows geometrically toward `max_out` instead of being
allocated up front — a 1 GiB bound costs nothing on a 1 KiB stream.

## Features

- **`zstd`** *(default)* — real zstd via `ruzstd`. Note: `ruzstd` 0.9
  declares `rust-version = 1.87`. If your build must honour MSRV 1.85
  exactly, use `default-features = false`; `zstd::decompress` then
  returns `CompError::Unsupported` and call sites compile unchanged.
- **`lzfse`** — opt-in marker for the future LZFSE decoder; enabling it
  today changes nothing (the honest stub remains).

## Known limitations

- **LZFSE is not implemented.** It combines LZVN opcodes with tANS
  entropy coding (~2 000 lines of tuned tables in Apple's BSD-licensed
  reference). A pure-Rust port is feasible but deferred; `lzfse` module +
  feature are the stable seam where it will land. Parsers should surface
  `Unsupported` for decmpfs types 11/12 exactly as before.
- `lznt1::decompress` is strict; forensic callers wanting partial output
  from a damaged unit should use `lznt1::decompress_unit`, which returns
  `(bytes, fully_decoded)`.
- LZO1X retried growth means a corrupt stream can cost several decode
  passes before `OutputLimit` — bounded by `log2(max_out)` retries.
- LZ4 frame decoding validates header/block/content checksums when
  present but does not verify optional dictionary IDs (dict-dependent
  frames are rare in filesystem use).

## License

Dual-licensed under MIT or Apache-2.0, at your option. The LZVN decoder
is a clean port of Apple's BSD-licensed reference implementation.
