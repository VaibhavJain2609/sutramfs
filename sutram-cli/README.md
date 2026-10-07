# sutram-cli (`sutramfs`)

Unified command-line front-end for the **SUTRAM-FS** forensic parser family.
Auto-detects the filesystem, streams forensic entries (live, deleted, orphaned),
carves free space, and extracts recoverable file data — with per-record
disk-offset provenance and extension↔magic mismatch flags.

## Usage

```
sutramfs detect  <image>                      probe all parsers, show confidences
sutramfs parts   <image>                      list MBR/GPT partitions
sutramfs android <image>                      Android layout (sparse/super.img/vbmeta/FBE)
sutramfs info    <image> [-p N] [-t FS]       volume summary
sutramfs ls      <image> [-p N] [-t FS] [-d] [-o tree|json|csv|bodyfile]
sutramfs cat     <image> <path>               extract recoverable file data
sutramfs carve   <image> [--offset O --len L | --unallocated] [--align A]
```

Parsers: `fat`, `exfat`, `ext4`, `btrfs`, `f2fs`, `xfs`, `hfs`, `ntfs`, `apfs`.
`-t` forces a parser when detection is ambiguous.

## Output formats

- `tree` — human table with `[DELETED]` and `[MAGIC-MISMATCH]` markers
- `json` — one JSON object per entry (full timestamps, meta, magic verdict, ranges)
- `csv` — spreadsheet-friendly summary
- `bodyfile` — mactime bodyfile for plaso/Timesketch-style pipelines

## License

MIT OR Apache-2.0
