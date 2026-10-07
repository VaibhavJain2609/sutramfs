# sutram-capi

C FFI (`cdylib`) and Python bindings for the **SUTRAM-FS** forensic
filesystem parser family. One shared library exposes every parser —
NTFS, exFAT, FAT12/16/32, ext4, btrfs, F2FS, XFS, HFS+ and APFS —
behind a small C ABI: detect, mount, enumerate entries as JSON/JSONL,
and read file content including recoverable bytes of deleted entries.

## Safety model

- All logic lives in safe Rust (`src/core.rs`, `src/json.rs`). The only
  `unsafe` code is the FFI boundary itself (`src/ffi.rs`), which:
  - validates every pointer argument (NULL → error, never a deref),
  - wraps every call in `catch_unwind` so no panic crosses the boundary,
  - documents ownership per function — see `include/sutram.h`.
- `sutram_last_error()` returns a thread-local message for the last
  failing call.
- Walk results stream through a callback (`sutram_list_entries`) or a
  caller-bounded buffer (`sutram_list_jsonl`), so huge images do not
  force unbounded allocation.
- `sutram_read_file` caps output at `max_bytes` — a hostile
  `uncompressed_size`/extent can't produce a memory bomb.

## Build

```sh
cargo build --release
# → target/release/libsutram_capi.{so,dylib,dll}  +  libsutram_capi.rlib
```

`crate-type = ["cdylib", "rlib"]`: the `.rlib` lets the Rust tests link
the same surface; the `cdylib` is what C/Python load.

## C usage

```sh
cc -Iinclude examples/list.c -Ltarget/release -lsutram_capi -o list
./list /evidence/disk.img /path/in/fs.txt
```

```c
SutramFs *fs = sutram_open_image("/evidence/disk.img");
if (!fs) { fprintf(stderr, "%s\n", sutram_last_error()); return 1; }

printf("mounted as %s\n", sutram_fs_type(fs));   /* borrowed */

sutram_list_entries(fs, my_cb, my_user);          /* one JSON line per entry */

uint64_t len = 0;
uint8_t *data = sutram_read_file(fs, "/hello.txt", 64u << 20, &len);
/* ... */
sutram_free_bytes(data, len);
sutram_close(fs);
```

See `include/sutram.h` for the full contract (ownership, error strings,
the entry JSON schema) and `examples/list.c` for a complete program.

## Python (feature `python`, off by default)

PyO3 bindings build a `sutramfs` extension module:

```sh
cargo build --release --features python
cp target/release/libsutram_capi.dylib sutramfs.so   # macOS; .so on Linux
```

```python
import sutramfs
sutramfs.detect("disk.img")                # {"filesystem": "fat", ...}
img = sutramfs.open_image("disk.img")      # or fs_type="ntfs", partition=0
img.info()                                 # dict
img.entries()                              # [dict, ...] live+deleted+orphans
img.entries_jsonl()                        # same stream as the C API
img.read("/hello.txt")                     # bytes
```

Requires a Python toolchain at build time; set `PYO3_PYTHON` if the
interpreter is not auto-detected (e.g.
`PYO3_PYTHON=/opt/homebrew/opt/python@3.12/bin/python3.12`). Built here
against PyO3 0.22 / Python 3.12.

## Tests

```sh
cargo test          # FFI round-trip on an in-repo generated FAT32 image
```

`tests/common/mod.rs` builds a synthetic FAT32 volume byte-by-byte
(boot sector, FATs, directory tables, live + deleted files); `tests/`
exercises the exported functions exactly as a C consumer would —
callbacks, JSONL bounding, file reads, ownership frees and NULL-safety
on every entry point.

## Limitations

- `sutram_list_jsonl` buffers its output; use the callback form for
  unbounded streams on very large images.
- Entry lookup in `sutram_read_file` walks the filesystem — O(entries)
  per call; iterate `sutram_list_entries` and read during a single pass
  for bulk extraction.
- No header generation tool is wired in; `include/sutram.h` is
  maintained by hand alongside `src/ffi.rs`.
- Python feature requires building per-interpreter (standard PyO3
  ABI3-free build).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
