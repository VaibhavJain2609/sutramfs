# sutram-fsd

`sutramfsd` — a gRPC daemon that serves the whole SUTRAM-FS forensic
filesystem-parser family over the network. Point it at disk images (server-
local paths or small inline payloads), get back mounts you can walk, read,
and inspect — with the parser layer's forensic contract intact: read-only
sources, lenient-by-default walks, deleted/orphan recovery states, full
byte-level provenance, and magic-verdict masquerade checks.

## The service

`proto/sutramfs.proto` defines one service with six calls mirroring
`sutram_fs::FsParser`/`FileSystem`:

| RPC | Signature | Notes |
|-----|-----------|-------|
| `Detect` | `ImageRef → Detections` | all 9 parsers probe the image, sorted by confidence |
| `Mount` | `ImageRef + MountOptions (+ parser hint) → MountHandle` | opaque id, sliding TTL |
| `Walk` | `handle + filters → stream FsEntryProto` | live + deleted + orphans + error records |
| `Read` | `handle + path + offset + len → stream ReadChunk` | bounded chunks, ≤ 1 MiB each |
| `Info` | `handle → FsInfoProto` | volume summary |
| `Unmount` | `handle → UnmountReply` | drop a handle early |

`ImageRef` carries either `path` (opened read-only **on the server**) or
`inline` bytes (≤ 64 MiB), plus an optional `offset`/`length` partition
window (`sutram_io::OffsetView`).

### Evidence correlation

Attach gRPC metadata keys `x-evidence-id` / `x-job-id` to any request.
They are stored on the mount handle and echoed back: in `meta` maps on
unary responses, in response headers on streaming calls.

### Mount handles

Mounts live in a TTL table (default 30 min idle, `--ttl-secs`). Every use
slides the window; a background sweeper evicts expired mounts. Handles are
opaque `mh-<counter>-<nanos>` ids — not guesses about image content.

## Running

```sh
cargo run --bin sutramfsd -- --listen 127.0.0.1:50051 --ttl-secs 1800
```

Flags: `--listen` (default `127.0.0.1:50051`), `--ttl-secs` (default
`1800`), `--max-inline-mb` (default `64`).

## Usage sketch (Rust)

```rust,ignore
let mut c = SutramFsClient::connect("http://127.0.0.1:50051").await?;
let h = c.mount(MountRequest {
    image: Some(ImageRef { source: Some(image_ref::Source::Path("/evidence/disk.img".into())), ..Default::default() }),
    ..Default::default()
}).await?.into_inner();
let mut s = c.walk(WalkRequest { handle_id: h.id.clone(), status_filter: "deleted".into(), ..Default::default() }).await?.into_inner();
while let Some(e) = s.message().await? { println!("{} {}", e.status, e.path); }
```

## Known limitations

- **Trusted-local tool.** `ImageRef.path` opens any file the daemon can
  read. There is no authentication; bind to localhost or front it.
- **`Read` resolves `path` by re-walking the tree** — `FileSystem` has no
  by-path lookup, so each read is O(entries). No caching is done.
- Walk/Read work happens on `spawn_blocking` threads; a client disconnect
  stops emission but the current parser step finishes.
- Enum vocabulary is stringly-typed on the wire (`"fat"`, `"live"`,
  `"partially_overwritten"`) — forward-compatible, but clients must treat
  unknown values gracefully.
- gRPC stack: tonic/prost/tokio (pure Rust). Chosen over the JSON-lines
  fallback because the deps resolved cleanly at authoring time.

## License

Dual-licensed under MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
