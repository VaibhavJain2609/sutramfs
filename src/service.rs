//! The `SutramFs` gRPC service implementation.
//!
//! Request flow: resolve [`ImageRef`] → [`ByteSource`], run the parser
//! registry (`Detect`/`Mount`), then serve `Walk`/`Read`/`Info`/`Unmount`
//! against the [`HandleTable`]. Walk and Read pump results through bounded
//! `mpsc` channels from `spawn_blocking` workers — the parser layer is
//! synchronous, so long-running calls are kept off the async executor
//! (`Detect`/`Mount` only touch superblock-sized reads and run inline).

use std::collections::HashMap;
use std::io::Read as _;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::metadata::{Ascii, MetadataMap, MetadataValue};
use tonic::{Request, Response, Status};

use sutram_fs::FsParser;

use crate::convert;
use crate::handles::{new_mount, HandleTable, Mount};
use crate::pb;
use crate::pb::sutram_fs_server::SutramFs;
use crate::registry;
use crate::source;

/// Default `Read` chunk size: 64 KiB.
pub const DEFAULT_READ_CHUNK: usize = 64 * 1024;
/// Hard ceiling on `Read` chunk size: 1 MiB — a client hint can only shrink.
pub const MAX_READ_CHUNK: usize = 1024 * 1024;
/// Walk stream channel depth — bounds in-flight `FsEntryProto`s.
const WALK_CHANNEL: usize = 64;
/// Read stream channel depth — bounds in-flight chunks.
const READ_CHANNEL: usize = 16;

/// The daemon's service object: parser registry + handle table + limits.
pub struct SutramFsService {
    handles: Arc<HandleTable>,
    parsers: Vec<Box<dyn FsParser>>,
    max_inline: u64,
}

impl SutramFsService {
    /// Service with the full nine-parser registry and `ttl` handle idle
    /// lifetime.
    pub fn new(ttl: Duration) -> Self {
        SutramFsService {
            handles: Arc::new(HandleTable::new(ttl)),
            parsers: registry::registry(),
            max_inline: source::MAX_INLINE_BYTES,
        }
    }

    /// Service over an explicit registry — tests can mount a subset.
    pub fn with_parsers(parsers: Vec<Box<dyn FsParser>>, ttl: Duration) -> Self {
        SutramFsService {
            handles: Arc::new(HandleTable::new(ttl)),
            parsers,
            max_inline: source::MAX_INLINE_BYTES,
        }
    }

    /// The shared handle table (sweeper, diagnostics, tests).
    pub fn handles(&self) -> Arc<HandleTable> {
        Arc::clone(&self.handles)
    }

    /// Override the inline-image cap (tests).
    pub fn set_max_inline(&mut self, bytes: u64) {
        self.max_inline = bytes;
    }

    /// Spawn the TTL sweeper on the current tokio runtime. Runs every
    /// `min(ttl/2, 60s)`, dropping mounts that went idle.
    pub fn spawn_sweeper(&self) -> tokio::task::JoinHandle<()> {
        let handles = Arc::clone(&self.handles);
        let period = (self.handles.ttl() / 2)
            .clamp(Duration::from_millis(50), Duration::from_secs(60));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.tick().await; // first tick fires immediately — skip it
            loop {
                tick.tick().await;
                handles.sweep();
            }
        })
    }

    fn resolve(&self, image: &pb::ImageRef) -> Result<Arc<dyn sutram_io::ByteSource>, Status> {
        source::resolve(image, self.max_inline).map_err(|e| convert::status_err(&e))
    }

    fn lookup(&self, id: &str) -> Result<Arc<Mount>, Status> {
        self.handles
            .get(id)
            .ok_or_else(|| convert::unknown_handle(id))
    }
}

/// Pull `x-evidence-id` / `x-job-id` out of request metadata into the
/// snake_case keys used in response `meta` maps.
fn extract_meta(md: &MetadataMap) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for (key, name) in [("x-evidence-id", "evidence_id"), ("x-job-id", "job_id")] {
        if let Some(v) = md.get(key) {
            if let Ok(s) = v.to_str() {
                m.insert(name.to_string(), s.to_string());
            }
        }
    }
    m
}

/// Echo evidence/job ids into *response* metadata (streaming calls have no
/// per-item meta map; headers carry the passthrough instead).
fn attach_meta<T>(resp: &mut Response<T>, meta: &HashMap<String, String>) {
    for (name, key) in [("evidence_id", "x-evidence-id"), ("job_id", "x-job-id")] {
        if let Some(v) = meta.get(name) {
            if let Ok(val) = MetadataValue::<Ascii>::try_from(v.as_str()) {
                resp.metadata_mut().insert(key, val);
            }
        }
    }
}

/// Does `e` satisfy the Walk request's filters? Unknown filter tokens are
/// treated as `"all"` — lenient like the parser layer.
fn walk_filters(req: &pb::WalkRequest, e: &sutram_fs::FsEntry) -> bool {
    match req.status_filter.as_str() {
        "" | "all" => {}
        "live" => {
            if e.is_deleted() {
                return false;
            }
        }
        "deleted" => {
            if !e.is_deleted() {
                return false;
            }
        }
        _ => {}
    }
    match req.kind_filter.as_str() {
        "" | "all" => {}
        k => {
            if Some(e.kind) != convert::kind_from_str(k) {
                return false;
            }
        }
    }
    if !req.path_prefix.is_empty() && !e.path.starts_with(&req.path_prefix) {
        return false;
    }
    true
}

#[tonic::async_trait]
impl SutramFs for SutramFsService {
    async fn detect(
        &self,
        request: Request<pb::ImageRef>,
    ) -> Result<Response<pb::Detections>, Status> {
        let meta = extract_meta(request.metadata());
        let image = request.into_inner();
        let src = self.resolve(&image)?;
        // Bounded: every detect() reads only a few KiB at fixed offsets.
        let results = registry::detect_all(&self.parsers, src.as_ref());
        Ok(Response::new(pb::Detections {
            results: results
                .into_iter()
                .map(|(parser, c)| pb::Detection {
                    parser: parser.to_string(),
                    confidence: convert::confidence_str(c).to_string(),
                })
                .collect(),
            meta,
        }))
    }

    async fn mount(
        &self,
        request: Request<pb::MountRequest>,
    ) -> Result<Response<pb::MountHandle>, Status> {
        let meta = extract_meta(request.metadata());
        let req = request.into_inner();
        let image = req
            .image
            .clone()
            .ok_or_else(|| Status::invalid_argument("MountRequest.image is required"))?;
        let src = self.resolve(&image)?;
        let opts = convert::mount_options(req.options.as_ref());

        let parser: &dyn FsParser = if req.parser.is_empty() {
            registry::best_parser(&self.parsers, src.as_ref())
                .map(|(p, _)| p)
                .ok_or_else(|| {
                    Status::failed_precondition("no registered parser recognised the image")
                })?
        } else {
            registry::by_name(&self.parsers, &req.parser).ok_or_else(|| {
                let known: Vec<_> = self.parsers.iter().map(|p| p.name()).collect();
                Status::invalid_argument(format!(
                    "unknown parser '{}'; known: {}",
                    req.parser,
                    known.join(", ")
                ))
            })?
        };

        let fs = parser
            .mount_with(src, &opts)
            .map_err(|e| convert::status_err(&e))?;
        let mount = new_mount(
            fs,
            parser.name(),
            source::describe(&image),
            meta.get("evidence_id").cloned(),
            meta.get("job_id").cloned(),
        );
        let reply = pb::MountHandle {
            id: String::new(), // filled by insert()
            parser: mount.parser.to_string(),
            fs_type: mount.fs_type.clone(),
            expires_at_unix: mount.expires_at_unix(),
            meta,
        };
        let id = self.handles.insert(mount);
        Ok(Response::new(pb::MountHandle { id, ..reply }))
    }

    type WalkStream =
        Pin<Box<dyn Stream<Item = Result<pb::FsEntryProto, Status>> + Send + 'static>>;

    async fn walk(
        &self,
        request: Request<pb::WalkRequest>,
    ) -> Result<Response<Self::WalkStream>, Status> {
        let meta = extract_meta(request.metadata());
        let req = request.into_inner();
        let mount = self.lookup(&req.handle_id)?;
        let (tx, rx) = mpsc::channel(WALK_CHANNEL);
        tokio::task::spawn_blocking(move || {
            let mut emitted = 0u32;
            for item in mount.fs.walk() {
                let proto = match item {
                    Ok(e) => {
                        if !walk_filters(&req, &e) {
                            continue;
                        }
                        convert::entry_to_proto(&e)
                    }
                    Err(err) => convert::error_to_proto(&err),
                };
                emitted += 1;
                if tx.blocking_send(Ok(proto)).is_err() {
                    return; // client went away
                }
                if req.max_entries != 0 && emitted >= req.max_entries {
                    return;
                }
            }
        });
        let mut resp = Response::new(Box::pin(ReceiverStream::new(rx)) as Self::WalkStream);
        attach_meta(&mut resp, &meta);
        Ok(resp)
    }

    type ReadStream =
        Pin<Box<dyn Stream<Item = Result<pb::ReadChunk, Status>> + Send + 'static>>;

    async fn read(
        &self,
        request: Request<pb::ReadRequest>,
    ) -> Result<Response<Self::ReadStream>, Status> {
        let meta = extract_meta(request.metadata());
        let req = request.into_inner();
        let mount = self.lookup(&req.handle_id)?;
        let chunk = if req.chunk_size == 0 {
            DEFAULT_READ_CHUNK
        } else {
            (req.chunk_size as usize).clamp(1, MAX_READ_CHUNK)
        };
        let (tx, rx) = mpsc::channel(READ_CHANNEL);
        tokio::task::spawn_blocking(move || {
            // FileSystem exposes no by-path lookup: walk until the first
            // match. Documented limitation — one O(tree) scan per Read.
            let mut entry = None;
            for item in mount.fs.walk() {
                if let Ok(e) = item {
                    if e.path == req.path {
                        entry = Some(e);
                        break;
                    }
                }
            }
            let entry = match entry {
                Some(e) => e,
                None => {
                    let _ = tx.blocking_send(Err(Status::not_found(format!(
                        "no entry at path '{}'",
                        req.path
                    ))));
                    return;
                }
            };
            let mut reader = match mount.fs.read_file(&entry) {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx.blocking_send(Err(convert::status_err(&e)));
                    return;
                }
            };
            // Seek to the requested logical offset (bounded buffer steps).
            let mut skip = req.offset;
            let mut scratch = vec![0u8; 8192];
            while skip > 0 {
                let want = skip.min(scratch.len() as u64) as usize;
                match reader.read(&mut scratch[..want]) {
                    Ok(0) => break,
                    Ok(n) => skip -= n as u64,
                    Err(e) => {
                        let _ = tx
                            .blocking_send(Err(Status::internal(format!("read failed: {e}"))));
                        return;
                    }
                }
            }
            let mut sent = 0u64;
            let mut buf = vec![0u8; chunk];
            loop {
                let room = if req.len == 0 {
                    chunk as u64
                } else {
                    req.len.saturating_sub(sent).min(chunk as u64)
                };
                if room == 0 {
                    break;
                }
                match reader.read(&mut buf[..room as usize]) {
                    Ok(0) => break,
                    Ok(n) => {
                        let off = req.offset + sent;
                        sent += n as u64;
                        let last = req.len != 0 && sent >= req.len;
                        if tx
                            .blocking_send(Ok(pb::ReadChunk {
                                offset: off,
                                data: buf[..n].to_vec(),
                                eof: last,
                            }))
                            .is_err()
                        {
                            return; // client went away
                        }
                        if last {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx
                            .blocking_send(Err(Status::internal(format!("read failed: {e}"))));
                        return;
                    }
                }
            }
            // Terminate with an explicit EOF marker so clients needn't guess.
            let _ = tx.blocking_send(Ok(pb::ReadChunk {
                offset: req.offset + sent,
                data: Vec::new(),
                eof: true,
            }));
        });
        let mut resp = Response::new(Box::pin(ReceiverStream::new(rx)) as Self::ReadStream);
        attach_meta(&mut resp, &meta);
        Ok(resp)
    }

    async fn info(
        &self,
        request: Request<pb::HandleRequest>,
    ) -> Result<Response<pb::FsInfoProto>, Status> {
        let meta = extract_meta(request.metadata());
        let mount = self.lookup(&request.into_inner().id)?;
        let info = mount.fs.info();
        // Handle-stored ids win; per-request values fill gaps.
        let mut m = meta;
        for (k, v) in mount.meta() {
            m.insert(k, v);
        }
        Ok(Response::new(convert::info_to_proto(&info, m)))
    }

    async fn unmount(
        &self,
        request: Request<pb::HandleRequest>,
    ) -> Result<Response<pb::UnmountReply>, Status> {
        let meta = extract_meta(request.metadata());
        let id = request.into_inner().id;
        let gone = self.handles.remove(&id).is_some();
        Ok(Response::new(pb::UnmountReply {
            unmounted: gone,
            meta,
        }))
    }
}
