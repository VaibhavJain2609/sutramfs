//! Handler-level tests over a real TCP listener, driven by a stub parser so
//! the walk/read error paths are reachable deterministically — the real
//! FAT corpus alone never produces a lenient `Err` item or a `read_file`
//! failure.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::metadata::MetadataValue;
use tonic::transport::Server;
use tonic::{Code, Request};

use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsError, FsInfo, FsParser, FileSystem,
    MountOptions, RecoveryState, Result as FsResult,
};
use sutram_fsd::pb;
use sutram_fsd::pb::image_ref::Source as ImageSource;
use sutram_fsd::pb::sutram_fs_client::SutramFsClient;
use sutram_fsd::pb::sutram_fs_server::SutramFsServer;
use sutram_fsd::{SutramFsService, MAX_READ_CHUNK};

// ---------------------------------------------------------------------------
// Stub parser/filesystem
// ---------------------------------------------------------------------------

/// `/A.BIN` — a 1.5 MiB file, large enough to prove the 1 MiB chunk cap.
const FILE_BYTES: usize = 1_500_000;

struct StubParser;
struct NeverParser;

fn entry(path: &str, kind: EntryKind, status: FsEntryStatus, size: u64) -> FsEntry {
    FsEntry {
        path: path.into(),
        name: path.rsplit('/').next().unwrap().into(),
        entry_id: 0x100,
        kind,
        size,
        disk_offset: 0x900,
        allocated_ranges: vec![(0x1000, size)],
        timestamps: Default::default(),
        status,
        meta: HashMap::new(),
        magic: None,
    }
}

struct StubFs;

impl FileSystem for StubFs {
    fn info(&self) -> FsInfo {
        FsInfo {
            fs_type: "STUB".into(),
            label: Some("STUBVOL".into()),
            uuid: Some("stub-uuid".into()),
            block_size: 512,
            total_blocks: 2048,
            free_blocks: Some(1000),
            total_nodes: Some(16),
            meta: HashMap::from([("note".into(), "stub-info".into())]),
        }
    }

    fn source(&self) -> Arc<dyn sutram_io::ByteSource> {
        Arc::new(vec![0u8; 4096])
    }

    fn walk(&self) -> Box<dyn Iterator<Item = FsResult<FsEntry>> + Send + '_> {
        let items: Vec<FsResult<FsEntry>> = vec![
            Ok(entry("/A.BIN", EntryKind::File, FsEntryStatus::Live, FILE_BYTES as u64)),
            Ok(entry("/BROKEN", EntryKind::File, FsEntryStatus::Live, 10)),
            Ok(entry("/DIR", EntryKind::Directory, FsEntryStatus::Live, 0)),
            Ok(entry("/LINK", EntryKind::Symlink, FsEntryStatus::Live, 0)),
            Ok(entry("/DEV", EntryKind::Other, FsEntryStatus::Live, 0)),
            Ok(entry(
                "/OLD.BIN",
                EntryKind::File,
                FsEntryStatus::Deleted {
                    recovery: RecoveryState::PartiallyOverwritten {
                        recovered_bytes: 5,
                        total_bytes: 10,
                    },
                },
                10,
            )),
            Err(FsError::corrupt(0x900, "corrupt dirent")),
        ];
        Box::new(items.into_iter())
    }

    fn read_file(&self, e: &FsEntry) -> FsResult<Box<dyn std::io::Read + Send>> {
        match e.path.as_str() {
            "/A.BIN" => Ok(Box::new(std::io::Cursor::new(vec![0xAAu8; FILE_BYTES]))),
            "/BROKEN" => Err(FsError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                "simulated source failure",
            ))),
            other => Err(FsError::InvalidInput {
                msg: format!("not a readable file: {other}"),
            }),
        }
    }
}

impl FsParser for StubParser {
    fn name(&self) -> &'static str {
        "stub"
    }
    fn detect(&self, _src: &dyn sutram_io::ByteSource) -> DetectConfidence {
        DetectConfidence::Certain
    }
    fn mount_with(
        &self,
        _src: Arc<dyn sutram_io::ByteSource>,
        _opts: &MountOptions,
    ) -> FsResult<Box<dyn FileSystem>> {
        Ok(Box::new(StubFs))
    }
}

impl FsParser for NeverParser {
    fn name(&self) -> &'static str {
        "never"
    }
    fn detect(&self, _src: &dyn sutram_io::ByteSource) -> DetectConfidence {
        DetectConfidence::None
    }
    fn mount_with(
        &self,
        _src: Arc<dyn sutram_io::ByteSource>,
        _opts: &MountOptions,
    ) -> FsResult<Box<dyn FileSystem>> {
        Err(FsError::unsupported("never mounts"))
    }
}

// ---------------------------------------------------------------------------
// Server/client plumbing
// ---------------------------------------------------------------------------

fn stub_registry() -> Vec<Box<dyn FsParser>> {
    vec![Box::new(StubParser), Box::new(NeverParser)]
}

async fn spawn_stub(ttl: Duration) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = SutramFsService::with_parsers(stub_registry(), ttl);
    let h = tokio::spawn(async move {
        Server::builder()
            .add_service(SutramFsServer::new(svc))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    (addr, h)
}

fn image_ref() -> pb::ImageRef {
    pb::ImageRef {
        source: Some(ImageSource::Inline(vec![0xAB; 512])),
        offset: 0,
        length: 0,
    }
}

fn with_meta<T>(inner: T, ev: &str, job: &str) -> Request<T> {
    let mut r = Request::new(inner);
    r.metadata_mut()
        .insert("x-evidence-id", MetadataValue::try_from(ev).unwrap());
    r.metadata_mut()
        .insert("x-job-id", MetadataValue::try_from(job).unwrap());
    r
}

async fn mount_stub(client: &mut SutramFsClient<tonic::transport::Channel>) -> pb::MountHandle {
    client
        .mount(with_meta(
            pb::MountRequest {
                image: Some(image_ref()),
                options: None,
                parser: "stub".into(),
            },
            "EV-9",
            "JOB-9",
        ))
        .await
        .expect("mount")
        .into_inner()
}

async fn collect_walk(
    client: &mut SutramFsClient<tonic::transport::Channel>,
    req: pb::WalkRequest,
) -> Vec<pb::FsEntryProto> {
    let mut s = client.walk(req).await.expect("walk").into_inner();
    let mut out = Vec::new();
    while let Some(e) = s.message().await.expect("walk item") {
        out.push(e);
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detect_sorts_stub_first_and_echoes_meta() {
    let (addr, _srv) = spawn_stub(Duration::from_secs(60)).await;
    let mut client = SutramFsClient::connect(format!("http://{addr}")).await.unwrap();

    let dets = client
        .detect(with_meta(image_ref(), "EV-D", "JOB-D"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(dets.results.len(), 2);
    assert_eq!(dets.results[0].parser, "stub");
    assert_eq!(dets.results[0].confidence, "certain");
    assert_eq!(dets.results[1].parser, "never");
    assert_eq!(dets.results[1].confidence, "none");
    assert_eq!(dets.meta.get("evidence_id").unwrap(), "EV-D");
    assert_eq!(dets.meta.get("job_id").unwrap(), "JOB-D");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn walk_filters_and_error_records() {
    let (addr, _srv) = spawn_stub(Duration::from_secs(60)).await;
    let mut client = SutramFsClient::connect(format!("http://{addr}")).await.unwrap();
    let h = mount_stub(&mut client).await;

    let base = pb::WalkRequest {
        handle_id: h.id.clone(),
        ..Default::default()
    };

    // Unfiltered: six entries + one lenient error record.
    let all = collect_walk(&mut client, pb::WalkRequest { ..base.clone() }).await;
    assert_eq!(all.iter().filter(|e| e.error.is_empty()).count(), 6);
    let err = all.iter().find(|e| !e.error.is_empty()).unwrap();
    assert!(err.error.contains("corrupt dirent"));
    assert!(err.path.is_empty());

    // status filters.
    for (filter, want_statuses) in [
        ("live", vec!["live"; 5]),
        ("deleted", vec!["deleted"]),
        ("bogus-token", vec!["live"; 5]), // unknown → lenient "all"
    ] {
        let got = collect_walk(
            &mut client,
            pb::WalkRequest {
                status_filter: filter.into(),
                ..base.clone()
            },
        )
        .await;
        let statuses: Vec<&str> = got
            .iter()
            .filter(|e| e.error.is_empty())
            .map(|e| e.status.as_str())
            .collect();
        let mut expect = want_statuses.clone();
        if filter == "bogus-token" {
            expect.push("deleted"); // passes everything
        }
        assert_eq!(statuses, expect, "status_filter {filter}");
    }

    // kind filters — one entry of each kind exists.
    for (filter, want_path) in [
        ("file", vec!["/A.BIN", "/BROKEN", "/OLD.BIN"]),
        ("dir", vec!["/DIR"]),
        ("directory", vec!["/DIR"]),
        ("symlink", vec!["/LINK"]),
        ("other", vec!["/DEV"]),
    ] {
        let got = collect_walk(
            &mut client,
            pb::WalkRequest {
                kind_filter: filter.into(),
                ..base.clone()
            },
        )
        .await;
        let mut paths: Vec<&str> = got
            .iter()
            .filter(|e| e.error.is_empty())
            .map(|e| e.path.as_str())
            .collect();
        paths.sort_unstable();
        assert_eq!(paths, want_path, "kind_filter {filter}");
    }

    // Unknown kind token is lenient ("all"), like the status filter.
    let got = collect_walk(
        &mut client,
        pb::WalkRequest {
            kind_filter: "bogus".into(),
            ..base.clone()
        },
    )
    .await;
    assert_eq!(got.iter().filter(|e| e.error.is_empty()).count(), 6);

    // path_prefix.
    let got = collect_walk(
        &mut client,
        pb::WalkRequest {
            path_prefix: "/A".into(),
            ..base.clone()
        },
    )
    .await;
    let paths: Vec<&str> = got.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths, ["/A.BIN"]);

    // max_entries bounds the stream (error records count too).
    let got = collect_walk(
        &mut client,
        pb::WalkRequest {
            max_entries: 2,
            ..base.clone()
        },
    )
    .await;
    assert_eq!(got.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn walk_response_headers_carry_evidence_ids() {
    let (addr, _srv) = spawn_stub(Duration::from_secs(60)).await;
    let mut client = SutramFsClient::connect(format!("http://{addr}")).await.unwrap();
    let h = mount_stub(&mut client).await;

    let resp = client
        .walk(with_meta(
            pb::WalkRequest {
                handle_id: h.id.clone(),
                ..Default::default()
            },
            "EV-WALK",
            "JOB-WALK",
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.metadata().get("x-evidence-id").unwrap(),
        "EV-WALK"
    );
    assert_eq!(resp.metadata().get("x-job-id").unwrap(), "JOB-WALK");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn read_chunk_cap_and_bounds() {
    let (addr, _srv) = spawn_stub(Duration::from_secs(60)).await;
    let mut client = SutramFsClient::connect(format!("http://{addr}")).await.unwrap();
    let h = mount_stub(&mut client).await;

    // chunk_size hint above the hard ceiling → clamped to 1 MiB.
    let mut s = client
        .read(with_meta(
            pb::ReadRequest {
                handle_id: h.id.clone(),
                path: "/A.BIN".into(),
                offset: 0,
                len: 0,
                chunk_size: u32::MAX,
            },
            "EV-R",
            "JOB-R",
        ))
        .await
        .unwrap()
        .into_inner();
    let mut data = Vec::new();
    let mut chunks = 0usize;
    let mut saw_eof = false;
    while let Some(c) = s.message().await.unwrap() {
        chunks += 1;
        assert!(c.data.len() <= MAX_READ_CHUNK, "chunk bound violated");
        if !c.data.is_empty() {
            assert_eq!(c.offset as usize, data.len(), "offsets are sequential");
            data.extend_from_slice(&c.data);
        }
        saw_eof |= c.eof;
    }
    assert!(saw_eof);
    assert!(chunks >= 2, "1.5 MiB in ≤1 MiB chunks → ≥2 messages");
    assert_eq!(data.len(), FILE_BYTES);
    assert!(data.iter().all(|&b| b == 0xAA));

    // Offset beyond end → single empty eof chunk, no panic.
    let mut s = client
        .read(pb::ReadRequest {
            handle_id: h.id.clone(),
            path: "/A.BIN".into(),
            offset: (FILE_BYTES + 4096) as u64,
            len: 0,
            chunk_size: 0,
        })
        .await
        .unwrap()
        .into_inner();
    let c = s.message().await.unwrap().unwrap();
    assert!(c.eof && c.data.is_empty());
    assert_eq!(c.offset, (FILE_BYTES + 4096) as u64);

    // len limits total bytes; last data chunk carries eof.
    let mut s = client
        .read(pb::ReadRequest {
            handle_id: h.id.clone(),
            path: "/A.BIN".into(),
            offset: 10,
            len: 5,
            chunk_size: 0,
        })
        .await
        .unwrap()
        .into_inner();
    let c = s.message().await.unwrap().unwrap();
    assert_eq!(c.data.len(), 5);
    assert!(c.eof);
    assert_eq!(c.offset, 10);
    assert!(s.message().await.unwrap().is_none(), "stream closed");

    // read_file failure → error arrives as a stream item.
    let mut s = client
        .read(pb::ReadRequest {
            handle_id: h.id.clone(),
            path: "/BROKEN".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let err = s.message().await.expect_err("read_file error");
    assert_eq!(err.code(), Code::Internal);
    assert!(err.message().contains("simulated source failure"));

    // Unknown handle → error at call time, not in-stream.
    let err = client
        .read(pb::ReadRequest {
            handle_id: "mh-dead".into(),
            path: "/A.BIN".into(),
            ..Default::default()
        })
        .await
        .expect_err("dead handle");
    assert_eq!(err.code(), Code::NotFound);

    // Directory read → InvalidInput via read_file.
    let mut s = client
        .read(pb::ReadRequest {
            handle_id: h.id.clone(),
            path: "/DIR".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let err = s.message().await.expect_err("directory read");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn info_merges_stored_and_request_meta() {
    let (addr, _srv) = spawn_stub(Duration::from_secs(60)).await;
    let mut client = SutramFsClient::connect(format!("http://{addr}")).await.unwrap();
    let h = mount_stub(&mut client).await;

    // Info request carries *different* ids; the handle-stored ones win.
    let info = client
        .info(with_meta(pb::HandleRequest { id: h.id.clone() }, "EV-OTHER", "JOB-OTHER"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(info.fs_type, "STUB");
    assert_eq!(info.label, "STUBVOL");
    assert_eq!(info.uuid, "stub-uuid");
    assert_eq!(info.block_size, 512);
    assert!(info.has_free_blocks && info.free_blocks == 1000);
    assert!(info.has_total_nodes && info.total_nodes == 16);
    assert_eq!(info.fs_meta.get("note").unwrap(), "stub-info");
    assert_eq!(info.meta.get("evidence_id").unwrap(), "EV-9");
    assert_eq!(info.meta.get("job_id").unwrap(), "JOB-9");

    // Info on an unknown handle → NotFound.
    let err = client
        .info(pb::HandleRequest {
            id: "mh-nope".into(),
        })
        .await
        .expect_err("unknown handle");
    assert_eq!(err.code(), Code::NotFound);

    // Unmount echoes the *request's* correlation ids.
    let r = client
        .unmount(with_meta(pb::HandleRequest { id: h.id.clone() }, "EV-U", "JOB-U"))
        .await
        .unwrap()
        .into_inner();
    assert!(r.unmounted);
    assert_eq!(r.meta.get("evidence_id").unwrap(), "EV-U");
    assert_eq!(r.meta.get("job_id").unwrap(), "JOB-U");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sweeper_evicts_expired_mounts() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = SutramFsService::with_parsers(stub_registry(), Duration::from_millis(60));
    let handles = svc.handles();
    let sweeper = svc.spawn_sweeper();
    tokio::spawn(async move {
        Server::builder()
            .add_service(SutramFsServer::new(svc))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let mut client = SutramFsClient::connect(format!("http://{addr}")).await.unwrap();
    let _h = mount_stub(&mut client).await;
    assert_eq!(handles.len(), 1, "mount registered");
    // Sweeper ticks at ~30ms (ttl/2 clamped to ≥50ms); wait well past it.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(handles.len(), 0, "sweeper must evict the idle mount");
    sweeper.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mount_requires_image_and_respects_inline_cap() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut svc = SutramFsService::with_parsers(stub_registry(), Duration::from_secs(60));
    svc.set_max_inline(4); // tiny cap: our 512-byte inline image is refused
    tokio::spawn(async move {
        Server::builder()
            .add_service(SutramFsServer::new(svc))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let mut client = SutramFsClient::connect(format!("http://{addr}")).await.unwrap();

    // Missing image field.
    let err = client
        .mount(pb::MountRequest {
            image: None,
            options: None,
            parser: "stub".into(),
        })
        .await
        .expect_err("missing image");
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(err.message().contains("image is required"));

    // Inline image beyond the configured cap.
    let err = client
        .mount(pb::MountRequest {
            image: Some(image_ref()),
            options: None,
            parser: "stub".into(),
        })
        .await
        .expect_err("oversize inline");
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(err.message().contains("too large"));

    // MountOptions proto is accepted and forwarded.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = SutramFsService::with_parsers(stub_registry(), Duration::from_secs(60));
    tokio::spawn(async move {
        Server::builder()
            .add_service(SutramFsServer::new(svc))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let mut client = SutramFsClient::connect(format!("http://{addr}")).await.unwrap();
    let h = client
        .mount(pb::MountRequest {
            image: Some(image_ref()),
            options: Some(pb::MountOptionsProto {
                strict: true,
                check_magic: false,
                include_orphans: false,
            }),
            parser: "stub".into(),
        })
        .await
        .expect("mount with options")
        .into_inner();
    assert_eq!(h.parser, "stub");
    assert_eq!(h.fs_type, "STUB");
    assert!(h.expires_at_unix > 0);
    assert!(h.meta.is_empty(), "no correlation ids were attached");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mount_path_source_is_read_only() {
    // End-to-end read-only guarantee: a chmod-400 image file on disk is
    // mounted via ImageRef.path and fully walked/read; its bytes and
    // permissions are untouched afterwards.
    use sutram_fsd::registry;
    let img_bytes = common::fat12_image();
    let path = std::env::temp_dir().join(format!(
        "sutram-fsd-ro-{}-{:x}.img",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, &img_bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    }

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = SutramFsService::with_parsers(registry(), Duration::from_secs(60));
    tokio::spawn(async move {
        Server::builder()
            .add_service(SutramFsServer::new(svc))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let mut client = SutramFsClient::connect(format!("http://{addr}")).await.unwrap();

    let h = client
        .mount(pb::MountRequest {
            image: Some(pb::ImageRef {
                source: Some(ImageSource::Path(path.to_string_lossy().into_owned())),
                offset: 0,
                length: 0,
            }),
            options: None,
            parser: "fat".into(),
        })
        .await
        .expect("path mount")
        .into_inner();
    assert_eq!(h.parser, "fat");

    let entries = collect_walk(
        &mut client,
        pb::WalkRequest {
            handle_id: h.id.clone(),
            ..Default::default()
        },
    )
    .await;
    assert!(entries.iter().any(|e| e.path == "/HELLO.TXT"));

    let mut s = client
        .read(pb::ReadRequest {
            handle_id: h.id.clone(),
            path: "/HELLO.TXT".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut data = Vec::new();
    while let Some(c) = s.message().await.unwrap() {
        data.extend_from_slice(&c.data);
    }
    assert_eq!(data, b"hello forensic world");

    client
        .unmount(pb::HandleRequest { id: h.id.clone() })
        .await
        .unwrap();

    // The evidence file is byte-identical afterwards.
    assert_eq!(std::fs::read(&path).unwrap(), img_bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // restore write permission so cleanup can't fail
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    std::fs::remove_file(&path).unwrap();
}
