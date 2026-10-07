//! In-process gRPC round-trip tests: bind a real `sutramfsd` service on an
//! ephemeral localhost port, drive it with the generated tonic client, and
//! walk a synthetic FAT12 image end to end.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tonic::{Code, Request};

use sutram_fsd::pb::image_ref::Source as ImageSource;
use sutram_fsd::pb::sutram_fs_client::SutramFsClient;
use sutram_fsd::pb::sutram_fs_server::SutramFsServer;
use sutram_fsd::pb;
use sutram_fsd::SutramFsService;

async fn spawn_server(ttl: Duration) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = SutramFsService::new(ttl);
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
        source: Some(ImageSource::Inline(common::fat12_image())),
        offset: 0,
        length: 0,
    }
}

/// Attach evidence-correlation metadata like a real pipeline would.
fn with_meta<T>(inner: T) -> Request<T> {
    let mut r = Request::new(inner);
    r.metadata_mut()
        .insert("x-evidence-id", "EV-001".parse().unwrap());
    r.metadata_mut()
        .insert("x-job-id", "JOB-77".parse().unwrap());
    r
}

async fn mount(client: &mut SutramFsClient<tonic::transport::Channel>) -> pb::MountHandle {
    client
        .mount(with_meta(pb::MountRequest {
            image: Some(image_ref()),
            options: None,
            parser: String::new(),
        }))
        .await
        .expect("mount")
        .into_inner()
}

async fn walk_all(
    client: &mut SutramFsClient<tonic::transport::Channel>,
    id: &str,
) -> Vec<pb::FsEntryProto> {
    let mut s = client
        .walk(pb::WalkRequest {
            handle_id: id.into(),
            ..Default::default()
        })
        .await
        .expect("walk")
        .into_inner();
    let mut out = Vec::new();
    while let Some(e) = s.message().await.expect("walk item") {
        out.push(e);
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detect_reports_fat_first() {
    let (addr, _srv) = spawn_server(Duration::from_secs(60)).await;
    let mut client = SutramFsClient::connect(format!("http://{addr}")).await.unwrap();

    let dets = client
        .detect(with_meta(image_ref()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(dets.results.len(), 9, "all parsers must report");
    assert_eq!(dets.results[0].parser, "fat");
    assert_eq!(dets.results[0].confidence, "certain");
    // Evidence metadata echoed back.
    assert_eq!(dets.meta.get("evidence_id").unwrap(), "EV-001");
    assert_eq!(dets.meta.get("job_id").unwrap(), "JOB-77");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mount_walk_read_info_unmount_roundtrip() {
    let (addr, _srv) = spawn_server(Duration::from_secs(60)).await;
    let mut client = SutramFsClient::connect(format!("http://{addr}")).await.unwrap();

    // ---- Mount ---------------------------------------------------------
    let h = mount(&mut client).await;
    assert!(h.id.starts_with("mh-"), "handle id: {}", h.id);
    assert_eq!(h.parser, "fat");
    assert!(h.fs_type.starts_with("FAT"), "fs_type: {}", h.fs_type);
    assert!(h.expires_at_unix > 0);
    assert_eq!(h.meta.get("evidence_id").unwrap(), "EV-001");

    // ---- Info ----------------------------------------------------------
    let info = client
        .info(pb::HandleRequest { id: h.id.clone() })
        .await
        .unwrap()
        .into_inner();
    assert!(info.fs_type.starts_with("FAT"));
    assert!(info.block_size > 0);
    // Evidence ids stored on the handle survive to Info.
    assert_eq!(info.meta.get("evidence_id").unwrap(), "EV-001");

    // ---- Walk ----------------------------------------------------------
    let entries = walk_all(&mut client, &h.id).await;
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"/HELLO.TXT"), "paths: {paths:?}");
    assert!(paths.contains(&"/TESTDIR/FAKE.TXT"));
    let deleted: Vec<_> = entries.iter().filter(|e| e.status == "deleted").collect();
    assert!(!deleted.is_empty(), "deleted dirent must be walked");
    // Masquerade verdict rides along on the entry.
    let fake = entries.iter().find(|e| e.path == "/TESTDIR/FAKE.TXT").unwrap();
    let mv = fake.magic.as_ref().expect("magic verdict on FAKE.TXT");
    assert!(mv.mismatch, "PE-in-TXT must mismatch");
    assert_eq!(mv.severity, "high");
    // Provenance: metadata record + data extents are absolute offsets.
    let hello = entries.iter().find(|e| e.path == "/HELLO.TXT").unwrap();
    assert_eq!(hello.disk_offset as usize, common::ROOT_OFF);
    assert_eq!(
        hello.allocated_ranges.first().map(|r| r.offset as usize),
        Some(common::clus_off(2))
    );

    // ---- Walk filters ----------------------------------------------------
    let mut s = client
        .walk(pb::WalkRequest {
            handle_id: h.id.clone(),
            status_filter: "deleted".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut n_deleted = 0;
    while let Some(e) = s.message().await.unwrap() {
        if e.error.is_empty() {
            assert_eq!(e.status, "deleted", "filter leaked live entry: {e:?}");
            n_deleted += 1;
        }
    }
    assert!(n_deleted >= 1);

    // ---- Read ------------------------------------------------------------
    let mut s = client
        .read(pb::ReadRequest {
            handle_id: h.id.clone(),
            path: "/HELLO.TXT".into(),
            offset: 0,
            len: 0,
            chunk_size: 8, // client hint below the file size → multi-chunk
        })
        .await
        .unwrap()
        .into_inner();
    let mut data = Vec::new();
    let mut saw_eof = false;
    while let Some(c) = s.message().await.unwrap() {
        assert!(c.data.len() <= 8, "chunk bound violated");
        data.extend_from_slice(&c.data);
        saw_eof |= c.eof;
    }
    assert!(saw_eof, "stream must end with eof");
    assert_eq!(data, b"hello forensic world");

    // Read: partial range.
    let mut s = client
        .read(pb::ReadRequest {
            handle_id: h.id.clone(),
            path: "/HELLO.TXT".into(),
            offset: 6,
            len: 8,
            chunk_size: 0,
        })
        .await
        .unwrap()
        .into_inner();
    let mut data = Vec::new();
    while let Some(c) = s.message().await.unwrap() {
        data.extend_from_slice(&c.data);
    }
    assert_eq!(data, b"forensic");

    // Read: missing path → NotFound as a stream item.
    let mut s = client
        .read(pb::ReadRequest {
            handle_id: h.id.clone(),
            path: "/NOPE.BIN".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let err = s.message().await.expect_err("missing path must error");
    assert_eq!(err.code(), Code::NotFound);

    // ---- Unmount ---------------------------------------------------------
    let r = client
        .unmount(pb::HandleRequest { id: h.id.clone() })
        .await
        .unwrap()
        .into_inner();
    assert!(r.unmounted);
    // Second unmount: handle gone → unmounted=false per proto contract.
    let r = client
        .unmount(pb::HandleRequest { id: h.id.clone() })
        .await
        .unwrap()
        .into_inner();
    assert!(!r.unmounted);
    // Walk on a dead handle → NotFound.
    let err = client
        .walk(pb::WalkRequest {
            handle_id: h.id.clone(),
            ..Default::default()
        })
        .await
        .expect_err("dead handle must fail");
    assert_eq!(err.code(), Code::NotFound);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mount_parser_selection_and_errors() {
    let (addr, _srv) = spawn_server(Duration::from_secs(60)).await;
    let mut client = SutramFsClient::connect(format!("http://{addr}")).await.unwrap();

    // Explicit parser name.
    let h = client
        .mount(pb::MountRequest {
            image: Some(image_ref()),
            options: None,
            parser: "fat".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(h.parser, "fat");

    // Unknown parser name → InvalidArgument listing known parsers.
    let err = client
        .mount(pb::MountRequest {
            image: Some(image_ref()),
            options: None,
            parser: "zfs".into(),
        })
        .await
        .expect_err("unknown parser must fail");
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(err.message().contains("fat"), "{}", err.message());

    // Garbage image, auto-detect → no parser claims it.
    let err = client
        .mount(pb::MountRequest {
            image: Some(pb::ImageRef {
                source: Some(ImageSource::Inline(vec![0xAB; 8192])),
                offset: 0,
                length: 0,
            }),
            options: None,
            parser: String::new(),
        })
        .await
        .expect_err("garbage image must fail");
    assert_eq!(err.code(), Code::FailedPrecondition);

    // Missing source entirely → InvalidArgument.
    let err = client
        .detect(pb::ImageRef {
            source: None,
            offset: 0,
            length: 0,
        })
        .await
        .expect_err("empty ImageRef must fail");
    assert_eq!(err.code(), Code::InvalidArgument);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handle_ttl_expires() {
    // 50 ms TTL: mount, wait past expiry, expect NotFound.
    let (addr, _srv) = spawn_server(Duration::from_millis(50)).await;
    let mut client = SutramFsClient::connect(format!("http://{addr}")).await.unwrap();
    let h = mount(&mut client).await;
    tokio::time::sleep(Duration::from_millis(120)).await;
    let err = client
        .info(pb::HandleRequest { id: h.id.clone() })
        .await
        .expect_err("expired handle must fail");
    assert_eq!(err.code(), Code::NotFound);
}
