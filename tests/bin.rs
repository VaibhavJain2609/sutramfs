//! Binary-level tests: spawn the real `sutramfsd` executable, exercise the
//! argument parser, then round-trip a synthetic FAT12 image through a live
//! daemon end to end.

mod common;

use std::process::{Command, Stdio};
use std::time::Duration;

use sutram_fsd::pb;
use sutram_fsd::pb::image_ref::Source as ImageSource;
use sutram_fsd::pb::sutram_fs_client::SutramFsClient;

const BIN: &str = env!("CARGO_BIN_EXE_sutramfsd");

#[test]
fn bad_arguments_exit_2_with_usage() {
    for args in [
        vec!["--help"],
        vec!["--bogus"],
        vec!["--listen", "not-an-address"],
        vec!["--ttl-secs", "abc"],
        vec!["--max-inline-mb", "zz"],
        vec!["--listen"], // missing value
        vec!["--ttl-secs"],
        vec!["--max-inline-mb"],
        vec!["positional"],
    ] {
        let out = Command::new(BIN)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "args {args:?} → {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("usage:"),
            "args {args:?} stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// A live daemon round-trip: bind to a real port, mount a synthetic FAT12
/// inline image, walk it, read a file, unmount. Proves the `main()` wiring
/// (runtime, sweeper spawn, tonic server) works end to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_binary_serves_roundtrip() {
    // Reserve-then-release an ephemeral port (tiny race, accepted locally;
    // the connect loop below tolerates slow startup).
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let mut child = Command::new(BIN)
        .args([
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--ttl-secs",
            "300",
            "--max-inline-mb",
            "16",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut client = None;
    for _ in 0..100 {
        // If the child died (e.g. port race), fail fast with its stderr.
        if let Some(status) = child.try_wait().unwrap() {
            let mut err = String::new();
            use std::io::Read as _;
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut err)
                .unwrap();
            panic!("sutramfsd exited early ({status}): {err}");
        }
        match SutramFsClient::connect(format!("http://127.0.0.1:{port}")).await {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    let mut client = client.expect("sutramfsd did not come up within 5s");

    let image = pb::ImageRef {
        source: Some(ImageSource::Inline(common::fat12_image())),
        offset: 0,
        length: 0,
    };

    let dets = client.detect(image.clone()).await.unwrap().into_inner();
    assert_eq!(dets.results.first().map(|d| d.parser.as_str()), Some("fat"));

    let h = client
        .mount(pb::MountRequest {
            image: Some(image),
            options: None,
            parser: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(h.parser, "fat");
    assert!(h.id.starts_with("mh-"));

    let mut s = client
        .walk(pb::WalkRequest {
            handle_id: h.id.clone(),
            kind_filter: "file".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let mut paths = Vec::new();
    while let Some(e) = s.message().await.unwrap() {
        paths.push(e.path);
    }
    assert!(paths.contains(&"/HELLO.TXT".to_string()), "{paths:?}");

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

    let r = client
        .unmount(pb::HandleRequest { id: h.id.clone() })
        .await
        .unwrap()
        .into_inner();
    assert!(r.unmounted);

    child.kill().unwrap();
    child.wait().unwrap();
}
