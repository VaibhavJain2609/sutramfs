//! `sutramfsd` — gRPC daemon front-end over the SUTRAM-FS parser family.
//!
//! ```text
//! sutramfsd [--listen HOST:PORT] [--ttl-secs N] [--max-inline-mb N]
//! ```
//!
//! Defaults: `127.0.0.1:50051`, 30-minute mount TTL, 64 MiB inline-image
//! cap. The daemon is a trusted-local tool: `ImageRef.path` opens any file
//! the process can read — do not expose the port untrusted.

use std::net::SocketAddr;
use std::time::Duration;

use sutram_fsd::handles::DEFAULT_TTL;
use sutram_fsd::pb::sutram_fs_server::SutramFsServer;
use sutram_fsd::source::MAX_INLINE_BYTES;
use sutram_fsd::SutramFsService;

fn usage() -> ! {
    eprintln!("usage: sutramfsd [--listen HOST:PORT] [--ttl-secs N] [--max-inline-mb N]");
    std::process::exit(2);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut listen: SocketAddr = "127.0.0.1:50051".parse().expect("default addr");
    let mut ttl = DEFAULT_TTL;
    let mut max_inline = MAX_INLINE_BYTES;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--listen" => {
                let v = args.next().unwrap_or_else(|| usage());
                listen = v.parse().unwrap_or_else(|_| {
                    eprintln!("bad --listen address: {v}");
                    usage()
                });
            }
            "--ttl-secs" => {
                let v = args.next().unwrap_or_else(|| usage());
                ttl = Duration::from_secs(v.parse().unwrap_or_else(|_| {
                    eprintln!("bad --ttl-secs: {v}");
                    usage()
                }));
            }
            "--max-inline-mb" => {
                let v = args.next().unwrap_or_else(|| usage());
                max_inline = v.parse::<u64>().unwrap_or_else(|_| {
                    eprintln!("bad --max-inline-mb: {v}");
                    usage()
                }) * 1024
                    * 1024;
            }
            "-h" | "--help" => usage(),
            _ => {
                eprintln!("unknown argument: {a}");
                usage();
            }
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let mut svc = SutramFsService::new(ttl);
        svc.set_max_inline(max_inline);
        svc.spawn_sweeper();
        eprintln!(
            "sutramfsd listening on {listen} (ttl {}s, inline cap {} MiB)",
            ttl.as_secs(),
            max_inline / (1024 * 1024)
        );
        tonic::transport::Server::builder()
            .add_service(SutramFsServer::new(svc))
            .serve(listen)
            .await?;
        Ok(())
    })
}
