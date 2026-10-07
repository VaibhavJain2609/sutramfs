//! sutram-decode — differential-testing helper, NOT part of any crate.
//!
//! Streams the *decoded logical view* of a container image to stdout so its
//! bytes can be hashed/compared against libewf (`ewfexport`) output.
//!
//!   sutram-decode info <img.E01>          print EWF metadata + warnings
//!   sutram-decode raw  <img.E01> [...]    decode all segments to stdout (raw)
//!
//! Exit codes: 0 ok, 1 error, 2 usage.
#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::process::ExitCode;

use sutram_io::{ewf::EwfSource, ByteSource};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("raw") if args.len() >= 2 => run(emit_raw(&args[1..])),
        Some("info") if args.len() == 2 => run(emit_info(&args[1])),
        _ => {
            eprintln!("usage: sutram-decode raw|info <img.E01> [img.E02 ...]");
            ExitCode::from(2)
        }
    }
}

fn run(r: Result<(), String>) -> ExitCode {
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn open(path: &str) -> Result<EwfSource, String> {
    let mut segments = vec![std::path::PathBuf::from(path)];
    // Auto-pick sibling segments (.E02, .E03, ...) in acquisition order.
    for i in 2..100u32 {
        match next_segment(path, i) {
            Some(c) => segments.push(c),
            None => break,
        }
    }
    EwfSource::open_segments(&segments).map_err(|e| format!("open {path}: {e}"))
}

/// Given `x.E01` and index n, return `x.E0n`-style path if it exists.
fn next_segment(first: &str, n: u32) -> Option<std::path::PathBuf> {
    let ext = format!("E{n:02}");
    let cand = std::path::Path::new(first).with_extension(ext);
    if cand.exists() {
        Some(cand)
    } else {
        // libewf also writes lowercase / EAA-style extensions; try common ones.
        for alt in [format!("e{n:02}")] {
            let c = std::path::Path::new(first).with_extension(alt);
            if c.exists() {
                return Some(c);
            }
        }
        None
    }
}

fn emit_info(path: &str) -> Result<(), String> {
    let src = open(path)?;
    let i = src.info();
    println!("media_type:      {:#x}", i.media_type);
    println!("compression:     {}", i.compression_level);
    println!("bytes_per_sector {}", i.bytes_per_sector);
    println!("sector_count:    {}", i.sector_count);
    println!("sectors/chunk:   {}", i.sectors_per_chunk);
    println!("chunk_count:     {}", i.chunk_count);
    println!("chunk_size:      {}", i.chunk_size);
    println!("decoded_len:     {}", src.len());
    println!("segments:        {} (multi={})", i.segment_count, i.multi_segment);
    if let Some(h) = src.acquisition_hash() {
        if let Some(m) = h.md5_hex() {
            println!("stored_md5:      {m}");
        }
        if let Some(s) = h.sha1_hex() {
            println!("stored_sha1:     {s}");
        }
    }
    for w in src.warnings() {
        println!("warning: {w}");
    }
    Ok(())
}

fn emit_raw(paths: &[String]) -> Result<(), String> {
    // The first path opens the set; sibling segments auto-join.
    let src = open(&paths[0])?;
    let stdout = io::stdout();
    let mut w = io::BufWriter::new(stdout.lock());
    let mut pos = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    while pos < src.len() {
        let n = src
            .read_at(pos, &mut buf)
            .map_err(|e| format!("read at {pos:#x}: {e}"))?;
        if n == 0 {
            break;
        }
        w.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        pos += n as u64;
    }
    w.flush().map_err(|e| e.to_string())
}
