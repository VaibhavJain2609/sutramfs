//! sutramfs — CLI front-end for the SUTRAM-FS forensic parser family.
//!
//! ```text
//! sutramfs detect  <image>                      probe all parsers, show confidences
//! sutramfs parts   <image>                      list MBR/GPT partitions
//! sutramfs android <image>                      Android layout (sparse/super/vbmeta/FBE)
//! sutramfs info    <image> [-p N]               mount best match (or -t fs), show FsInfo
//! sutramfs ls      <image> [-p N] [-t fs] [-d|--deleted] [-o fmt]
//! sutramfs cat     <image> <path> [-p N] [-t fs] [--recover]
//! sutramfs carve   <image> [-p N] [-t fs] [--offset O --len L] [--align A]
//! ```
//! `-o` formats: `tree` (default), `json` (JSONL), `csv`, `bodyfile` (mactime).
#![forbid(unsafe_code)]

mod out;

use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::Arc;

use sutram_fs::{DetectConfidence, FsEntry, FsParser, MountOptions};
use sutram_io::ByteSource;

fn parsers() -> Vec<Box<dyn FsParser>> {
    vec![
        Box::new(sutram_ntfs::NtfsParser),
        Box::new(sutram_exfat::ExFatParser),
        Box::new(sutram_fat::FatParser),
        Box::new(sutram_ext4::Ext4Parser),
        Box::new(sutram_btrfs::BtrfsParser),
        Box::new(sutram_f2fs::F2fsParser),
        Box::new(sutram_xfs::XfsParser),
        Box::new(sutram_hfs::HfsParser),
        Box::new(sutram_apfs::ApfsParser),
    ]
}

fn usage() -> ! {
    eprintln!("{}", include_str!("usage.txt"));
    std::process::exit(2);
}

fn open_image(path: &str) -> io::Result<Arc<dyn ByteSource>> {
    // sniff raw/E01/VHD/VHDX/QCOW2/split-raw in one place
    sutram_io::open_image(path).map_err(|e| match e {
        sutram_io::Error::Io(e) => e,
        e => io::Error::new(io::ErrorKind::InvalidData, e.to_string()),
    })
}

/// Optional `-p N`: scope the source to partition N (0-based).
fn maybe_partition(src: Arc<dyn ByteSource>, part: Option<usize>) -> Result<Arc<dyn ByteSource>, String> {
    match part {
        None => Ok(src),
        Some(i) => {
            let parts = sutram_io::open_partitions(src).map_err(|e| format!("partition table: {e}"))?;
            parts
                .into_iter()
                .nth(i)
                .map(|p| sutram_io::into_arc(p.source))
                .ok_or_else(|| format!("no partition #{i}"))
        }
    }
}

/// Pick a parser: explicit `-t name`, else best detect() confidence.
fn choose_parser(
    src: &Arc<dyn ByteSource>,
    forced: Option<&str>,
) -> Result<(Box<dyn FsParser>, DetectConfidence), String> {
    if let Some(name) = forced {
        return parsers()
            .into_iter()
            .find(|p| p.name() == name)
            .map(|p| (p, DetectConfidence::Certain))
            .ok_or_else(|| format!("unknown fs type '{name}' (try `sutramfs detect`)"));
    }
    let mut best: Option<(Box<dyn FsParser>, DetectConfidence)> = None;
    for p in parsers() {
        let c = p.detect(src.as_ref());
        if c > best.as_ref().map(|(_, bc)| *bc).unwrap_or(DetectConfidence::None) {
            best = Some((p, c));
        }
    }
    match best {
        Some((p, c)) if c >= DetectConfidence::Medium => Ok((p, c)),
        _ => Err("no parser recognised the image (use -t to force)".into()),
    }
}

struct Common {
    image: String,
    part: Option<usize>,
    fstype: Option<String>,
    strict: bool,
}

impl Common {
    fn mount(&self) -> Result<Box<dyn sutram_fs::FileSystem>, String> {
        let src = open_image(&self.image).map_err(|e| format!("open {}: {e}", self.image))?;
        let src = maybe_partition(src, self.part)?;
        let (parser, _conf) = choose_parser(&src, self.fstype.as_deref())?;
        let opts = MountOptions {
            strict: self.strict,
            ..MountOptions::default()
        };
        parser.mount_with(src, &opts).map_err(|e| format!("mount: {e}"))
    }
}

/// Parse common flags; returns (Common, remaining positionals).
fn parse_common(args: &[String]) -> Result<(Common, Vec<String>), String> {
    let mut c = Common {
        image: String::new(),
        part: None,
        fstype: None,
        strict: false,
    };
    let mut pos = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--partition" => {
                i += 1;
                c.part = Some(
                    args.get(i)
                        .and_then(|s| s.parse().ok())
                        .ok_or("-p needs a partition index")?,
                );
            }
            "-t" | "--type" => {
                i += 1;
                c.fstype = Some(args.get(i).ok_or("-t needs an fs name")?.clone());
            }
            "--strict" => c.strict = true,
            s if s.starts_with('-') => return Err(format!("unknown flag {s}")),
            s => pos.push(s.to_string()),
        }
        i += 1;
    }
    c.image = pos.first().cloned().unwrap_or_default();
    if c.image.is_empty() {
        return Err("missing <image>".into());
    }
    Ok((c, pos))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("detect") => run(cmd_detect(&args[1..])),
        Some("parts") => run(cmd_parts(&args[1..])),
        Some("android") => run(cmd_android(&args[1..])),
        Some("info") => run(cmd_info(&args[1..])),
        Some("ls") | Some("walk") => run(cmd_ls(&args[1..])),
        Some("cat") | Some("extract") => run(cmd_cat(&args[1..])),
        Some("carve") => run(cmd_carve(&args[1..])),
        Some("remnants") => run(cmd_remnants(&args[1..])),
        Some("rebuild") => run(cmd_rebuild(&args[1..])),
        Some("-h") | Some("--help") | None => usage(),
        Some(other) => {
            eprintln!("unknown command '{other}'");
            usage()
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

fn cmd_detect(args: &[String]) -> Result<(), String> {
    let (c, _) = parse_common(args)?;
    let src = open_image(&c.image).map_err(|e| format!("open: {e}"))?;
    let src = maybe_partition(src, c.part)?;
    let mut rows: Vec<(&'static str, DetectConfidence)> = parsers()
        .iter()
        .map(|p| (p.name(), p.detect(src.as_ref())))
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.1));
    println!("{:<10} confidence", "parser");
    for (name, conf) in rows {
        println!("{name:<10} {conf:?}");
    }
    Ok(())
}

fn cmd_parts(args: &[String]) -> Result<(), String> {
    let (c, _) = parse_common(args)?;
    let src = open_image(&c.image).map_err(|e| format!("open: {e}"))?;
    let parts = sutram_io::partitions(src.as_ref()).map_err(|e| format!("{e}"))?;
    if parts.is_empty() {
        println!("no partition table found (image may be a bare filesystem)");
        return Ok(());
    }
    for p in parts {
        let kind = p
            .type_guid
            .clone()
            .or_else(|| p.ptype.map(|t| format!("0x{t:02x}")))
            .unwrap_or_else(|| "?".into());
        println!(
            "#{:<2} {:>12} {:>12} {:<8} {} {}",
            p.index,
            p.offset,
            p.size,
            format!("{:?}", p.table),
            kind,
            p.label.clone().unwrap_or_default()
        );
    }
    Ok(())
}

fn cmd_android(args: &[String]) -> Result<(), String> {
    let (c, _) = parse_common(args)?;
    let src = open_image(&c.image).map_err(|e| format!("open: {e}"))?;
    let layout = sutram_part::analyze(src).map_err(|e| format!("{e}"))?;
    println!("container: {:?}", layout.container);
    for cf in &layout.crypto {
        println!("crypto:    {:?} {} — {}", cf.kind, cf.partition, cf.note);
    }
    for p in &layout.partitions {
        println!(
            "{:<20} {:>10} bytes  role={:?} group={} {}",
            p.name,
            p.source.len(),
            p.role,
            p.group,
            if p.attrs.readonly() { "ro" } else { "" }
        );
    }
    for w in &layout.warnings {
        println!("warning:   {w}");
    }
    Ok(())
}

fn cmd_info(args: &[String]) -> Result<(), String> {
    let (c, _) = parse_common(args)?;
    let fs = c.mount()?;
    let i = fs.info();
    println!("type:        {}", i.fs_type);
    if let Some(l) = &i.label {
        println!("label:       {l}");
    }
    if let Some(u) = &i.uuid {
        println!("uuid:        {u}");
    }
    println!("block_size:  {}", i.block_size);
    println!("blocks:      {}", i.total_blocks);
    if let Some(f) = i.free_blocks {
        println!("free_blocks: {f}");
    }
    if let Some(n) = i.total_nodes {
        println!("nodes:       {n}");
    }
    for (k, v) in &i.meta {
        println!("meta.{k}: {v}");
    }
    Ok(())
}

fn cmd_ls(args: &[String]) -> Result<(), String> {
    let mut deleted_only = false;
    let mut format = "tree".to_string();
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-d" | "--deleted" => deleted_only = true,
            "-o" | "--output" => {
                i += 1;
                format = args.get(i).ok_or("-o needs a format")?.clone();
            }
            _ => rest.push(args[i].clone()),
        }
        i += 1;
    }
    if !matches!(
        format.as_str(),
        "tree" | "json" | "jsonl" | "csv" | "bodyfile" | "mactime"
    ) {
        return Err(format!(
            "unknown output format '{format}' (tree|json|csv|bodyfile)"
        ));
    }
    let (c, _) = parse_common(&rest)?;
    let fs = c.mount()?;
    let out = io::stdout();
    let mut w = io::BufWriter::new(out.lock());
    if format == "csv" {
        writeln!(w, "entry_id,kind,size,status,mtime,disk_offset,path")
            .map_err(|e| e.to_string())?;
    }
    let iter = fs.walk();
    let mut n = 0usize;
    for item in iter {
        match item {
            Ok(e) => {
                if deleted_only && !e.is_deleted() {
                    continue;
                }
                out::emit(&mut w, &e, &format).map_err(|e| e.to_string())?;
                n += 1;
            }
            // Walk errors go to stderr so json/csv/bodyfile stay parseable.
            Err(e) => eprintln!("ERROR {e}"),
        }
    }
    if format == "tree" {
        writeln!(w, "-- {n} entries").map_err(|e| e.to_string())?;
    }
    w.flush().map_err(|e| e.to_string())
}

fn cmd_cat(args: &[String]) -> Result<(), String> {
    // `--recover` is advisory: cat already attempts recovery reads of
    // deleted entries, so accept (and drop) the flag the usage advertises.
    let args: Vec<String> = args
        .iter()
        .filter(|a| a.as_str() != "--recover")
        .cloned()
        .collect();
    let (c, pos) = parse_common(&args)?;
    let target = pos.get(1).ok_or("usage: sutramfs cat <image> <path>")?;
    let fs = c.mount()?;
    let mut found: Option<FsEntry> = None;
    for e in fs.walk().flatten() {
        if e.path == *target || e.name == *target {
            found = Some(e);
            break;
        }
    }
    let e = found.ok_or_else(|| format!("no entry '{target}'"))?;
    let mut r = fs.read_file(&e).map_err(|e| format!("read: {e}"))?;
    let mut out = io::stdout().lock();
    let n = io::copy(&mut r, &mut out).map_err(|e| e.to_string())?;
    eprintln!("# {} bytes recovered from {} ({:?})", n, e.path, e.status);
    Ok(())
}

fn cmd_carve(args: &[String]) -> Result<(), String> {
    let mut offset = 0u64;
    let mut len: Option<u64> = None;
    let mut align = 512u64;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--offset" => {
                i += 1;
                offset = args.get(i).and_then(|s| s.parse().ok()).ok_or("--offset")?;
            }
            "--len" => {
                i += 1;
                len = Some(args.get(i).and_then(|s| s.parse().ok()).ok_or("--len")?);
            }
            "--align" => {
                i += 1;
                align = args.get(i).and_then(|s| s.parse().ok()).ok_or("--align")?;
            }
            "--unallocated" => { /* handled below via unallocated_ranges */ }
            _ => rest.push(args[i].clone()),
        }
        i += 1;
    }
    let unalloc = args.iter().any(|a| a == "--unallocated");
    let (c, _) = parse_common(&rest)?;
    let fs = c.mount()?;
    let src = fs.source();
    let end = len
        .map(|l| offset.saturating_add(l).min(src.len()))
        .unwrap_or_else(|| src.len());
    if !unalloc && offset >= end {
        return Err(format!(
            "--offset {offset:#x} at or beyond image end ({:#x})",
            src.len()
        ));
    }
    let mut hits = 0usize;
    let mut scan = |off: u64, len_: u64| -> Result<(), String> {
        for h in fs.carve_region(off, len_, align).map_err(|e| e.to_string())? {
            let h = h.map_err(|e| e.to_string())?;
            println!("{:#x}  {:>8}  {:?}", h.offset, h.len, h.kind);
            hits += 1;
        }
        Ok(())
    };
    if unalloc {
        for (off, l) in fs.unallocated_ranges() {
            scan(off, l)?;
        }
    } else {
        scan(offset, end - offset)?;
    }
    eprintln!("-- {hits} carve hits");
    Ok(())
}

fn cmd_remnants(args: &[String]) -> Result<(), String> {
    let mut offset = 0u64;
    let mut len: Option<u64> = None;
    let mut aligned_only = false;
    let mut exclude_mft = false;
    let mut sector_size = 0u64;
    let mut rec_size = 0u64;
    let mut indx_size = 0u64;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--offset" => {
                i += 1;
                offset = args.get(i).and_then(|s| s.parse().ok()).ok_or("--offset")?;
            }
            "--len" => {
                i += 1;
                len = Some(args.get(i).and_then(|s| s.parse().ok()).ok_or("--len")?);
            }
            "--sector-size" => {
                i += 1;
                sector_size = args.get(i).and_then(|s| s.parse().ok()).ok_or("--sector-size")?;
            }
            "--rec-size" => {
                i += 1;
                rec_size = args.get(i).and_then(|s| s.parse().ok()).ok_or("--rec-size")?;
            }
            "--indx-size" => {
                i += 1;
                indx_size = args.get(i).and_then(|s| s.parse().ok()).ok_or("--indx-size")?;
            }
            "--aligned-only" => aligned_only = true,
            "--exclude-live-mft" => exclude_mft = true,
            _ => rest.push(args[i].clone()),
        }
        i += 1;
    }
    let (c, _) = parse_common(&rest)?;
    let src = open_image(&c.image).map_err(|e| format!("open {}: {e}", c.image))?;
    let src = maybe_partition(src, c.part)?;

    let mut opts = sutram_ntfs::RemnantScanOpts::default();
    match sutram_ntfs::probe_geometry(src.as_ref()) {
        Some((ss, rs, is_)) => {
            opts.sector_size = ss as usize;
            opts.record_size = rs;
            opts.index_size = is_ as usize;
        }
        None => eprintln!("warning: no NTFS boot sector at offset 0 — using defaults (sector 512, record 1024, index 4096)"),
    }
    if sector_size > 0 {
        opts.sector_size = sector_size as usize;
    }
    if rec_size > 0 {
        opts.record_size = rec_size;
    }
    if indx_size > 0 {
        opts.index_size = indx_size as usize;
    }
    opts.aligned_only = aligned_only;

    if exclude_mft {
        match sutram_ntfs::NtfsFs::mount(src.clone(), MountOptions::default()) {
            Ok(fs) => {
                let ex = sutram_ntfs::live_mft_extents(&fs);
                eprintln!("-- excluding {} live $MFT extent(s)", ex.len());
                opts.exclude = ex;
            }
            Err(e) => eprintln!("warning: mount failed ({e}); scanning everything"),
        }
    }

    let end = len
        .map(|l| offset.saturating_add(l).min(src.len()))
        .unwrap_or_else(|| src.len());
    if offset >= end {
        return Err(format!("--offset {offset:#x} at or beyond image end ({:#x})", src.len()));
    }

    let mut last = 0u64;
    let mut progress = |pos: u64| {
        if pos - last >= 1024 * 1024 * 1024 {
            last = pos;
            eprintln!("... {:.1} GB", pos as f64 / 1e9);
        }
    };

    let out = io::stdout();
    let mut w = io::BufWriter::new(out.lock());
    let stats = sutram_ntfs::scan_to_jsonl(
        src.as_ref(),
        offset,
        end,
        &opts,
        Some(&mut progress),
        &mut w,
    )
    .map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())?;
    eprintln!(
        "-- scanned {:.2} GB: {} FILE records, {} INDX blocks",
        stats.bytes_scanned as f64 / 1e9, stats.file_hits, stats.indx_hits
    );
    Ok(())
}

/// `rebuild`: reconstruct the dead filesystem's directory tree from remnant
/// records (live scan and/or saved JSONL), then match live files back onto
/// old paths by (basename, size). Emits a restore plan.
fn cmd_rebuild(args: &[String]) -> Result<(), String> {
    let mut offset = 0u64;
    let mut len: Option<u64> = None;
    let mut remnant_files: Vec<String> = Vec::new();
    let mut under: Vec<String> = Vec::new();
    let mut format = "csv".to_string();
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--offset" => {
                i += 1;
                offset = args.get(i).and_then(|s| s.parse().ok()).ok_or("--offset")?;
            }
            "--len" => {
                i += 1;
                len = Some(args.get(i).and_then(|s| s.parse().ok()).ok_or("--len")?);
            }
            "--remnants" => {
                i += 1;
                remnant_files.push(args.get(i).ok_or("--remnants needs a file")?.clone());
            }
            "--under" => {
                i += 1;
                under.push(args.get(i).ok_or("--under needs a path")?.clone());
            }
            "-o" | "--output" => {
                i += 1;
                format = args.get(i).ok_or("-o needs a format")?.clone();
            }
            _ => rest.push(args[i].clone()),
        }
        i += 1;
    }
    if !matches!(format.as_str(), "csv" | "jsonl") {
        return Err("unknown output format (csv|jsonl)".into());
    }
    let (c, _) = parse_common(&rest)?;
    let src = open_image(&c.image).map_err(|e| format!("open {}: {e}", c.image))?;
    let src = maybe_partition(src, c.part)?;

    // Mount live FS: needed for the live file list; also gives us the live
    // $MFT extents to exclude from remnant scanning.
    let fs = sutram_ntfs::NtfsFs::mount(src.clone(), MountOptions::default())
        .map_err(|e| format!("mount: {e}"))?;
    let mut opts = sutram_ntfs::RemnantScanOpts::default();
    if let Some((ss, rs, is_)) = sutram_ntfs::probe_geometry(src.as_ref()) {
        opts.sector_size = ss as usize;
        opts.record_size = rs;
        opts.index_size = is_ as usize;
    }
    opts.exclude = sutram_ntfs::live_mft_extents(&fs);

    // --- gather remnants ---
    let live_map = fs.live_names();
    let mut tree = sutram_ntfs::RemnantTree::new();
    let mut n_file = 0u64;
    let mut n_indx = 0u64;
    let mut feed = |r: &sutram_ntfs::Remnant| {
        match r {
            sutram_ntfs::Remnant::File(_) => n_file += 1,
            sutram_ntfs::Remnant::Index(_) => n_indx += 1,
        }
        tree.feed(r, Some(&live_map));
    };

    for path in &remnant_files {
        let f = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
        for line in std::io::BufRead::lines(std::io::BufReader::new(f)) {
            let line = line.map_err(|e| e.to_string())?;
            if let Some(r) = sutram_ntfs::parse_remnant_line(&line) {
                feed(&r);
            }
        }
        eprintln!("-- loaded {}", path);
    }

    if remnant_files.is_empty() || offset != 0 || len.is_some() {
        // live scan too (default: whole source, minus live MFT extents)
        let end = len
            .map(|l| offset.saturating_add(l).min(src.len()))
            .unwrap_or_else(|| src.len());
        eprintln!("-- scanning {:.1} GB for remnants...", (end - offset) as f64 / 1e9);
        sutram_ntfs::scan_remnants(src.as_ref(), offset, end, &opts, None, |r| feed(&r))
            .map_err(|e| e.to_string())?;
    }
    tree.normalize();
    let entries = tree.entries();
    let n_dirs = entries.iter().filter(|e| e.is_dir).count();
    eprintln!(
        "-- tree: {} FILE + {} INDX remnants -> {} entries ({} dirs)",
        n_file, n_indx, entries.len(), n_dirs
    );

    // --- live files ---
    let fsdyn: &dyn sutram_fs::FileSystem = &fs;
    let mut live = Vec::new();
    for e in fsdyn.walk().flatten() {
        if e.kind != sutram_fs::EntryKind::File {
            continue;
        }
        if !under.is_empty() && !under.iter().any(|u| e.path.starts_with(u.as_str())) {
            continue;
        }
        live.push(sutram_ntfs::LiveFile {
            entry_id: e.entry_id,
            path: e.path.clone(),
            name: e.name.clone(),
            size: e.size,
        });
    }
    eprintln!("-- live candidate files: {}", live.len());

    let plan = sutram_ntfs::match_live(&entries, &live);

    let out = io::stdout();
    let mut w = io::BufWriter::new(out.lock());
    match format.as_str() {
        "csv" => {
            writeln!(w, "live_path,restore_to,size,live_recno,old_recno,ambiguous")
                .map_err(|e| e.to_string())?;
            for p in &plan {
                writeln!(
                    w,
                    "\"{}\",\"{}\",{},{},{},{}",
                    p.live_path.replace('"', "\"\""),
                    p.restored_path.replace('"', "\"\""),
                    p.size,
                    p.live_entry_id,
                    p.old_recno,
                    p.ambiguous
                )
                .map_err(|e| e.to_string())?;
            }
        }
        _ => {
            for p in &plan {
                writeln!(
                    w,
                    "{{\"live\":\"{}\",\"restore\":\"{}\",\"size\":{},\"live_recno\":{},\"old_recno\":{},\"ambiguous\":{}}}",
                    p.live_path.replace('\\', "\\\\").replace('"', "\\\""),
                    p.restored_path.replace('\\', "\\\\").replace('"', "\\\""),
                    p.size,
                    p.live_entry_id,
                    p.old_recno,
                    p.ambiguous
                )
                .map_err(|e| e.to_string())?;
            }
        }
    }
    w.flush().map_err(|e| e.to_string())?;
    eprintln!(
        "-- restore plan: {} files mapped ({} ambiguous)",
        plan.len(),
        plan.iter().filter(|p| p.ambiguous).count()
    );
    Ok(())
}
