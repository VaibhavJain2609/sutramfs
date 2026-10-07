//! Remnant carving: sweep a raw byte range for orphaned `FILE` records and
//! `INDX` index blocks belonging to a *dead* filesystem state — the classic
//! post-format / overwritten-$MFT scenario.
//!
//! Unlike the mount-time scan (which walks the live `$MFT`'s extents), this
//! module knows nothing about which regions were the old MFT: it sweeps the
//! source sequentially, finds `FILE`/`INDX` signatures at candidate offsets,
//! applies the fixup, and emits every structurally valid hit. Callers layer
//! meaning on top — parent-record links inside `$FILE_NAME` attributes let a
//! consumer rebuild a directory tree even when the MFT itself is gone.
//!
//! INDX flag bits follow ntfs-3g: `0x0001` = entry has a sub-node pointer,
//! `0x0002` = terminator entry (end of index level).

use std::io::Write;

use sutram_fs::{FsError, Result};
use sutram_io::{le, ByteSource};

use crate::attr::{self};
use crate::fs::NtfsFs;
use crate::indx;
use crate::record::{self, FileRecord};

/// One `$FILE_NAME` payload lifted out of a FILE record.
#[derive(Debug)]
pub struct RemnantName {
    /// Parent directory file reference (low 48 bits = record number).
    pub parent_ref: u64,
    pub parent_rec: u64,
    pub name: String,
    pub real_size: u64,
    /// Win32 attribute flags (`0x1000_0000` = directory).
    pub flags: u32,
    /// 0 POSIX, 1 WIN32, 2 DOS, 3 WIN32&DOS.
    pub namespace: u8,
}

/// One `$DATA` stream of a FILE remnant.
#[derive(Debug)]
pub struct RemnantData {
    /// ADS name (`None`/`""` = default stream).
    pub name: Option<String>,
    pub real_size: u64,
    /// Content was resident in the record (no runlist).
    pub resident: bool,
    /// Resident content length in bytes.
    pub resident_len: usize,
    /// Non-resident extents: `(lcn, cluster_count)`; sparse runs excluded.
    pub runs: Vec<(u64, u64)>,
}

/// A structurally valid `FILE` record found outside the live `$MFT`.
#[derive(Debug)]
pub struct RemnantRecord {
    /// Absolute byte offset on the source.
    pub offset: u64,
    /// Self-reported MFT record number (field at 0x2C; `0` when absent —
    /// pre-Vista formats or log-embedded copies).
    pub record_no: u32,
    pub signature: [u8; 4],
    pub sequence: u16,
    pub in_use: bool,
    pub is_dir: bool,
    /// Base-record reference (nonzero => this is an extension record).
    pub base_ref: u64,
    pub names: Vec<RemnantName>,
    pub data: Vec<RemnantData>,
}

/// One entry of a recovered `INDX` block: a stale directory listing line —
/// `(child record, name, parent directory record, size)`.
#[derive(Debug)]
pub struct RemnantIndexEntry {
    /// Indexed child's file reference (record + sequence).
    pub child_ref: u64,
    pub child_rec: u64,
    /// Parent-directory reference from the embedded `$FILE_NAME`.
    pub parent_ref: u64,
    pub parent_rec: u64,
    pub name: String,
    pub real_size: u64,
    pub flags: u32,
    pub namespace: u8,
    /// Entry points at a child index node (`INDEX_ENTRY_NODE`).
    pub has_subnode: bool,
}

/// A structurally valid `INDX` index-allocation block.
#[derive(Debug)]
pub struct RemnantIndex {
    pub offset: u64,
    /// VCN the block covered within its index allocation.
    pub vcn: u64,
    pub entries: Vec<RemnantIndexEntry>,
}

/// Scan hit produced by [`scan_remnants`].
#[derive(Debug)]
pub enum Remnant {
    File(RemnantRecord),
    Index(RemnantIndex),
}

/// Knobs for [`scan_remnants`].
#[derive(Debug, Clone)]
pub struct RemnantScanOpts {
    /// Bytes per sector (fixup granularity). Default 512.
    pub sector_size: usize,
    /// INDX record size. Default 4096.
    pub index_size: usize,
    /// Only probe offsets divisible by `record_size`. Default `false` —
    /// records embedded in `$LogFile` pages or unmapped fragments are not
    /// always MFT-aligned.
    pub aligned_only: bool,
    /// FILE record size used for `aligned_only` probing. Default 1024.
    pub record_size: u64,
    /// Sequential read granularity. Default 64 MiB.
    pub chunk_size: usize,
    /// Byte ranges to skip entirely (e.g. the live `$MFT` extents when only
    /// *old* records are wanted). `(offset, len)` pairs, absolute.
    pub exclude: Vec<(u64, u64)>,
}

impl Default for RemnantScanOpts {
    fn default() -> Self {
        Self {
            sector_size: 512,
            index_size: 4096,
            aligned_only: false,
            record_size: 1024,
            chunk_size: 64 * 1024 * 1024,
            exclude: Vec::new(),
        }
    }
}

/// Scan tallies.
#[derive(Debug, Default, Clone, Copy)]
pub struct RemnantStats {
    pub bytes_scanned: u64,
    pub file_hits: u64,
    pub indx_hits: u64,
}

fn excluded(opts: &RemnantScanOpts, off: u64) -> bool {
    opts.exclude.iter().any(|&(s, l)| off >= s && off < s + l)
}

/// Lift a FILE record at `off` from `raw` (len ≥ record size) into a
/// [`RemnantRecord`]; `None` when the bytes are not a sane record.
fn parse_file_hit(raw: &[u8], off: u64, opts: &RemnantScanOpts) -> Option<RemnantRecord> {
    let n = opts.record_size as usize;
    if raw.len() < n || n < 0x30 {
        return None;
    }
    let rec: FileRecord =
        record::parse_record(raw[..n].to_vec(), off, 0, opts.sector_size).ok()?;
    let (attrs, _err) = NtfsFs::collect_attrs(&rec);
    let mut names = Vec::new();
    let mut datas = Vec::new();
    for a in attrs {
        match a.type_code {
            attr::T_FILE_NAME => {
                if let Some((body_off, body_len)) = a.resident {
                    let rel = body_off.checked_sub(rec.offset)? as usize;
                    let end = rel.saturating_add(body_len as usize);
                    if end <= rec.data.len() {
                        if let Some(f) = attr::parse_fn(&rec.data[rel..end]) {
                            names.push(RemnantName {
                                parent_ref: f.parent_ref,
                                parent_rec: attr::file_ref_rec(f.parent_ref),
                                name: f.name,
                                real_size: f.real_size,
                                flags: f.flags,
                                namespace: f.namespace,
                            });
                        }
                    }
                }
            }
            attr::T_DATA => {
                if let Some((body_off, body_len)) = a.resident {
                    let _ = (body_off, body_len);
                    datas.push(RemnantData {
                        name: a.name.filter(|s| !s.is_empty()),
                        real_size: a.real_size,
                        resident: true,
                        resident_len: body_len as usize,
                        runs: Vec::new(),
                    });
                } else {
                    datas.push(RemnantData {
                        name: a.name.filter(|s| !s.is_empty()),
                        real_size: a.real_size,
                        resident: false,
                        resident_len: 0,
                        runs: a
                            .runs
                            .iter()
                            .filter_map(|r| r.lcn.map(|l| (l, r.len)))
                            .collect(),
                    });
                }
            }
            _ => {}
        }
    }
    if names.is_empty() {
        return None; // a FILE record without $FILE_NAME is rarely useful
    }
    Some(RemnantRecord {
        offset: off,
        record_no: le::u32(&rec.data, 0x2C).unwrap_or(0),
        signature: rec.signature,
        sequence: rec.sequence,
        in_use: rec.in_use(),
        is_dir: rec.is_dir(),
        base_ref: rec.base_ref,
        names,
        data: datas,
    })
}

/// Lift an INDX block at `off` into a [`RemnantIndex`].
fn parse_indx_hit(raw: &[u8], off: u64, opts: &RemnantScanOpts) -> Option<RemnantIndex> {
    let n = opts.index_size.min(raw.len());
    if n < 0x30 {
        return None;
    }
    let mut blk = raw[..n].to_vec();
    record::apply_indx_fixup(&mut blk, off, opts.sector_size).ok()?;
    let (vcn, hdr_off) = indx::indx_record_header(&blk, off).ok()?;
    let hdr = indx::index_header(&blk, hdr_off)?;
    let node_end = blk.len().saturating_sub(hdr_off);
    let ents = indx::index_entries(&blk, hdr_off, hdr.entries_off, hdr.used_len.min(node_end));
    let mut out = Vec::new();
    for e in ents {
        if e.is_end || e.body_len < 0x42 {
            continue;
        }
        let end = e.body_off.saturating_add(e.body_len);
        if end > blk.len() {
            break;
        }
        if let Some(f) = attr::parse_fn(&blk[e.body_off..end]) {
            let entry_flags = le::u16(&blk, e.body_off - 0x10 + 0x0C).unwrap_or(0);
            out.push(RemnantIndexEntry {
                child_ref: e.file_ref,
                child_rec: e.record_no,
                parent_ref: f.parent_ref,
                parent_rec: attr::file_ref_rec(f.parent_ref),
                name: f.name,
                real_size: f.real_size,
                flags: f.flags,
                namespace: f.namespace,
                has_subnode: entry_flags & 0x01 != 0,
            });
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(RemnantIndex {
        offset: off,
        vcn,
        entries: out,
    })
}

/// Sweep `src[start..end]` for FILE/INDX signatures, invoking `emit` on every
/// valid remnant. `progress` (optional) receives the absolute scan position at
/// each chunk boundary — hook it to stderr for a live indicator.
///
/// Streaming and bounded-memory: the rolling buffer is `chunk_size` plus one
/// `index_size` tail so hits spanning a chunk edge are still caught.
pub fn scan_remnants(
    src: &dyn ByteSource,
    start: u64,
    end: u64,
    opts: &RemnantScanOpts,
    mut progress: Option<&mut dyn FnMut(u64)>,
    mut emit: impl FnMut(Remnant),
) -> Result<RemnantStats> {
    let mut stats = RemnantStats::default();
    let end = end.min(src.len());
    if start >= end {
        return Ok(stats);
    }
    let keep = opts.index_size; // tail carried across chunk reads
    let mut buf: Vec<u8> = Vec::with_capacity(opts.chunk_size + keep);
    let mut base = start; // absolute offset of buf[0]
    let mut pos = start;
    while pos < end {
        let want = (opts.chunk_size as u64).min(end - pos) as usize;
        let chunk = src
            .read_slice(pos, want)
            .map_err(FsError::Io)?;
        if chunk.is_empty() {
            break;
        }
        pos += chunk.len() as u64;
        buf.extend_from_slice(&chunk);

        // Only records whose start leaves `keep` bytes of lookahead are
        // safe to decode this round.
        let scannable = buf.len().saturating_sub(keep);
        let mut i = 0usize;
        while i < scannable {
            let sig = &buf[i..i + 4];
            if sig == b"FILE" || sig == b"INDX" {
                let off = base + i as u64;
                if !(opts.aligned_only && off % opts.record_size != 0) && !excluded(opts, off) {
                    let hit = if sig == b"FILE" {
                        parse_file_hit(&buf[i..], off, opts).map(Remnant::File)
                    } else {
                        parse_indx_hit(&buf[i..], off, opts).map(Remnant::Index)
                    };
                    if let Some(r) = hit {
                        match r {
                            Remnant::File(_) => stats.file_hits += 1,
                            Remnant::Index(_) => stats.indx_hits += 1,
                        }
                        emit(r);
                    }
                }
                i += 1;
            } else {
                i += 1;
            }
        }
        stats.bytes_scanned += scannable as u64;
        buf.drain(..scannable);
        base += scannable as u64;
        if let Some(p) = progress.as_deref_mut() {
            p(base + buf.len() as u64);
        }
    }
    Ok(stats)
}

/// Probe NTFS geometry from the boot sector at source offset 0:
/// `(bytes_per_sector, file_record_size, index_record_size)`. `None` when
/// the source doesn't start with a parseable NTFS BPB (e.g. a bare raw
/// region) — callers should then fall back to the [`RemnantScanOpts`]
/// defaults.
pub fn probe_geometry(src: &dyn ByteSource) -> Option<(u64, u64, u64)> {
    let bs = crate::boot::BootSector::parse(src).ok()?;
    Some((
        bs.bytes_per_sector,
        bs.file_record_size,
        bs.index_record_size,
    ))
}

/// Byte ranges of the live `$MFT` extents — pass to
/// [`RemnantScanOpts::exclude`] to keep live records out of the remnant set.
pub fn live_mft_extents(fs: &NtfsFs) -> Vec<(u64, u64)> {
    let csz = fs.bs.cluster_size;
    fs.mft_runs
        .iter()
        .filter_map(|r| r.lcn.map(|l| (l * csz, r.len * csz)))
        .collect()
}

fn esc(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Render one remnant as a JSONL line — the interchange format consumed by
/// tree-rebuild tooling (`old_records*.jsonl` schema).
pub fn to_jsonl(r: &Remnant) -> String {
    let mut s = String::with_capacity(256);
    match r {
        Remnant::File(f) => {
            s.push_str("{\"kind\":\"FILE\",\"off\":");
            s.push_str(&f.offset.to_string());
            s.push_str(",\"rec_no\":");
            s.push_str(&f.record_no.to_string());
            s.push_str(",\"sig\":");
            esc(std::str::from_utf8(&f.signature).unwrap_or("????"), &mut s);
            s.push_str(",\"in_use\":");
            s.push_str(if f.in_use { "true" } else { "false" });
            s.push_str(",\"is_dir\":");
            s.push_str(if f.is_dir { "true" } else { "false" });
            s.push_str(",\"seq\":");
            s.push_str(&f.sequence.to_string());
            s.push_str(",\"base\":");
            s.push_str(&f.base_ref.to_string());
            s.push_str(",\"names\":[");
            for (i, n) in f.names.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str("{\"name\":");
                esc(&n.name, &mut s);
                s.push_str(",\"parent\":");
                s.push_str(&n.parent_rec.to_string());
                s.push_str(",\"real\":");
                s.push_str(&n.real_size.to_string());
                s.push_str(",\"ns\":");
                s.push_str(&n.namespace.to_string());
                s.push_str(",\"flags\":");
                s.push_str(&n.flags.to_string());
                s.push('}');
            }
            s.push_str("],\"datas\":[");
            for (i, d) in f.data.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str("{\"name\":");
                match &d.name {
                    Some(n) => esc(n, &mut s),
                    None => s.push_str("\"\""),
                }
                s.push_str(",\"real\":");
                s.push_str(&d.real_size.to_string());
                if d.resident {
                    s.push_str(",\"resident\":true,\"res_len\":");
                    s.push_str(&d.resident_len.to_string());
                } else {
                    s.push_str(",\"runs\":[");
                    for (j, (lcn, len)) in d.runs.iter().enumerate() {
                        if j > 0 {
                            s.push(',');
                        }
                        s.push('[');
                        s.push_str(&lcn.to_string());
                        s.push(',');
                        s.push_str(&len.to_string());
                        s.push(']');
                    }
                    s.push(']');
                }
                s.push('}');
            }
            s.push_str("]}");
        }
        Remnant::Index(x) => {
            s.push_str("{\"kind\":\"INDX\",\"off\":");
            s.push_str(&x.offset.to_string());
            s.push_str(",\"vcn\":");
            s.push_str(&x.vcn.to_string());
            s.push_str(",\"entries\":[");
            for (i, e) in x.entries.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str("{\"child\":");
                s.push_str(&e.child_rec.to_string());
                s.push_str(",\"cseq\":");
                s.push_str(&(e.child_ref >> 48).to_string());
                s.push_str(",\"name\":");
                esc(&e.name, &mut s);
                s.push_str(",\"parent\":");
                s.push_str(&e.parent_rec.to_string());
                s.push_str(",\"size\":");
                s.push_str(&e.real_size.to_string());
                s.push_str(",\"is_dir\":");
                s.push_str(if e.flags & 0x1000_0000 != 0 {
                    "true"
                } else {
                    "false"
                });
                s.push_str(",\"sub\":");
                s.push_str(if e.has_subnode { "1" } else { "0" });
                s.push('}');
            }
            s.push_str("]}");
        }
    }
    s
}

/// Convenience: run the scan and stream JSONL to `w`.
pub fn scan_to_jsonl(
    src: &dyn ByteSource,
    start: u64,
    end: u64,
    opts: &RemnantScanOpts,
    progress: Option<&mut dyn FnMut(u64)>,
    w: &mut dyn Write,
) -> Result<RemnantStats> {
    let mut werr: Option<String> = None;
    let stats = scan_remnants(src, start, end, opts, progress, |r| {
        if werr.is_none() {
            if let Err(e) = writeln!(w, "{}", to_jsonl(&r)) {
                werr = Some(e.to_string());
            }
        }
    })?;
    if let Some(e) = werr {
        return Err(FsError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)));
    }
    Ok(stats)
}
