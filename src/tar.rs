//! TAR forensic parser: ustar/v7/pax header walks, GNU longname/longlink,
//! sparse members, supersession, and truncated-tail recovery.
//!
//! A tar is a sequential stream of 512-byte header blocks each followed by
//! `ceil(size/512)` data blocks; two consecutive zero blocks end the
//! archive. Forensic behaviours:
//!
//! * **Truncated tail** — a member whose declared data runs past EOF is
//!   emitted `Deleted{PartiallyOverwritten}` with `allocated_ranges`
//!   clamped to the surviving bytes.
//! * **Superseded duplicates** — tar appends newer versions under the
//!   same path; all but the last keep `meta["superseded"]=true`.
//! * **Sparse members** — GNU `S` headers and pax `GNU.sparse.*` maps are
//!   honoured: holes read as zeroes, `allocated_ranges` lists only the
//!   extents physically stored.
//! * **Slack** — bytes after the two zero end-of-archive blocks are
//!   reported via `unallocated_ranges()`.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use sutram_fs::util;
use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsError, FsInfo, FsParser, FsTimestamp,
    FileSystem, MountOptions, RecoveryState, Result, Timestamps,
};
use sutram_io::ByteSource;

use crate::reader::{Segment, SegmentReader};

const BLOCK: u64 = 512;
/// pax record text is bounded — a hostile `len` field could otherwise
/// force a giant allocation.
const MAX_PAX_DATA: u64 = 1 << 20;
/// Longname records beyond this are implausible.
const MAX_NAME: u64 = 1 << 16;
/// Sparse map entry cap (per member).
const MAX_SPARSE: usize = 1 << 16;

/// The parser entry point — stateless.
pub struct TarParser;

impl FsParser for TarParser {
    fn name(&self) -> &'static str {
        "tar"
    }

    fn detect(&self, src: &dyn ByteSource) -> DetectConfidence {
        let h = match src.read_slice(0, BLOCK as usize) {
            Ok(h) if h.len() == BLOCK as usize => h,
            _ => return DetectConfidence::None,
        };
        if is_zero_block(&h) {
            return DetectConfidence::None;
        }
        let magic = &h[257..263];
        let has_ustar = magic == b"ustar\0" || magic == b"ustar ";
        let sum_ok = checksum_ok(&h);
        match (has_ustar, sum_ok) {
            (true, true) => DetectConfidence::Certain,
            (true, false) => DetectConfidence::Medium,
            // v7: no magic — a valid checksum + plausible fields is the
            // whole signature.
            (false, true) => {
                let name_ok = h[0..100].iter().any(|&b| b != 0);
                let tf = h[156];
                let tf_ok = matches!(tf, 0 | b'0'..=b'7' | b'x' | b'g' | b'L' | b'K' | b'S');
                if name_ok && tf_ok && parse_size(&h[124..136]).is_some() {
                    DetectConfidence::Medium
                } else {
                    DetectConfidence::Low
                }
            }
            (false, false) => DetectConfidence::None,
        }
    }

    fn mount_with(
        &self,
        src: Arc<dyn ByteSource>,
        opts: &MountOptions,
    ) -> Result<Box<dyn FileSystem>> {
        Ok(Box::new(TarFs::mount(src, opts.clone())?))
    }
}

fn is_zero_block(b: &[u8]) -> bool {
    b.iter().all(|&x| x == 0)
}

/// Header checksum: bytes 148..156 are stored as the octal sum, computed
/// with those bytes treated as spaces. Accept unsigned and signed sums.
fn checksum_ok(h: &[u8]) -> bool {
    let stored = match parse_octal(&h[148..156]) {
        Some(v) => v as i64,
        None => return false,
    };
    let mut unsigned = 0i64;
    let mut signed = 0i64;
    for (i, &b) in h.iter().enumerate() {
        let v = if (148..156).contains(&i) { b' ' } else { b };
        unsigned += v as i64;
        signed += (v as i8) as i64;
    }
    stored == unsigned || stored == signed
}

/// Octal field: leading spaces/NUL skipped, digits until NUL/space.
fn parse_octal(f: &[u8]) -> Option<u64> {
    let mut v: u64 = 0;
    let mut seen = false;
    for &b in f {
        match b {
            b'0'..=b'7' => {
                v = v.checked_mul(8)?.checked_add((b - b'0') as u64)?;
                seen = true;
            }
            0 | b' ' if seen => break,
            0 | b' ' => {} // leading
            _ => return None,
        }
    }
    if seen {
        Some(v)
    } else {
        None
    }
}

/// Size field: octal, or base-256 binary when the top bit is set
/// (POSIX.1-2001 extension for >8 GiB members).
fn parse_size(f: &[u8]) -> Option<u64> {
    if f.first().map(|b| b & 0x80 != 0).unwrap_or(false) {
        let mut v: u64 = (f[0] & 0x7f) as u64;
        for &b in &f[1..] {
            v = v.checked_mul(256)?.checked_add(b as u64)?;
        }
        Some(v)
    } else {
        parse_octal(f)
    }
}

fn field_str(f: &[u8]) -> String {
    let end = f.iter().position(|&b| b == 0).unwrap_or(f.len());
    String::from_utf8_lossy(&f[..end]).trim_end().to_string()
}

/// Parsed 512-byte header.
struct Header {
    name: String,
    prefix: String,
    mode: u64,
    uid: u64,
    gid: u64,
    size: u64,
    mtime: u64,
    typeflag: u8,
    linkname: String,
    variant: &'static str, // "v7", "ustar", "gnu"
    uname: String,
    gname: String,
    devmajor: u64,
    devminor: u64,
    /// Old-GNU sparse map from the header (offsets 386..).
    gnu_sparse: Vec<(u64, u64)>,
    gnu_sparse_ext: bool,
    gnu_realsize: Option<u64>,
}

fn parse_header(h: &[u8]) -> Result<Header> {
    let magic = &h[257..263];
    let variant = if magic == b"ustar\0" && &h[263..265] == b"00" {
        "ustar"
    } else if magic == b"ustar " {
        "gnu"
    } else {
        "v7"
    };
    let gnu = variant == "gnu";
    let mut gnu_sparse = Vec::new();
    let mut gnu_realsize = None;
    if gnu || variant == "ustar" {
        // Old-GNU sparse map lives at 386.. regardless (ustar prefix area
        // overlaps it for non-sparse members; only trust when typeflag S
        // — handled by caller).
        for i in 0..4 {
            let off = parse_octal(&h[386 + i * 24..386 + i * 24 + 12]).unwrap_or(0);
            let len = parse_octal(&h[386 + i * 24 + 12..386 + i * 24 + 24]).unwrap_or(0);
            if len > 0 {
                gnu_sparse.push((off, len));
            }
        }
        gnu_realsize = parse_octal(&h[483..495]);
    }
    Ok(Header {
        name: field_str(&h[0..100]),
        prefix: field_str(&h[345..500]),
        mode: parse_octal(&h[100..108]).unwrap_or(0),
        uid: parse_octal(&h[108..116]).unwrap_or(0),
        gid: parse_octal(&h[116..124]).unwrap_or(0),
        size: parse_size(&h[124..136]).unwrap_or(0),
        mtime: parse_octal(&h[136..148]).unwrap_or(0),
        typeflag: h[156],
        linkname: field_str(&h[157..257]),
        variant,
        uname: field_str(&h[265..297]),
        gname: field_str(&h[297..329]),
        devmajor: parse_octal(&h[329..337]).unwrap_or(0),
        devminor: parse_octal(&h[337..345]).unwrap_or(0),
        gnu_sparse,
        gnu_sparse_ext: gnu && h[482] == b'1',
        gnu_realsize,
    })
}

/// pax `len key=value\n` records.
fn parse_pax(data: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        // `<len> <key>=<value>\n` — len covers itself.
        let sp = match data[i..].iter().position(|&b| b == b' ') {
            Some(p) => i + p,
            None => break,
        };
        let len: usize = match std::str::from_utf8(&data[i..sp])
            .ok()
            .and_then(|s| s.parse().ok())
        {
            Some(l) if l > 0 => l,
            _ => break,
        };
        let rec = match data.get(sp + 1..i + len) {
            Some(r) => r,
            None => break,
        };
        if let Some(eq) = rec.iter().position(|&b| b == b'=') {
            let key = String::from_utf8_lossy(&rec[..eq]).into_owned();
            let mut val = String::from_utf8_lossy(&rec[eq + 1..]).into_owned();
            if val.ends_with('\n') {
                val.pop();
            }
            out.push((key, val));
        }
        i += len;
    }
    out
}

/// pax-style decimal timestamp `"sec[.frac]"` → nanoseconds.
fn pax_ts(s: &str) -> Option<(u64, i64, &'static str)> {
    let (sec, frac) = s.split_once('.').unwrap_or((s, ""));
    let sec: i64 = sec.trim().parse().ok()?;
    let nanos = if frac.is_empty() {
        0
    } else {
        let mut f = frac.as_bytes().to_vec();
        f.truncate(9);
        while f.len() < 9 {
            f.push(b'0');
        }
        std::str::from_utf8(&f).ok()?.parse::<i64>().ok()?
    };
    let base = util::unix_nanos(1970, 1, 1, 0, 0, 0, 0)?;
    Some((0, base.checked_add(sec.checked_mul(1_000_000_000)?)?.checked_add(nanos)?, "pax-unix-sec"))
        .map(|(_, v, e)| (sec as u64, v, e))
}

fn unix_sec_ts(raw: u64) -> FsTimestamp {
    let base = util::unix_nanos(1970, 1, 1, 0, 0, 0, 0);
    FsTimestamp {
        value: base.and_then(|b| b.checked_add(raw as i64 * 1_000_000_000)),
        raw_value: raw,
        raw_encoding: "octal-unix-sec",
        granularity: Duration::from_secs(1),
    }
}

/// A resolved member record.
struct Member {
    path: String,
    name: String,
    kind: EntryKind,
    /// Logical (real) size.
    size: u64,
    /// Absolute offset of the 512-byte header.
    disk_offset: u64,
    /// Logical read segments (handles sparse holes).
    segs: Vec<(Segment, u64)>,
    /// Disk extents actually present (for `allocated_ranges`).
    extents: Vec<(u64, u64)>,
    status: FsEntryStatus,
    timestamps: Timestamps,
    meta: HashMap<String, String>,
}

/// A mounted TAR archive.
pub struct TarFs {
    src: Arc<dyn ByteSource>,
    opts: MountOptions,
    members: Vec<Member>,
    errors: Vec<FsError>,
    /// Offset of the first zero end-block, when reached.
    archive_end: Option<u64>,
    /// Archive bytes total.
    total_size: u64,
    variants: HashSet<&'static str>,
    sparse_count: u64,
    pax_count: u64,
}

impl TarFs {
    pub(crate) fn mount(src: Arc<dyn ByteSource>, opts: MountOptions) -> Result<Self> {
        let mut fs = TarFs {
            src,
            opts,
            members: Vec::new(),
            errors: Vec::new(),
            archive_end: None,
            total_size: 0,
            variants: HashSet::new(),
            sparse_count: 0,
            pax_count: 0,
        };
        fs.total_size = fs.src.len();
        fs.scan()?;
        // Zero members + no end marker = unrecognised image, not an
        // (empty) archive — even lenient mounts refuse garbage.
        if fs.members.is_empty() && fs.archive_end.is_none() {
            return Err(FsError::corrupt(0, "no valid tar headers found"));
        }
        Ok(fs)
    }

    fn fail(&mut self, e: FsError) -> Result<()> {
        if self.opts.strict {
            Err(e)
        } else {
            self.errors.push(e);
            Ok(())
        }
    }

    /// Header-stream scan: parse headers at 512 boundaries until the zero
    /// end-blocks, EOF, or an unrecoverable record.
    fn scan(&mut self) -> Result<()> {
        let len = self.src.len();
        let mut pos = 0u64;
        let mut longname: Option<String> = None;
        let mut longlink: Option<String> = None;
        let mut pax_next: HashMap<String, String> = HashMap::new();
        let mut pax_global: HashMap<String, String> = HashMap::new();
        let mut seen_any = false;

        loop {
            if pos + BLOCK > len {
                if seen_any {
                    // Ran out mid-stream — a truncated archive.
                    if pos < len {
                        self.fail(FsError::truncated(pos, BLOCK, len - pos))?;
                    }
                    break;
                }
                return Err(FsError::truncated(0, BLOCK, len));
            }
            let h = self.src.read_slice(pos, BLOCK as usize)?;
            if h.len() < BLOCK as usize {
                self.fail(FsError::truncated(pos, BLOCK, h.len() as u64))?;
                break;
            }
            if is_zero_block(&h) {
                self.archive_end = Some(pos);
                break;
            }
            if !checksum_ok(&h) {
                // Resynchronising inside tar data is unreliable — data
                // blocks share the 512 rhythm — so report and stop.
                self.fail(FsError::corrupt(pos, "tar header checksum mismatch"))?;
                break;
            }
            let hdr = parse_header(&h)?;
            seen_any = true;
            self.variants.insert(hdr.variant);
            let data_off = pos + BLOCK;
            let data_blocks = hdr.size.div_ceil(BLOCK);
            let data_end = data_off.saturating_add(data_blocks * BLOCK);
            if data_end > len {
                // Member data runs past the image — truncated archive.
                self.fail(FsError::truncated(
                    data_off,
                    data_blocks * BLOCK,
                    len.saturating_sub(data_off),
                ))?;
            }

            match hdr.typeflag {
                b'L' => {
                    let d = self.read_data(data_off, hdr.size, MAX_NAME)?;
                    longname = Some(
                        String::from_utf8_lossy(&d)
                            .trim_end_matches('\0')
                            .to_string(),
                    );
                }
                b'K' => {
                    let d = self.read_data(data_off, hdr.size, MAX_NAME)?;
                    longlink = Some(
                        String::from_utf8_lossy(&d)
                            .trim_end_matches('\0')
                            .to_string(),
                    );
                }
                b'g' => {
                    if let Ok(d) = self.read_data(data_off, hdr.size, MAX_PAX_DATA) {
                        for (k, v) in parse_pax(&d) {
                            pax_global.insert(k, v);
                        }
                        self.pax_count += 1;
                    }
                }
                b'x' => {
                    match self.read_data(data_off, hdr.size, MAX_PAX_DATA) {
                        Ok(d) => {
                            for (k, v) in parse_pax(&d) {
                                pax_next.insert(k, v);
                            }
                            self.pax_count += 1;
                        }
                        Err(e) => self.fail(e)?,
                    }
                }
                _ => {
                    pos = self.emit_member(
                        pos,
                        data_off,
                        data_end,
                        &hdr,
                        longname.take(),
                        longlink.take(),
                        std::mem::take(&mut pax_next),
                        &pax_global,
                    )?;
                    continue;
                }
            }
            pos = data_end;
        }
        self.mark_superseded();
        Ok(())
    }

    fn read_data(&self, off: u64, len: u64, cap: u64) -> Result<Vec<u8>> {
        if len > cap {
            return Err(FsError::corrupt(
                off,
                format!("record payload {len} exceeds cap {cap}"),
            ));
        }
        Ok(self.src.read_slice(off, len as usize)?)
    }

    /// Merge global+per-entry pax over the header fields, then emit.
    #[allow(clippy::too_many_arguments)]
    fn emit_member(
        &mut self,
        hdr_off: u64,
        data_off: u64,
        data_end: u64,
        hdr: &Header,
        longname: Option<String>,
        longlink: Option<String>,
        pax_next: HashMap<String, String>,
        pax_global: &HashMap<String, String>,
    ) -> Result<u64> {
        let src_len = self.src.len();
        let mut meta: HashMap<String, String> = HashMap::new();
        let mut pax_keys: Vec<String> = Vec::new();
        let mut pax = pax_global.clone();
        for (k, v) in pax_next {
            pax_keys.push(k.clone());
            pax.insert(k, v);
        }
        pax_keys.sort();
        if !pax_keys.is_empty() {
            meta.insert("pax_keys".into(), pax_keys.join(","));
        }

        // Name precedence: pax path > GNU longname > ustar prefix/name.
        let raw_name = pax
            .get("path")
            .cloned()
            .or(longname)
            .unwrap_or_else(|| {
                if hdr.prefix.is_empty() {
                    hdr.name.clone()
                } else {
                    format!("{}/{}", hdr.prefix, hdr.name)
                }
            });
        let linkname = pax
            .get("linkpath")
            .cloned()
            .or(longlink)
            .unwrap_or_else(|| hdr.linkname.clone());

        let mut comps = Vec::new();
        for c in raw_name.split('/') {
            match c {
                "" | "." => {}
                ".." => comps.push("__".to_string()),
                c => comps.push(util::sanitize_name(c)),
            }
        }
        let path = comps.join("/");
        if path.is_empty() {
            return Ok(data_end); // nameless record — skip entirely
        }

        // Size precedence: pax size > GNU sparse realsize > header size.
        let mut logical_size = hdr.size;
        if let Some(s) = pax.get("size") {
            if let Ok(v) = s.trim().parse::<u64>() {
                logical_size = v;
            }
        }
        let mut sparse_map: Option<Vec<(u64, u64)>> = None;
        // GNU 'S' continuation headers (isextended) sit between the main
        // header and the data, shifting `data_off` forward.
        let mut data_off = data_off;
        let mut data_end = data_end;
        if hdr.typeflag == b'S' || pax.contains_key("GNU.sparse.map") {
            self.sparse_count += 1;
            if let Some(m) = pax.get("GNU.sparse.map") {
                let map: Vec<(u64, u64)> = m
                    .split(',')
                    .filter_map(|p| p.trim().parse::<u64>().ok())
                    .collect::<Vec<u64>>()
                    .chunks_exact(2)
                    .map(|c| (c[0], c[1]))
                    .take(MAX_SPARSE)
                    .collect();
                sparse_map = Some(map);
            } else if hdr.typeflag == b'S' {
                let mut map = hdr.gnu_sparse.clone();
                let mut ext = hdr.gnu_sparse_ext;
                let mut guard = 0usize;
                while ext && guard < MAX_SPARSE {
                    let eh = match self.src.read_slice(data_off, BLOCK as usize) {
                        Ok(b) if b.len() == BLOCK as usize => b,
                        _ => break,
                    };
                    for i in 0..21 {
                        let off =
                            parse_octal(&eh[i * 24..i * 24 + 12]).unwrap_or(0);
                        let ln =
                            parse_octal(&eh[i * 24 + 12..i * 24 + 24]).unwrap_or(0);
                        if ln > 0 {
                            map.push((off, ln));
                        }
                    }
                    ext = eh[504] == b'1';
                    data_off += BLOCK;
                    data_end += BLOCK;
                    guard += 1;
                }
                sparse_map = Some(map);
            }
            if let Some(s) = pax
                .get("GNU.sparse.size")
                .or_else(|| pax.get("GNU.sparse.realsize"))
            {
                if let Ok(v) = s.trim().parse::<u64>() {
                    logical_size = v;
                }
            } else if let Some(rs) = hdr.gnu_realsize {
                logical_size = rs;
            }
        }

        // Build read segments + disk extents.
        let avail = src_len.saturating_sub(data_off);
        let stored_cap = data_end.saturating_sub(data_off).min(avail);
        let mut segs: Vec<(Segment, u64)> = Vec::new();
        let mut extents: Vec<(u64, u64)> = Vec::new();
        let mut truncated = false;
        if let Some(map) = &sparse_map {
            // Stored stream packs non-hole bytes contiguously.
            let mut disk_cursor = data_off;
            let mut covered = 0u64;
            for &(foff, flen) in map {
                if foff > covered {
                    segs.push((Segment::Zero, foff - covered));
                }
                let room = src_len.saturating_sub(disk_cursor);
                let take = flen.min(room);
                if take > 0 {
                    segs.push((Segment::Disk(disk_cursor), take));
                    extents.push((disk_cursor, take));
                }
                if take < flen {
                    truncated = true;
                }
                disk_cursor += take;
                covered = foff + flen;
            }
            if logical_size > covered {
                segs.push((Segment::Zero, logical_size - covered));
            }
            if disk_cursor > data_off + stored_cap && avail < data_end - data_off {
                truncated = true;
            }
        } else {
            let take = logical_size.min(avail);
            if take > 0 {
                segs.push((Segment::Disk(data_off), take));
                extents.push((data_off, take));
            }
            if take < logical_size {
                truncated = true;
            }
        }

        let kind = match hdr.typeflag {
            b'5' => EntryKind::Directory,
            b'2' => EntryKind::Symlink,
            b'1' => EntryKind::File, // hard link
            b'3' | b'4' | b'6' => EntryKind::Other,
            _ => EntryKind::File,
        };

        let mut status = FsEntryStatus::Live;
        if truncated {
            let recovered: u64 = extents.iter().map(|(_, l)| l).sum();
            status = FsEntryStatus::Deleted {
                recovery: RecoveryState::PartiallyOverwritten {
                    recovered_bytes: recovered.min(logical_size),
                    total_bytes: logical_size,
                },
            };
            meta.insert(
                "note".into(),
                "archive truncated: member data runs past end of image".into(),
            );
        }

        let mut ts = Timestamps::default();
        ts.modified = Some(unix_sec_ts(hdr.mtime));
        if let Some(v) = pax.get("mtime") {
            if let Some((raw, ns, enc)) = pax_ts(v) {
                ts.modified = Some(FsTimestamp {
                    value: Some(ns),
                    raw_value: raw,
                    raw_encoding: enc,
                    granularity: Duration::from_nanos(1),
                });
            }
        }
        if let Some(v) = pax.get("atime") {
            if let Some((raw, ns, enc)) = pax_ts(v) {
                ts.accessed = Some(FsTimestamp {
                    value: Some(ns),
                    raw_value: raw,
                    raw_encoding: enc,
                    granularity: Duration::from_nanos(1),
                });
            }
        }
        if let Some(v) = pax.get("ctime") {
            if let Some((raw, ns, enc)) = pax_ts(v) {
                ts.changed = Some(FsTimestamp {
                    value: Some(ns),
                    raw_value: raw,
                    raw_encoding: enc,
                    granularity: Duration::from_nanos(1),
                });
            }
        }

        meta.insert("mode".into(), format!("{:#07o}", hdr.mode));
        meta.insert("uid".into(), hdr.uid.to_string());
        meta.insert("gid".into(), hdr.gid.to_string());
        meta.insert("typeflag".into(), (hdr.typeflag as char).to_string());
        meta.insert("variant".into(), hdr.variant.to_string());
        if !hdr.uname.is_empty() {
            meta.insert("uname".into(), hdr.uname.clone());
        }
        if !hdr.gname.is_empty() {
            meta.insert("gname".into(), hdr.gname.clone());
        }
        if kind == EntryKind::Symlink || hdr.typeflag == b'1' {
            if !linkname.is_empty() {
                if kind == EntryKind::Symlink {
                    meta.insert("symlink_target".into(), linkname.clone());
                } else {
                    meta.insert("hardlink_of".into(), linkname.clone());
                }
            }
        }
        if matches!(hdr.typeflag, b'3' | b'4') {
            meta.insert("device".into(), format!("{},{}", hdr.devmajor, hdr.devminor));
        }
        if let Some(map) = &sparse_map {
            meta.insert("sparse".into(), "true".into());
            meta.insert("sparse_map".into(), map.len().to_string());
        }
        if raw_name != path {
            meta.insert("raw_name".into(), raw_name.clone());
        }

        let name = path.rsplit('/').next().unwrap_or(&path).to_string();
        self.members.push(Member {
            path,
            name,
            kind,
            size: logical_size,
            disk_offset: hdr_off,
            segs,
            extents,
            status,
            timestamps: ts,
            meta,
        });
        Ok(data_end)
    }

    /// All but the last occurrence of a path are superseded versions.
    fn mark_superseded(&mut self) {
        let offsets: Vec<u64> = self.members.iter().map(|m| m.disk_offset).collect();
        let mut last: HashMap<String, usize> = HashMap::new();
        for (i, m) in self.members.iter().enumerate() {
            last.insert(m.path.clone(), i);
        }
        for (i, m) in self.members.iter_mut().enumerate() {
            if let Some(&li) = last.get(m.path.as_str()) {
                if li != i {
                    m.meta.insert("superseded".into(), "true".into());
                    m.meta.insert(
                        "superseded_by".into(),
                        format!("{:#x}", offsets.get(li).copied().unwrap_or(0)),
                    );
                }
            }
        }
    }

    fn magic_for(&self, m: &Member) -> Option<sutram_magic::MagicVerdict> {
        if !self.opts.check_magic || m.kind != EntryKind::File || m.size == 0 {
            return None;
        }
        let mut r = self.read_member(m).ok()?;
        let mut header = vec![0u8; 4096usize.min(m.size as usize)];
        let n = r.read(&mut header).ok()?;
        header.truncate(n);
        Some(sutram_magic::check_entry_sized(&m.name, &header, m.size))
    }

    fn read_member(&self, m: &Member) -> Result<Box<dyn Read + Send>> {
        Ok(Box::new(SegmentReader::new(
            self.src.clone(),
            m.segs.clone(),
            m.size,
        )))
    }
}

fn member_entry(fs: &TarFs, idx: usize) -> FsEntry {
    let m = &fs.members[idx];
    let mut entry = FsEntry {
        path: util::join_path("/", &m.path),
        name: m.name.clone(),
        entry_id: idx as u64,
        kind: m.kind,
        size: m.size,
        disk_offset: m.disk_offset,
        allocated_ranges: m.extents.clone(),
        timestamps: m.timestamps.clone(),
        status: m.status,
        meta: m.meta.clone(),
        magic: None,
    };
    entry.magic = fs.magic_for(m);
    entry
}

struct TarWalk<'f> {
    fs: &'f TarFs,
    next: usize,
    emitted_dirs: HashSet<String>,
    root_done: bool,
    errors: std::collections::VecDeque<FsError>,
    pending: std::collections::VecDeque<FsEntry>,
}

impl Iterator for TarWalk<'_> {
    type Item = Result<FsEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(e) = self.pending.pop_front() {
                return Some(Ok(e));
            }
            if !self.root_done {
                self.root_done = true;
                self.emitted_dirs.insert(String::new());
                return Some(Ok(FsEntry {
                    path: "/".into(),
                    name: "/".into(),
                    entry_id: u64::MAX,
                    kind: EntryKind::Directory,
                    size: 0,
                    disk_offset: 0,
                    allocated_ranges: Vec::new(),
                    timestamps: Default::default(),
                    status: FsEntryStatus::Live,
                    meta: Default::default(),
                    magic: None,
                }));
            }
            if let Some(e) = self.errors.pop_front() {
                return Some(Err(e));
            }
            if self.next >= self.fs.members.len() {
                return None;
            }
            let idx = self.next;
            self.next += 1;
            let m = &self.fs.members[idx];
            let comps: Vec<&str> = m.path.split('/').collect();
            let mut acc = String::new();
            for c in &comps[..comps.len().saturating_sub(1)] {
                if !acc.is_empty() {
                    acc.push('/');
                }
                acc.push_str(c);
                if !self.emitted_dirs.contains(&acc) {
                    self.emitted_dirs.insert(acc.clone());
                    let mut meta = HashMap::new();
                    meta.insert("implied".into(), "true".into());
                    self.pending.push_back(FsEntry {
                        path: util::join_path("/", &acc),
                        name: acc.rsplit('/').next().unwrap_or(&acc).to_string(),
                        entry_id: u64::MAX,
                        kind: EntryKind::Directory,
                        size: 0,
                        disk_offset: m.disk_offset,
                        allocated_ranges: Vec::new(),
                        timestamps: Default::default(),
                        status: FsEntryStatus::Live,
                        meta,
                        magic: None,
                    });
                }
            }
            return Some(Ok(member_entry(self.fs, idx)));
        }
    }
}

impl FileSystem for TarFs {
    fn info(&self) -> FsInfo {
        let mut meta = HashMap::new();
        meta.insert("format".into(), "tar".into());
        meta.insert("entries".into(), self.members.len().to_string());
        meta.insert("archive_size".into(), self.total_size.to_string());
        meta.insert(
            "variants".into(),
            self.variants.iter().copied().collect::<Vec<_>>().join(","),
        );
        meta.insert("sparse_entries".into(), self.sparse_count.to_string());
        meta.insert("pax_records".into(), self.pax_count.to_string());
        if let Some(e) = self.archive_end {
            meta.insert("archive_end".into(), format!("{e:#x}"));
            meta.insert(
                "trailing_bytes".into(),
                self.total_size.saturating_sub(e).to_string(),
            );
        }
        let unalloc: u64 = self.unallocated_ranges().iter().map(|(_, l)| l).sum();
        FsInfo {
            fs_type: "TAR".into(),
            label: None,
            uuid: None,
            block_size: BLOCK,
            total_blocks: self.total_size / BLOCK,
            free_blocks: Some(unalloc / BLOCK),
            total_nodes: Some(self.members.len() as u64),
            meta,
        }
    }

    fn source(&self) -> Arc<dyn ByteSource> {
        self.src.clone()
    }

    fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
        Box::new(TarWalk {
            fs: self,
            next: 0,
            emitted_dirs: HashSet::new(),
            root_done: false,
            errors: self.errors.iter().map(|e| match e {
                FsError::Corrupt { offset, msg } => FsError::Corrupt {
                    offset: *offset,
                    msg: msg.clone(),
                },
                FsError::Truncated {
                    offset,
                    needed,
                    available,
                } => FsError::Truncated {
                    offset: *offset,
                    needed: *needed,
                    available: *available,
                },
                FsError::Unsupported { msg } => FsError::Unsupported { msg: msg.clone() },
                FsError::Io(e) => FsError::Io(std::io::Error::new(e.kind(), e.to_string())),
                FsError::NotFound { path } => FsError::NotFound { path: path.clone() },
                FsError::InvalidInput { msg } => FsError::InvalidInput { msg: msg.clone() },
            }).collect(),
            pending: Default::default(),
        })
    }

    fn read_file(&self, entry: &FsEntry) -> Result<Box<dyn Read + Send>> {
        match entry.kind {
            EntryKind::File | EntryKind::Other | EntryKind::Symlink => {}
            _ => {
                return Err(FsError::InvalidInput {
                    msg: format!("cannot read {}: not a file", entry.path),
                })
            }
        }
        let m = self
            .members
            .get(entry.entry_id as usize)
            .ok_or_else(|| FsError::InvalidInput {
                msg: format!("entry id {} not a member", entry.entry_id),
            })?;
        self.read_member(m)
    }

    /// Bytes after the zero end-of-archive blocks are tar slack; gaps do
    /// not otherwise exist in the 512-byte rhythm.
    fn unallocated_ranges(&self) -> Vec<(u64, u64)> {
        match self.archive_end {
            Some(end) if end + 2 * BLOCK < self.total_size => {
                vec![(end + 2 * BLOCK, self.total_size - end - 2 * BLOCK)]
            }
            _ => Vec::new(),
        }
    }
}
