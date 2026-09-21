//! ZIP forensic parser: EOCD scan, central-directory walk, local-header
//! forensics (hidden members, anomalies), store/deflate decompression.
//!
//! A ZIP is two descriptions of the same members: a *local file header*
//! (LFH) before each member's data, and the *central directory* (CD) at
//! EOF indexed by the *end of central directory* (EOCD) record. The CD is
//! the authoritative catalog — but LFHs whose members are absent from the
//! CD are exactly the "deleted/hidden" evidence this parser surfaces.
//!
//! Forensic behaviours:
//!
//! * LFHs unreferenced by the CD → `Deleted{Intact}` (or `Unknown` when
//!   the data span cannot be bounded) with `meta["hidden_entry"]=true`.
//! * LFH fields that disagree with the CD record (flags, method, CRC,
//!   sizes, name) → `meta["anomaly"]` listing the differing fields.
//! * Archive comment → `FsInfo.meta["comment"]`; member comments and
//!   extra-field inventory → `meta["comment"]` / `meta["extra_fields"]`.
//! * DOS datetime → `Timestamps::modified` (`raw_encoding`
//!   `"dos-datetime"`, 2 s granularity); `0x5455` UT and `0x000a` NTFS
//!   extra fields additionally populate `accessed`/`changed`.
//! * Self-extracting stubs: when the CD sits `delta` bytes past where the
//!   EOCD claims, all local-header offsets are rebased (`meta`
//!   `"archive_base"`).

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

use crate::reader::{InflateReader, Segment, SegmentReader};

// Signatures (little-endian u32 of the "PK\x.." bytes).
const SIG_LFH: u32 = 0x0403_4b50;
const SIG_CD: u32 = 0x0201_4b50;
const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_DD: u32 = 0x0807_4b50;
const SIG_Z64_EOCD: u32 = 0x0606_4b50;
const SIG_Z64_LOC: u32 = 0x0706_4b50;

const LFH_LEN: u64 = 30;
const CD_LEN: u64 = 46;
const EOCD_LEN: u64 = 22;
const Z64_LOC_LEN: u64 = 20;
/// EOCD lives in the last 64 KiB + 22 bytes of the file.
const EOCD_SEARCH: u64 = 64 * 1024 + EOCD_LEN;
/// Flag bit 3: sizes/CRC live in a data descriptor after the data.
const FLAG_DATA_DESC: u16 = 0x0008;
/// Flag bit 0: member is encrypted.
const FLAG_ENCRYPTED: u16 = 0x0001;
/// Flag bit 11: name/comment are UTF-8.
const FLAG_UTF8: u16 = 0x0800;
/// Scan window for local-header / signature searches.
const SCAN_WIN: u64 = 64 * 1024;

fn r16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn r32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// The parser entry point — stateless.
pub struct ZipParser;

impl FsParser for ZipParser {
    fn name(&self) -> &'static str {
        "zip"
    }

    fn detect(&self, src: &dyn ByteSource) -> DetectConfidence {
        match find_eocd(src) {
            Ok(Some(_)) => return DetectConfidence::Certain,
            _ => {}
        }
        // No EOCD: a parseable LFH at offset 0 is still strong evidence
        // (streaming-written zips, truncated archives).
        match parse_lfh(src, 0) {
            Ok(Some(_)) => return DetectConfidence::High,
            _ => {}
        }
        // Self-extracting stub? Probe the first 64 KiB for an LFH.
        if let Ok(Some(_)) = scan_next_lfh(src, 0, src.len().min(EOCD_SEARCH)) {
            return DetectConfidence::Medium;
        }
        DetectConfidence::None
    }

    fn mount_with(
        &self,
        src: Arc<dyn ByteSource>,
        opts: &MountOptions,
    ) -> Result<Box<dyn FileSystem>> {
        Ok(Box::new(ZipFs::mount(src, opts.clone())?))
    }
}

/// Parsed EOCD (+ optional ZIP64 records) summary.
struct Eocd {
    /// Absolute offset of the EOCD record.
    eocd_off: u64,
    /// Central-directory offset as recorded.
    cd_off: u64,
    /// Central-directory byte size.
    cd_size: u64,
    /// Total member count claimed.
    entries: u64,
    /// Archive comment (may be empty).
    comment: Vec<u8>,
    /// True when a ZIP64 EOCD locator/record supplied the values.
    zip64: bool,
    /// Multi-disk indicators (disk numbers / per-disk counts).
    multi_disk: bool,
}

/// Locate a well-formed EOCD: scan the tail backwards for the signature
/// and require `comment_len` to exactly cover the remaining bytes.
fn find_eocd(src: &dyn ByteSource) -> Result<Option<Eocd>> {
    let len = src.len();
    if len < EOCD_LEN {
        return Ok(None);
    }
    let start = len.saturating_sub(EOCD_SEARCH);
    let win = src.read_slice(start, (len - start) as usize)?;
    if win.len() < EOCD_LEN as usize {
        return Ok(None);
    }
    // Walk candidates from the tail: the last exact-length match wins.
    for i in (0..=win.len() - 4).rev() {
        if r32(&win, i) != SIG_EOCD {
            continue;
        }
        let rec = &win[i..];
        if rec.len() < EOCD_LEN as usize {
            break;
        }
        let comment_len = r16(rec, 20) as usize;
        if EOCD_LEN as usize + comment_len != rec.len() {
            continue; // not the real EOCD (or trailing junk follows)
        }
        let mut e = Eocd {
            eocd_off: start + i as u64,
            cd_off: r32(rec, 16) as u64,
            cd_size: r32(rec, 12) as u64,
            entries: r16(rec, 10) as u64,
            comment: rec[EOCD_LEN as usize..].to_vec(),
            zip64: false,
            multi_disk: r16(rec, 4) != 0
                || r16(rec, 6) != 0
                || r16(rec, 8) != r16(rec, 10),
        };
        // ZIP64: any saturated field, or a locator parked before the EOCD.
        let saturated = e.cd_off == u32::MAX as u64
            || e.cd_size == u32::MAX as u64
            || e.entries == u16::MAX as u64;
        if (saturated || e.eocd_off >= Z64_LOC_LEN)
            && read_zip64_eocd(src, &mut e).unwrap_or(false)
        {
            e.zip64 = true;
        }
        return Ok(Some(e));
    }
    Ok(None)
}

/// If a ZIP64 locator precedes the EOCD, read the ZIP64 EOCD record and
/// patch `e`. Returns `true` on success. Failures are non-fatal.
fn read_zip64_eocd(src: &dyn ByteSource, e: &mut Eocd) -> Result<bool> {
    let loc_off = match e.eocd_off.checked_sub(Z64_LOC_LEN) {
        Some(o) => o,
        None => return Ok(false),
    };
    let loc = src.read_slice(loc_off, Z64_LOC_LEN as usize)?;
    if loc.len() < Z64_LOC_LEN as usize || r32(&loc, 0) != SIG_Z64_LOC {
        return Ok(false);
    }
    let z64_off = u64::from_le_bytes(loc[8..16].try_into().unwrap_or([0; 8]));
    let rec = src.read_slice(z64_off, 56)?;
    if rec.len() < 56 || r32(&rec, 0) != SIG_Z64_EOCD {
        return Ok(false);
    }
    e.entries = u64::from_le_bytes(rec[32..40].try_into().unwrap_or([0; 8]));
    e.cd_size = u64::from_le_bytes(rec[40..48].try_into().unwrap_or([0; 8]));
    e.cd_off = u64::from_le_bytes(rec[48..56].try_into().unwrap_or([0; 8]));
    e.multi_disk |= r32(&rec, 16) != 0 || r32(&rec, 20) != 0;
    Ok(true)
}

/// Parsed local file header.
struct LocalHdr {
    flags: u16,
    method: u16,
    mtime: u16,
    mdate: u16,
    crc32: u32,
    comp_size: u32,
    uncomp_size: u32,
    name: Vec<u8>,
    extra: Vec<u8>,
    /// Absolute offset where member data starts.
    data_off: u64,
}

/// Parse the LFH at `off`. `Ok(None)` = signature mismatch (not a LFH);
/// `Err` = truncated/implausible.
fn parse_lfh(src: &dyn ByteSource, off: u64) -> Result<Option<LocalHdr>> {
    let h = src.read_slice(off, LFH_LEN as usize)?;
    if h.len() < LFH_LEN as usize {
        return Ok(None); // beyond EOF — nothing here
    }
    if r32(&h, 0) != SIG_LFH {
        return Ok(None);
    }
    let name_len = r16(&h, 26) as u64;
    let extra_len = r16(&h, 28) as u64;
    let name = src.read_slice(off + LFH_LEN, name_len as usize)?;
    if name.len() < name_len as usize {
        return Err(FsError::truncated(off, LFH_LEN + name_len, h.len() as u64));
    }
    let extra = src.read_slice(off + LFH_LEN + name_len, extra_len as usize)?;
    Ok(Some(LocalHdr {
        flags: r16(&h, 6),
        method: r16(&h, 8),
        mtime: r16(&h, 10),
        mdate: r16(&h, 12),
        crc32: r32(&h, 14),
        comp_size: r32(&h, 18),
        uncomp_size: r32(&h, 22),
        name,
        extra,
        data_off: off + LFH_LEN + name_len + extra_len,
    }))
}

/// Scan `[pos, end)` for the next plausible LFH signature. Cheap windowed
/// probe used by `detect` — mount does its own richer scan.
fn scan_next_lfh(src: &dyn ByteSource, pos: u64, end: u64) -> Result<Option<u64>> {
    let mut p = pos;
    while p + 4 <= end {
        let want = (end - p).min(SCAN_WIN) as usize;
        let win = src.read_slice(p, want)?;
        if win.len() < 4 {
            break;
        }
        for i in 0..win.len() - 3 {
            if r32(&win, i) == SIG_LFH {
                return Ok(Some(p + i as u64));
            }
        }
        p += win.len() as u64 - 3;
    }
    Ok(None)
}

/// When the flag says "data descriptor follows", consume it past the
/// member data. With signature: `PK\x07\x08` + 12/24 bytes. Without:
/// 12 bytes (16-bit-era) — detected by checking what follows for a known
/// signature. Best-effort; the cursor only needs to land on the next
/// record.
fn skip_data_descriptor(src: &dyn ByteSource, data_end: u64, zip64: bool) -> u64 {
    let sig_len = 4u64;
    let body = if zip64 { 24u64 } else { 12u64 };
    if let Ok(tail) = src.read_slice(data_end, (sig_len + body) as usize) {
        if tail.len() >= (sig_len + body) as usize && r32(&tail, 0) == SIG_DD {
            return data_end + sig_len + body;
        }
    }
    // No signature: the DD is 12 raw bytes iff a known record follows them.
    if let Ok(tail) = src.read_slice(data_end + 12, 4) {
        if tail.len() == 4 {
            let s = r32(&tail, 0);
            if s == SIG_LFH || s == SIG_CD || s == SIG_EOCD {
                return data_end + 12;
            }
        }
    }
    data_end
}

/// DOS date+time → `FsTimestamp` (modified; 2 s granularity).
fn dos_timestamp(date: u16, time: u16) -> FsTimestamp {
    let value = if date == 0 {
        None
    } else {
        util::unix_nanos(
            1980 + (date as i64 >> 9),
            ((date >> 5) & 0x0f) as i64,
            (date & 0x1f) as i64,
            (time >> 11) as i64,
            ((time >> 5) & 0x3f) as i64,
            ((time & 0x1f) * 2) as i64,
            0,
        )
    };
    FsTimestamp {
        value,
        raw_value: ((date as u64) << 16) | time as u64,
        raw_encoding: "dos-datetime",
        granularity: Duration::from_secs(2),
    }
}

fn unix_ts(sec: u32) -> Option<i64> {
    util::unix_nanos(1970, 1, 1, 0, 0, 0, 0)?.checked_add(sec as i64 * 1_000_000_000)
}

fn filetime_ns(v: u64) -> Option<i64> {
    // 100-ns ticks since 1601-01-01 → ns since 1970.
    let ticks = i64::try_from(v).ok()?.checked_sub(11_644_473_600_000_000)?;
    ticks.checked_mul(100)
}

/// Decode a member name: UTF-8 when flag 11 set, else CP437.
fn decode_name(raw: &[u8], utf8: bool) -> String {
    if utf8 {
        return String::from_utf8_lossy(raw).into_owned();
    }
    raw.iter()
        .map(|&b| if b < 0x80 { b as char } else { cp437_upper(b) })
        .collect()
}

/// CP437 upper half (0x80..=0xFF).
fn cp437_upper(b: u8) -> char {
    const T: &[char; 128] = &[
        'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', 'É', 'æ',
        'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', 'á', 'í', 'ó', 'ú',
        'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', '░', '▒', '▓', '│', '┤', '╡',
        '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐', '└', '┴', '┬', '├', '─', '┼', '╞', '╟',
        '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧', '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘',
        '┌', '█', '▄', '▌', '▐', '▀', 'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ',
        '∞', 'φ', 'ε', '∩', '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²',
        '■', ' ',
    ];
    T[(b - 0x80) as usize]
}

/// Turn a raw member name into a safe relative path (no leading `/`).
/// `".."` components (zip-slip attempts) become `"__"`; the verbatim name
/// is preserved separately in `meta["raw_name"]`.
fn member_path(raw: &[u8], utf8: bool) -> (String, bool /*is_dir*/) {
    let decoded = decode_name(raw, utf8);
    let is_dir = decoded.ends_with('/');
    let mut comps = Vec::new();
    for c in decoded.split('/') {
        match c {
            "" | "." => {}
            ".." => comps.push("__".to_string()),
            c => comps.push(util::sanitize_name(c)),
        }
    }
    (comps.join("/"), is_dir)
}

/// Extra-field handling: inventory tags into `meta["extra_fields"]`,
/// resolve ZIP64 sizes, and lift UT/NTFS timestamps into `ts`.
struct ExtraOut {
    uncomp_size: Option<u64>,
    comp_size: Option<u64>,
    local_off: Option<u64>,
    accessed: Option<FsTimestamp>,
    changed: Option<FsTimestamp>,
    meta: Vec<(String, String)>,
    tags: Vec<u16>,
}

fn parse_extra(
    extra: &[u8],
    need_uncomp: bool,
    need_comp: bool,
    need_off: bool,
) -> ExtraOut {
    let mut out = ExtraOut {
        uncomp_size: None,
        comp_size: None,
        local_off: None,
        accessed: None,
        changed: None,
        meta: Vec::new(),
        tags: Vec::new(),
    };
    let mut i = 0usize;
    while i + 4 <= extra.len() {
        let tag = r16(extra, i);
        let len = r16(extra, i + 2) as usize;
        i += 4;
        let f = match extra.get(i..i + len) {
            Some(f) => f,
            None => break, // truncated field — stop, keep what we have
        };
        out.tags.push(tag);
        match tag {
            0x0001 => {
                // ZIP64: fields appear only for saturated values, in this
                // fixed order.
                let mut j = 0usize;
                if need_uncomp && j + 8 <= f.len() {
                    out.uncomp_size = Some(u64::from_le_bytes(
                        f[j..j + 8].try_into().unwrap_or([0; 8]),
                    ));
                    j += 8;
                }
                if need_comp && j + 8 <= f.len() {
                    out.comp_size = Some(u64::from_le_bytes(
                        f[j..j + 8].try_into().unwrap_or([0; 8]),
                    ));
                    j += 8;
                }
                if need_off && j + 8 <= f.len() {
                    out.local_off = Some(u64::from_le_bytes(
                        f[j..j + 8].try_into().unwrap_or([0; 8]),
                    ));
                }
            }
            0x5455 => {
                // Extended timestamp: flags byte then present u32 unix secs.
                let flags = f.first().copied().unwrap_or(0);
                let mut j = 1usize;
                for (bit, _name) in [(0x01u8, "mtime"), (0x02, "atime"), (0x04, "ctime")] {
                    if flags & bit != 0 && j + 4 <= f.len() {
                        let sec = r32(f, j);
                        j += 4;
                        let ts = FsTimestamp {
                            value: unix_ts(sec),
                            raw_value: sec as u64,
                            raw_encoding: "unix-sec",
                            granularity: Duration::from_secs(1),
                        };
                        match bit {
                            0x02 => out.accessed = Some(ts),
                            0x04 => out.changed = Some(ts),
                            _ => out.meta.push(("ut_mtime_unix".into(), sec.to_string())),
                        }
                    }
                }
            }
            0x000a => {
                // NTFS: u32 reserved then tagged attrs; tag 1 = three FILETIMEs.
                let mut j = 4usize;
                while j + 4 <= f.len() {
                    let atag = r16(f, j);
                    let alen = r16(f, j + 2) as usize;
                    j += 4;
                    let a = match f.get(j..j + alen) {
                        Some(a) => a,
                        None => break,
                    };
                    if atag == 0x0001 && a.len() >= 24 {
                        let m = u64::from_le_bytes(a[0..8].try_into().unwrap_or([0; 8]));
                        let ac = u64::from_le_bytes(a[8..16].try_into().unwrap_or([0; 8]));
                        let c = u64::from_le_bytes(a[16..24].try_into().unwrap_or([0; 8]));
                        let ts = |v: u64| FsTimestamp {
                            value: filetime_ns(v),
                            raw_value: v,
                            raw_encoding: "ntfs-filetime",
                            granularity: Duration::from_nanos(100),
                        };
                        out.meta.push(("ntfs_mtime_filetime".into(), format!("{m:#x}")));
                        out.accessed = Some(ts(ac));
                        out.changed = Some(ts(c));
                    }
                    j += alen;
                }
            }
            0x7875 => {
                // Unix uid/gid: ver(1) uid_len(1) uid gid_len(1) gid.
                if f.len() >= 2 {
                    let ul = f[1] as usize;
                    if 2 + ul < f.len() {
                        let uid = f[2..2 + ul]
                            .iter()
                            .fold(0u64, |a, &b| (a << 8) | b as u64);
                        let gl = f[2 + ul] as usize;
                        let gid = f
                            .get(3 + ul..3 + ul + gl)
                            .unwrap_or(&[])
                            .iter()
                            .fold(0u64, |a, &b| (a << 8) | b as u64);
                        out.meta.push(("uid".into(), uid.to_string()));
                        out.meta.push(("gid".into(), gid.to_string()));
                    }
                }
            }
            _ => {}
        }
        i += len;
    }
    out
}

/// A resolved member ready to emit.
struct Member {
    /// Path relative to root (sanitised, `/`-joined, no leading slash).
    path: String,
    /// Basename.
    name: String,
    kind: EntryKind,
    size: u64,
    method: u16,
    flags: u16,
    /// Declared compressed size (metadata truth).
    comp_size: u64,
    /// Where the compressed/stored data begins.
    data_off: Option<u64>,
    /// Bytes of data actually present on the source.
    data_avail: u64,
    /// Record offset (CD record for live members, LFH for hidden ones).
    disk_offset: u64,
    /// The LFH's offset, when located (for provenance/unallocated calc).
    lfh_off: Option<u64>,
    /// Span `[lfh_off, end)` covering header+data+descriptor.
    span: Option<(u64, u64)>,
    status: FsEntryStatus,
    timestamps: Timestamps,
    meta: HashMap<String, String>,
}

/// A mounted ZIP archive.
pub struct ZipFs {
    src: Arc<dyn ByteSource>,
    opts: MountOptions,
    members: Vec<Member>,
    /// Mount-phase errors to surface as walk records.
    errors: Vec<FsError>,
    /// `[start,end)` of the central directory, when found.
    cd_region: Option<(u64, u64)>,
    eocd_region: Option<(u64, u64)>,
    comment: Option<String>,
    zip64: bool,
    /// Self-extracting stub size (delta applied to member offsets).
    base_delta: u64,
    hidden_count: u64,
    total_size: u64,
}

impl ZipFs {
    pub(crate) fn mount(src: Arc<dyn ByteSource>, opts: MountOptions) -> Result<Self> {
        let len = src.len();
        let mut fs = ZipFs {
            src,
            opts,
            members: Vec::new(),
            errors: Vec::new(),
            cd_region: None,
            eocd_region: None,
            comment: None,
            zip64: false,
            base_delta: 0,
            hidden_count: 0,
            total_size: len,
        };
        match find_eocd(fs.src.as_ref()) {
            Ok(Some(e)) => {
                fs.zip64 = e.zip64;
                fs.comment = Some(String::from_utf8_lossy(&e.comment).into_owned());
                fs.eocd_region = Some((
                    e.eocd_off,
                    len - e.eocd_off,
                ));
                if e.multi_disk {
                    fs.errors.push(FsError::unsupported(
                        "multi-disk archive: central directory may be on another disk",
                    ));
                }
                if let Err(err) = fs.walk_central(&e) {
                    if fs.opts.strict {
                        return Err(err);
                    }
                    fs.errors.push(err);
                }
            }
            Ok(None) => {
                if fs.opts.strict {
                    return Err(FsError::corrupt(
                        len.saturating_sub(1),
                        "no end-of-central-directory record found",
                    ));
                }
                fs.errors.push(FsError::corrupt(
                    len.saturating_sub(1),
                    "no end-of-central-directory record; cataloguing local headers",
                ));
            }
            Err(err) => {
                if fs.opts.strict {
                    return Err(err);
                }
                fs.errors.push(err);
            }
        }
        fs.scan_hidden();
        if fs.members.is_empty() && fs.cd_region.is_none() {
            return Err(FsError::corrupt(
                0,
                "not a ZIP archive: no EOCD and no local file headers",
            ));
        }
        Ok(fs)
    }

    /// Parse the central directory described by `e` into `self.members`.
    fn walk_central(&mut self, e: &Eocd) -> Result<()> {
        let len = self.src.len();
        // Self-extracting stub: the CD may sit at `eocd_off - cd_size`
        // rather than the recorded offset. Pick whichever starts with the
        // CD signature and rebase local offsets by the delta.
        let recorded = e.cd_off;
        let adjusted = e.eocd_off.saturating_sub(e.cd_size);
        let mut cd_start = recorded;
        let sig_at = |off: u64| -> bool {
            self.src
                .read_slice(off, 4)
                .map(|b| b.len() == 4 && r32(&b, 0) == SIG_CD)
                .unwrap_or(false)
        };
        if !sig_at(cd_start) && adjusted != recorded && sig_at(adjusted) {
            cd_start = adjusted;
        }
        self.base_delta = cd_start.saturating_sub(recorded);
        let cd_end = e
            .eocd_off
            .min(cd_start.saturating_add(e.cd_size))
            .min(len);
        if !sig_at(cd_start) && e.cd_size > 0 {
            return Err(FsError::corrupt(
                cd_start,
                "central directory does not start with a PK\\x01\\x02 signature",
            ));
        }
        self.cd_region = Some((cd_start, cd_end.saturating_sub(cd_start)));
        // Bound the record count by the directory size (46 B each minimum)
        // — the EOCD's own count is untrusted.
        let max_entries = (e.cd_size / CD_LEN).min(e.entries.max(1) + 16).max(64);
        let mut pos = cd_start;
        let mut n = 0u64;
        while pos + CD_LEN <= cd_end && n < max_entries {
            let h = self.src.read_slice(pos, CD_LEN as usize)?;
            if h.len() < CD_LEN as usize {
                return Err(FsError::truncated(pos, CD_LEN, h.len() as u64));
            }
            if r32(&h, 0) != SIG_CD {
                if n == 0 {
                    return Err(FsError::corrupt(pos, "bad central-directory signature"));
                }
                if n < e.entries {
                    // Claimed members remain unaccounted for — record it.
                    return Err(FsError::corrupt(
                        pos,
                        format!(
                            "central directory ends early: {n} of {} entries parsed",
                            e.entries
                        ),
                    ));
                }
                break; // all claimed entries seen — trailing slack is fine
            }
            let name_len = r16(&h, 28) as u64;
            let extra_len = r16(&h, 30) as u64;
            let comment_len = r16(&h, 32) as u64;
            let rec_len = CD_LEN + name_len + extra_len + comment_len;
            if pos + rec_len > len {
                return Err(FsError::truncated(pos, rec_len, len - pos));
            }
            self.emit_central_record(pos, &h, name_len, extra_len, comment_len)?;
            pos += rec_len;
            n += 1;
        }
        Ok(())
    }

    /// Decode one CD record and its LFH twin into `self.members`.
    fn emit_central_record(
        &mut self,
        pos: u64,
        h: &[u8],
        name_len: u64,
        extra_len: u64,
        comment_len: u64,
    ) -> Result<()> {
        let len = self.src.len();
        let name_raw = self.src.read_slice(pos + CD_LEN, name_len as usize)?;
        let extra_raw = self
            .src
            .read_slice(pos + CD_LEN + name_len, extra_len as usize)?;
        let comment_raw = self
            .src
            .read_slice(pos + CD_LEN + name_len + extra_len, comment_len as usize)?;

        let flags = r16(h, 8);
        let method = r16(h, 10);
        let mtime = r16(h, 12);
        let mdate = r16(h, 14);
        let crc32 = r32(h, 16);
        let mut comp_size = r32(h, 20) as u64;
        let mut uncomp_size = r32(h, 24) as u64;
        let mut local_off = r32(h, 42) as u64;
        let ext_attrs = r32(h, 38);
        let made_by = r16(h, 4);

        let x = parse_extra(
            &extra_raw,
            uncomp_size == u32::MAX as u64,
            comp_size == u32::MAX as u64,
            local_off == u32::MAX as u64,
        );
        if let Some(v) = x.uncomp_size {
            uncomp_size = v;
        }
        if let Some(v) = x.comp_size {
            comp_size = v;
        }
        if let Some(v) = x.local_off {
            local_off = v;
        }
        local_off = local_off.saturating_add(self.base_delta);

        let (path, mut is_dir) = member_path(&name_raw, flags & FLAG_UTF8 != 0);
        let mut meta: HashMap<String, String> = HashMap::new();
        let mut ts = Timestamps::default();
        ts.modified = Some(dos_timestamp(mdate, mtime));
        if x.accessed.is_some() {
            ts.accessed = x.accessed;
        }
        if x.changed.is_some() {
            ts.changed = x.changed;
        }
        for (k, v) in x.meta {
            meta.insert(k, v);
        }
        if !x.tags.is_empty() {
            meta.insert(
                "extra_fields".into(),
                x.tags.iter().map(|t| format!("{t:#06x}")).collect::<Vec<_>>().join(","),
            );
        }

        meta.insert("compression_method".into(), method_name(method).into());
        meta.insert("flags".into(), format!("{flags:#06x}"));
        meta.insert("crc32".into(), format!("{crc32:#010x}"));
        meta.insert("compressed_size".into(), comp_size.to_string());
        meta.insert("version_needed".into(), r16(h, 6).to_string());
        meta.insert(
            "made_by".into(),
            format!("{} (0x{:02x})", host_os_name(made_by >> 8), made_by >> 8),
        );
        if ext_attrs != 0 {
            meta.insert("external_attrs".into(), format!("{ext_attrs:#010x}"));
        }
        if flags & FLAG_ENCRYPTED != 0 {
            meta.insert("encrypted".into(), "true".into());
        }
        if flags & FLAG_UTF8 != 0 {
            meta.insert("utf8_name".into(), "true".into());
        }
        if flags & FLAG_DATA_DESC != 0 {
            meta.insert("data_descriptor".into(), "true".into());
        }
        if !comment_raw.is_empty() {
            meta.insert(
                "comment".into(),
                String::from_utf8_lossy(&comment_raw).into_owned(),
            );
        }
        if name_raw != path.as_bytes() {
            meta.insert("raw_name".into(), String::from_utf8_lossy(&name_raw).into_owned());
        }

        // Unix mode rides the high 16 bits of external attributes when the
        // archiver ran on Unix (made-by host 3).
        let mut kind = if is_dir {
            EntryKind::Directory
        } else {
            EntryKind::File
        };
        if made_by >> 8 == 3 {
            let mode = ext_attrs >> 16;
            match mode & 0o170000 {
                0o040000 => {
                    is_dir = true;
                    kind = EntryKind::Directory;
                }
                0o120000 => kind = EntryKind::Symlink,
                0o100000 | 0 => {}
                m => {
                    if m != 0 {
                        kind = EntryKind::Other;
                    }
                }
            }
            if mode != 0 {
                meta.insert("mode".into(), format!("{mode:#07o}"));
            }
        }
        let _ = is_dir;

        // Resolve the local header → data offset + anomaly comparison.
        let mut data_off = None;
        let mut data_avail = 0u64;
        let mut span = None;
        let mut anomalies: Vec<&'static str> = Vec::new();
        match parse_lfh(self.src.as_ref(), local_off) {
            Ok(Some(l)) => {
                if l.flags != flags {
                    anomalies.push("flags");
                }
                if l.method != method {
                    anomalies.push("method");
                }
                // Bit 3 legitimately zeroes the LFH's crc/sizes — that is
                // not an anomaly.
                if flags & FLAG_DATA_DESC == 0 {
                    if l.crc32 != crc32 {
                        anomalies.push("crc32");
                    }
                    if l.comp_size as u64 != comp_size {
                        anomalies.push("compressed_size");
                    }
                    if l.uncomp_size as u64 != uncomp_size {
                        anomalies.push("uncompressed_size");
                    }
                } else if l.crc32 != 0 && l.crc32 != crc32 {
                    anomalies.push("crc32");
                }
                if l.name != name_raw {
                    anomalies.push("name");
                }
                if !l.extra.is_empty() && l.extra != extra_raw {
                    // Extra-field drift is common and usually benign;
                    // report it separately from field corruption.
                    meta.insert("extra_differs".into(), "true".into());
                }
                let data_end = l.data_off.saturating_add(comp_size.min(len));
                let end = if flags & FLAG_DATA_DESC != 0 {
                    let zip64 = comp_size > u32::MAX as u64
                        || uncomp_size > u32::MAX as u64;
                    skip_data_descriptor(self.src.as_ref(), data_end, zip64)
                } else {
                    data_end
                };
                data_off = Some(l.data_off);
                // Clamp readable data at EOF and at the central directory
                // (a member preceding the CD cannot own catalog bytes).
                let mut hard_end = len;
                if let Some((cs, _)) = self.cd_region {
                    if local_off < cs {
                        hard_end = hard_end.min(cs);
                    }
                }
                data_avail = comp_size.min(hard_end.saturating_sub(l.data_off));
                span = Some((local_off, end.min(hard_end)));
            }
            Ok(None) => {
                anomalies.push("local_header_missing");
            }
            Err(_) => {
                anomalies.push("local_header_corrupt");
            }
        }
        if !anomalies.is_empty() {
            meta.insert("anomaly".into(), anomalies.join(","));
        }
        // Truncation: declared data runs past EOF *or* into the central
        // directory that was appended after the member stream was cut.
        if comp_size > 0 && data_off.is_some() {
            let claimed_end = data_off.unwrap_or(0).saturating_add(comp_size);
            let over_eof = claimed_end > len;
            let over_cd = self
                .cd_region
                .map(|(cs, _)| local_off < cs && claimed_end > cs)
                .unwrap_or(false);
            if over_eof || over_cd {
                meta.insert("data_truncated".into(), "true".into());
            }
        }

        let (name, _) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
        self.members.push(Member {
            name: if name.is_empty() { path.clone() } else { name.to_string() },
            path,
            kind,
            size: uncomp_size,
            method,
            flags,
            comp_size,
            data_off,
            data_avail,
            disk_offset: pos,
            lfh_off: data_off.map(|_| local_off),
            span,
            status: FsEntryStatus::Live,
            timestamps: ts,
            meta,
        });
        Ok(())
    }

    /// Sequential scan for LFHs the central directory never referenced —
    /// "deleted"/hidden members. Runs over `[0, cd_start)` (or the whole
    /// source when there is no EOCD).
    fn scan_hidden(&mut self) {
        let limit = self.cd_region.map(|(s, _)| s).unwrap_or(self.src.len());
        let referenced: HashSet<u64> =
            self.members.iter().filter_map(|m| m.lfh_off).collect();
        // Compressed sizes keyed by LFH offset let the scan skip live
        // member data without rescanning it.
        let known: HashMap<u64, u64> = self
            .members
            .iter()
            .filter_map(|m| m.lfh_off.map(|o| (o, m.comp_size)))
            .collect();
        let dd_flag: HashMap<u64, bool> = self
            .members
            .iter()
            .filter_map(|m| m.lfh_off.map(|o| (o, m.flags & FLAG_DATA_DESC != 0)))
            .collect();

        let mut pos = 0u64;
        let mut found: HashSet<u64> = HashSet::new();
        while pos + 4 <= limit {
            let want = (limit - pos).min(SCAN_WIN) as usize;
            let win = match self.src.read_slice(pos, want) {
                Ok(w) => w,
                Err(e) => {
                    self.errors.push(FsError::Io(e));
                    break;
                }
            };
            if win.len() < 4 {
                break;
            }
            let mut jumped = false;
            let mut i = 0usize;
            while i + 4 <= win.len() {
                if r32(&win, i) != SIG_LFH {
                    i += 1;
                    continue;
                }
                let abs = pos + i as u64;
                match parse_lfh(self.src.as_ref(), abs) {
                    Ok(Some(l)) if !l.name.is_empty() => {
                        // Advance past this member.
                        let (csize, has_dd) = if referenced.contains(&abs) {
                            (
                                known.get(&abs).copied().unwrap_or(l.comp_size as u64),
                                dd_flag.get(&abs).copied().unwrap_or(false),
                            )
                        } else {
                            self.add_hidden(abs, &l);
                            (
                                l.comp_size as u64,
                                l.flags & FLAG_DATA_DESC != 0,
                            )
                        };
                        found.insert(abs);
                        let mut end = l.data_off.saturating_add(csize);
                        if has_dd {
                            end = skip_data_descriptor(self.src.as_ref(), end, false);
                        }
                        // Jump the cursor past the member (reload window).
                        pos = end.max(abs + LFH_LEN);
                        jumped = true;
                        break;
                    }
                    _ => {
                        i += 4;
                    }
                }
            }
            if !jumped {
                pos += win.len() as u64 - 3;
            }
        }
        let _ = found;
    }

    /// Build a hidden-member record for an unreferenced LFH.
    fn add_hidden(&mut self, off: u64, l: &LocalHdr) {
        let len = self.src.len();
        let (path, is_dir) = member_path(&l.name, l.flags & FLAG_UTF8 != 0);
        let mut meta: HashMap<String, String> = HashMap::new();
        meta.insert("hidden_entry".into(), "true".into());
        meta.insert(
            "note".into(),
            "local file header not referenced by the central directory".into(),
        );
        meta.insert("compression_method".into(), method_name(l.method).into());
        meta.insert("flags".into(), format!("{:#06x}", l.flags));
        meta.insert("crc32".into(), format!("{:#010x}", l.crc32));
        meta.insert("raw_name".into(), String::from_utf8_lossy(&l.name).into_owned());
        if l.flags & FLAG_ENCRYPTED != 0 {
            meta.insert("encrypted".into(), "true".into());
        }
        let x = parse_extra(&l.extra, false, false, false);
        if !x.tags.is_empty() {
            meta.insert(
                "extra_fields".into(),
                x.tags.iter().map(|t| format!("{t:#06x}")).collect::<Vec<_>>().join(","),
            );
        }
        let mut ts = Timestamps::default();
        ts.modified = Some(dos_timestamp(l.mdate, l.mtime));

        // Data span: trust the LFH's compressed size; when a data
        // descriptor holds it (bit 3, size 0), bound by the next
        // signature instead.
        let mut comp_size = l.comp_size as u64;
        let mut bounded = true;
        let span_end;
        if l.flags & FLAG_DATA_DESC != 0 && comp_size == 0 {
            match self.bound_hidden_data(l.data_off) {
                Some((cs, dd_end)) => {
                    comp_size = cs;
                    span_end = dd_end;
                    meta.insert(
                        "size_note".into(),
                        "recovered from trailing data descriptor".into(),
                    );
                }
                None => {
                    bounded = false;
                    span_end = l.data_off;
                    meta.insert(
                        "size_note".into(),
                        "data descriptor flag set; size unrecoverable, span unbounded".into(),
                    );
                }
            }
        } else {
            span_end = l.data_off.saturating_add(comp_size.min(len - l.data_off.min(len)));
        }
        self.finish_hidden(off, l, path, is_dir, comp_size, span_end, bounded, meta, ts);
    }

    /// For bit-3 hidden members with zeroed sizes: find the data
    /// descriptor signature ahead and recover the compressed size.
    /// Returns `(comp_size, span_end)`.
    fn bound_hidden_data(&self, data_off: u64) -> Option<(u64, u64)> {
        let limit = self.src.len().min(data_off.saturating_add(64 * 1024 * 1024));
        let mut pos = data_off;
        while pos + 8 <= limit {
            let want = (limit - pos).min(SCAN_WIN) as usize;
            let win = self.src.read_slice(pos, want).ok()?;
            if win.len() < 8 {
                break;
            }
            for i in 0..win.len() - 3 {
                let s = r32(&win, i);
                if s == SIG_DD && i + 16 <= win.len() {
                    let csize = r32(&win, i + 8) as u64;
                    // Sanity: the descriptor must agree with where it sits.
                    if i as u64 >= csize {
                        return Some((csize, pos + i as u64 + 16));
                    }
                } else if s == SIG_LFH || s == SIG_CD || s == SIG_EOCD {
                    // Hit the next record without a descriptor — bound here.
                    return Some((i as u64, pos + i as u64));
                }
            }
            pos += win.len() as u64 - 3;
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_hidden(
        &mut self,
        off: u64,
        l: &LocalHdr,
        path: String,
        is_dir: bool,
        comp_size: u64,
        span_end: u64,
        bounded: bool,
        mut meta: HashMap<String, String>,
        ts: Timestamps,
    ) {
        let len = self.src.len();
        let avail = comp_size.min(len.saturating_sub(l.data_off));
        if avail < comp_size {
            meta.insert("data_truncated".into(), "true".into());
        }
        let recovery = if !bounded {
            RecoveryState::Unknown
        } else if avail < comp_size {
            RecoveryState::PartiallyOverwritten {
                recovered_bytes: avail,
                total_bytes: comp_size,
            }
        } else {
            RecoveryState::Intact
        };
        let kind = if is_dir {
            EntryKind::Directory
        } else {
            EntryKind::File
        };
        let (name, _) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
        self.hidden_count += 1;
        self.members.push(Member {
            name: if name.is_empty() { path.clone() } else { name.to_string() },
            path,
            kind,
            size: l.uncomp_size as u64,
            method: l.method,
            flags: l.flags,
            comp_size,
            data_off: Some(l.data_off),
            data_avail: avail,
            disk_offset: off,
            lfh_off: Some(off),
            span: Some((off, span_end.min(len))),
            status: FsEntryStatus::Deleted { recovery },
            timestamps: ts,
            meta,
        });
    }

    /// Per-member magic verdict via a bounded decompressed header read.
    fn magic_for(&self, m: &Member) -> Option<sutram_magic::MagicVerdict> {
        if !self.opts.check_magic
            || m.kind != EntryKind::File
            || m.size == 0
            || m.flags & FLAG_ENCRYPTED != 0
        {
            return None;
        }
        let mut r = self.read_member(m).ok()?;
        let mut header = vec![0u8; 4096usize.min(m.size as usize)];
        let n = r.read(&mut header).ok()?;
        header.truncate(n);
        Some(sutram_magic::check_entry_sized(&m.name, &header, m.size))
    }

    /// Raw reader over a member's stored bytes (no decompression).
    fn read_member(&self, m: &Member) -> Result<Box<dyn Read + Send>> {
        let data_off = m.data_off.ok_or_else(|| FsError::Corrupt {
            offset: m.disk_offset,
            msg: "member data offset unknown (local header missing)".into(),
        })?;
        match m.method {
            0 => Ok(Box::new(SegmentReader::new(
                self.src.clone(),
                vec![(Segment::Disk(data_off), m.data_avail)],
                m.data_avail.min(m.size.max(m.data_avail)),
            ))),
            8 => Ok(Box::new(InflateReader::new(
                self.src.clone(),
                data_off,
                m.data_avail,
                m.size,
            ))),
            other => Err(FsError::unsupported(format!(
                "compression method {other} ({})",
                method_name(other)
            ))),
        }
    }

    /// Byte ranges of the archive not claimed by any record — slack,
    /// SFX-adjacent gaps, hidden payload not inside any member span.
    fn covered_ranges(&self) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = Vec::new();
        if self.base_delta > 0 {
            v.push((0, self.base_delta)); // SFX stub — used, not slack
        }
        for m in &self.members {
            if let Some((s, e)) = m.span {
                if e > s {
                    v.push((s, e - s));
                }
            }
        }
        if let Some((s, l)) = self.cd_region {
            v.push((s, l));
        }
        if let Some((s, l)) = self.eocd_region {
            v.push((s, l));
        }
        v.sort_unstable();
        v
    }
}

fn method_name(m: u16) -> &'static str {
    match m {
        0 => "store",
        1 => "shrink",
        6 => "implode",
        8 => "deflate",
        9 => "deflate64",
        12 => "bzip2",
        14 => "lzma",
        93 => "zstd",
        98 => "ppmd",
        _ => "unknown",
    }
}

fn host_os_name(b: u16) -> &'static str {
    match b {
        0 => "msdos/fat",
        3 => "unix",
        10 => "windows-ntfs",
        11 => "mvs",
        19 => "macos",
        _ => "other",
    }
}

/// Emit one `FsEntry` for a member (filling magic lazily).
fn member_entry(fs: &ZipFs, idx: usize) -> FsEntry {
    let m = &fs.members[idx];
    let mut allocated = Vec::new();
    if let Some(off) = m.data_off {
        if m.data_avail > 0 {
            allocated.push((off, m.data_avail));
        }
    }
    let mut entry = FsEntry {
        path: util::join_path("/", &m.path),
        name: m.name.clone(),
        entry_id: idx as u64,
        kind: m.kind,
        size: m.size,
        disk_offset: m.disk_offset,
        allocated_ranges: allocated,
        timestamps: m.timestamps.clone(),
        status: m.status,
        meta: m.meta.clone(),
        magic: None,
    };
    if entry.name.is_empty() {
        entry.name = entry.path.clone();
    }
    entry.magic = fs.magic_for(m);
    entry
}

/// Streaming walk iterator: root, stored errors, live members (with
/// implied parent directories), then hidden members.
struct ZipWalk<'f> {
    fs: &'f ZipFs,
    next: usize,
    emitted_dirs: HashSet<String>,
    root_done: bool,
    errors: std::collections::VecDeque<FsError>,
    pending: std::collections::VecDeque<FsEntry>,
}

impl Iterator for ZipWalk<'_> {
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
            // Emit implied parent directories first.
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

impl FileSystem for ZipFs {
    fn info(&self) -> FsInfo {
        let mut meta = HashMap::new();
        meta.insert("format".into(), "zip".into());
        meta.insert("entries".into(), self.members.len().to_string());
        meta.insert("hidden_entries".into(), self.hidden_count.to_string());
        meta.insert("archive_size".into(), self.total_size.to_string());
        meta.insert("zip64".into(), self.zip64.to_string());
        meta.insert("eocd_found".into(), self.cd_region.is_some().to_string());
        meta.insert("archive_base".into(), format!("{:#x}", self.base_delta));
        if let Some(c) = &self.comment {
            meta.insert("comment".into(), c.clone());
        }
        if let Some((s, l)) = self.cd_region {
            meta.insert("central_directory_offset".into(), format!("{s:#x}"));
            meta.insert("central_directory_size".into(), l.to_string());
        }
        let unalloc: u64 = self.unallocated_ranges().iter().map(|(_, l)| l).sum();
        FsInfo {
            fs_type: "ZIP".into(),
            label: None,
            uuid: None,
            block_size: 1,
            total_blocks: self.total_size,
            free_blocks: Some(unalloc),
            total_nodes: Some(self.members.len() as u64),
            meta,
        }
    }

    fn source(&self) -> Arc<dyn ByteSource> {
        self.src.clone()
    }

    fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
        Box::new(ZipWalk {
            fs: self,
            next: 0,
            emitted_dirs: HashSet::new(),
            root_done: false,
            errors: self.errors.iter().map(dup_err).collect(),
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
        let idx = entry.entry_id as usize;
        let m = self.members.get(idx).ok_or_else(|| FsError::InvalidInput {
            msg: format!("entry id {} not a member of this archive", entry.entry_id),
        })?;
        if m.flags & FLAG_ENCRYPTED != 0 {
            return Err(FsError::unsupported("encrypted member (no key material)"));
        }
        self.read_member(m)
    }

    /// Gaps between records — including the space where hidden members
    /// were *not* found — are the carving ground.
    fn unallocated_ranges(&self) -> Vec<(u64, u64)> {
        let covered = self.covered_ranges();
        let mut out = Vec::new();
        let mut pos = 0u64;
        for (s, l) in covered {
            if s > pos {
                out.push((pos, s - pos));
            }
            pos = pos.max(s + l);
        }
        if pos < self.total_size {
            out.push((pos, self.total_size - pos));
        }
        out
    }
}

/// `FsError` is not `Clone` — rebuild a stored mount-phase error as an
/// owned value for the walk stream.
fn dup_err(e: &FsError) -> FsError {
    match e {
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
    }
}
