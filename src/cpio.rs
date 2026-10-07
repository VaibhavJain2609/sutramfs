//! CPIO forensic parser: newc (`070701`/`070702`), odc (`070707` ASCII)
//! and binary (`0x71C7`, little- and big-endian) dialects.
//!
//! A cpio archive is a flat header+name+data stream terminated by a
//! `TRAILER!!!` entry. Forensic behaviours:
//!
//! * **Archive slack** — bytes after `TRAILER!!!` (and the bytes a
//!   truncated archive leaves behind) are emitted as a
//!   `/$ORPHANED/archive_slack` deleted pseudo-entry (`Deleted{Unknown}`)
//!   carrying `slack_offset`/`slack_len` — carving ground, surfaced
//!   through `unallocated_ranges()` for `carve_region`.
//! * **Truncated members** — data past EOF → `Deleted{Partially…}`.
//! * **Hard links** — `nlink > 1` records sharing an inode get
//!   `meta["hardlink_of"]` pointing at the first-seen path.
//! * `070702` CRC fields are recorded (`meta["check"]`); verification is
//!   noted but not enforced at parse time.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use sutram_fs::util;
use sutram_fs::{
    DetectConfidence, EntryKind, FileSystem, FsEntry, FsEntryStatus, FsError, FsInfo, FsParser,
    FsTimestamp, MountOptions, RecoveryState, Result, Timestamps,
};
use sutram_io::ByteSource;

use crate::reader::{Segment, SegmentReader};

const NEWC_LEN: u64 = 110;
const ODC_LEN: u64 = 76;
const BIN_LEN: u64 = 26;
const MAX_NAME: u64 = 1 << 16;
/// Trailer names are fixed.
const TRAILER: &str = "TRAILER!!!";

/// On-disk dialect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variant {
    /// SVR4 ASCII hex, 110-byte header, 4-byte alignment.
    Newc,
    /// `070702` — newc with a CRC check field.
    Crc,
    /// POSIX.1 portable ASCII octal, 76-byte header, no alignment.
    Odc,
    /// Binary, 26-byte header, 2-byte alignment; `le` picks field order.
    Bin { le: bool },
}

impl Variant {
    fn name(self) -> &'static str {
        match self {
            Variant::Newc => "newc",
            Variant::Crc => "crc",
            Variant::Odc => "odc",
            Variant::Bin { le: true } => "bin-le",
            Variant::Bin { le: false } => "bin-be",
        }
    }
}

/// The parser entry point — stateless.
pub struct CpioParser;

fn variant_at(src: &dyn ByteSource) -> Option<Variant> {
    let h = src.read_slice(0, 8).ok()?;
    match h.get(0..6) {
        Some(b"070701") => Some(Variant::Newc),
        Some(b"070702") => Some(Variant::Crc),
        Some(b"070707") => Some(Variant::Odc),
        _ => match h.get(0..2) {
            Some([0x71, 0xC7]) => Some(Variant::Bin { le: false }),
            Some([0xC7, 0x71]) => Some(Variant::Bin { le: true }),
            _ => None,
        },
    }
}

impl FsParser for CpioParser {
    fn name(&self) -> &'static str {
        "cpio"
    }

    fn detect(&self, src: &dyn ByteSource) -> DetectConfidence {
        match variant_at(src) {
            Some(Variant::Newc | Variant::Crc | Variant::Odc) => DetectConfidence::Certain,
            Some(Variant::Bin { .. }) => DetectConfidence::High,
            None => DetectConfidence::None,
        }
    }

    fn mount_with(
        &self,
        src: Arc<dyn ByteSource>,
        opts: &MountOptions,
    ) -> Result<Box<dyn FileSystem>> {
        Ok(Box::new(CpioFs::mount(src, opts.clone())?))
    }
}

/// A parsed member header.
struct Header {
    ino: u64,
    mode: u64,
    uid: u64,
    gid: u64,
    nlink: u64,
    mtime: u64,
    filesize: u64,
    check: u64,
    devmajor: u64,
    devminor: u64,
    rdevmajor: u64,
    rdevminor: u64,
    name: Vec<u8>,
    /// Absolute offset where member data starts (post-alignment).
    data_off: u64,
    /// Absolute offset where the next header starts.
    next: u64,
}

pub(crate) fn hex_field(f: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(f).ok()?;
    u64::from_str_radix(s.trim(), 16).ok()
}

pub(crate) fn oct_field(f: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(f).ok()?;
    u64::from_str_radix(s.trim_end_matches('\0').trim(), 8).ok()
}

fn r16e(b: &[u8], le: bool) -> u64 {
    let w = if le {
        u16::from_le_bytes([b[0], b[1]])
    } else {
        u16::from_be_bytes([b[0], b[1]])
    };
    w as u64
}

/// Binary 32-bit fields: two 16-bit halves, most-significant first
/// (PDP-endian), each half in the archive's byte order.
pub(crate) fn r32bin(b: &[u8], le: bool) -> u64 {
    (r16e(b, le) << 16) | r16e(&b[2..], le)
}

fn parse_header(src: &dyn ByteSource, off: u64, v: Variant) -> Result<Option<Header>> {
    let len = src.len();
    let hlen = match v {
        Variant::Newc | Variant::Crc => NEWC_LEN,
        Variant::Odc => ODC_LEN,
        Variant::Bin { .. } => BIN_LEN,
    };
    if off + hlen > len {
        if len - off.min(len) == 0 {
            return Ok(None); // clean EOF
        }
        return Err(FsError::truncated(off, hlen, len - off.min(len)));
    }
    let h = src.read_slice(off, hlen as usize)?;
    match v {
        Variant::Newc | Variant::Crc => {
            let namesize = hex_field(&h[94..102])
                .ok_or_else(|| FsError::corrupt(off + 94, "bad c_namesize"))?;
            if namesize == 0 || namesize > MAX_NAME {
                return Err(FsError::corrupt(off + 94, "implausible c_namesize"));
            }
            let filesize = hex_field(&h[54..62])
                .ok_or_else(|| FsError::corrupt(off + 54, "bad c_filesize"))?;
            let name = src.read_slice(off + NEWC_LEN, namesize as usize)?;
            if name.len() < namesize as usize {
                return Err(FsError::truncated(off, NEWC_LEN + namesize, len - off));
            }
            // newc aligns header+name and data to 4 bytes.
            let data_off = (off + NEWC_LEN + namesize).div_ceil(4) * 4;
            let next = (data_off + filesize).div_ceil(4) * 4;
            Ok(Some(Header {
                ino: hex_field(&h[6..14]).unwrap_or(0),
                mode: hex_field(&h[14..22]).unwrap_or(0),
                uid: hex_field(&h[22..30]).unwrap_or(0),
                gid: hex_field(&h[30..38]).unwrap_or(0),
                nlink: hex_field(&h[38..46]).unwrap_or(0),
                mtime: hex_field(&h[46..54]).unwrap_or(0),
                filesize,
                check: hex_field(&h[102..110]).unwrap_or(0),
                devmajor: hex_field(&h[62..70]).unwrap_or(0),
                devminor: hex_field(&h[70..78]).unwrap_or(0),
                rdevmajor: hex_field(&h[78..86]).unwrap_or(0),
                rdevminor: hex_field(&h[86..94]).unwrap_or(0),
                name,
                data_off,
                next,
            }))
        }
        Variant::Odc => {
            let namesize = oct_field(&h[59..65])
                .ok_or_else(|| FsError::corrupt(off + 59, "bad c_namesize"))?;
            if namesize == 0 || namesize > MAX_NAME {
                return Err(FsError::corrupt(off + 59, "implausible c_namesize"));
            }
            let filesize = oct_field(&h[65..76])
                .ok_or_else(|| FsError::corrupt(off + 65, "bad c_filesize"))?;
            let name = src.read_slice(off + ODC_LEN, namesize as usize)?;
            if name.len() < namesize as usize {
                return Err(FsError::truncated(off, ODC_LEN + namesize, len - off));
            }
            let data_off = off + ODC_LEN + namesize;
            Ok(Some(Header {
                ino: oct_field(&h[12..18]).unwrap_or(0),
                mode: oct_field(&h[18..24]).unwrap_or(0),
                uid: oct_field(&h[24..30]).unwrap_or(0),
                gid: oct_field(&h[30..36]).unwrap_or(0),
                nlink: oct_field(&h[36..42]).unwrap_or(0),
                mtime: oct_field(&h[48..59]).unwrap_or(0),
                filesize,
                check: 0,
                devmajor: oct_field(&h[6..12]).unwrap_or(0),
                devminor: 0,
                rdevmajor: oct_field(&h[42..48]).unwrap_or(0),
                rdevminor: 0,
                name,
                data_off,
                next: data_off + filesize, // no alignment in odc
            }))
        }
        Variant::Bin { le } => {
            let namesize = r16e(&h[20..22], le);
            if namesize == 0 || namesize > MAX_NAME {
                return Err(FsError::corrupt(off + 20, "implausible h_namesize"));
            }
            let filesize = r32bin(&h[22..26], le);
            let name = src.read_slice(off + BIN_LEN, namesize as usize)?;
            if name.len() < namesize as usize {
                return Err(FsError::truncated(off, BIN_LEN + namesize, len - off));
            }
            // Binary format pads name and data to even boundaries.
            let data_off = (off + BIN_LEN + namesize).div_ceil(2) * 2;
            let next = (data_off + filesize).div_ceil(2) * 2;
            Ok(Some(Header {
                ino: r16e(&h[4..6], le),
                mode: r16e(&h[6..8], le),
                uid: r16e(&h[8..10], le),
                gid: r16e(&h[10..12], le),
                nlink: r16e(&h[12..14], le),
                mtime: r32bin(&h[16..20], le),
                filesize,
                check: 0,
                devmajor: r16e(&h[2..4], le),
                devminor: 0,
                rdevmajor: r16e(&h[14..16], le),
                rdevminor: 0,
                name,
                data_off,
                next,
            }))
        }
    }
}

/// A resolved member record.
struct Member {
    path: String,
    name: String,
    kind: EntryKind,
    size: u64,
    disk_offset: u64,
    segs: Vec<(Segment, u64)>,
    extents: Vec<(u64, u64)>,
    status: FsEntryStatus,
    timestamps: Timestamps,
    meta: HashMap<String, String>,
}

/// A mounted CPIO archive.
pub struct CpioFs {
    src: Arc<dyn ByteSource>,
    opts: MountOptions,
    members: Vec<Member>,
    errors: Vec<FsError>,
    variant: Option<Variant>,
    /// Where the trailer record ended (post-padding), if found.
    trailer_end: Option<u64>,
    trailer_found: bool,
    total_size: u64,
}

impl CpioFs {
    pub(crate) fn mount(src: Arc<dyn ByteSource>, opts: MountOptions) -> Result<Self> {
        let mut fs = CpioFs {
            src,
            opts,
            members: Vec::new(),
            errors: Vec::new(),
            variant: None,
            trailer_end: None,
            trailer_found: false,
            total_size: 0,
        };
        fs.total_size = fs.src.len();
        let v = variant_at(fs.src.as_ref()).ok_or_else(|| FsError::Corrupt {
            offset: 0,
            msg: "unrecognised cpio magic".into(),
        })?;
        fs.variant = Some(v);
        fs.scan(v)?;
        if fs.members.is_empty() && !fs.trailer_found {
            return Err(FsError::corrupt(0, "no parseable cpio records"));
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

    fn scan(&mut self, v: Variant) -> Result<()> {
        let len = self.src.len();
        let mut pos = 0u64;
        // ino → first path, for hardlink annotation.
        let mut seen_ino: HashMap<u64, String> = HashMap::new();
        loop {
            let hdr = match parse_header(self.src.as_ref(), pos, v) {
                Ok(Some(h)) => h,
                Ok(None) => break,
                Err(e) => {
                    self.fail(e)?;
                    break;
                }
            };
            let name_raw = hdr.name.clone();
            let mut name_bytes = name_raw.as_slice();
            if let Some(z) = name_bytes.iter().position(|&b| b == 0) {
                name_bytes = &name_bytes[..z];
            }
            let name = String::from_utf8_lossy(name_bytes).into_owned();

            if name == TRAILER {
                self.trailer_found = true;
                self.trailer_end = Some(hdr.next.min(len));
                // Slack after the trailer → carving candidates.
                if hdr.next < len {
                    self.emit_slack(hdr.next, len - hdr.next);
                }
                break;
            }

            let avail = len.saturating_sub(hdr.data_off);
            let take = hdr.filesize.min(avail);
            let truncated = take < hdr.filesize;

            let mut comps = Vec::new();
            for c in name.split('/') {
                match c {
                    "" | "." => {}
                    ".." => comps.push("__".to_string()),
                    c => comps.push(util::sanitize_name(c)),
                }
            }
            let path = comps.join("/");

            let kind = match hdr.mode & 0o170000 {
                0o040000 => EntryKind::Directory,
                0o120000 => EntryKind::Symlink,
                0o100000 | 0 => EntryKind::File,
                _ => EntryKind::Other,
            };

            let mut meta: HashMap<String, String> = HashMap::new();
            meta.insert("format".into(), v.name().into());
            meta.insert("ino".into(), hdr.ino.to_string());
            meta.insert("mode".into(), format!("{:#07o}", hdr.mode));
            meta.insert("uid".into(), hdr.uid.to_string());
            meta.insert("gid".into(), hdr.gid.to_string());
            meta.insert("nlink".into(), hdr.nlink.to_string());
            if hdr.devmajor != 0 || hdr.devminor != 0 {
                meta.insert("dev".into(), format!("{},{}", hdr.devmajor, hdr.devminor));
            }
            if hdr.check != 0 {
                meta.insert("check".into(), format!("{:#010x}", hdr.check));
            }
            if matches!(kind, EntryKind::Other) && hdr.mode & 0o170000 != 0 {
                meta.insert(
                    "device".into(),
                    format!("{},{}", hdr.rdevmajor, hdr.rdevminor),
                );
            }
            if hdr.nlink > 1 {
                if let Some(first) = seen_ino.get(&hdr.ino) {
                    meta.insert("hardlink_of".into(), first.clone());
                } else if kind == EntryKind::File {
                    seen_ino.insert(hdr.ino, format!("/{path}"));
                }
            }
            if kind == EntryKind::Symlink && take > 0 {
                if let Ok(d) = self.src.read_slice(hdr.data_off, take.min(4096) as usize) {
                    let t = String::from_utf8_lossy(&d)
                        .trim_end_matches('\0')
                        .to_string();
                    meta.insert("symlink_target".into(), t);
                }
            }
            if name != path {
                meta.insert("raw_name".into(), name.clone());
            }

            let ts = Timestamps {
                modified: Some(FsTimestamp {
                    value: util::unix_nanos(1970, 1, 1, 0, 0, 0, 0)
                        .and_then(|b| b.checked_add(hdr.mtime as i64 * 1_000_000_000)),
                    raw_value: hdr.mtime,
                    raw_encoding: "unix-sec",
                    granularity: Duration::from_secs(1),
                }),
                ..Default::default()
            };

            let mut status = FsEntryStatus::Live;
            if truncated {
                status = FsEntryStatus::Deleted {
                    recovery: RecoveryState::PartiallyOverwritten {
                        recovered_bytes: take,
                        total_bytes: hdr.filesize,
                    },
                };
                meta.insert(
                    "note".into(),
                    "archive truncated: member data runs past end of image".into(),
                );
            }

            if path.is_empty() {
                // Degenerate nameless record — keep as an Other artefact.
                self.members.push(Member {
                    path: format!("/$UNNAMED/{pos:#x}"),
                    name: format!("unnamed_{pos:#x}"),
                    kind: EntryKind::Other,
                    size: hdr.filesize,
                    disk_offset: pos,
                    segs: if take > 0 {
                        vec![(Segment::Disk(hdr.data_off), take)]
                    } else {
                        Vec::new()
                    },
                    extents: if take > 0 {
                        vec![(hdr.data_off, take)]
                    } else {
                        Vec::new()
                    },
                    status,
                    timestamps: ts,
                    meta,
                });
            } else {
                self.members.push(Member {
                    name: path.rsplit('/').next().unwrap_or(&path).to_string(),
                    path,
                    kind,
                    size: hdr.filesize,
                    disk_offset: pos,
                    segs: if take > 0 {
                        vec![(Segment::Disk(hdr.data_off), take)]
                    } else {
                        Vec::new()
                    },
                    extents: if take > 0 {
                        vec![(hdr.data_off, take)]
                    } else {
                        Vec::new()
                    },
                    status,
                    timestamps: ts,
                    meta,
                });
            }

            if truncated {
                break; // the archive ends inside this member
            }
            if hdr.next <= pos {
                // No forward progress — corrupt stream; stop.
                self.fail(FsError::corrupt(pos, "cpio record made no progress"))?;
                break;
            }
            pos = hdr.next;
        }
        // Trailing bytes with no trailer at all are also slack —
        // carve them even when the stream ended in a parse error.
        if !self.trailer_found && pos < len && !self.members.is_empty() {
            self.emit_slack(pos, len - pos);
        }
        Ok(())
    }

    /// Emit the post-trailer/trailing slack pseudo-entry — carving ground.
    fn emit_slack(&mut self, off: u64, len: u64) {
        if len == 0 {
            return;
        }
        let mut meta = HashMap::new();
        meta.insert("slack_offset".into(), format!("{off:#x}"));
        meta.insert("slack_len".into(), len.to_string());
        meta.insert("carve_candidate".into(), "true".into());
        meta.insert(
            "note".into(),
            "archive slack after TRAILER!!! / stream end — carve with carve_region".into(),
        );
        self.members.push(Member {
            path: "/$ORPHANED/archive_slack".into(),
            name: "archive_slack".into(),
            kind: EntryKind::Other,
            size: len,
            disk_offset: off,
            segs: vec![(Segment::Disk(off), len)],
            extents: vec![(off, len)],
            status: FsEntryStatus::Deleted {
                recovery: RecoveryState::Unknown,
            },
            timestamps: Default::default(),
            meta,
        });
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
        // Segments are already clamped to surviving bytes at parse time.
        Ok(Box::new(SegmentReader::new(
            self.src.clone(),
            m.segs.clone(),
            m.size,
        )))
    }
}

fn member_entry(fs: &CpioFs, idx: usize) -> FsEntry {
    let m = &fs.members[idx];
    let mut entry = FsEntry {
        path: if m.path.starts_with('/') {
            m.path.clone()
        } else {
            util::join_path("/", &m.path)
        },
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

struct CpioWalk<'f> {
    fs: &'f CpioFs,
    next: usize,
    emitted_dirs: HashSet<String>,
    root_done: bool,
    errors: std::collections::VecDeque<FsError>,
    pending: std::collections::VecDeque<FsEntry>,
}

impl Iterator for CpioWalk<'_> {
    type Item = Result<FsEntry>;

    fn next(&mut self) -> Option<Self::Item> {
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
        if !m.path.starts_with("/$") {
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
        }
        Some(Ok(member_entry(self.fs, idx)))
    }
}

impl FileSystem for CpioFs {
    fn info(&self) -> FsInfo {
        let mut meta = HashMap::new();
        meta.insert(
            "format".into(),
            self.variant.map(|v| v.name()).unwrap_or("unknown").into(),
        );
        meta.insert("entries".into(), self.members.len().to_string());
        meta.insert("archive_size".into(), self.total_size.to_string());
        meta.insert("trailer_found".into(), self.trailer_found.to_string());
        if let Some(e) = self.trailer_end {
            meta.insert("trailer_end".into(), format!("{e:#x}"));
            meta.insert(
                "trailing_bytes".into(),
                self.total_size.saturating_sub(e).to_string(),
            );
        }
        FsInfo {
            fs_type: "CPIO".into(),
            label: None,
            uuid: None,
            block_size: 1,
            total_blocks: self.total_size,
            free_blocks: Some(self.unallocated_ranges().iter().map(|(_, l)| l).sum()),
            total_nodes: Some(self.members.len() as u64),
            meta,
        }
    }

    fn source(&self) -> Arc<dyn ByteSource> {
        self.src.clone()
    }

    fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
        Box::new(CpioWalk {
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
        let m = self
            .members
            .get(entry.entry_id as usize)
            .ok_or_else(|| FsError::InvalidInput {
                msg: format!("entry id {} not a member", entry.entry_id),
            })?;
        self.read_member(m)
    }

    /// Post-trailer / post-stream slack regions are the carving ground.
    fn unallocated_ranges(&self) -> Vec<(u64, u64)> {
        self.members
            .iter()
            .filter(|m| m.meta.contains_key("carve_candidate"))
            .flat_map(|m| m.extents.iter().copied())
            .collect()
    }
}

/// `FsError` is not `Clone` — rebuild stored errors for the walk stream.
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
