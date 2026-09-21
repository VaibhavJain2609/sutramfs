//! [`NtfsFs`] — the mounted NTFS volume: $MFT enumeration, attribute-list
//! merging, the live-cluster map driving recovery assessment, $BITMAP
//! free-space reporting, and the `FileSystem` impl.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;

use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsError, FsInfo, FsParser, FileSystem, MountOptions,
    Result,
};
use sutram_io::ByteSource;

use crate::attr::{self, Attr, DataRun, FileName};
use crate::boot::BootSector;
use crate::record::{self, FileRecord};
use crate::walk::Walk;

/// The parser entry point — stateless, cheap to construct.
///
/// ```
/// use sutram_ntfs::NtfsParser;
/// use sutram_fs::FsParser;
/// let p = NtfsParser;
/// assert_eq!(p.name(), "ntfs");
/// ```
pub struct NtfsParser;

impl FsParser for NtfsParser {
    fn name(&self) -> &'static str {
        "ntfs"
    }

    fn detect(&self, src: &dyn ByteSource) -> DetectConfidence {
        BootSector::detect(src)
    }

    fn mount_with(
        &self,
        src: Arc<dyn ByteSource>,
        opts: &MountOptions,
    ) -> Result<Box<dyn FileSystem>> {
        Ok(Box::new(NtfsFs::mount(src, opts.clone())?))
    }
}

/// Per-slot MFT state established by the mount-time scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotState {
    /// Zeroed / never-written slot.
    Empty,
    /// In-use base or extension record.
    Live,
    /// Valid FILE record with the in-use flag clear — deleted artefact.
    Free,
    /// `"BAAD"` signature — record flagged corrupt by chkdsk/a torn write.
    Baad,
    /// Parses as FILE but lives beyond $MFT's used data size — MFT-slack
    /// carved fragment.
    Fragment,
    /// Non-zero slot that failed header/fixup parsing.
    Corrupt,
}

/// Mount-time summary of one MFT record slot. `slots[i]` ↔ record `i`.
#[derive(Debug)]
pub(crate) struct RecSlot {
    pub state: SlotState,
    /// Absolute byte offset of the record.
    pub offset: u64,
    pub in_use: bool,
    pub is_dir: bool,
    /// Base-record reference for extension records (`0` for base records).
    pub base_ref: u64,
    pub seq: u16,
    /// Decoded $FILE_NAME attributes (drive path reconstruction).
    pub fns: Vec<FileName>,
    /// Stored parse-error text for `Corrupt` slots.
    pub error: Option<String>,
}

/// A logical stream view of one attribute across all its record extents
/// ($ATTRIBUTE_LIST merge). For `$DATA` this is one named/unnamed stream.
#[derive(Debug, Default)]
pub(crate) struct Stream {
    pub name: Option<String>,
    /// Resident content `(absolute_offset, len)`.
    pub resident: Option<(u64, u32)>,
    /// Merged non-resident runs (absolute VCN order).
    pub runs: Vec<DataRun>,
    pub real_size: u64,
    pub alloc_size: u64,
    pub init_size: u64,
    pub compressed: bool,
    pub sparse: bool,
    pub encrypted: bool,
    /// Compression unit as log2(clusters); 0 = none.
    pub comp_shift: u8,
    /// Absolute offsets of every attribute header that contributed.
    pub attr_offsets: Vec<u64>,
}

impl Stream {
    /// Byte extents of the *allocated* (non-sparse) runs.
    pub(crate) fn ranges(&self, cluster_size: u64, src_len: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        if let Some((off, len)) = self.resident {
            out.push((off, len as u64));
            return out;
        }
        for r in &self.runs {
            if let Some(lcn) = r.lcn {
                let off = lcn.saturating_mul(cluster_size);
                let len = r.len.saturating_mul(cluster_size);
                if off >= src_len {
                    continue; // points past end of image — corrupt runlist
                }
                out.push((off, len.min(src_len - off)));
            }
        }
        out
    }
}

/// A fully-parsed FILE record with extension-record attributes merged in.
#[derive(Debug)]
pub(crate) struct ParsedFile {
    pub rec: FileRecord,
    pub attrs: Vec<Attr>,
    /// First attribute-parse error encountered (lenient collection).
    pub attr_error: Option<String>,
    /// Extension record numbers that contributed attributes.
    pub ext_records: Vec<u64>,
}

/// A mounted NTFS volume.
pub struct NtfsFs {
    pub(crate) src: Arc<dyn ByteSource>,
    pub(crate) bs: BootSector,
    pub(crate) opts: MountOptions,
    /// $MFT's own data runs (VCN → LCN map of the MFT itself).
    pub(crate) mft_runs: Vec<DataRun>,
    /// $MFT real (used) byte size.
    pub(crate) mft_data_size: u64,
    /// Record slots scanned at mount (`slots[i]` = record `i`).
    pub(crate) slots: Vec<RecSlot>,
    /// Record count covered by $MFT's *real* size (slack starts after).
    pub(crate) live_rec_end: u64,
    /// Merged cluster ranges claimed by live records — `(lcn, len_clusters)`
    /// sorted by `lcn`. Drives deleted-record overwrite analysis.
    pub(crate) live_ranges: Vec<(u64, u64)>,
    /// Volume cluster bitmap ($Bitmap $DATA), when readable.
    pub(crate) bitmap: Option<Vec<u8>>,
    /// $MFT's own record bitmap (bit per record slot), when present.
    pub(crate) mft_bitmap: Option<Vec<u8>>,
    pub(crate) label: Option<String>,
    pub(crate) ntfs_version: Option<(u8, u8)>,
}

/// Cap on extension records followed per base record.
const MAX_EXT_RECORDS: usize = 64;
/// Cap on total attributes merged per file.
const MAX_ATTRS: usize = 512;

impl NtfsFs {
    pub(crate) fn mount(src: Arc<dyn ByteSource>, opts: MountOptions) -> Result<Self> {
        let bs = BootSector::parse(src.as_ref())?;
        let rec_size = bs.file_record_size;
        let csz = bs.cluster_size;

        // ---- record 0 ($MFT) -------------------------------------------
        let rec0_off = bs.mft_lcn * csz;
        let rec0_raw = src
            .read_slice(rec0_off, rec_size as usize)
            .map_err(FsError::Io)?;
        let rec0 = record::parse_record(rec0_raw, rec0_off, 0, bs.bytes_per_sector as usize)?;
        let (attrs0, _) = Self::collect_attrs(&rec0);
        let mut mft_runs = None;
        let mut mft_data_size = 0u64;
        let mut mft_alloc_size = 0u64;
        let mut mft_bitmap = None;
        for a in &attrs0 {
            match a.type_code {
                attr::T_DATA if a.name.is_none() && a.non_resident => {
                    if mft_runs.is_none() {
                        mft_runs = Some(a.runs.clone());
                        mft_data_size = a.real_size;
                        mft_alloc_size = a.alloc_size.max(a.real_size);
                    }
                }
                attr::T_BITMAP if a.name.is_none() => {
                    if let Some((off, len)) = a.resident {
                        mft_bitmap = src.read_slice(off, len as usize).ok();
                    } else if a.non_resident {
                        mft_bitmap = Self::read_stream_bytes(&src, &a.runs, csz, a.real_size).ok();
                    }
                }
                _ => {}
            }
        }
        let mft_runs = mft_runs.ok_or_else(|| {
            FsError::corrupt(rec0_off, "$MFT record 0 has no non-resident $DATA")
        })?;
        if mft_data_size == 0 {
            return Err(FsError::corrupt(rec0_off, "$MFT $DATA has zero size"));
        }

        let mut fs = NtfsFs {
            src,
            bs,
            opts,
            mft_runs,
            mft_data_size,
            slots: Vec::new(),
            live_rec_end: 0,
            live_ranges: Vec::new(),
            bitmap: None,
            mft_bitmap,
            label: None,
            ntfs_version: None,
        };

        // Scan bound: the MFT's *allocated* span (covers MFT slack used for
        // fragment carving), capped by run coverage and image size.
        let covered_clusters: u64 = fs
            .mft_runs
            .iter()
            .fold(0u64, |acc, r| acc.saturating_add(r.len));
        let scan_bytes = mft_alloc_size
            .min(covered_clusters.saturating_mul(csz))
            .min(fs.src.len());
        let rec_count = scan_bytes / rec_size;
        fs.live_rec_end = mft_data_size / rec_size;

        // ---- mount scan: classify every slot, build live map -----------
        let mut live_raw: Vec<(u64, u64)> = Vec::new();
        for rec_no in 0..rec_count {
            let slot = fs.scan_slot(rec_no, &mut live_raw);
            if slot.state == SlotState::Live && rec_no == 3 {
                fs.read_volume_meta(&slot);
            }
            if slot.state == SlotState::Live && rec_no == 6 {
                fs.read_bitmap(&slot);
            }
            fs.slots.push(slot);
        }
        live_raw.sort_unstable();
        fs.live_ranges = merge_ranges(live_raw);
        Ok(fs)
    }

    /// Mount-scan one slot: read + fixup + header-level parse.
    fn scan_slot(&self, rec_no: u64, live_raw: &mut Vec<(u64, u64)>) -> RecSlot {
        let mut slot = RecSlot {
            state: SlotState::Empty,
            offset: 0,
            in_use: false,
            is_dir: false,
            base_ref: 0,
            seq: 0,
            fns: Vec::new(),
            error: None,
        };
        let Some(offset) = self.mft_offset(rec_no) else {
            slot.state = SlotState::Corrupt;
            slot.error = Some("record beyond $MFT run coverage".into());
            return slot;
        };
        slot.offset = offset;
        let raw = match self
            .src
            .read_slice(offset, self.bs.file_record_size as usize)
        {
            Ok(r) => r,
            Err(e) => {
                slot.state = SlotState::Corrupt;
                slot.error = Some(format!("read failed: {e}"));
                return slot;
            }
        };
        if raw.len() < self.bs.file_record_size as usize || raw.iter().all(|&b| b == 0) {
            return slot; // Empty
        }
        let rec = match record::parse_record(
            raw,
            offset,
            rec_no,
            self.bs.bytes_per_sector as usize,
        ) {
            Ok(r) => r,
            Err(e) => {
                slot.state = SlotState::Corrupt;
                slot.error = Some(format!("{e}"));
                return slot;
            }
        };
        slot.seq = rec.sequence;
        slot.in_use = rec.in_use();
        slot.is_dir = rec.is_dir();
        slot.base_ref = rec.base_ref;
        let (attrs, aerr) = Self::collect_attrs(&rec);
        slot.error = aerr;
        for a in &attrs {
            if a.type_code == attr::T_FILE_NAME {
                if let Some((off, len)) = a.resident {
                    if let Ok(body) = self.src.read_slice(off, len as usize) {
                        if let Some(f) = attr::parse_fn(&body) {
                            slot.fns.push(f);
                        }
                    }
                }
            }
            if rec.in_use() {
                for r in &a.runs {
                    if let Some(lcn) = r.lcn {
                        live_raw.push((lcn, r.len));
                    }
                }
            }
        }
        slot.state = if &rec.signature == b"BAAD" {
            SlotState::Baad
        } else if rec_no >= self.live_rec_end && rec_no > 0 {
            SlotState::Fragment // MFT slack — beyond used record space
        } else if rec.in_use() {
            SlotState::Live
        } else {
            SlotState::Free
        };
        slot
    }

    /// Absolute disk offset of MFT record `n`, via $MFT's data runs.
    pub(crate) fn mft_offset(&self, rec_no: u64) -> Option<u64> {
        let csz = self.bs.cluster_size;
        let logical = rec_no.checked_mul(self.bs.file_record_size)?;
        let vcn = logical / csz;
        let in_run = logical % csz;
        for r in &self.mft_runs {
            if vcn >= r.vcn && vcn < r.vcn.saturating_add(r.len) {
                return r.lcn.and_then(|l| {
                    l.saturating_mul(csz)
                        .checked_add((vcn - r.vcn).saturating_mul(csz))
                        .and_then(|o| o.checked_add(in_run))
                });
            }
        }
        None
    }

    /// Read raw bytes of MFT record `n`.
    pub(crate) fn read_record_bytes(&self, rec_no: u64) -> Result<(Vec<u8>, u64)> {
        let off = self.mft_offset(rec_no).ok_or_else(|| FsError::Corrupt {
            offset: 0,
            msg: format!("MFT record {rec_no} beyond run coverage"),
        })?;
        let raw = self
            .src
            .read_slice(off, self.bs.file_record_size as usize)
            .map_err(FsError::Io)?;
        if (raw.len() as u64) < self.bs.file_record_size {
            return Err(FsError::truncated(
                off,
                self.bs.file_record_size,
                raw.len() as u64,
            ));
        }
        Ok((raw, off))
    }

    /// Read + fixup + parse record `n`.
    pub(crate) fn parse_record(&self, rec_no: u64) -> Result<FileRecord> {
        let (raw, off) = self.read_record_bytes(rec_no)?;
        record::parse_record(raw, off, rec_no, self.bs.bytes_per_sector as usize)
    }

    /// Collect a record's attributes; lenient — stops (reporting) at the
    /// first corrupt header.
    pub(crate) fn collect_attrs(rec: &FileRecord) -> (Vec<Attr>, Option<String>) {
        let mut out = Vec::new();
        let data = &rec.data;
        let limit = (rec.used_size as usize).clamp(rec.first_attr_off, data.len());
        let mut off = rec.first_attr_off;
        let mut err = None;
        while off + 8 <= limit && out.len() < MAX_ATTRS {
            match attr::parse_attr(data, off, rec.offset) {
                Ok(None) => break,
                Ok(Some((a, len))) => {
                    out.push(a);
                    off += len;
                }
                Err(e) => {
                    err = Some(format!("{e}"));
                    break;
                }
            }
        }
        (out, err)
    }

    /// Parse record `n` and merge in every attribute reachable through its
    /// `$ATTRIBUTE_LIST` (extension records). Bounded and cycle-guarded.
    pub(crate) fn parse_full(&self, rec_no: u64) -> Result<ParsedFile> {
        let rec = self.parse_record(rec_no)?;
        let (mut attrs, mut attr_error) = Self::collect_attrs(&rec);
        let mut ext_records = Vec::new();
        let mut visited: HashSet<u64> = HashSet::from([rec_no]);

        // Find the (usually resident) $ATTRIBUTE_LIST bodies.
        let list_bodies: Vec<Vec<u8>> = attrs
            .iter()
            .filter(|a| a.type_code == attr::T_ATTRIBUTE_LIST)
            .filter_map(|a| {
                if let Some((off, len)) = a.resident {
                    self.src.read_slice(off, len as usize).ok()
                } else if a.non_resident {
                    Self::read_stream_bytes(&self.src, &a.runs, self.bs.cluster_size, a.real_size)
                        .ok()
                } else {
                    None
                }
            })
            .collect();

        for body in &list_bodies {
            let entries = attr::parse_attr_list(body, rec.offset).unwrap_or_default();
            for e in entries {
                let target = attr::file_ref_rec(e.record_ref);
                if target == rec_no || visited.contains(&target) {
                    continue;
                }
                if ext_records.len() >= MAX_EXT_RECORDS {
                    if attr_error.is_none() {
                        attr_error = Some("attribute-list extent cap reached".into());
                    }
                    break;
                }
                visited.insert(target);
                match self.parse_record(target) {
                    Ok(ext_rec) => {
                        ext_records.push(target);
                        let (eattrs, eerr) = Self::collect_attrs(&ext_rec);
                        for a in eattrs {
                            if attrs.len() < MAX_ATTRS {
                                attrs.push(a);
                            }
                        }
                        if attr_error.is_none() {
                            attr_error = eerr;
                        }
                    }
                    Err(e) => {
                        if attr_error.is_none() {
                            attr_error = Some(format!("extension record {target}: {e}"));
                        }
                    }
                }
            }
        }
        Ok(ParsedFile {
            rec,
            attrs,
            attr_error,
            ext_records,
        })
    }

    /// Group all attributes of `type_code` into logical [`Stream`]s —
    /// merging extents that share a name (the `$ATTRIBUTE_LIST` case).
    /// Streams are ordered by first appearance; extents by `first_vcn`.
    pub(crate) fn group_streams(attrs: &[Attr], type_code: u32) -> Vec<Stream> {
        let mut order: Vec<Option<String>> = Vec::new();
        let mut map: HashMap<Option<String>, Vec<&Attr>> = HashMap::new();
        for a in attrs.iter().filter(|a| a.type_code == type_code) {
            if !map.contains_key(&a.name) {
                order.push(a.name.clone());
            }
            map.entry(a.name.clone()).or_default().push(a);
        }
        let mut streams = Vec::new();
        for name in order {
            let mut insts = map.remove(&name).unwrap_or_default();
            insts.sort_by_key(|a| a.first_vcn);
            let mut s = Stream {
                name: name.clone(),
                ..Default::default()
            };
            for a in insts {
                if let Some((off, len)) = a.resident {
                    // Resident instance: the stream is resident (NTFS does
                    // not split resident attributes across records).
                    s.resident = Some((off, len));
                    s.real_size = s.real_size.max(len as u64);
                    s.alloc_size = s.alloc_size.max(len as u64);
                } else {
                    s.runs.extend_from_slice(&a.runs);
                    s.real_size = s.real_size.max(a.real_size);
                    s.alloc_size = s.alloc_size.max(a.alloc_size);
                    s.init_size = s.init_size.max(a.init_size);
                    s.comp_shift = s.comp_shift.max(a.comp_unit_shift);
                }
                s.compressed |= a.compressed();
                s.sparse |= a.sparse();
                s.encrypted |= a.encrypted();
                s.attr_offsets.push(a.offset);
            }
            s.runs.sort_by_key(|r| r.vcn);
            streams.push(s);
        }
        streams
    }

    /// Read a non-resident runlist's stored bytes (sparse holes → zeros),
    /// capped at `size` logical bytes. Bounded by `size`.
    fn read_stream_bytes(
        src: &Arc<dyn ByteSource>,
        runs: &[DataRun],
        csz: u64,
        size: u64,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity((size as usize).min(1 << 22));
        for r in runs {
            if out.len() as u64 >= size {
                break;
            }
            let want = (r.len.saturating_mul(csz).min(size - out.len() as u64)) as usize;
            match r.lcn {
                Some(l) => {
                    let b = src
                        .read_slice(l.saturating_mul(csz), want)
                        .map_err(FsError::Io)?;
                    out.extend_from_slice(&b);
                    if b.len() < want {
                        break; // truncated source
                    }
                }
                None => out.resize(out.len() + want, 0),
            }
        }
        Ok(out)
    }

    /// $Volume (record 3): label + NTFS version.
    fn read_volume_meta(&mut self, _slot: &RecSlot) {
        if let Ok(rec) = self.parse_record(3) {
            let (attrs, _) = Self::collect_attrs(&rec);
            for a in &attrs {
                if let Some((off, len)) = a.resident {
                    if let Ok(body) = self.src.read_slice(off, len as usize) {
                        match a.type_code {
                            attr::T_VOLUME_NAME => {
                                if let Some(l) = attr::parse_volume_name(&body) {
                                    if !l.is_empty() {
                                        self.label = Some(l);
                                    }
                                }
                            }
                            attr::T_VOLUME_INFORMATION => {
                                self.ntfs_version = attr::parse_volume_information(&body);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    /// $Bitmap (record 6): the volume cluster allocation bitmap.
    fn read_bitmap(&mut self, _slot: &RecSlot) {
        if let Ok(rec) = self.parse_record(6) {
            let (attrs, _) = Self::collect_attrs(&rec);
            for a in &attrs {
                if a.type_code != attr::T_DATA || a.name.is_some() {
                    continue;
                }
                let cap = (self.bs.total_clusters / 8 + 4096) as usize;
                let bytes = if let Some((off, len)) = a.resident {
                    self.src.read_slice(off, (len as usize).min(cap)).ok()
                } else if a.non_resident {
                    Self::read_stream_bytes(
                        &self.src,
                        &a.runs,
                        self.bs.cluster_size,
                        a.real_size.min(cap as u64),
                    )
                    .ok()
                } else {
                    None
                };
                if let Some(b) = bytes {
                    self.bitmap = Some(b);
                }
                break;
            }
        }
    }

    /// Is cluster `lcn` marked allocated in $BITMAP? `None` = unknown.
    pub(crate) fn cluster_allocated(&self, lcn: u64) -> Option<bool> {
        let bm = self.bitmap.as_ref()?;
        let byte = *bm.get((lcn / 8) as usize)?;
        Some(byte & (1 << (lcn % 8)) != 0)
    }

    /// Subtract live-claimed clusters from `runs`; returns surviving
    /// `(vcn, lcn, len)` cluster extents so callers can map survivors back
    /// to logical file offsets.
    pub(crate) fn surviving_runs(
        &self,
        runs: &[DataRun],
    ) -> (Vec<(u64, u64, u64)>, Vec<String>) {
        let mut surviving = Vec::new();
        let mut notes = Vec::new();
        let mut lost = 0u64;
        for r in runs {
            let Some(lcn) = r.lcn else { continue }; // sparse runs: nothing to lose
            let mut pos = lcn;
            let run_end = lcn.saturating_add(r.len);
            while pos < run_end {
                // Find the first live range that could overlap [pos, run_end).
                let idx = self.live_ranges.partition_point(|&(s, _)| s <= pos);
                let overlap = if idx > 0 {
                    let (s, l) = self.live_ranges[idx - 1];
                    if s.saturating_add(l) > pos { Some((s, l)) } else { None }
                } else {
                    None
                };
                match overlap {
                    Some((s, l)) if s <= pos => {
                        // pos inside a live range — skip to its end.
                        pos = s.saturating_add(l).min(run_end);
                        lost += 1; // refined below by bytes
                    }
                    _ => {
                        // Gap until next live range start (or run end).
                        let next_live = self.live_ranges[idx..]
                            .iter()
                            .map(|&(s, _)| s)
                            .find(|&s| s > pos)
                            .unwrap_or(run_end);
                        let free_end = next_live.min(run_end);
                        surviving.push((r.vcn + (pos - lcn), pos, free_end - pos));
                        pos = free_end;
                    }
                }
            }
        }
        if lost > 0 {
            notes.push("some clusters reallocated to live files".into());
        }
        (surviving, notes)
    }

    /// Per-file magic verdict via a bounded header read.
    pub(crate) fn magic_for(&self, e: &FsEntry) -> Option<sutram_magic::MagicVerdict> {
        if !self.opts.check_magic || e.kind != EntryKind::File || e.size == 0 {
            return None;
        }
        if e.allocated_ranges.is_empty() {
            return None;
        }
        // Compressed/encrypted content is not directly checkable.
        if e.meta.contains_key("compressed") || e.meta.contains_key("encrypted") {
            return None;
        }
        let mut r = self.read_file(e).ok()?;
        let mut header = vec![0u8; 4096.min(e.size as usize)];
        let n = r.read(&mut header).ok()?;
        header.truncate(n);
        Some(sutram_magic::check_entry(&e.name, &header))
    }

    /// Rebuild the full logical run map for a live entry's `$DATA` stream —
    /// needed for sparse (holes) and compressed (unit) reads.
    /// `(rec_no, data_stream_idx)` come from the entry's meta.
    fn rebuild_stream(&self, entry: &FsEntry) -> Result<Stream> {
        let rec_no: u64 = entry
            .meta
            .get("mft_record")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| FsError::InvalidInput {
                msg: "entry has no mft_record provenance".into(),
            })?;
        let idx: usize = entry
            .meta
            .get("data_stream_index")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let pf = self.parse_full(rec_no)?;
        let streams = Self::group_streams(&pf.attrs, attr::T_DATA);
        streams.into_iter().nth(idx).ok_or_else(|| FsError::Corrupt {
            offset: pf.rec.offset,
            msg: format!("data stream {idx} no longer present in record {rec_no}"),
        })
    }
}

/// Merge sorted `(start, len)` cluster ranges.
fn merge_ranges(mut v: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    if v.is_empty() {
        return v;
    }
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(v.len());
    for (s, l) in v.drain(..) {
        if let Some(last) = out.last_mut() {
            if s <= last.0 + last.1 {
                let end = (s + l).max(last.0 + last.1);
                last.1 = end - last.0;
                continue;
            }
        }
        out.push((s, l));
    }
    out
}

impl FileSystem for NtfsFs {
    fn info(&self) -> FsInfo {
        let mut meta = HashMap::new();
        meta.insert("oem".into(), "NTFS".into());
        meta.insert("bytes_per_sector".into(), self.bs.bytes_per_sector.to_string());
        meta.insert(
            "sectors_per_cluster".into(),
            self.bs.sectors_per_cluster.to_string(),
        );
        meta.insert("total_sectors".into(), self.bs.total_sectors.to_string());
        meta.insert("mft_lcn".into(), self.bs.mft_lcn.to_string());
        meta.insert("mft_mirr_lcn".into(), self.bs.mft_mirr_lcn.to_string());
        meta.insert("mft_size".into(), self.mft_data_size.to_string());
        meta.insert(
            "file_record_size".into(),
            self.bs.file_record_size.to_string(),
        );
        meta.insert(
            "index_record_size".into(),
            self.bs.index_record_size.to_string(),
        );
        if let Some((maj, min)) = self.ntfs_version {
            meta.insert("ntfs_version".into(), format!("{maj}.{min}"));
        }
        // Journal artefacts: $LogFile is record 2; $UsnJrnl is located by
        // name under $Extend. Parsing them is the platform's job — flag
        // their presence.
        if self.slots.get(2).map(|s| s.in_use).unwrap_or(false) {
            meta.insert("logfile_present".into(), "true".into());
        }
        if self
            .slots
            .iter()
            .any(|s| s.in_use && s.fns.iter().any(|f| f.name == "$UsnJrnl"))
        {
            meta.insert("usn_journal_present".into(), "true".into());
        }
        let free = self.bitmap.as_ref().map(|bm| {
            let mut free = 0u64;
            for c in 0..self.bs.total_clusters {
                let b = bm.get((c / 8) as usize).copied().unwrap_or(0xFF);
                if b & (1 << (c % 8)) == 0 {
                    free += 1;
                }
            }
            free
        });
        FsInfo {
            fs_type: "NTFS".into(),
            label: self.label.clone(),
            uuid: Some(format!("{:016X}", self.bs.serial)),
            block_size: self.bs.cluster_size,
            total_blocks: self.bs.total_clusters,
            free_blocks: free,
            total_nodes: Some(self.slots.len() as u64),
            meta,
        }
    }

    fn source(&self) -> Arc<dyn ByteSource> {
        self.src.clone()
    }

    fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
        Box::new(Walk::new(self))
    }

    fn read_file(&self, entry: &FsEntry) -> Result<Box<dyn Read + Send>> {
        match entry.kind {
            EntryKind::File | EntryKind::Other => {}
            _ => {
                return Err(FsError::InvalidInput {
                    msg: format!("cannot read {}: not a file", entry.path),
                })
            }
        }
        // Deleted entries read only their surviving extents; live entries
        // that are neither sparse nor compressed stream flat extents.
        let needs_rebuild = matches!(entry.status, sutram_fs::FsEntryStatus::Live)
            && (entry.meta.contains_key("sparse") || entry.meta.contains_key("compressed"));
        if needs_rebuild {
            // Fall back to flat extents when the stream can't be rebuilt.
            if let Ok(stream) = self.rebuild_stream(entry) {
                if stream.compressed {
                    return Ok(Box::new(CompressedReader::new(
                        self.src.clone(),
                        stream,
                        self.bs.cluster_size,
                    )));
                }
                return Ok(Box::new(SparseReader::new(
                    self.src.clone(),
                    stream,
                    self.bs.cluster_size,
                )));
            }
        }
        Ok(Box::new(ExtentReader {
            src: self.src.clone(),
            ranges: entry.allocated_ranges.clone(),
            idx: 0,
            off_in: 0,
            remaining: entry.size,
        }))
    }

    /// Free clusters per $BITMAP, coalesced — the carving ground.
    fn unallocated_ranges(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let Some(bm) = &self.bitmap else {
            return out;
        };
        let csz = self.bs.cluster_size;
        let src_len = self.src.len();
        let mut run_start: Option<u64> = None;
        for c in 0..self.bs.total_clusters {
            let allocated = bm
                .get((c / 8) as usize)
                .map(|b| b & (1 << (c % 8)) != 0)
                .unwrap_or(true); // unreadable tail → assume allocated
            match (allocated, run_start) {
                (false, None) => run_start = Some(c),
                (true, Some(s)) => {
                    let off = s * csz;
                    let end = (c * csz).min(src_len);
                    if end > off {
                        out.push((off, end - off));
                    }
                    run_start = None;
                }
                _ => {}
            }
        }
        if let Some(s) = run_start {
            let off = s * csz;
            let end = (self.bs.total_clusters * csz).min(src_len);
            if end > off {
                out.push((off, end - off));
            }
        }
        out
    }
}

/// Sequential reader over byte extents, capped at `remaining` logical
/// bytes — used for live flat files and the surviving extents of deleted
/// ones.
pub(crate) struct ExtentReader {
    src: Arc<dyn ByteSource>,
    ranges: Vec<(u64, u64)>,
    idx: usize,
    off_in: u64,
    remaining: u64,
}

impl Read for ExtentReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.remaining > 0 && self.idx < self.ranges.len() {
            let (off, len) = self.ranges[self.idx];
            let avail = len.saturating_sub(self.off_in);
            if avail == 0 {
                self.idx += 1;
                self.off_in = 0;
                continue;
            }
            let want = buf.len().min(avail.min(self.remaining) as usize);
            let n = self.src.read_at(off + self.off_in, &mut buf[..want])?;
            self.off_in += n as u64;
            self.remaining -= n as u64;
            if n == 0 {
                break;
            }
            return Ok(n);
        }
        Ok(0)
    }
}

/// Reader for sparse files: holes read as zeros, extents read from disk,
/// preserving logical file offsets (a flat `ExtentReader` would shift
/// data after each hole).
pub(crate) struct SparseReader {
    src: Arc<dyn ByteSource>,
    /// Logical map: `(file_offset, Option<disk_offset>, len)`.
    map: Vec<(u64, Option<u64>, u64)>,
    pos: u64,
    size: u64,
}

impl SparseReader {
    fn new(src: Arc<dyn ByteSource>, stream: Stream, csz: u64) -> Self {
        let mut map = Vec::with_capacity(stream.runs.len());
        for r in &stream.runs {
            map.push((
                r.vcn * csz,
                r.lcn.map(|l| l * csz),
                r.len * csz,
            ));
        }
        SparseReader {
            src,
            map,
            pos: 0,
            size: stream.real_size,
        }
    }
}

impl Read for SparseReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.size {
            return Ok(0);
        }
        // Locate the extent covering `pos` (runs are VCN-sorted).
        for &(foff, doff, len) in &self.map {
            if self.pos >= foff && self.pos < foff + len {
                let want = (buf.len() as u64)
                    .min(foff + len - self.pos)
                    .min(self.size - self.pos) as usize;
                let n = match doff {
                    Some(d) => self
                        .src
                        .read_at(d + (self.pos - foff), &mut buf[..want])?,
                    None => {
                        buf[..want].fill(0);
                        want
                    }
                };
                self.pos += n as u64;
                return Ok(n);
            }
        }
        // Gap in the map (uninitialized region between runs) — zeros,
        // but only up to the next extent so real data isn't skipped.
        let next_start = self
            .map
            .iter()
            .filter(|&&(foff, _, _)| foff > self.pos)
            .map(|&(foff, _, _)| foff)
            .min()
            .unwrap_or(self.size);
        let want = (buf.len() as u64)
            .min(self.size - self.pos)
            .min(next_start - self.pos) as usize;
        buf[..want].fill(0);
        self.pos += want as u64;
        Ok(want)
    }
}

/// Reader for NTFS-compressed streams: decompresses one compression unit
/// (LZNT1) at a time — bounded memory regardless of file size.
pub(crate) struct CompressedReader {
    src: Arc<dyn ByteSource>,
    /// Stored (on-disk) extents: `(vcn, Option<lcn>, len_clusters)`.
    runs: Vec<DataRun>,
    csz: u64,
    unit_clusters: u64,
    /// Decoded bytes of the current unit.
    buf: Vec<u8>,
    buf_pos: usize,
    /// Next unit index to decode.
    unit_idx: u64,
    /// Total units implied by real_size.
    total_units: u64,
    remaining: u64,
}

impl CompressedReader {
    fn new(src: Arc<dyn ByteSource>, stream: Stream, csz: u64) -> Self {
        let unit_clusters = if stream.comp_shift > 0 && stream.comp_shift < 32 {
            1u64 << stream.comp_shift
        } else {
            16
        };
        let unit_bytes = unit_clusters * csz;
        let total_units = stream.real_size.div_ceil(unit_bytes);
        CompressedReader {
            src,
            runs: stream.runs,
            csz,
            unit_clusters,
            buf: Vec::new(),
            buf_pos: 0,
            unit_idx: 0,
            total_units,
            remaining: stream.real_size,
        }
    }

    /// Decode the next compression unit into `self.buf`.
    fn next_unit(&mut self) -> std::io::Result<()> {
        self.buf.clear();
        self.buf_pos = 0;
        if self.unit_idx >= self.total_units {
            return Ok(());
        }
        let unit_vcn = self.unit_idx * self.unit_clusters;
        let unit_end = unit_vcn + self.unit_clusters;
        // Collect the stored bytes for this unit's VCN range.
        let mut stored = Vec::new();
        let mut sparse = false;
        for r in &self.runs {
            if r.vcn + r.len <= unit_vcn || r.vcn >= unit_end {
                continue;
            }
            match r.lcn {
                Some(lcn) => {
                    let skip = unit_vcn.saturating_sub(r.vcn);
                    let take = (r.len - skip).min(unit_end - (r.vcn + skip));
                    let off = (lcn + skip) * self.csz;
                    let want = (take * self.csz) as usize;
                    let b = self.src.read_slice(off, want)?;
                    stored.extend_from_slice(&b);
                    if b.len() < want {
                        break;
                    }
                }
                None => sparse = true,
            }
        }
        self.unit_idx += 1;
        let unit_bytes = (self.unit_clusters * self.csz) as usize;
        if sparse && stored.is_empty() {
            self.buf.resize(unit_bytes, 0); // wholly sparse unit
            return Ok(());
        }
        if stored.len() >= unit_bytes || !crate::lznt1::looks_compressed(&stored) {
            // Stored raw (incompressible unit).
            stored.resize(unit_bytes, 0);
            self.buf = stored;
        } else {
            let (out, clean) = crate::lznt1::decompress_unit(&stored, unit_bytes);
            if !clean && out.is_empty() {
                stored.resize(unit_bytes, 0);
                self.buf = stored;
            } else {
                self.buf = out;
            }
        }
        Ok(())
    }
}

impl Read for CompressedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.remaining > 0 {
            if self.buf_pos < self.buf.len() {
                let want = buf
                    .len()
                    .min(self.buf.len() - self.buf_pos)
                    .min(self.remaining as usize);
                buf[..want].copy_from_slice(&self.buf[self.buf_pos..self.buf_pos + want]);
                self.buf_pos += want;
                self.remaining -= want as u64;
                return Ok(want);
            }
            if self.unit_idx >= self.total_units {
                return Ok(0);
            }
            self.next_unit()?;
        }
        Ok(0)
    }
}
