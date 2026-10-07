//! [`NtfsFs`] — the mounted NTFS volume: $MFT enumeration, attribute-list
//! merging, the live-cluster map driving recovery assessment, $BITMAP
//! free-space reporting, and the `FileSystem` impl.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;

use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsError, FsInfo, FsParser, FileSystem,
    MountOptions, RecoveryState, Result, Timestamps,
};
use sutram_io::ByteSource;

use crate::attr::{self, Attr, DataRun, FileName};
use crate::boot::BootSector;
use crate::journal::{self, JournalEvent};
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
    /// Mount the volume directly — the concrete handle exposes journal
    /// forensics ([`Self::journal_events`]) beyond the `dyn FileSystem`
    /// surface.
    pub fn mount(src: Arc<dyn ByteSource>, opts: MountOptions) -> Result<Self> {
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
                        // Record bitmap ≈ records/8 bytes — cap the read.
                        mft_bitmap =
                            Self::read_stream_bytes(&src, &a.runs, csz, a.real_size.min(64 << 20))
                                .ok();
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

    /// recno → (display name, parent recno) for every live base record.
    /// Used by remnant rebuild to filter entries that merely echo the
    /// current filesystem's own index blocks.
    pub fn live_names(&self) -> HashMap<u64, (String, u64)> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.state == SlotState::Live && s.base_ref == 0)
            .filter_map(|(i, s)| {
                let f = s
                    .fns
                    .iter()
                    .find(|f| f.namespace != 2)
                    .or_else(|| s.fns.first())?;
                Some((
                    i as u64,
                    (f.name.clone(), crate::attr::file_ref_rec(f.parent_ref)),
                ))
            })
            .collect()
    }

    /// Debug: number of scanned MFT slots.
    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Debug: human-readable summary of one slot's mount-scan state.
    pub fn debug_slot(&self, rec_no: u64) -> String {
        match self.slots.get(rec_no as usize) {
            None => "beyond slot table".into(),
            Some(s) => format!(
                "{:?} in_use={} is_dir={} base_ref={:#x} seq={} fns={:?} err={:?}",
                s.state, s.in_use, s.is_dir, s.base_ref, s.seq,
                s.fns.iter().map(|f| (f.name.clone(), f.parent_ref, f.namespace))
                    .collect::<Vec<_>>(),
                s.error
            ),
        }
    }

    /// Debug: dump parsed attribute headers of record `n`.
    pub fn debug_attrs(&self, rec_no: u64) -> String {
        match self.parse_record(rec_no) {
            Err(e) => format!("parse_record: {e}"),
            Ok(rec) => {
                let (attrs, err) = Self::collect_attrs(&rec);
                let mut s = format!(
                    "first_attr={:#x} used={:#x} data_len={} nattr={} err={:?}\n",
                    rec.first_attr_off, rec.used_size, rec.data.len(), attrs.len(), err
                );
                for a in &attrs {
                    let body_ok = a
                        .resident
                        .map(|(o, l)| self.src.read_slice(o, l as usize).is_ok());
                    s.push_str(&format!(
                        "  type={:#06x} len n/a off={:#x} nonres={} resident={:?} body_ok={:?} name={:?}\n",
                        a.type_code, a.offset, a.non_resident, a.resident, body_ok, a.name
                    ));
                    if a.type_code == attr::T_FILE_NAME {
                        if let Some((o, l)) = a.resident {
                            if let Ok(b) = self.src.read_slice(o, l as usize) {
                                s.push_str(&format!(
                                    "    body[0..8]={:02x?} parse_fn={:?}\n",
                                    &b[..b.len().min(8)],
                                    attr::parse_fn(&b).map(|f| (f.name, f.parent_ref, f.real_size))
                                ));
                            }
                        }
                    }
                }
                s
            }
        }
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
                    // Cap: an attribute list is small metadata; a hostile
                    // real_size must not become an allocation bomb.
                    Self::read_stream_bytes(
                        &self.src,
                        &a.runs,
                        self.bs.cluster_size,
                        a.real_size.min(1 << 20),
                    )
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
                        // Verify the extension record really belongs to
                        // this base record: its base-file-reference must
                        // point back here, and the reference's sequence
                        // (when nonzero) must match the slot's. A stale or
                        // corrupt $ATTRIBUTE_LIST otherwise grafts another
                        // file's extents onto this one — a live-data
                        // misfire.
                        if attr::file_ref_rec(ext_rec.base_ref) != rec_no {
                            if attr_error.is_none() {
                                attr_error = Some(format!(
                                    "extension record {target} does not reference \
                                     base record {rec_no} (ignored)"
                                ));
                            }
                            continue;
                        }
                        let ref_seq = (e.record_ref >> 48) as u16;
                        if ref_seq != 0 && ref_seq != ext_rec.sequence {
                            if attr_error.is_none() {
                                attr_error = Some(format!(
                                    "extension record {target} sequence {:#06x} != \
                                     reference {ref_seq:#06x} (stale slot, ignored)",
                                    ext_rec.sequence
                                ));
                            }
                            continue;
                        }
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
                // Cap at 512 MiB: the bitmap needs ClusterCount/8 bytes,
                // but a hostile BPB/real_size must not become an
                // allocation bomb (sparse runs zero-fill without reads).
                let cap = ((self.bs.total_clusters / 8 + 4096).min(512 << 20)) as usize;
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

    // ---- journal forensics ($UsnJrnl + $LogFile) ------------------------

    /// Locate record `rec_no`'s `$DATA` stream named `name` (`None` =
    /// unnamed). Used for `$UsnJrnl:$J` and `$LogFile`.
    fn journal_stream(&self, rec_no: u64, name: Option<&str>) -> Option<Stream> {
        let rec = self.parse_record(rec_no).ok()?;
        let (attrs, _) = Self::collect_attrs(&rec);
        Self::group_streams(&attrs, attr::T_DATA)
            .into_iter()
            .find(|s| s.name.as_deref() == name)
    }

    /// `(logical_off, disk_off, len)` regions covering a stream's
    /// *allocated* bytes — sparse holes omitted so logical offsets stay
    /// honest.
    fn stream_regions(&self, s: &Stream) -> Vec<(u64, u64, u64)> {
        if let Some((off, len)) = s.resident {
            return vec![(0, off, len as u64)];
        }
        let csz = self.bs.cluster_size;
        s.runs
            .iter()
            .filter_map(|r| {
                r.lcn.map(|l| {
                    (
                        r.vcn.saturating_mul(csz),
                        l.saturating_mul(csz),
                        r.len.saturating_mul(csz),
                    )
                })
            })
            .collect()
    }

    /// Read a stream's logical bytes (sparse holes → zeros), bounded by
    /// `cap`.
    fn stream_bytes(&self, s: &Stream, cap: u64) -> Result<Vec<u8>> {
        if let Some((off, len)) = s.resident {
            return self
                .src
                .read_slice(off, (len as u64).min(cap) as usize)
                .map_err(FsError::Io);
        }
        Self::read_stream_bytes(
            &self.src,
            &s.runs,
            self.bs.cluster_size,
            s.real_size.min(cap),
        )
    }

    /// Stream the parsed journals as typed [`JournalEvent`]s: USN change
    /// records from `$UsnJrnl:$J` (record 12), then `$LogFile` (record 2)
    /// restart areas, log-record headers, checkpoints and torn pages.
    /// Journals are **parsed, never replayed** — a USN record is evidence
    /// a file changed, not a view of its contents. Each stream is scanned
    /// over at most `MAX_JOURNAL_BYTES` (64 MiB) of materialised bytes.
    /// Empty when neither journal stream exists.
    pub fn journal_events(&self) -> Box<dyn Iterator<Item = Result<JournalEvent>> + Send + '_> {
        let usn = self
            .journal_stream(12, Some("$J"))
            .and_then(|s| {
                self.stream_bytes(&s, journal::MAX_JOURNAL_BYTES)
                    .ok()
                    .map(|b| {
                        journal::UsnIter::new(b, self.stream_regions(&s), self.opts.strict)
                    })
            })
            .into_iter()
            .flatten()
            .map(|r| r.map(JournalEvent::Usn));
        let log = self
            .journal_stream(2, None)
            .and_then(|s| {
                self.stream_bytes(&s, journal::MAX_JOURNAL_BYTES)
                    .ok()
                    .map(|b| {
                        journal::LogIter::new(
                            b,
                            self.stream_regions(&s),
                            self.bs.bytes_per_sector as usize,
                            self.opts.strict,
                        )
                    })
            })
            .into_iter()
            .flatten()
            .map(|r| r.map(JournalEvent::from));
        // Strict mode: the first error ends the whole journal stream —
        // not just whichever sub-iterator produced it.
        let strict = self.opts.strict;
        let mut done = false;
        Box::new(usn.chain(log).map_while(move |item| {
            if done {
                return None;
            }
            if strict && item.is_err() {
                done = true;
            }
            Some(item)
        }))
    }

    /// Render one journal event as a forensic `FsEntry`.
    fn journal_entry(&self, ev: &JournalEvent) -> Option<FsEntry> {
        let mut meta = HashMap::new();
        meta.insert("journal".into(), "ntfs".into());
        let mut timestamps = Timestamps::default();
        let (name, path, kind, disk_offset) = match ev {
            JournalEvent::Usn(r) => {
                let recno = attr::file_ref_rec(r.file_ref);
                meta.insert("usn".into(), r.usn.to_string());
                meta.insert("usn_reason".into(), format!("{:#x}", r.reason));
                let reasons = journal::reason_names(r.reason);
                if !reasons.is_empty() {
                    meta.insert("usn_reason_names".into(), reasons.join(","));
                }
                meta.insert("file_ref".into(), r.file_ref.to_string());
                meta.insert("parent_ref".into(), r.parent_ref.to_string());
                if let Some(slot) = self
                    .slots
                    .get(attr::file_ref_rec(r.parent_ref) as usize)
                {
                    if let Some(f) = slot.fns.first() {
                        meta.insert("parent_name".into(), f.name.clone());
                    }
                }
                meta.insert(
                    "usn_version".into(),
                    format!("{}.{}", r.major_version, r.minor_version),
                );
                meta.insert("source_info".into(), format!("{:#x}", r.source_info));
                meta.insert("security_id".into(), r.security_id.to_string());
                meta.insert(
                    "file_attributes".into(),
                    format!("{:#x}", r.file_attributes),
                );
                meta.insert(
                    "usn_stream_offset".into(),
                    format!("{:#x}", r.stream_offset),
                );
                timestamps.changed = Some(attr::filetime_ts(r.filetime));
                let name = if r.name.is_empty() {
                    format!("rec_{recno}")
                } else {
                    r.name.clone()
                };
                let path = format!("/$USN_JRNL/{:#x}/{name}", r.usn);
                let kind = if r.file_attributes & 0x10 != 0 {
                    EntryKind::Directory
                } else {
                    EntryKind::File
                };
                (name, path, kind, r.disk_offset.unwrap_or(0))
            }
            JournalEvent::Restart(ra) => {
                meta.insert("current_lsn".into(), format!("{:#x}", ra.current_lsn));
                meta.insert("log_clients".into(), ra.log_clients.to_string());
                meta.insert("seq_nr_bits".into(), ra.seq_nr_bits.to_string());
                meta.insert("restart_area_len".into(), ra.restart_area_len.to_string());
                meta.insert("logfile_size".into(), ra.file_size.to_string());
                meta.insert("record_page_len".into(), ra.record_page_len.to_string());
                (
                    format!("restart_area_{:#x}", ra.disk_offset),
                    format!("/$LOGFILE/restart_{:#x}", ra.disk_offset),
                    EntryKind::Other,
                    ra.disk_offset,
                )
            }
            JournalEvent::LogRecord(lr) => {
                meta.insert("lsn".into(), format!("{:#x}", lr.this_lsn));
                meta.insert(
                    "client_prev_lsn".into(),
                    format!("{:#x}", lr.client_prev_lsn),
                );
                meta.insert(
                    "client_undo_next_lsn".into(),
                    format!("{:#x}", lr.client_undo_next_lsn),
                );
                meta.insert("record_type".into(), format!("{:#x}", lr.record_type));
                meta.insert("transaction_id".into(), lr.transaction_id.to_string());
                meta.insert("flags".into(), format!("{:#x}", lr.flags));
                meta.insert("redo_op".into(), format!("{:#x}", lr.redo_op));
                meta.insert("undo_op".into(), format!("{:#x}", lr.undo_op));
                meta.insert("redo_len".into(), lr.redo_len.to_string());
                meta.insert("undo_len".into(), lr.undo_len.to_string());
                meta.insert("client_data_len".into(), lr.client_data_len.to_string());
                // Payload interpretation: op names, target MFT record,
                // $I30/$FILE_NAME filenames, attribute type codes.
                let it = lr.interpret(self.bs.cluster_size, self.bs.file_record_size);
                meta.insert("op".into(), it.redo_op.name().into());
                if it.redo_op != it.undo_op {
                    meta.insert("undo_op_name".into(), it.undo_op.name().into());
                }
                if !it.detail.is_empty() {
                    meta.insert("op_detail".into(), it.detail.clone());
                }
                if lr.target_attribute != 0 {
                    meta.insert(
                        "target_attr_offset".into(),
                        format!("{:#x}", lr.target_attribute),
                    );
                }
                if lr.lcns_to_follow != 0 {
                    meta.insert("lcns_to_follow".into(), lr.lcns_to_follow.to_string());
                }
                if lr.mft_cluster_index != 0 {
                    meta.insert(
                        "mft_cluster_index".into(),
                        format!("{:#x}", lr.mft_cluster_index),
                    );
                }
                if let Some(rec) = it.mft_record {
                    meta.insert("target_mft_record".into(), rec.to_string());
                    if it.record_is_bound {
                        meta.insert(
                            "target_mft_record_bound".into(),
                            "cluster floor — exact record not encoded".into(),
                        );
                    }
                    // Resolve the slot's current name for context.
                    if let Some(slot) = self.slots.get(rec as usize) {
                        if let Some(f) = slot.fns.first() {
                            meta.insert("target_name".into(), f.name.clone());
                        }
                    }
                }
                if let Some(name) = &it.file_name {
                    meta.insert("target_file_name".into(), name.clone());
                }
                if let Some(p) = it.parent_ref {
                    meta.insert("target_parent_ref".into(), format!("{:#x}", p));
                }
                if let Some(c) = it.child_ref {
                    meta.insert("target_child_ref".into(), format!("{:#x}", c));
                }
                if let Some(t) = it.attr_type {
                    meta.insert("attr_type".into(), format!("{:#x}", t));
                }
                if let Some(n) = &it.attr_name {
                    meta.insert("attr_name".into(), n.clone());
                }
                let name = format!("lsn_{:#x}", lr.this_lsn);
                (
                    name.clone(),
                    format!("/$LOGFILE/{name}"),
                    EntryKind::Other,
                    lr.disk_offset.unwrap_or(0),
                )
            }
            JournalEvent::Checkpoint { lsn, disk_offset } => {
                meta.insert("lsn".into(), format!("{lsn:#x}"));
                meta.insert("note".into(), "$LogFile checkpoint page (CHKD)".into());
                (
                    format!("checkpoint_{disk_offset:#x}"),
                    format!("/$LOGFILE/checkpoint_{disk_offset:#x}"),
                    EntryKind::Other,
                    *disk_offset,
                )
            }
            JournalEvent::TornPage { disk_offset } => {
                meta.insert(
                    "note".into(),
                    "torn log page (BAAD) — evidence of the last in-flight write".into(),
                );
                (
                    format!("torn_{disk_offset:#x}"),
                    format!("/$LOGFILE/torn_{disk_offset:#x}"),
                    EntryKind::Other,
                    *disk_offset,
                )
            }
        };
        Some(FsEntry {
            path,
            name,
            entry_id: 0,
            kind,
            size: 0,
            disk_offset,
            allocated_ranges: Vec::new(),
            timestamps,
            status: FsEntryStatus::Deleted {
                recovery: RecoveryState::Unknown,
            },
            meta,
            magic: None,
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
        // name under $Extend. Their contents are parsed (bounded) —
        // counts summarise the scan.
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
        if let Some(s) = self.journal_stream(12, Some("$J")) {
            meta.insert("usn_stream_size".into(), s.real_size.to_string());
            if s.real_size > journal::MAX_JOURNAL_BYTES {
                meta.insert("usn_scan_truncated".into(), "true".into());
            }
        }
        if let Some(s) = self.journal_stream(2, None) {
            meta.insert("logfile_size".into(), s.real_size.to_string());
            if s.real_size > journal::MAX_JOURNAL_BYTES {
                meta.insert("logfile_scan_truncated".into(), "true".into());
            }
        }
        if meta.contains_key("usn_journal_present") || meta.contains_key("logfile_present") {
            let mut usn = 0u64;
            let mut restarts = 0u64;
            let mut records = 0u64;
            let mut checkpoints = 0u64;
            let mut torn = 0u64;
            let mut errs = 0u64;
            for item in self.journal_events() {
                match item {
                    Ok(JournalEvent::Usn(_)) => usn += 1,
                    Ok(JournalEvent::Restart(_)) => restarts += 1,
                    Ok(JournalEvent::LogRecord(_)) => records += 1,
                    Ok(JournalEvent::Checkpoint { .. }) => checkpoints += 1,
                    Ok(JournalEvent::TornPage { .. }) => torn += 1,
                    Err(_) => errs += 1,
                }
            }
            meta.insert("usn_records".into(), usn.to_string());
            meta.insert("logfile_restart_areas".into(), restarts.to_string());
            meta.insert("logfile_records".into(), records.to_string());
            meta.insert("logfile_checkpoints".into(), checkpoints.to_string());
            meta.insert("logfile_torn_pages".into(), torn.to_string());
            meta.insert("journal_parse_errors".into(), errs.to_string());
        }
        let free = self.bitmap.as_ref().map(|bm| {
            // Bound the scan: a hostile BPB can declare astronomic cluster
            // counts — never iterate past bits the bitmap/image has.
            let limit = self
                .bs
                .total_clusters
                .min(self.src.len() / self.bs.cluster_size + 2)
                .min(bm.len() as u64 * 8);
            let mut free = 0u64;
            for c in 0..limit {
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

    /// Journal artefacts as pseudo-entries: `$UsnJrnl` change records
    /// under `/$USN_JRNL/` and `$LogFile` structures under `/$LOGFILE/`.
    /// These sit alongside — never inside — the `walk()` tree.
    ///
    /// USN records stream before `$LogFile` records (the streams are
    /// chained that way), so a `file_ref → usns` map accumulates as items
    /// pass through; each interpreted log record whose target record
    /// number matches a seen USN file ref is annotated with
    /// `correlated_usn` — the journal's own cross-stream link between a
    /// transaction record and the change journal entry.
    fn journal_entries(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
        // Bounded: cap tracked refs and USNs per ref (hostile journals).
        const MAX_CORR_REFS: usize = 1 << 18;
        const MAX_CORR_USNS: usize = 8;
        let mut corr: HashMap<u64, (Vec<i64>, u64)> = HashMap::new();
        Box::new(
            self.journal_events()
                .filter_map(move |item| match item {
                    Err(e) => Some(Err(e)),
                    Ok(ev) => {
                        if let JournalEvent::Usn(u) = &ev {
                            // Key by bare record number — a log record's
                            // target carries no sequence number.
                            let rec = attr::file_ref_rec(u.file_ref);
                            if corr.len() < MAX_CORR_REFS || corr.contains_key(&rec) {
                                let ent = corr.entry(rec).or_default();
                                if ent.0.len() < MAX_CORR_USNS {
                                    ent.0.push(u.usn);
                                }
                                ent.1 += 1;
                            }
                        }
                        let mut e = self.journal_entry(&ev)?;
                        if let JournalEvent::LogRecord(lr) = &ev {
                            let it = lr.interpret(
                                self.bs.cluster_size,
                                self.bs.file_record_size,
                            );
                            // Correlate on the exact record number when
                            // known, else the record cluster's floor.
                            if let Some(rec) = it.mft_record {
                                if let Some((usns, total)) = corr.get(&rec) {
                                    if !usns.is_empty() {
                                        e.meta.insert(
                                            "correlated_usn".into(),
                                            usns.iter()
                                                .map(|u| format!("{u:#x}"))
                                                .collect::<Vec<_>>()
                                                .join(","),
                                        );
                                        e.meta.insert(
                                            "correlated_usn_count".into(),
                                            total.to_string(),
                                        );
                                    }
                                }
                            }
                        }
                        Some(Ok(e))
                    }
                }),
        )
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
        // Bound the scan: hostile BPB geometry can declare astronomic
        // cluster counts — bits beyond the bitmap/image are uninteresting
        // anyway (clusters past the image can't be carved).
        let limit = self
            .bs
            .total_clusters
            .min(src_len / csz + 2)
            .min(bm.len() as u64 * 8);
        let mut run_start: Option<u64> = None;
        for c in 0..limit {
            let allocated = bm
                .get((c / 8) as usize)
                .map(|b| b & (1 << (c % 8)) != 0)
                .unwrap_or(true); // unreadable tail → assume allocated
            match (allocated, run_start) {
                (false, None) => run_start = Some(c),
                (true, Some(s)) => {
                    let off = s.saturating_mul(csz);
                    let end = (c.saturating_mul(csz)).min(src_len);
                    if end > off {
                        out.push((off, end - off));
                    }
                    run_start = None;
                }
                _ => {}
            }
        }
        if let Some(s) = run_start {
            let off = s.saturating_mul(csz);
            let end = limit.saturating_mul(csz).min(src_len);
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
    pub(crate) fn new(src: Arc<dyn ByteSource>, stream: Stream, csz: u64) -> Self {
        let mut map = Vec::with_capacity(stream.runs.len());
        for r in &stream.runs {
            // Saturating: a hostile runlist may carry VCN/LCN values whose
            // byte offsets overflow u64 — never panic on untrusted input.
            map.push((
                r.vcn.saturating_mul(csz),
                r.lcn.map(|l| l.saturating_mul(csz)),
                r.len.saturating_mul(csz),
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
        // Comparisons use subtraction — saturated `foff`/`len` values from
        // hostile runlists would overflow `foff + len`.
        for &(foff, doff, len) in &self.map {
            if self.pos >= foff && self.pos - foff < len {
                let want = (buf.len() as u64)
                    .min(len - (self.pos - foff))
                    .min(self.size - self.pos) as usize;
                let n = match doff {
                    Some(d) => self
                        .src
                        .read_at(d.saturating_add(self.pos - foff), &mut buf[..want])?,
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
    pub(crate) fn new(src: Arc<dyn ByteSource>, stream: Stream, csz: u64) -> Self {
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
                    // Saturating: hostile LCN/VCN values must not panic.
                    let off = lcn.saturating_add(skip).saturating_mul(self.csz);
                    let want = take.saturating_mul(self.csz) as usize;
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
        if stored.len() >= unit_bytes || !sutram_compress::lznt1::looks_compressed(&stored) {
            // Stored raw (incompressible unit).
            stored.resize(unit_bytes, 0);
            self.buf = stored;
        } else {
            let (out, clean) = sutram_compress::lznt1::decompress_unit(&stored, unit_bytes);
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
