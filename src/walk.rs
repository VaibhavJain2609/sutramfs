//! The streaming walk: linear MFT scan emitting live files/dirs, ADS
//! streams, hardlink paths, deleted records, BAAD/MFT-slack fragments and
//! orphans — then an INDX pass per live directory for slack residue.

use std::collections::{HashMap, HashSet, VecDeque};

use sutram_fs::util;
use sutram_fs::{
    EntryKind, FsEntry, FsEntryStatus, FsError, RecoveryState, Result, Timestamps,
};

use crate::attr::{self, Attr, FileName};
use crate::fs::{NtfsFs, ParsedFile, SlotState, Stream};
use crate::indx;
use crate::record::apply_indx_fixup;

/// Well-known metafile names for the reserved MFT slots.
pub(crate) fn metafile_name(rec_no: u64) -> Option<&'static str> {
    Some(match rec_no {
        0 => "$MFT",
        1 => "$MFTMirr",
        2 => "$LogFile",
        3 => "$Volume",
        4 => "$AttrDef",
        5 => ".",
        6 => "$Bitmap",
        7 => "$Boot",
        8 => "$BadClus",
        9 => "$Secure",
        10 => "$UpCase",
        11 => "$Extend",
        _ => return None,
    })
}

/// `true` for $STANDARD_INFORMATION DOS attribute bits we surface.
const DOS_RO: u32 = 0x01;
const DOS_HIDDEN: u32 = 0x02;
const DOS_SYSTEM: u32 = 0x04;

/// Streaming `walk()` iterator.
pub(crate) struct Walk<'m> {
    fs: &'m NtfsFs,
    queue: VecDeque<Result<FsEntry>>,
    /// Next MFT slot to process.
    rec_no: u64,
    /// Live directory records awaiting the INDX slack pass.
    indx_dirs: VecDeque<u64>,
    /// INDX pass finished.
    indx_done: bool,
    /// Terminal state.
    finished: bool,
}

impl<'m> Walk<'m> {
    pub(crate) fn new(fs: &'m NtfsFs) -> Self {
        Walk {
            fs,
            queue: VecDeque::new(),
            rec_no: 0,
            indx_dirs: VecDeque::new(),
            indx_done: false,
            finished: false,
        }
    }

    /// Record an error honouring strict mode.
    fn fail(&mut self, e: FsError) -> Option<Result<FsEntry>> {
        if self.fs.opts.strict {
            self.finished = true;
            Some(Err(e))
        } else {
            self.queue.push_back(Err(e));
            None
        }
    }

    /// Resolve a `(parent_rec, name)` to an absolute path by walking FN
    /// parent links through the mount-scan slot table. Returns
    /// `(path, reached_root)` — `reached_root == false` means the chain
    /// broke (orphan or stale parent link).
    fn resolve_path(&self, parent_rec: u64, name: &str) -> (String, bool) {
        if parent_rec == 5 || parent_rec == 0 {
            return (util::join_path("/", &util::sanitize_name(name)), true);
        }
        let mut components = vec![util::sanitize_name(name)];
        let mut cur = parent_rec;
        let mut seen: HashSet<u64> = HashSet::new();
        let mut reached = false;
        for _ in 0..64 {
            if cur == 5 {
                reached = true;
                break;
            }
            if !seen.insert(cur) {
                break; // cycle
            }
            let Some(slot) = self.fs.slots.get(cur as usize) else {
                break;
            };
            let Some(f) = best_fn(&slot.fns) else {
                break;
            };
            components.push(util::sanitize_name(&f.name));
            cur = crate::attr::file_ref_rec(f.parent_ref);
        }
        let mut path = String::new();
        for c in components.iter().rev() {
            path.push('/');
            path.push_str(c);
        }
        if path.is_empty() {
            path = "/".into();
        }
        (path, reached)
    }

    /// Decode the resident body of `attr` through the source.
    fn resident_body(&self, a: &Attr) -> Option<Vec<u8>> {
        let (off, len) = a.resident?;
        self.fs.src.read_slice(off, len as usize).ok()
    }

    /// Fill `meta`/`timestamps` with the SI and FN timestamp sets and the
    /// timestomp heuristic. Emits `si_*` and `fn_*` keys for *both* sets —
    /// the raw material for timestomp detection.
    fn timestamps_meta(
        &self,
        pf: &ParsedFile,
        fns: &[FileName],
        meta: &mut HashMap<String, String>,
    ) -> Timestamps {
        let mut ts = Timestamps::default();
        let mut si = None;
        for a in &pf.attrs {
            if a.type_code == attr::T_STANDARD_INFORMATION {
                si = self.resident_body(a).and_then(|b| attr::parse_si(&b));
                break;
            }
        }
        if let Some(s) = si {
            ts.created = Some(attr::filetime_ts(s.created));
            ts.modified = Some(attr::filetime_ts(s.modified));
            ts.accessed = Some(attr::filetime_ts(s.accessed));
            ts.changed = Some(attr::filetime_ts(s.mft_changed));
            // The DOS attribute flags live in $SI (RO/hidden/system/etc.)
            // — the FILE record's own flags are a different field.
            meta.insert("attributes".into(), format!("{:#06x}", s.file_attributes));
            meta.insert("si_created".into(), ns_or_unset(s.created));
            meta.insert("si_modified".into(), ns_or_unset(s.modified));
            meta.insert("si_mft_changed".into(), ns_or_unset(s.mft_changed));
            meta.insert("si_accessed".into(), ns_or_unset(s.accessed));
            if s.file_attributes & DOS_RO != 0 {
                meta.insert("readonly".into(), "true".into());
            }
            if s.file_attributes & DOS_HIDDEN != 0 {
                meta.insert("hidden".into(), "true".into());
            }
            if s.file_attributes & DOS_SYSTEM != 0 {
                meta.insert("system".into(), "true".into());
            }
            // Timestomp heuristic: SI fields are what tools like
            // timestomp.exe rewrite; FN fields lag behind. An SI create or
            // modify time *earlier* than its FN counterpart is impossible
            // under normal operation — FN copies SI at file creation and
            // only moves forward on rename/move.
            if let Some(f) = fns.first() {
                let mut suspect = Vec::new();
                if s.created != 0 && f.created != 0 && s.created < f.created {
                    suspect.push("si_created<fn_created");
                }
                if s.modified != 0 && f.modified != 0 && s.modified < f.modified {
                    suspect.push("si_modified<fn_modified");
                }
                if s.mft_changed != 0 && f.mft_changed != 0 && s.mft_changed < f.mft_changed {
                    suspect.push("si_mft_changed<fn_mft_changed");
                }
                if s.accessed != 0 && f.accessed != 0 && s.accessed < f.accessed {
                    suspect.push("si_accessed<fn_accessed");
                }
                if !suspect.is_empty() {
                    meta.insert("timestomp_suspect".into(), suspect.join(","));
                }
            }
        }
        if let Some(f) = fns.first() {
            meta.insert("fn_created".into(), ns_or_unset(f.created));
            meta.insert("fn_modified".into(), ns_or_unset(f.modified));
            meta.insert("fn_mft_changed".into(), ns_or_unset(f.mft_changed));
            meta.insert("fn_accessed".into(), ns_or_unset(f.accessed));
            if si.is_none() {
                // No SI (damaged record): FN is the only timestamp set.
                ts.created = Some(attr::filetime_ts(f.created));
                ts.modified = Some(attr::filetime_ts(f.modified));
                ts.accessed = Some(attr::filetime_ts(f.accessed));
                ts.changed = Some(attr::filetime_ts(f.mft_changed));
            }
        }
        ts
    }

    /// Common meta fields for any record-derived entry.
    fn base_meta(&self, pf: &ParsedFile, data_idx: usize) -> HashMap<String, String> {
        let mut meta = HashMap::new();
        meta.insert("mft_record".into(), pf.rec.record_no.to_string());
        meta.insert("mft_offset".into(), format!("{:#x}", pf.rec.offset));
        meta.insert("record_seq".into(), pf.rec.sequence.to_string());
        meta.insert("link_count".into(), pf.rec.link_count.to_string());
        meta.insert("data_stream_index".into(), data_idx.to_string());
        if !pf.ext_records.is_empty() {
            meta.insert(
                "extension_records".into(),
                pf.ext_records
                    .iter()
                    .map(|r| r.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        if let Some(e) = &pf.attr_error {
            meta.insert("note".into(), format!("attribute parse: {e}"));
        }
        meta
    }

    /// Assess recoverability of a deleted stream: surviving extents =
    /// runlist minus clusters now claimed by live records.
    fn recovery_for_stream(&self, s: &Stream) -> (RecoveryState, Vec<(u64, u64)>, Vec<String>) {
        let mut notes = Vec::new();
        if let Some((off, len)) = s.resident {
            // Resident data lives inside the (surviving) record itself.
            return (
                RecoveryState::Intact,
                vec![(off, len as u64)],
                notes,
            );
        }
        let csz = self.fs.bs.cluster_size;
        if s.runs.is_empty() {
            if s.real_size == 0 {
                return (RecoveryState::Intact, Vec::new(), notes);
            }
            notes.push("no data runs survived in record".into());
            return (RecoveryState::Unrecoverable, Vec::new(), notes);
        }
        let (surviving, mut n) = self.fs.surviving_runs(&s.runs);
        notes.append(&mut n);
        let expected = s.real_size.div_ceil(csz);
        let allocated: u64 = s
            .runs
            .iter()
            .filter(|r| r.lcn.is_some())
            .fold(0u64, |a, r| a.saturating_add(r.len));
        let sparse: u64 = s
            .runs
            .iter()
            .filter(|r| r.lcn.is_none())
            .fold(0u64, |a, r| a.saturating_add(r.len));
        if allocated < expected && sparse == 0 {
            notes.push(format!(
                "runlist covers {allocated} of {expected} expected clusters"
            ));
        }
        if sparse > 0 {
            notes.push(format!("{sparse} sparse cluster(s) (zero-filled content)"));
        }
        // Survivors carry their logical VCN: only clusters inside the
        // file's [0, real_size) window count as recoverable bytes — data
        // beyond the logical end (partially-trimmed tail) does not.
        let eof_vcn = s.real_size.div_ceil(csz);
        let mut surviving_bytes: u64 = 0;
        let mut ranges = Vec::new();
        for &(vcn, lcn, len) in &surviving {
            // Clusters of this extent that fall inside [0, eof_vcn).
            let in_file = eof_vcn.saturating_sub(vcn).min(len);
            surviving_bytes = surviving_bytes.saturating_add(in_file.saturating_mul(csz));
            let off = lcn.saturating_mul(csz);
            ranges.push((
                off,
                len.saturating_mul(csz)
                    .min(self.fs.src.len().saturating_sub(off)),
            ));
        }
        // Clusters in-window that survive = surviving extents ∩ [0,eof).
        let surviving_in_window: u64 = surviving
            .iter()
            .map(|&(vcn, _, len)| eof_vcn.saturating_sub(vcn).min(len))
            .sum();
        // Sparse holes inside the window are trivially recoverable — they
        // read as zeros. Credit them so a deleted sparse file is not
        // under-reported as partially overwritten.
        let sparse_in_window: u64 = s
            .runs
            .iter()
            .filter(|r| r.lcn.is_none())
            .map(|r| eof_vcn.saturating_sub(r.vcn).min(r.len))
            .sum();
        // $BITMAP cross-check: extents still marked allocated suggest the
        // deletion never fully committed (or $BITMAP itself is stale).
        // Bounded per extent — hostile runlists can declare astronomic
        // lengths, and this is an advisory note, not the verdict.
        let marked: u64 = surviving
            .iter()
            .take(4096)
            .map(|&(_, l, len)| {
                (0..len.min(4096))
                    .filter(|&c| {
                        self.fs.cluster_allocated(l.saturating_add(c)) == Some(true)
                    })
                    .count() as u64
            })
            .sum();
        if marked > 0 {
            notes.push(format!(
                "{marked} surviving cluster(s) still marked allocated in $BITMAP"
            ));
        }
        // Recoverable bytes = surviving in-window bytes + sparse zeros,
        // capped at the logical size.
        let recoverable_bytes = surviving_bytes
            .saturating_add(sparse_in_window.saturating_mul(csz))
            .min(s.real_size);
        let state = if expected == 0
            || surviving_in_window + sparse_in_window >= expected
        {
            RecoveryState::Intact
        } else if recoverable_bytes == 0 {
            RecoveryState::Unrecoverable
        } else {
            RecoveryState::PartiallyOverwritten {
                recovered_bytes: recoverable_bytes,
                total_bytes: s.real_size,
            }
        };
        (state, ranges, notes)
    }

    /// Emit every entry for one parsed base record (live or deleted).
    /// Returns items to queue; directories get queued for the INDX pass.
    fn emit_record(&mut self, pf: ParsedFile, deleted: bool, fragment: bool) {
        let rec = &pf.rec;
        let data_streams = NtfsFs::group_streams(&pf.attrs, attr::T_DATA);
        let fns: Vec<FileName> = pf
            .attrs
            .iter()
            .filter(|a| a.type_code == attr::T_FILE_NAME)
            .filter_map(|a| self.resident_body(a))
            .filter_map(|b| attr::parse_fn(&b))
            .collect();
        // Name + path: prefer a non-DOS FN; metafiles and FN-less records
        // get synthesized names.
        let best = best_fn(&fns);
        let (display_name, parent_rec) = match best {
            Some(f) => (f.name.clone(), crate::attr::file_ref_rec(f.parent_ref)),
            None => (
                metafile_name(rec.record_no)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("$RECORD_{}", rec.record_no)),
                5,
            ),
        };
        let (path, reached_root) = if rec.record_no == 5 {
            ("/".to_string(), true) // root dir
        } else {
            self.resolve_path(parent_rec, &display_name)
        };

        let mut meta = self.base_meta(&pf, 0);
        let timestamps = self.timestamps_meta(&pf, &fns, &mut meta);
        if !meta.contains_key("attributes") {
            // No $SI decoded — fall back to the record flags.
            meta.insert("attributes".into(), format!("{:#06x}", rec.flags));
        }
        if let Some(f) = best {
            meta.insert("fn_namespace".into(), f.namespace.to_string());
            meta.insert("fn_real_size".into(), f.real_size.to_string());
            // DOS-namespace alias (the 8.3 name) is evidence of its own.
            for f2 in &fns {
                if f2.namespace == 2 && !std::ptr::eq(f2, f) {
                    meta.insert("dos_name".into(), f2.name.clone());
                }
            }
        }
        // Reparse point → symlink detection + EA + object id.
        let mut kind = if rec.is_dir() {
            EntryKind::Directory
        } else {
            EntryKind::File
        };
        let mut ea_names = Vec::new();
        for a in &pf.attrs {
            match a.type_code {
                attr::T_REPARSE_POINT => {
                    if let Some((tag, target)) =
                        self.resident_body(a).as_deref().and_then(attr::parse_reparse)
                    {
                        meta.insert("reparse_tag".into(), format!("{tag:#010x}"));
                        if let Some(t) = target {
                            meta.insert("symlink_target".into(), t);
                            kind = EntryKind::Symlink;
                        }
                    }
                }
                attr::T_EA => {
                    if let Some(body) = self.resident_body(a) {
                        ea_names = attr::parse_ea(&body)
                            .into_iter()
                            .map(|(n, _)| n)
                            .collect();
                    }
                }
                attr::T_EA_INFORMATION => {
                    meta.insert("ea_present".into(), "true".into());
                }
                attr::T_OBJECT_ID => {
                    if let Some(id) =
                        self.resident_body(a).as_deref().and_then(attr::parse_object_id)
                    {
                        meta.insert("object_id".into(), id);
                    }
                }
                _ => {}
            }
        }
        if !ea_names.is_empty() {
            meta.insert("ea_names".into(), ea_names.join(","));
        }
        if matches!(display_name.as_str(), "$LogFile" | "$UsnJrnl" | "$BadClus" | "$Secure")
            || (2..=11).contains(&rec.record_no)
        {
            meta.insert("system_file".into(), "true".into());
        }

        // ---- status / recovery ------------------------------------------
        let unnamed_idx = data_streams.iter().position(|s| s.name.is_none());
        let unnamed = unnamed_idx.map(|i| &data_streams[i]);
        let size_fallback = best.map(|f| f.real_size).unwrap_or(0);

        let status;
        let primary_ranges;
        if deleted || fragment {
            let note = if fragment {
                "MFT slack: FILE record fragment beyond $MFT used size"
            } else if &rec.signature == b"BAAD" {
                "BAAD record (chkdsk-flagged/torn)"
            } else {
                "MFT record with in-use flag clear"
            };
            // The deletion *evidence* differs per case — an in-use flag
            // still set in slack means the MFT shrank around a once-live
            // record; BAAD means chkdsk/torn-write marking.
            let marker = if fragment {
                if rec.in_use() {
                    "mft_slack_inuse"
                } else {
                    "mft_slack"
                }
            } else if &rec.signature == b"BAAD" {
                "baad_record"
            } else {
                "mft_inactive"
            };
            meta.insert("deleted_marker".into(), marker.into());
            meta.insert("recovery_note_0".into(), note.into());
            if fragment {
                meta.insert("mft_slack".into(), "true".into());
            }
            if &rec.signature == b"BAAD" {
                meta.insert("baad".into(), "true".into());
            }
            // $MFT bitmap cross-check: a slot still marked allocated is
            // fresher evidence (deletion may not have committed).
            if let Some(bm) = &self.fs.mft_bitmap {
                let bit_set = bm
                    .get((rec.record_no / 8) as usize)
                    .map(|b| b & (1 << (rec.record_no % 8)) != 0)
                    .unwrap_or(false);
                if bit_set && !rec.in_use() {
                    meta.insert("mft_bitmap_inuse".into(), "true".into());
                }
            }
            match unnamed {
                Some(s) => {
                    let (state, ranges, notes) = self.recovery_for_stream(s);
                    for (i, n) in notes.iter().enumerate() {
                        meta.insert(format!("recovery_note_{}", i + 1), n.clone());
                    }
                    status = FsEntryStatus::Deleted { recovery: state };
                    primary_ranges = ranges;
                }
                None => {
                    let state = if rec.is_dir() {
                        // Directories: assess INDEX_ALLOCATION instead.
                        let idx_streams =
                            NtfsFs::group_streams(&pf.attrs, attr::T_INDEX_ALLOCATION);
                        if let Some(s) = idx_streams.first() {
                            let (state, _r, _n) = self.recovery_for_stream(s);
                            state
                        } else {
                            RecoveryState::Unknown
                        }
                    } else if fns.is_empty() && data_streams.is_empty() {
                        RecoveryState::Unknown
                    } else {
                        RecoveryState::Unrecoverable
                    };
                    status = FsEntryStatus::Deleted { recovery: state };
                    primary_ranges = Vec::new();
                }
            }
        } else {
            status = FsEntryStatus::Live;
            primary_ranges = unnamed
                .map(|s| s.ranges(self.fs.bs.cluster_size, self.fs.src.len()))
                .unwrap_or_default();
        };

        // Orphan: live/deleted record whose parent chain never reaches root.
        let is_orphan = !reached_root && rec.record_no != 5 && rec.record_no > 15;
        let (final_path, final_name) = if is_orphan {
            meta.insert("orphan".into(), "true".into());
            meta.insert("orphan_name".into(), display_name.clone());
            (
                format!("/$ORPHANED/{}", util::sanitize_name(&display_name)),
                util::sanitize_name(&display_name),
            )
        } else {
            (path.clone(), util::sanitize_name(&display_name))
        };

        // Primary entry (unnamed $DATA stream, or the FN size for
        // data-less records like directories and meta stubs).
        let unnamed_stream_idx = unnamed_idx.unwrap_or(0);
        let mut primary_meta = meta.clone();
        primary_meta.insert("data_stream_index".into(), unnamed_stream_idx.to_string());
        let mut entry = FsEntry {
            path: final_path.clone(),
            name: final_name.clone(),
            entry_id: (rec.record_no << 16) | (unnamed_stream_idx as u64),
            kind,
            size: unnamed.map(|s| s.real_size).unwrap_or(size_fallback),
            disk_offset: rec.offset,
            allocated_ranges: primary_ranges,
            timestamps: timestamps.clone(),
            status,
            meta: primary_meta,
            magic: None,
        };
        // Sparse/compressed/encrypted flags are honest evidence for
        // deleted entries too — and they keep `magic_for` from verdicting
        // on undecodable content.
        if let Some(s) = unnamed {
            decorate_stream_meta(&mut entry.meta, s, self.fs.bs.cluster_size);
        }
        entry.magic = self.fs.magic_for(&entry);
        self.queue.push_back(Ok(entry));

        // Hardlinks: every additional non-DOS FN is another path to the
        // same record+data (aliases carrying the *same* name+parent are
        // collapsed — real hardlinks differ in name or directory).
        if fns.len() > 1 {
            for f in &fns {
                if f.namespace == 2 {
                    continue; // DOS alias of the primary name
                }
                let parent = crate::attr::file_ref_rec(f.parent_ref);
                if let Some(b) = best {
                    if f.name == b.name && parent == parent_rec {
                        continue; // same path as primary (ns 1/3 pair)
                    }
                }
                let (lpath, reached) = self.resolve_path(parent, &f.name);
                let mut m = meta.clone();
                m.insert("hardlink".into(), "true".into());
                m.insert("fn_namespace".into(), f.namespace.to_string());
                let (lpath, lname) = if !reached {
                    m.insert("orphan".into(), "true".into());
                    (
                        format!("/$ORPHANED/{}", util::sanitize_name(&f.name)),
                        util::sanitize_name(&f.name),
                    )
                } else {
                    (lpath, util::sanitize_name(&f.name))
                };
                let mut e = FsEntry {
                    path: lpath,
                    name: lname,
                    entry_id: (rec.record_no << 16) | (unnamed_stream_idx as u64),
                    kind,
                    size: unnamed.map(|s| s.real_size).unwrap_or(f.real_size),
                    disk_offset: rec.offset,
                    allocated_ranges: unnamed
                        .map(|s| s.ranges(self.fs.bs.cluster_size, self.fs.src.len()))
                        .unwrap_or_default(),
                    timestamps: timestamps.clone(),
                    status,
                    meta: m,
                    magic: None,
                };
                if let Some(s) = unnamed {
                    decorate_stream_meta(&mut e.meta, s, self.fs.bs.cluster_size);
                }
                e.magic = self.fs.magic_for(&e);
                self.queue.push_back(Ok(e));
            }
        }

        // ADS: each named $DATA stream is its own entry.
        for (i, s) in data_streams.iter().enumerate() {
            let Some(ads) = &s.name else { continue };
            let ads_name = util::sanitize_name(ads);
            let mut m = meta.clone();
            m.insert("ads".into(), "true".into());
            m.insert("stream_name".into(), ads.clone());
            m.insert("data_stream_index".into(), i.to_string());
            let (ads_status, ranges) = if deleted || fragment {
                let (st, r, notes) = self.recovery_for_stream(s);
                for (j, n) in notes.iter().enumerate() {
                    m.insert(format!("recovery_note_{}", j + 1), n.clone());
                }
                (FsEntryStatus::Deleted { recovery: st }, r)
            } else {
                (
                    FsEntryStatus::Live,
                    s.ranges(self.fs.bs.cluster_size, self.fs.src.len()),
                )
            };
            let mut e = FsEntry {
                path: format!("{final_path}:{ads_name}"),
                name: format!("{final_name}:{ads_name}"),
                entry_id: (rec.record_no << 16) | (i as u64),
                kind: EntryKind::File,
                size: s.real_size,
                disk_offset: rec.offset,
                allocated_ranges: ranges,
                timestamps: timestamps.clone(),
                status: ads_status,
                meta: m,
                magic: None,
            };
            decorate_stream_meta(&mut e.meta, s, self.fs.bs.cluster_size);
            e.magic = self.fs.magic_for(&e);
            self.queue.push_back(Ok(e));
        }

        // Queue live dirs for the INDX slack pass.
        if rec.is_dir() && rec.in_use() && !fragment {
            self.indx_dirs.push_back(rec.record_no);
        }
    }

    /// Emit an orphan entry for an extension record whose base record is
    /// not live (or missing).
    fn emit_orphan_extent(&mut self, rec_no: u64) {
        match self.fs.parse_record(rec_no) {
            Ok(rec) => {
                let (attrs, _) = NtfsFs::collect_attrs(&rec);
                let fns: Vec<FileName> = attrs
                    .iter()
                    .filter(|a| a.type_code == attr::T_FILE_NAME)
                    .filter_map(|a| self.resident_body(a))
                    .filter_map(|b| attr::parse_fn(&b))
                    .collect();
                let mut meta = HashMap::new();
                meta.insert("orphan".into(), "true".into());
                meta.insert("mft_record".into(), rec_no.to_string());
                meta.insert("mft_offset".into(), format!("{:#x}", rec.offset));
                meta.insert(
                    "note".into(),
                    "extension record whose base record is not in use".into(),
                );
                let name = best_fn(&fns)
                    .map(|f| f.name.clone())
                    .unwrap_or_else(|| format!("extent_{rec_no}"));
                let e = FsEntry {
                    path: util::orphan_path(rec_no),
                    name: util::sanitize_name(&name),
                    entry_id: rec_no << 16,
                    kind: EntryKind::Other,
                    size: 0,
                    disk_offset: rec.offset,
                    allocated_ranges: Vec::new(),
                    timestamps: Default::default(),
                    status: FsEntryStatus::Deleted {
                        recovery: RecoveryState::Unknown,
                    },
                    meta,
                    magic: None,
                };
                self.queue.push_back(Ok(e));
            }
            Err(e) => {
                let _ = self.fail(e);
            }
        }
    }

    /// INDX slack pass over one live directory: emit deleted-name residue
    /// found beyond the used region of each index node, plus live-region
    /// entries pointing at inactive/reused records (dangling).
    fn scan_indx(&mut self, dir_rec: u64) {
        let pf = match self.fs.parse_full(dir_rec) {
            Ok(p) => p,
            Err(e) => {
                let _ = self.fail(e);
                return;
            }
        };
        let dir_fns: Vec<FileName> = pf
            .attrs
            .iter()
            .filter(|a| a.type_code == attr::T_FILE_NAME)
            .filter_map(|a| self.resident_body(a))
            .filter_map(|b| attr::parse_fn(&b))
            .collect();
        let dir_name = best_fn(&dir_fns)
            .map(|f| f.name.clone())
            .unwrap_or_else(|| format!("dir_{dir_rec}"));
        let dir_parent = best_fn(&dir_fns)
            .map(|f| crate::attr::file_ref_rec(f.parent_ref))
            .unwrap_or(5);
        let (dir_path, _) = if dir_rec == 5 {
            ("/".to_string(), true)
        } else {
            self.resolve_path(dir_parent, &dir_name)
        };

        // $INDEX_ROOT resident body → index header at +0x10.
        for a in pf.attrs.iter().filter(|a| a.type_code == attr::T_INDEX_ROOT) {
            let Some(body) = self.resident_body(a) else {
                continue;
            };
            let Some((hdr_off, _ty)) = indx::index_root(&body) else {
                continue;
            };
            let Some(hdr) = indx::index_header(&body, hdr_off) else {
                continue;
            };
            let abs_hdr = a.resident.map(|(o, _)| o).unwrap_or(0) + hdr_off as u64;
            self.emit_indx_entries(&body, hdr_off, hdr, abs_hdr, &dir_path);
        }

        // $INDEX_ALLOCATION: non-resident INDX blocks.
        let csz = self.fs.bs.cluster_size;
        let irec = self.fs.bs.index_record_size as usize;
        // Hard cap: a hostile runlist can declare astronomic run lengths —
        // real directory indexes are a handful of records.
        const MAX_INDX_BLOCKS: usize = 8192;
        let mut blocks = 0usize;
        'alloc: for a in pf
            .attrs
            .iter()
            .filter(|a| a.type_code == attr::T_INDEX_ALLOCATION)
        {
            for r in &a.runs {
                let Some(lcn) = r.lcn else { continue };
                let mut off = lcn.saturating_mul(csz);
                let end = off.saturating_add(r.len.saturating_mul(csz));
                while end.saturating_sub(off) >= irec as u64 {
                    if blocks >= MAX_INDX_BLOCKS {
                        break 'alloc;
                    }
                    blocks += 1;
                    let raw = match self.fs.src.read_slice(off, irec) {
                        Ok(b) => b,
                        Err(e) => {
                            let _ = self.fail(FsError::Io(e));
                            break;
                        }
                    };
                    if raw.iter().all(|&b| b == 0) {
                        off += irec as u64;
                        continue;
                    }
                    let mut blk = raw;
                    if let Err(e) =
                        apply_indx_fixup(&mut blk, off, self.fs.bs.bytes_per_sector as usize)
                    {
                        let _ = self.fail(e);
                        off += irec as u64;
                        continue;
                    }
                    match indx::indx_record_header(&blk, off) {
                        Ok((_vcn, hdr_off)) => {
                            if let Some(hdr) = indx::index_header(&blk, hdr_off) {
                                self.emit_indx_entries(
                                    &blk,
                                    hdr_off,
                                    hdr,
                                    off + hdr_off as u64,
                                    &dir_path,
                                );
                            }
                        }
                        Err(e) => {
                            let _ = self.fail(e);
                        }
                    }
                    off += irec as u64;
                }
            }
        }
    }

    /// Emit slack + dangling residue entries from one index node.
    /// `data` = the node bytes, `hdr_off` = index-header offset inside it,
    /// `abs_hdr` = absolute disk offset of that header.
    fn emit_indx_entries(
        &mut self,
        data: &[u8],
        hdr_off: usize,
        hdr: indx::IndexHeader,
        abs_hdr: u64,
        dir_path: &str,
    ) {
        let node_end = hdr.alloc_len.min(data.len().saturating_sub(hdr_off));
        // Within-used entries: flag dangling file refs (target inactive or
        // sequence-reused) — the index entry outlived the MFT record.
        let live_entries = indx::index_entries(data, hdr_off, hdr.entries_off, hdr.used_len.min(node_end));
        for e in &live_entries {
            if e.is_end {
                continue;
            }
            let dangling = match self.fs.slots.get(e.record_no as usize) {
                Some(s) if s.in_use && s.seq == (e.file_ref >> 48) as u16 => false,
                Some(s) if s.in_use => true, // reused slot, different generation
                _ => true,
            };
            if !dangling {
                continue;
            }
            self.emit_indx_residue(data, e, abs_hdr, dir_path, "indx_dangling");
        }
        // Slack region: bytes between used and allocated — deleted residue.
        if hdr.used_len < node_end {
            let slack =
                indx::index_entries(data, hdr_off, hdr.used_len, node_end);
            for e in &slack {
                if e.is_end || e.body_len < 0x42 {
                    continue;
                }
                self.emit_indx_residue(data, e, abs_hdr, dir_path, "indx_slack");
            }
        }
    }

    fn emit_indx_residue(
        &mut self,
        data: &[u8],
        e: &indx::IndexEntry,
        abs_hdr: u64,
        dir_path: &str,
        source: &str,
    ) {
        let Some(body) = data.get(e.body_off..e.body_off + e.body_len) else {
            return;
        };
        let Some(f) = attr::parse_fn(body) else {
            return;
        };
        let name = util::sanitize_name(&f.name);
        let mut meta = HashMap::new();
        meta.insert("source".into(), source.into());
        meta.insert("target_record".into(), e.record_no.to_string());
        meta.insert("target_ref".into(), format!("{:#x}", e.file_ref));
        meta.insert("deleted_marker".into(), "indx_residue".into());
        meta.insert("fn_created".into(), ns_or_unset(f.created));
        meta.insert("fn_modified".into(), ns_or_unset(f.modified));
        meta.insert("fn_mft_changed".into(), ns_or_unset(f.mft_changed));
        meta.insert("fn_accessed".into(), ns_or_unset(f.accessed));
        let entry = FsEntry {
            path: format!("{}/{}", dir_path.trim_end_matches('/'), name)
                .replace("//", "/"),
            name: name.clone(),
            entry_id: 0x8000_0000_0000_0000 | (e.record_no << 16),
            kind: EntryKind::File,
            size: f.real_size,
            disk_offset: abs_hdr + e.rel_off as u64,
            allocated_ranges: Vec::new(),
            timestamps: Timestamps {
                created: Some(attr::filetime_ts(f.created)),
                modified: Some(attr::filetime_ts(f.modified)),
                accessed: Some(attr::filetime_ts(f.accessed)),
                changed: Some(attr::filetime_ts(f.mft_changed)),
                deleted: None,
            },
            status: FsEntryStatus::Deleted {
                recovery: RecoveryState::Unknown,
            },
            meta,
            magic: None,
        };
        self.queue.push_back(Ok(entry));
    }
}

/// Pick the best display FN: prefer WIN32 (1) or WIN32&DOS (3) over the
/// 8.3 DOS (2) alias; POSIX (0) acceptable.
fn best_fn(fns: &[FileName]) -> Option<&FileName> {
    fns.iter()
        .find(|f| f.namespace != 2)
        .or_else(|| fns.first())
}

/// FILETIME → ns string for `si_*`/`fn_*` meta values (`"0"` = unset).
fn ns_or_unset(raw: u64) -> String {
    match attr::filetime_ts(raw).value {
        Some(v) => v.to_string(),
        None => "0".into(),
    }
}

/// Sparse/compressed/encrypted + slack meta for a live stream entry.
fn decorate_stream_meta(meta: &mut HashMap<String, String>, s: &Stream, csz: u64) {
    if s.compressed {
        meta.insert("compressed".into(), "lznt1".into());
        meta.insert(
            "compression_unit_clusters".into(),
            (1u64 << s.comp_shift).to_string(),
        );
    }
    if s.sparse {
        meta.insert("sparse".into(), "true".into());
    }
    if s.encrypted {
        meta.insert("encrypted".into(), "true".into());
    }
    if s.attr_offsets.len() > 1 {
        meta.insert(
            "attr_offsets".into(),
            s.attr_offsets
                .iter()
                .map(|o| format!("{o:#x}"))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if s.resident.is_none() {
        let alloc: u64 = s
            .runs
            .iter()
            .filter(|r| r.lcn.is_some())
            .fold(0u64, |acc, r| {
                acc.saturating_add(r.len.saturating_mul(csz))
            });
        if alloc > s.real_size {
            meta.insert("slack_len".into(), (alloc - s.real_size).to_string());
        }
    }
}

impl Iterator for Walk<'_> {
    type Item = Result<FsEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.finished {
                return None;
            }
            if let Some(item) = self.queue.pop_front() {
                return Some(item);
            }
            // ---- MFT slot scan -------------------------------------------
            while (self.rec_no as usize) < self.fs.slots.len() {
                let rec_no = self.rec_no;
                self.rec_no += 1;
                let (state, base_ref, slot_off, slot_err) = {
                    let slot = &self.fs.slots[rec_no as usize];
                    (
                        slot.state,
                        slot.base_ref,
                        slot.offset,
                        slot.error.clone(),
                    )
                };
                match state {
                    SlotState::Empty => continue,
                    SlotState::Corrupt => {
                        let e = FsError::corrupt(
                            slot_off,
                            slot_err.unwrap_or_else(|| "unparseable MFT record".into()),
                        );
                        if let r @ Some(_) = self.fail(e) {
                            return r;
                        }
                        continue;
                    }
                    SlotState::Live => {
                        if base_ref != 0 {
                            // Extension record: merged into its base — emit
                            // an orphan only when the base is gone.
                            let base = crate::attr::file_ref_rec(base_ref);
                            let base_live = self
                                .fs
                                .slots
                                .get(base as usize)
                                .map(|s| s.in_use)
                                .unwrap_or(false);
                            if !base_live && self.fs.opts.include_orphans {
                                self.emit_orphan_extent(rec_no);
                            }
                            continue;
                        }
                        match self.fs.parse_full(rec_no) {
                            Ok(pf) => {
                                self.emit_record(pf, false, false);
                                if let Some(item) = self.queue.pop_front() {
                                    return Some(item);
                                }
                            }
                            Err(e) => {
                                if let r @ Some(_) = self.fail(e) {
                                    return r;
                                }
                            }
                        }
                    }
                    SlotState::Free | SlotState::Baad | SlotState::Fragment => {
                        let fragment = state == SlotState::Fragment;
                        match self.fs.parse_full(rec_no) {
                            Ok(pf) => {
                                self.emit_record(pf, !fragment, fragment);
                                if let Some(item) = self.queue.pop_front() {
                                    return Some(item);
                                }
                            }
                            Err(e) => {
                                if let r @ Some(_) = self.fail(e) {
                                    return r;
                                }
                            }
                        }
                    }
                }
            }
            // ---- INDX slack pass ------------------------------------------
            if !self.indx_done {
                if let Some(dir) = self.indx_dirs.pop_front() {
                    self.scan_indx(dir);
                    continue;
                }
                self.indx_done = true;
                continue;
            }
            self.finished = true;
        }
    }
}
