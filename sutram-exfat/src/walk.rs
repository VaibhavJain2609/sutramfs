//! The streaming directory walk: live + deleted entry sets, stray
//! secondary salvage, recovery assessment, orphan cluster chains, and
//! error records.

use std::collections::{HashSet, VecDeque};

use sutram_fs::util;
use sutram_fs::{
    EntryKind, FsEntry, FsEntryStatus, FsError, RecoveryState, Result, Timestamps,
};

use crate::dirent::{self, FileSet};
use crate::fs::ExFatFs;

/// Where a directory's entry stream lives.
#[derive(Clone, Copy)]
pub(crate) struct DirLoc {
    pub first_cluster: u32,
    /// `NoFatChain` — the directory is one contiguous extent of `len` bytes.
    pub contiguous: bool,
    /// DataLength from the stream extension (0 = unknown → whole chain).
    pub len: u64,
}

/// An activated directory scan in progress.
pub(crate) struct DirCursor {
    /// Path of this directory (for children paths).
    path: String,
    /// Raw entry-table bytes.
    data: Vec<u8>,
    /// logical-pos → disk map: `(logical_start, disk_offset, len)` extents.
    map: Vec<(u64, u64, u64)>,
    /// Parse position in `data`.
    pos: usize,
    /// We've passed a 0x00 end-of-directory marker — subsequent entries are
    /// forensic residue, flagged via `meta["beyond_eod"]`.
    beyond_eod: bool,
}

impl DirCursor {
    /// Absolute disk offset of the slot at logical `pos`.
    fn disk_offset(&self, pos: usize) -> u64 {
        for &(logical, disk, len) in &self.map {
            if (pos as u64) >= logical && (pos as u64) < logical + len {
                return disk + pos as u64 - logical;
            }
        }
        self.map.first().map(|(_, d, _)| *d).unwrap_or(0)
    }
}

/// Streaming `walk()` iterator — BFS over directories, then an orphan
/// cluster-chain pass.
pub(crate) struct Walk<'m> {
    fs: &'m ExFatFs,
    /// Ready-to-yield items (entries and error records).
    queue: VecDeque<Result<FsEntry>>,
    /// Directories discovered but not yet scanned `(path, loc)` — FIFO.
    /// Includes *deleted* directories: their member sets were all deleted
    /// with them, and their slack still parses.
    pending_dirs: VecDeque<(String, DirLoc)>,
    /// Directory first-clusters already activated (loop guard).
    visited_dirs: HashSet<u32>,
    /// Directory currently being scanned.
    cur: Option<DirCursor>,
    /// Clusters already accounted for (live map ∪ deleted extents seen) —
    /// the orphan pass emits the allocated remainder.
    claimed: HashSet<u32>,
    /// Orphan scan progress (cluster index).
    scan_cluster: u32,
    /// Orphan pass completed.
    orphans_done: bool,
    /// Terminal state (strict abort or natural end).
    finished: bool,
}

impl<'m> Walk<'m> {
    pub(crate) fn new(fs: &'m ExFatFs) -> Self {
        Walk {
            fs,
            queue: VecDeque::new(),
            pending_dirs: VecDeque::from(vec![(
                "/".to_string(),
                DirLoc {
                    first_cluster: fs.bs.root_cluster,
                    contiguous: false,
                    len: 0,
                },
            )]),
            visited_dirs: HashSet::new(),
            cur: None,
            claimed: fs.live.keys().copied().collect(),
            scan_cluster: 2,
            orphans_done: false,
            finished: false,
        }
    }

    /// Record an error honouring strict mode: lenient queues it and keeps
    /// going; strict emits it once then ends the walk.
    fn fail(&mut self, e: FsError) -> Option<Result<FsEntry>> {
        if self.fs.opts.strict {
            self.finished = true;
            Some(Err(e))
        } else {
            self.queue.push_back(Err(e));
            None
        }
    }

    /// UTC-offset meta value, e.g. `+02:00` / `-03:30` / `utc`.
    fn tz_string(minutes: i32) -> String {
        if minutes == 0 {
            return "utc".into();
        }
        let sign = if minutes < 0 { "-" } else { "+" };
        let m = minutes.unsigned_abs();
        format!("{sign}{:02}:{:02}", m / 60, m % 60)
    }

    /// Shared meta map for any file-set-derived entry.
    fn set_meta(&self, set: &FileSet, beyond_eod: bool) -> std::collections::HashMap<String, String> {
        let mut meta = std::collections::HashMap::new();
        meta.insert("attributes".into(), format!("{:#06x}", set.attr));
        meta.insert(
            "secondary_count".into(),
            set.secondary_count.to_string(),
        );
        meta.insert(
            "set_checksum".into(),
            format!("{:#06x}", set.set_checksum),
        );
        if let Some(ok) = set.checksum_ok {
            meta.insert("checksum_ok".into(), ok.to_string());
        } else {
            meta.insert(
                "checksum_ok".into(),
                "unverifiable (truncated set)".into(),
            );
        }
        if set.secondaries_seen < set.secondary_count as usize {
            meta.insert(
                "note".into(),
                format!(
                    "entry set truncated: {} of {} secondaries present",
                    set.secondaries_seen, set.secondary_count
                ),
            );
        }
        if set.has_stream {
            meta.insert("name_hash".into(), format!("{:#06x}", set.name_hash));
            meta.insert(
                "valid_data_length".into(),
                set.valid_len.to_string(),
            );
            meta.insert("data_length".into(), set.data_len.to_string());
            if set.no_fat_chain {
                meta.insert("no_fat_chain".into(), "true".into());
            }
            if set.data_len < set.valid_len {
                meta.insert(
                    "size_note".into(),
                    "valid_data_length exceeds data_length (corrupt)".into(),
                );
            }
        } else {
            meta.insert("note".into(), "no stream extension survives".into());
        }
        for (key, off) in [
            ("created_utc_offset", set.tz_minutes[0]),
            ("modified_utc_offset", set.tz_minutes[1]),
            ("accessed_utc_offset", set.tz_minutes[2]),
        ] {
            if let Some(m) = off {
                meta.insert(key.into(), Self::tz_string(m));
            }
        }
        if set.deleted {
            meta.insert("deleted_marker".into(), "entry_type_inuse_cleared".into());
        }
        if beyond_eod {
            meta.insert("beyond_eod".into(), "true".into());
        }
        if set.attr & dirent::ATTR_RO != 0 {
            meta.insert("readonly".into(), "true".into());
        }
        if set.attr & dirent::ATTR_HIDDEN != 0 {
            meta.insert("hidden".into(), "true".into());
        }
        if set.attr & dirent::ATTR_SYSTEM != 0 {
            meta.insert("system".into(), "true".into());
        }
        if set.attr & dirent::ATTR_ARCHIVE != 0 {
            meta.insert("archive".into(), "true".into());
        }
        meta
    }

    /// Compute extents + status for a set, and record slack metadata.
    fn extents_and_status(
        &mut self,
        set: &FileSet,
        kind: EntryKind,
        meta: &mut std::collections::HashMap<String, String>,
    ) -> (FsEntryStatus, Vec<(u64, u64)>) {
        let csz = self.fs.bs.cluster_size;
        if set.deleted {
            if !set.has_stream {
                return (
                    FsEntryStatus::Deleted {
                        recovery: RecoveryState::Unknown,
                    },
                    Vec::new(),
                );
            }
            let (state, ranges, notes) = self.fs.recovery_for(
                set.first_cluster,
                set.valid_len,
                set.data_len,
                set.no_fat_chain,
            );
            for (i, n) in notes.iter().enumerate() {
                meta.insert(format!("recovery_note_{i}"), n.clone());
            }
            // Claim the expected extent so the orphan pass skips it
            // (relevant when no bitmap is present).
            if set.no_fat_chain {
                for c in self.fs.contiguous_clusters(set.first_cluster, set.data_len.max(set.valid_len))
                {
                    self.claimed.insert(c);
                }
            } else if let Ok(ch) = self.fs.chain(set.first_cluster, usize::MAX) {
                for c in ch {
                    self.claimed.insert(c);
                }
            }
            return (FsEntryStatus::Deleted { recovery: state }, ranges);
        }
        // Live entry.
        let status = FsEntryStatus::Live;
        let alloc_len = set.data_len.max(set.valid_len);
        let ranges = if !set.has_stream || alloc_len == 0 || !self.fs.valid_cluster(set.first_cluster)
        {
            Vec::new()
        } else if set.no_fat_chain {
            self.fs
                .chain_ranges(&self.fs.contiguous_clusters(set.first_cluster, alloc_len))
        } else {
            let needed = if kind == EntryKind::Directory {
                usize::MAX
            } else {
                alloc_len.div_ceil(csz).max(1) as usize
            };
            match self.fs.chain(set.first_cluster, needed) {
                Ok(ch) => self.fs.chain_ranges(&ch),
                Err(_) => Vec::new(),
            }
        };
        // File slack: allocation tail beyond ValidDataLength.
        if kind == EntryKind::File && set.valid_len > 0 {
            let alloc = ranges.iter().map(|(_, l)| *l).sum::<u64>();
            if alloc > set.valid_len && !ranges.is_empty() {
                let slack = alloc - set.valid_len;
                let mut acc = 0u64;
                for (off, len) in &ranges {
                    if acc + len > set.valid_len {
                        meta.insert(
                            "slack_offset".into(),
                            format!("{:#x}", off + (set.valid_len - acc)),
                        );
                        meta.insert("slack_len".into(), slack.to_string());
                        break;
                    }
                    acc += len;
                }
            }
        }
        (status, ranges)
    }

    /// Turn one parsed file entry set into an [`FsEntry`].
    fn emit_set(
        &mut self,
        dir_path: &str,
        set: FileSet,
        disk_offset: u64,
        beyond_eod: bool,
    ) -> FsEntry {
        let name = set
            .name
            .clone()
            .unwrap_or_else(|| format!("NONAME_{disk_offset:08X}"));
        let path = util::join_path(dir_path, &name);
        let kind = if set.is_dir() {
            EntryKind::Directory
        } else {
            EntryKind::File
        };
        let mut meta = self.set_meta(&set, beyond_eod);
        let (status, ranges) = self.extents_and_status(&set, kind, &mut meta);
        let size = if set.has_stream { set.valid_len } else { 0 };
        let ts = set.timestamps.clone();
        let fc = set.first_cluster;
        let dir_loc = DirLoc {
            first_cluster: fc,
            contiguous: set.no_fat_chain,
            // max(): a damaged set may carry a small DataLength with a
            // larger ValidDataLength — under-sizing would clip the scan.
            len: set.data_len.max(set.valid_len),
        };
        let is_dir = set.is_dir();

        let mut entry = FsEntry {
            path,
            name,
            // The primary entry's disk offset is the stable identifier —
            // unique even for zero-length files with no cluster.
            entry_id: disk_offset,
            kind,
            size,
            disk_offset,
            allocated_ranges: ranges,
            timestamps: ts,
            status,
            meta,
            magic: None,
        };
        entry.magic = self.fs.magic_for(&entry);

        // Recurse into live *and* deleted directories — a deleted dir's
        // member sets retain their cleared in-use bits and still parse.
        if is_dir && self.fs.valid_cluster(fc) && !self.visited_dirs.contains(&fc) {
            self.pending_dirs.push_back((entry.path.clone(), dir_loc));
        }
        entry
    }

    /// Synthetic entry for the root directory.
    fn root_entry(&self) -> FsEntry {
        let (off, len) = self
            .fs
            .cluster_range(self.fs.bs.root_cluster)
            .unwrap_or((0, 0));
        FsEntry {
            path: "/".into(),
            name: "/".into(),
            entry_id: 0,
            kind: EntryKind::Directory,
            size: 0,
            disk_offset: off,
            allocated_ranges: vec![(off, len)],
            timestamps: Default::default(),
            status: FsEntryStatus::Live,
            meta: Default::default(),
            magic: None,
        }
    }

    /// Salvage a run of secondary entries that lost their primary (partial
    /// overwrite of a deleted set). Emitted as a deleted file when a stream
    /// extension survives; `None` otherwise.
    fn salvage_secondaries(
        &mut self,
        dir_path: &str,
        slots: &[(u64, [u8; 32])],
    ) -> Option<FsEntry> {
        let mut has_stream = false;
        let mut no_fat_chain = false;
        let mut name_len = 0u8;
        let mut valid_len = 0u64;
        let mut data_len = 0u64;
        let mut first_cluster = 0u32;
        let mut units: Vec<u16> = Vec::new();
        let disk_offset = slots.first().map(|(o, _)| *o).unwrap_or(0);
        for (_, s) in slots {
            match dirent::code(s[0]) {
                dirent::CODE_STREAM => {
                    has_stream = true;
                    no_fat_chain = s[1] & dirent::FLAG_NO_FAT_CHAIN != 0;
                    name_len = s[3];
                    valid_len = sutram_io::le::u64(s, 8).unwrap_or(0);
                    first_cluster = sutram_io::le::u32(s, 20).unwrap_or(0);
                    data_len = sutram_io::le::u64(s, 24).unwrap_or(0);
                }
                dirent::CODE_NAME => {
                    for j in 0..15 {
                        if let Some(u) = sutram_io::le::u16(s, 2 + j * 2) {
                            units.push(u);
                        }
                    }
                }
                _ => {}
            }
        }
        if !has_stream {
            return None;
        }
        let name = if name_len > 0 && !units.is_empty() {
            let n = (name_len as usize).min(units.len());
            let n = util::sanitize_name(&String::from_utf16_lossy(&units[..n]));
            if n.is_empty() {
                format!("NONAME_{disk_offset:08X}")
            } else {
                n
            }
        } else {
            format!("NONAME_{disk_offset:08X}")
        };
        let (state, ranges, notes) = self.fs.recovery_for(
            first_cluster,
            valid_len,
            data_len,
            no_fat_chain,
        );
        // Claim the apparent extent so the orphan pass skips it.
        if no_fat_chain {
            for c in self.fs.contiguous_clusters(first_cluster, data_len.max(valid_len)) {
                self.claimed.insert(c);
            }
        } else if let Ok(ch) = self.fs.chain(first_cluster, usize::MAX) {
            for c in ch {
                self.claimed.insert(c);
            }
        }
        let mut meta = std::collections::HashMap::new();
        meta.insert("orphan".into(), "true".into());
        meta.insert(
            "note".into(),
            "secondary entry set without a primary file entry (partial overwrite?)".into(),
        );
        meta.insert("no_fat_chain".into(), no_fat_chain.to_string());
        meta.insert("valid_data_length".into(), valid_len.to_string());
        for (i, n) in notes.iter().enumerate() {
            meta.insert(format!("recovery_note_{i}"), n.clone());
        }
        let mut entry = FsEntry {
            path: util::join_path(dir_path, &name),
            name,
            entry_id: disk_offset,
            kind: EntryKind::File,
            size: valid_len,
            disk_offset,
            allocated_ranges: ranges,
            timestamps: Timestamps::default(),
            status: FsEntryStatus::Deleted { recovery: state },
            meta,
            magic: None,
        };
        entry.magic = self.fs.magic_for(&entry);
        Some(entry)
    }

    /// Orphan pass: allocated clusters no live or deleted entry claimed.
    /// Each unclaimed chain becomes one entry under `/$ORPHANED/`.
    fn scan_orphans(&mut self) -> Option<Result<FsEntry>> {
        // Only clusters whose first byte is actually in the image can be
        // read or carved — the declared count can exceed a partial image.
        let count = (self.fs.bs.cluster_count as u64).min(self.fs.bs.present_clusters);
        while (self.scan_cluster as u64) < count + 2 {
            let c = self.scan_cluster;
            self.scan_cluster += 1;
            if !self.fs.allocated(c) || self.claimed.contains(&c) {
                continue;
            }
            // Unclaimed allocated cluster → follow and claim its chain.
            let mut chain = match self.fs.chain(c, usize::MAX) {
                Ok(ch) => ch,
                Err(e) => {
                    if let r @ Some(_) = self.fail(e) {
                        return r;
                    }
                    continue;
                }
            };
            if chain.is_empty() {
                chain.push(c); // allocated but unlinked — report it anyway
            }
            for &cl in &chain {
                self.claimed.insert(cl);
            }
            let ranges = self.fs.chain_ranges(&chain);
            let size = chain.len() as u64 * self.fs.bs.cluster_size;
            let fat_off = self.fs.bs.fat_offset + c as u64 * 4;
            let mut meta = std::collections::HashMap::new();
            meta.insert("orphan".into(), "true".into());
            meta.insert(
                "note".into(),
                "allocated cluster chain referenced by no directory entry".into(),
            );
            meta.insert(
                "size_note".into(),
                "allocation size; logical size unknown".into(),
            );
            return Some(Ok(FsEntry {
                path: util::orphan_path(c as u64),
                name: format!("chain_{c}"),
                entry_id: c as u64,
                kind: EntryKind::Other,
                size,
                disk_offset: fat_off,
                allocated_ranges: ranges,
                timestamps: Timestamps {
                    ..Default::default()
                },
                status: FsEntryStatus::Deleted {
                    recovery: RecoveryState::Unknown,
                },
                meta,
                magic: None,
            }));
        }
        self.orphans_done = true;
        None
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
            // Activate the next pending directory.
            if self.cur.is_none() {
                if let Some((path, loc)) = self.pending_dirs.pop_front() {
                    if !self.visited_dirs.insert(loc.first_cluster) {
                        continue;
                    }
                    match self.fs.read_dir(&loc) {
                        Ok((data, map)) => {
                            if path == "/" {
                                self.queue.push_back(Ok(self.root_entry()));
                            }
                            self.cur = Some(DirCursor {
                                path,
                                data,
                                map,
                                pos: 0,
                                beyond_eod: false,
                            });
                        }
                        Err(e) => {
                            if let r @ Some(_) = self.fail(e) {
                                return r;
                            }
                        }
                    }
                    continue;
                }
                // No more directories → orphan pass, then done.
                if !self.orphans_done {
                    if self.fs.opts.include_orphans {
                        if let Some(item) = self.scan_orphans() {
                            return Some(item);
                        }
                        continue;
                    }
                    self.orphans_done = true;
                    continue;
                }
                self.finished = true;
                continue;
            }

            // Parse the next 32-byte slot of the active directory.
            let cur = self.cur.as_mut().unwrap();
            if cur.pos + 32 > cur.data.len() {
                self.cur = None;
                continue;
            }
            let slot_at = cur.pos;
            let entry_type = cur.data[slot_at];
            let disk_offset = cur.disk_offset(slot_at);
            let path = cur.path.clone();
            let beyond = cur.beyond_eod;

            if entry_type == 0 {
                // End-of-directory: keep scanning — deleted entry sets
                // routinely survive in directory slack past this marker.
                cur.beyond_eod = true;
                cur.pos += 32;
                continue;
            }

            if dirent::is_secondary(entry_type) {
                // Stray secondary run — the primary is gone (partial
                // overwrite of a deleted set, or slack garbage).
                let mut slots = Vec::new();
                while cur.pos + 32 <= cur.data.len()
                    && dirent::is_secondary(cur.data[cur.pos])
                {
                    let off = cur.pos;
                    let mut raw = [0u8; 32];
                    raw.copy_from_slice(&cur.data[off..off + 32]);
                    slots.push((cur.disk_offset(off), raw));
                    cur.pos += 32;
                }
                if let Some(entry) = self.salvage_secondaries(&path, &slots) {
                    return Some(Ok(entry));
                }
                continue;
            }

            cur.pos += 32;
            // Benign primaries (bitmap, upcase, label, GUID, padding,
            // vendor-defined) are parsed at mount, not emitted as entries.
            if dirent::code(entry_type) == dirent::CODE_FILE {
                let data = &self.cur.as_ref().unwrap().data;
                match dirent::parse_file_set(data, slot_at) {
                    Ok((set, used)) => {
                        // Consume the secondaries we examined.
                        let cur = self.cur.as_mut().unwrap();
                        cur.pos = slot_at + used * 32;
                        let entry = self.emit_set(&path, set, disk_offset, beyond);
                        return Some(Ok(entry));
                    }
                    Err(msg) => {
                        if let r @ Some(_) = self.fail(FsError::corrupt(disk_offset, msg)) {
                            return r;
                        }
                    }
                }
            }
        }
    }
}
