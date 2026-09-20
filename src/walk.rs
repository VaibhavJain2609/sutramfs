//! The streaming directory walk: live + deleted entries, LFN assembly,
//! recovery assessment, orphan cluster chains, and error records.

use std::collections::{HashSet, VecDeque};

use sutram_fs::util;
use sutram_fs::{EntryKind, FsEntry, FsEntryStatus, FsError, RecoveryState, Result};

use crate::boot::FatType;
use crate::dirent::{self, DirEntry, LfnPart, Slot};
use crate::fs::FatFs;

/// Where a directory's entry table lives.
#[derive(Clone, Copy)]
pub(crate) enum DirLoc {
    /// Fixed root-dir region (FAT12/16).
    RootRegion,
    /// Cluster-chain directory (FAT32 root + all subdirectories).
    Chain(u32),
}

/// An activated directory scan in progress.
pub(crate) struct DirCursor {
    /// Path of this directory (for children paths).
    path: String,
    /// Raw entry table bytes.
    data: Vec<u8>,
    /// logical-pos → disk map: `(logical_start, disk_offset, len)` extents.
    map: Vec<(u64, u64, u64)>,
    /// Parse position in `data`.
    pos: usize,
    /// LFN parts collected for the next dirent.
    pending_lfn: Vec<LfnPart>,
    /// Whether any collected LFN part was itself deleted.
    lfn_partial: bool,
    /// We've passed a 0x00 end-of-directory marker — subsequent entries
    /// are forensic residue, flagged via `meta["beyond_eod"]`.
    beyond_eod: bool,
}

impl DirCursor {
    /// Absolute disk offset of the slot at `pos`.
    fn disk_offset(&self, pos: usize) -> u64 {
        for &(logical, disk, len) in &self.map {
            if (pos as u64) >= logical && (pos as u64) < logical + len {
                return disk + pos as u64 - logical;
            }
        }
        self.map.first().map(|(_, d, _)| *d).unwrap_or(0)
    }
}

/// Streaming `walk()` iterator — DFS/BFS over directories, then an orphan
/// cluster-chain pass.
pub(crate) struct Walk<'m> {
    fs: &'m FatFs,
    /// Ready-to-yield items (entries and error records).
    queue: VecDeque<Result<FsEntry>>,
    /// Directories discovered but not yet scanned `(path, loc)` — FIFO.
    pending_dirs: VecDeque<(String, DirLoc)>,
    /// Directory currently being scanned.
    cur: Option<DirCursor>,
    /// Clusters already accounted for (live map ∪ deleted chains seen) —
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
    pub(crate) fn new(fs: &'m FatFs) -> Self {
        let root = if fs.bs.fat_type == FatType::Fat32 {
            DirLoc::Chain(fs.bs.root_cluster)
        } else {
            DirLoc::RootRegion
        };
        Walk {
            fs,
            queue: VecDeque::new(),
            pending_dirs: VecDeque::from(vec![("/".to_string(), root)]),
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

    /// LFN checksum over the 11 raw 8.3 name bytes (per MS spec).
    fn lfn_checksum(raw: &[u8; 11]) -> u8 {
        let mut sum = 0u8;
        for &b in raw {
            sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(b);
        }
        sum
    }

    /// Turn one dirent into an [`FsEntry`] (or `None` to skip).
    fn emit_entry(
        &mut self,
        cur_path: &str,
        e: DirEntry,
        disk_offset: u64,
        lfn_parts: Vec<LfnPart>,
        lfn_partial: bool,
        beyond_eod: bool,
    ) -> Option<FsEntry> {
        if e.is_volume_label() {
            return None;
        }
        let short = dirent::name83(&e);
        if short == "." || short == ".." {
            return None;
        }
        // Verify the LFN↔8.3 binding: a mismatched checksum means the LFN
        // slots belong to a different (probably deleted) entry.
        let lfn_checksum_ok = lfn_parts
            .first()
            .map(|p| p.checksum == Self::lfn_checksum(&e.raw_name));
        let lfn = dirent::assemble_lfn(&lfn_parts);
        let name = lfn.clone().unwrap_or_else(|| short.clone());
        let path = util::join_path(cur_path, &name);
        let kind = if e.is_dir() {
            EntryKind::Directory
        } else {
            EntryKind::File
        };

        let mut meta = std::collections::HashMap::new();
        meta.insert("attributes".into(), format!("{:#04x}", e.attr));
        meta.insert("dos_name".into(), short.clone());
        if e.deleted {
            meta.insert("deleted_marker".into(), "0xe5".into());
        }
        if let Some(l) = &lfn {
            meta.insert("lfn".into(), l.clone());
            if let Some(ok) = lfn_checksum_ok {
                meta.insert("lfn_checksum_ok".into(), ok.to_string());
            }
        }
        if lfn_partial {
            meta.insert("lfn_partial".into(), "true".into());
        }
        if beyond_eod {
            meta.insert("beyond_eod".into(), "true".into());
        }
        if e.attr & dirent::ATTR_RO != 0 {
            meta.insert("readonly".into(), "true".into());
        }
        if e.attr & dirent::ATTR_HIDDEN != 0 {
            meta.insert("hidden".into(), "true".into());
        }
        if e.attr & dirent::ATTR_SYSTEM != 0 {
            meta.insert("system".into(), "true".into());
        }

        let csz = self.fs.bs.cluster_size;
        let (status, ranges);
        if e.deleted {
            let (state, surviving, notes) =
                self.fs.recovery_for(e.first_cluster, e.size as u64);
            for (i, n) in notes.iter().enumerate() {
                meta.insert(format!("recovery_note_{i}"), n.clone());
            }
            status = FsEntryStatus::Deleted { recovery: state };
            ranges = surviving;
            // Deleted chains become claimed so the orphan pass skips them.
            if let Ok(ch) = self.fs.chain(e.first_cluster, usize::MAX) {
                for c in ch {
                    self.claimed.insert(c);
                }
            } else if e.first_cluster >= 2 {
                self.claimed.insert(e.first_cluster);
            }
        } else {
            status = FsEntryStatus::Live;
            let cap = if kind == EntryKind::File {
                (e.size as u64).div_ceil(csz).max(1) as usize
            } else {
                usize::MAX
            };
            ranges = match self.fs.chain(e.first_cluster, cap) {
                Ok(ch) => self.fs.chain_ranges(&ch),
                Err(_) => Vec::new(),
            };
        }

        // Slack reporting: last cluster's tail beyond `size` is file slack —
        // historically significant (may hold overwritten/deleted data).
        if kind == EntryKind::File && e.size as u64 > 0 {
            let alloc = ranges.iter().map(|(_, l)| *l).sum::<u64>();
            if alloc > e.size as u64 && !ranges.is_empty() {
                let slack = alloc - e.size as u64;
                // slack starts at logical `size` inside the extents
                let mut acc = 0u64;
                let mut slack_off = None;
                for (off, len) in &ranges {
                    if acc + len > e.size as u64 {
                        slack_off = Some(off + (e.size as u64 - acc));
                        break;
                    }
                    acc += len;
                }
                if let Some(so) = slack_off {
                    meta.insert("slack_offset".into(), format!("{so:#x}"));
                    meta.insert("slack_len".into(), slack.to_string());
                }
            }
        }

        let mut entry = FsEntry {
            path,
            name,
            entry_id: e.first_cluster as u64,
            kind,
            size: e.size as u64,
            disk_offset,
            allocated_ranges: ranges,
            timestamps: dirent::timestamps(&e),
            status,
            meta,
            magic: None,
        };
        entry.magic = self.fs.magic_for(&entry);

        if kind == EntryKind::Directory && !e.deleted && e.first_cluster >= 2 {
            self.pending_dirs
                .push_back((entry.path.clone(), DirLoc::Chain(e.first_cluster)));
        }
        Some(entry)
    }

    /// Synthetic entry for a directory being activated (only the root —
    /// subdirs were emitted at discovery).
    fn root_entry(&self, loc: &DirLoc) -> FsEntry {
        let (disk_offset, ranges) = match *loc {
            DirLoc::RootRegion => (
                self.fs.bs.root_dir_offset,
                vec![(self.fs.bs.root_dir_offset, self.fs.bs.root_dir_size)],
            ),
            DirLoc::Chain(c) => {
                let (off, len) = self.fs.cluster_range(c);
                (off, vec![(off, len)])
            }
        };
        FsEntry {
            path: "/".into(),
            name: "/".into(),
            entry_id: 0,
            kind: EntryKind::Directory,
            size: 0,
            disk_offset,
            allocated_ranges: ranges,
            timestamps: Default::default(),
            status: FsEntryStatus::Live,
            meta: Default::default(),
            magic: None,
        }
    }

    /// Orphan pass: allocated clusters no live or deleted entry claimed.
    /// Each unclaimed chain becomes one entry under `/$ORPHANED/`.
    fn scan_orphans(&mut self) -> Option<Result<FsEntry>> {
        let count = self.fs.bs.count_of_clusters as u32;
        while self.scan_cluster <= count + 1 {
            let c = self.scan_cluster;
            self.scan_cluster += 1;
            let v = match self.fs.fat_entry(c) {
                Ok(v) => v,
                Err(e) => {
                    if let r @ Some(_) = self.fail(e) {
                        return r;
                    }
                    continue;
                }
            };
            let allocated = v != 0 && v != self.fs.bs.fat_type.bad();
            if !allocated || self.claimed.contains(&c) {
                continue;
            }
            // Unclaimed allocated cluster → follow and claim its chain.
            let chain = match self.fs.chain(c, usize::MAX) {
                Ok(ch) => ch,
                Err(e) => {
                    if let r @ Some(_) = self.fail(e) {
                        return r;
                    }
                    continue;
                }
            };
            for &cl in &chain {
                self.claimed.insert(cl);
            }
            let ranges = self.fs.chain_ranges(&chain);
            let size = chain.len() as u64 * self.fs.bs.cluster_size;
            let fat_off = self.fs.bs.fat_offset
                + (c as u64 * self.fs.bs.fat_type.entry_bits() as u64) / 8;
            let mut meta = std::collections::HashMap::new();
            meta.insert("orphan".into(), "true".into());
            meta.insert("note".into(),
                "allocated cluster chain referenced by no directory entry".into());
            meta.insert("size_note".into(), "allocation size; logical size unknown".into());
            let entry = FsEntry {
                path: util::orphan_path(c as u64),
                name: format!("chain_{c}"),
                entry_id: c as u64,
                kind: EntryKind::Other,
                size,
                disk_offset: fat_off,
                allocated_ranges: ranges,
                timestamps: Default::default(),
                status: FsEntryStatus::Deleted {
                    recovery: RecoveryState::Unknown,
                },
                meta,
                magic: None,
            };
            return Some(Ok(entry));
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
                    match self.fs.read_dir(&loc) {
                        Ok((data, map)) => {
                            if path == "/" {
                                self.queue.push_back(Ok(self.root_entry(&loc)));
                            }
                            self.cur = Some(DirCursor {
                                path,
                                data,
                                map,
                                pos: 0,
                                pending_lfn: Vec::new(),
                                lfn_partial: false,
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
            let slot = dirent::parse_slot(&cur.data[slot_at..slot_at + 32]);
            cur.pos += 32;
            let disk_offset = cur.disk_offset(slot_at);
            match slot {
                Slot::EndOfDir => {
                    // Keep scanning: deleted entries routinely survive past
                    // this marker — flagged via meta["beyond_eod"].
                    cur.beyond_eod = true;
                    cur.pending_lfn.clear();
                    cur.lfn_partial = false;
                }
                Slot::Lfn(part) => {
                    cur.lfn_partial |= part.deleted;
                    cur.pending_lfn.push(part);
                }
                Slot::Entry(e) => {
                    let parts = std::mem::take(&mut cur.pending_lfn);
                    let partial = std::mem::replace(&mut cur.lfn_partial, false);
                    let path = cur.path.clone();
                    let beyond = cur.beyond_eod;
                    match self.emit_entry(&path, e, disk_offset, parts, partial, beyond) {
                        Some(entry) => return Some(Ok(entry)),
                        None => continue,
                    }
                }
            }
        }
    }
}
