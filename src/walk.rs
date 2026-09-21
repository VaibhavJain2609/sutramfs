//! The streaming walk: live directory tree → dirent-slack carving →
//! unallocated-inode scan → orphan/ journal artefacts. Bounded memory:
//! one directory's bytes at a time, one bitmap block at a time.

use std::collections::{HashMap, HashSet, VecDeque};

use sutram_fs::util;
use sutram_fs::{
    EntryKind, FsEntry, FsEntryStatus, FsError, RecoveryState, Result, Timestamps,
};
use sutram_io::ByteSource;

use crate::dirent::{self, RawDirent};
use crate::fs::Ext4Fs;
use crate::inode::{self, Inode};

/// Cap on the orphan-list chain length (`s_last_orphan` → `i_dtime` links).
const MAX_ORPHAN_CHAIN: u32 = 1 << 20;

/// Walk phases.
enum Phase {
    /// Live tree + slack carving.
    Dirs,
    /// Unallocated-inode scan + allocated-unreferenced (orphan) pass.
    InodeScan,
    Done,
}

/// A directory being scanned.
struct DirCursor {
    path: String,
    data: Vec<u8>,
    /// logical-off → disk-off map for dirent provenance.
    map: Vec<(u64, u64, u64)>,
    blk: usize,
    pos: usize,
    /// Slack regions collected while scanning entries (carve afterwards).
    slacks: Vec<(usize, usize)>,
    /// Carving sub-phase: index into `slacks`, plus carved dirents found
    /// in the current slack region.
    slack_idx: usize,
    carved: VecDeque<RawDirent>,
}

/// Streaming `walk()` iterator.
pub(crate) struct Walk<'m> {
    fs: &'m Ext4Fs,
    queue: VecDeque<Result<FsEntry>>,
    pending_dirs: VecDeque<(String, u32)>,
    cur: Option<DirCursor>,
    /// Directory inodes already queued/walked (loop guard).
    seen_dirs: HashSet<u32>,
    /// Inos emitted as *live* entries → first path (hardlink detection).
    live_paths: HashMap<u32, String>,
    /// Inos already emitted as deleted artefacts (slack-carved or scanned).
    deleted_seen: HashSet<u32>,
    /// Inodes on the `s_last_orphan` chain.
    orphan_list: HashSet<u32>,
    phase: Phase,
    scan_ino: u32,
    finished: bool,
}

impl<'m> Walk<'m> {
    pub(crate) fn new(fs: &'m Ext4Fs) -> Self {
        Walk {
            fs,
            queue: VecDeque::new(),
            pending_dirs: VecDeque::from(vec![("/".to_string(), 2)]),
            cur: None,
            seen_dirs: HashSet::new(),
            live_paths: HashMap::new(),
            deleted_seen: HashSet::new(),
            orphan_list: HashSet::new(),
            phase: Phase::Dirs,
            scan_ino: 1,
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

    /// Shared FsEntry construction from an inode.
    #[allow(clippy::too_many_arguments)]
    fn base_entry(
        &mut self,
        inode: &Inode,
        path: String,
        name: String,
        disk_offset: u64,
        status: FsEntryStatus,
        ranges: Vec<(u64, u64)>,
        notes: Vec<String>,
    ) -> FsEntry {
        let kind = if inode.is_dir() {
            EntryKind::Directory
        } else if inode.is_symlink() {
            EntryKind::Symlink
        } else if inode.is_reg() {
            EntryKind::File
        } else {
            EntryKind::Other
        };
        let mut meta = HashMap::new();
        meta.insert("inode".into(), inode.ino.to_string());
        meta.insert("inode_offset".into(), format!("{:#x}", inode.disk_offset));
        meta.insert("mode".into(), format!("{:#06x}", inode.mode));
        meta.insert("uid".into(), inode.uid.to_string());
        meta.insert("gid".into(), inode.gid.to_string());
        // NFS file-handle generation — distinguishes inode-slot reuse.
        meta.insert("generation".into(), inode.generation.to_string());
        meta.insert("links_count".into(), inode.links_count.to_string());
        meta.insert("attributes".into(), format!("{:#x}", inode.flags));
        meta.insert(
            "mapping".into(),
            if inode.has_inline_data() {
                "inline"
            } else if inode.has_extents() {
                "extents"
            } else {
                "indirect"
            }
            .into(),
        );
        if inode.flags & inode::EXT4_INDEX_FL != 0 && inode.is_dir() {
            meta.insert("htree".into(), "true".into());
        }
        if inode.flags & inode::EXT4_ENCRYPT_FL != 0 {
            meta.insert("encrypted".into(), "true".into());
        }
        if inode.flags & inode::EXT4_CASEFOLD_FL != 0 {
            meta.insert("casefold".into(), "true".into());
        }
        if inode.flags & inode::EXT4_INLINE_DATA_FL != 0 {
            meta.insert("inline_data".into(), "true".into());
        }
        // xattrs: in-inode body + dedicated i_file_acl block.
        let mut xattrs = inode.ibody_xattr_names();
        if inode.file_acl != 0 {
            if let Ok(blk) = self
                .fs
                .src
                .read_slice(self.fs.block_off(inode.file_acl), self.fs.sb.block_size as usize)
            {
                xattrs.extend(inode::parse_xattr_block(&blk));
            }
        }
        if !xattrs.is_empty() {
            meta.insert("xattr_count".into(), xattrs.len().to_string());
            meta.insert("xattrs".into(), xattrs.join(";"));
        }
        // Fast symlink target lives in i_block; slow symlink in data.
        if inode.is_symlink() {
            let target = if inode.is_fast_symlink() {
                let n = (inode.size as usize).min(60);
                Some(String::from_utf8_lossy(&inode.block60[..n]).into_owned())
            } else if let Ok(runs) = self.fs.runs_of(inode) {
                runs.first().and_then(|r| {
                    self.fs
                        .src
                        .read_slice(
                            self.fs.block_off(r.phys),
                            (inode.size as usize).min(self.fs.sb.block_size as usize),
                        )
                        .ok()
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                })
            } else {
                None
            };
            if let Some(t) = target {
                meta.insert("symlink_target".into(), t);
            }
        }
        // File tail slack: allocated tail beyond `size` may hold residue.
        if kind == EntryKind::File && inode.size > 0 {
            let alloc: u64 = ranges.iter().map(|(_, l)| *l).sum();
            if alloc > inode.size {
                let mut acc = 0u64;
                for (off, len) in &ranges {
                    if acc + len > inode.size {
                        meta.insert("slack_offset".into(), format!("{:#x}", off + (inode.size - acc)));
                        meta.insert("slack_len".into(), (alloc - inode.size).to_string());
                        break;
                    }
                    acc += len;
                }
            }
        }
        for (i, n) in notes.iter().enumerate() {
            meta.insert(format!("recovery_note_{i}"), n.clone());
        }
        FsEntry {
            path,
            name,
            entry_id: inode.ino as u64,
            kind,
            size: inode.size,
            disk_offset,
            allocated_ranges: ranges,
            timestamps: inode.timestamps(),
            status,
            meta,
            magic: None,
        }
    }

    /// Emit a live dirent's entry (or push its subdir for later).
    fn emit_live(
        &mut self,
        parent: &str,
        de: &RawDirent,
        disk_offset: u64,
    ) -> Option<Result<FsEntry>> {
        if de.ino == 0 || de.name == "." || de.name == ".." {
            return None;
        }
        let inode = match self.fs.read_inode(de.ino) {
            Ok(i) => i,
            Err(e) => return self.fail(e),
        };
        let path = util::join_path(parent, &de.name);
        let mut allocated = true;
        match self.fs.inode_allocated(de.ino) {
            Ok(a) => allocated = a,
            Err(e) => {
                if let r @ Some(_) = self.fail(e) {
                    return r;
                }
            }
        }
        let ranges = match self.fs.map(&inode) {
            Ok(crate::extent::BlockMap::Runs(runs)) => self.fs.run_ranges(&runs),
            Ok(crate::extent::BlockMap::Inline { .. })
            | Ok(crate::extent::BlockMap::InlineDir) => {
                // Inline data lives inside the inode — point provenance
                // at the i_block payload (+ system.data spillover).
                self.fs.inline_ranges(&inode)
            }
            Ok(crate::extent::BlockMap::Empty) => Vec::new(),
            Err(e) => {
                if let r @ Some(_) = self.fail(e) {
                    return r;
                }
                Vec::new()
            }
        };
        let mut entry = self.base_entry(
            &inode,
            path.clone(),
            de.name.clone(),
            disk_offset,
            FsEntryStatus::Live,
            ranges,
            Vec::new(),
        );
        entry
            .meta
            .insert("file_type".into(), de.file_type.to_string());
        if !allocated {
            // Dirent is live but the inode slot is free — the inode contents
            // may be a stale deleted file. Report, don't hide it.
            entry
                .meta
                .insert("inode_unallocated".into(), "true".into());
        }
        if inode.is_reg() && inode.links_count > 1 {
            if let Some(first) = self.live_paths.get(&de.ino) {
                entry.meta.insert("hardlink_of".into(), first.clone());
            }
        }
        self.live_paths.entry(de.ino).or_insert(path.clone());
        entry.magic = self.fs.magic_for(&entry);
        if inode.is_dir() && self.seen_dirs.insert(de.ino) {
            self.pending_dirs.push_back((path, de.ino));
        }
        Some(Ok(entry))
    }

    /// Emit an entry for a dirent carved out of slack space — a deleted
    /// name (and its inode link) recovered from a live entry's `rec_len`.
    /// Returns `None` for duplicates; `Some(Err)` is queued via `fail`.
    fn emit_carved(
        &mut self,
        parent: &str,
        de: &RawDirent,
        disk_offset: u64,
    ) -> Option<Result<FsEntry>> {
        let path = util::join_path(parent, &de.name);
        let mut notes = vec!["dirent carved from rec_len slack".to_string()];
        if de.ino == 0 {
            // ext4 zeroes `inode` when deleting a block's first entry —
            // the name survives but the link to data is gone.
            notes.push("inode field cleared on delete".into());
            let mut e = self.dead_dirent_entry(path, de, disk_offset, notes);
            e.meta.insert("inode_cleared".into(), "true".into());
            return Some(Ok(e));
        }
        if self.deleted_seen.contains(&de.ino) {
            return None; // already emitted via another carved dirent
        }
        self.deleted_seen.insert(de.ino);
        match self.fs.inode_allocated(de.ino) {
            Ok(true) => {
                // The inode slot was reused — its current contents belong
                // to a live file, not the deleted one.
                notes.push(format!(
                    "inode {} reallocated{}",
                    de.ino,
                    self.live_paths
                        .get(&de.ino)
                        .map(|p| format!(" to {p}"))
                        .unwrap_or_default()
                ));
                let mut e = self.dead_dirent_entry(path, de, disk_offset, notes);
                e.entry_id = de.ino as u64;
                e.meta.insert("inode_reused".into(), "true".into());
                Some(Ok(e))
            }
            Ok(false) => match self.fs.read_inode(de.ino) {
                Ok(inode) if inode.is_plausible() => {
                    let (state, ranges, mut rnotes) = self.fs.recovery_for(&inode);
                    notes.append(&mut rnotes);
                    let mut e = self.base_entry(
                        &inode,
                        path,
                        de.name.clone(),
                        disk_offset,
                        FsEntryStatus::Deleted { recovery: state },
                        ranges,
                        notes,
                    );
                    e.meta.insert("carved_dirent".into(), "true".into());
                    e.magic = self.fs.magic_for(&e);
                    Some(Ok(e))
                }
                _ => {
                    notes.push("inode slot zeroed/unreadable".into());
                    let mut e = self.dead_dirent_entry(path, de, disk_offset, notes);
                    e.entry_id = de.ino as u64;
                    Some(Ok(e))
                }
            },
            Err(e) => self.fail(e),
        }
    }

    /// A metadata-only entry for a carved dirent whose inode is gone.
    fn dead_dirent_entry(
        &self,
        path: String,
        de: &RawDirent,
        disk_offset: u64,
        notes: Vec<String>,
    ) -> FsEntry {
        let kind = match de.file_type {
            dirent::FT_REG => EntryKind::File,
            dirent::FT_DIR => EntryKind::Directory,
            dirent::FT_SYMLINK => EntryKind::Symlink,
            _ => EntryKind::Other,
        };
        let mut meta = HashMap::new();
        meta.insert("carved_dirent".into(), "true".into());
        meta.insert("inode".into(), de.ino.to_string());
        meta.insert("file_type".into(), de.file_type.to_string());
        for (i, n) in notes.iter().enumerate() {
            meta.insert(format!("recovery_note_{i}"), n.clone());
        }
        FsEntry {
            path,
            name: de.name.clone(),
            entry_id: 0,
            kind,
            size: 0,
            disk_offset,
            allocated_ranges: Vec::new(),
            timestamps: Timestamps::default(),
            status: FsEntryStatus::Deleted {
                recovery: RecoveryState::Unrecoverable,
            },
            meta,
            magic: None,
        }
    }

    /// Emit an inode-only artefact (unallocated inode with surviving
    /// content, or an allocated-but-unreferenced orphan).
    fn emit_inode_artefact(&mut self, ino: u32) -> Option<Result<FsEntry>> {
        if self.deleted_seen.contains(&ino) || self.live_paths.contains_key(&ino) {
            return None;
        }
        let allocated = match self.fs.inode_allocated(ino) {
            Ok(a) => a,
            Err(e) => return self.fail(e),
        };
        // Unallocated inode in a group flagged INODE_UNINIT/INODE_ZEROED
        // is guaranteed zeroed — skip the read entirely.
        if !allocated
            && self.fs.inode_group_flags(ino)
                & (crate::gdt::BG_INODE_UNINIT | crate::gdt::BG_INODE_ZEROED)
                != 0
        {
            return None;
        }
        let inode = match self.fs.read_inode(ino) {
            Ok(i) => i,
            Err(e) => return self.fail(e),
        };
        if allocated {
            // Allocated inode with no live dirent → orphan artefact.
            if !inode.is_plausible() {
                return None; // reserved ino, never initialised
            }
            let mut notes = vec![
                "allocated inode unreferenced by any directory".to_string()
            ];
            if self.orphan_list.contains(&ino) {
                notes.push("on the orphan inode list (s_last_orphan chain)".into());
            }
            let (state, ranges) = if inode.is_dir() || inode.is_symlink() {
                (RecoveryState::Intact, self.fs.entry_ranges(&inode))
            } else {
                match self.fs.runs_of(&inode) {
                    Ok(r) => (RecoveryState::Intact, self.fs.run_ranges(&r)),
                    Err(e) => {
                        notes.push(format!("block map unreadable: {e}"));
                        (RecoveryState::Unknown, Vec::new())
                    }
                }
            };
            let mut e = self.base_entry(
                &inode,
                util::orphan_path(ino as u64),
                format!("ino_{ino}"),
                inode.disk_offset,
                FsEntryStatus::Deleted { recovery: state },
                ranges,
                notes,
            );
            e.meta.insert("orphan".into(), "true".into());
            if self.orphan_list.contains(&ino) {
                e.meta.insert("orphan_list".into(), "true".into());
            }
            if ino == self.fs.sb.journal_inum {
                e.meta.insert("journal".into(), "true".into());
                e.meta.insert(
                    "note".into(),
                    "jbd2 journal inode — see FsInfo.meta for journal state; \
                     transaction replay is a documented TODO"
                        .into(),
                );
            }
            self.deleted_seen.insert(ino);
            e.magic = self.fs.magic_for(&e);
            return Some(Ok(e));
        }
        // Unallocated inode: emit only if it still carries content —
        // a mode plus data or a deletion timestamp.
        if !inode.is_plausible() || (inode.blocks_512 == 0 && inode.dtime == 0 && inode.size == 0) {
            return None;
        }
        let mut notes = vec!["unallocated inode with surviving content".to_string()];
        if self.orphan_list.contains(&ino) {
            notes.push("on the orphan inode list".into());
        }
        let (state, ranges, mut rnotes) = self.fs.recovery_for(&inode);
        notes.append(&mut rnotes);
        let mut e = self.base_entry(
            &inode,
            util::orphan_path(ino as u64),
            format!("ino_{ino}"),
            inode.disk_offset,
            FsEntryStatus::Deleted { recovery: state },
            ranges,
            notes,
        );
        e.meta.insert("orphan".into(), "true".into());
        if self.orphan_list.contains(&ino) {
            e.meta.insert("orphan_list".into(), "true".into());
        }
        self.deleted_seen.insert(ino);
        e.magic = self.fs.magic_for(&e);
        Some(Ok(e))
    }

    /// Follow the `s_last_orphan` chain: each orphan inode's `i_dtime`
    /// links to the next. Bounded + visited-guarded.
    fn collect_orphan_list(&mut self) {
        let mut ino = self.fs.sb.last_orphan;
        while ino != 0 && self.orphan_list.len() < MAX_ORPHAN_CHAIN as usize {
            if !self.orphan_list.insert(ino) {
                break; // cycle
            }
            match self.fs.read_inode(ino) {
                Ok(i) => ino = i.dtime,
                Err(_) => break,
            }
        }
    }

    /// Advance the directory cursor one item. The cursor borrow is scoped
    /// so emitters can use `&mut self` freely.
    fn step_dir(&mut self) -> Option<Result<FsEntry>> {
        enum Found {
            Live(RawDirent, u64),
            Corrupt(u64),
            CarvePhase,
        }
        let found = {
            let cur = self.cur.as_mut()?;
            // Phase A: linear dirent scan.
            let mut found = None;
            while cur.pos < cur.data.len() {
                let bend = ((cur.pos / cur.blk) + 1) * cur.blk;
                let bend = bend.min(cur.data.len());
                if cur.pos + 8 > bend {
                    cur.pos = bend;
                    continue;
                }
                match dirent::dirent_at(&cur.data, cur.pos, bend) {
                    Some(d) => {
                        if let Some(s) = d.slack {
                            cur.slacks.push(s);
                        }
                        let pos = d.pos;
                        cur.pos = pos + d.rec_len.max(8) as usize;
                        if d.ino == 0 || d.name == "." || d.name == ".." {
                            continue; // dead slot / dots — never emitted
                        }
                        let disk = Ext4Fs::dir_disk_offset(&cur.map, pos as u64);
                        found = Some(Found::Live(d, disk));
                        break;
                    }
                    None => {
                        let disk = Ext4Fs::dir_disk_offset(&cur.map, cur.pos as u64);
                        cur.pos = bend;
                        found = Some(Found::Corrupt(disk));
                        break;
                    }
                }
            }
            found.unwrap_or(Found::CarvePhase)
        };
        match found {
            Found::Live(d, disk) => {
                let path = self.cur.as_ref()?.path.clone();
                self.emit_live(&path, &d, disk)
            }
            Found::Corrupt(disk) => self.fail(FsError::corrupt(
                disk,
                "invalid dirent header (rec_len)".to_string(),
            )),
            Found::CarvePhase => self.step_dir_carve(),
        }
    }

    /// Phase B of a directory scan: carve `rec_len` slack for deleted
    /// dirents and emit them. Returns `None` when the dir is exhausted.
    fn step_dir_carve(&mut self) -> Option<Result<FsEntry>> {
        // Pop the next carved dirent (filling `carved` per slack region).
        let next = {
            let cur = self.cur.as_mut()?;
            loop {
                if let Some(d) = cur.carved.pop_front() {
                    let disk = Ext4Fs::dir_disk_offset(&cur.map, d.pos as u64);
                    break Some((d, disk));
                }
                if cur.slack_idx >= cur.slacks.len() {
                    break None;
                }
                let (s, l) = cur.slacks[cur.slack_idx];
                cur.slack_idx += 1;
                let bend = (((s / cur.blk) + 1) * cur.blk).min(cur.data.len());
                for d in dirent::carve_slack(&cur.data, s, l, bend) {
                    cur.carved.push_back(d);
                }
            }
        };
        match next {
            Some((d, disk)) => {
                let path = self.cur.as_ref()?.path.clone();
                self.emit_carved(&path, &d, disk)
            }
            None => {
                self.cur = None;
                None
            }
        }
    }

    /// The unallocated-inode / orphan scan; one candidate per call.
    fn step_inode_scan(&mut self) -> Option<Result<FsEntry>> {
        while self.scan_ino <= self.fs.sb.inodes_count {
            let ino = self.scan_ino;
            self.scan_ino += 1;
            // Reserved inodes are skipped, except the journal inode which
            // is emitted as a named artefact.
            if ino < self.fs.sb.first_ino && ino != self.fs.sb.journal_inum {
                continue;
            }
            if let Some(item) = self.emit_inode_artefact(ino) {
                return Some(item);
            }
        }
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
            match self.phase {
                Phase::Dirs => {
                    if self.cur.is_none() {
                        match self.pending_dirs.pop_front() {
                            Some((path, ino)) => {
                                let inode = match self.fs.read_inode(ino) {
                                    Ok(i) => i,
                                    Err(e) => {
                                        if let r @ Some(_) = self.fail(e) {
                                            return r;
                                        }
                                        continue;
                                    }
                                };
                                if path == "/" {
                                    // Emit the root inode itself.
                                    let ranges = self.fs.entry_ranges(&inode);
                                    let e = self.base_entry(
                                        &inode,
                                        "/".into(),
                                        "/".into(),
                                        inode.disk_offset,
                                        FsEntryStatus::Live,
                                        ranges,
                                        Vec::new(),
                                    );
                                    self.live_paths.insert(2, "/".into());
                                    self.queue.push_back(Ok(e));
                                }
                                match self.fs.read_dir(&inode) {
                                    Ok((data, map)) => {
                                        self.cur = Some(DirCursor {
                                            path,
                                            data,
                                            map,
                                            blk: self.fs.sb.block_size as usize,
                                            pos: 0,
                                            slacks: Vec::new(),
                                            slack_idx: 0,
                                            carved: VecDeque::new(),
                                        });
                                    }
                                    Err(e) => {
                                        if let r @ Some(_) = self.fail(e) {
                                            return r;
                                        }
                                    }
                                }
                            }
                            None => {
                                self.phase = Phase::InodeScan;
                                if self.fs.opts.include_orphans {
                                    self.collect_orphan_list();
                                }
                            }
                        }
                        continue;
                    }
                    if let Some(item) = self.step_dir() {
                        return Some(item);
                    }
                }
                Phase::InodeScan => {
                    if !self.fs.opts.include_orphans {
                        self.phase = Phase::Done;
                        continue;
                    }
                    match self.step_inode_scan() {
                        Some(item) => return Some(item),
                        None => self.phase = Phase::Done,
                    }
                }
                Phase::Done => {
                    self.finished = true;
                }
            }
        }
    }
}
