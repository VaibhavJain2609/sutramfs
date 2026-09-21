//! Streaming filesystem walk.
//!
//! Emission order:
//!
//! 1. errors collected at mount (AG headers, btree walks, live scan),
//! 2. the live tree — BFS from `sb_rootino`, one `FsEntry` at a time,
//!    with stale directory-entry residue emitted as deleted entries at
//!    the point it's found,
//! 3. free inodes with surviving residue (inobt free bitmaps; the
//!    recently-freed set is cross-checked against finobt),
//! 4. the `agi_unlinked` chains (unlinked-but-open inodes),
//! 5. allocated-but-unreachable inodes (orphans; `include_orphans`).
//!
//! Strict mode aborts the walk on the first error record.

use std::collections::{HashMap, HashSet, VecDeque};

use sutram_fs::util::{join_path, orphan_path, sanitize_name};
use sutram_fs::{EntryKind, FsEntry, FsEntryStatus, FsError, RecoveryState, Result, Timestamps};

use crate::dir::{parse_shortform, scan_residue, RawDirent};
use crate::fs::XfsFs;
use crate::inode::{Inode, FMT_BTREE, FMT_EXTENTS, FMT_LOCAL};
use crate::sb::NULLAGINO;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Drain errors collected while mounting.
    MountErrors,
    /// BFS over the live directory tree.
    Live,
    /// inobt free-bitmap scan → deleted inodes with residue.
    FreeInodes,
    /// agi_unlinked chains → unlinked-but-allocated inodes.
    Unlinked,
    /// Allocated but unreachable inodes (orphans).
    Orphans,
    Done,
}

pub(crate) struct Walk<'m> {
    fs: &'m XfsFs,
    phase: Phase,
    /// Ready items (entries and error records).
    pending: VecDeque<Result<FsEntry>>,
    /// Directory BFS queue: (ino, path).
    dirs: VecDeque<(u64, String)>,
    /// Directory inos already queued (cycle guard).
    seen_dirs: HashSet<u64>,
    /// Inode numbers already emitted (live, residue, deleted, orphan).
    emitted: HashSet<u64>,
    /// inobt scan cursor: (ag, record, bit).
    fi: (usize, usize, u32),
    /// Orphan scan cursor.
    orc: (usize, usize, u32),
    /// agi_unlinked cursor: (ag, bucket, current agino in chain).
    ul: (usize, usize, u32),
    ul_seen: HashSet<u64>,
    /// Total deleted/orphan records emitted — hard cap.
    deleted_emitted: usize,
    /// Stop after the pending queue drains (strict abort).
    stopped: bool,
}

const MAX_DELETED: usize = 1 << 22;
const MAX_UNLINKED_STEPS: usize = 1 << 16;

impl<'m> Walk<'m> {
    pub(crate) fn new(fs: &'m XfsFs) -> Self {
        let mut pending: VecDeque<Result<FsEntry>> = VecDeque::new();
        for e in &fs.mount_errors {
            pending.push_back(Err(clone_err(e)));
        }
        // Emit the root directory entry itself.
        match fs.inode(fs.sb.rootino) {
            Ok(inode) => {
                let e = fs.make_entry(
                    &inode,
                    "/",
                    "/".to_string(),
                    FsEntryStatus::Live,
                    None,
                    HashMap::new(),
                );
                pending.push_back(Ok(e));
            }
            Err(e) => pending.push_back(Err(e)),
        }
        Walk {
            fs,
            phase: Phase::MountErrors,
            pending,
            dirs: VecDeque::from([(fs.sb.rootino, "/".to_string())]),
            seen_dirs: HashSet::from([fs.sb.rootino]),
            emitted: HashSet::from([fs.sb.rootino]),
            fi: (0, 0, 0),
            orc: (0, 0, 0),
            ul: (0, 0, NULLAGINO),
            ul_seen: HashSet::new(),
            deleted_emitted: 0,
            stopped: false,
        }
    }

    /// One live directory → entries + residue + queued children.
    fn process_dir(&mut self, ino: u64, path: &str) {
        let inode = match self.fs.inode(ino) {
            Ok(i) => i,
            Err(e) => {
                self.push(Err(e));
                return;
            }
        };
        // Collect live dirents and (for extent dirs) residue.
        match inode.format {
            FMT_LOCAL => {
                match parse_shortform(
                    inode.dfork(),
                    inode.disk_off + inode.core as u64,
                    &self.fs.sb,
                ) {
                    Ok((_, ents)) => self.emit_dirents(&ents, path),
                    Err(e) => self.push(Err(e)),
                }
            }
            FMT_EXTENTS | FMT_BTREE => {
                let exts = match self.fs.data_extents(&inode) {
                    Ok(e) => e,
                    Err(e) => {
                        self.push(Err(e));
                        return;
                    }
                };
                for item in self.fs.dir_blocks(&inode, &exts) {
                    match item {
                        Ok((blk_off, blk)) => {
                            let raw = blk.raw.clone();
                            self.emit_dirents(&blk.entries, path);
                            // Stale residue inside freed regions.
                            for run in &blk.unused {
                                let stale = scan_residue(&raw, *run, blk_off, &self.fs.sb);
                                self.emit_residue(&stale, path);
                            }
                        }
                        Err(e) => self.push(Err(e)),
                    }
                }
            }
            _ => {
                self.push(Err(FsError::corrupt(
                    inode.disk_off,
                    "directory inode has non-directory format",
                )));
            }
        }
    }

    /// Emit live entries for a dirent list.
    fn emit_dirents(&mut self, ents: &[RawDirent], path: &str) {
        for d in ents {
            if d.name == b"." || d.name == b".." {
                continue;
            }
            let name = sanitize_name(&String::from_utf8_lossy(&d.name));
            let child_path = join_path(path, &name);
            match self.fs.inode(d.ino) {
                Ok(child) => {
                    let mut extra = HashMap::new();
                    if d.ftype != 0 {
                        extra.insert("dirent_ftype".into(), d.ftype.to_string());
                    }
                    let e = self.fs.make_entry(
                        &child,
                        &name,
                        child_path.clone(),
                        FsEntryStatus::Live,
                        Some(d.off),
                        extra,
                    );
                    self.emitted.insert(d.ino);
                    if e.kind == EntryKind::Directory && self.seen_dirs.insert(d.ino) {
                        self.dirs.push_back((d.ino, child_path));
                    }
                    self.push(Ok(e));
                }
                Err(e) => self.push(Err(e)),
            }
        }
    }

    /// Emit deleted entries recovered from freed dirent residue.
    fn emit_residue(&mut self, stale: &[RawDirent], path: &str) {
        for d in stale {
            if d.ino == 0 || self.deleted_emitted >= MAX_DELETED {
                continue;
            }
            let name = sanitize_name(&String::from_utf8_lossy(&d.name));
            if name.is_empty() {
                continue;
            }
            let child_path = join_path(path, &name);
            let mut extra = HashMap::new();
            extra.insert("stale_residue".into(), "dirent".into());
            extra.insert("dirent_offset".into(), format!("{:#x}", d.off));
            if d.ino_truncated {
                extra.insert(
                    "ino_truncated".into(),
                    "only low 32 bits of inode number survive".into(),
                );
            }
            if self.fs.live_inos.contains(&d.ino) {
                extra.insert(
                    "recovery_note_0".into(),
                    format!("inode {:#x} reallocated to a live file", d.ino),
                );
                let e = self.minimal_entry(&name, child_path, d, extra);
                self.deleted_emitted += 1;
                self.push(Ok(e));
                continue;
            }
            match self.fs.inode(d.ino) {
                Ok(inode) if inode.has_residue() => {
                    let e = self.fs.make_entry(
                        &inode,
                        &name,
                        child_path,
                        FsEntryStatus::Deleted {
                            recovery: RecoveryState::Unknown,
                        },
                        Some(d.off),
                        extra,
                    );
                    self.emitted.insert(d.ino);
                    self.deleted_emitted += 1;
                    self.push(Ok(e));
                }
                Ok(_) => {
                    extra.insert(
                        "recovery_note_0".into(),
                        "inode slot carries no residual content".into(),
                    );
                    let e = self.minimal_entry(&name, child_path, d, extra);
                    self.deleted_emitted += 1;
                    self.push(Ok(e));
                }
                Err(_) => {
                    extra.insert(
                        "recovery_note_0".into(),
                        "inode unreadable or scrubbed".into(),
                    );
                    let e = self.minimal_entry(&name, child_path, d, extra);
                    self.deleted_emitted += 1;
                    self.push(Ok(e));
                }
            }
        }
    }

    /// Minimal deleted entry for a residue record whose inode could not
    /// be decoded.
    fn minimal_entry(
        &self,
        name: &str,
        path: String,
        d: &RawDirent,
        meta: HashMap<String, String>,
    ) -> FsEntry {
        let kind = match d.ftype {
            1 => EntryKind::File,
            2 => EntryKind::Directory,
            7 => EntryKind::Symlink,
            _ => EntryKind::Other,
        };
        FsEntry {
            path,
            name: name.to_string(),
            entry_id: d.ino,
            kind,
            size: 0,
            disk_offset: d.off,
            allocated_ranges: Vec::new(),
            timestamps: Timestamps::default(),
            status: FsEntryStatus::Deleted {
                recovery: RecoveryState::Unknown,
            },
            meta,
            magic: None,
        }
    }

    /// Step the inobt free-bitmap scan; emits deleted inodes that still
    /// carry residual content (skips never-used zeroed slots).
    fn step_free_inodes(&mut self) -> bool {
        loop {
            let (ag, rec, bit) = self.fi;
            if ag >= self.fs.ags.len() {
                return false;
            }
            let recs = &self.fs.ags[ag].inobt;
            if rec >= recs.len() {
                self.fi = (ag + 1, 0, 0);
                continue;
            }
            if bit >= 64 {
                self.fi = (ag, rec + 1, 0);
                continue;
            }
            self.fi = (ag, rec, bit + 1);
            let r = recs[rec];
            // Sparse chunks: holes have no storage at all.
            if let Some(holes) = r.holemask {
                if holes & (1 << (bit / 4)) != 0 {
                    continue;
                }
            }
            if r.free & (1u64 << bit) == 0 {
                continue;
            }
            let ino = ((ag as u64) << self.fs.sb.agino_bits()) | (r.startino + bit) as u64;
            if self.emitted.contains(&ino) || self.fs.live_inos.contains(&ino) {
                continue;
            }
            // Zeroed never-used slot → skip; non-zero bytes → emit even
            // when the inode magic is gone (partially scrubbed residue).
            let (raw, off) = match self.fs.inode_bytes(ino) {
                Ok(v) => v,
                Err(e) => {
                    self.push(Err(e));
                    return true;
                }
            };
            if raw.iter().all(|&b| b == 0) {
                continue;
            }
            let mut extra = HashMap::new();
            extra.insert("inode_source".into(), self.inode_source(ag, r.startino));
            let e = match Inode::parse(raw, off, ino, &self.fs.sb) {
                Ok(inode) if inode.has_residue() => self.fs.make_entry(
                    &inode,
                    &format!("{ino:#x}"),
                    orphan_path(ino),
                    FsEntryStatus::Deleted {
                        recovery: RecoveryState::Unknown,
                    },
                    None,
                    extra,
                ),
                Ok(_) => continue, // magic ok but nothing residual
                Err(_) => {
                    extra.insert(
                        "inode_magic_bad".into(),
                        "true — inode partially scrubbed".into(),
                    );
                    self.minimal_ino_entry(ino, off, extra)
                }
            };
            self.emitted.insert(ino);
            self.deleted_emitted += 1;
            if self.deleted_emitted >= MAX_DELETED {
                return false;
            }
            self.push(Ok(e));
            return true;
        }
    }

    /// finobt membership makes a free-inode record a "recently freed"
    /// chunk — note it in the metadata.
    fn inode_source(&self, ag: usize, startino: u32) -> String {
        let in_finobt = self
            .fs
            .ags
            .get(ag)
            .map(|a| a.finobt.contains(&startino))
            .unwrap_or(false);
        if in_finobt {
            "inobt+finobt (recently freed chunk)".to_string()
        } else {
            "inobt".to_string()
        }
    }

    /// Minimal deleted entry for an unreadable/scrubbed inode slot.
    fn minimal_ino_entry(&self, ino: u64, off: u64, meta: HashMap<String, String>) -> FsEntry {
        FsEntry {
            path: orphan_path(ino),
            name: format!("{ino:#x}"),
            entry_id: ino,
            kind: EntryKind::Other,
            size: 0,
            disk_offset: off,
            allocated_ranges: Vec::new(),
            timestamps: Timestamps::default(),
            status: FsEntryStatus::Deleted {
                recovery: RecoveryState::Unknown,
            },
            meta,
            magic: None,
        }
    }

    /// Step the agi_unlinked chains: allocated inodes that were unlinked
    /// while still open — classic deleted-file evidence.
    fn step_unlinked(&mut self) -> bool {
        let mut steps = 0usize;
        loop {
            let (ag, bucket, cur) = self.ul;
            if ag >= self.fs.ags.len() || steps >= MAX_UNLINKED_STEPS {
                return false;
            }
            steps += 1;
            let Some(agi) = &self.fs.ags[ag].agi else {
                self.ul = (ag + 1, 0, NULLAGINO);
                continue;
            };
            if cur == NULLAGINO {
                // Chain exhausted — load the next bucket's head.
                if bucket >= 64 {
                    self.ul = (ag + 1, 0, NULLAGINO);
                    continue;
                }
                self.ul = (ag, bucket + 1, agi.unlinked[bucket]);
                continue;
            }
            let ino = ((ag as u64) << self.fs.sb.agino_bits()) | cur as u64;
            // Advance the cursor before emitting (chain may corrupt-loop).
            match self.fs.inode(ino) {
                Ok(inode) => {
                    let mut next = inode.next_unlinked;
                    // A next_unlinked that revisits a seen inode would loop
                    // the chain forever — terminate it instead.
                    if next != NULLAGINO {
                        let nino =
                            ((ag as u64) << self.fs.sb.agino_bits()) | next as u64;
                        if self.ul_seen.contains(&nino) {
                            next = NULLAGINO;
                        }
                    }
                    self.ul = (ag, bucket, next);
                    if self.emitted.contains(&ino) || !self.ul_seen.insert(ino) {
                        continue;
                    }
                    let mut extra = HashMap::new();
                    extra.insert("inode_source".into(), "agi_unlinked".into());
                    extra.insert(
                        "note".into(),
                        "unlinked but still allocated — deleted while open".into(),
                    );
                    let e = self.fs.make_entry(
                        &inode,
                        &format!("{ino:#x}"),
                        orphan_path(ino),
                        FsEntryStatus::Deleted {
                            recovery: RecoveryState::Unknown,
                        },
                        None,
                        extra,
                    );
                    self.emitted.insert(ino);
                    self.deleted_emitted += 1;
                    self.push(Ok(e));
                    return true;
                }
                Err(_) => {
                    self.ul = (ag, bucket, NULLAGINO);
                    continue;
                }
            }
        }
    }

    /// Step the orphan scan: allocated inodes that no directory reaches.
    fn step_orphans(&mut self) -> bool {
        if !self.fs.opts.include_orphans {
            return false;
        }
        loop {
            let (ag, rec, bit) = self.orc;
            if ag >= self.fs.ags.len() {
                return false;
            }
            let recs = &self.fs.ags[ag].inobt;
            if rec >= recs.len() {
                self.orc = (ag + 1, 0, 0);
                continue;
            }
            if bit >= 64 {
                self.orc = (ag, rec + 1, 0);
                continue;
            }
            self.orc = (ag, rec, bit + 1);
            let r = recs[rec];
            if let Some(holes) = r.holemask {
                if holes & (1 << (bit / 4)) != 0 {
                    continue;
                }
            }
            // allocated = bit clear in the free mask.
            if r.free & (1u64 << bit) != 0 {
                continue;
            }
            let ino = ((ag as u64) << self.fs.sb.agino_bits()) | (r.startino + bit) as u64;
            if self.emitted.contains(&ino) || self.fs.live_inos.contains(&ino) {
                continue;
            }
            let inode = match self.fs.inode(ino) {
                Ok(i) => i,
                Err(e) => {
                    self.push(Err(e));
                    return true;
                }
            };
            if !inode.has_residue() {
                continue;
            }
            let mut extra = HashMap::new();
            extra.insert("orphan".into(), "true".into());
            extra.insert(
                "note".into(),
                "allocated inode not reachable from the directory tree".into(),
            );
            let e = self.fs.make_entry(
                &inode,
                &format!("{ino:#x}"),
                orphan_path(ino),
                FsEntryStatus::Deleted {
                    recovery: RecoveryState::Unknown,
                },
                None,
                extra,
            );
            self.emitted.insert(ino);
            self.deleted_emitted += 1;
            if self.deleted_emitted >= MAX_DELETED {
                return false;
            }
            self.push(Ok(e));
            return true;
        }
    }

    fn push(&mut self, item: Result<FsEntry>) {
        if self.fs.opts.strict && item.is_err() {
            self.stopped = true;
        }
        self.pending.push_back(item);
    }
}

fn clone_err(e: &FsError) -> FsError {
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

impl Iterator for Walk<'_> {
    type Item = Result<FsEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.stopped {
                return None;
            }
            if let Some(item) = self.pending.pop_front() {
                // Strict mode: emitting an error record ends the walk.
                if self.fs.opts.strict && item.is_err() {
                    self.stopped = true;
                }
                return Some(item);
            }
            match self.phase {
                Phase::MountErrors => {
                    self.phase = Phase::Live;
                }
                Phase::Live => match self.dirs.pop_front() {
                    Some((ino, path)) => self.process_dir(ino, &path),
                    None => self.phase = Phase::FreeInodes,
                },
                Phase::FreeInodes => {
                    if !self.step_free_inodes() {
                        self.phase = Phase::Unlinked;
                    }
                }
                Phase::Unlinked => {
                    if !self.step_unlinked() {
                        self.phase = Phase::Orphans;
                    }
                }
                Phase::Orphans => {
                    if !self.step_orphans() {
                        self.phase = Phase::Done;
                    }
                }
                Phase::Done => return None,
            }
        }
    }
}
