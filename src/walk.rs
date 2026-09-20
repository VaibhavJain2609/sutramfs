//! The streaming walk: live tree (via NAT + dentry blocks), dentry residue,
//! orphan inodes, stale-NAT prior versions, and free-segment node scanning.
//!
//! Phases, in order:
//!
//! 1. **Live tree** — BFS from `root_ino` through dentry blocks; deleted
//!    *name residue* (bitmap-clear slots with surviving dirents) is emitted
//!    inline under its real parent path.
//! 2. **Orphan inodes** — the checkpoint's orphan list (files unlinked while
//!    still open at checkpoint time).
//! 3. **Stale-NAT scan** — every NAT block's previous copy; nids whose
//!    current entry is free but whose stale entry maps a node are deleted
//!    inodes; nids whose stale entry maps a *different* block expose a
//!    prior version of that node.
//! 4. **Free-segment scan** — blocks inside SIT-free segments are scanned
//!    for node footers and dentry blocks, recovering inodes and names no
//!    table still references.

use std::collections::{HashSet, VecDeque};

use sutram_fs::util;
use sutram_fs::{EntryKind, FsEntry, FsEntryStatus, FsError, RecoveryState, Result};

use crate::dentry::{self, Dentry};
use crate::fs::F2fsFs;
use crate::node::{file_type, inline_flag, Inode, NodeFooter, NodeView};
use crate::tables::NatEntry;

/// Walk phases.
enum Phase {
    Tree,
    Orphans,
    NatScan,
    SegScan,
    Done,
}

pub(crate) struct Walk<'m> {
    fs: &'m F2fsFs,
    queue: VecDeque<Result<FsEntry>>,
    /// (path, nid) of directories awaiting traversal.
    pending_dirs: VecDeque<(String, u32)>,
    /// nids already queued/emitted live (cycle guard).
    visited: HashSet<u32>,
    /// nids already emitted as deleted (dedup across phases).
    emitted_deleted: HashSet<u32>,
    /// (nid, cp_ver) of prior-version entries already emitted.
    emitted_prior: HashSet<(u32, u64)>,
    /// (dentry_blk, slot) residue already emitted.
    seen_residue: HashSet<(u64, u16)>,
    phase: Phase,
    /// Orphan-list cursor.
    orphan_idx: usize,
    /// NAT block index for the stale-copy scan.
    nat_boff: u64,
    /// Current NAT block pair being scanned, plus the entry cursor.
    nat_pair: Option<(Vec<NatEntry>, Vec<NatEntry>)>,
    nat_i: usize,
    /// Free-segment scan cursor: (main segno, block offset within segment).
    scan_seg: u64,
    scan_off: u64,
    finished: bool,
}

impl<'m> Walk<'m> {
    pub(crate) fn new(fs: &'m F2fsFs) -> Self {
        Walk {
            fs,
            queue: VecDeque::new(),
            pending_dirs: VecDeque::from([(String::from("/"), fs.sb.root_ino)]),
            visited: HashSet::new(),
            emitted_deleted: HashSet::new(),
            emitted_prior: HashSet::new(),
            seen_residue: HashSet::new(),
            phase: Phase::Tree,
            orphan_idx: 0,
            nat_boff: 0,
            nat_pair: None,
            nat_i: 0,
            scan_seg: 0,
            scan_off: 0,
            finished: false,
        }
    }

    /// Lenient error record: queued and the walk continues; strict aborts.
    fn fail(&mut self, e: FsError) -> Option<Result<FsEntry>> {
        if self.fs.opts.strict {
            self.finished = true;
            Some(Err(e))
        } else {
            self.queue.push_back(Err(e));
            None
        }
    }

    /// EntryKind from an on-disk `file_type` byte.
    fn kind_of(ft: u8, mode: u16) -> EntryKind {
        if mode & 0o170000 != 0 {
            return match mode & 0o170000 {
                0o040000 => EntryKind::Directory,
                0o120000 => EntryKind::Symlink,
                0o100000 => EntryKind::File,
                _ => EntryKind::Other,
            };
        }
        match ft {
            file_type::DIR => EntryKind::Directory,
            file_type::SYMLINK => EntryKind::Symlink,
            file_type::REG_FILE => EntryKind::File,
            _ => EntryKind::Other,
        }
    }

    /// Emit the root directory entry once.
    fn root_entry(&self, nid: u32, inode: &Inode) -> FsEntry {
        let footer = NodeFooter {
            nid,
            ino: nid,
            flag: 0,
            cp_ver: self.fs.ckpt.checkpoint_ver,
            next_blkaddr: 0,
        };
        self.fs.entry_from_inode(
            "/".into(),
            "/".into(),
            nid,
            inode,
            footer,
            self.fs.sb.blk_off(inode.blk),
            FsEntryStatus::Live,
            None,
            Default::default(),
            false,
        )
    }

    /// Resolve a dentry's `ino` to its inode and build an entry.
    /// Returns `Ok(None)` for dentries that should be skipped (`.`, `..`,
    /// free nids), or an entry (live or deleted-residue).
    fn dentry_entry(
        &mut self,
        dir_path: &str,
        dir_inode: &Inode,
        de: &Dentry,
        dentry_blk: u64,
    ) -> Option<Result<FsEntry>> {
        let raw_name = String::from_utf8_lossy(&de.name);
        if raw_name == "." || raw_name == ".." {
            return None;
        }
        let name = util::sanitize_name(&raw_name);
        let path = util::join_path(dir_path, &name);
        let disk_offset = self.fs.sb.blk_off(dentry_blk) + de.rec_off;

        if !de.live {
            return Some(self.residue_entry(de, name, path, disk_offset));
        }

        // Live dentry → resolve nid through the current NAT.
        match self.fs.read_node(de.ino) {
            Ok((_blk, footer, NodeView::Inode(inode))) => {
                let encrypted_parent = dir_inode.is_encrypted();
                let mut meta = std::collections::HashMap::new();
                meta.insert("file_type".into(), de.file_type.to_string());
                let entry = self.fs.entry_from_inode(
                    path.clone(),
                    name,
                    de.ino,
                    &inode,
                    footer,
                    disk_offset,
                    FsEntryStatus::Live,
                    None,
                    meta,
                    encrypted_parent,
                );
                if entry.kind == EntryKind::Directory && self.visited.insert(de.ino) {
                    self.pending_dirs.push_back((path, de.ino));
                }
                Some(Ok(entry))
            }
            Ok((_blk, _footer, NodeView::Indirect(_))) => {
                // NAT maps the nid to a non-inode node — corrupt or stale.
                Some(Err(FsError::corrupt(
                    disk_offset,
                    format!("nid {} resolves to non-inode node", de.ino),
                )))
            }
            Err(e) => {
                // NAT lookup miss on a live dentry → deleted or corrupt.
                match e {
                    FsError::NotFound { .. } => {
                        let mut meta = std::collections::HashMap::new();
                        meta.insert(
                            "note".into(),
                            "live dentry but nid has no current NAT entry".into(),
                        );
                        meta.insert("file_type".into(), de.file_type.to_string());
                        Some(Ok(FsEntry {
                            path,
                            name,
                            entry_id: de.ino as u64,
                            kind: Self::kind_of(de.file_type, 0),
                            size: 0,
                            disk_offset,
                            allocated_ranges: Vec::new(),
                            timestamps: Default::default(),
                            status: FsEntryStatus::Deleted {
                                recovery: RecoveryState::Unknown,
                            },
                            meta,
                            magic: None,
                        }))
                    }
                    other => Some(Err(other)),
                }
            }
        }
    }

    /// Build the entry for a *residue* (bitmap-clear) dentry: the name
    /// survives but the inode may be deleted or the nid reused.
    fn residue_entry(
        &mut self,
        de: &Dentry,
        name: String,
        path: String,
        disk_offset: u64,
    ) -> Result<FsEntry> {
        let nid = de.ino;
        let mut meta = std::collections::HashMap::new();
        meta.insert("dentry_residue".into(), "true".into());
        meta.insert("file_type".into(), de.file_type.to_string());
        meta.insert("hash_code".into(), format!("{:#x}", de.hash));

        // Current NAT still maps it → the nid was reused by a live inode.
        // The inode found is *not* the deleted file — emit a metadata-only
        // residue record instead of misattributing its extents.
        if let Ok(Some(NatEntry { block_addr: b, .. })) = self.fs.tables().nat_entry(nid) {
            if b != 0 {
                meta.insert("nid_reused".into(), "true".into());
                meta.insert(
                    "note".into(),
                    "dentry residue; nid now maps to a live inode".into(),
                );
                if let Ok((_, _f, NodeView::Inode(inode))) = self.fs.read_node(nid) {
                    meta.insert("live_inode_mode".into(), format!("{:#06o}", inode.mode));
                    meta.insert("live_inode_size".into(), inode.size.to_string());
                }
                self.emitted_deleted.insert(nid);
                return Ok(FsEntry {
                    path,
                    name,
                    entry_id: nid as u64,
                    kind: Self::kind_of(de.file_type, 0),
                    size: 0,
                    disk_offset,
                    allocated_ranges: Vec::new(),
                    timestamps: Default::default(),
                    status: FsEntryStatus::Deleted {
                        recovery: RecoveryState::Unknown,
                    },
                    meta,
                    magic: None,
                });
            }
        }
        // Stale NAT copy may still hold the deleted nid's node block.
        if let Ok(Some(NatEntry { block_addr: b, .. })) = self.fs.tables().stale_nat_entry(nid) {
            if b != 0 {
                if let Ok((_, footer, NodeView::Inode(inode))) = self.fs.read_node_at(b, Some(nid))
                {
                    self.emitted_deleted.insert(nid);
                    let mut e = self.fs.deleted_entry(
                        nid,
                        &inode,
                        footer,
                        "dentry-residue+stale-nat",
                        Some((path, name)),
                    );
                    e.meta.extend(meta);
                    return Ok(e);
                }
            }
        }
        // No surviving inode — metadata-only entry.
        meta.insert(
            "note".into(),
            "dentry residue; no node block survives".into(),
        );
        self.emitted_deleted.insert(nid);
        Ok(FsEntry {
            path,
            name,
            entry_id: nid as u64,
            kind: Self::kind_of(de.file_type, 0),
            size: 0,
            disk_offset,
            allocated_ranges: Vec::new(),
            timestamps: Default::default(),
            status: FsEntryStatus::Deleted {
                recovery: RecoveryState::Unrecoverable,
            },
            meta,
            magic: None,
        })
    }

    /// Push an item; in strict mode an `Err` is emitted immediately and
    /// terminates the walk (matching `fail` semantics).
    fn emit(&mut self, item: Result<FsEntry>) -> Option<Result<FsEntry>> {
        if item.is_err() && self.fs.opts.strict {
            self.finished = true;
            return Some(item);
        }
        self.queue.push_back(item);
        None
    }

    /// Scan one directory inode: emit its entries, queue its subdirs.
    /// Reads at most one dentry block at a time (bounded memory).
    fn scan_dir(&mut self, path: &str, nid: u32) -> Option<Result<FsEntry>> {
        let (blk, _footer, view) = match self.fs.read_node(nid) {
            Ok(v) => v,
            Err(e) => return self.fail(e),
        };
        let inode = match view {
            NodeView::Inode(i) => i,
            NodeView::Indirect(_) => {
                return self.fail(FsError::corrupt(
                    self.fs.sb.blk_off(blk as u64),
                    format!("dir nid {nid} is not an inode node"),
                ));
            }
        };
        if path == "/" {
            self.queue.push_back(Ok(self.root_entry(nid, &inode)));
        }
        // Build the list of dentry-bearing regions: (blk, region_off_in_blk,
        // bytes). Inline dentry dirs carry dentries inside the inode block.
        let mut regions: Vec<(u64, u64, Vec<u8>)> = Vec::new();
        if inode.inline_flags & inline_flag::INLINE_DENTRY != 0 {
            let (start, len) = inode.inline_region(self.fs.sb.block_size as usize);
            if let Some(region) = inode.raw.get(start..start + len) {
                regions.push((inode.blk, start as u64, region.to_vec()));
            }
        } else {
            for b in self.fs.dir_data_blocks(nid, &inode) {
                match self.fs.read_block(b) {
                    Ok(bytes) => {
                        if let r @ Some(_) = self.scan_dentry_region(path, &inode, b, 0, &bytes) {
                            return r;
                        }
                    }
                    Err(e) => {
                        if let r @ Some(_) = self.fail(e) {
                            return r;
                        }
                    }
                }
            }
            return None;
        }
        for (blk, base, bytes) in regions {
            if let r @ Some(_) = self.scan_dentry_region(path, &inode, blk, base, &bytes) {
                return r;
            }
        }
        None
    }

    /// Parse one dentry-bearing region and queue its entries.
    /// `base` is the region's byte offset inside block `blk` (0 for whole
    /// blocks; >0 for the inode's inline region) so provenance offsets stay
    /// absolute.
    fn scan_dentry_region(
        &mut self,
        path: &str,
        inode: &Inode,
        blk: u64,
        base: u64,
        bytes: &[u8],
    ) -> Option<Result<FsEntry>> {
        match dentry::parse_dentries(bytes, 0, bytes.len(), self.fs.sb.max_nid()) {
            Ok((des, errs)) => {
                for e in errs {
                    if let r @ Some(_) =
                        self.fail(FsError::corrupt(self.fs.sb.blk_off(blk) + base, e))
                    {
                        return r;
                    }
                }
                for de in des {
                    if !de.live && !self.seen_residue.insert((blk, de.slot)) {
                        continue;
                    }
                    // Fix provenance for regions nested inside a block.
                    let mut de = de;
                    de.rec_off += base;
                    if let Some(item) = self.dentry_entry(path, inode, &de, blk) {
                        if let r @ Some(_) = self.emit(item) {
                            return r;
                        }
                    }
                }
            }
            Err(e) => {
                if let r @ Some(_) = self.fail(e) {
                    return r;
                }
            }
        }
        None
    }

    /// Emit a deleted entry for `nid`'s inode when the node block parses.
    fn emit_deleted_inode(&mut self, nid: u32, blk: u32, source: &str) -> Option<Result<FsEntry>> {
        match self.fs.read_node_at(blk, Some(nid)) {
            Ok((_, footer, NodeView::Inode(inode))) => {
                self.emitted_deleted.insert(nid);
                Some(Ok(self.fs.deleted_entry(nid, &inode, footer, source, None)))
            }
            Ok(_) => None,
            Err(e) => self.fail(e),
        }
    }

    /// Orphan-inode pass.
    fn scan_orphans(&mut self) -> Option<Result<FsEntry>> {
        while self.orphan_idx < self.fs.ckpt.orphan_inos.len() {
            let nid = self.fs.ckpt.orphan_inos[self.orphan_idx];
            self.orphan_idx += 1;
            if self.emitted_deleted.contains(&nid) {
                continue;
            }
            // Orphan inode is usually still NAT-allocated (unlinked while
            // open) — try current NAT, then stale copy.
            let blk = self
                .fs
                .node_blk_for(nid)
                .ok()
                .flatten()
                .filter(|&b| b != 0)
                .or_else(|| {
                    self.fs
                        .tables()
                        .stale_nat_entry(nid)
                        .ok()
                        .flatten()
                        .map(|e| e.block_addr)
                        .filter(|&b| b != 0)
                });
            match blk {
                Some(b) => {
                    if let Some(item) = self.emit_deleted_inode(nid, b, "checkpoint-orphan") {
                        if let Ok(e) = &item {
                            let _ = e; // orphan flag merged below if needed
                        }
                        // tag orphan
                        if let Ok(mut e) = item {
                            e.meta.insert("orphan".into(), "true".into());
                            return Some(Ok(e));
                        }
                        return Some(item);
                    }
                }
                None => {
                    self.emitted_deleted.insert(nid);
                    let mut meta = std::collections::HashMap::new();
                    meta.insert("orphan".into(), "true".into());
                    meta.insert(
                        "note".into(),
                        "orphan inode; no node block in either NAT copy".into(),
                    );
                    return Some(Ok(FsEntry {
                        path: util::orphan_path(nid as u64),
                        name: format!("orphan_{nid}"),
                        entry_id: nid as u64,
                        kind: EntryKind::Other,
                        size: 0,
                        disk_offset: self.fs.sb.blk_off(self.fs.ckpt.pack_blk),
                        allocated_ranges: Vec::new(),
                        timestamps: Default::default(),
                        status: FsEntryStatus::Deleted {
                            recovery: RecoveryState::Unrecoverable,
                        },
                        meta,
                        magic: None,
                    }));
                }
            }
        }
        None
    }

    /// Stale-NAT scan — one entry per call. `nat_pair`/`nat_i` keep the
    /// in-block cursor so an early return doesn't drop later entries.
    fn scan_stale_nat(&mut self) -> Option<Result<FsEntry>> {
        let nat_blocks = self.fs.sb.nat_blocks();
        let per_block = self.fs.sb.block_size / 9;
        while self.nat_boff < nat_blocks {
            if self.nat_pair.is_none() {
                match self.fs.tables().nat_block_pair(self.nat_boff) {
                    Ok(p) => {
                        self.nat_pair = Some(p);
                        self.nat_i = 0;
                    }
                    Err(e) => {
                        self.nat_boff += 1;
                        if let r @ Some(_) = self.fail(e) {
                            return r;
                        }
                        continue;
                    }
                }
            }
            let n_entries = self.nat_pair.as_ref().map(|(c, _)| c.len()).unwrap_or(0);
            while self.nat_i < n_entries {
                let i = self.nat_i;
                self.nat_i += 1;
                let (c, s) = {
                    let (cur, stale) = self.nat_pair.as_ref().unwrap();
                    (cur[i], stale[i])
                };
                let nid = (self.nat_boff * per_block) as u32 + i as u32;
                if c.is_free() && !s.is_free() {
                    // Deleted since the stale checkpoint — try its old node.
                    if self.emitted_deleted.contains(&nid) {
                        continue;
                    }
                    match self.emit_deleted_inode(nid, s.block_addr, "stale-nat") {
                        Some(item) => return Some(item),
                        None => {
                            // Node block gone/mismatched — still report the
                            // deleted nid.
                            if self.emitted_deleted.insert(nid) {
                                let mut meta = std::collections::HashMap::new();
                                meta.insert("recovery_source".into(), "stale-nat".into());
                                meta.insert(
                                    "note".into(),
                                    "stale NAT entry; node block unreadable".into(),
                                );
                                meta.insert("stale_blkaddr".into(), s.block_addr.to_string());
                                return Some(Ok(FsEntry {
                                    path: util::orphan_path(nid as u64),
                                    name: format!("nid_{nid}"),
                                    entry_id: nid as u64,
                                    kind: EntryKind::Other,
                                    size: 0,
                                    disk_offset: self.fs.sb.blk_off(s.block_addr as u64),
                                    allocated_ranges: Vec::new(),
                                    timestamps: Default::default(),
                                    status: FsEntryStatus::Deleted {
                                        recovery: RecoveryState::Unrecoverable,
                                    },
                                    meta,
                                    magic: None,
                                }));
                            }
                        }
                    }
                } else if !c.is_free() && !s.is_free() && c.block_addr != s.block_addr {
                    // Same nid, different node block → a prior version of the
                    // node survives at the stale address.
                    if let Ok((_, footer, NodeView::Inode(inode))) =
                        self.fs.read_node_at(s.block_addr, Some(nid))
                    {
                        if footer.cp_ver >= self.fs.ckpt.checkpoint_ver {
                            continue; // not actually older
                        }
                        if !self.emitted_prior.insert((nid, footer.cp_ver)) {
                            continue;
                        }
                        let mut e = self.fs.deleted_entry(
                            nid,
                            &inode,
                            footer,
                            "prior-version(stale-nat)",
                            None,
                        );
                        e.name = format!("nid_{nid}_v{}", footer.cp_ver);
                        e.path = util::join_path("/$ORPHANED", &e.name);
                        e.meta.insert(
                            "prior_version".into(),
                            format!("cp_ver {} < {}", footer.cp_ver, self.fs.ckpt.checkpoint_ver),
                        );
                        e.meta.insert("live_nid".into(), nid.to_string());
                        return Some(Ok(e));
                    }
                }
            }
            self.nat_pair = None;
            self.nat_boff += 1;
        }
        None
    }

    /// Free-segment scan pass — one block per call. Finds node blocks
    /// (deleted inodes / prior versions) and stale dentry blocks inside
    /// segments the SIT marks free.
    fn scan_free_segments(&mut self) -> Option<Result<FsEntry>> {
        while self.scan_seg < self.fs.sb.segment_count_main as u64 {
            let seg = self.scan_seg;
            let free = self.fs.sit_entry(seg).map(|e| e.is_free()).unwrap_or(false);
            if !free {
                self.scan_seg += 1;
                self.scan_off = 0;
                continue;
            }
            if self.scan_off >= self.fs.sb.blks_per_seg {
                self.scan_seg += 1;
                self.scan_off = 0;
                continue;
            }
            let blk = self.fs.sb.main_seg_blk(seg) + self.scan_off;
            self.scan_off += 1;
            let bytes = match self.fs.read_block(blk) {
                Ok(b) => b,
                Err(e) => {
                    // Skip the rest of this segment — a truncated image
                    // would otherwise flood the stream with per-block errors.
                    if let r @ Some(_) = self.fail(e) {
                        return r;
                    }
                    self.scan_seg += 1;
                    self.scan_off = 0;
                    continue;
                }
            };
            // Node block?
            if let Some(footer) = crate::node::looks_like_node(
                &bytes,
                self.fs.sb.max_nid(),
                self.fs.ckpt.checkpoint_ver,
            ) {
                let nid = footer.nid;
                let live_blk = self.fs.node_blk_for(nid).ok().flatten().filter(|&b| b != 0);
                match live_blk {
                    Some(b) if b as u64 == blk => continue, // live node — SIT stale?
                    Some(_) => {
                        // nid is live elsewhere → this is a prior version.
                        if footer.cp_ver < self.fs.ckpt.checkpoint_ver
                            && self.emitted_prior.insert((nid, footer.cp_ver))
                        {
                            if let Ok((_, f2, NodeView::Inode(inode))) =
                                self.fs.read_node_at(blk as u32, Some(nid))
                            {
                                let mut e = self.fs.deleted_entry(
                                    nid,
                                    &inode,
                                    f2,
                                    "prior-version(segment-scan)",
                                    None,
                                );
                                e.name = format!("nid_{nid}_v{}", f2.cp_ver);
                                e.path = util::join_path("/$ORPHANED", &e.name);
                                e.meta.insert(
                                    "prior_version".into(),
                                    format!("cp_ver {}", f2.cp_ver),
                                );
                                if let Some(se) = self.fs.sit_entry(seg) {
                                    e.meta.insert("seg_mtime".into(), se.mtime.to_string());
                                }
                                return Some(Ok(e));
                            }
                        }
                        continue;
                    }
                    None => {
                        // No live mapping → deleted node. Only inode nodes
                        // produce entries (dnodes/indirects are metadata
                        // residue — noted but not emitted as files).
                        if footer.nid == footer.ino && !self.emitted_deleted.contains(&nid) {
                            if let Some(item) =
                                self.emit_deleted_inode(nid, blk as u32, "free-segment-scan")
                            {
                                // Attach the segment's last-checkpoint age.
                                if let (Ok(e), Some(se)) = (&item, self.fs.sit_entry(seg)) {
                                    let mut e = e.clone();
                                    e.meta.insert("seg_mtime".into(), se.mtime.to_string());
                                    return Some(Ok(e));
                                }
                                return Some(item);
                            }
                        }
                        continue;
                    }
                }
            }
            // Dentry block residue?
            if crate::dentry::looks_like_dentry_block(&bytes, self.fs.sb.max_nid()) {
                if let Ok((des, _)) = dentry::parse_dentries(
                    &bytes,
                    0,
                    self.fs.sb.block_size as usize,
                    self.fs.sb.max_nid(),
                ) {
                    for de in des {
                        if !self.seen_residue.insert((blk, de.slot)) {
                            continue;
                        }
                        let raw = String::from_utf8_lossy(&de.name);
                        if raw == "." || raw == ".." {
                            continue;
                        }
                        let name = util::sanitize_name(&raw);
                        // Resolve the residue nid through either NAT copy.
                        let nid = de.ino;
                        let blk_hint = self
                            .fs
                            .node_blk_for(nid)
                            .ok()
                            .flatten()
                            .filter(|&b| b != 0)
                            .or_else(|| {
                                self.fs
                                    .tables()
                                    .stale_nat_entry(nid)
                                    .ok()
                                    .flatten()
                                    .map(|e| e.block_addr)
                                    .filter(|&b| b != 0)
                            });
                        if let Some(nb) = blk_hint {
                            if let Ok((_, footer, NodeView::Inode(inode))) =
                                self.fs.read_node_at(nb, Some(nid))
                            {
                                if self.emitted_deleted.insert(nid) {
                                    let mut e = self.fs.deleted_entry(
                                        nid,
                                        &inode,
                                        footer,
                                        "stale-dentry-block",
                                        None,
                                    );
                                    e.name = name;
                                    e.path = util::join_path("/$ORPHANED", &e.name);
                                    e.meta.insert("stale_dentry_block".into(), blk.to_string());
                                    self.queue.push_back(Ok(e));
                                }
                                continue;
                            }
                        }
                        // Metadata-only residue.
                        if self.emitted_deleted.insert(nid) {
                            let mut meta = std::collections::HashMap::new();
                            meta.insert("dentry_residue".into(), "true".into());
                            meta.insert("stale_dentry_block".into(), blk.to_string());
                            meta.insert("note".into(), "name residue in stale dentry block".into());
                            self.queue.push_back(Ok(FsEntry {
                                path: util::join_path("/$ORPHANED", &name),
                                name,
                                entry_id: nid as u64,
                                kind: Self::kind_of(de.file_type, 0),
                                size: 0,
                                disk_offset: self.fs.sb.blk_off(blk) + de.rec_off,
                                allocated_ranges: Vec::new(),
                                timestamps: Default::default(),
                                status: FsEntryStatus::Deleted {
                                    recovery: RecoveryState::Unrecoverable,
                                },
                                meta,
                                magic: None,
                            }));
                        }
                    }
                }
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
                Phase::Tree => {
                    if let Some((path, nid)) = self.pending_dirs.pop_front() {
                        if let Some(item) = self.scan_dir(&path, nid) {
                            return Some(item);
                        }
                        continue;
                    }
                    self.phase = Phase::Orphans;
                }
                Phase::Orphans => {
                    if self.fs.opts.include_orphans {
                        if let Some(item) = self.scan_orphans() {
                            return Some(item);
                        }
                    }
                    self.phase = Phase::NatScan;
                }
                Phase::NatScan => {
                    if self.fs.opts.include_orphans {
                        if let Some(item) = self.scan_stale_nat() {
                            return Some(item);
                        }
                    }
                    self.phase = Phase::SegScan;
                }
                Phase::SegScan => {
                    if self.fs.opts.include_orphans {
                        if let Some(item) = self.scan_free_segments() {
                            return Some(item);
                        }
                    }
                    self.phase = Phase::Done;
                }
                Phase::Done => {
                    self.finished = true;
                }
            }
        }
    }
}
