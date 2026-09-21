//! The streaming catalog walk: live tree DFS, then forensic passes —
//! leaf free-space residue, dead-node residue, and orphaned extents.
//!
//! Live paths come from the mount-time index (`children` by parent CNID);
//! each record's bytes are re-read from its B-tree node at emit time so the
//! iterator stays bounded by per-directory memory.

use std::collections::{HashSet, VecDeque};

use sutram_fs::util;
use sutram_fs::{EntryKind, FsEntry, FsEntryStatus, FsError, RecoveryState, Result};

use crate::attrs::{self, DecmpfsHeader};
use crate::btree::Node;
use crate::catalog::{self, CatKey, CatRecord, FileRec, FolderRec, RecRef};
use crate::extents;
use crate::fs::HfsFs;
use crate::vh::ForkData;

/// Walk phases — live tree, unreachable-record orphans, residue, orphans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Live,
    OrphanLive,
    LeafResidue,
    DeadNodes,
    OrphanExtents,
    Done,
}

/// Streaming `walk()` iterator.
pub(crate) struct Walk<'m> {
    fs: &'m HfsFs,
    /// Ready-to-yield items (entries + error records).
    queue: VecDeque<Result<FsEntry>>,
    /// Directories to expand: `(path, folder_cnid)`.
    pending: VecDeque<(String, u32)>,
    /// Folder CNIDs already expanded (cycle guard).
    seen_dirs: HashSet<u32>,
    /// `recs` indices emitted during the live phase.
    emitted: HashSet<usize>,
    /// Children (rec indices) of the directory currently emitting.
    cur_children: VecDeque<usize>,
    /// Path of the directory currently emitting.
    cur_path: String,
    /// Cursor for the orphan-live pass over `fs.recs`.
    live_scan_pos: usize,
    /// Node buffer cache for record re-reads.
    node_cache: Option<(u32, Vec<u8>)>,
    /// Residue scan state.
    leaf_pos: usize,
    residue_seen: HashSet<(u32, String)>,
    /// Dead-node scan cursor.
    dead_node: u32,
    /// Orphan-extents cursor.
    orphan_ext_pos: usize,
    /// Mount-time notes replayed once at the head of the stream.
    notes: VecDeque<FsError>,
    phase: Phase,
    finished: bool,
}

impl<'m> Walk<'m> {
    pub(crate) fn new(fs: &'m HfsFs) -> Self {
        let mut pending = VecDeque::new();
        pending.push_back(("/".to_string(), catalog::CNID_ROOT));
        Walk {
            fs,
            queue: VecDeque::new(),
            pending,
            seen_dirs: HashSet::new(),
            emitted: HashSet::new(),
            cur_children: VecDeque::new(),
            cur_path: "/".into(),
            live_scan_pos: 0,
            node_cache: None,
            leaf_pos: 0,
            residue_seen: HashSet::new(),
            dead_node: 0,
            orphan_ext_pos: 0,
            notes: fs
                .mount_notes
                .iter()
                .map(|(o, m)| FsError::corrupt(*o, m.clone()))
                .collect(),
            phase: Phase::Live,
            finished: false,
        }
    }

    /// Lenient-vs-strict error handling: queue it, or end the walk.
    fn fail(&mut self, e: FsError) -> Option<Result<FsEntry>> {
        if self.fs.opts.strict {
            self.finished = true;
            Some(Err(e))
        } else {
            self.queue.push_back(Err(e));
            None
        }
    }

    /// Fetch catalog node `idx`'s buffer, cached.
    fn node_buf(&mut self, idx: u32) -> Result<Vec<u8>> {
        if self.node_cache.as_ref().map(|(n, _)| *n) != Some(idx) {
            let buf = self.fs.cat.read_node(self.fs.src.as_ref(), idx)?;
            self.node_cache = Some((idx, buf));
        }
        match &self.node_cache {
            Some((_, b)) => Ok(b.clone()),
            None => Err(FsError::corrupt(0, "node cache unexpectedly empty")),
        }
    }

    /// Absolute disk offset of catalog node `idx` (residue provenance).
    fn node_disk(&self, idx: u32) -> u64 {
        self.fs.cat.node_offset(idx).unwrap_or(0)
    }

    /// The synthetic `/` entry (root folder record's offset as provenance).
    fn root_entry(&self) -> FsEntry {
        let info = self
            .fs
            .recs
            .iter()
            .find(|r| r.rectype == catalog::REC_FOLDER && r.cnid == catalog::CNID_ROOT)
            .and_then(|r| {
                self.fs
                    .read_record(r)
                    .ok()
                    .map(|(rec, _)| (r.disk_off, rec))
            })
            .and_then(|(off, rec)| match rec {
                CatRecord::Folder(f) => Some((off, f.dates)),
                _ => None,
            });
        let (disk_off, timestamps) = match info {
            Some((o, d)) => (o, catalog::timestamps(&d)),
            None => (1024, Default::default()),
        };
        let mut meta = std::collections::HashMap::new();
        meta.insert("cnid".into(), catalog::CNID_ROOT.to_string());
        FsEntry {
            path: "/".into(),
            name: "/".into(),
            entry_id: catalog::CNID_ROOT as u64,
            kind: EntryKind::Directory,
            size: 0,
            disk_offset: disk_off,
            allocated_ranges: Vec::new(),
            timestamps,
            status: FsEntryStatus::Live,
            meta,
            magic: None,
        }
    }

    /// Build an `FsEntry` for a live catalog record.
    fn live_entry(&mut self, r: &RecRef, parent_path: &str) -> Result<FsEntry> {
        let (record, _raw) = self.fs.read_record(r)?;
        let path = util::join_path(parent_path, &r.name);
        match record {
            CatRecord::Folder(f) => {
                let mut meta = std::collections::HashMap::new();
                folder_meta(&mut meta, &f, r);
                self.attach_xattrs(&mut meta, f.cnid);
                let entry = FsEntry {
                    path: path.clone(),
                    name: r.name.clone(),
                    entry_id: f.cnid as u64,
                    kind: EntryKind::Directory,
                    size: 0,
                    disk_offset: r.disk_off,
                    allocated_ranges: Vec::new(),
                    timestamps: catalog::timestamps(&f.dates),
                    status: FsEntryStatus::Live,
                    meta,
                    magic: None,
                };
                if self.seen_dirs.insert(f.cnid) {
                    self.pending.push_back((path, f.cnid));
                }
                Ok(entry)
            }
            CatRecord::File(f) => self.file_entry(r, &f, path, FsEntryStatus::Live, None),
            _ => Err(FsError::corrupt(r.disk_off, "unexpected record type")),
        }
    }

    /// Build a file `FsEntry` — live records only (residue uses
    /// [`deleted_file_entry`] since its bytes aren't re-readable by ref).
    /// `override_ranges` forces `allocated_ranges` (deleted survivors).
    fn file_entry(
        &mut self,
        r: &RecRef,
        f: &FileRec,
        path: String,
        status: FsEntryStatus,
        override_ranges: Option<Vec<(u64, u64)>>,
    ) -> Result<FsEntry> {
        let mut meta = std::collections::HashMap::new();
        file_meta(&mut meta, f, r);
        let mut size = f.data_fork.logical_size;
        let mut kind = EntryKind::File;

        // Symlink (`slnk`/`rhap`): data fork holds the target path.
        if f.is_symlink() {
            kind = EntryKind::Symlink;
            let exts = self
                .fs
                .fork_extents(&f.data_fork, f.cnid, extents::FORK_DATA);
            let ranges = self.fs.extents_to_ranges(&exts, size.min(4096));
            if let Some((off, len)) = ranges.first() {
                if let Ok(b) = self.fs.src.read_slice(*off, (*len).min(4096) as usize) {
                    let t = String::from_utf8_lossy(&b)
                        .trim_end_matches('\0')
                        .to_string();
                    if !t.is_empty() {
                        meta.insert("symlink_target".into(), t);
                    }
                }
            }
        }

        // Hard link (`hlnk`): extents live on `iNode<special>` (CNID 18's dir).
        let mut inode_fork: Option<ForkData> = None;
        let mut inode_cnid = f.cnid;
        if f.is_hardlink() && f.special != 0 {
            meta.insert("hardlink".into(), "true".into());
            meta.insert("inode_ref".into(), format!("iNode{}", f.special));
            if let Some(&irec_idx) = self.fs.file_recs.get(&f.special) {
                let irec = self.fs.recs[irec_idx].clone();
                if let Ok((CatRecord::File(inode), _)) = self.fs.read_record(&irec) {
                    meta.insert(
                        "inode_path".into(),
                        self.fs
                            .path_of(irec.parent)
                            .map(|p| util::join_path(&p, &irec.name))
                            .unwrap_or_else(|| irec.name.clone()),
                    );
                    size = inode.data_fork.logical_size;
                    inode_fork = Some(inode.data_fork);
                    // Overflow extents are keyed under the *inode file's*
                    // CNID, not the hardlink's.
                    inode_cnid = inode.cnid;
                }
            }
        }

        // decmpfs compression via `com.apple.decmpfs` xattr.
        let xattrs = self.fs.xattrs.get(&f.cnid).cloned().unwrap_or_default();
        for x in &xattrs {
            meta.insert(
                format!("xattr_{}", x.name),
                format!("{} bytes ({})", x.size, x.storage),
            );
        }
        let mut stored_ranges: Option<Vec<(u64, u64)>> = None;
        if f.user_flags & catalog::UF_COMPRESSED != 0
            || xattrs.iter().any(|x| x.name == attrs::DECMPFS_XATTR)
        {
            if let Some(x) = xattrs.iter().find(|x| x.name == attrs::DECMPFS_XATTR) {
                self.decmpfs_meta(&mut meta, &mut size, &mut stored_ranges, x, f);
            }
        }

        let ranges = override_ranges.or(stored_ranges).unwrap_or_else(|| {
            let fork = inode_fork.as_ref().unwrap_or(&f.data_fork);
            let exts = self.fs.fork_extents(fork, inode_cnid, extents::FORK_DATA);
            self.fs.extents_to_ranges(&exts, size)
        });

        let mut entry = FsEntry {
            path,
            name: r.name.clone(),
            entry_id: f.cnid as u64,
            kind,
            size,
            disk_offset: r.disk_off,
            allocated_ranges: ranges,
            timestamps: catalog::timestamps(&f.dates),
            status,
            meta,
            magic: None,
        };
        if matches!(entry.status, FsEntryStatus::Live) {
            entry.magic = self.fs.magic_for(&entry);
        }
        // Resource fork as a sibling pseudo-entry (`name:rsrc`) — skipped
        // for decmpfs-rsrc files (the rsrc is compressed payload, not a
        // user-visible resource fork).
        if f.rsrc_fork.logical_size > 0 && !entry.meta.contains_key("decmpfs_type") {
            let exts = self
                .fs
                .fork_extents(&f.rsrc_fork, f.cnid, extents::FORK_RSRC);
            let rr = self.fs.extents_to_ranges(&exts, f.rsrc_fork.logical_size);
            let mut rmeta = std::collections::HashMap::new();
            rmeta.insert("fork".into(), "rsrc".into());
            rmeta.insert("cnid".into(), f.cnid.to_string());
            self.queue.push_back(Ok(FsEntry {
                path: format!("{}:rsrc", entry.path),
                name: format!("{}:rsrc", entry.name),
                entry_id: f.cnid as u64,
                kind: EntryKind::File,
                size: f.rsrc_fork.logical_size,
                disk_offset: r.disk_off,
                allocated_ranges: rr,
                timestamps: catalog::timestamps(&f.dates),
                status: entry.status,
                meta: rmeta,
                magic: None,
            }));
        }
        // Each xattr as a `name:xattr:<attr>` pseudo-entry.
        for x in &xattrs {
            let mut xmeta = std::collections::HashMap::new();
            xmeta.insert("xattr".into(), x.name.clone());
            xmeta.insert("xattr_storage".into(), x.storage.clone());
            if x.start_block != 0 {
                xmeta.insert("xattr_continuation".into(), x.start_block.to_string());
            }
            xmeta.insert("fork".into(), "xattr".into());
            xmeta.insert("cnid".into(), f.cnid.to_string());
            self.queue.push_back(Ok(FsEntry {
                path: format!("{}:xattr:{}", entry.path, x.name),
                name: format!("{}:xattr:{}", entry.name, x.name),
                entry_id: f.cnid as u64,
                kind: EntryKind::Other,
                size: x.size,
                disk_offset: x.disk_off,
                allocated_ranges: x.ranges.clone(),
                timestamps: Default::default(),
                status: entry.status,
                meta: xmeta,
                magic: None,
            }));
        }
        Ok(entry)
    }

    /// Parse the decmpfs xattr and set compression meta / stored ranges.
    fn decmpfs_meta(
        &mut self,
        meta: &mut std::collections::HashMap<String, String>,
        size: &mut u64,
        stored_ranges: &mut Option<Vec<(u64, u64)>>,
        x: &crate::fs::Xattr,
        f: &FileRec,
    ) {
        let val = match self.fs.read_xattr(x) {
            Ok(v) => v,
            Err(e) => {
                meta.insert("compression_note".into(), format!("xattr read: {e}"));
                return;
            }
        };
        let hdr = match attrs::parse_decmpfs(&val) {
            Ok(h) => h,
            Err(e) => {
                meta.insert("compressed".into(), "decmpfs-unparseable".into());
                meta.insert("compression_note".into(), format!("{e}"));
                return;
            }
        };
        meta.insert("compressed".into(), "decmpfs".into());
        meta.insert("decmpfs_type".into(), hdr.compression_type.to_string());
        meta.insert(
            "decmpfs_codec".into(),
            attrs::decmpfs_type_name(hdr.compression_type).into(),
        );
        meta.insert(
            "decmpfs_uncompressed_size".into(),
            hdr.uncompressed_size.to_string(),
        );
        *size = hdr.uncompressed_size;
        // Where the stored bytes live (even types → resource fork).
        *stored_ranges = if attrs::decmpfs_is_rsrc(hdr.compression_type) {
            let re = self
                .fs
                .fork_extents(&f.rsrc_fork, f.cnid, extents::FORK_RSRC);
            Some(self.fs.extents_to_ranges(&re, f.rsrc_fork.logical_size))
        } else {
            Some(x.ranges.clone())
        };
        // Codec support check (inline types can be probed without rsrc).
        if !attrs::decmpfs_is_rsrc(hdr.compression_type) {
            let probe = DecmpfsHeader {
                compression_type: hdr.compression_type,
                uncompressed_size: hdr.uncompressed_size,
                inline: hdr.inline,
            };
            if let Err(e) = attrs::decompress(&probe, None) {
                meta.insert("compression_note".into(), format!("{e}"));
            }
        }
    }

    /// Folder-level xattr listing into `meta`.
    fn attach_xattrs(&mut self, meta: &mut std::collections::HashMap<String, String>, cnid: u32) {
        if let Some(xs) = self.fs.xattrs.get(&cnid) {
            for x in xs {
                meta.insert(
                    format!("xattr_{}", x.name),
                    format!("{} bytes ({})", x.size, x.storage),
                );
            }
        }
    }

    /// Phase B: live records unreachable from the root → orphans.
    fn emit_orphan_live(&mut self) -> Option<Result<FsEntry>> {
        if !self.fs.opts.include_orphans {
            self.phase = Phase::LeafResidue;
            return None;
        }
        while self.live_scan_pos < self.fs.recs.len() {
            let idx = self.live_scan_pos;
            self.live_scan_pos += 1;
            if self.emitted.contains(&idx) {
                continue;
            }
            let r = self.fs.recs[idx].clone();
            if !matches!(r.rectype, catalog::REC_FILE | catalog::REC_FOLDER) {
                continue;
            }
            // The root folder record is keyed under CNID 1 and was already
            // emitted as the synthetic `/` entry.
            if r.rectype == catalog::REC_FOLDER && r.cnid == catalog::CNID_ROOT {
                continue;
            }
            match self.orphan_entry(&r) {
                Ok(e) => return Some(Ok(e)),
                Err(e) => {
                    if let it @ Some(_) = self.fail(e) {
                        return it;
                    }
                }
            }
        }
        self.phase = Phase::LeafResidue;
        None
    }

    /// A record in the live leaf chain whose parent chain is broken.
    fn orphan_entry(&mut self, r: &RecRef) -> Result<FsEntry> {
        let (record, _) = self.fs.read_record(r)?;
        let path = format!("{}/{}", util::orphan_path(r.cnid as u64), r.name);
        let mut entry = match record {
            CatRecord::File(f) => {
                let mut e = self.file_entry(
                    r,
                    &f,
                    path,
                    FsEntryStatus::Deleted {
                        recovery: RecoveryState::Unknown,
                    },
                    None,
                )?;
                e.status = FsEntryStatus::Deleted {
                    recovery: RecoveryState::Unknown,
                };
                e
            }
            CatRecord::Folder(f) => FsEntry {
                path: util::orphan_path(f.cnid as u64),
                name: r.name.clone(),
                entry_id: f.cnid as u64,
                kind: EntryKind::Directory,
                size: 0,
                disk_offset: r.disk_off,
                allocated_ranges: Vec::new(),
                timestamps: catalog::timestamps(&f.dates),
                status: FsEntryStatus::Deleted {
                    recovery: RecoveryState::Unknown,
                },
                meta: std::collections::HashMap::new(),
                magic: None,
            },
            _ => return Err(FsError::corrupt(r.disk_off, "orphan: bad record type")),
        };
        entry.meta.insert("orphan".into(), "true".into());
        entry.meta.insert(
            "note".into(),
            "catalog record present but parent chain unreachable".into(),
        );
        Ok(entry)
    }

    /// Phase C: scan live leaf nodes' free space for stale record residue.
    fn scan_leaf_residue(&mut self) -> Option<Result<FsEntry>> {
        while self.leaf_pos < self.fs.leaf_nodes.len() {
            let nidx = self.fs.leaf_nodes[self.leaf_pos];
            self.leaf_pos += 1;
            let buf = match self.node_buf(nidx) {
                Ok(b) => b,
                Err(e) => {
                    if let it @ Some(_) = self.fail(e) {
                        return it;
                    }
                    continue;
                }
            };
            let node = match Node::parse(buf, nidx) {
                Ok(n) => n,
                Err(e) => {
                    if let it @ Some(_) = self.fail(e) {
                        return it;
                    }
                    continue;
                }
            };
            let Some((fs_start, fs_end)) = node.free_space() else {
                continue;
            };
            let base = self.node_disk(nidx);
            let mut pos = fs_start;
            while pos + 8 <= fs_end {
                match catalog::sniff_record(&node.buf[..fs_end], pos) {
                    Some((len, key)) => {
                        let data = &node.buf[pos + key.total_len..pos + len];
                        let item =
                            self.residue_entry(data, &key, base + pos as u64, "leaf_free_space");
                        pos += len.max(2);
                        if let Some(it) = item {
                            match it {
                                Ok(e) => self.queue.push_back(Ok(e)),
                                Err(e) => {
                                    if let out @ Some(_) = self.fail(e) {
                                        return out;
                                    }
                                }
                            }
                        }
                    }
                    None => pos += 2, // catalog keys are even-aligned
                }
            }
            if let Some(item) = self.queue.pop_front() {
                return Some(item);
            }
        }
        self.phase = Phase::DeadNodes;
        None
    }

    /// Turn a sniffed record into a residue entry when it isn't a stale
    /// copy of a live record. `data` = record bytes after the key.
    fn residue_entry(
        &mut self,
        data: &[u8],
        key: &CatKey,
        disk_off: u64,
        kind: &'static str,
    ) -> Option<Result<FsEntry>> {
        let name = catalog::clean_name(&key.name);
        if self.fs.live_keys.contains(&(key.parent, name.clone()))
            || self.residue_seen.contains(&(key.parent, name.clone()))
        {
            return None;
        }
        let record = catalog::parse_record(data)?;
        let r = RecRef {
            node: 0,
            rec_off: 0,
            disk_off,
            parent: key.parent,
            name,
            rectype: match &record {
                CatRecord::Folder(_) => catalog::REC_FOLDER,
                CatRecord::File(_) => catalog::REC_FILE,
                _ => return None,
            },
            cnid: 0,
        };
        Some(match record {
            CatRecord::File(f) => {
                self.residue_seen.insert((key.parent, r.name.clone()));
                self.deleted_file_entry(&r, &f, kind)
            }
            CatRecord::Folder(f) => {
                self.residue_seen.insert((key.parent, r.name.clone()));
                let parent_path = self
                    .fs
                    .path_of(key.parent)
                    .unwrap_or_else(|| "/$DELETED".into());
                let mut meta = std::collections::HashMap::new();
                folder_meta(&mut meta, &f, &r);
                meta.insert("residue".into(), kind.into());
                Ok(FsEntry {
                    path: util::join_path(&parent_path, &r.name),
                    name: r.name.clone(),
                    entry_id: f.cnid as u64,
                    kind: EntryKind::Directory,
                    size: 0,
                    disk_offset: disk_off,
                    allocated_ranges: Vec::new(),
                    timestamps: catalog::timestamps(&f.dates),
                    status: FsEntryStatus::Deleted {
                        recovery: RecoveryState::Unknown,
                    },
                    meta,
                    magic: None,
                })
            }
            _ => return None,
        })
    }

    /// Recovery assessment + entry for a residue file record (the record
    /// bytes are supplied, not re-read — free-space bytes aren't indexed).
    fn deleted_file_entry(
        &mut self,
        r: &RecRef,
        f: &FileRec,
        residue_kind: &'static str,
    ) -> Result<FsEntry> {
        let extents = self
            .fs
            .fork_extents(&f.data_fork, f.cnid, extents::FORK_DATA);
        let (state, surviving, notes) = self.fs.recovery_for(&extents, f.data_fork.logical_size);
        let parent_path = self
            .fs
            .path_of(r.parent)
            .unwrap_or_else(|| "/$DELETED".into());
        let mut meta = std::collections::HashMap::new();
        file_meta(&mut meta, f, r);
        meta.insert("residue".into(), residue_kind.into());
        for (i, n) in notes.iter().enumerate() {
            meta.insert(format!("recovery_note_{i}"), n.clone());
        }
        Ok(FsEntry {
            path: util::join_path(&parent_path, &r.name),
            name: r.name.clone(),
            entry_id: f.cnid as u64,
            kind: EntryKind::File,
            size: f.data_fork.logical_size,
            disk_offset: r.disk_off,
            allocated_ranges: surviving,
            timestamps: catalog::timestamps(&f.dates),
            status: FsEntryStatus::Deleted { recovery: state },
            meta,
            magic: None,
        })
    }

    /// Phase D: B-tree nodes outside the leaf chain that still parse as
    /// leaf nodes — freed during compaction, full of deleted records.
    fn scan_dead_nodes(&mut self) -> Option<Result<FsEntry>> {
        // A hostile header can claim billions of nodes; only node indexes
        // the catalog file can actually hold are scannable (a node past
        // the file's extents can't exist).
        let file_bytes: u64 = self.fs.cat.ranges.iter().map(|(_, l)| *l).sum();
        let capacity = file_bytes / self.fs.cat.hdr.node_size.max(1) as u64;
        let max = (self.fs.cat.hdr.total_nodes as u64).min(capacity) as u32;
        while self.dead_node < max {
            let n = self.dead_node;
            self.dead_node += 1;
            if n == 0 || self.fs.leaf_nodes.contains(&n) {
                continue;
            }
            let buf = match self.fs.cat.read_node(self.fs.src.as_ref(), n) {
                Ok(b) => b,
                Err(_) => continue,
            };
            // Cheap descriptor sanity: leaf kind (-1 → 0xFF), height 1.
            if buf.len() < 16 || buf[8] != 0xFF || buf[9] != 1 {
                continue;
            }
            let node = match Node::parse(buf, n) {
                Ok(nd) if nd.num_recs > 0 => nd,
                _ => continue,
            };
            let base = self.node_disk(n);
            for i in 0..node.num_recs as usize {
                let Some(rec) = node.record(i) else { continue };
                let Some(key) = catalog::parse_key(rec) else {
                    continue;
                };
                let Some(data) = rec.get(key.total_len..) else {
                    continue;
                };
                if let Some(item) =
                    self.residue_entry(data, &key, base + node.offsets[i] as u64, "dead_node")
                {
                    match item {
                        Ok(e) => self.queue.push_back(Ok(e)),
                        Err(e) => {
                            if let out @ Some(_) = self.fail(e) {
                                return out;
                            }
                        }
                    }
                }
            }
            // The dead node's own free space may hold residue too.
            if let Some((fs0, fs1)) = node.free_space() {
                let mut pos = fs0;
                while pos + 8 <= fs1 {
                    match catalog::sniff_record(&node.buf[..fs1], pos) {
                        Some((len, key)) => {
                            let data = &node.buf[pos + key.total_len..pos + len];
                            let item = self.residue_entry(
                                data,
                                &key,
                                base + pos as u64,
                                "dead_node_free_space",
                            );
                            pos += len.max(2);
                            if let Some(it) = item {
                                match it {
                                    Ok(e) => self.queue.push_back(Ok(e)),
                                    Err(e) => {
                                        if let out @ Some(_) = self.fail(e) {
                                            return out;
                                        }
                                    }
                                }
                            }
                        }
                        None => pos += 2,
                    }
                }
            }
            if let Some(item) = self.queue.pop_front() {
                return Some(item);
            }
        }
        self.phase = Phase::OrphanExtents;
        None
    }

    /// Phase E: extents-overflow records for CNIDs with no catalog entry.
    fn scan_orphan_extents(&mut self) -> Option<Result<FsEntry>> {
        if !self.fs.opts.include_orphans {
            self.phase = Phase::Done;
            return None;
        }
        while self.orphan_ext_pos < self.fs.orphan_extents.len() {
            let cnid;
            let fork;
            let start_block;
            let disk_off;
            let ranges;
            {
                let o = &self.fs.orphan_extents[self.orphan_ext_pos];
                cnid = o.cnid;
                fork = o.fork;
                start_block = o.start_block;
                disk_off = o.disk_off;
                ranges = self.fs.extents_to_ranges(&o.extents, u64::MAX);
            }
            self.orphan_ext_pos += 1;
            if ranges.is_empty() {
                continue;
            }
            let size = ranges.iter().map(|(_, l)| *l).sum::<u64>();
            let mut meta = std::collections::HashMap::new();
            meta.insert("orphan".into(), "true".into());
            meta.insert("cnid".into(), cnid.to_string());
            meta.insert(
                "fork".into(),
                if fork == extents::FORK_RSRC {
                    "rsrc".into()
                } else {
                    "data".into()
                },
            );
            meta.insert("start_block".into(), start_block.to_string());
            meta.insert(
                "note".into(),
                "extents-overflow record for CNID with no catalog entry".into(),
            );
            meta.insert(
                "size_note".into(),
                "allocation size; logical size unknown".into(),
            );
            return Some(Ok(FsEntry {
                path: format!("{}/extents_{}", util::orphan_path(cnid as u64), cnid),
                name: format!("extents_{cnid}"),
                entry_id: cnid as u64,
                kind: EntryKind::Other,
                size,
                disk_offset: disk_off,
                allocated_ranges: ranges,
                timestamps: Default::default(),
                status: FsEntryStatus::Deleted {
                    recovery: RecoveryState::Unknown,
                },
                meta,
                magic: None,
            }));
        }
        self.phase = Phase::Done;
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
            if let Some(e) = self.notes.pop_front() {
                if self.fs.opts.strict {
                    self.finished = true;
                }
                return Some(Err(e));
            }
            if let Some(item) = self.queue.pop_front() {
                return Some(item);
            }
            match self.phase {
                Phase::Live => {
                    if self.cur_children.is_empty() {
                        match self.pending.pop_front() {
                            Some((path, cnid)) => {
                                if path == "/" {
                                    self.queue.push_back(Ok(self.root_entry()));
                                }
                                self.cur_path = path;
                                self.cur_children = self
                                    .fs
                                    .children
                                    .get(&cnid)
                                    .cloned()
                                    .unwrap_or_default()
                                    .into();
                                continue; // let queued items drain first
                            }
                            None => {
                                self.phase = Phase::OrphanLive;
                                continue;
                            }
                        }
                    }
                    if let Some(idx) = self.cur_children.pop_front() {
                        self.emitted.insert(idx);
                        let r = self.fs.recs[idx].clone();
                        let parent_path = self.cur_path.clone();
                        match self.live_entry(&r, &parent_path) {
                            Ok(e) => return Some(Ok(e)),
                            Err(e) => {
                                if let it @ Some(_) = self.fail(e) {
                                    return it;
                                }
                            }
                        }
                    }
                    // children exhausted → loop pops next pending dir.
                }
                Phase::OrphanLive => {
                    if let Some(item) = self.emit_orphan_live() {
                        return Some(item);
                    }
                }
                Phase::LeafResidue => {
                    if let Some(item) = self.scan_leaf_residue() {
                        return Some(item);
                    }
                }
                Phase::DeadNodes => {
                    if let Some(item) = self.scan_dead_nodes() {
                        return Some(item);
                    }
                }
                Phase::OrphanExtents => {
                    if let Some(item) = self.scan_orphan_extents() {
                        return Some(item);
                    }
                }
                Phase::Done => {
                    self.finished = true;
                }
            }
        }
    }
}

/// Common file-record meta keys.
fn file_meta(meta: &mut std::collections::HashMap<String, String>, f: &FileRec, r: &RecRef) {
    meta.insert("cnid".into(), f.cnid.to_string());
    meta.insert("flags".into(), format!("{:#06x}", f.flags));
    meta.insert("owner".into(), f.owner.to_string());
    meta.insert("group".into(), f.group.to_string());
    meta.insert("mode".into(), format!("{:#06o}", f.mode));
    if f.fd_type != 0 {
        meta.insert("finder_type".into(), fourcc(f.fd_type));
    }
    if f.fd_creator != 0 {
        meta.insert("finder_creator".into(), fourcc(f.fd_creator));
    }
    if f.fd_flags != 0 {
        meta.insert("finder_flags".into(), format!("{:#06x}", f.fd_flags));
    }
    if f.dates[4] != 0 {
        meta.insert("backup_date".into(), format!("{:#010x}", f.dates[4]));
    }
    if f.flags & catalog::FLAG_LOCKED != 0 {
        meta.insert("readonly".into(), "true".into());
    }
    if f.flags & catalog::FLAG_THREAD_EXISTS != 0 {
        meta.insert("has_thread".into(), "true".into());
    }
    if f.flags & catalog::FLAG_XATTR != 0 {
        meta.insert("has_xattrs".into(), "true".into());
    }
    if f.flags & catalog::FLAG_ACL != 0 {
        meta.insert("has_acl".into(), "true".into());
    }
    if f.user_flags & catalog::UF_COMPRESSED != 0 {
        meta.insert("uf_compressed".into(), "true".into());
    }
    if f.text_encoding != 0 {
        meta.insert("text_encoding".into(), format!("{:#010x}", f.text_encoding));
    }
    if f.ext_info.iter().any(|&b| b != 0) {
        meta.insert("finder_extinfo".into(), hex(&f.ext_info));
    }
    if f.data_fork.clump_size != 0 {
        meta.insert("data_clump_size".into(), f.data_fork.clump_size.to_string());
    }
    meta.insert("record_type".into(), format!("{:#06x}", r.rectype));
}

/// Common folder-record meta keys.
fn folder_meta(meta: &mut std::collections::HashMap<String, String>, f: &FolderRec, r: &RecRef) {
    meta.insert("cnid".into(), f.cnid.to_string());
    meta.insert("valence".into(), f.valence.to_string());
    meta.insert("flags".into(), format!("{:#06x}", f.flags));
    meta.insert("owner".into(), f.owner.to_string());
    meta.insert("group".into(), f.group.to_string());
    meta.insert("mode".into(), format!("{:#06o}", f.mode));
    if f.user_flags != 0 {
        meta.insert("user_flags".into(), format!("{:#04x}", f.user_flags));
    }
    if f.finder_info.iter().any(|&b| b != 0) {
        meta.insert("finder_info".into(), hex(&f.finder_info));
    }
    if f.text_encoding != 0 {
        meta.insert("text_encoding".into(), format!("{:#010x}", f.text_encoding));
    }
    if f.dates[4] != 0 {
        meta.insert("backup_date".into(), format!("{:#010x}", f.dates[4]));
    }
    if r.parent == catalog::CNID_METADATA_DIR || r.parent == catalog::CNID_DIR_METADATA_DIR {
        meta.insert("metadata_dir".into(), "true".into());
    }
    meta.insert("record_type".into(), format!("{:#06x}", r.rectype));
}

/// Lowercase hex of a byte string.
fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

/// Render a big-endian u32 FourCC as ASCII (hex if unprintable).
fn fourcc(v: u32) -> String {
    let b = v.to_be_bytes();
    if b.iter().all(|c| c.is_ascii_graphic() || *c == b' ') {
        String::from_utf8_lossy(&b).into_owned()
    } else {
        format!("{v:#010x}")
    }
}
