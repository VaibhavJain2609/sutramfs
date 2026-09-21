//! Streaming directory walk + deleted-entry emission.
//!
//! Live entries come from directory records (`parent_oid → name → file_id`),
//! plus sibling links (extra hardlink names) and orphan inodes with no
//! directory record. Deleted entries are inodes present in a prior
//! checkpoint's fs tree but absent from the live tree.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use sutram_fs::util;
use sutram_fs::{EntryKind, FsEntry, FsEntryStatus, FsTimestamp, Result, Timestamps};

use crate::fs::ApfsFs;
use crate::jrec::{self, ExtentRec, InodeVal};

/// A deleted inode recovered from a prior checkpoint generation.
pub(crate) struct DeletedInode {
    pub oid: u64,
    pub inode: InodeVal,
    /// Disk offset of the inode record's key in the old fs tree.
    pub record_off: u64,
    /// Checkpoint xid the record came from.
    pub from_xid: u64,
    /// Old-generation extents keyed by the inode's private_id.
    pub extents: Vec<ExtentRec>,
    /// file_id → (parent_oid, name) in the old generation (for paths).
    pub old_names: HashMap<u64, (u64, String)>,
}

/// One planned live entry emission.
enum Plan {
    /// A directory record (name under a parent inode).
    Drec {
        parent_oid: u64,
        name: String,
        file_id: u64,
        record_off: u64,
        date_added: i64,
        flags: u16,
        name_hash: Option<u32>,
        sibling_id: Option<u64>,
    },
    /// A sibling link — an additional hardlink name for `oid`.
    Sibling {
        oid: u64,
        sibling_id: u64,
        parent_oid: u64,
        name: String,
        record_off: u64,
    },
    /// An inode with no directory record.
    Orphan { oid: u64, record_off: u64 },
}

/// The streaming walk iterator.
pub(crate) struct Walk<'m> {
    fs: &'m ApfsFs,
    /// file_id → (parent_oid, name) from live drecs (first wins).
    names: HashMap<u64, (u64, String)>,
    queue: VecDeque<Result<FsEntry>>,
    plans: Vec<Plan>,
    /// Path cache: inode oid → absolute path without leading "/" for root
    /// (`""` = filesystem root).
    paths: HashMap<u64, Option<String>>,
    deleted_done: bool,
    strict_failed: bool,
}

impl<'m> Walk<'m> {
    pub(crate) fn new(fs: &'m ApfsFs) -> Self {
        let mut names = HashMap::new();
        let mut linked = HashSet::new();
        for d in &fs.view.recs.drecs {
            names
                .entry(d.file_id)
                .or_insert((d.parent_oid, d.name.clone()));
            linked.insert(d.file_id);
        }

        // Build the emission plan: live drecs + sibling links + orphans.
        let mut plans: Vec<Plan> = Vec::new();
        for d in &fs.view.recs.drecs {
            plans.push(Plan::Drec {
                parent_oid: d.parent_oid,
                name: d.name.clone(),
                file_id: d.file_id,
                record_off: d.off,
                date_added: d.date_added,
                flags: d.flags,
                name_hash: d.name_hash,
                sibling_id: d.sibling_id,
            });
        }
        for s in &fs.view.recs.sibling_links {
            plans.push(Plan::Sibling {
                oid: s.oid,
                sibling_id: s.sibling_id,
                parent_oid: s.parent_id,
                name: s.name.clone(),
                record_off: s.off,
            });
        }
        if fs.opts.include_orphans {
            for (&oid, &(off, _)) in &fs.view.recs.inodes {
                if oid != jrec::ROOT_DIR_INODE && !linked.contains(&oid) {
                    plans.push(Plan::Orphan {
                        oid,
                        record_off: off,
                    });
                }
            }
        }

        let mut w = Walk {
            fs,
            names,
            queue: VecDeque::new(),
            plans,
            paths: HashMap::new(),
            deleted_done: false,
            strict_failed: false,
        };
        // Mount-time warnings stream out first (lenient provenance). Drained
        // once — `FsError` isn't `Clone`, so the fs holds them in a Mutex.
        if let Ok(mut w_store) = fs.warnings.lock() {
            for e in w_store.drain(..) {
                w.queue.push_back(Err(e));
            }
        }
        w
    }

    /// Absolute path of a directory inode in the live view, `None` when the
    /// chain is broken or cyclic. `oid == ROOT_DIR_INODE` → `Some("")`.
    fn dir_path(&mut self, oid: u64, depth: usize) -> Option<String> {
        if oid == jrec::ROOT_DIR_INODE {
            return Some(String::new());
        }
        if depth > 64 {
            return None;
        }
        if let Some(p) = self.paths.get(&oid) {
            return p.clone();
        }
        let (parent, name) = self.names.get(&oid)?.clone();
        let base = self.dir_path(parent, depth + 1)?;
        let path = util::join_path(&base, &name);
        self.paths.insert(oid, Some(path.clone()));
        Some(path)
    }

    /// Emit the fs entry for inode `oid` at `path`/`name`.
    ///
    /// `record_off` is the disk offset of the record that produced the entry
    /// (the drec/sibling key); `iv` is the inode value when one exists.
    fn emit_inode(
        &self,
        oid: u64,
        iv: Option<&InodeVal>,
        path: String,
        name: String,
        record_off: u64,
        extra_meta: Vec<(String, String)>,
    ) -> FsEntry {
        let apsb = &self.fs.view.apsb;
        let mut kind = EntryKind::Other;
        let mut size = 0u64;
        let mut extents: Vec<ExtentRec> = Vec::new();
        let mut meta = HashMap::from([
            ("inode".into(), format!("{oid:#x}")),
            (
                "fs_tree_root".into(),
                format!("{:#x}", self.fs.view.root_paddr),
            ),
            ("checkpoint_xid".into(), self.fs.checkpoint_xid.to_string()),
            ("volume_uuid".into(), apsb.uuid.clone()),
        ]);
        let mut ts = Timestamps::default();

        match iv {
            Some(iv) => {
                kind = match iv.mode & jrec::S_IFMT {
                    jrec::S_IFDIR => EntryKind::Directory,
                    jrec::S_IFREG => EntryKind::File,
                    jrec::S_IFLNK => EntryKind::Symlink,
                    _ => EntryKind::Other,
                };
                extents = self
                    .fs
                    .view
                    .recs
                    .extents
                    .get(&iv.private_id)
                    .cloned()
                    .unwrap_or_default();
                size = iv.dstream.map(|d| d.size).unwrap_or_else(|| {
                    extents
                        .iter()
                        .map(|e| e.logical_addr.saturating_add(e.len))
                        .max()
                        .unwrap_or(0)
                });
                meta.insert("mode".into(), format!("0{:o}", iv.mode));
                meta.insert("uid".into(), iv.owner.to_string());
                meta.insert("gid".into(), iv.group.to_string());
                meta.insert(
                    if kind == EntryKind::Directory {
                        "nchildren".into()
                    } else {
                        "nlink".into()
                    },
                    iv.nchildren_or_nlink.to_string(),
                );
                meta.insert("internal_flags".into(), format!("{:#x}", iv.internal_flags));
                meta.insert("bsd_flags".into(), format!("{:#x}", iv.bsd_flags));
                meta.insert("private_id".into(), format!("{:#x}", iv.private_id));
                meta.insert("parent_id".into(), format!("{:#x}", iv.parent_id));
                meta.insert(
                    "default_protection_class".into(),
                    iv.default_protection_class.to_string(),
                );
                meta.insert(
                    "write_generation_counter".into(),
                    iv.write_generation_counter.to_string(),
                );
                if iv.internal_flags & jrec::inode_flags::APFS_PRIVATE != 0 {
                    meta.insert("apfs_private".into(), "true".into());
                }
                if let Some(d) = iv.dstream {
                    meta.insert("dstream_alloced_size".into(), d.alloced_size.to_string());
                    meta.insert(
                        "dstream_bytes_written".into(),
                        d.total_bytes_written.to_string(),
                    );
                    meta.insert("dstream_bytes_read".into(), d.total_bytes_read.to_string());
                    if d.default_crypto_id != 0 {
                        meta.insert(
                            "default_crypto_id".into(),
                            format!("{:#x}", d.default_crypto_id),
                        );
                    }
                }
                if let Some(f) = iv.prev_fsize {
                    meta.insert("prev_fsize".into(), f.to_string());
                }
                if let Some(x) = iv.snap_xid {
                    meta.insert("inode_snap_xid".into(), x.to_string());
                }
                if iv.internal_flags & jrec::inode_flags::IS_SPARSE != 0 {
                    meta.insert("sparse".into(), "true".into());
                }
                if let Some(&(nc, tsz)) = self.fs.view.recs.dir_stats.get(&oid) {
                    meta.insert("dir_stats_children".into(), nc.to_string());
                    meta.insert("dir_stats_size".into(), tsz.to_string());
                }
                if let Some(b) = iv.sparse_bytes {
                    meta.insert("sparse_bytes".into(), b.to_string());
                }
                if let Some(d) = iv.document_id {
                    meta.insert("document_id".into(), d.to_string());
                }
                if let Some(r) = iv.rdev {
                    meta.insert("rdev".into(), format!("{r:#x}"));
                }
                if iv.has_finder_info {
                    meta.insert("finder_info".into(), "true".into());
                }
                ts = Timestamps {
                    created: Some(fs_ts(iv.create_time)),
                    modified: Some(fs_ts(iv.mod_time)),
                    accessed: Some(fs_ts(iv.access_time)),
                    changed: Some(fs_ts(iv.change_time)),
                    deleted: None,
                };
            }
            None => {
                meta.insert("note".into(), "drec with no matching inode record".into());
            }
        }

        // Extents → allocated_ranges. Encrypted extents are listed as-is —
        // `read_file` yields ciphertext; decryption is never attempted.
        let bs = self.fs.nx.block_size as u64;
        extents.sort_by_key(|e| e.logical_addr);
        let mut ranges = Vec::with_capacity(extents.len());
        let mut any_crypto = self.fs.view.recs.crypto_oids.contains(&oid);
        for (i, ex) in extents.iter().enumerate() {
            ranges.push((ex.phys_block.saturating_mul(bs), ex.len));
            meta.insert(format!("extent_{i}_record_off"), format!("{:#x}", ex.off));
            if ex.flags != 0 {
                meta.insert(format!("extent_{i}_flags"), format!("{:#x}", ex.flags));
            }
            if ex.crypto_id != 0 {
                any_crypto = true;
                meta.insert(
                    format!("extent_{i}_crypto_id"),
                    format!("{:#x}", ex.crypto_id),
                );
            }
        }
        if any_crypto {
            meta.insert("extent_encrypted".into(), "true".into());
        }

        // Xattrs (names + sizes; symlink target lifted out when embedded).
        if let Some(xattrs) = self.fs.view.recs.xattrs.get(&oid) {
            for x in xattrs {
                meta.insert(format!("xattr_{}", x.name), x.data_len.to_string());
                meta.insert(format!("xattr_{}_flags", x.name), format!("{:#x}", x.flags));
                meta.insert(format!("xattr_{}_off", x.name), format!("{:#x}", x.off));
                if let Some(s) = x.stream_oid {
                    meta.insert(format!("xattr_{}_stream_oid", x.name), format!("{s:#x}"));
                }
                if x.name == "com.apple.fs.symlink" {
                    if let Some(d) = &x.embedded {
                        let t = String::from_utf8_lossy(d);
                        meta.insert(
                            "symlink_target".into(),
                            t.trim_end_matches('\0').to_string(),
                        );
                    }
                }
            }
        }

        // Slack: bytes allocated beyond the logical EOF.
        let alloc: u64 = ranges.iter().map(|(_, l)| *l).sum();
        if alloc > size {
            if let Some(&(off, len)) = ranges.last() {
                let slack = alloc - size;
                meta.insert("slack_len".into(), slack.to_string());
                if len >= slack {
                    meta.insert("slack_offset".into(), (off + len - slack).to_string());
                } else {
                    meta.insert("slack_offset".into(), off.to_string());
                }
            }
        }

        for (k, v) in extra_meta {
            meta.insert(k, v);
        }
        if self.fs.encrypted {
            meta.insert("volume_encrypted".into(), "true".into());
        }
        if self.fs.sealed {
            meta.insert("volume_sealed".into(), "true".into());
        }

        let mut e = FsEntry {
            path,
            name: util::sanitize_name(&name),
            entry_id: oid,
            kind,
            size,
            disk_offset: record_off,
            allocated_ranges: ranges,
            timestamps: ts,
            status: FsEntryStatus::Live,
            meta,
            magic: None,
        };
        e.magic = self.fs.magic_for(&e);
        e
    }

    /// Emit one deleted inode recovered from a prior checkpoint.
    fn emit_deleted(&self, d: &DeletedInode) -> FsEntry {
        let iv = &d.inode;
        let (mut cur, name) = d
            .old_names
            .get(&d.oid)
            .cloned()
            .unwrap_or((jrec::ROOT_DIR_INODE, format!("inode_{:x}", d.oid)));
        // Reconstruct the path inside the old generation; fall back to the
        // orphan bucket when the chain is broken.
        let mut components = vec![name.clone()];
        let mut path = None;
        for _ in 0..64 {
            if cur == jrec::ROOT_DIR_INODE {
                components.reverse();
                path = Some(format!("/{}", components.join("/")));
                break;
            }
            match d.old_names.get(&cur) {
                Some((p, n)) => {
                    components.push(n.clone());
                    cur = *p;
                }
                None => break,
            }
        }
        let path = path.unwrap_or_else(|| util::orphan_path(d.oid));

        let kind = match iv.mode & jrec::S_IFMT {
            jrec::S_IFDIR => EntryKind::Directory,
            jrec::S_IFREG => EntryKind::File,
            jrec::S_IFLNK => EntryKind::Symlink,
            _ => EntryKind::Other,
        };
        let size = iv.dstream.map(|s| s.size).unwrap_or_else(|| {
            d.extents
                .iter()
                .map(|e| e.logical_addr.saturating_add(e.len))
                .max()
                .unwrap_or(0)
        });
        let (recovery, surviving, notes) = self.fs.recovery_for_deleted(&d.extents, size);
        let mut meta = HashMap::from([
            ("inode".into(), format!("{:#x}", d.oid)),
            ("deleted".into(), "true".into()),
            ("recovered_from_xid".into(), d.from_xid.to_string()),
            ("checkpoint_xid".into(), self.fs.checkpoint_xid.to_string()),
            ("private_id".into(), format!("{:#x}", iv.private_id)),
            ("parent_id".into(), format!("{:#x}", iv.parent_id)),
            ("mode".into(), format!("0{:o}", iv.mode)),
        ]);
        if !notes.is_empty() {
            meta.insert("note".into(), notes.join("; "));
        }
        FsEntry {
            path,
            name: util::sanitize_name(&name),
            entry_id: d.oid,
            kind,
            size,
            disk_offset: d.record_off,
            allocated_ranges: surviving,
            timestamps: Timestamps {
                created: Some(fs_ts(iv.create_time)),
                modified: Some(fs_ts(iv.mod_time)),
                accessed: Some(fs_ts(iv.access_time)),
                changed: Some(fs_ts(iv.change_time)),
                deleted: None,
            },
            status: FsEntryStatus::Deleted { recovery },
            meta,
            magic: None,
        }
    }
}

/// APFS timestamps: signed ns since Unix epoch; 0 = unset.
fn fs_ts(ns: i64) -> FsTimestamp {
    FsTimestamp {
        value: if ns == 0 { None } else { Some(ns) },
        raw_value: ns as u64,
        raw_encoding: "apfs-nano",
        granularity: Duration::from_nanos(1),
    }
}

impl Iterator for Walk<'_> {
    type Item = Result<FsEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.strict_failed {
            return None;
        }
        if let Some(item) = self.queue.pop_front() {
            if self.fs.opts.strict && item.is_err() {
                self.strict_failed = true;
            }
            return Some(item);
        }
        if self.plans.is_empty() {
            if !self.deleted_done {
                self.deleted_done = true;
                for i in 0..self.fs.deleted.len() {
                    let e = self.emit_deleted(&self.fs.deleted[i]);
                    self.queue.push_back(Ok(e));
                }
                return self.queue.pop_front();
            }
            return None;
        }
        let plan = self.plans.remove(0);
        let entry = match plan {
            Plan::Drec {
                parent_oid,
                name,
                file_id,
                record_off,
                date_added,
                flags,
                name_hash,
                sibling_id,
            } => {
                let (path, mut extra) = match self.dir_path(parent_oid, 0) {
                    Some(b) => (util::join_path(&b, &name), Vec::new()),
                    None => (
                        util::orphan_path(file_id),
                        vec![("note".into(), "parent directory chain broken".into())],
                    ),
                };
                extra.push((
                    "drec_type".into(),
                    format!("{:#x}", flags & jrec::DREC_TYPE_MASK),
                ));
                if date_added != 0 {
                    extra.push(("date_added".into(), date_added.to_string()));
                }
                if let Some(h) = name_hash {
                    extra.push(("name_hash".into(), format!("{h:#x}")));
                }
                if let Some(s) = sibling_id {
                    extra.push(("sibling_id".into(), format!("{s:#x}")));
                }
                let iv = self.fs.view.recs.inodes.get(&file_id).map(|(_, v)| v);
                self.emit_inode(file_id, iv, path, name, record_off, extra)
            }
            Plan::Sibling {
                oid,
                sibling_id,
                parent_oid,
                name,
                record_off,
            } => {
                let (path, mut extra) = match self.dir_path(parent_oid, 0) {
                    Some(b) => (util::join_path(&b, &name), Vec::new()),
                    None => (
                        util::orphan_path(oid),
                        vec![("note".into(), "hardlink parent chain broken".into())],
                    ),
                };
                extra.push(("hardlink".into(), "true".into()));
                extra.push(("sibling_id".into(), format!("{sibling_id:#x}")));
                // Cross-check the sibling map (sibling_id → file_id).
                match self.fs.view.recs.sibling_map.get(&sibling_id) {
                    Some(&target) if target == oid => {
                        extra.push(("sibling_map_ok".into(), "true".into()))
                    }
                    Some(&target) => extra.push((
                        "note".into(),
                        format!("sibling map resolves to {target:#x}, not {oid:#x}"),
                    )),
                    None => extra.push(("note".into(), "sibling map entry missing".into())),
                }
                let iv = self.fs.view.recs.inodes.get(&oid).map(|(_, v)| v);
                self.emit_inode(oid, iv, path, name, record_off, extra)
            }
            Plan::Orphan { oid, record_off } => {
                let iv = self.fs.view.recs.inodes.get(&oid).map(|(_, v)| v);
                let name = format!("inode_{oid:x}");
                self.emit_inode(
                    oid,
                    iv,
                    util::orphan_path(oid),
                    name,
                    record_off,
                    vec![("orphan".into(), "true".into())],
                )
            }
        };
        Some(Ok(entry))
    }
}
