//! [`BtrfsFs`] — the mounted filesystem: superblock → chunk map → root
//! tree → FS-tree indexes → extent tree → COW history, plus recovery
//! assessment and the `FileSystem` impl.
//!
//! Pipeline (port of `btrfs_parser.py`'s mount sequence, extended):
//!
//! ```text
//! superblock (+mirrors) ── sys_chunk_array ──▶ chunk tree ──▶ ChunkMap
//!        │                                        │
//!        └── root tree ──▶ ROOT_ITEMs ──▶ per-subvolume FS trees
//!        └── backup roots ──▶ old-generation trees (deleted recovery)
//!        └── extent tree ──▶ allocation map + backrefs (provenance)
//!        └── free-space tree (v2) ──▶ unallocated cross-check
//! ```

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;

use sutram_fs::util;
use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsError, FsInfo, FsParser, FileSystem,
    MountOptions, RecoveryState, Result,
};
use sutram_io::ByteSource;

use crate::chunk::{self, ChunkMap};
use crate::index::{
    self, ExtentIndex, ExtentRec, InodeRec, RootEntry, TreeIndex,
};
use crate::ondisk::{self, objid, root_flags};
use crate::read::ExtentReader;
use crate::superblock::{self, Superblock};
use crate::walk::{PlanItem, Walk};

/// Structural clone of an [`FsError`] (the `Io` variant degrades to
/// `Corrupt` with the message preserved — `io::Error` isn't cloneable).
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
        FsError::Io(e) => FsError::corrupt(0, format!("i/o: {e}")),
        FsError::NotFound { path } => FsError::NotFound { path: path.clone() },
        FsError::InvalidInput { msg } => FsError::InvalidInput { msg: msg.clone() },
    }
}

/// The parser entry point.
///
/// ```
/// use sutram_btrfs::BtrfsParser;
/// use sutram_fs::FsParser;
/// let p = BtrfsParser;
/// assert_eq!(p.name(), "btrfs");
/// ```
pub struct BtrfsParser;

impl FsParser for BtrfsParser {
    fn name(&self) -> &'static str {
        "btrfs"
    }

    fn detect(&self, src: &dyn ByteSource) -> DetectConfidence {
        superblock::detect(src)
    }

    fn mount_with(
        &self,
        src: Arc<dyn ByteSource>,
        opts: &MountOptions,
    ) -> Result<Box<dyn FileSystem>> {
        Ok(Box::new(BtrfsFs::mount(src, opts.clone())?))
    }
}

/// Recovery verdict for one deleted inode: per-extent surviving ranges.
#[derive(Debug, Clone)]
pub(crate) struct Recovery {
    pub state: RecoveryState,
    /// Parallel to `InodeRec.extents`: surviving *physical* subranges for
    /// uncompressed extents, or the whole-blob ranges for compressed
    /// (empty vec = extent lost; holes/inlines store their marker range).
    pub surviving: Vec<Vec<(u64, u64)>>,
    pub notes: Vec<String>,
}

/// One planned walk item — an entry location or a deferred error record.
#[derive(Debug)]
pub(crate) struct EntryLoc {
    /// Index into `BtrfsFs::trees`.
    pub tree: usize,
    /// Inode number inside that tree (may be absent → dangling record).
    pub ino: u64,
    /// Name+type override for name-only deleted entries (from a dir item
    /// whose inode record is gone).
    pub stub: Option<(String, u8)>,
}

/// A mounted BTRFS volume.
pub struct BtrfsFs {
    src: Arc<dyn ByteSource>,
    sb: Superblock,
    /// The primary superblock was unusable; a mirror was mounted.
    used_mirror: bool,
    pub(crate) opts: MountOptions,
    map: ChunkMap,
    /// Live trees (FS_TREE first, then subvolumes by objectid), then
    /// old-generation trees (newest first).
    trees: Vec<TreeIndex>,
    /// live tree index by objectid.
    live_tree_of: HashMap<u64, usize>,
    extent_index: ExtentIndex,
    /// Free logical ranges from the free-space tree (when present).
    free_tree_ranges: Vec<(u64, u64)>,
    /// `(subvol, ino, extent logical)` referenced by *live* trees.
    live_refs: HashSet<(u64, u64, u64)>,
    /// The walk plan — entry locations in emission order, interleaved with
    /// deferred error records.
    plan: Vec<PlanItem>,
    /// Recovery assessment per deleted inode, keyed by (tree_idx, ino).
    recovery: HashMap<(usize, u64), Recovery>,
    /// Whether the extent tree was usable at mount.
    extent_tree_ok: bool,
    /// Device capacities from DEV_ITEMs in the chunk tree.
    dev_total_bytes: u64,
    /// uid → login name, resolved from the volume's passwd file
    /// (port of Python `resolve_names_from_filesystem`).
    uid_names: HashMap<u64, String>,
    /// gid → group name, resolved from the volume's group file.
    gid_names: HashMap<u64, String>,
}

impl BtrfsFs {
    pub(crate) fn mount(src: Arc<dyn ByteSource>, opts: MountOptions) -> Result<Self> {
        let (sb, used_mirror) = superblock::read_superblock(src.as_ref())?;
        let nodesize = sb.nodesize;
        let csum_type = sb.csum_type;

        // -- chunk map: sys_chunk_array then the full chunk tree ---------
        let mut map = chunk::parse_sys_chunk_array(&sb.sys_chunk_array);
        let mount_errors =
            chunk::read_chunk_tree(src.as_ref(), sb.chunk_root, &mut map, nodesize);

        if map.chunks.is_empty() {
            return Err(FsError::corrupt(
                sb.source_offset,
                "no usable chunks (sys_chunk_array empty and chunk tree unreadable)",
            ));
        }

        let dev_total_bytes = chunk::dev_items(
            src.as_ref(),
            sb.chunk_root,
            &map,
            nodesize,
        )
        .iter()
        .map(|d| d.total_bytes)
        .sum();

        // -- root tree → subvolumes & system trees -----------------------
        let root_idx = index::index_root_tree(
            src.as_ref(),
            &map,
            nodesize,
            csum_type,
            sb.root,
        );
        let mut errors = mount_errors;
        errors.extend(root_idx.errors.iter().map(clone_err));

        if root_idx.roots.is_empty() && opts.strict {
            return Err(FsError::corrupt(sb.root, "root tree unreadable/empty"));
        }

        // -- live FS trees ------------------------------------------------
        let mut trees: Vec<TreeIndex> = Vec::new();
        let mut live_tree_of: HashMap<u64, usize> = HashMap::new();

        // FS_TREE (default subvolume) first, then objectid ≥ 256 subvols
        // in order — mirrors `find_all_subvolumes`.
        let mut live_roots: Vec<&RootEntry> = Vec::new();
        if let Some(fs) = root_idx.roots.get(&objid::FS_TREE) {
            live_roots.push(fs);
        }
        let mut subs: Vec<&RootEntry> = root_idx
            .roots
            .values()
            .filter(|r| r.objectid >= objid::FIRST_FREE)
            .collect();
        subs.sort_by_key(|r| r.objectid);
        live_roots.extend(subs);

        for root in live_roots {
            let mount_name = if root.objectid == objid::FS_TREE {
                String::new()
            } else {
                root.name
                    .clone()
                    .unwrap_or_else(|| format!("subvol_{}", root.objectid))
            };
            let idx = index::index_fs_tree(
                src.as_ref(),
                &map,
                nodesize,
                csum_type,
                root.objectid,
                mount_name,
                root.bytenr,
                root.generation,
                true,
                root.flags & root_flags::RDONLY != 0,
                root.is_snapshot,
            );
            live_tree_of.insert(root.objectid, trees.len());
            trees.push(idx);
        }

        // -- extent tree → allocation/backref index -----------------------
        let extent_root = root_idx
            .roots
            .get(&objid::EXTENT_TREE)
            .map(|r| r.bytenr)
            .unwrap_or(0);
        let extent_index = index::index_extent_tree(
            src.as_ref(),
            &map,
            nodesize,
            csum_type,
            extent_root,
        );
        let extent_tree_ok = extent_root != 0 && extent_index.errors.is_empty();
        errors.extend(extent_index.errors.iter().map(clone_err));

        // -- free-space tree (optional, v2) --------------------------------
        let free_root = root_idx
            .roots
            .get(&objid::FREE_SPACE_TREE)
            .map(|r| r.bytenr)
            .unwrap_or(0);
        let (free_tree_ranges, free_errs) = index::index_free_space_tree(
            src.as_ref(),
            &map,
            nodesize,
            csum_type,
            free_root,
            sb.sectorsize as u64,
        );
        errors.extend(free_errs.iter().map(clone_err));

        // -- live extent reference set ------------------------------------
        let mut live_refs = HashSet::new();
        for tree in &trees {
            for (ino, rec) in &tree.inodes {
                for ex in &rec.extents {
                    if ex.logical != 0 {
                        live_refs.insert((tree.objectid, *ino, ex.logical));
                    }
                }
            }
        }

        // -- COW history: backup roots → old-generation trees --------------
        let mut old_specs: Vec<(u64, u64, u64, String)> = Vec::new(); // (objectid, root, gen, name)
        let mut seen_old: HashSet<(u64, u64)> = HashSet::new();
        for backup in &sb.backup_roots {
            // The backup's own root tree lists that generation's roots.
            let old_root = index::index_root_tree(
                src.as_ref(),
                &map,
                nodesize,
                csum_type,
                backup.tree_root,
            );
            for r in old_root.roots.values() {
                if r.generation >= sb.generation || r.bytenr == 0 {
                    continue; // not actually older
                }
                if seen_old.insert((r.objectid, r.bytenr)) {
                    let name = r
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("subvol_{}", r.objectid));
                    old_specs.push((r.objectid, r.bytenr, r.generation, name));
                }
            }
            // The backup's fs_root is the FS_TREE for that generation.
            if backup.fs_root != 0
                && backup.fs_root_gen < sb.generation
                && seen_old.insert((objid::FS_TREE, backup.fs_root))
            {
                old_specs.push((objid::FS_TREE, backup.fs_root, backup.fs_root_gen, String::new()));
            }
            errors.extend(old_root.errors);
        }
        // Only filesystem trees (FS_TREE + subvolumes) yield entries.
        old_specs.retain(|(oid, _, _, _)| *oid == objid::FS_TREE || *oid >= objid::FIRST_FREE);
        // Newest old trees first so dedup keeps the freshest version.
        old_specs.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)));
        old_specs.truncate(64); // hard cap on COW-history depth

        for (objectid, bytenr, gen, name) in old_specs {
            let mount_name = if objectid == objid::FS_TREE {
                String::new()
            } else if let Some(&li) = live_tree_of.get(&objectid) {
                trees[li].mount_name.clone()
            } else {
                name
            };
            let idx = index::index_fs_tree(
                src.as_ref(),
                &map,
                nodesize,
                csum_type,
                objectid,
                mount_name,
                bytenr,
                gen,
                false,
                false,
                false,
            );
            trees.push(idx);
        }

        let mut fs = BtrfsFs {
            src,
            sb,
            used_mirror,
            opts,
            map,
            trees,
            live_tree_of,
            extent_index,
            free_tree_ranges,
            live_refs,
            plan: Vec::new(),
            recovery: HashMap::new(),
            extent_tree_ok,
            dev_total_bytes,
            uid_names: HashMap::new(),
            gid_names: HashMap::new(),
        };
        fs.load_id_maps();
        fs.build_plan();
        // Mount-phase errors trail the plan as deferred error records.
        for e in errors {
            fs.plan.push(PlanItem::Error(e));
        }
        // Pre-assess every deleted entry so `read_file` and the walk agree
        // (bounded: one assessment per deleted inode).
        let deleted: Vec<(usize, u64)> = fs
            .plan
            .iter()
            .filter_map(|p| match p {
                PlanItem::Entry(loc) if !fs.is_live(loc.tree, loc.ino) => {
                    Some((loc.tree, loc.ino))
                }
                _ => None,
            })
            .collect();
        for (ti, ino) in deleted {
            let rc = {
                let tree = &fs.trees[ti];
                let rec = tree.inodes.get(&ino);
                fs.assess_deleted(tree, ino, rec)
            };
            fs.recovery.insert((ti, ino), rc);
        }
        Ok(fs)
    }

    /// Plan item accessor for the walk iterator.
    pub(crate) fn plan_item(&self, idx: usize) -> Option<&PlanItem> {
        self.plan.get(idx)
    }

    /// Reconstructed error record at plan position `idx` (FsError isn't
    /// `Clone` — `io::Error` degrades to `Corrupt` with the text kept).
    pub(crate) fn plan_error(&self, idx: usize) -> Option<FsError> {
        match self.plan.get(idx) {
            Some(PlanItem::Error(e)) => Some(clone_err(e)),
            _ => None,
        }
    }

    /// Resolve uid→user / gid→group by reading the volume's passwd and
    /// group files — the Python `resolve_names_from_filesystem` port.
    /// Searches `/etc/{passwd,group}` and `/root/etc/{passwd,group}`.
    fn load_id_maps(&mut self) {
        const CANDIDATES: &[(&str, bool)] = &[
            ("/etc/passwd", true),
            ("/root/etc/passwd", true),
            ("/etc/group", false),
            ("/root/etc/group", false),
        ];
        let live: Vec<usize> = self
            .trees
            .iter()
            .enumerate()
            .filter(|(_, t)| t.is_live)
            .map(|(i, _)| i)
            .collect();
        for ti in live {
            let inos: Vec<u64> = self.trees[ti].inodes.keys().copied().collect();
            for ino in inos {
                let (path, _) = self.trees[ti].build_path(ino);
                let Some(&(_, is_passwd)) =
                    CANDIDATES.iter().find(|(p, _)| *p == path)
                else {
                    continue;
                };
                let Some(rec) = self.trees[ti].inodes.get(&ino) else {
                    continue;
                };
                let size = rec.item.as_ref().map(|i| i.size).unwrap_or(0);
                if size == 0 || size > (1 << 20) {
                    continue; // passwd/group are small; cap at 1 MiB
                }
                let segs: Vec<(index::Extent, Vec<(u64, u64)>)> = rec
                    .extents
                    .iter()
                    .map(|e| (e.clone(), e.live_ranges()))
                    .collect();
                let mut r =
                    ExtentReader::new(self.src.clone(), &self.map, segs, size);
                let mut buf = Vec::new();
                if r.read_to_end(&mut buf).is_err() {
                    continue;
                }
                let map = if is_passwd {
                    &mut self.uid_names
                } else {
                    &mut self.gid_names
                };
                for (id, name) in parse_id_file(&buf) {
                    map.entry(id).or_insert(name);
                }
            }
        }
    }

    /// True when `(tree, ino)` is a live-tree inode.
    fn is_live(&self, tree: usize, ino: u64) -> bool {
        self.trees[tree].is_live && !self.trees[tree].orphans.contains(&ino)
    }

    /// Build the walk plan: live trees, orphan records, old-generation
    /// (deleted/prior-version) entries, dangling dir entries.
    fn build_plan(&mut self) {
        let mut emitted_old: HashMap<(u64, u64), u64> = HashMap::new(); // (subvol,ino) → gen emitted

        for ti in 0..self.trees.len() {
            let items = {
                let tree = &self.trees[ti];
                let mut items = Vec::new();
                if tree.is_live {
                    // subvolume root first
                    items.push(PlanItem::Entry(EntryLoc {
                        tree: ti,
                        ino: objid::FIRST_FREE,
                        stub: None,
                    }));
                }
                for &ino in tree.inodes.keys() {
                    if tree.is_live && ino == objid::FIRST_FREE {
                        continue; // already emitted as root
                    }
                    if !tree.is_live {
                        // Old-generation tree: emit only deleted or
                        // superseded inodes; dedupe across backup gens.
                        let sub = tree.objectid;
                        if ino == objid::FIRST_FREE && self.live_tree_of.contains_key(&sub) {
                            // The subvolume still lives — its root dir's
                            // churn is bookkeeping, not a deleted artefact.
                            continue;
                        }
                        if let Some(&g) = emitted_old.get(&(sub, ino)) {
                            if g >= tree.generation {
                                continue;
                            }
                        }
                        match self
                            .live_tree_of
                            .get(&sub)
                            .and_then(|&li| self.trees[li].inodes.get(&ino))
                        {
                            Some(live_rec)
                                if same_version(live_rec, tree.inodes.get(&ino)) =>
                            {
                                continue; // unchanged between generations
                            }
                            _ => {}
                        }
                        emitted_old.insert((sub, ino), tree.generation);
                    }
                    items.push(PlanItem::Entry(EntryLoc {
                        tree: ti,
                        ino,
                        stub: None,
                    }));
                }
                // Orphan inos with no inode record at all → name-only stub.
                for &ino in &tree.orphans {
                    if !tree.inodes.contains_key(&ino) {
                        items.push(PlanItem::Entry(EntryLoc {
                            tree: ti,
                            ino,
                            stub: None,
                        }));
                    }
                }
                // Dangling dir children (dir item whose inode is gone) —
                // name-only deleted records; forensic name residue.
                let mut seen_stub: HashSet<u64> = HashSet::new();
                for children in tree.dir_children.values() {
                    for c in children {
                        if tree.inodes.contains_key(&c.ino) || !seen_stub.insert(c.ino) {
                            continue;
                        }
                        items.push(PlanItem::Entry(EntryLoc {
                            tree: ti,
                            ino: c.ino,
                            stub: Some((c.name.clone(), c.ty)),
                        }));
                    }
                }
                items
            };
            self.plan.extend(items);
            // Tree-walk errors become deferred error records in-stream.
            let errs = std::mem::take(&mut self.trees[ti].errors);
            for e in errs {
                self.plan.push(PlanItem::Error(e));
            }
        }
    }

    /// Locate the live counterpart record of `(subvol, ino)`.
    pub(crate) fn live_rec(&self, subvol: u64, ino: u64) -> Option<&InodeRec> {
        let li = *self.live_tree_of.get(&subvol)?;
        self.trees[li].inodes.get(&ino)
    }

    /// Physical offset + name for an entry's producing record.
    fn record_phys(&self, loc: &EntryLoc) -> u64 {
        self.trees[loc.tree]
            .inodes
            .get(&loc.ino)
            .map(|r| r.item_phys)
            .filter(|&p| p != 0)
            .unwrap_or_else(|| {
                self.trees[loc.tree]
                    .dir_children
                    .values()
                    .flat_map(|cs| cs.iter())
                    .find(|c| c.ino == loc.ino)
                    .map(|c| c.phys)
                    .unwrap_or(0)
            })
    }

    /// Build the [`FsEntry`] for one plan item.
    pub(crate) fn build_entry(&self, loc: &EntryLoc) -> FsEntry {
        let tree = &self.trees[loc.tree];
        let rec = tree.inodes.get(&loc.ino);
        let is_root = loc.ino == objid::FIRST_FREE && tree.is_live;

        // ---- path / name ------------------------------------------------
        let (path, name) = if is_root {
            let p = tree.mount_prefix();
            (
                if p.is_empty() { "/".into() } else { p },
                tree.display_root_name(),
            )
        } else if rec.filter(|r| r.item.is_some() || !r.names.is_empty()).is_some() {
            let (p, n) = tree.build_path(loc.ino);
            if tree.is_live {
                (p, n)
            } else {
                // Old-generation artefact: distinguish deleted-vs-prior.
                match self.live_rec(tree.objectid, loc.ino) {
                    Some(_) => (format!("{p}@v{}", tree.generation), format!("{n}@v{}", tree.generation)),
                    None => (p, n),
                }
            }
        } else if let Some((stub, _)) = &loc.stub {
            (
                util::join_path(&tree.mount_prefix(), &util::sanitize_name(stub)),
                util::sanitize_name(stub),
            )
        } else {
            let uniq = unique_inode(tree.objectid, loc.ino);
            (util::orphan_path(uniq), format!("ino_{:#x}", uniq))
        };

        // ---- status / recovery ------------------------------------------
        let (status, mut ranges, mut notes) = if self.is_live(loc.tree, loc.ino) {
            (
                FsEntryStatus::Live,
                rec.map(|r| {
                    r.extents
                        .iter()
                        .flat_map(|e| e.live_ranges())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
                Vec::new(),
            )
        } else {
            let rec_cl = rec.cloned();
            let rc = match self.recovery.get(&(loc.tree, loc.ino)) {
                Some(r) => r.clone(),
                None => self.assess_deleted(tree, loc.ino, rec_cl.as_ref()),
            };
            let mut rs = Vec::new();
            if let Some(r) = rec_cl.as_ref() {
                for i in 0..r.extents.len() {
                    rs.extend(rc.surviving.get(i).cloned().unwrap_or_default());
                }
            }
            (
                FsEntryStatus::Deleted {
                    recovery: rc.state,
                },
                rs,
                rc.notes.clone(),
            )
        };

        let item = rec.and_then(|r| r.item.clone());
        let kind = item
            .as_ref()
            .map(|i| i.kind())
            .or_else(|| {
                loc.stub
                    .as_ref()
                    .and_then(|(_, t)| ondisk::ft::entry_kind(*t))
                    .or(Some(EntryKind::File))
            })
            .unwrap_or(EntryKind::Other);
        let size = item.as_ref().map(|i| i.size).unwrap_or(0);

        // ---- meta --------------------------------------------------------
        let mut meta: HashMap<String, String> = HashMap::new();
        meta.insert("inode".into(), loc.ino.to_string());
        meta.insert("subvolume_id".into(), tree.objectid.to_string());
        meta.insert(
            "unique_inode".into(),
            format!("{:#x}", unique_inode(tree.objectid, loc.ino)),
        );
        meta.insert("tree_root".into(), format!("{:#x}", tree.root_logical));
        meta.insert("tree_generation".into(), tree.generation.to_string());
        if let Some(i) = &item {
            meta.insert("uid".into(), i.uid.to_string());
            meta.insert("gid".into(), i.gid.to_string());
            if let Some(n) = self.uid_names.get(&i.uid.into()) {
                meta.insert("user".into(), n.clone());
            }
            if let Some(n) = self.gid_names.get(&i.gid.into()) {
                meta.insert("group".into(), n.clone());
            }
            meta.insert("nlink".into(), i.nlink.to_string());
            meta.insert("mode".into(), format!("{:#o}", i.mode));
            meta.insert("generation".into(), i.generation.to_string());
            meta.insert("transid".into(), i.transid.to_string());
            let fl = ondisk::inode_flags::to_string(i.flags);
            if !fl.is_empty() {
                meta.insert("attributes".into(), fl);
            }
        }
        if let Some(r) = rec {
            if !r.xattrs.is_empty() {
                meta.insert("xattr_count".into(), r.xattrs.len().to_string());
                for (i, x) in r.xattrs.iter().take(16).enumerate() {
                    meta.insert(format!("xattr_{i}"), x.name.clone());
                }
            }
            meta.insert("extent_count".into(), r.extents.len().to_string());
            let comps: HashSet<u8> = r
                .extents
                .iter()
                .map(|e| e.compression)
                .filter(|&c| c != ondisk::compression::NONE)
                .collect();
            if !comps.is_empty() {
                let names: Vec<&str> = comps
                    .iter()
                    .map(|&c| ondisk::compression::name(c))
                    .collect();
                meta.insert("compressed".into(), names.join(","));
            }
            if r.extents.iter().any(|e| e.ty == ondisk::extent_ty::INLINE) {
                meta.insert("inline".into(), "true".into());
            }
            if r.extents.iter().any(|e| e.encryption != 0) {
                meta.insert("encrypted".into(), "true".into());
            }
            if r.extents
                .iter()
                .any(|e| e.compression != 0 && !crate::decompress::supported(e.compression))
            {
                meta.insert("compression_unsupported".into(), "true".into());
            }
            if r.csum_bad {
                meta.insert("note".into(), "produced by a block with a bad checksum".into());
            }
            if r.gen_mismatch {
                meta.insert(
                    "generation_mismatch".into(),
                    "true".into(),
                );
            }
            if r.item_phys != 0 {
                meta.insert("inode_item_physical".into(), format!("{:#x}", r.item_phys));
                meta.insert(
                    "inode_item_logical".into(),
                    format!("{:#x}", r.item_logical),
                );
            }
            // first extent provenance (logical + physical)
            if let Some(ex) = r.extents.iter().find(|e| e.logical != 0) {
                meta.insert("data_logical".into(), format!("{:#x}", ex.logical));
                if let Some((p, _)) = ex.phys_ranges.first() {
                    meta.insert("data_physical".into(), format!("{p:#x}"));
                }
            }
            if r.orphan {
                meta.insert("orphan".into(), "true".into());
                meta.insert(
                    "note".into(),
                    "ORPHAN_ITEM present: unlinked but not yet reaped".into(),
                );
            }
        }
        if !tree.is_live {
            meta.insert("cow_generation".into(), tree.generation.to_string());
            meta.insert(
                "cow_root".into(),
                format!("{:#x}", tree.root_logical),
            );
            if let Some(live) = self.live_rec(tree.objectid, loc.ino) {
                if let (Some(l), Some(o)) = (live.item.as_ref(), item.as_ref()) {
                    if l.transid != o.transid {
                        meta.insert("prior_version_of".into(), {
                            let lt = &self.trees[*self.live_tree_of.get(&tree.objectid).unwrap_or(&0)];
                            lt.build_path(loc.ino).0
                        });
                    }
                }
            }
        }
        if loc.stub.is_some() && rec.map(|r| r.item.is_none()).unwrap_or(true) {
            meta.insert(
                "note".into(),
                "dangling dir item: name survives, inode item gone".into(),
            );
        }
        if kind == EntryKind::Symlink {
            if let Some(t) = self.symlink_target(loc) {
                meta.insert("symlink_target".into(), t);
            }
        }
        for (i, n) in notes.drain(..).enumerate() {
            meta.insert(format!("recovery_note_{i}"), n);
        }
        if tree.readonly {
            meta.insert("readonly_subvolume".into(), "true".into());
        }
        if tree.is_snapshot {
            meta.insert("snapshot".into(), "true".into());
        }

        // dedupe allocated_ranges
        ranges.sort_unstable();
        ranges.dedup();

        let mut entry = FsEntry {
            path,
            name,
            entry_id: 0, // filled by Walk (plan index)
            kind,
            size,
            disk_offset: self.record_phys(loc),
            allocated_ranges: ranges,
            timestamps: inode_timestamps(item.as_ref()),
            status,
            meta,
            magic: None,
        };
        entry.magic = self.magic_for(&entry, loc);
        entry
    }

    /// Recovery assessment for a deleted/orphan/old-version inode.
    ///
    /// Per extent (in file order):
    /// * inline → always survives (its bytes live in metadata we just read);
    /// * hole → not data;
    /// * extent not in the current extent tree → freed but residual bytes
    ///   presumed on disk → surviving;
    /// * still allocated → survive iff a data backref still points at this
    ///   inode, a live inode shares the extent, or the extent record's
    ///   generation predates/at-equals the file extent's generation (same
    ///   allocation era — a reallocated slot carries a newer item).
    fn assess_deleted(&self, tree: &TreeIndex, ino: u64, rec: Option<&InodeRec>) -> Recovery {
        let mut notes = Vec::new();
        let Some(rec) = rec else {
            return Recovery {
                state: RecoveryState::Unrecoverable,
                surviving: Vec::new(),
                notes: vec!["no inode item survives".into()],
            };
        };
        let size = rec.item.as_ref().map(|i| i.size).unwrap_or(0);
        if size == 0 && rec.extents.is_empty() {
            return Recovery {
                state: RecoveryState::Intact,
                surviving: Vec::new(),
                notes,
            };
        }
        if rec.extents.is_empty() {
            notes.push("inode records size but no EXTENT_DATA survives".into());
            return Recovery {
                state: RecoveryState::Unrecoverable,
                surviving: Vec::new(),
                notes,
            };
        }
        if self.extent_index.recs.is_empty() && !self.extent_tree_ok {
            notes.push("extent tree unavailable; recoverability undetermined".into());
            return Recovery {
                state: RecoveryState::Unknown,
                surviving: Vec::new(),
                notes,
            };
        }

        let mut surviving: Vec<Vec<(u64, u64)>> = Vec::with_capacity(rec.extents.len());
        let mut recovered = 0u64;
        for ex in &rec.extents {
            let (phys, logical) = self.assess_extent(tree.objectid, ino, ex, &mut notes);
            // Recovered bytes are counted in *file* bytes: an inline or
            // fully-surviving compressed extent yields num_bytes; raw
            // extents yield their surviving subrange coverage.
            let got = if ex.is_hole() {
                ex.num_bytes
            } else if ex.ty == ondisk::extent_ty::INLINE
                || ex.compression != ondisk::compression::NONE
            {
                if phys.is_empty() { 0 } else { ex.num_bytes }
            } else {
                logical.iter().map(|(_, l)| *l).sum::<u64>().min(ex.num_bytes)
            };
            recovered += got;
            surviving.push(phys);
        }
        let state = if recovered >= size && size > 0 {
            RecoveryState::Intact
        } else if recovered > 0 {
            RecoveryState::PartiallyOverwritten {
                recovered_bytes: recovered,
                total_bytes: size,
            }
        } else {
            RecoveryState::Unrecoverable
        };
        Recovery {
            state,
            surviving,
            notes,
        }
    }

    /// Assess one extent → (surviving physical ranges, surviving logical
    /// subranges of the file-relevant disk span).
    fn assess_extent(
        &self,
        subvol: u64,
        ino: u64,
        ex: &index::Extent,
        notes: &mut Vec<String>,
    ) -> (Vec<(u64, u64)>, Vec<(u64, u64)>) {
        match ex.ty {
            ondisk::extent_ty::INLINE => {
                return (ex.phys_ranges.clone(), vec![(ex.logical, ex.num_bytes)]);
            }
            _ => {}
        }
        if ex.is_hole() {
            return (Vec::new(), vec![(0, ex.num_bytes)]); // zeros always "survive"
        }
        // The disk span the file actually reads: whole compressed blob, or
        // the uncompressed subrange.
        let (span_start, span_len) = if ex.compression != ondisk::compression::NONE {
            (ex.logical, ex.disk_len)
        } else {
            (
                ex.logical.saturating_add(ex.extent_offset),
                ex.num_bytes.min(ex.disk_len.max(ex.num_bytes)),
            )
        };
        let end = span_start.saturating_add(span_len);
        let mut surviving = Vec::new();
        let mut cursor = span_start;
        for rec in self.extent_index.overlapping(span_start, span_len) {
            if rec.logical > cursor {
                // gap = freed space → residual bytes survive
                surviving.push((cursor, rec.logical.min(end) - cursor));
            }
            let o_start = cursor.max(rec.logical);
            let o_end = end.min(rec.logical + rec.len);
            if o_end <= o_start {
                continue;
            }
            if self.extent_survives(subvol, ino, ex, rec, notes) {
                surviving.push((o_start, o_end - o_start));
            } else {
                notes.push(format!(
                    "extent {:#x}+{} reallocated (gen {} > {}) — bytes lost",
                    rec.logical,
                    rec.len,
                    rec.generation,
                    ex.generation
                ));
            }
            cursor = o_end.max(cursor);
        }
        if cursor < end {
            surviving.push((cursor, end - cursor));
        }
        // For compressed extents, partial survival is unusable — the whole
        // blob must be intact to decompress.
        let survives_wholly = surviving
            .iter()
            .map(|(_, l)| *l)
            .sum::<u64>()
            >= span_len;
        if ex.compression != ondisk::compression::NONE && !survives_wholly {
            notes.push(format!(
                "compressed extent {:#x} partially reallocated — blob unreadable",
                ex.logical
            ));
            return (Vec::new(), Vec::new());
        }
        // Translate each surviving logical subrange to physical.
        let mut phys = Vec::new();
        for (l, len) in &surviving {
            phys.extend(self.map.translate_range(*l, *len));
        }
        (phys, surviving)
    }

    /// Is the allocation record covering our deleted extent still "ours"?
    fn extent_survives(
        &self,
        subvol: u64,
        ino: u64,
        ex: &index::Extent,
        rec: &ExtentRec,
        notes: &mut Vec<String>,
    ) -> bool {
        // A direct backref to our inode → still referenced (orphan pending
        // delete, or shared snapshot extent).
        if index::rec_references(rec, subvol, ino) {
            return true;
        }
        // A live inode references the same logical extent → shared content
        // (BTRFS never writes shared extents in place).
        if self.live_refs.contains(&(subvol, ino, rec.logical)) {
            return true;
        }
        // Extent record predates or equals our extent's generation → it is
        // the same allocation (a reallocated slot carries a newer item).
        if rec.generation <= ex.generation {
            if index::rec_references_other(rec, subvol, ino) {
                notes.push(format!(
                    "extent {:#x} shared via backref — content presumed identical",
                    rec.logical
                ));
            }
            return true;
        }
        false
    }

    /// Extents (with surviving-filtering for deleted entries) backing an
    /// entry — used by `read_file` and the magic check.
    pub(crate) fn extents_for(&self, loc: &EntryLoc) -> Vec<(index::Extent, Vec<(u64, u64)>)> {
        let Some(rec) = self.trees[loc.tree].inodes.get(&loc.ino) else {
            return Vec::new();
        };
        if self.is_live(loc.tree, loc.ino) {
            return rec
                .extents
                .iter()
                .map(|e| (e.clone(), e.live_ranges()))
                .collect();
        }
        let rc = match self.recovery.get(&(loc.tree, loc.ino)) {
            Some(r) => r.clone(),
            None => self.assess_deleted(&self.trees[loc.tree], loc.ino, Some(rec)),
        };
        rec.extents
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                let phys = rc.surviving.get(i)?.clone();
                if phys.is_empty() && !e.is_hole() && e.ty != ondisk::extent_ty::INLINE {
                    return None;
                }
                Some((e.clone(), phys))
            })
            .collect()
    }

    /// Read a symlink's target (its extent data), ≤ 4 KiB.
    fn symlink_target(&self, loc: &EntryLoc) -> Option<String> {
        let rec = self.trees[loc.tree].inodes.get(&loc.ino)?;
        if !matches!(rec.item.as_ref().map(|i| i.kind()), Some(EntryKind::Symlink)) {
            return None;
        }
        let segs = self.extents_for(loc);
        let mut r = ExtentReader::new(self.src.clone(), &self.map, segs, 4096);
        let mut buf = vec![0u8; 4096];
        let n = r.read(&mut buf).ok()?;
        buf.truncate(n);
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Some(String::from_utf8_lossy(&buf[..end]).to_string())
    }

    /// Bounded header read → `MagicVerdict` (compressed extents are
    /// decompressed first; if decompression is impossible we still run
    /// magic on the raw bytes and flag it).
    pub(crate) fn magic_for(&self, e: &FsEntry, loc: &EntryLoc) -> Option<sutram_magic::MagicVerdict> {
        if !self.opts.check_magic || e.kind != EntryKind::File || e.size == 0 {
            return None;
        }
        let segs = self.extents_for(loc);
        if segs.is_empty() {
            return None;
        }
        let mut r = ExtentReader::new(self.src.clone(), &self.map, segs.clone(), 4096);
        let mut header = vec![0u8; 4096.min(e.size.max(4096) as usize)];
        let n = r.read(&mut header).unwrap_or(0);
        if n > 0 {
            header.truncate(n);
            return Some(sutram_magic::check_entry(&e.name, &header));
        }
        // Fallback: magic over the raw (compressed) extent bytes.
        if let Some((phys, len)) = segs
            .iter()
            .flat_map(|(_, r)| r.iter().copied())
            .next()
        {
            let raw = self
                .src
                .read_slice(phys, (len as usize).min(4096))
                .unwrap_or_default();
            if !raw.is_empty() {
                return Some(sutram_magic::check_entry(&e.name, &raw));
            }
        }
        None
    }

    /// Look up the plan location for an emitted entry.
    pub(crate) fn loc_of(&self, entry_id: u64) -> Option<&EntryLoc> {
        match self.plan.get(entry_id as usize) {
            Some(PlanItem::Entry(loc)) => Some(loc),
            _ => None,
        }
    }

    /// Sum of free logical bytes (extent-complement), for `info()`.
    fn free_bytes(&self) -> Option<u64> {
        let unalloc = self.unallocated_logical();
        Some(unalloc.iter().map(|(_, l)| *l).sum())
    }

    /// Unallocated *logical* ranges: chunk coverage minus extent-tree
    /// allocations.
    fn unallocated_logical(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for (cl, clen) in self.map.covered_ranges() {
            let cend = cl + clen;
            // An extent record may start before the chunk and overlap it.
            let mut cursor = cl;
            if let Some((_, r)) = self.extent_index.recs.range(..=cl).next_back() {
                if r.logical + r.len > cl {
                    cursor = cl.max(r.logical + r.len);
                }
            }
            for (_, r) in self.extent_index.recs.range(cl..cend) {
                if r.logical > cursor {
                    out.push((cursor, r.logical.min(cend) - cursor));
                }
                cursor = cursor.max(r.logical + r.len);
                if cursor >= cend {
                    break;
                }
            }
            if cursor < cend {
                out.push((cursor, cend - cursor));
            }
        }
        // Intersect with the free-space tree when present (cross-check —
        // union would over-report).
        if !self.free_tree_ranges.is_empty() {
            out = intersect_ranges(out, self.free_tree_ranges.clone());
        }
        out
    }
}

/// `subvol << 48 | ino` — the Python parser's unique-inode scheme.
pub fn unique_inode(subvol: u64, ino: u64) -> u64 {
    (subvol << 48) | (ino & 0xFFFF_FFFF_FFFF)
}

/// Did the inode change between generations? (`transid` or extent layout).
fn same_version(live: &InodeRec, old: Option<&InodeRec>) -> bool {
    let Some(old) = old else { return false };
    match (&live.item, &old.item) {
        (Some(l), Some(o)) => {
            if l.transid != o.transid || l.size != o.size {
                return false;
            }
        }
        (None, None) => {}
        _ => return false,
    }
    live.extents.len() == old.extents.len()
        && live
            .extents
            .iter()
            .zip(old.extents.iter())
            .all(|(a, b)| {
                a.file_offset == b.file_offset
                    && a.logical == b.logical
                    && a.disk_len == b.disk_len
                    && a.num_bytes == b.num_bytes
            })
}

fn inode_timestamps(item: Option<&crate::ondisk::InodeItem>) -> sutram_fs::Timestamps {
    let Some(i) = item else {
        return Default::default();
    };
    sutram_fs::Timestamps {
        modified: Some(i.mtime.to_fs()),
        accessed: Some(i.atime.to_fs()),
        created: Some(i.otime.to_fs()),
        changed: Some(i.ctime.to_fs()),
        deleted: None,
    }
}

/// Intersect two sorted range lists.
fn intersect_ranges(a: Vec<(u64, u64)>, b: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut sorted_a = a;
    let mut sorted_b = b;
    sorted_a.sort_unstable();
    sorted_b.sort_unstable();
    let (mut i, mut j) = (0, 0);
    while i < sorted_a.len() && j < sorted_b.len() {
        let (as_, ae) = (sorted_a[i].0, sorted_a[i].0 + sorted_a[i].1);
        let (bs, be) = (sorted_b[j].0, sorted_b[j].0 + sorted_b[j].1);
        let (s, e) = (as_.max(bs), ae.min(be));
        if e > s {
            out.push((s, e - s));
        }
        if ae < be {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

impl FileSystem for BtrfsFs {
    fn info(&self) -> FsInfo {
        let mut meta = HashMap::new();
        meta.insert("generation".into(), self.sb.generation.to_string());
        meta.insert("nodesize".into(), self.sb.nodesize.to_string());
        meta.insert("sectorsize".into(), self.sb.sectorsize.to_string());
        meta.insert("num_devices".into(), self.sb.num_devices.to_string());
        meta.insert("csum_type".into(), self.sb.csum_type.to_string());
        meta.insert("root_tree".into(), format!("{:#x}", self.sb.root));
        meta.insert("chunk_tree".into(), format!("{:#x}", self.sb.chunk_root));
        if self.sb.log_root != 0 {
            meta.insert("log_tree".into(), format!("{:#x}", self.sb.log_root));
        }
        meta.insert("chunks".into(), self.map.chunks.len().to_string());
        if self.dev_total_bytes > 0 {
            meta.insert("dev_total_bytes".into(), self.dev_total_bytes.to_string());
        }
        {
            use ondisk::block_group as bg;
            let (mut d, mut m, mut s_) = (0u32, 0u32, 0u32);
            for c in &self.map.chunks {
                if c.ty & bg::SYSTEM != 0 {
                    s_ += 1;
                } else if c.ty & bg::METADATA != 0 {
                    m += 1;
                } else {
                    d += 1;
                }
            }
            meta.insert("chunks_data".into(), d.to_string());
            meta.insert("chunks_metadata".into(), m.to_string());
            meta.insert("chunks_system".into(), s_.to_string());
        }
        meta.insert("bytes_used".into(), self.sb.bytes_used.to_string());
        meta.insert(
            "subvolumes".into(),
            self.trees.iter().filter(|t| t.is_live).count().to_string(),
        );
        meta.insert(
            "cow_history_trees".into(),
            self.trees.iter().filter(|t| !t.is_live).count().to_string(),
        );
        meta.insert(
            "backup_roots".into(),
            self.sb.backup_roots.len().to_string(),
        );
        meta.insert(
            "incompat_flags".into(),
            format!("{:#x}", self.sb.incompat_flags),
        );
        if self.used_mirror {
            meta.insert(
                "note".into(),
                format!(
                    "mounted from superblock mirror at {:#x}",
                    self.sb.source_offset
                ),
            );
        }
        if let Some(ok) = self.sb.csum_ok {
            meta.insert("superblock_csum_ok".into(), ok.to_string());
        }
        FsInfo {
            fs_type: "BTRFS".into(),
            label: if self.sb.label.is_empty() {
                None
            } else {
                Some(self.sb.label.clone())
            },
            uuid: Some(format_uuid(&self.sb.fsid)),
            block_size: self.sb.sectorsize as u64,
            total_blocks: self.sb.total_bytes / self.sb.sectorsize as u64,
            free_blocks: self
                .free_bytes()
                .map(|b| b / self.sb.sectorsize as u64),
            total_nodes: Some(
                self.trees
                    .iter()
                    .filter(|t| t.is_live)
                    .map(|t| t.inodes.len() as u64)
                    .sum(),
            ),
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
            EntryKind::File | EntryKind::Other | EntryKind::Symlink => {}
            _ => {
                return Err(FsError::InvalidInput {
                    msg: format!("cannot read {}: not a file", entry.path),
                })
            }
        }
        let loc = self.loc_of(entry.entry_id).ok_or_else(|| FsError::InvalidInput {
            msg: format!("entry id {} not produced by this filesystem", entry.entry_id),
        })?;
        let segs = self.extents_for(loc);
        let cap = if entry.is_deleted() { u64::MAX } else { entry.size };
        Ok(Box::new(ExtentReader::new(
            self.src.clone(),
            &self.map,
            segs,
            cap,
        )))
    }

    /// Free space: chunk coverage minus allocated extents (translated to
    /// physical), minus the reserved superblock zones. When a free-space
    /// tree exists it is intersected as a cross-check.
    fn unallocated_ranges(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for (l, len) in self.unallocated_logical() {
            out.extend(self.map.translate_range(l, len));
        }
        // Reserved zones: bootstrap region + the three superblock copies.
        let reserved = [
            (0u64, SUPERBLOCK_RSVD),
            (ondisk::SUPERBLOCK_MIRRORS[1], 4096),
            (ondisk::SUPERBLOCK_MIRRORS[2], 4096),
        ];
        let mut free = Vec::new();
        'outer: for (off, len) in out {
            let mut segs = vec![(off, len)];
            for &(roff, rlen) in &reserved {
                let rend = roff + rlen;
                let mut next = Vec::new();
                for (s, l) in segs {
                    let e = s + l;
                    if roff >= e || rend <= s {
                        next.push((s, l));
                        continue;
                    }
                    if s < roff {
                        next.push((s, roff - s));
                    }
                    if e > rend {
                        next.push((rend, e - rend));
                    }
                }
                segs = next;
            }
            free.extend(segs);
            if free.len() > 1_000_000 {
                break 'outer;
            }
        }
        free
    }
}

/// Bytes reserved at device start (bootstrap area + primary superblock).
const SUPERBLOCK_RSVD: u64 = 0x11000;

fn format_uuid(b: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    )
}


/// Parse `/etc/passwd` or `/etc/group` content → `id → name`.
/// Format: `name:passwd:id:…` (fields 0 and 2).
fn parse_id_file(data: &[u8]) -> Vec<(u64, String)> {
    let text = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split(':');
        let name = parts.next().unwrap_or("");
        let _pw = parts.next();
        if let Some(Ok(id)) = parts.next().map(|s| s.parse::<u64>()) {
            if !name.is_empty() {
                out.push((id, name.to_string()));
            }
        }
    }
    out
}
