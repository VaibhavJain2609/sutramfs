//! Per-tree indexes: interpret the raw item stream of one BTRFS tree into
//! inodes, names, dir entries, extents, orphans — plus the extent tree's
//! allocation/backref index used for recovery assessment and free space.
//!
//! This is the `filesystem.py` port (`parse_filesystem`, `find_all_subvolumes`)
//! extended with item-level provenance and the extent/free-space trees the
//! Python version never read.

use std::collections::{BTreeMap, HashSet};

use sutram_fs::FsError;
use sutram_io::{le, ByteSource};

use crate::btree::TreeWalk;
use crate::chunk::ChunkMap;
use crate::ondisk::{self, objid, ty, DirItem, ExtentDataRef, ExtentItem, FileExtentItem,
                    InodeItem, RootItem, RootRef};

/// A resolved data extent of a file (logical→physical already applied).
#[derive(Debug, Clone)]
pub struct Extent {
    /// File offset this item covers (`key.offset`).
    pub file_offset: u64,
    /// File bytes covered by this item.
    pub num_bytes: u64,
    /// Extent type: inline/regular/prealloc.
    pub ty: u8,
    /// Compression algorithm (`compression::*`).
    pub compression: u8,
    pub encryption: u8,
    /// Transaction that wrote the extent.
    pub generation: u64,
    /// Logical disk address (`disk_bytenr`; 0 = hole/inline).
    pub logical: u64,
    /// On-disk bytes (`disk_num_bytes`; compressed size).
    pub disk_len: u64,
    /// Offset into the (uncompressed) extent the file starts at.
    pub extent_offset: u64,
    /// Uncompressed extent size (`ram_bytes`); kept for citation.
    #[allow(dead_code)]
    pub ram_bytes: u64,
    /// Inline-extent payload (as stored — may itself be compressed).
    pub inline_data: Option<Vec<u8>>,
    /// Physical `(offset,len)` ranges backing this extent (provenance).
    pub phys_ranges: Vec<(u64, u64)>,
    /// Physical offset of the EXTENT_DATA item body.
    pub item_phys: u64,
}

impl Extent {
    pub fn is_hole(&self) -> bool {
        self.ty != ondisk::extent_ty::INLINE && self.logical == 0
    }

    /// Physical ranges a *live* reader needs. For deleted entries the
    /// caller substitutes the surviving-ranges view.
    pub fn live_ranges(&self) -> Vec<(u64, u64)> {
        self.phys_ranges.clone()
    }
}

/// One `(parent_dir, name)` link for an inode (INODE_REF/EXTREF or a
/// surviving DIR_ITEM fallback).
#[derive(Debug, Clone)]
pub struct NameRef {
    pub parent: u64,
    pub name: String,
    /// Physical offset of the ref record (kept for citation).
    #[allow(dead_code)]
    pub phys: u64,
}

/// A directory entry as recorded by a parent's DIR_ITEM/DIR_INDEX.
#[derive(Debug, Clone)]
pub struct DirChild {
    /// Target inode (`location.objectid`).
    pub ino: u64,
    pub name: String,
    /// `BTRFS_FT_*`.
    pub ty: u8,
    pub phys: u64,
}

/// Extended attribute record. `value_len`/`phys` kept for citation.
#[derive(Debug, Clone)]
pub struct XattrRec {
    pub name: String,
    #[allow(dead_code)]
    pub value_len: u64,
    #[allow(dead_code)]
    pub phys: u64,
}

/// Everything we know about one inode number inside one tree.
#[derive(Debug, Default, Clone)]
pub struct InodeRec {
    /// The INODE_ITEM (`None` when only refs/extents survive).
    pub item: Option<InodeItem>,
    /// Physical offset of the inode item body (provenance).
    pub item_phys: u64,
    /// Logical address of the inode item body.
    pub item_logical: u64,
    pub names: Vec<NameRef>,
    pub extents: Vec<Extent>,
    pub xattrs: Vec<XattrRec>,
    /// ORPHAN_ITEM referenced this inode (delete pending — forensically
    /// "deleted but not yet reaped").
    pub orphan: bool,
    /// The leaf that produced this inode had a bad checksum / generation
    /// mismatch somewhere in its items.
    pub csum_bad: bool,
    pub gen_mismatch: bool,
}

/// Interpreted contents of one tree (FS/subvolume tree or a historic one).
#[derive(Debug)]
pub struct TreeIndex {
    /// Tree objectid (5 = FS_TREE, ≥256 = subvolume/snapshot).
    pub objectid: u64,
    /// Logical address of the root block we walked.
    pub root_logical: u64,
    /// Tree generation (from ROOT_ITEM / backup root).
    pub generation: u64,
    /// Mount name: `""` for FS_TREE (its path is `/`), else the subvol name.
    pub mount_name: String,
    /// Part of the current generation (`true`) or a COW remnant.
    pub is_live: bool,
    /// ROOT_ITEM said `BTRFS_SUBVOL_RDONLY` (snapshot flag).
    pub readonly: bool,
    /// `parent_uuid` non-zero → this is a snapshot.
    pub is_snapshot: bool,
    pub inodes: BTreeMap<u64, InodeRec>,
    /// parent dir ino → children from DIR_ITEM/DIR_INDEX.
    pub dir_children: BTreeMap<u64, Vec<DirChild>>,
    /// Inode numbers named by ORPHAN_ITEMs.
    pub orphans: HashSet<u64>,
    /// Lenient errors collected while walking this tree.
    pub errors: Vec<FsError>,
}

impl TreeIndex {
    /// Path prefix for entries of this tree (`"/"` for FS_TREE).
    pub fn mount_prefix(&self) -> String {
        if self.mount_name.is_empty() {
            String::new()
        } else {
            format!("/{}", self.mount_name)
        }
    }

    /// Reconstruct the path of `ino` inside this tree by walking
    /// INODE_REF parents (the Python `build_path` loop, hardened with a
    /// visited set). Falls back to DIR_ITEM names when no INODE_REF
    /// survives.
    pub fn build_path(&self, ino: u64) -> (String, String) {
        let mut parts: Vec<String> = Vec::new();
        let mut cur = ino;
        let mut seen = HashSet::new();
        for _ in 0..128 {
            if !seen.insert(cur) {
                break;
            }
            if cur == objid::FIRST_FREE {
                break; // reached the tree root dir
            }
            let name = self
                .inodes
                .get(&cur)
                .and_then(|r| r.names.first())
                .map(|n| n.name.clone())
                .or_else(|| self.dir_name_of(cur));
            let parent = self
                .inodes
                .get(&cur)
                .and_then(|r| r.names.first())
                .map(|n| n.parent)
                .or_else(|| self.dir_parent_of(cur));
            match name {
                Some(n) => parts.push(sutram_fs::util::sanitize_name(&n)),
                None => parts.push(format!("ino_{cur:#x}")),
            }
            match parent {
                Some(p) if p != cur => cur = p,
                _ => break,
            }
        }
        parts.reverse();
        let name = if ino == objid::FIRST_FREE {
            self.display_root_name()
        } else {
            parts.last().cloned().unwrap_or_else(|| format!("ino_{ino:#x}"))
        };
        let prefix = self.mount_prefix();
        let path = if ino == objid::FIRST_FREE {
            if prefix.is_empty() {
                "/".to_string()
            } else {
                prefix
            }
        } else if parts.is_empty() {
            format!("{prefix}/ino_{ino:#x}")
        } else {
            format!("{prefix}/{}", parts.join("/"))
        };
        (path, name)
    }

    /// Display name of this tree's root (`/` or the subvolume name).
    pub fn display_root_name(&self) -> String {
        if self.mount_name.is_empty() {
            "/".to_string()
        } else {
            self.mount_name.clone()
        }
    }

    /// Find a name for `ino` from any parent's DIR_ITEM (fallback for
    /// deleted entries whose INODE_REF is gone).
    fn dir_name_of(&self, ino: u64) -> Option<String> {
        for children in self.dir_children.values() {
            for c in children {
                if c.ino == ino {
                    return Some(c.name.clone());
                }
            }
        }
        None
    }

    fn dir_parent_of(&self, ino: u64) -> Option<u64> {
        for (parent, children) in &self.dir_children {
            for c in children {
                if c.ino == ino {
                    return Some(*parent);
                }
            }
        }
        None
    }
}

/// Lossy UTF-8 decode of an on-disk name.
pub fn name_str(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).to_string()
}

/// Interpret one FS/subvolume tree's item stream into a [`TreeIndex`].
#[allow(clippy::too_many_arguments)]
pub fn index_fs_tree(
    src: &dyn ByteSource,
    map: &ChunkMap,
    nodesize: u32,
    csum_type: u16,
    objectid: u64,
    mount_name: String,
    root_logical: u64,
    generation: u64,
    is_live: bool,
    readonly: bool,
    is_snapshot: bool,
) -> TreeIndex {
    let mut tree = TreeIndex {
        objectid,
        root_logical,
        generation,
        mount_name,
        is_live,
        readonly,
        is_snapshot,
        inodes: BTreeMap::new(),
        dir_children: BTreeMap::new(),
        orphans: HashSet::new(),
        errors: Vec::new(),
    };

    let mut walk = TreeWalk::new(src, map, nodesize, csum_type);
    walk.for_each_item(root_logical, &mut |it| {
        let ino = it.key.objectid;
        match it.key.ty {
            ty::INODE_ITEM => {
                if let Some(item) = InodeItem::parse(it.data, 0) {
                    let rec = tree.inodes.entry(ino).or_default();
                    rec.item = Some(item);
                    rec.item_phys = it.item_phys;
                    rec.item_logical = it.leaf_logical + it.body_off_in_block as u64;
                    rec.csum_bad |= it.csum_ok == Some(false);
                    rec.gen_mismatch |= it.gen_mismatch;
                }
            }
            ty::INODE_REF => {
                // body: repeated (index u64, name_len u16, name)
                let mut pos = 0usize;
                while pos + 10 <= it.data.len() {
                    let name_len = match le::u16(it.data, pos + 8) {
                        Some(n) => n as usize,
                        None => break,
                    };
                    let name = match le::get(it.data, pos + 10, name_len) {
                        Some(n) => n,
                        None => break,
                    };
                    tree.inodes.entry(ino).or_default().names.push(NameRef {
                        parent: it.key.offset,
                        name: name_str(name),
                        phys: it.item_phys + pos as u64,
                    });
                    pos += 10 + name_len;
                }
            }
            ty::INODE_EXTREF => {
                // body: repeated btrfs_inode_extref records —
                // parent_objectid u64 @0, index u64 @8, name_len u16 @16,
                // name @18 (18-byte header).
                let mut pos = 0usize;
                while pos + 18 <= it.data.len() {
                    let (parent, name_len) = match (
                        le::u64(it.data, pos),
                        le::u16(it.data, pos + 16),
                    ) {
                        (Some(p), Some(n)) => (p, n as usize),
                        _ => break,
                    };
                    let name = match le::get(it.data, pos + 18, name_len) {
                        Some(n) => n,
                        None => break,
                    };
                    tree.inodes.entry(ino).or_default().names.push(NameRef {
                        parent,
                        name: name_str(name),
                        phys: it.item_phys + pos as u64,
                    });
                    pos += 18 + name_len;
                }
            }
            ty::DIR_ITEM | ty::DIR_INDEX | ty::XATTR_ITEM => {
                // body: one or more btrfs_dir_item records
                let mut pos = 0usize;
                while pos + DIR_ITEM_HDR <= it.data.len() {
                    let d = match DirItem::parse(it.data, pos) {
                        Some(d) => d,
                        None => break,
                    };
                    let name = d.name(it.data).map(name_str).unwrap_or_default();
                    if it.key.ty == ty::XATTR_ITEM {
                        let vlen = d.value(it.data).map(|v| v.len() as u64).unwrap_or(0);
                        tree.inodes.entry(ino).or_default().xattrs.push(XattrRec {
                            name,
                            value_len: vlen,
                            phys: it.item_phys + pos as u64,
                        });
                    } else {
                        tree.dir_children.entry(ino).or_default().push(DirChild {
                            ino: d.location.objectid,
                            name,
                            ty: d.ty,
                            phys: it.item_phys + pos as u64,
                        });
                    }
                    pos += d.total;
                }
            }
            ty::EXTENT_DATA => {
                if let Some(fe) = FileExtentItem::parse(it.data) {
                    let mut ex =
                        resolve_extent(&fe, it.key.offset, it.item_phys, it.data.len(), map);
                    fix_inline(&mut ex, it.data);
                    tree.inodes.entry(ino).or_default().extents.push(ex);
                }
            }
            // Orphan items live under objectid BTRFS_ORPHAN_OBJECTID;
            // key.offset = the orphaned inode.
            ty::ORPHAN_ITEM if it.key.objectid == objid::ORPHAN => {
                tree.orphans.insert(it.key.offset);
                tree.inodes.entry(it.key.offset).or_default().orphan = true;
            }
            _ => {}
        }
    });
    tree.errors = std::mem::take(&mut walk.errors);

    // Sort extents per inode by file offset (tree order guarantees it, but
    // don't rely on corrupt input being sorted).
    for rec in tree.inodes.values_mut() {
        rec.extents.sort_by_key(|e| e.file_offset);
    }
    tree
}

const DIR_ITEM_HDR: usize = ondisk::DIR_ITEM_FIXED_SIZE;

/// Turn a parsed `FileExtentItem` into a resolved [`Extent`] with physical
/// provenance ranges.
fn resolve_extent(
    fe: &FileExtentItem,
    file_offset: u64,
    item_phys: u64,
    body_len: usize,
    map: &ChunkMap,
) -> Extent {
    let inline_data = if fe.ty == ondisk::extent_ty::INLINE && body_len > 21 {
        // inline payload follows the 21-byte fixed header; filled by
        // `fix_inline` (which owns the body slice).
        Some(Vec::new())
    } else {
        None
    };
    let mut ex = Extent {
        file_offset,
        num_bytes: if fe.ty == ondisk::extent_ty::INLINE {
            fe.ram_bytes
        } else {
            fe.num_bytes
        },
        ty: fe.ty,
        compression: fe.compression,
        encryption: fe.encryption,
        generation: fe.generation,
        logical: fe.disk_bytenr,
        disk_len: fe.disk_num_bytes,
        extent_offset: fe.offset,
        ram_bytes: fe.ram_bytes,
        inline_data,
        phys_ranges: Vec::new(),
        item_phys,
    };
    if ex.ty == ondisk::extent_ty::INLINE {
        ex.phys_ranges = vec![(item_phys + 21, (body_len - 21) as u64)];
    } else if !ex.is_hole() {
        if ex.compression == ondisk::compression::NONE {
            // Uncompressed: file data sits at disk_bytenr+extent_offset and
            // runs to the end of the on-disk extent — cite the whole
            // remaining allocation (tail slack included); readers cap at
            // num_bytes.
            let span = fe.disk_num_bytes.saturating_sub(fe.offset);
            ex.phys_ranges =
                map.translate_range(fe.disk_bytenr.saturating_add(fe.offset), span);
        } else {
            // Compressed: the whole blob must be read.
            ex.phys_ranges = map.translate_range(fe.disk_bytenr, fe.disk_num_bytes);
        }
    }
    ex
}

/// Set the inline payload bytes — done by the caller which owns the item
/// body slice (avoids a second copy path in `resolve_extent`).
pub fn fix_inline(ex: &mut Extent, body: &[u8]) {
    if ex.ty == ondisk::extent_ty::INLINE && body.len() > 21 {
        ex.inline_data = Some(body[21..].to_vec());
        ex.phys_ranges = vec![(ex.item_phys + 21, (body.len() - 21) as u64)];
        // For compressed inline extents num_bytes = uncompressed size.
        if ex.compression == ondisk::compression::NONE {
            ex.num_bytes = (body.len() - 21) as u64;
        }
    }
}

// ---------------------------------------------------------------------------
// Extent tree — allocation + backref index
// ---------------------------------------------------------------------------

/// A resolved backref (who references this extent). Payloads are kept for
/// provenance reporting even where the recovery heuristic only needs the
/// variant shape.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ExtentRef {
    /// EXTENT_DATA_REF: `(tree objectid, inode, file offset)`.
    Data { root: u64, inode: u64, offset: u64 },
    /// SHARED_DATA_REF: parent tree-block logical address.
    SharedData { parent: u64 },
    /// TREE_BLOCK_REF: referencing tree objectid.
    TreeBlock { root: u64 },
    /// SHARED_BLOCK_REF: parent tree-block logical address.
    SharedBlock { parent: u64 },
    /// EXTENT_OWNER_REF (newer kernels): owning root.
    Owner { root: u64 },
}

/// One allocated extent as recorded by the extent tree.
#[derive(Debug, Clone)]
pub struct ExtentRec {
    /// Logical start (`key.objectid`).
    pub logical: u64,
    /// Length (EXTENT_ITEM `key.offset`; nodesize for METADATA_ITEM).
    pub len: u64,
    /// Allocation transaction.
    pub generation: u64,
    /// `BTRFS_EXTENT_FLAG_*`.
    pub flags: u64,
    /// This is a tree block (METADATA_ITEM or TREE_BLOCK flag).
    pub is_metadata: bool,
    pub refs: Vec<ExtentRef>,
    /// Physical offset of the extent item (provenance — kept for citation).
    #[allow(dead_code)]
    pub item_phys: u64,
}

/// The extent-tree interpretation.
#[derive(Debug, Default)]
pub struct ExtentIndex {
    /// `logical start → record` — the authoritative allocation map.
    pub recs: BTreeMap<u64, ExtentRec>,
    /// Block-group items `(start, len, used, flags)` for `info()`.
    pub block_groups: Vec<(u64, u64, u64, u64)>,
    pub errors: Vec<FsError>,
}

impl ExtentIndex {
    /// All records overlapping logical `[start, start+len)`.
    pub fn overlapping(&self, start: u64, len: u64) -> Vec<&ExtentRec> {
        let end = start.saturating_add(len);
        let mut out = Vec::new();
        // The record containing/starting before `start`:
        if let Some((_, r)) = self.recs.range(..=start).next_back() {
            if r.logical.saturating_add(r.len) > start {
                out.push(r);
            }
        }
        for (_, r) in self.recs.range(start..end) {
            if r.logical >= end {
                break;
            }
            if out.last().map(|l| l.logical) != Some(r.logical) {
                out.push(r);
            }
        }
        out
    }
}

/// Walk the extent tree (objectid 2) and build the allocation index.
pub fn index_extent_tree(
    src: &dyn ByteSource,
    map: &ChunkMap,
    nodesize: u32,
    csum_type: u16,
    root_logical: u64,
) -> ExtentIndex {
    let mut idx = ExtentIndex::default();
    if root_logical == 0 {
        return idx;
    }
    let mut walk = TreeWalk::new(src, map, nodesize, csum_type);
    walk.for_each_item(root_logical, &mut |it| {
        let key = it.key;
        match key.ty {
            ty::EXTENT_ITEM | ty::METADATA_ITEM => {
                let len = if key.ty == ty::EXTENT_ITEM {
                    key.offset
                } else {
                    nodesize as u64
                };
                let mut rec = ExtentRec {
                    logical: key.objectid,
                    len,
                    generation: 0,
                    flags: if key.ty == ty::METADATA_ITEM {
                        ondisk::extent_flags::TREE_BLOCK
                    } else {
                        0
                    },
                    is_metadata: key.ty == ty::METADATA_ITEM,
                    refs: Vec::new(),
                    item_phys: it.item_phys,
                };
                if let Some(ei) = ExtentItem::parse(it.data) {
                    rec.generation = ei.generation;
                    rec.flags = ei.flags;
                    if ei.flags & ondisk::extent_flags::TREE_BLOCK != 0 {
                        rec.is_metadata = true;
                    }
                    // Inline backrefs follow the 24-byte fixed part: each is
                    // a u8 type tag + fixed-size payload.
                    let mut pos = 24usize;
                    while pos < it.data.len() {
                        let rt = it.data[pos];
                        pos += 1;
                        match rt {
                            ty::TREE_BLOCK_REF => {
                                // Inline payload = u64 referencing root
                                // (btrfs_extent_inline_ref_size: full
                                // extent_inline_ref = type(1)+offset(8)).
                                if let Some(r) = le::u64(it.data, pos) {
                                    rec.refs.push(ExtentRef::TreeBlock { root: r });
                                }
                                pos += 8;
                            }
                            ty::SHARED_BLOCK_REF => {
                                if let Some(p) = le::u64(it.data, pos) {
                                    rec.refs.push(ExtentRef::SharedBlock { parent: p });
                                }
                                pos += 8;
                            }
                            ty::EXTENT_DATA_REF => {
                                if let Some(r) = ExtentDataRef::parse(it.data, pos) {
                                    rec.refs.push(ExtentRef::Data {
                                        root: r.root,
                                        inode: r.objectid,
                                        offset: r.offset,
                                    });
                                }
                                pos += 28;
                            }
                            ty::SHARED_DATA_REF => {
                                // Payload = parent bytenr(8) + count(4).
                                if let Some(p) = le::u64(it.data, pos) {
                                    rec.refs.push(ExtentRef::SharedData { parent: p });
                                }
                                pos += 12;
                            }
                            ty::EXTENT_OWNER_REF => {
                                if let Some(r) = le::u64(it.data, pos) {
                                    rec.refs.push(ExtentRef::Owner { root: r });
                                }
                                pos += 8;
                            }
                            _ => break,
                        }
                    }
                }
                // Merge backrefs if a separate-ref item created the record
                // first (key order puts EXTENT_ITEM before refs, but be
                // safe on corrupt input).
                idx.recs
                    .entry(key.objectid)
                    .and_modify(|e| {
                        e.len = rec.len;
                        e.generation = rec.generation;
                        e.flags = rec.flags;
                        e.is_metadata = rec.is_metadata;
                        e.item_phys = rec.item_phys;
                    })
                    .or_insert(rec);
            }
            ty::EXTENT_DATA_REF => {
                if let Some(r) = ExtentDataRef::parse(it.data, 0) {
                    idx.recs
                        .entry(key.objectid)
                        .or_insert_with(|| ExtentRec {
                            logical: key.objectid,
                            len: 0,
                            generation: 0,
                            flags: 0,
                            is_metadata: false,
                            refs: Vec::new(),
                            item_phys: it.item_phys,
                        })
                        .refs
                        .push(ExtentRef::Data {
                            root: r.root,
                            inode: r.objectid,
                            offset: r.offset,
                        });
                }
            }
            ty::SHARED_DATA_REF => {
                if let Some(p) = le::u64(it.data, 0) {
                    idx.recs
                        .entry(key.objectid)
                        .or_insert_with(|| ExtentRec {
                            logical: key.objectid,
                            len: 0,
                            generation: 0,
                            flags: 0,
                            is_metadata: false,
                            refs: Vec::new(),
                            item_phys: it.item_phys,
                        })
                        .refs
                        .push(ExtentRef::SharedData { parent: p });
                }
            }
            ty::TREE_BLOCK_REF => {
                idx.recs
                    .entry(key.objectid)
                    .or_insert_with(|| ExtentRec {
                        logical: key.objectid,
                        len: 0,
                        generation: 0,
                        flags: 0,
                        is_metadata: true,
                        refs: Vec::new(),
                        item_phys: it.item_phys,
                    })
                    .refs
                    .push(ExtentRef::TreeBlock { root: key.offset });
            }
            ty::SHARED_BLOCK_REF => {
                idx.recs
                    .entry(key.objectid)
                    .or_insert_with(|| ExtentRec {
                        logical: key.objectid,
                        len: 0,
                        generation: 0,
                        flags: 0,
                        is_metadata: true,
                        refs: Vec::new(),
                        item_phys: it.item_phys,
                    })
                    .refs
                    .push(ExtentRef::SharedBlock { parent: key.offset });
            }
            ty::BLOCK_GROUP_ITEM => {
                let used = le::u64(it.data, 0).unwrap_or(0);
                let flags = le::u64(it.data, 16).unwrap_or(0);
                idx.block_groups.push((key.objectid, key.offset, used, flags));
            }
            _ => {}
        }
    });
    idx.errors = std::mem::take(&mut walk.errors);
    idx
}

// ---------------------------------------------------------------------------
// Root tree — subvolumes and system trees
// ---------------------------------------------------------------------------

/// A tree discovered through the root tree.
#[derive(Debug, Clone)]
pub struct RootEntry {
    pub objectid: u64,
    pub bytenr: u64,
    pub generation: u64,
    /// ROOT_ITEM flags (`BTRFS_SUBVOL_*`).
    pub flags: u64,
    /// Snapshot indicator (`parent_uuid` non-zero).
    pub is_snapshot: bool,
    /// Name from ROOT_REF/ROOT_BACKREF (subvolumes only).
    pub name: Option<String>,
    /// Parent tree id via ROOT_REF.
    pub parent: Option<u64>,
    /// Physical offset of the ROOT_ITEM body (provenance — citation).
    #[allow(dead_code)]
    pub item_phys: u64,
}

/// Interpreted root tree.
#[derive(Debug, Default)]
pub struct RootTreeIndex {
    /// objectid → root entry.
    pub roots: BTreeMap<u64, RootEntry>,
    /// child objectid → (parent objectid, name) from ROOT_REFs.
    pub ref_names: BTreeMap<u64, (u64, String)>,
    pub errors: Vec<FsError>,
}

/// Walk the root tree (any generation — used for both the live root tree
/// and backup-root root trees).
pub fn index_root_tree(
    src: &dyn ByteSource,
    map: &ChunkMap,
    nodesize: u32,
    csum_type: u16,
    root_logical: u64,
) -> RootTreeIndex {
    let mut idx = RootTreeIndex::default();
    if root_logical == 0 {
        return idx;
    }
    let mut walk = TreeWalk::new(src, map, nodesize, csum_type);
    walk.for_each_item(root_logical, &mut |it| {
        match it.key.ty {
            ty::ROOT_ITEM => {
                if let Some(ri) = RootItem::parse(it.data) {
                    idx.roots.insert(
                        it.key.objectid,
                        RootEntry {
                            objectid: it.key.objectid,
                            bytenr: ri.bytenr,
                            generation: ri.tree_gen(),
                            flags: ri.flags,
                            is_snapshot: ri.parent_uuid.iter().any(|&b| b != 0),
                            name: None,
                            parent: None,
                            item_phys: it.item_phys,
                        },
                    );
                }
            }
            ty::ROOT_REF => {
                // key.objectid = parent tree, key.offset = child tree
                if let Some(r) = RootRef::parse(it.data, 0) {
                    let name = r.name(it.data).map(name_str).unwrap_or_default();
                    idx.ref_names
                        .insert(it.key.offset, (it.key.objectid, name.clone()));
                    if let Some(e) = idx.roots.get_mut(&it.key.offset) {
                        e.name = Some(name);
                        e.parent = Some(it.key.objectid);
                    }
                }
            }
            ty::ROOT_BACKREF => {
                // key.objectid = child tree, key.offset = parent tree
                if let Some(r) = RootRef::parse(it.data, 0) {
                    let name = r.name(it.data).map(name_str).unwrap_or_default();
                    idx.ref_names
                        .entry(it.key.objectid)
                        .or_insert((it.key.offset, name.clone()));
                    if let Some(e) = idx.roots.get_mut(&it.key.objectid) {
                        if e.name.is_none() {
                            e.name = Some(name);
                        }
                        e.parent = Some(it.key.offset);
                    }
                }
            }
            _ => {}
        }
    });
    // A ROOT_REF may sort before the child's ROOT_ITEM (items are keyed by
    // objectid) — fill in names that arrived too early in a second pass.
    for (&child, &(parent, ref name)) in &idx.ref_names {
        if let Some(e) = idx.roots.get_mut(&child) {
            if e.name.is_none() {
                e.name = Some(name.clone());
            }
            e.parent.get_or_insert(parent);
        }
    }
    idx.errors = std::mem::take(&mut walk.errors);
    idx
}

// ---------------------------------------------------------------------------
// Free-space tree (v2) — optional cross-check source
// ---------------------------------------------------------------------------

/// Parse the free-space tree (objectid 10) → free *logical* ranges.
/// `sectorsize` is the bitmap bit granularity.
pub fn index_free_space_tree(
    src: &dyn ByteSource,
    map: &ChunkMap,
    nodesize: u32,
    csum_type: u16,
    root_logical: u64,
    sectorsize: u64,
) -> (Vec<(u64, u64)>, Vec<FsError>) {
    let mut free = Vec::new();
    if root_logical == 0 {
        return (free, Vec::new());
    }
    let mut walk = TreeWalk::new(src, map, nodesize, csum_type);
    walk.for_each_item(root_logical, &mut |it| {
        match it.key.ty {
            ty::FREE_SPACE_EXTENT => {
                // body = btrfs_free_space_entry { offset, length }
                if let Some(e) = ondisk::FreeSpaceEntry::parse(it.data) {
                    if e.length > 0 {
                        free.push((e.offset, e.length));
                    }
                } else if it.key.offset != 0 {
                    // Some layouts put the length in the item body start
                    // only; key.offset is the start.
                }
            }
            ty::FREE_SPACE_BITMAP => {
                // body = entry {offset, length} + bitmap; bit i covers
                // [offset + i*sectorsize, +sectorsize).
                if let Some(e) = ondisk::FreeSpaceEntry::parse(it.data) {
                    let bitmap = &it.data[16.min(it.data.len())..];
                    for (i, byte) in bitmap.iter().enumerate() {
                        for b in 0..8 {
                            if byte & (1 << b) != 0 {
                                let bit = i * 8 + b;
                                let off = e.offset.saturating_add(bit as u64 * sectorsize);
                                if off < e.offset.saturating_add(e.length) {
                                    free.push((off, sectorsize));
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    });
    (free, std::mem::take(&mut walk.errors))
}

/// Short-hand used by fs.rs: does the extent record carry a data backref
/// to `(subvol, ino)`?
pub fn rec_references(rec: &ExtentRec, subvol: u64, ino: u64) -> bool {
    rec.refs.iter().any(|r| {
        matches!(r, ExtentRef::Data { root, inode, .. } if *root == subvol && *inode == ino)
    })
}

/// Does any *other* inode hold a direct data backref?
pub fn rec_references_other(rec: &ExtentRec, subvol: u64, ino: u64) -> bool {
    rec.refs.iter().any(|r| {
        matches!(r, ExtentRef::Data { root, inode, .. } if !(*root == subvol && *inode == ino))
    })
}
