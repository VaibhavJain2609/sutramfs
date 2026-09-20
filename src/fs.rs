//! [`ApfsFs`] — the mounted APFS volume: the mount pipeline (checkpoint scan
//! → container omap → volume superblock → volume omap → fs tree), the
//! live-allocation map, deleted-object recovery from prior checkpoints, and
//! the `FileSystem` implementation.
//!
//! ## Mount pipeline (per the spec's "Mounting an Apple File System
//! Partition")
//!
//! 1. `nx_superblock_t` at block 0 → block geometry + descriptor area.
//! 2. Scan the checkpoint descriptor area; take the valid `nx_superblock_t`
//!    with the largest `o_xid` (≤ the mount bound for snapshot views).
//! 3. The checkpoint's `checkpoint_map_phys_t` blocks map ephemeral oids to
//!    the blocks they were written to in the checkpoint data area — this is
//!    how the container omap object and its B-tree are found.
//! 4. Container omap B-tree (`omap_key_t{oid,xid} → omap_val_t{paddr}`):
//!    resolves `nx_fs_oid[]` volume oids to their `apfs_superblock_t`.
//! 5. Volume omap (`apfs_omap_oid` is a *physical* block number): resolves
//!    `apfs_root_tree_oid` and fs-tree child oids to physical blocks.
//! 6. The fs B-tree's leaf records are the `jrec` universe: inodes,
//!    directory records, extents, xattrs, sibling links, snapshot names.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::sync::{Arc, Mutex};

use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsError, FsInfo, FsParser, FileSystem, MountOptions,
    Result,
};
use sutram_io::ByteSource;

use crate::apsb::Apsb;
use crate::btree::{BtreeNode, MAX_TREE_DEPTH};
use crate::checksum;
use crate::jrec::{
    self, DrecRec, ExtentRec, SiblingLinkRec, SnapMetaRec, SplitRecords, XattrRec,
};
use crate::nx::{self, Checkpoint, CheckpointScan, NxSuperblock};
use crate::object::{otype, Storage};
use crate::omap::{OmapIndex, OmapPhys, OMAP_KV_SIZE};
use crate::spaceman::Spaceman;
use crate::walk::{DeletedInode, Walk};

/// The parser entry point — stateless, cheap to construct.
pub struct ApfsParser;

/// A snapshot of a mounted volume: name ↔ transaction id, with the
/// snapshot-metadata record's extra detail when present.
#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    /// Snapshot name (from `APFS_TYPE_SNAP_NAME` / snap-metadata records).
    pub name: String,
    /// Last transaction id included in the snapshot.
    pub snap_xid: u64,
    /// Creation time (ns since Unix epoch) when recorded.
    pub create_time: Option<i64>,
    /// Change time (ns since Unix epoch) when recorded.
    pub change_time: Option<i64>,
    /// `j_snap_metadata_val_t.sblock_oid` — physical block of the volume
    /// superblock copy taken at snapshot time.
    pub sblock_oid: u64,
    /// `j_snap_metadata_val_t.extentref_tree_oid` (0 when absent).
    pub extentref_tree_oid: u64,
    /// `j_snap_metadata_val_t.flags`.
    pub flags: u32,
    /// Absolute offset of the metadata record that produced this entry.
    pub disk_offset: u64,
}

/// A volume enumerated in the container (`nx_fs_oid[]`).
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// Index into `nx_fs_oid[]` / `mount_volume` selector.
    pub index: usize,
    /// Volume superblock virtual oid.
    pub oid: u64,
    /// `apfs_volname`.
    pub name: String,
    /// `apfs_vol_uuid`.
    pub uuid: String,
    /// `true` when the volume is encrypted (FileVault / data protection).
    pub encrypted: bool,
    /// `true` for sealed (integrity-protected) volumes.
    pub sealed: bool,
    /// `apfs_num_snapshots`.
    pub num_snapshots: u64,
    /// Whether this volume parsed cleanly.
    pub valid: bool,
}

/// How an internal B-tree node's 8-byte child references are resolved.
enum ChildResolver<'a> {
    /// `BTREE_PHYSICAL`: the value *is* the child's block number.
    Physical,
    /// `BTREE_EPHEMERAL`: the value is an oid resolved via the checkpoint map.
    Ephemeral(&'a Checkpoint),
    /// Default (virtual): the value is an oid resolved via this omap index.
    Virtual(&'a OmapIndex, u64),
}

impl ChildResolver<'_> {
    fn resolve(&self, child: u64) -> Result<u64> {
        match self {
            ChildResolver::Physical => Ok(child),
            ChildResolver::Ephemeral(cp) => cp
                .lookup(child)
                .map(|(p, _)| p)
                .ok_or_else(|| FsError::NotFound {
                    path: format!("ephemeral oid {child:#x} not in checkpoint map"),
                }),
            ChildResolver::Virtual(omap, bound) => omap
                .lookup(child, *bound)
                .map(|e| e.paddr)
                .ok_or_else(|| FsError::NotFound {
                    path: format!("virtual oid {child:#x} not in object map"),
                }),
        }
    }

    /// The `bt_flags` bit a tree's `btree_info_t` should carry for this
    /// resolver's namespace (0 = virtual/default, no flag expected).
    fn expected_bt_flag(&self) -> u32 {
        match self {
            ChildResolver::Physical => crate::btree::BTREE_PHYSICAL,
            ChildResolver::Ephemeral(_) => crate::btree::BTREE_EPHEMERAL,
            ChildResolver::Virtual(..) => 0,
        }
    }
}

/// Shared read context during mount: tracks which physical blocks are
/// referenced by the live object graph (`used`) and collects non-fatal
/// parse warnings that the walk later surfaces as `Err` records.
pub(crate) struct Ctx<'a> {
    src: &'a dyn ByteSource,
    block_size: u32,
    pub used: BTreeSet<u64>,
    pub warnings: Vec<FsError>,
}

impl<'a> Ctx<'a> {
    fn new(src: &'a dyn ByteSource, block_size: u32) -> Self {
        Ctx {
            src,
            block_size,
            used: BTreeSet::new(),
            warnings: Vec::new(),
        }
    }

    /// Read the block at `paddr`, verify its Fletcher-64, and mark it used.
    fn read_object(&mut self, paddr: u64) -> Result<Vec<u8>> {
        let off = paddr
            .checked_mul(self.block_size as u64)
            .ok_or_else(|| FsError::corrupt(0, "paddr * block_size overflow"))?;
        let block = self
            .src
            .read_slice(off, self.block_size as usize)
            .map_err(FsError::Io)?;
        if block.len() < self.block_size as usize {
            return Err(FsError::truncated(
                off,
                self.block_size as u64,
                block.len() as u64,
            ));
        }
        if !checksum::verify(&block) {
            return Err(FsError::corrupt(
                off,
                "object Fletcher-64 checksum mismatch",
            ));
        }
        self.used.insert(paddr);
        Ok(block)
    }
}

/// The collected leaf records of one fs-tree view: `(key_disk_off, key, val)`.
type LeafRecords = Vec<(u64, Vec<u8>, Vec<u8>)>;

/// Walk a B-tree from `root_paddr`, collecting leaf `(key_off, key, value)`
/// triples in key order. `resolve` translates internal-node child references;
/// `fixed_kv` supplies `(key_len, _)` for `kvoff_t` tables (omap trees);
/// `expect_subtype` is the `o_subtype` every node should carry (0 = skip).
///
/// Non-fatal structural oddities (missing ROOT flag, mismatched subtype,
/// encrypted or multi-block nodes) become `ctx.warnings`, not aborts.
///
/// Loop safety: visited set on paddrs + depth cap.
fn collect_tree(
    ctx: &mut Ctx,
    root_paddr: u64,
    resolve: &ChildResolver,
    fixed_kv: (u16, u16),
    expect_subtype: u32,
) -> Result<(LeafRecords, Option<crate::btree::BtreeInfo>)> {
    let mut out = Vec::new();
    let mut root_info = None;
    let mut visited: HashSet<u64> = HashSet::new();
    let mut stack: Vec<(u64, usize)> = vec![(root_paddr, 0)];
    while let Some((paddr, depth)) = stack.pop() {
        if depth > MAX_TREE_DEPTH || !visited.insert(paddr) {
            continue;
        }
        let block = ctx.read_object(paddr)?;
        let node = BtreeNode::parse(&block, paddr * ctx.block_size as u64)?;
        let off = node.disk_offset;
        if depth == 0 && !node.is_root() {
            ctx.warnings.push(FsError::corrupt(
                off,
                "btree root node lacks BTNODE_ROOT",
            ));
        }
        if expect_subtype != 0 && node.hdr.osubtype != 0 && node.hdr.osubtype != expect_subtype {
            ctx.warnings.push(FsError::corrupt(
                off,
                format!(
                    "{} node o_subtype {:#x}, expected {:#x}",
                    node.hdr.type_name(),
                    node.hdr.osubtype,
                    expect_subtype
                ),
            ));
        }
        if node.hdr.encrypted() {
            ctx.warnings.push(FsError::corrupt(
                off,
                "btree node flagged OBJ_ENCRYPTED; contents are ciphertext",
            ));
        }
        if node.is_leaf() && node.level != 0 {
            ctx.warnings.push(FsError::corrupt(
                off,
                format!("leaf node claims level {}", node.level),
            ));
        }
        if depth == 0 {
            if let Some(info) = node.info() {
                if info.node_size != 0 && info.node_size != ctx.block_size {
                    ctx.warnings.push(FsError::corrupt(
                        off,
                        format!(
                            "btree_info node_size {} != block size {}",
                            info.node_size, ctx.block_size
                        ),
                    ));
                }
                let expected = resolve.expected_bt_flag();
                if expected != 0 && info.flags & expected == 0 {
                    ctx.warnings.push(FsError::corrupt(
                        off,
                        format!("btree_info flags {:#x} miss expected storage bit", info.flags),
                    ));
                }
                root_info = Some(info);
            }
        }
        if node.is_leaf() {
            for e in node.entries(fixed_kv) {
                let (koff, k, v) = e?;
                out.push((koff, k.to_vec(), v.to_vec()));
            }
        } else {
            let mut children = Vec::with_capacity(node.nkeys as usize);
            for i in 0..node.nkeys {
                let (_k, child) = node.child_at(i, fixed_kv.0)?;
                children.push(child);
            }
            for child in children.into_iter().rev() {
                let cp = resolve.resolve(child)?;
                stack.push((cp, depth + 1));
            }
        }
    }
    Ok((out, root_info))
}

/// Collect an omap B-tree's leaf records into an [`OmapIndex`].
fn load_omap_tree(
    ctx: &mut Ctx,
    tree_root_paddr: u64,
    resolve: &ChildResolver,
) -> Result<OmapIndex> {
    let (leafs, _info) = collect_tree(ctx, tree_root_paddr, resolve, OMAP_KV_SIZE, otype::OMAP)?;
    let mut idx = OmapIndex::default();
    for (_off, k, v) in leafs {
        match crate::omap::OmapEntry::decode(&k, &v) {
            Ok(e) => {
                if e.flags & crate::omap::OMAP_VAL_ENCRYPTED != 0 {
                    ctx.warnings.push(FsError::corrupt(
                        e.paddr * ctx.block_size as u64,
                        format!("omap entry for oid {:#x} is OMAP_VAL_ENCRYPTED", e.oid),
                    ));
                }
                idx.insert(e);
            }
            Err(e) => ctx.warnings.push(e),
        }
    }
    Ok(idx)
}

/// Everything needed to walk one generation of the file-system tree.
pub(crate) struct FsView {
    /// Typed record indexes.
    pub recs: SplitRecords,
    /// Physical block of the fs-tree root node that produced these records.
    pub root_paddr: u64,
    /// The apsb in effect for this view (name, flags).
    pub apsb: Apsb,
}

/// A mounted APFS volume.
pub struct ApfsFs {
    src: Arc<dyn ByteSource>,
    pub(crate) opts: MountOptions,
    /// The checkpoint the mount is anchored at.
    pub(crate) nx: NxSuperblock,
    /// Whether block 0's own checksum verified (block 0 is often stale).
    block0_checksum_ok: bool,
    /// `o_xid` of the mounted checkpoint.
    pub(crate) checkpoint_xid: u64,
    /// Upper bound on object transaction ids — `u64::MAX` for the live mount,
    /// a snapshot's `snap_xid` for a snapshot view.
    xid_bound: u64,
    /// Number of valid checkpoints found in the descriptor area.
    checkpoints_found: usize,
    /// Descriptor slots that failed validation.
    malformed_desc_slots: Vec<u64>,
    /// Every volume in `nx_fs_oid[]` (valid or not), for reporting.
    volumes: Vec<VolumeInfo>,
    /// Index of the mounted volume.
    volume_index: usize,
    /// Live record view.
    pub(crate) view: FsView,
    /// `btree_info_t` of the fs-tree root (node/key statistics).
    fstree_info: Option<crate::btree::BtreeInfo>,
    /// Container omap counters surfaced in `info()`.
    container_omap_snap_count: u32,
    container_omap_recent_snap: u64,
    /// Deleted inodes recovered from prior checkpoints (newest first).
    pub(crate) deleted: Vec<DeletedInode>,
    /// Snapshots merged from SNAP_NAME + snap-metadata records.
    snapshots: Vec<SnapshotInfo>,
    /// Blocks referenced by the live object graph (metadata + extents).
    live_blocks: BTreeSet<u64>,
    /// Total container blocks.
    block_count: u64,
    /// Parsed space-manager header when the object was readable.
    spaceman: Option<Spaceman>,
    /// Mount-time warnings surfaced inside the walk stream (lenient mode).
    /// `Mutex` because `FsError` isn't `Clone` and `walk()` only has `&self`;
    /// the first walk drains them into the entry stream.
    pub(crate) warnings: Mutex<Vec<FsError>>,
    /// Volume-level encryption flag (FileVault): structure is listed, data
    /// reads stay raw ciphertext — we never attempt decryption.
    pub(crate) encrypted: bool,
    /// Sealed-volume flag.
    pub(crate) sealed: bool,
}

impl ApfsParser {
    /// Mount a specific volume of the container (`nx_fs_oid[]` index).
    pub fn mount_volume(
        &self,
        src: Arc<dyn ByteSource>,
        opts: &MountOptions,
        index: usize,
    ) -> Result<Box<dyn FileSystem>> {
        Ok(Box::new(ApfsFs::mount_inner(
            src,
            opts.clone(),
            index,
            u64::MAX,
        )?))
    }

    /// Mount a snapshot view: object resolution is bounded by `snap_xid`, so
    /// the fs tree is read as of that transaction. Use
    /// [`FileSystem::info`] `meta["snapshot_view_xid"]` to confirm the bound.
    pub fn mount_snapshot(
        &self,
        src: Arc<dyn ByteSource>,
        opts: &MountOptions,
        snap_xid: u64,
    ) -> Result<Box<dyn FileSystem>> {
        Ok(Box::new(ApfsFs::mount_inner(
            src,
            opts.clone(),
            0,
            snap_xid,
        )?))
    }
}

impl ApfsFs {
    /// Snapshot metadata merged from the fs tree's SNAP_NAME records and the
    /// snapshot-metadata tree (when present).
    pub fn snapshots(&self) -> &[SnapshotInfo] {
        &self.snapshots
    }

    /// All volumes enumerated from `nx_fs_oid[]`.
    pub fn volumes(&self) -> &[VolumeInfo] {
        &self.volumes
    }

    /// Transaction id of the mounted checkpoint.
    pub fn checkpoint_xid(&self) -> u64 {
        self.checkpoint_xid
    }

    /// The xid bound in effect (`u64::MAX` on a live mount).
    pub fn xid_bound(&self) -> u64 {
        self.xid_bound
    }

    /// Core mount: `vol_index` selects the volume, `xid_bound` the
    /// transaction bound (`u64::MAX` = latest checkpoint).
    pub(crate) fn mount_inner(
        src: Arc<dyn ByteSource>,
        opts: MountOptions,
        vol_index: usize,
        xid_bound: u64,
    ) -> Result<Self> {
        let label = NxSuperblock::read_block0(src.as_ref())?;
        let block0_checksum_ok = label.checksum_ok_at(src.as_ref());
        let block_size = label.block_size;
        if !label.xp_desc_contiguous {
            return Err(FsError::unsupported(
                "non-contiguous checkpoint descriptor area (descriptor B-tree)",
            ));
        }
        let scan: CheckpointScan = nx::scan_checkpoints(src.as_ref(), &label)?;

        // Candidate checkpoints: highest xid first, bounded by `xid_bound`.
        let mut candidates: Vec<&Checkpoint> = scan
            .checkpoints
            .iter()
            .filter(|c| c.xid <= xid_bound)
            .rev()
            .collect();
        if candidates.is_empty() {
            return Err(FsError::corrupt(
                label.xp_desc_base * block_size as u64,
                "no valid checkpoint in the descriptor area",
            ));
        }

        // Lenient mount: if the newest checkpoint's objects are malformed the
        // spec says to roll back to an older one — which is also the forensic
        // behaviour we want.
        let mut errors = Vec::new();
        let mut mounted: Option<ApfsFs> = None;
        for cp in candidates.drain(..) {
            match Self::mount_at_checkpoint(
                &src,
                &opts,
                cp,
                &scan,
                vol_index,
                xid_bound,
                block0_checksum_ok,
            ) {
                Ok(ok) => {
                    mounted = Some(ok);
                    break;
                }
                Err(e) => {
                    if opts.strict {
                        return Err(e);
                    }
                    errors.push(e);
                }
            }
        }
        let fs = match mounted {
            Some(v) => v,
            None => {
                return Err(errors.into_iter().next().unwrap_or_else(|| {
                    FsError::corrupt(0, "no mountable checkpoint")
                }))
            }
        };
        if let Ok(mut w) = fs.warnings.lock() {
            w.append(&mut errors);
        }
        Ok(fs)
    }

    /// Try to build a complete view at one checkpoint.
    fn mount_at_checkpoint(
        src: &Arc<dyn ByteSource>,
        opts: &MountOptions,
        cp: &Checkpoint,
        scan: &CheckpointScan,
        vol_index: usize,
        xid_bound: u64,
        block0_checksum_ok: bool,
    ) -> Result<ApfsFs> {
        let nx = &cp.nx;
        let mut ctx = Ctx::new(src.as_ref(), nx.block_size);
        // Object resolution bound: `xid_bound` (a snapshot xid for snapshot
        // mounts, u64::MAX for live). The checkpoint's omap only carries
        // entries ≤ cp.xid, so bounding by the requested xid is what makes
        // snapshot views see the tree as-of the snapshot.
        let bound = xid_bound;

        // Mark the checkpoint infrastructure itself allocated: the whole
        // descriptor ring is reserved even where slots are unused. The data
        // area is NOT marked wholesale — its unreferenced blocks are the
        // free/carving space reported by `unallocated_ranges`.
        for i in 0..nx.xp_desc_blocks as u64 {
            ctx.used.insert(nx.xp_desc_base + i);
        }
        for e in &cp.map {
            let blocks = (e.size as u64).max(nx.block_size as u64) / nx.block_size as u64;
            for b in 0..blocks.max(1) {
                ctx.used.insert(e.paddr + b);
            }
        }
        if nx.keybag_blocks > 0 {
            for b in 0..nx.keybag_blocks {
                ctx.used.insert(nx.keybag_base + b);
            }
        }
        ctx.used.insert(0);

        // ---- container object map -------------------------------------
        let (container_omap, container_omap_phys) = Self::load_container_omap(&mut ctx, cp)?;
        // Mark every block the omap points at ≤ bound as allocated —
        // including multi-block objects whose tail blocks we never read.
        {
            let bs = ctx.block_size as u64;
            for e in container_omap
                .by_oid
                .values()
                .flatten()
                .filter(|e| e.xid <= bound)
            {
                for b in 0..(e.size as u64).max(bs).div_ceil(bs) {
                    ctx.used.insert(e.paddr + b);
                }
            }
        }
        // Record the omap's own blocks.
        // (read_object already marked them.)

        // ---- enumerate volumes -----------------------------------------
        let mut volumes: Vec<VolumeInfo> = Vec::new();
        let mut apsbs: Vec<Option<Apsb>> = Vec::new();
        for (i, &fs_oid) in nx.fs_oids.iter().enumerate() {
            let apsb = Self::load_apsb(&mut ctx, &container_omap, fs_oid, bound)
                .map_err(|e| {
                    ctx.warnings.push(e);
                    None::<Apsb>
                })
                .ok()
                .flatten();
            volumes.push(match &apsb {
                Some(a) => VolumeInfo {
                    index: i,
                    oid: fs_oid,
                    name: a.name.clone(),
                    uuid: a.uuid.clone(),
                    encrypted: a.is_encrypted(),
                    sealed: a.is_sealed(),
                    num_snapshots: a.num_snapshots,
                    valid: true,
                },
                None => VolumeInfo {
                    index: i,
                    oid: fs_oid,
                    name: String::new(),
                    uuid: String::new(),
                    encrypted: false,
                    sealed: false,
                    num_snapshots: 0,
                    valid: false,
                },
            });
            apsbs.push(apsb);
        }
        if apsbs.iter().all(|a| a.is_none()) && !nx.fs_oids.is_empty() {
            return Err(FsError::corrupt(
                nx.disk_offset,
                "no volume superblock could be resolved",
            ));
        }
        let vi = vol_index.min(apsbs.len().saturating_sub(1));
        let apsb = apsbs
            .get(vi)
            .and_then(|a| a.clone())
            .or_else(|| apsbs.iter().flatten().next().cloned())
            .ok_or_else(|| FsError::corrupt(nx.disk_offset, "empty nx_fs_oid table"))?;

        // ---- volume object map (physical tree) --------------------------
        let vol_omap_phys_block = ctx.read_object(apsb.omap_oid)?;
        let vol_omap = OmapPhys::parse(&vol_omap_phys_block, apsb.omap_oid * ctx.block_size as u64)?;
        let vol_omap_idx = load_omap_tree(
            &mut ctx,
            vol_omap.tree_oid,
            &ChildResolver::Physical,
        )?;

        // ---- file-system tree (virtual tree via the volume omap) --------
        let root = vol_omap_idx
            .lookup(apsb.root_tree_oid, bound)
            .ok_or_else(|| FsError::NotFound {
                path: format!("root_tree_oid {:#x} not in volume omap", apsb.root_tree_oid),
            })?;
        let (leafs, fstree_info) = collect_tree(
            &mut ctx,
            root.paddr,
            &ChildResolver::Virtual(&vol_omap_idx, bound),
            (0, 0),
            otype::FSTREE,
        )?;
        let hashed = match apsb.drec_layout() {
            crate::apsb::DrecLayout::Hashed => Some(true),
            crate::apsb::DrecLayout::Plain => Some(false),
        };
        let (recs, errs) = decode_leafs(leafs, hashed);
        ctx.warnings.extend(errs);

        // ---- snapshot metadata tree (physical) ---------------------------
        let mut snap_meta: Vec<SnapMetaRec> = Vec::new();
        if apsb.snap_meta_tree_oid != 0 {
            match collect_tree(
                &mut ctx,
                apsb.snap_meta_tree_oid,
                &ChildResolver::Physical,
                (0, 0),
                otype::SNAPMETATREE,
            ) {
                Ok((leafs, _)) => {
                    for (off, k, v) in leafs {
                        match jrec::decode_record(&k, &v, None) {
                            Ok(jrec::JRecord::SnapMetadata {
                                snap_xid,
                                extentref_tree_oid,
                                sblock_oid,
                                create_time,
                                change_time,
                                flags,
                                name,
                            }) => snap_meta.push(SnapMetaRec {
                                off,
                                snap_xid,
                                extentref_tree_oid,
                                sblock_oid,
                                create_time,
                                change_time,
                                flags,
                                name,
                            }),
                            Ok(_) => {}
                            Err(e) => ctx.warnings.push(e),
                        }
                    }
                }
                Err(e) => ctx.warnings.push(e),
            }
        }

        // ---- space manager (free-block count for info) -------------------
        let mut spaceman = None;
        if let Some((paddr, _)) = cp.lookup(nx.spaceman_oid) {
            match ctx.read_object(paddr) {
                Ok(b) => match Spaceman::parse(&b, paddr * ctx.block_size as u64) {
                    Ok(sm) => spaceman = Some(sm),
                    Err(e) => ctx.warnings.push(e),
                },
                Err(e) => ctx.warnings.push(e),
            }
        }

        // ---- live file extents + physical-extent records are claimed ------
        for list in recs.extents.values() {
            for ex in list {
                claim_extent(&mut ctx.used, ex, nx.block_size as u64);
            }
        }
        for &(oid, len) in &recs.phys_extents {
            for b in 0..len.div_ceil(nx.block_size as u64).max(1) {
                ctx.used.insert(oid + b);
            }
        }

        // ---- prior checkpoints → superseded generations ------------------
        let mut deleted: Vec<DeletedInode> = Vec::new();
        let mut deleted_seen: HashSet<u64> = HashSet::new();
        for prior in scan
            .checkpoints
            .iter()
            .filter(|p| p.xid < cp.xid)
            .rev()
            .take(MAX_PRIOR_CHECKPOINTS)
        {
            match Self::load_prior_view(src, prior, nx, &apsb) {
                Ok(old) => {
                    // file_id → (parent_oid, name) for path reconstruction
                    // inside the superseded generation.
                    let old_names: HashMap<u64, (u64, String)> = old
                        .recs
                        .drecs
                        .iter()
                        .map(|d| (d.file_id, (d.parent_oid, d.name.clone())))
                        .collect();
                    for (&oid, (off, iv)) in &old.recs.inodes {
                        if oid == jrec::ROOT_DIR_INODE
                            || recs.inodes.contains_key(&oid)
                            || !deleted_seen.insert(oid)
                        {
                            continue;
                        }
                        deleted.push(DeletedInode {
                            oid,
                            inode: iv.clone(),
                            record_off: *off,
                            from_xid: prior.xid,
                            extents: old
                                .recs
                                .extents
                                .get(&iv.private_id)
                                .cloned()
                                .unwrap_or_default(),
                            old_names: old_names.clone(),
                        });
                    }
                }
                Err(e) => ctx.warnings.push(e),
            }
        }

        // ---- merge snapshot name + metadata records -----------------------
        let snapshots = merge_snapshots(&recs.snap_names, &snap_meta);

        let used = std::mem::take(&mut ctx.used);
        let warnings = std::mem::take(&mut ctx.warnings);
        let fs = ApfsFs {
            src: src.clone(),
            opts: opts.clone(),
            nx: nx.clone(),
            block0_checksum_ok,
            checkpoint_xid: cp.xid,
            xid_bound,
            checkpoints_found: scan.checkpoints.len(),
            malformed_desc_slots: scan.malformed_slots.clone(),
            volumes,
            volume_index: vi,
            view: FsView {
                recs,
                root_paddr: root.paddr,
                apsb: apsb.clone(),
            },
            fstree_info,
            container_omap_snap_count: container_omap_phys.snap_count,
            container_omap_recent_snap: container_omap_phys.most_recent_snap,
            deleted,
            snapshots,
            live_blocks: used,
            block_count: nx.block_count,
            spaceman,
            warnings: Mutex::new(warnings),
            encrypted: apsb.is_encrypted(),
            sealed: apsb.is_sealed(),
        };
        Ok(fs)
    }

    /// Load the container omap for a checkpoint: `nx_omap_oid` is resolved
    /// through the checkpoint map (ephemeral). Fallback for non-Apple
    /// writers that store a physical block number there. Returns the leaf
    /// index and the omap object's own header data for reporting.
    fn load_container_omap(ctx: &mut Ctx, cp: &Checkpoint) -> Result<(OmapIndex, OmapPhys)> {
        let bs = ctx.block_size as u64;
        let (omap_paddr, ephemeral) = match cp.lookup(cp.nx.omap_oid) {
            Some((p, _)) => (p, true),
            None => (cp.nx.omap_oid, false), // paddr fallback
        };
        let block = ctx.read_object(omap_paddr)?;
        let om = OmapPhys::parse(&block, omap_paddr * bs)?;
        if om.hdr.oid != cp.nx.omap_oid && ephemeral {
            ctx.warnings.push(FsError::corrupt(
                omap_paddr * bs + 8,
                format!(
                    "omap o_oid {:#x} != nx_omap_oid {:#x}",
                    om.hdr.oid, cp.nx.omap_oid
                ),
            ));
        }
        let tree_ephemeral = ephemeral
            || om.hdr.storage() == Storage::Ephemeral
            || om.tree_type & crate::object::oflags::EPHEMERAL != 0;
        let (tree_root, resolver): (u64, ChildResolver) = if tree_ephemeral {
            let (p, _) = cp.lookup(om.tree_oid).ok_or_else(|| FsError::NotFound {
                path: format!("omap tree oid {:#x} not in checkpoint map", om.tree_oid),
            })?;
            (p, ChildResolver::Ephemeral(cp))
        } else {
            (om.tree_oid, ChildResolver::Physical)
        };
        let idx = load_omap_tree(ctx, tree_root, &resolver)?;
        Ok((idx, om))
    }

    /// Resolve a volume superblock oid through the container omap and parse
    /// the `apfs_superblock_t` it points at.
    fn load_apsb(
        ctx: &mut Ctx,
        omap: &OmapIndex,
        fs_oid: u64,
        bound: u64,
    ) -> Result<Option<Apsb>> {
        let Some(e) = omap.lookup(fs_oid, bound) else {
            return Ok(None);
        };
        let block = ctx.read_object(e.paddr)?;
        Ok(Some(Apsb::parse(&block, e.paddr * ctx.block_size as u64)?))
    }

    /// Rebuild a prior checkpoint's fs-tree view (superseded generation)
    /// for deleted-object recovery.
    fn load_prior_view(
        src: &Arc<dyn ByteSource>,
        prior: &Checkpoint,
        live_nx: &NxSuperblock,
        live_apsb: &Apsb,
    ) -> Result<FsView> {
        let mut ctx = Ctx::new(src.as_ref(), live_nx.block_size);
        let bound = prior.xid;
        let (c_omap, _om_phys) = Self::load_container_omap(&mut ctx, prior)?;

        // Find the volume matching our mounted volume (by UUID, falling back
        // to the same nx_fs_oid index position).
        let mut old_apsb = None;
        for &fs_oid in &prior.nx.fs_oids {
            if let Some(a) = Self::load_apsb(&mut ctx, &c_omap, fs_oid, bound)? {
                let matches = a.uuid == live_apsb.uuid;
                if matches || old_apsb.is_none() {
                    old_apsb = Some(a);
                    if matches {
                        break;
                    }
                }
            }
        }
        let old_apsb = old_apsb.ok_or_else(|| FsError::NotFound {
            path: "volume not present in prior checkpoint".into(),
        })?;
        let v_omap_blk = ctx.read_object(old_apsb.omap_oid)?;
        let v_omap = OmapPhys::parse(&v_omap_blk, old_apsb.omap_oid * ctx.block_size as u64)?;
        let v_omap_idx = load_omap_tree(&mut ctx, v_omap.tree_oid, &ChildResolver::Physical)?;
        let root = v_omap_idx
            .lookup(old_apsb.root_tree_oid, bound)
            .ok_or_else(|| FsError::NotFound {
                path: "prior fs root not in volume omap".into(),
            })?;
        let (leafs, _) = collect_tree(
            &mut ctx,
            root.paddr,
            &ChildResolver::Virtual(&v_omap_idx, bound),
            (0, 0),
            otype::FSTREE,
        )?;
        let hashed = match old_apsb.drec_layout() {
            crate::apsb::DrecLayout::Hashed => Some(true),
            crate::apsb::DrecLayout::Plain => Some(false),
        };
        let (recs, errs) = decode_leafs(leafs, hashed);
        ctx.warnings.extend(errs);
        Ok(FsView {
            recs,
            root_paddr: root.paddr,
            apsb: old_apsb,
        })
    }

    /// Block-level ranges of the image that hold no live-referenced data:
    /// the carving ground. `live_blocks` covers every block reached through
    /// the mounted checkpoint's object graph plus live file extents and the
    /// checkpoint areas. Anything else is reported (includes superseded
    /// objects — where deleted data survives).
    fn free_ranges(&self) -> Vec<(u64, u64)> {
        let bs = self.nx.block_size as u64;
        let total = self.block_count.min(self.src.len() / bs);
        let mut out = Vec::new();
        let mut run_start: Option<u64> = None;
        for b in 0..total {
            if self.live_blocks.contains(&b) {
                if let Some(s) = run_start.take() {
                    out.push((s * bs, (b - s) * bs));
                }
            } else if run_start.is_none() {
                run_start = Some(b);
            }
        }
        if let Some(s) = run_start {
            out.push((s * bs, (total - s) * bs));
        }
        out
    }

    /// Per-file magic verdict via a bounded header read.
    pub(crate) fn magic_for(&self, e: &FsEntry) -> Option<sutram_magic::MagicVerdict> {
        if !self.opts.check_magic || e.kind != EntryKind::File || e.size == 0 {
            return None;
        }
        if e.allocated_ranges.is_empty() {
            return None;
        }
        let mut r = self.read_file(e).ok()?;
        let mut header = vec![0u8; 4096.min(e.size as usize)];
        let n = r.read(&mut header).ok()?;
        header.truncate(n);
        Some(sutram_magic::check_entry(&e.name, &header))
    }

    /// Recovery assessment for a deleted inode's extents: which physical
    /// blocks are not claimed by the live object graph.
    pub(crate) fn recovery_for_deleted(
        &self,
        extents: &[ExtentRec],
        size: u64,
    ) -> (sutram_fs::RecoveryState, Vec<(u64, u64)>, Vec<String>) {
        use sutram_fs::RecoveryState;
        let bs = self.nx.block_size as u64;
        let mut notes = Vec::new();
        if extents.is_empty() || size == 0 {
            return (
                if size == 0 {
                    RecoveryState::Intact
                } else {
                    RecoveryState::Unrecoverable
                },
                Vec::new(),
                notes,
            );
        }
        let mut surviving: Vec<(u64, u64)> = Vec::new();
        let mut lost_blocks = 0u64;
        let mut total_blocks = 0u64;
        let mut exts: Vec<&ExtentRec> = extents.iter().collect();
        exts.sort_by_key(|e| e.logical_addr);
        for ex in exts {
            let nblocks = ex.len.div_ceil(bs).max(1);
            total_blocks += nblocks;
            // Per-block granularity: a block either survives or was claimed.
            let mut run: Option<(u64, u64)> = None; // (start_off, len)
            for i in 0..nblocks {
                let blk = ex.phys_block + i;
                let blk_off = blk * bs;
                let blk_len = bs.min(ex.len - i * bs);
                if self.live_blocks.contains(&blk) {
                    lost_blocks += 1;
                    if let Some((o, l)) = run.take() {
                        surviving.push((o, l));
                    }
                } else {
                    match &mut run {
                        Some((_, l)) => *l += blk_len,
                        slot => *slot = Some((blk_off, blk_len)),
                    }
                }
            }
            if let Some((o, l)) = run.take() {
                surviving.push((o, l));
            }
        }
        let recovered_bytes: u64 = surviving.iter().map(|(_, l)| *l).sum::<u64>().min(size);
        if lost_blocks > 0 {
            notes.push(format!(
                "{lost_blocks}/{total_blocks} extent block(s) reclaimed by the live checkpoint"
            ));
        }
        let state = if lost_blocks == 0 {
            RecoveryState::Intact
        } else if recovered_bytes == 0 {
            RecoveryState::Unrecoverable
        } else {
            RecoveryState::PartiallyOverwritten {
                recovered_bytes,
                total_bytes: size,
            }
        };
        (state, surviving, notes)
    }
}

/// Claim the blocks of a file extent as live-allocated.
fn claim_extent(used: &mut BTreeSet<u64>, ex: &ExtentRec, bs: u64) {
    let n = ex.len.div_ceil(bs).max(1);
    for i in 0..n {
        used.insert(ex.phys_block + i);
    }
}

/// Decode all leaf `(key_off, key, val)` triples into typed records.
fn decode_leafs(
    leafs: LeafRecords,
    hashed: Option<bool>,
) -> (SplitRecords, Vec<FsError>) {
    let mut errs = Vec::new();
    let mut split = SplitRecords::default();
    for (off, k, v) in leafs {
        match jrec::decode_record(&k, &v, hashed) {
            Ok(rec) => pending_records(&mut split, off, rec),
            Err(e) => errs.push(e),
        }
    }
    (split, errs)
}

/// Single-record insertion (same classification as `jrec::split_by_type`
/// but preserving per-record provenance offsets).
fn pending_records(s: &mut SplitRecords, off: u64, rec: jrec::JRecord) {
    match rec {
        jrec::JRecord::Inode { oid, val } => {
            s.inodes.insert(oid, (off, val));
        }
        jrec::JRecord::Drec {
            parent_oid,
            name,
            name_hash,
            file_id,
            date_added,
            flags,
            sibling_id,
        } => s.drecs.push(DrecRec {
            off,
            parent_oid,
            name,
            name_hash,
            file_id,
            date_added,
            flags,
            sibling_id,
        }),
        jrec::JRecord::FileExtent {
            private_id,
            logical_addr,
            len,
            flags,
            phys_block,
            crypto_id,
        } => {
            s.extents.entry(private_id).or_default().push(ExtentRec {
                off,
                logical_addr,
                len,
                flags,
                phys_block,
                crypto_id,
            });
        }
        jrec::JRecord::Xattr {
            oid,
            name,
            flags,
            data_len,
            embedded,
            stream_oid,
        } => {
            s.xattrs.entry(oid).or_default().push(XattrRec {
                off,
                name,
                flags,
                data_len,
                embedded,
                stream_oid,
            });
        }
        jrec::JRecord::SiblingLink {
            oid,
            sibling_id,
            parent_id,
            name,
        } => s.sibling_links.push(SiblingLinkRec {
            off,
            oid,
            sibling_id,
            parent_id,
            name,
        }),
        jrec::JRecord::SiblingMap {
            sibling_id,
            file_id,
        } => {
            s.sibling_map.insert(sibling_id, file_id);
        }
        jrec::JRecord::DirStats {
            oid,
            num_children,
            total_size,
        } => {
            s.dir_stats.insert(oid, (num_children, total_size));
        }
        jrec::JRecord::SnapName { name, snap_xid } => {
            s.snap_names.push((off, name, snap_xid));
        }
        jrec::JRecord::SnapMetadata { .. } => {
            // SNAP_METADATA records live in the snapshot-metadata tree; the
            // fs tree shouldn't carry them. Collected separately.
        }
        jrec::JRecord::CryptoState { oid } => {
            s.crypto_oids.insert(oid);
        }
        jrec::JRecord::PhysExtent { oid, len } => {
            s.phys_extents.push((oid, len));
        }
        jrec::JRecord::Other { oid, jtype } => {
            s.other_count.entry(jtype).or_insert((0, oid)).0 += 1;
        }
    }
}

/// Merge SNAP_NAME records (fs tree) with snap-metadata records (snap-meta
/// tree) into per-snapshot report entries.
fn merge_snapshots(
    names: &[(u64, String, u64)],
    meta: &[SnapMetaRec],
) -> Vec<SnapshotInfo> {
    let mut by_xid: HashMap<u64, SnapshotInfo> = HashMap::new();
    for (off, name, xid) in names {
        let e = by_xid.entry(*xid).or_insert_with(|| SnapshotInfo {
            name: String::new(),
            snap_xid: *xid,
            create_time: None,
            change_time: None,
            sblock_oid: 0,
            extentref_tree_oid: 0,
            flags: 0,
            disk_offset: *off,
        });
        if !name.is_empty() {
            e.name = name.clone();
        }
    }
    for m in meta {
        let e = by_xid.entry(m.snap_xid).or_insert_with(|| SnapshotInfo {
            name: String::new(),
            snap_xid: m.snap_xid,
            create_time: None,
            change_time: None,
            sblock_oid: 0,
            extentref_tree_oid: 0,
            flags: 0,
            disk_offset: m.off,
        });
        if !m.name.is_empty() {
            e.name = m.name.clone();
        }
        e.create_time = Some(m.create_time);
        e.change_time = Some(m.change_time);
        e.sblock_oid = m.sblock_oid;
        e.extentref_tree_oid = m.extentref_tree_oid;
        e.flags = m.flags;
        e.disk_offset = m.off;
    }
    let mut out: Vec<SnapshotInfo> = by_xid.into_values().collect();
    out.sort_by_key(|s| s.snap_xid);
    out
}

/// Cap on how many prior checkpoints we walk for deleted-object recovery.
pub(crate) const MAX_PRIOR_CHECKPOINTS: usize = 8;

impl FsParser for ApfsParser {
    fn name(&self) -> &'static str {
        "apfs"
    }

    fn detect(&self, src: &dyn ByteSource) -> DetectConfidence {
        nx::detect(src)
    }

    fn mount_with(
        &self,
        src: Arc<dyn ByteSource>,
        opts: &MountOptions,
    ) -> Result<Box<dyn FileSystem>> {
        Ok(Box::new(ApfsFs::mount_inner(
            src,
            opts.clone(),
            0,
            u64::MAX,
        )?))
    }
}

impl FileSystem for ApfsFs {
    fn info(&self) -> FsInfo {
        let apsb = &self.view.apsb;
        let mut meta = HashMap::new();
        meta.insert("container_uuid".into(), self.nx.uuid.clone());
        meta.insert("checkpoint_xid".into(), self.checkpoint_xid.to_string());
        meta.insert("checkpoints_found".into(), self.checkpoints_found.to_string());
        meta.insert(
            "block0_checksum_ok".into(),
            self.block0_checksum_ok.to_string(),
        );
        meta.insert("volume_index".into(), self.volume_index.to_string());
        meta.insert("volume_count".into(), self.volumes.len().to_string());
        meta.insert("volume_oid".into(), format!("{:#x}", self.nx.fs_oids.get(self.volume_index).copied().unwrap_or(0)));
        meta.insert("apsb_xid".into(), apsb.hdr.xid.to_string());
        meta.insert("apsb_fs_index".into(), apsb.fs_index.to_string());
        meta.insert("apsb_alloc_count".into(), apsb.alloc_count.to_string());
        meta.insert("apsb_unmount_time".into(), apsb.unmount_time.to_string());
        meta.insert("apsb_last_mod_time".into(), apsb.last_mod_time.to_string());
        meta.insert("apsb_num_other".into(), apsb.num_other.to_string());
        meta.insert("root_tree_type".into(), format!("{:#x}", apsb.root_tree_type));
        meta.insert("snap_meta_tree_oid".into(), format!("{:#x}", apsb.snap_meta_tree_oid));
        meta.insert("meta_crypto_present".into(), apsb.meta_crypto_nonzero.to_string());
        meta.insert("apsb_off".into(), format!("{:#x}", apsb.disk_offset));
        meta.insert("nx_max_file_systems".into(), self.nx.max_file_systems.to_string());
        meta.insert("nx_data_base".into(), self.nx.xp_data_base.to_string());
        meta.insert("nx_data_blocks".into(), self.nx.xp_data_blocks.to_string());
        meta.insert("features".into(), format!("{:#x}", apsb.features));
        meta.insert("ro_compat".into(), format!("{:#x}", apsb.ro_compat));
        meta.insert("incompat".into(), format!("{:#x}", apsb.incompat));
        meta.insert("fs_flags".into(), format!("{:#x}", apsb.fs_flags));
        meta.insert("nx_features".into(), format!("{:#x}", self.nx.features));
        meta.insert("nx_ro_compat".into(), format!("{:#x}", self.nx.ro_compat));
        meta.insert("nx_incompat".into(), format!("{:#x}", self.nx.incompat));
        meta.insert("nx_flags".into(), format!("{:#x}", self.nx.nx_flags));
        meta.insert("nx_next_oid".into(), format!("{:#x}", self.nx.next_oid));
        meta.insert("nx_next_xid".into(), self.nx.next_xid.to_string());
        meta.insert("nx_reaper_oid".into(), format!("{:#x}", self.nx.reaper_oid));
        meta.insert(
            "checkpoint_desc_index".into(),
            self.nx.xp_desc_index.to_string(),
        );
        meta.insert(
            "checkpoint_desc_len".into(),
            self.nx.xp_desc_len.to_string(),
        );
        meta.insert(
            "container_omap_snap_count".into(),
            self.container_omap_snap_count.to_string(),
        );
        meta.insert(
            "container_omap_recent_snap".into(),
            self.container_omap_recent_snap.to_string(),
        );
        if let Some(info) = &self.fstree_info {
            meta.insert("fstree_flags".into(), format!("{:#x}", info.flags));
            meta.insert("fstree_key_count".into(), info.key_count.to_string());
            meta.insert("fstree_node_count".into(), info.node_count.to_string());
        }
        if let Some(sm) = &self.spaceman {
            meta.insert("sm_blocks_per_chunk".into(), sm.blocks_per_chunk.to_string());
            meta.insert("sm_chunks_per_cib".into(), sm.chunks_per_cib.to_string());
            meta.insert("sm_cibs_per_cab".into(), sm.cibs_per_cab.to_string());
            meta.insert("sm_flags".into(), format!("{:#x}", sm.flags));
            meta.insert("sm_dev_block_count".into(), sm.dev_block_count.to_string());
            meta.insert("sm_dev_chunk_count".into(), sm.dev_chunk_count.to_string());
            meta.insert("sm_block_size".into(), sm.block_size.to_string());
        }
        if !self.view.recs.other_count.is_empty() {
            let mut v: Vec<_> = self.view.recs.other_count.iter().collect();
            v.sort_by_key(|(t, _)| **t);
            meta.insert(
                "unhandled_jrec_types".into(),
                v.iter()
                    .map(|(t, (n, _))| format!("{t:#x}x{n}"))
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        meta.insert(
            "phys_extent_records".into(),
            self.view.recs.phys_extents.len().to_string(),
        );
        meta.insert("num_files".into(), apsb.num_files.to_string());
        meta.insert("num_directories".into(), apsb.num_directories.to_string());
        meta.insert("num_symlinks".into(), apsb.num_symlinks.to_string());
        meta.insert("root_tree_oid".into(), format!("{:#x}", apsb.root_tree_oid));
        meta.insert("extentref_tree_oid".into(), format!("{:#x}", apsb.extentref_tree_oid));
        if self.xid_bound != u64::MAX {
            meta.insert("snapshot_view_xid".into(), self.xid_bound.to_string());
        }
        meta.insert("sealed".into(), self.sealed.to_string());
        meta.insert("encrypted".into(), self.encrypted.to_string());
        meta.insert(
            "deleted_recovered".into(),
            self.deleted.len().to_string(),
        );
        if !self.malformed_desc_slots.is_empty() {
            meta.insert(
                "malformed_desc_slots".into(),
                self.malformed_desc_slots
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            );
        }
        meta.insert("snapshot_count".into(), self.snapshots.len().to_string());
        for (i, s) in self.snapshots.iter().enumerate() {
            meta.insert(format!("snapshot_{i}_name"), s.name.clone());
            meta.insert(format!("snapshot_{i}_xid"), s.snap_xid.to_string());
            meta.insert(format!("snapshot_{i}_view"), "mountable".into());
            if let Some(t) = s.create_time {
                meta.insert(format!("snapshot_{i}_create_time"), t.to_string());
            }
        }
        FsInfo {
            fs_type: "APFS".into(),
            label: if apsb.name.is_empty() {
                None
            } else {
                Some(apsb.name.clone())
            },
            uuid: Some(apsb.uuid.clone()),
            block_size: self.nx.block_size as u64,
            total_blocks: self.block_count,
            free_blocks: self
                .spaceman
                .map(|s| s.dev_free_count)
                .or_else(|| {
                    Some(
                        self.free_ranges()
                            .iter()
                            .map(|(_, l)| l / self.nx.block_size as u64)
                            .sum(),
                    )
                }),
            total_nodes: Some(self.view.recs.inodes.len() as u64),
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
        // Encrypted extents yield their raw ciphertext — flagged in meta —
        // never decrypted. Files with no readable extents read as empty.
        Ok(Box::new(ExtentReader {
            src: self.src.clone(),
            ranges: entry.allocated_ranges.clone(),
            idx: 0,
            off_in: 0,
            remaining: entry.size,
        }))
    }

    /// Free-space estimate: complement of every block reachable from the
    /// live object graph. Includes superseded-checkpoint objects (the
    /// carving ground for deleted data).
    fn unallocated_ranges(&self) -> Vec<(u64, u64)> {
        self.free_ranges()
    }
}

/// Sequential reader over byte extents, capped at `remaining` logical bytes.
pub(crate) struct ExtentReader {
    src: Arc<dyn ByteSource>,
    ranges: Vec<(u64, u64)>,
    idx: usize,
    off_in: u64,
    remaining: u64,
}

impl Read for ExtentReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.remaining > 0 && self.idx < self.ranges.len() {
            let (off, len) = self.ranges[self.idx];
            let avail = len - self.off_in;
            if avail == 0 {
                self.idx += 1;
                self.off_in = 0;
                continue;
            }
            let want = buf.len().min(avail.min(self.remaining) as usize);
            let n = self.src.read_at(off + self.off_in, &mut buf[..want])?;
            self.off_in += n as u64;
            self.remaining -= n as u64;
            if n == 0 {
                break;
            }
            return Ok(n);
        }
        Ok(0)
    }
}
