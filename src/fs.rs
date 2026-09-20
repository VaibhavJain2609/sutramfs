//! [`HfsFs`] — the mounted filesystem: B-tree plumbing over the special
//! files, mount-time live-metadata index, recovery analysis and the
//! `FileSystem` implementation.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;

use sutram_fs::{
    DetectConfidence, EntryKind, FileSystem, FsEntry, FsError, FsInfo, FsParser, MountOptions,
    RecoveryState, Result,
};
use sutram_io::le;
use sutram_io::ByteSource;

use crate::attrs::{self, AttrData};
use crate::btree::{self, Btree, Node};
use crate::catalog::{self, CatRecord, RecRef};
use crate::extents::{self, ExtKey};
use crate::vh::{self, Extent, ForkData, JournalInfo, VolumeHeader};
use crate::walk::Walk;

/// The parser entry point — stateless, cheap to construct.
///
/// ```
/// use sutram_hfs::HfsParser;
/// use sutram_fs::FsParser;
/// let p = HfsParser;
/// assert_eq!(p.name(), "hfs");
/// ```
pub struct HfsParser;

impl FsParser for HfsParser {
    fn name(&self) -> &'static str {
        "hfs"
    }

    fn detect(&self, src: &dyn ByteSource) -> DetectConfidence {
        VolumeHeader::detect(src)
    }

    fn mount_with(
        &self,
        src: Arc<dyn ByteSource>,
        opts: &MountOptions,
    ) -> Result<Box<dyn FileSystem>> {
        Ok(Box::new(HfsFs::mount(src, opts.clone())?))
    }
}

/// One extended attribute, located for `read_file`/meta.
#[derive(Debug, Clone)]
pub(crate) struct Xattr {
    /// Attribute name (e.g. `com.apple.decmpfs`).
    pub name: String,
    /// Absolute disk offset of the attribute record (provenance).
    pub disk_off: u64,
    /// Byte ranges holding the attribute *value*.
    pub ranges: Vec<(u64, u64)>,
    /// Value byte length.
    pub size: u64,
    /// Where the value lives (`"inline"` / `"fork"` / `"extents"`).
    pub storage: &'static str,
    /// Key's `startBlock` — non-zero marks a continuation record.
    pub start_block: u32,
}

/// An extents-overflow record that references a CNID with no catalog
/// record — orphaned extents, carved under `/$ORPHANED/`.
#[derive(Debug)]
pub(crate) struct OrphanExtent {
    pub cnid: u32,
    pub fork: u8,
    pub start_block: u32,
    pub extents: Vec<Extent>,
    /// Disk offset of the extents record (provenance).
    pub disk_off: u64,
}

/// A mounted HFS+/HFSX volume.
pub struct HfsFs {
    pub(crate) src: Arc<dyn ByteSource>,
    pub(crate) vh: VolumeHeader,
    pub(crate) opts: MountOptions,
    /// The three metadata B-trees (attributes tree may be absent).
    pub(crate) cat: Btree,
    pub(crate) ext: Option<Btree>,
    pub(crate) attr: Option<Btree>,

    /// Mount-time index over *live* catalog leaf records (bounded by the
    /// number of catalog records — live metadata, not raw bytes).
    pub(crate) recs: Vec<RecRef>,
    /// `parentID` → indices into `recs` (file+folder records only).
    pub(crate) children: HashMap<u32, Vec<usize>>,
    /// Folder CNID → `(parentID, name)` for path resolution.
    pub(crate) folders: HashMap<u32, (u32, String)>,
    /// Fallback path resolution from *thread* records: the CNID a thread
    /// describes → `(its parent, its name)`.
    pub(crate) threads: HashMap<u32, (u32, String)>,
    /// File CNID → index into `recs` (hardlink-inode + xattr resolution).
    pub(crate) file_recs: HashMap<u32, usize>,
    /// `(parentID, name)` of every live leaf record — residue dedup.
    pub(crate) live_keys: HashSet<(u32, String)>,
    /// Node indices of the live leaf chain (skipped by dead-node scan).
    pub(crate) leaf_nodes: Vec<u32>,
    /// Allocation blocks owned by live files/metadata → owner path.
    /// Drives overwritten detection for deleted residue.
    pub(crate) live_blocks: HashMap<u32, String>,
    /// `(cnid, fork)` → `(start_block, extents)` overflow records.
    pub(crate) overflow: HashMap<(u32, u8), Vec<(u32, Vec<Extent>)>>,
    /// Extents records whose CNID is not in the live catalog.
    pub(crate) orphan_extents: Vec<OrphanExtent>,
    /// CNID → extended attributes found in the attributes file.
    pub(crate) xattrs: HashMap<u32, Vec<Xattr>>,
    /// Raw allocation-file bitmap (one bit per block, MSB first).
    pub(crate) alloc_bitmap: Option<Vec<u8>>,
    /// Journal info block (awareness only — no replay).
    pub(crate) journal: Option<JournalInfo>,
    /// Volume label = root thread's name, when found.
    pub(crate) label: Option<String>,
    /// Path memoisation for `path_of` (Mutex — `FileSystem` is `Sync`).
    pub(crate) path_cache: std::sync::Mutex<HashMap<u32, Option<String>>>,
    /// Non-fatal mount-time problems as `(offset, msg)` — replayed as
    /// `Err` items at the head of `walk()`. (FsError isn't Clone, so we
    /// store the parts.)
    pub(crate) mount_notes: Vec<(u64, String)>,
}

impl HfsFs {
    pub(crate) fn mount(src: Arc<dyn ByteSource>, opts: MountOptions) -> Result<Self> {
        let vh = VolumeHeader::parse(src.as_ref())?;
        let mut fs = HfsFs {
            src,
            vh,
            opts,
            cat: Btree {
                hdr: btree::BtreeHeader {
                    depth: 0,
                    root: 0,
                    leaf_count: 0,
                    first_leaf: 0,
                    last_leaf: 0,
                    node_size: 512,
                    max_key_len: 0,
                    total_nodes: 0,
                    free_nodes: 0,
                    clump_size: 0,
                    btree_type: 0,
                    key_type: 0,
                    attributes: 0,
                },
                ranges: Vec::new(),
                first_off: 0,
            },
            ext: None,
            attr: None,
            recs: Vec::new(),
            children: HashMap::new(),
            folders: HashMap::new(),
            threads: HashMap::new(),
            file_recs: HashMap::new(),
            live_keys: HashSet::new(),
            leaf_nodes: Vec::new(),
            live_blocks: HashMap::new(),
            overflow: HashMap::new(),
            orphan_extents: Vec::new(),
            xattrs: HashMap::new(),
            alloc_bitmap: None,
            journal: None,
            label: None,
            path_cache: std::sync::Mutex::new(HashMap::new()),
            mount_notes: Vec::new(),
        };
        fs.build_trees()?;
        fs.journal = vh::read_journal_info(fs.src.as_ref(), &fs.vh);
        fs.index_catalog();
        fs.index_extents_orphans();
        fs.index_attrs();
        fs.claim_metadata_blocks();
        fs.claim_live_blocks();
        fs.read_bitmap();
        Ok(fs)
    }

    /// Record a non-fatal mount problem as `(offset, msg)` parts.
    fn note(&mut self, e: FsError) {
        let (off, msg) = match &e {
            FsError::Corrupt { offset, msg } => (*offset, msg.clone()),
            FsError::Truncated { offset, .. } => (*offset, e.to_string()),
            _ => (0, e.to_string()),
        };
        self.mount_notes.push((off, msg));
    }

    /// Open the three metadata B-trees (extents first — the catalog's own
    /// overflow extents live there).
    fn build_trees(&mut self) -> Result<()> {
        // Extents file: inline extents only (it cannot overflow itself).
        let ext_ranges = self.fork_byte_ranges(&self.vh.ext_fork.clone(), &[]);
        if !ext_ranges.is_empty() {
            match Btree::open(
                self.src.as_ref(),
                ext_ranges,
                self.vh.block_off(self.vh.ext_fork.extents[0].start),
            ) {
                Ok(t) => {
                    self.ext = Some(t);
                    self.scan_overflow();
                }
                Err(e) => self.note(e),
            }
        }
        // Catalog file: inline + overflow extents keyed (4, data).
        let cat_ranges = self.fork_ranges_for(catalog::CNID_CATALOG, extents::FORK_DATA);
        self.cat = Btree::open(
            self.src.as_ref(),
            cat_ranges,
            self.vh.block_off(self.vh.cat_fork.extents[0].start),
        )?;
        // Attributes file (optional on real volumes).
        if self.vh.attr_fork.logical_size > 0 {
            let ranges = self.fork_ranges_for(catalog::CNID_ATTRS, extents::FORK_DATA);
            match Btree::open(
                self.src.as_ref(),
                ranges,
                self.vh.block_off(self.vh.attr_fork.extents[0].start),
            ) {
                Ok(t) => self.attr = Some(t),
                Err(e) => self.note(e),
            }
        }
        Ok(())
    }

    /// Byte ranges of a fork given only its inline extents, clipped to the
    /// fork's logical size.
    pub(crate) fn fork_byte_ranges(&self, fork: &ForkData, extra: &[Extent]) -> Vec<(u64, u64)> {
        let mut extents = VolumeHeader::extents_of(fork);
        extents.extend_from_slice(extra);
        self.extents_to_ranges(&extents, fork.logical_size)
    }

    /// Expand `(block, count)` extents into absolute `(offset, len)` byte
    /// ranges, clipped to `logical` bytes total.
    pub(crate) fn extents_to_ranges(&self, extents: &[Extent], logical: u64) -> Vec<(u64, u64)> {
        let bs = self.vh.block_size as u64;
        let mut out = Vec::with_capacity(extents.len());
        let mut acc = 0u64;
        for e in extents {
            if e.count == 0 {
                continue;
            }
            let bytes = e.count as u64 * bs;
            let want = bytes.min(logical.saturating_sub(acc));
            if want == 0 {
                break;
            }
            out.push((self.vh.block_off(e.start), want));
            acc += bytes;
        }
        out
    }

    /// All extents of a fork: the record's inline 8 plus overflow records
    /// keyed `(cnid, fork_type)`, sorted by their logical start block.
    pub(crate) fn fork_extents(&self, fork: &ForkData, cnid: u32, fork_type: u8) -> Vec<Extent> {
        let mut out = VolumeHeader::extents_of(fork);
        if let Some(ovs) = self.overflow.get(&(cnid, fork_type)) {
            let mut ovs: Vec<&(u32, Vec<Extent>)> = ovs.iter().collect();
            ovs.sort_by_key(|(sb, _)| *sb);
            for (_, exts) in ovs {
                out.extend(exts.iter().copied().filter(|e| e.count != 0));
            }
        }
        out
    }

    /// Byte ranges for CNID `cnid`'s `fork_type` — used for the special
    /// files whose [`ForkData`] comes from the volume header.
    fn fork_ranges_for(&self, cnid: u32, fork_type: u8) -> Vec<(u64, u64)> {
        let fork = match cnid {
            catalog::CNID_CATALOG => &self.vh.cat_fork,
            catalog::CNID_EXTENTS => &self.vh.ext_fork,
            catalog::CNID_ATTRS => &self.vh.attr_fork,
            catalog::CNID_ALLOC => &self.vh.alloc_fork,
            catalog::CNID_STARTUP => &self.vh.start_fork,
            _ => return Vec::new(),
        };
        let extents = self.fork_extents(fork, cnid, fork_type);
        self.extents_to_ranges(&extents, fork.logical_size)
    }

    /// Scan the extents-overflow B-tree: fill `overflow` and collect
    /// records pointing at CNIDs with no live catalog record.
    fn scan_overflow(&mut self) {
        let ext = match &self.ext {
            Some(e) => e,
            None => return,
        };
        let mut recs: Vec<(ExtKey, Vec<Extent>, u64)> = Vec::new();
        let res = ext.for_each_leaf(self.src.as_ref(), |n, node| {
            let base = ext.node_offset(n).unwrap_or(0);
            for i in 0..node.num_recs as usize {
                let Some(rec) = node.record(i) else { continue };
                let Some((key, klen)) = extents::parse_key(rec) else {
                    continue;
                };
                let Some(data) = rec.get(klen..) else {
                    continue;
                };
                let Some(exts) = extents::parse_record(data) else {
                    continue;
                };
                let live_exts: Vec<Extent> =
                    exts.iter().copied().filter(|e| e.count != 0).collect();
                recs.push((key, live_exts, base + node.offsets[i] as u64));
            }
            Ok(())
        });
        if let Err(e) = res {
            self.note(e);
        }
        for (key, exts, off) in recs {
            self.overflow
                .entry((key.cnid, key.fork))
                .or_default()
                .push((key.start_block, exts.clone()));
            self.orphan_extents.push(OrphanExtent {
                cnid: key.cnid,
                fork: key.fork,
                start_block: key.start_block,
                extents: exts,
                disk_off: off,
            });
        }
    }

    /// Scan the catalog leaf chain: build the live-record index.
    /// Lenient — unreadable nodes/records become `mount_notes`, not panics.
    fn index_catalog(&mut self) {
        let cat = &self.cat;
        let mut recs: Vec<RecRef> = Vec::new();
        let mut leaf_nodes = Vec::new();
        let mut thread_index: Vec<(u32, u32, String)> = Vec::new();
        let res = cat.for_each_leaf(self.src.as_ref(), |n, node| {
            leaf_nodes.push(n);
            let base = cat.node_offset(n).unwrap_or(0);
            for i in 0..node.num_recs as usize {
                let Some(rec) = node.record(i) else { continue };
                let Some(key) = catalog::parse_key(rec) else {
                    continue;
                };
                let Some(data) = rec.get(key.total_len..) else {
                    continue;
                };
                let Some(record) = catalog::parse_record(data) else {
                    continue;
                };
                let (rectype, cnid) = match &record {
                    CatRecord::Folder(f) => (catalog::REC_FOLDER, f.cnid),
                    CatRecord::File(f) => (catalog::REC_FILE, f.cnid),
                    CatRecord::Thread { parent, name } => {
                        // Thread for cnid X is keyed (X, "") and names X's
                        // parent + name — path resolution fallback.
                        thread_index.push((key.parent, *parent, name.clone()));
                        (le::u16_be(data, 0).unwrap_or(0) as i16, 0)
                    }
                    CatRecord::Other(t) => (*t, 0),
                };
                recs.push(RecRef {
                    node: n,
                    rec_off: node.offsets[i],
                    disk_off: base + node.offsets[i] as u64,
                    parent: key.parent,
                    name: catalog::clean_name(&key.name),
                    rectype,
                    cnid,
                });
            }
            Ok(())
        });
        if let Err(e) = res {
            self.note(e);
        }
        self.leaf_nodes = leaf_nodes;
        // Build maps.
        for (idx, r) in recs.iter().enumerate() {
            match r.rectype {
                catalog::REC_FOLDER => {
                    self.folders.insert(r.cnid, (r.parent, r.name.clone()));
                    self.children.entry(r.parent).or_default().push(idx);
                    self.live_keys.insert((r.parent, r.name.clone()));
                }
                catalog::REC_FILE => {
                    self.file_recs.insert(r.cnid, idx);
                    self.children.entry(r.parent).or_default().push(idx);
                    self.live_keys.insert((r.parent, r.name.clone()));
                }
                _ => {}
            }
        }
        for (cnid, parent, name) in thread_index {
            self.threads
                .insert(cnid, (parent, catalog::clean_name(&name)));
        }
        self.recs = recs;
        // Volume label = the root folder's thread-record name.
        if self.label.is_none() {
            self.label = self
                .threads
                .get(&catalog::CNID_ROOT)
                .map(|(_, n)| n.clone())
                .filter(|n| !n.is_empty());
        }
    }

    /// Keep only extents-overflow records whose CNID has no live catalog
    /// record — those are the orphaned extents.
    fn index_extents_orphans(&mut self) {
        let live = &self.file_recs;
        let folders = &self.folders;
        self.orphan_extents
            .retain(|o| !live.contains_key(&o.cnid) && !folders.contains_key(&o.cnid));
    }

    /// Re-read + parse the record body for a [`RecRef`].
    /// Returns `(record, raw_record_bytes)` so callers can slice further.
    pub(crate) fn read_record(&self, r: &RecRef) -> Result<(CatRecord, Vec<u8>)> {
        let buf = self.cat.read_node(self.src.as_ref(), r.node)?;
        let node = Node::parse(buf, r.node)?;
        let rec = node
            .record_at(r.rec_off as usize)
            .ok_or_else(|| FsError::corrupt(r.disk_off, "record offset gone"))?;
        let key = catalog::parse_key(rec)
            .ok_or_else(|| FsError::corrupt(r.disk_off, "record key unreadable"))?;
        let data = rec
            .get(key.total_len..)
            .ok_or_else(|| FsError::corrupt(r.disk_off, "record data missing"))?;
        let record = catalog::parse_record(data)
            .ok_or_else(|| FsError::corrupt(r.disk_off, "record body unreadable"))?;
        Ok((record, rec.to_vec()))
    }

    /// Claim the allocation blocks of the five special files.
    fn claim_metadata_blocks(&mut self) {
        let metas: [(&str, u32); 5] = [
            ("$Metadata/allocation", catalog::CNID_ALLOC),
            ("$Metadata/extents", catalog::CNID_EXTENTS),
            ("$Metadata/catalog", catalog::CNID_CATALOG),
            ("$Metadata/attributes", catalog::CNID_ATTRS),
            ("$Metadata/startup", catalog::CNID_STARTUP),
        ];
        for (name, cnid) in metas {
            let extents = self.fork_extents(
                match cnid {
                    catalog::CNID_ALLOC => &self.vh.alloc_fork,
                    catalog::CNID_EXTENTS => &self.vh.ext_fork,
                    catalog::CNID_ATTRS => &self.vh.attr_fork,
                    catalog::CNID_STARTUP => &self.vh.start_fork,
                    _ => &self.vh.cat_fork,
                },
                cnid,
                extents::FORK_DATA,
            );
            for e in extents {
                for b in e.start..e.start.saturating_add(e.count) {
                    self.live_blocks.insert(b, name.to_string());
                }
            }
        }
        // The volume header itself lives in block 0.
        self.live_blocks.insert(0, "$Metadata/volume-header".into());
        // Journal info block + buffer are live too.
        if let Some(j) = &self.journal {
            self.live_blocks
                .insert(j.jib_block, "$Metadata/journal-info".into());
        }
    }

    /// Claim every live file's data + resource fork blocks.
    fn claim_live_blocks(&mut self) {
        for idx in 0..self.recs.len() {
            let r = &self.recs[idx];
            if r.rectype != catalog::REC_FILE {
                continue;
            }
            let Ok((CatRecord::File(f), _)) = self.read_record(r) else {
                continue;
            };
            let path = self
                .path_of(r.parent)
                .map(|p| sutram_fs::util::join_path(&p, &r.name))
                .unwrap_or_else(|| format!("<parent {}>", r.parent));
            for ft in [extents::FORK_DATA, extents::FORK_RSRC] {
                let fork = if ft == extents::FORK_DATA {
                    &f.data_fork
                } else {
                    &f.rsrc_fork
                };
                for e in self.fork_extents(fork, f.cnid, ft) {
                    for b in e.start..e.start.saturating_add(e.count) {
                        self.live_blocks.entry(b).or_insert_with(|| path.clone());
                    }
                }
            }
        }
    }

    /// Path-cache get/put that degrade gracefully on a poisoned mutex
    /// (never panic on a forensic path).
    fn cache_get(&self, cnid: u32) -> Option<Option<String>> {
        let g = self.path_cache.lock().unwrap_or_else(|e| e.into_inner());
        g.get(&cnid).cloned()
    }

    fn cache_put(&self, cnid: u32, v: Option<String>) {
        let mut g = self.path_cache.lock().unwrap_or_else(|e| e.into_inner());
        g.insert(cnid, v);
    }

    /// Resolve the absolute path of folder `cnid` via the folder map,
    /// memoised; `None` when the chain doesn't reach the root.
    pub(crate) fn path_of(&self, cnid: u32) -> Option<String> {
        if cnid == catalog::CNID_ROOT {
            return Some("/".to_string());
        }
        if let Some(c) = self.cache_get(cnid) {
            return c;
        }
        // Walk up iteratively with a cycle guard.
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        let mut cur = cnid;
        loop {
            if !seen.insert(cur) || chain.len() > 256 {
                self.cache_put(cnid, None);
                return None;
            }
            if cur == catalog::CNID_ROOT {
                break;
            }
            let parent_name = self
                .folders
                .get(&cur)
                .or_else(|| self.threads.get(&cur))
                .cloned();
            let Some((parent, name)) = parent_name else {
                self.cache_put(cnid, None);
                return None;
            };
            chain.push(name);
            cur = parent;
        }
        let mut p = String::new();
        for name in chain.iter().rev() {
            p.push('/');
            p.push_str(name);
        }
        let p = if p.is_empty() { "/".to_string() } else { p };
        self.cache_put(cnid, Some(p.clone()));
        Some(p)
    }

    /// Scan the attributes-file leaf chain into `xattrs`.
    fn index_attrs(&mut self) {
        let Some(attr) = &self.attr else { return };
        let mut found: Vec<(u32, Xattr)> = Vec::new();
        let res = attr.for_each_leaf(self.src.as_ref(), |n, node| {
            let base = attr.node_offset(n).unwrap_or(0);
            for i in 0..node.num_recs as usize {
                let Some(rec) = node.record(i) else { continue };
                let Some(key) = attrs::parse_key(rec) else {
                    continue;
                };
                let Some(data) = rec.get(key.total_len..) else {
                    continue;
                };
                let Some(a) = attrs::parse_record(data) else {
                    continue;
                };
                let rec_disk = base + node.offsets[i] as u64;
                let data_disk = rec_disk + key.total_len as u64;
                let (ranges, size, storage) = match a {
                    AttrData::Inline { data_off, len } => (
                        vec![(data_disk + data_off as u64, len as u64)],
                        len as u64,
                        "inline",
                    ),
                    AttrData::ForkData(fork) => (
                        self.extents_to_ranges(&VolumeHeader::extents_of(&fork), fork.logical_size),
                        fork.logical_size,
                        "fork",
                    ),
                    AttrData::Extents(e) => (
                        vec![(
                            self.vh.block_off(e.start),
                            e.count as u64 * self.vh.block_size as u64,
                        )],
                        e.count as u64 * self.vh.block_size as u64,
                        "extents",
                    ),
                    AttrData::Other(t) => (
                        Vec::new(),
                        0,
                        match t {
                            _ => "unknown",
                        },
                    ),
                };
                found.push((
                    key.cnid,
                    Xattr {
                        name: key.name,
                        disk_off: rec_disk,
                        ranges,
                        size,
                        storage,
                        start_block: key.start_block,
                    },
                ));
            }
            Ok(())
        });
        if let Err(e) = res {
            self.note(e);
        }
        for (cnid, x) in found {
            self.xattrs.entry(cnid).or_default().push(x);
        }
    }

    /// Read an xattr's value bytes (bounded: ≤ 16 MiB).
    pub(crate) fn read_xattr(&self, x: &Xattr) -> Result<Vec<u8>> {
        let total: u64 = x.ranges.iter().map(|(_, l)| *l).sum();
        let mut out = Vec::with_capacity(total.min(16 << 20) as usize);
        for &(off, len) in &x.ranges {
            let chunk = self
                .src
                .read_slice(off, len.min(16 << 20) as usize)
                .map_err(FsError::Io)?;
            out.extend_from_slice(&chunk);
            if out.len() as u64 >= x.size.min(16 << 20) {
                break;
            }
        }
        out.truncate(x.size.min(16 << 20) as usize);
        Ok(out)
    }

    /// Read the allocation-file bitmap (bounded by total_blocks/8 + slack).
    fn read_bitmap(&mut self) {
        let ranges = self.fork_byte_ranges(&self.vh.alloc_fork.clone(), &[]);
        let need = (self.vh.total_blocks as u64).div_ceil(8).min(64 << 20);
        let mut bits = Vec::with_capacity(need as usize);
        let mut got = 0u64;
        for &(off, len) in &ranges {
            if got >= need {
                break;
            }
            let want = len.min(need - got) as usize;
            match self.src.read_slice(off, want) {
                Ok(b) => {
                    got += b.len() as u64;
                    bits.extend_from_slice(&b);
                }
                Err(e) => {
                    self.note(FsError::Io(e));
                    return;
                }
            }
        }
        self.alloc_bitmap = Some(bits);
    }

    /// Is allocation block `b` marked allocated in the bitmap?
    /// `None` when no bitmap was read (then live_blocks is the only truth).
    pub(crate) fn block_allocated(&self, b: u32) -> Option<bool> {
        let bits = self.alloc_bitmap.as_ref()?;
        let byte = (b / 8) as usize;
        let byte = *bits.get(byte)?;
        Some(byte & (0x80 >> (b % 8)) != 0)
    }

    /// Recovery assessment for a deleted record's extents: compare its
    /// expected blocks against `live_blocks` (blocks live files own now).
    /// Returns `(state, surviving_byte_ranges, notes)`.
    pub(crate) fn recovery_for(
        &self,
        extents: &[Extent],
        size: u64,
    ) -> (RecoveryState, Vec<(u64, u64)>, Vec<String>) {
        let bs = self.vh.block_size as u64;
        let mut notes = Vec::new();
        if size == 0 || extents.is_empty() {
            if size == 0 {
                return (RecoveryState::Intact, Vec::new(), notes);
            }
            notes.push("record carries no extents".into());
            return (RecoveryState::Unrecoverable, Vec::new(), notes);
        }
        let expected_blocks = size.div_ceil(bs).max(1);
        let mut have_blocks = 0u64;
        let mut surviving_runs: Vec<(u32, u32)> = Vec::new();
        let mut lost = 0u64;
        let mut lost_to: Vec<String> = Vec::new();
        for e in extents {
            for b in e.start..e.start.saturating_add(e.count) {
                have_blocks += 1;
                if have_blocks > expected_blocks {
                    break;
                }
                match self.live_blocks.get(&b) {
                    Some(owner) => {
                        lost += 1;
                        if lost_to.len() < 4 {
                            lost_to.push(format!("block {b}→{owner}"));
                        }
                    }
                    None => {
                        // Bitmap cross-check: a "surviving" block still
                        // marked allocated means the bitmap disagrees with
                        // the live map — flag it rather than hide it.
                        if self.block_allocated(b) == Some(true) {
                            notes.push(format!(
                                "block {b} unclaimed by live files but marked allocated in bitmap"
                            ));
                        }
                        match surviving_runs.last_mut() {
                            Some(run) if b == run.0 + run.1 => run.1 += 1,
                            _ => surviving_runs.push((b, 1)),
                        }
                    }
                }
            }
        }
        if !lost_to.is_empty() {
            notes.push(format!(
                "{} allocation block(s) reallocated: {}",
                lost,
                lost_to.join(", ")
            ));
        }
        if have_blocks < expected_blocks {
            notes.push(format!(
                "extent list covers {have_blocks} of {expected_blocks} expected blocks"
            ));
        }
        let surviving_ranges: Vec<(u64, u64)> = surviving_runs
            .iter()
            .map(|&(s, c)| (self.vh.block_off(s), c as u64 * bs))
            .collect();
        let recovered_bytes = surviving_ranges
            .iter()
            .map(|(_, l)| *l)
            .sum::<u64>()
            .min(size);
        let state = if lost == 0 && have_blocks >= expected_blocks {
            RecoveryState::Intact
        } else if recovered_bytes == 0 {
            RecoveryState::Unrecoverable
        } else {
            RecoveryState::PartiallyOverwritten {
                recovered_bytes,
                total_bytes: size,
            }
        };
        (state, surviving_ranges, notes)
    }

    /// Per-file magic verdict via a bounded header read (≤ 4 KiB).
    pub(crate) fn magic_for(&self, e: &FsEntry) -> Option<sutram_magic::MagicVerdict> {
        if !self.opts.check_magic || e.kind != EntryKind::File || e.size == 0 {
            return None;
        }
        if e.allocated_ranges.is_empty() && !e.meta.contains_key("decmpfs_type") {
            return None;
        }
        let mut r = self.read_file(e).ok()?;
        let mut header = vec![0u8; 4096usize.min(e.size as usize).max(64)];
        let n = r.read(&mut header).ok()?;
        header.truncate(n);
        if header.is_empty() {
            return None;
        }
        Some(sutram_magic::check_entry(&e.name, &header))
    }
}

/// Render a big-endian u32 FourCC as ASCII (hex if unprintable).
fn fourcc(v: u32) -> String {
    let b = v.to_be_bytes();
    if b.iter().all(|c| c.is_ascii_graphic() || *c == b' ') {
        String::from_utf8_lossy(&b).trim_end().to_string()
    } else {
        format!("{v:#010x}")
    }
}

impl FileSystem for HfsFs {
    fn info(&self) -> FsInfo {
        let mut meta = HashMap::new();
        let vh = &self.vh;
        meta.insert(
            "signature".into(),
            match vh.signature {
                vh::SIG_HFSPLUS => "H+".into(),
                vh::SIG_HFSX => "HX".into(),
                s => format!("{s:#06x}"),
            },
        );
        meta.insert("version".into(), vh.version.to_string());
        meta.insert("attributes".into(), format!("{:#010x}", vh.attributes));
        meta.insert(
            "journaled".into(),
            (vh.attributes & vh::VOL_JOURNALED != 0).to_string(),
        );
        meta.insert(
            "software_lock".into(),
            (vh.attributes & vh::VOL_SOFTLOCK != 0).to_string(),
        );
        meta.insert(
            "unmounted_clean".into(),
            (vh.attributes & vh::VOL_UNMOUNTED != 0).to_string(),
        );
        meta.insert("next_cnid".into(), vh.next_cnid.to_string());
        meta.insert("write_count".into(), vh.write_count.to_string());
        meta.insert("file_count".into(), vh.file_count.to_string());
        meta.insert("folder_count".into(), vh.folder_count.to_string());
        meta.insert("wrapped".into(), vh.wrapped.to_string());
        if let Some(l) = &vh.wrapper_label {
            meta.insert("wrapper_label".into(), l.clone());
        }
        {
            let cat = &self.cat;
            meta.insert(
                "catalog_key_compare".into(),
                match cat.hdr.key_type {
                    0xCF => "case-folding".into(),
                    0xBC => "binary".into(),
                    k => format!("{k:#04x}"),
                },
            );
            meta.insert("catalog_depth".into(), cat.hdr.depth.to_string());
            meta.insert("catalog_nodes".into(), cat.hdr.total_nodes.to_string());
            meta.insert(
                "catalog_leaf_records".into(),
                cat.hdr.leaf_count.to_string(),
            );
            meta.insert("catalog_free_nodes".into(), cat.hdr.free_nodes.to_string());
            meta.insert(
                "catalog_max_key_len".into(),
                cat.hdr.max_key_len.to_string(),
            );
            meta.insert(
                "catalog_btree_type".into(),
                format!("{:#04x}", cat.hdr.btree_type),
            );
            meta.insert("catalog_root_node".into(), cat.hdr.root.to_string());
            meta.insert("catalog_last_leaf".into(), cat.hdr.last_leaf.to_string());
            meta.insert("catalog_clump_size".into(), cat.hdr.clump_size.to_string());
            meta.insert(
                "catalog_tree_attributes".into(),
                format!("{:#010x}", cat.hdr.attributes),
            );
        }
        meta.insert("last_mounted".into(), fourcc(vh.last_mounted));
        meta.insert("create_date".into(), format!("{:#010x}", vh.create_date));
        meta.insert("modify_date".into(), format!("{:#010x}", vh.modify_date));
        meta.insert("backup_date".into(), format!("{:#010x}", vh.backup_date));
        meta.insert("checked_date".into(), format!("{:#010x}", vh.checked_date));
        meta.insert("next_alloc".into(), vh.next_alloc.to_string());
        meta.insert("data_clump_size".into(), vh.data_clump.to_string());
        meta.insert("rsrc_clump_size".into(), vh.rsrc_clump.to_string());
        if vh.encodings != 0 {
            meta.insert("encodings_bitmap".into(), format!("{:#018x}", vh.encodings));
        }
        if vh.finder_info.iter().any(|&x| x != 0) {
            meta.insert(
                "finder_info".into(),
                vh.finder_info
                    .iter()
                    .map(|x| format!("{x:08x}"))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
        if let Some(j) = &self.journal {
            meta.insert("journal_info_block".into(), j.jib_block.to_string());
            meta.insert("journal_flags".into(), format!("{:#010x}", j.flags));
            meta.insert("journal_offset".into(), format!("{:#x}", j.buffer_offset));
            meta.insert("journal_size".into(), format!("{:#x}", j.buffer_size));
            if let Some(m) = j.journal_magic {
                meta.insert("journal_magic".into(), format!("{m:#010x}"));
            }
            meta.insert(
                "journal_replay".into(),
                "TODO: journal contents parsed but transactions not replayed".into(),
            );
        }
        FsInfo {
            fs_type: if vh.signature == vh::SIG_HFSX {
                "HFSX".into()
            } else {
                "HFS+".into()
            },
            label: self.label.clone(),
            uuid: None,
            block_size: vh.block_size as u64,
            total_blocks: vh.total_blocks as u64,
            free_blocks: Some(vh.free_blocks as u64),
            total_nodes: Some(self.recs.len() as u64),
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
        // Compressed (decmpfs) entries: ranges hold the stored bytes;
        // decompress when the codec is implemented.
        if let Some(t) = entry.meta.get("decmpfs_type") {
            let compression_type: u32 = t.parse().unwrap_or(0);
            let usize_hint: u64 = entry
                .meta
                .get("decmpfs_uncompressed_size")
                .and_then(|s| s.parse().ok())
                .unwrap_or(entry.size);
            let mut blob = Vec::new();
            let cap = usize_hint.saturating_mul(4).max(1 << 20).min(512 << 20);
            let mut rdr = ExtentReader {
                src: self.src.clone(),
                ranges: entry.allocated_ranges.clone(),
                idx: 0,
                off_in: 0,
                remaining: cap,
            };
            let mut tmp = [0u8; 65536];
            loop {
                let n = rdr.read(&mut tmp)?;
                if n == 0 {
                    break;
                }
                blob.extend_from_slice(&tmp[..n]);
                if blob.len() as u64 >= cap {
                    break;
                }
            }
            // Inline types carry the 16-byte decmpfs header at the front of
            // the stored bytes; resource-fork types need only the size hint.
            let is_inline = !matches!(compression_type, 4 | 8 | 10 | 12);
            let (hdr, rsrc) = if is_inline {
                (attrs::parse_decmpfs(&blob)?, None)
            } else {
                (
                    attrs::DecmpfsHeader {
                        compression_type,
                        uncompressed_size: usize_hint,
                        inline: Vec::new(),
                    },
                    Some(&blob[..]),
                )
            };
            let out = attrs::decompress(&hdr, rsrc)?;
            return Ok(Box::new(std::io::Cursor::new(out)));
        }
        Ok(Box::new(ExtentReader {
            src: self.src.clone(),
            ranges: entry.allocated_ranges.clone(),
            idx: 0,
            off_in: 0,
            remaining: entry.size,
        }))
    }

    /// Free allocation blocks as byte ranges — the carving ground.
    /// Only meaningful when the allocation file was readable.
    fn unallocated_ranges(&self) -> Vec<(u64, u64)> {
        let Some(bits) = &self.alloc_bitmap else {
            return Vec::new();
        };
        let bs = self.vh.block_size as u64;
        let mut out = Vec::new();
        let mut run_start: Option<u32> = None;
        for b in 0..self.vh.total_blocks {
            let byte = bits.get((b / 8) as usize).copied().unwrap_or(0);
            let free = byte & (0x80 >> (b % 8)) == 0;
            match (free, run_start) {
                (true, None) => run_start = Some(b),
                (false, Some(s)) => {
                    out.push((self.vh.block_off(s), (b - s) as u64 * bs));
                    run_start = None;
                }
                _ => {}
            }
        }
        if let Some(s) = run_start {
            out.push((self.vh.block_off(s), (self.vh.total_blocks - s) as u64 * bs));
        }
        out
    }
}

/// Sequential reader over byte extents, capped at `remaining` logical
/// bytes — same pattern as `sutram-fat`.
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
