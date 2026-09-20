//! [`F2fsFs`] — the mounted filesystem: geometry, table access, node-block
//! fetching, extent enumeration, recovery analysis and the `FileSystem`
//! impl.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;

use sutram_fs::util;
use sutram_fs::{
    DetectConfidence, EntryKind, FileSystem, FsEntry, FsEntryStatus, FsError, FsInfo, FsParser,
    FsTimestamp, MountOptions, RecoveryState, Result, Timestamps,
};
use sutram_io::ByteSource;

use sutram_io::le;

use crate::checkpoint::{self, Checkpoint};
use crate::node::{
    self, inline_flag, inode_flag, Inode, NodeFooter, NodeView, COMPRESS_ADDR, NEW_ADDR, NULL_ADDR,
};
use crate::sb::{feature, SuperBlock};
use crate::tables::{SitEntry, Tables};

/// The parser entry point — stateless, cheap to construct.
///
/// ```
/// use sutram_f2fs::F2fsParser;
/// use sutram_fs::FsParser;
/// let p = F2fsParser;
/// assert_eq!(p.name(), "f2fs");
/// ```
pub struct F2fsParser;

impl FsParser for F2fsParser {
    fn name(&self) -> &'static str {
        "f2fs"
    }

    fn detect(&self, src: &dyn ByteSource) -> DetectConfidence {
        SuperBlock::detect(src)
    }

    fn mount_with(
        &self,
        src: Arc<dyn ByteSource>,
        opts: &MountOptions,
    ) -> Result<Box<dyn FileSystem>> {
        Ok(Box::new(F2fsFs::mount(src, opts.clone())?))
    }
}

/// Maximum node blocks fetched while enumerating one file's extent tree
/// (loop/blast guard for corrupt `i_nid` chains).
const MAX_NODE_FETCH: usize = 16_384;

/// A mounted F2FS volume.
pub struct F2fsFs {
    src: Arc<dyn ByteSource>,
    pub(crate) sb: SuperBlock,
    pub(crate) ckpt: Checkpoint,
    pub(crate) opts: MountOptions,
    /// Per-segment SIT entries for the whole main area (index = main-
    /// relative segno). `None` where the SIT block was unreadable —
    /// proportional to live metadata, loaded once at mount.
    sit: Vec<Option<SitEntry>>,
}

impl F2fsFs {
    pub(crate) fn mount(src: Arc<dyn ByteSource>, opts: MountOptions) -> Result<Self> {
        let sb = SuperBlock::parse(src.as_ref())?;
        let ckpt = checkpoint::read_checkpoint(src.as_ref(), &sb)?;
        let mut fs = F2fsFs {
            src,
            sb,
            ckpt,
            opts,
            sit: Vec::new(),
        };
        fs.load_sit()?;
        Ok(fs)
    }

    /// Convenience accessor over SIT/NAT/SSA.
    pub(crate) fn tables(&self) -> Tables<'_> {
        Tables {
            src: self.src.as_ref(),
            sb: &self.sb,
            sit_bitmap: &self.ckpt.sit_bitmap,
            nat_bitmap: &self.ckpt.nat_bitmap,
        }
    }

    /// Load all main-area SIT entries (streaming, one block at a time).
    fn load_sit(&mut self) -> Result<()> {
        let per_block = self.sb.block_size / 74;
        let t = self.tables();
        let mut entries = Vec::with_capacity(self.sb.segment_count_main as usize);
        let mut first_err = None;
        let n_blocks = self.sb.sit_block_count();
        for boff in 0..n_blocks {
            let blk = t.sit_blk(boff);
            let b = self
                .src
                .read_slice(self.sb.blk_off(blk), self.sb.block_size as usize);
            match b {
                Ok(b) if b.len() as u64 >= self.sb.block_size => {
                    let base = boff * per_block;
                    for i in 0..per_block {
                        if base + i >= self.sb.segment_count_main as u64 {
                            break;
                        }
                        let o = i as usize * 74;
                        let mut valid_map = [0u8; 64];
                        valid_map.copy_from_slice(&b[o + 2..o + 66]);
                        entries.push(Some(SitEntry {
                            vblocks: le::u16(&b, o).unwrap_or(0),
                            valid_map,
                            mtime: le::u64(&b, o + 66).unwrap_or(0),
                        }));
                    }
                }
                Ok(b) => {
                    let e = FsError::truncated(
                        self.sb.blk_off(blk),
                        self.sb.block_size,
                        b.len() as u64,
                    );
                    if self.opts.strict {
                        return Err(e);
                    }
                    first_err.get_or_insert(e);
                    for _ in 0..per_block.min(self.sb.segment_count_main as u64 - boff * per_block)
                    {
                        entries.push(None);
                    }
                }
                Err(e) => {
                    let e = FsError::Io(e);
                    if self.opts.strict {
                        return Err(e);
                    }
                    first_err.get_or_insert(e);
                    for _ in 0..per_block.min(self.sb.segment_count_main as u64 - boff * per_block)
                    {
                        entries.push(None);
                    }
                }
            }
        }
        while entries.len() < self.sb.segment_count_main as usize {
            entries.push(None);
        }
        if let Some(e) = first_err {
            self.ckpt
                .notes
                .push(format!("SIT partially unreadable: {e}"));
        }
        self.sit = entries;
        Ok(())
    }

    /// Is main-area block `blk` live per the loaded SIT?
    /// `None` = outside main area / SIT unreadable.
    pub(crate) fn block_is_live(&self, blk: u64) -> Option<bool> {
        let seg = self.sb.main_segno(blk)?;
        let e = self.sit.get(seg as usize)?.as_ref()?;
        let off = blk - self.sb.main_seg_blk(seg);
        if off >= self.sb.blks_per_seg {
            return None;
        }
        Some(crate::tables::bit_le(&e.valid_map[..], off))
    }

    /// SIT entry for a main-relative segno (from the loaded copy).
    pub(crate) fn sit_entry(&self, segno: u64) -> Option<&SitEntry> {
        self.sit.get(segno as usize)?.as_ref()
    }

    /// Read one filesystem block.
    pub(crate) fn read_block(&self, blk: u64) -> Result<Vec<u8>> {
        let off = self.sb.blk_off(blk);
        let b = self
            .src
            .read_slice(off, self.sb.block_size as usize)
            .map_err(FsError::Io)?;
        if (b.len() as u64) < self.sb.block_size {
            return Err(FsError::truncated(off, self.sb.block_size, b.len() as u64));
        }
        Ok(b)
    }

    /// Resolve nid → node block via the current NAT.
    pub(crate) fn node_blk_for(&self, nid: u32) -> Result<Option<u32>> {
        Ok(self.tables().nat_entry(nid)?.map(|e| e.block_addr))
    }

    /// Read and decode the node block for `nid` (current NAT mapping).
    /// Verifies the footer nid/ino; lenient mode tolerates nothing here —
    /// a footer mismatch means the block is stale or corrupt.
    pub(crate) fn read_node(&self, nid: u32) -> Result<(u32, NodeFooter, NodeView)> {
        let blk = self.node_blk_for(nid)?.ok_or_else(|| FsError::NotFound {
            path: format!("nid {nid} not in NAT"),
        })?;
        if blk == 0 {
            return Err(FsError::NotFound {
                path: format!("nid {nid} NAT entry is free"),
            });
        }
        self.read_node_at(blk, Some(nid))
    }

    /// Read and decode the node block at absolute block `blk`,
    /// optionally asserting its footer nid.
    pub(crate) fn read_node_at(
        &self,
        blk: u32,
        expect_nid: Option<u32>,
    ) -> Result<(u32, NodeFooter, NodeView)> {
        if blk as u64
            >= self.sb.segment0_blkaddr + self.sb.segment_count as u64 * self.sb.blks_per_seg
        {
            return Err(FsError::corrupt(
                self.sb.blk_off(blk as u64),
                format!("node block {blk} outside segment space"),
            ));
        }
        let b = self.read_block(blk as u64)?;
        let (footer, view) = node::parse_node(&b, blk as u64, self.sb.block_size as usize)?;
        if let Some(want) = expect_nid {
            if footer.nid != want {
                return Err(FsError::corrupt(
                    self.sb.blk_off(blk as u64) + self.sb.block_size - 24,
                    format!("node footer nid {} != expected {want}", footer.nid),
                ));
            }
        }
        Ok((blk, footer, view))
    }

    /// DEF_ADDRS_PER_INODE for this block size.
    fn def_addrs(&self) -> usize {
        (self.sb.block_size as usize - Inode::I_ADDR_OFF - 20 - node::FOOTER_LEN) / 4
    }

    /// DEF_ADDRS_PER_BLOCK / NIDS_PER_BLOCK for this block size.
    fn ptrs_per_node(&self) -> usize {
        (self.sb.block_size as usize - node::FOOTER_LEN) / 4
    }

    /// Enumerate `(logical_index, block_addr)` data extents of an inode —
    /// direct `i_addr` pointers plus the direct/indirect/double-indirect
    /// node chain. `nid` is the inode's own node id (its inode number) and
    /// is used to sanity-check fetched node blocks. Bounded by
    /// `MAX_NODE_FETCH` node reads and a visited-nid set; corrupt subtrees
    /// yield notes instead of aborting.
    ///
    /// Returns `(extents, notes)`.
    pub(crate) fn extents(&self, nid: u32, inode: &Inode) -> (Vec<(u64, u32)>, Vec<String>) {
        let mut out: Vec<(u64, u32)> = Vec::new();
        let mut notes = Vec::new();
        let mut visited: HashSet<u32> = HashSet::new();
        let mut fetched = 0usize;
        let def_addrs = self.def_addrs();
        let per_node = self.ptrs_per_node();
        let direct_index = inode.addrs_count(def_addrs) as u64;

        // Level 0: direct pointers inside the inode.
        for k in 0..inode.addrs_count(def_addrs) {
            if let Some(blk) = inode.i_addr(k, def_addrs) {
                match blk {
                    NULL_ADDR | NEW_ADDR => {}
                    COMPRESS_ADDR => {
                        notes.push(format!("logical block {k} is compressed (COMPRESS_ADDR)"))
                    }
                    b => out.push((k as u64, b)),
                }
            }
        }

        if inode.inline_flags & inline_flag::INLINE_DATA != 0 {
            return (out, notes); // inline data replaces extents
        }

        // Node-chain walk. `pending` = (nid, base_logical, fan_in).
        // fan_in: 0 = direct node (u32 data addrs), 1 = indirect (nids→dnodes),
        // 2 = double-indirect (nids→inodes→dnodes).
        struct Pending {
            nid: u32,
            base: u64,
            depth: u8, // 0=dnode, 1=indirect, 2=double-indirect
        }
        let mut stack: Vec<Pending> = Vec::new();
        let push = |arr: &mut Vec<Pending>, nid: Option<u32>, base: u64, depth: u8| {
            if let Some(n) = nid {
                if n != 0 {
                    arr.push(Pending {
                        nid: n,
                        base,
                        depth,
                    });
                }
            }
        };
        let db = per_node as u64;
        push(&mut stack, inode.i_nid(0), direct_index, 0);
        push(&mut stack, inode.i_nid(1), direct_index + db, 0);
        push(&mut stack, inode.i_nid(2), direct_index + 2 * db, 1);
        push(
            &mut stack,
            inode.i_nid(3),
            direct_index + 2 * db + db * db,
            1,
        );
        push(
            &mut stack,
            inode.i_nid(4),
            direct_index + 2 * db + 2 * db * db,
            2,
        );

        while let Some(p) = stack.pop() {
            if fetched >= MAX_NODE_FETCH {
                notes.push(format!("node chain capped at {MAX_NODE_FETCH} blocks"));
                break;
            }
            if !visited.insert(p.nid) {
                notes.push(format!("node nid {} visited twice — cycle cut", p.nid));
                continue;
            }
            let Some(blk) = (match self.node_blk_for(p.nid) {
                Ok(b) => b,
                Err(e) => {
                    notes.push(format!("NAT lookup failed for nid {}: {e}", p.nid));
                    continue;
                }
            }) else {
                continue; // i_nid slot points at a freed nid
            };
            if blk == 0 {
                continue;
            }
            fetched += 1;
            let (got_blk, footer, view) = match self.read_node_at(blk, Some(p.nid)) {
                Ok(v) => v,
                Err(e) => {
                    notes.push(format!("node nid {} at blk {blk}: {e}", p.nid));
                    continue;
                }
            };
            let _ = got_blk;
            if footer.ino != footer.nid && footer.ino != nid {
                notes.push(format!(
                    "node nid {} owner ino {} mismatches inode",
                    p.nid, footer.ino
                ));
                continue;
            }
            let ptrs = match view {
                NodeView::Indirect(v) => v,
                NodeView::Inode(_) => {
                    notes.push(format!(
                        "nid {} is an inode node, expected data node",
                        p.nid
                    ));
                    continue;
                }
            };
            match p.depth {
                0 => {
                    for (j, &a) in ptrs.iter().enumerate() {
                        match a {
                            NULL_ADDR | NEW_ADDR => {}
                            COMPRESS_ADDR => notes
                                .push(format!("logical block {} is compressed", p.base + j as u64)),
                            b => out.push((p.base + j as u64, b)),
                        }
                    }
                }
                1 => {
                    for (j, &n) in ptrs.iter().enumerate() {
                        if n != 0 {
                            stack.push(Pending {
                                nid: n,
                                base: p.base + j as u64 * db,
                                depth: 0,
                            });
                        }
                    }
                }
                _ => {
                    for (j, &n) in ptrs.iter().enumerate() {
                        if n != 0 {
                            stack.push(Pending {
                                nid: n,
                                base: p.base + j as u64 * db * db,
                                depth: 1,
                            });
                        }
                    }
                }
            }
        }
        out.sort_by_key(|(l, _)| *l);
        (out, notes)
    }

    /// Byte extents `(offset, len)` for a live file, from its inode.
    /// Inline-data files get a range *inside* the inode's node block.
    /// Returns `(ranges, notes)`.
    pub(crate) fn file_ranges(&self, inode: &Inode) -> (Vec<(u64, u64)>, Vec<String>) {
        if inode.inline_flags & inline_flag::INLINE_DATA != 0 {
            let (start, len) = inode.inline_region(self.sb.block_size as usize);
            let cap = (len as u64).min(inode.size);
            if cap == 0 {
                return (Vec::new(), Vec::new());
            }
            return (
                vec![(self.sb.blk_off(inode.blk) + start as u64, cap)],
                Vec::new(),
            );
        }
        let (extents, notes) = self.extents(inode.nid, inode);
        let ranges: Vec<(u64, u64)> = extents
            .iter()
            .map(|(_, b)| (self.sb.blk_off(*b as u64), self.sb.block_size))
            .collect();
        (coalesce(ranges), notes)
    }

    /// The data blocks of a directory inode — each is a dentry block.
    /// For `INLINE_DENTRY` dirs returns an empty list (the caller uses the
    /// inline region instead).
    pub(crate) fn dir_data_blocks(&self, nid: u32, inode: &Inode) -> Vec<u64> {
        if inode.inline_flags & inline_flag::INLINE_DENTRY != 0 {
            return Vec::new();
        }
        let (extents, _) = self.extents(nid, inode);
        extents.into_iter().map(|(_, b)| b as u64).collect()
    }

    /// Parse all xattrs reachable from an inode (block + inline regions).
    pub(crate) fn xattrs(&self, inode: &Inode) -> node::Xattrs {
        let mut merged = node::Xattrs::default();
        if inode.xattr_nid != 0 {
            // Try current NAT first, then the stale copy (deleted inodes).
            let blk = self
                .node_blk_for(inode.xattr_nid)
                .ok()
                .flatten()
                .or_else(|| {
                    self.tables()
                        .stale_nat_entry(inode.xattr_nid)
                        .ok()
                        .flatten()
                        .map(|e| e.block_addr)
                        .filter(|&b| b != 0)
                });
            if let Some(b) = blk {
                if let Ok(raw) = self.read_block(b as u64) {
                    if let Some(x) = node::parse_xattr_block(&raw) {
                        merged.encrypt_ctx = x.encrypt_ctx.or(merged.encrypt_ctx);
                        merged.verity |= x.verity;
                        merged.list.extend(x.list);
                    }
                }
            }
        }
        if let Some((off, len)) = inode.inline_xattr_region(self.sb.block_size as usize) {
            if let Some(region) = inode.raw.get(off..off + len) {
                let x = node::parse_xattr_entries(region);
                merged.encrypt_ctx = x.encrypt_ctx.or(merged.encrypt_ctx);
                merged.verity |= x.verity;
                merged.list.extend(x.list);
            }
        }
        merged
    }

    /// Read the symlink target (bounded to one block / inline region).
    pub(crate) fn symlink_target(&self, inode: &Inode) -> Option<String> {
        if inode.inline_flags & inline_flag::INLINE_DATA != 0 {
            let (start, len) = inode.inline_region(self.sb.block_size as usize);
            let n = (len as u64).min(inode.size) as usize;
            let bytes = inode.raw.get(start..start + n)?;
            return Some(String::from_utf8_lossy(bytes).to_string());
        }
        let (extents, _) = self.extents(inode.nid, inode);
        let (_, blk) = extents.iter().find(|(_, b)| *b != 0).copied()?;
        let n = (inode.size as usize).min(self.sb.block_size as usize);
        let b = self.src.read_slice(self.sb.blk_off(blk as u64), n).ok()?;
        Some(String::from_utf8_lossy(&b).to_string())
    }

    /// Timestamps for an inode → `Timestamps` (MACB + crtime).
    pub(crate) fn timestamps(&self, inode: &Inode) -> Timestamps {
        let ts = |sec: u64, nsec: u32| -> FsTimestamp {
            let value = if sec == 0 || nsec >= 1_000_000_000 {
                None
            } else {
                (sec as i64)
                    .checked_mul(1_000_000_000)
                    .and_then(|s| s.checked_add(nsec as i64))
            };
            FsTimestamp {
                value,
                raw_value: (sec << 32) | nsec as u64,
                raw_encoding: "f2fs-sec-nsec",
                granularity: std::time::Duration::from_nanos(1),
            }
        };
        Timestamps {
            modified: Some(ts(inode.mtime, inode.mtime_nsec)),
            accessed: Some(ts(inode.atime, inode.atime_nsec)),
            created: inode.crtime.map(|(s, n)| ts(s, n)),
            changed: Some(ts(inode.ctime, inode.ctime_nsec)),
            deleted: None,
        }
    }

    /// Common `meta` keys for an inode-derived entry.
    pub(crate) fn inode_meta(
        &self,
        inode: &Inode,
        footer: Option<NodeFooter>,
    ) -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("nid".into(), inode.nid.to_string());
        m.insert("mode".into(), format!("{:#06o}", inode.mode));
        m.insert("uid".into(), inode.uid.to_string());
        m.insert("gid".into(), inode.gid.to_string());
        m.insert("links".into(), inode.links.to_string());
        m.insert("flags".into(), format!("{:#x}", inode.flags));
        m.insert("blocks".into(), inode.blocks.to_string());
        m.insert("pino".into(), inode.pino.to_string());
        if inode.generation != 0 {
            m.insert("generation".into(), inode.generation.to_string());
        }
        if inode.advise != 0 {
            m.insert("advise".into(), format!("{:#x}", inode.advise));
        }
        if inode.current_depth != 0 {
            m.insert("dir_depth".into(), inode.current_depth.to_string());
        }
        if inode.dir_level != 0 {
            m.insert("dir_level".into(), inode.dir_level.to_string());
        }
        let (fofs, eblk, elen) = inode.i_ext;
        if elen != 0 {
            m.insert("ext_cache".into(), format!("{fofs}:{eblk:#x}+{elen}"));
        }
        if let Some(f) = footer {
            m.insert("node_cp_ver".into(), f.cp_ver.to_string());
            m.insert("node_flag".into(), format!("{:#x}", f.flag));
            if f.next_blkaddr != 0 {
                m.insert("fsync_next_blk".into(), f.next_blkaddr.to_string());
            }
        }
        if inode.inline_flags & inline_flag::EXTRA_ATTR != 0 {
            m.insert("extra_isize".into(), inode.extra_isize.to_string());
        }
        if inode.inline_xattr_size != 0 {
            m.insert(
                "inline_xattr_size".into(),
                inode.inline_xattr_size.to_string(),
            );
        }
        if inode.flags & inode_flag::IMMUTABLE != 0 {
            m.insert("immutable".into(), "true".into());
        }
        if inode.flags & inode_flag::APPEND != 0 {
            m.insert("append".into(), "true".into());
        }
        if inode.flags & inode_flag::NODUMP != 0 {
            m.insert("nodump".into(), "true".into());
        }
        if inode.flags & inode_flag::VERITY != 0 {
            m.insert("fsverity".into(), "true".into());
        }
        if inode.flags & inode_flag::COMPR != 0 || inode.compr_blocks > 0 {
            m.insert("compressed".into(), "true".into());
            m.insert(
                "compress_algorithm".into(),
                inode.compress_algorithm.to_string(),
            );
            m.insert(
                "compress_flag".into(),
                format!("{:#x}", inode.compress_flag),
            );
            m.insert(
                "log_cluster_size".into(),
                inode.log_cluster_size.to_string(),
            );
            m.insert("compr_blocks".into(), inode.compr_blocks.to_string());
        }
        if inode.inline_flags & inline_flag::INLINE_DATA != 0 {
            m.insert("inline_data".into(), "true".into());
        }
        if inode.inline_flags & inline_flag::INLINE_DENTRY != 0 {
            m.insert("inline_dentry".into(), "true".into());
        }
        m
    }

    /// Merge encryption/xattr awareness into `meta`.
    pub(crate) fn crypto_meta(&self, inode: &Inode, meta: &mut HashMap<String, String>) {
        let x = self.xattrs(inode);
        if inode.is_encrypted() || x.encrypt_ctx.is_some() {
            meta.insert("encrypted".into(), "fscrypt".into());
            if let Some(ctx) = &x.encrypt_ctx {
                let ver = ctx.first().copied().unwrap_or(0);
                meta.insert(
                    "fscrypt_context".into(),
                    format!("v{ver} ({} bytes)", ctx.len()),
                );
                if ctx.len() >= 4 {
                    meta.insert(
                        "fscrypt_modes".into(),
                        format!("contents={} filenames={}", ctx[1], ctx[2]),
                    );
                }
            }
        }
        if x.verity {
            meta.insert("fsverity_xattr".into(), "true".into());
        }
        if !x.list.is_empty() {
            meta.insert("xattrs".into(), x.list.join(","));
        }
    }

    /// Build an `FsEntry` from a live inode node + dentry info.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn entry_from_inode(
        &self,
        path: String,
        name: String,
        nid: u32,
        inode: &Inode,
        footer: NodeFooter,
        disk_offset: u64,
        status: FsEntryStatus,
        surviving_ranges: Option<Vec<(u64, u64)>>,
        extra_meta: HashMap<String, String>,
        encrypted_parent: bool,
    ) -> FsEntry {
        let kind = match inode.mode & 0o170000 {
            0o040000 => EntryKind::Directory,
            0o120000 => EntryKind::Symlink,
            0o100000 => EntryKind::File,
            _ => match extra_meta.get("file_type").map(String::as_str) {
                Some("1") => EntryKind::File,
                Some("2") => EntryKind::Directory,
                Some("7") => EntryKind::Symlink,
                _ => EntryKind::Other,
            },
        };
        let mut meta = self.inode_meta(inode, Some(footer));
        meta.extend(extra_meta);
        self.crypto_meta(inode, &mut meta);
        if encrypted_parent {
            meta.insert("encrypted_name".into(), "true".into());
        }
        if kind == EntryKind::Symlink {
            if let Some(t) = self.symlink_target(inode) {
                let t: String = t.chars().filter(|c| !c.is_control()).collect();
                meta.insert("symlink_target".into(), t);
            }
        }
        let (ranges, notes) = if let Some(r) = surviving_ranges {
            (r, Vec::new())
        } else {
            self.file_ranges(inode)
        };
        for (i, n) in notes.iter().enumerate() {
            meta.insert(format!("recovery_note_{i}"), n.clone());
        }
        let mut entry = FsEntry {
            path,
            name,
            entry_id: nid as u64,
            kind,
            size: inode.size,
            disk_offset,
            allocated_ranges: ranges,
            timestamps: self.timestamps(inode),
            status,
            meta,
            magic: None,
        };
        entry.magic = self.magic_for(&entry);
        entry
    }

    /// Recovery assessment for a deleted inode's extents.
    ///
    /// F2FS never writes in place: a block whose SIT validity bit is *clear*
    /// still holds whatever was last written there — so a deleted file's
    /// extent survives iff its block is not currently claimed by live data.
    /// Returns `(state, surviving_byte_ranges, notes)`.
    pub(crate) fn recovery_for(
        &self,
        inode: &Inode,
    ) -> (RecoveryState, Vec<(u64, u64)>, Vec<String>) {
        let mut notes = Vec::new();
        // Inline data lives inside the node block we already have — intact.
        if inode.inline_flags & inline_flag::INLINE_DATA != 0 {
            let (ranges, _) = self.file_ranges(inode);
            return if inode.size == 0 || !ranges.is_empty() {
                (RecoveryState::Intact, ranges, notes)
            } else {
                (RecoveryState::Unrecoverable, Vec::new(), notes)
            };
        }
        let (extents, mut ns) = self.extents(inode.nid, inode);
        notes.append(&mut ns);
        let needed = inode.size.div_ceil(self.sb.block_size);
        let mut surviving = Vec::new();
        let mut lost = 0u64;
        let mut unknown = 0u64;
        for (logical, blk) in &extents {
            if *logical >= needed && needed > 0 {
                notes.push(format!("extent blk {blk} is beyond EOF (prealloc?)"));
            }
            match self.block_is_live(*blk as u64) {
                Some(true) => {
                    lost += 1;
                    if let Ok(Some(se)) = self.tables().sum_entry(*blk as u64) {
                        notes.push(format!(
                            "blk {blk} reallocated (ssa: nid={} ver={} ofs={})",
                            se.nid, se.version, se.ofs_in_node
                        ));
                    } else {
                        notes.push(format!("blk {blk} reallocated to live data"));
                    }
                }
                Some(false) => surviving.push((self.sb.blk_off(*blk as u64), self.sb.block_size)),
                None => {
                    unknown += 1;
                    surviving.push((self.sb.blk_off(*blk as u64), self.sb.block_size));
                    notes.push(format!("blk {blk}: SIT state unknown, counting surviving"));
                }
            }
        }
        let ranges = coalesce(surviving);
        if extents.is_empty() && inode.size > 0 {
            notes.push("inode records no extents".into());
            return (RecoveryState::Unrecoverable, ranges, notes);
        }
        let recovered = (ranges.iter().map(|(_, l)| *l).sum::<u64>()).min(inode.size);
        let state = if lost == 0 && unknown == 0 {
            RecoveryState::Intact
        } else if recovered == 0 {
            RecoveryState::Unrecoverable
        } else {
            RecoveryState::PartiallyOverwritten {
                recovered_bytes: recovered,
                total_bytes: inode.size,
            }
        };
        (state, ranges, notes)
    }

    /// Build a deleted entry from an inode node (stale NAT / orphan / scan).
    /// `path`/`name` come from residue, the inode's SPOR name, or
    /// `util::orphan_path`.
    pub(crate) fn deleted_entry(
        &self,
        nid: u32,
        inode: &Inode,
        footer: NodeFooter,
        source: &str,
        name_hint: Option<(String, String)>, // (path, name)
    ) -> FsEntry {
        let (state, ranges, notes) = self.recovery_for(inode);
        let (path, name) = match name_hint {
            Some((p, n)) => (p, n),
            None => {
                let nm = if !inode.name.is_empty() {
                    util::sanitize_name(&String::from_utf8_lossy(&inode.name))
                } else {
                    format!("nid_{nid}")
                };
                (util::join_path("/$ORPHANED", &nm), nm)
            }
        };
        let mut meta = HashMap::new();
        meta.insert("recovery_source".into(), source.into());
        meta.insert("deleted_marker".into(), "f2fs".into());
        for (i, n) in notes.iter().enumerate() {
            meta.insert(format!("recovery_note_{i}"), n.clone());
        }
        self.entry_from_inode(
            path,
            name,
            nid,
            inode,
            footer,
            self.sb.blk_off(inode.blk),
            FsEntryStatus::Deleted { recovery: state },
            Some(ranges),
            meta,
            false,
        )
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

    /// Free main-area byte ranges (SIT-invalid blocks), coalesced.
    fn free_ranges(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut run: Option<u64> = None; // start blk
        let bsz = self.sb.block_size;
        for seg in 0..self.sb.segment_count_main as u64 {
            let base = self.sb.main_seg_blk(seg);
            for off in 0..self.sb.blks_per_seg {
                let live = self
                    .sit_entry(seg)
                    .map(|e| crate::tables::bit_le(&e.valid_map[..], off))
                    .unwrap_or(true); // unreadable SIT → don't report as free
                match (live, run) {
                    (false, None) => run = Some(base + off),
                    (true, Some(s)) => {
                        out.push((self.sb.blk_off(s), (base + off - s) * bsz));
                        run = None;
                    }
                    _ => {}
                }
            }
        }
        if let Some(s) = run {
            let end = self.sb.main_seg_blk(self.sb.segment_count_main as u64);
            out.push((self.sb.blk_off(s), (end - s) * bsz));
        }
        out
    }
}

/// Coalesce adjacent `(offset, len)` byte ranges.
fn coalesce(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort();
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (off, len) in ranges {
        if let Some(last) = out.last_mut() {
            if last.0 + last.1 == off {
                last.1 += len;
                continue;
            }
        }
        out.push((off, len));
    }
    out
}

impl FileSystem for F2fsFs {
    fn info(&self) -> FsInfo {
        let mut meta = HashMap::new();
        let sb = &self.sb;
        meta.insert(
            "f2fs_version".into(),
            format!("{}.{}", sb.major_ver, sb.minor_ver),
        );
        meta.insert("kernel_version".into(), sb.version.clone());
        meta.insert("feature".into(), format!("{:#x}", sb.feature));
        meta.insert(
            "log_blocksize".into(),
            sb.block_size.trailing_zeros().to_string(),
        );
        meta.insert(
            "log_blocks_per_seg".into(),
            sb.log_blocks_per_seg.to_string(),
        );
        meta.insert("segs_per_sec".into(), sb.segs_per_sec.to_string());
        meta.insert("secs_per_zone".into(), sb.secs_per_zone.to_string());
        meta.insert(
            "segment_count_ckpt".into(),
            sb.segment_count_ckpt.to_string(),
        );
        meta.insert("segment_count_sit".into(), sb.segment_count_sit.to_string());
        meta.insert("segment_count_nat".into(), sb.segment_count_nat.to_string());
        meta.insert("segment_count_ssa".into(), sb.segment_count_ssa.to_string());
        meta.insert(
            "segment_count_main".into(),
            sb.segment_count_main.to_string(),
        );
        meta.insert("section_count".into(), sb.section_count.to_string());
        meta.insert("node_ino".into(), sb.node_ino.to_string());
        meta.insert("meta_ino".into(), sb.meta_ino.to_string());
        meta.insert("superblock_crc_ok".into(), sb.crc_ok.to_string());
        meta.insert("extension_count".into(), sb.extension_count.to_string());
        meta.insert(
            "user_block_count".into(),
            self.ckpt.user_block_count.to_string(),
        );
        meta.insert(
            "valid_block_count".into(),
            self.ckpt.valid_block_count.to_string(),
        );
        meta.insert(
            "overprov_segment_count".into(),
            self.ckpt.overprov_segment_count.to_string(),
        );
        meta.insert(
            "cp_pack_total".into(),
            self.ckpt.cp_pack_total_block_count.to_string(),
        );
        meta.insert(
            "checkpoint_ver".into(),
            self.ckpt.checkpoint_ver.to_string(),
        );
        meta.insert("checkpoint_pack_blk".into(), self.ckpt.pack_blk.to_string());
        meta.insert("checkpoint_crc_ok".into(), self.ckpt.crc_ok.to_string());
        meta.insert("ckpt_flags".into(), format!("{:#x}", self.ckpt.ckpt_flags));
        meta.insert(
            "clean_unmount".into(),
            (self.ckpt.ckpt_flags & checkpoint::cp_flag::UMOUNT != 0).to_string(),
        );
        meta.insert(
            "valid_node_count".into(),
            self.ckpt.valid_node_count.to_string(),
        );
        meta.insert(
            "valid_inode_count".into(),
            self.ckpt.valid_inode_count.to_string(),
        );
        meta.insert("next_free_nid".into(), self.ckpt.next_free_nid.to_string());
        meta.insert("elapsed_time".into(), self.ckpt.elapsed_time.to_string());
        meta.insert(
            "orphan_inodes".into(),
            self.ckpt.orphan_inos.len().to_string(),
        );
        meta.insert("max_nid".into(), sb.max_nid().to_string());
        if self.sb.has_feature(feature::ENCRYPT) {
            meta.insert("encryption_feature".into(), "true".into());
        }
        if self.sb.has_feature(feature::CASEFOLD) {
            meta.insert("casefold_feature".into(), "true".into());
        }
        if self.sb.has_feature(feature::COMPRESSION) {
            meta.insert("compression_feature".into(), "true".into());
        }
        for (i, n) in self.ckpt.notes.iter().enumerate() {
            meta.insert(format!("mount_note_{i}"), n.clone());
        }
        FsInfo {
            fs_type: "F2FS".into(),
            label: sb.volume_name.clone(),
            uuid: Some(sb.uuid.clone()),
            block_size: sb.block_size,
            total_blocks: sb.block_count,
            free_blocks: Some(self.ckpt.free_segment_count as u64 * sb.blks_per_seg),
            total_nodes: Some(sb.max_nid()),
            meta,
        }
    }

    fn source(&self) -> Arc<dyn ByteSource> {
        self.src.clone()
    }

    fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
        Box::new(crate::walk::Walk::new(self))
    }

    fn read_file(&self, entry: &FsEntry) -> Result<Box<dyn Read + Send>> {
        match entry.kind {
            EntryKind::File | EntryKind::Symlink | EntryKind::Other => {}
            _ => {
                return Err(FsError::InvalidInput {
                    msg: format!("cannot read {}: not a file", entry.path),
                })
            }
        }
        Ok(Box::new(ExtentReader {
            src: self.src.clone(),
            ranges: entry.allocated_ranges.clone(),
            idx: 0,
            off_in: 0,
            remaining: entry.size,
        }))
    }

    /// Main-area blocks whose SIT validity bit is clear — the carving
    /// ground. F2FS never writes in place, so this space routinely holds
    /// stale node blocks, old file versions and dentry residue.
    fn unallocated_ranges(&self) -> Vec<(u64, u64)> {
        self.free_ranges()
    }
}

/// Sequential reader over byte extents, capped at `remaining` logical bytes
/// (identical semantics to the FAT reader: surviving extents only).
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
