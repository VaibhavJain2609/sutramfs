//! [`Ext4Fs`] — the mounted filesystem: superblock + GDT, bitmap access,
//! inode reads, the mount-time live scan, recovery analysis and the
//! `FileSystem` impl.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::{Arc, Mutex};

use sutram_fs::util;
use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsError, FsInfo, FsParser, FsTimestamp,
    FileSystem, MountOptions, RecoveryState, Result, Timestamps,
};
use sutram_io::ByteSource;

use crate::dirent;
use crate::extent::{self, BlockMap, BlockRun};
use crate::gdt::{self, GroupDesc, BG_BLOCK_UNINIT};
use crate::inode::{self, Inode};
use crate::journal::{self, JournalEvent, JournalInfo};
use crate::superblock::{self, Superblock};
use crate::walk::Walk;

/// Upper bound on buffered bytes for a single directory (32 MiB —
/// ~2M dirents). Larger claims are almost certainly corruption; the walk
/// emits an error record instead of allocating.
pub(crate) const MAX_DIR_BYTES: u64 = 32 << 20;

/// (logical offset, absolute disk offset, length) segments inside a
/// directory-data buffer — dirent provenance.
pub(crate) type DirMap = Vec<(u64, u64, u64)>;

/// The parser entry point — stateless, cheap to construct.
///
/// ```
/// use sutram_ext4::Ext4Parser;
/// use sutram_fs::FsParser;
/// let p = Ext4Parser;
/// assert_eq!(p.name(), "ext4");
/// ```
pub struct Ext4Parser;

impl FsParser for Ext4Parser {
    fn name(&self) -> &'static str {
        "ext4"
    }

    fn detect(&self, src: &dyn ByteSource) -> DetectConfidence {
        Superblock::detect(src)
    }

    fn mount_with(
        &self,
        src: Arc<dyn ByteSource>,
        opts: &MountOptions,
    ) -> Result<Box<dyn FileSystem>> {
        Ok(Box::new(Ext4Fs::mount(src, opts.clone())?))
    }
}

/// A mounted ext2/3/4 volume.
pub struct Ext4Fs {
    pub(crate) src: Arc<dyn ByteSource>,
    pub(crate) sb: Superblock,
    pub(crate) groups: Vec<GroupDesc>,
    pub(crate) opts: MountOptions,
    /// Data blocks claimed by *live* files → owning path (for recovery
    /// notes). Built at mount by a metadata-only scan; proportional to
    /// live file extents, not image bytes.
    pub(crate) live_blocks: HashMap<u64, String>,
    /// Inode numbers referenced by live dirents (the live namespace).
    pub(crate) referenced: HashSet<u32>,
    /// Lazily-read bitmap blocks (block/inode), one fs block per group.
    bbm_cache: Mutex<HashMap<u32, Arc<Vec<u8>>>>,
    ibm_cache: Mutex<HashMap<u32, Arc<Vec<u8>>>>,
    /// jbd2 superblock summary, when a journal inode exists and parses.
    pub(crate) journal: Option<JournalInfo>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A poisoned bitmap cache is not fatal — recover the guard.
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Ext4Fs {
    /// Mount the volume directly — the concrete handle exposes
    /// journal forensics ([`Self::journal_events`]) beyond the
    /// `dyn FileSystem` surface.
    pub fn mount(src: Arc<dyn ByteSource>, opts: MountOptions) -> Result<Self> {
        let sb = Superblock::parse(src.as_ref())?;
        let groups = gdt::read_gdt(src.as_ref(), &sb)?;
        let mut fs = Ext4Fs {
            src,
            sb,
            groups,
            opts,
            live_blocks: HashMap::new(),
            referenced: HashSet::new(),
            bbm_cache: Mutex::new(HashMap::new()),
            ibm_cache: Mutex::new(HashMap::new()),
            journal: None,
        };
        fs.scan_live();
        fs.journal = fs.probe_journal();
        Ok(fs)
    }

    // -- geometry ------------------------------------------------------

    /// Byte offset of block `b` (no bounds check — callers validate).
    pub(crate) fn block_off(&self, b: u64) -> u64 {
        b * self.sb.block_size
    }

    /// Absolute byte offset of inode `ino` (1-based), or `None` when out
    /// of range or its group is missing.
    pub(crate) fn inode_offset(&self, ino: u32) -> Option<u64> {
        if ino == 0 || ino > self.sb.inodes_count || self.sb.inodes_per_group == 0 {
            return None;
        }
        let g = (ino - 1) / self.sb.inodes_per_group;
        let idx = (ino - 1) % self.sb.inodes_per_group;
        let gd = self.groups.get(g as usize)?;
        Some(gd.inode_table * self.sb.block_size + idx as u64 * self.sb.inode_size as u64)
    }

    /// Read and decode inode `ino`.
    pub(crate) fn read_inode(&self, ino: u32) -> Result<Inode> {
        let off = self.inode_offset(ino).ok_or_else(|| FsError::InvalidInput {
            msg: format!("inode {ino} out of range"),
        })?;
        let need = inode::MIN_INODE_SIZE as u64;
        let raw = self
            .src
            .read_slice(off, self.sb.inode_size as usize)
            .map_err(FsError::Io)?;
        if (raw.len() as u64) < need {
            return Err(FsError::truncated(off, need, raw.len() as u64));
        }
        Inode::parse(&raw, ino, off)
            .ok_or_else(|| FsError::corrupt(off, "inode shorter than minimum size"))
    }

    /// Read one filesystem block.
    pub(crate) fn read_block(&self, b: u64) -> Result<Vec<u8>> {
        let off = self.block_off(b);
        let data = self
            .src
            .read_slice(off, self.sb.block_size as usize)
            .map_err(FsError::Io)?;
        if (data.len() as u64) < self.sb.block_size {
            return Err(FsError::truncated(
                off,
                self.sb.block_size,
                data.len() as u64,
            ));
        }
        Ok(data)
    }

    // -- bitmaps ---------------------------------------------------------

    fn bitmap(
        &self,
        cache: &Mutex<HashMap<u32, Arc<Vec<u8>>>>,
        block: u64,
        group: u32,
    ) -> Result<Arc<Vec<u8>>> {
        if let Some(b) = lock(cache).get(&group) {
            return Ok(b.clone());
        }
        let data = Arc::new(self.read_block(block)?);
        lock(cache).insert(group, data.clone());
        Ok(data)
    }

    pub(crate) fn block_bitmap(&self, g: u32) -> Result<Arc<Vec<u8>>> {
        let gd = self
            .groups
            .get(g as usize)
            .ok_or_else(|| FsError::corrupt(0, format!("block group {g} out of range")))?;
        self.bitmap(&self.bbm_cache, gd.block_bitmap, g)
    }

    pub(crate) fn inode_bitmap(&self, g: u32) -> Result<Arc<Vec<u8>>> {
        let gd = self
            .groups
            .get(g as usize)
            .ok_or_else(|| FsError::corrupt(0, format!("block group {g} out of range")))?;
        self.bitmap(&self.ibm_cache, gd.inode_bitmap, g)
    }

    /// Is filesystem block `b` allocated? Out-of-range and pre-data blocks
    /// count as allocated (conservative — never claim data survives in
    /// space the filesystem doesn't even own).
    pub(crate) fn block_allocated(&self, b: u64) -> Result<bool> {
        if b < self.sb.first_data_block as u64 || b >= self.sb.blocks_count {
            return Ok(true);
        }
        let g = (b / self.sb.blocks_per_group as u64) as u32;
        let idx = b - g as u64 * self.sb.blocks_per_group as u64;
        let bm = self.block_bitmap(g)?;
        let byte = bm.get(idx as usize / 8);
        Ok(match byte {
            Some(v) => v & (1 << (idx % 8)) != 0,
            None => true, // bitmap shorter than geometry — conservative
        })
    }

    /// Is inode `ino` marked allocated in its group's inode bitmap?
    /// Invalid/out-of-range inodes count as allocated.
    pub(crate) fn inode_allocated(&self, ino: u32) -> Result<bool> {
        if ino == 0 || ino > self.sb.inodes_count {
            return Ok(true);
        }
        let g = (ino - 1) / self.sb.inodes_per_group;
        let idx = (ino - 1) % self.sb.inodes_per_group;
        let bm = self.inode_bitmap(g)?;
        let byte = bm.get(idx as usize / 8);
        Ok(match byte {
            Some(v) => v & (1 << (idx % 8)) != 0,
            None => true,
        })
    }

    /// `bg_flags` of the group holding inode `ino` (0 when out of range).
    pub(crate) fn inode_group_flags(&self, ino: u32) -> u16 {
        if ino == 0 || self.sb.inodes_per_group == 0 {
            return 0;
        }
        let g = (ino - 1) / self.sb.inodes_per_group;
        self.groups.get(g as usize).map(|d| d.flags).unwrap_or(0)
    }

    // -- block mapping -----------------------------------------------------

    /// Full block map for an inode (extent tree or legacy indirect).
    pub(crate) fn map(&self, inode: &Inode) -> Result<BlockMap> {
        extent::map_inode(
            self.src.as_ref(),
            inode,
            self.sb.block_size,
            self.sb.blocks_count,
        )
    }

    /// Physical runs for a block-mapped inode; `[]` for inline/empty.
    pub(crate) fn runs_of(&self, inode: &Inode) -> Result<Vec<BlockRun>> {
        match self.map(inode)? {
            BlockMap::Runs(r) => Ok(r),
            _ => Ok(Vec::new()),
        }
    }

    /// Physical block covering logical file block `l`, if mapped.
    /// `runs` are sorted by `logical` — binary search.
    pub(crate) fn phys_at(runs: &[BlockRun], l: u64) -> Option<u64> {
        let i = match runs.binary_search_by(|r| {
            if l < r.logical {
                std::cmp::Ordering::Greater
            } else if l >= r.logical + r.len {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            Ok(i) => i,
            Err(_) => return None,
        };
        let r = runs[i];
        Some(r.phys + (l - r.logical))
    }

    /// Runs → absolute byte extents.
    pub(crate) fn run_ranges(&self, runs: &[BlockRun]) -> Vec<(u64, u64)> {
        runs.iter()
            .map(|r| (self.block_off(r.phys), r.len * self.sb.block_size))
            .collect()
    }

    /// Logical blocks the file's `size` actually requires.
    pub(crate) fn expected_blocks(&self, inode: &Inode) -> u64 {
        inode.size.div_ceil(self.sb.block_size)
    }

    // -- directories -------------------------------------------------------

    /// Absolute byte ranges holding an inline-data inode's contents:
    /// the `i_block` payload (`[0..min(size,60)]` for files, dirents in
    /// `[4..60]` for directories) plus the `system.data` xattr spillover
    /// when the logical size overflows i_block.
    pub(crate) fn inline_ranges(&self, inode: &Inode) -> Vec<(u64, u64)> {
        let mut v = Vec::new();
        let spill_need = if inode.is_dir() {
            v.push((inode.disk_offset + 0x2C, 56));
            // For inline directories the xattr region is a second dirent
            // block; its size is whatever the xattr holds.
            inode.ibody_xattr_value(inode::XATTR_IDX_SYSTEM, "system.data")
        } else {
            let head = inode.size.min(60);
            if head > 0 {
                v.push((inode.disk_offset + 0x28, head));
            }
            if inode.size > 60 {
                inode.ibody_xattr_value(inode::XATTR_IDX_SYSTEM, "system.data")
            } else {
                None
            }
        };
        if let Some((off, len)) = spill_need {
            let take = if inode.is_dir() {
                len
            } else {
                (inode.size - 60).min(len)
            };
            if take > 0 {
                v.push((inode.disk_offset + off, take));
            }
        }
        v
    }

    /// All byte ranges backing an inode's contents (block-mapped or
    /// inline) — used for `allocated_ranges` provenance.
    pub(crate) fn entry_ranges(&self, inode: &Inode) -> Vec<(u64, u64)> {
        match self.map(inode) {
            Ok(BlockMap::Runs(r)) => self.run_ranges(&r),
            Ok(BlockMap::Inline { .. }) | Ok(BlockMap::InlineDir) => {
                self.inline_ranges(inode)
            }
            _ => Vec::new(),
        }
    }

    /// Read a directory's data (bounded by `MAX_DIR_BYTES`) plus a
    /// logical→disk offset map for dirent provenance.
    pub(crate) fn read_dir(&self, inode: &Inode) -> Result<(Vec<u8>, DirMap)> {
        match self.map(inode)? {
            BlockMap::Inline { len } => {
                // Inline-data file (files aren't normally read as dirs,
                // but keep the path honest for corrupt mode bits).
                let l = (len as usize).min(inode.raw.len().saturating_sub(0x28));
                let data = inode.raw[0x28..0x28 + l].to_vec();
                Ok((data, vec![(0, inode.disk_offset + 0x28, l as u64)]))
            }
            BlockMap::InlineDir => {
                // i_block[0..4] = parent ino; dirents live in [4..60].
                let l = 56usize.min(inode.raw.len().saturating_sub(0x2C));
                let data = inode.raw[0x2C..0x2C + l].to_vec();
                Ok((data, vec![(0, inode.disk_offset + 0x2C, l as u64)]))
            }
            BlockMap::Empty => Ok((Vec::new(), Vec::new())),
            BlockMap::Runs(runs) => {
                // Read the whole mapped range, not just i_size: a
                // corrupt/short i_size must not hide dirents or the
                // freed-entry residue that can survive past it.
                let mapped_end = runs
                    .iter()
                    .map(|r| (r.logical + r.len) * self.sb.block_size)
                    .max()
                    .unwrap_or(0);
                let cap = inode.size.max(mapped_end).min(MAX_DIR_BYTES);
                let mut data = Vec::new();
                let mut map = Vec::new();
                let mut logical = 0u64;
                for r in runs {
                    if logical >= cap {
                        break;
                    }
                    // Pad sparse holes so buffer offsets track file-
                    // logical offsets (a sparse dir would otherwise
                    // slide later dirents into the wrong positions).
                    let hole = r
                        .logical
                        .saturating_mul(self.sb.block_size)
                        .saturating_sub(logical);
                    if hole > 0 {
                        let pad = hole.min(cap - logical);
                        data.resize(data.len() + pad as usize, 0);
                        logical += pad;
                        if logical >= cap {
                            break;
                        }
                    }
                    let want = (r.len * self.sb.block_size).min(cap - logical);
                    let chunk = self
                        .src
                        .read_slice(self.block_off(r.phys), want as usize)
                        .map_err(FsError::Io)?;
                    let got = chunk.len() as u64;
                    map.push((logical, self.block_off(r.phys), got));
                    data.extend_from_slice(&chunk);
                    logical += got;
                    if got < want {
                        break; // truncated image — emit what we have
                    }
                }
                Ok((data, map))
            }
        }
    }

    /// Map a logical position inside a directory buffer to its absolute
    /// disk offset (for `FsEntry::disk_offset` provenance).
    pub(crate) fn dir_disk_offset(map: &[(u64, u64, u64)], pos: u64) -> u64 {
        for &(logical, disk, len) in map {
            if pos >= logical && pos < logical + len {
                return disk + pos - logical;
            }
        }
        map.first().map(|(_, d, _)| *d).unwrap_or(0)
    }

    // -- mount-time live scan ------------------------------------------------

    /// Metadata-only pass over the live tree: claims every data block a
    /// live file/dir *needs* into `live_blocks` and records live dirent
    /// inodes in `referenced`. Lenient — errors are swallowed here and
    /// reported properly during `walk()`.
    fn scan_live(&mut self) {
        let mut stack: Vec<(String, u32)> = vec![("/".into(), 2)];
        let mut dirs_seen: HashSet<u32> = HashSet::new();
        self.referenced.insert(2);
        while let Some((path, ino)) = stack.pop() {
            if !dirs_seen.insert(ino) {
                continue;
            }
            let Ok(inode) = self.read_inode(ino) else {
                continue;
            };
            if let Ok(runs) = self.runs_of(&inode) {
                for r in &runs {
                    for b in r.phys..r.phys + r.len {
                        self.live_blocks.entry(b).or_insert_with(|| path.clone());
                    }
                }
            }
            let Ok((data, _)) = self.read_dir(&inode) else {
                continue;
            };
            let blk = self.sb.block_size as usize;
            let mut pos = 0usize;
            while pos < data.len() {
                let bend = ((pos / blk) + 1) * blk;
                let bend = bend.min(data.len());
                match dirent::dirent_at(&data, pos, bend) {
                    Some(d) => {
                        if d.ino != 0 && d.name != "." && d.name != ".." {
                            self.referenced.insert(d.ino);
                            let child = util::join_path(&path, &d.name);
                            if let Ok(ci) = self.read_inode(d.ino) {
                                let expected = self.expected_blocks(&ci);
                                if let Ok(runs) = self.runs_of(&ci) {
                                    for r in &runs {
                                        // Claim only blocks the file's size
                                        // actually needs — tail blocks of a
                                        // longer surviving map may still hold
                                        // a deleted file's bytes.
                                        let end = if ci.is_dir() {
                                            r.logical + r.len
                                        } else {
                                            (r.logical + r.len).min(expected)
                                        };
                                        for l in r.logical..end {
                                            if let Some(p) = Self::phys_at(&[*r], l) {
                                                self.live_blocks
                                                    .entry(p)
                                                    .or_insert_with(|| child.clone());
                                            }
                                        }
                                    }
                                }
                                if ci.is_dir() {
                                    stack.push((child, d.ino));
                                }
                            }
                        }
                        pos += d.rec_len.max(8) as usize;
                    }
                    None => {
                        pos = bend; // corrupt record — skip to next block
                    }
                }
            }
        }
    }

    // -- recovery analysis ---------------------------------------------------

    /// Recovery assessment for a *deleted* inode: map its surviving extent
    /// info against the block bitmap and the live-claim map.
    ///
    /// Returns `(state, surviving byte ranges, notes)`.
    pub(crate) fn recovery_for(
        &self,
        inode: &Inode,
    ) -> (RecoveryState, Vec<(u64, u64)>, Vec<String>) {
        let mut notes = Vec::new();
        let map = match self.map(inode) {
            Ok(m) => m,
            Err(e) => {
                notes.push(format!("block map unreadable: {e}"));
                return (RecoveryState::Unknown, Vec::new(), notes);
            }
        };
        match map {
            BlockMap::Inline { .. } | BlockMap::InlineDir => {
                notes.push("inline data survives inside the inode".into());
                let ranges = self.inline_ranges(inode);
                if inode.size > 60
                    && inode.ibody_xattr_value(inode::XATTR_IDX_SYSTEM, "system.data").is_none()
                {
                    notes.push(
                        "system.data xattr missing — inline spillover lost".into(),
                    );
                }
                let avail: u64 = ranges.iter().map(|(_, l)| *l).sum();
                let state = if avail >= inode.size {
                    RecoveryState::Intact
                } else if avail == 0 {
                    RecoveryState::Unrecoverable
                } else {
                    RecoveryState::PartiallyOverwritten {
                        recovered_bytes: avail,
                        total_bytes: inode.size,
                    }
                };
                (state, ranges, notes)
            }
            BlockMap::Empty => {
                if inode.size == 0 {
                    (RecoveryState::Intact, Vec::new(), notes)
                } else {
                    notes.push("no block map survives (i_block zeroed)".into());
                    (RecoveryState::Unrecoverable, Vec::new(), notes)
                }
            }
            BlockMap::Runs(runs) => {
                let expected = self.expected_blocks(inode);
                if expected == 0 {
                    return (RecoveryState::Intact, Vec::new(), notes);
                }
                let blk = self.sb.block_size;
                let mut surviving: Vec<(u64, u64)> = Vec::new();
                let mut recovered_bytes = 0u64;
                let mut lost_alloc = 0u64;
                let mut lost_nomap = 0u64;
                for l in 0..expected {
                    match Self::phys_at(&runs, l) {
                        Some(p) => match self.block_allocated(p) {
                            Ok(false) => {
                                let take = (inode.size - l * blk).min(blk);
                                recovered_bytes += take;
                                surviving.push((self.block_off(p), blk));
                            }
                            Ok(true) => {
                                lost_alloc += 1;
                                if let Some(owner) = self.live_blocks.get(&p) {
                                    notes.push(format!(
                                        "block {p} reallocated to {owner}"
                                    ));
                                }
                            }
                            Err(e) => {
                                notes.push(format!("block bitmap read failed: {e}"));
                            }
                        },
                        None => lost_nomap += 1,
                    }
                }
                if lost_nomap > 0 {
                    notes.push(format!(
                        "extent info lost for {lost_nomap} logical block(s) (freed leaf?)"
                    ));
                }
                // Uninitialised block bitmaps make allocation status unreliable.
                let g = ((inode.ino - 1) / self.sb.inodes_per_group.max(1)) as usize;
                if self
                    .groups
                    .get(g)
                    .map(|d| d.flags & BG_BLOCK_UNINIT != 0)
                    .unwrap_or(false)
                {
                    notes.push(
                        "group block bitmap marked uninitialised — allocation status unreliable"
                            .into(),
                    );
                }
                let state = if lost_alloc + lost_nomap == 0 {
                    RecoveryState::Intact
                } else if recovered_bytes == 0 {
                    RecoveryState::Unrecoverable
                } else {
                    RecoveryState::PartiallyOverwritten {
                        recovered_bytes,
                        total_bytes: inode.size,
                    }
                };
                (state, surviving, notes)
            }
        }
    }

    // -- misc --------------------------------------------------------------

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

    /// Probe the journal inode (normally 8) for a jbd2 superblock.
    fn probe_journal(&self) -> Option<JournalInfo> {
        if self.sb.feature_compat & superblock::COMPAT_HAS_JOURNAL == 0 {
            return None;
        }
        let inode = self.read_inode(self.sb.journal_inum).ok()?;
        let runs = self.runs_of(&inode).ok()?;
        let first = runs.first()?;
        let mut info = JournalInfo::parse(self.src.as_ref(), self.block_off(first.phys))?;
        if info.block_size == 0 || info.block_size > (16 << 20) {
            info.block_size = self.sb.block_size as u32;
        }
        info.ranges = self.run_ranges(&runs);
        Some(info)
    }

    /// Metadata-block layout for journal tag-target classification.
    fn journal_layout(&self) -> journal::MetaLayout {
        let sb = &self.sb;
        let gdt_start = sb.gdt_offset() / sb.block_size;
        let gdt_blocks = (sb.groups_count as u64 * sb.desc_size as u64).div_ceil(sb.block_size);
        let itable_blocks =
            (sb.inodes_per_group as u64 * sb.inode_size as u64).div_ceil(sb.block_size);
        journal::MetaLayout {
            blocks_count: sb.blocks_count,
            superblock: sb.first_data_block as u64,
            backups: sb.backup_sb_blocks(),
            gdt: (gdt_start, gdt_start + gdt_blocks),
            tables: self
                .groups
                .iter()
                .enumerate()
                .map(|(i, g)| {
                    (
                        i as u32,
                        g.block_bitmap,
                        g.inode_bitmap,
                        g.inode_table,
                        g.inode_table.saturating_add(itable_blocks),
                    )
                })
                .collect(),
        }
    }

    /// Stream the parsed jbd2 journal as [`JournalEvent`]s — descriptor,
    /// commit, revoke and per-tag journaled-block records. Each
    /// `JournaledBlock` is prior-state evidence: its tag names the
    /// filesystem block the copy belongs to, classified against today's
    /// metadata layout ([`JournalTag::prior_state`] flags inode-table,
    /// bitmap, GDT and since-freed targets). The journal is **parsed**,
    /// not replayed. Empty when the volume has no journal.
    pub fn journal_events(&self) -> Box<dyn Iterator<Item = Result<JournalEvent>> + Send + '_> {
        let Some(info) = &self.journal else {
            return Box::new(std::iter::empty());
        };
        Box::new(journal::JournalScan::new(
            self.src.clone(),
            info,
            self.journal_layout(),
            Box::new(|b| self.block_allocated(b).ok()),
            self.opts.strict,
        ))
    }
}

/// Render one journal event as a forensic `FsEntry` — journaled data
/// copies become pseudo-entries whose `allocated_ranges` read back the
/// journaled payload (prior metadata state, `Deleted{Intact}`); revoke
/// and commit records are metadata-only (`Deleted{Unknown}`).
fn journal_entry(ev: &JournalEvent, block_size: u64) -> Option<FsEntry> {
    use crate::journal::JournalEventKind;
    let mut meta = HashMap::new();
    meta.insert("journal".into(), "jbd2".into());
    meta.insert("jbd2_transid".into(), ev.transid.to_string());
    meta.insert(
        "jbd2_journal_block".into(),
        ev.journal_block.to_string(),
    );
    let mut timestamps = Timestamps::default();
    let (name, kind, status, ranges, disk_offset, size) = match &ev.kind {
        JournalEventKind::JournaledBlock(tag) => {
            meta.insert("jbd2_fs_block".into(), tag.fs_block.to_string());
            meta.insert("jbd2_tag_flags".into(), format!("{:#x}", tag.flags));
            meta.insert("jbd2_target".into(), tag.target.name());
            if tag.escaped {
                meta.insert("jbd2_escaped".into(), "true".into());
            }
            if tag.deleted {
                meta.insert("jbd2_tag_deleted".into(), "true".into());
            }
            if tag.uuid_present {
                meta.insert("jbd2_tag_uuid".into(), "true".into());
            }
            if let Some(a) = tag.target_allocated {
                meta.insert("jbd2_target_allocated".into(), a.to_string());
            }
            if tag.prior_state() {
                meta.insert(
                    "note".into(),
                    "journaled copy of prior filesystem metadata state".into(),
                );
            }
            let ranges: Vec<(u64, u64)> = tag
                .data_offset
                .map(|o| vec![(o, block_size)])
                .unwrap_or_default();
            let status = if ranges.is_empty() {
                RecoveryState::Unrecoverable
            } else {
                RecoveryState::Intact
            };
            (
                format!("block_{}", tag.fs_block),
                EntryKind::Other,
                FsEntryStatus::Deleted { recovery: status },
                ranges,
                tag.tag_offset,
                block_size,
            )
        }
        JournalEventKind::Revoke { blocks } => {
            meta.insert("jbd2_revoked_count".into(), blocks.len().to_string());
            let shown: Vec<String> = blocks.iter().take(64).map(u64::to_string).collect();
            let mut list = shown.join(",");
            if blocks.len() > 64 {
                list.push_str(",…");
            }
            meta.insert("jbd2_revoked_blocks".into(), list);
            meta.insert(
                "note".into(),
                "revocation: transaction cancelled replay of these blocks".into(),
            );
            (
                format!("revoke_{}", ev.journal_block),
                EntryKind::Other,
                FsEntryStatus::Deleted {
                    recovery: RecoveryState::Unknown,
                },
                Vec::new(),
                ev.disk_offset,
                0,
            )
        }
        JournalEventKind::Commit { sec, nsec } => {
            meta.insert("jbd2_commit_time".into(), format!("{sec}.{nsec:09}"));
            timestamps.changed = Some(FsTimestamp {
                value: (*sec as i64)
                    .checked_mul(1_000_000_000)
                    .and_then(|v| v.checked_add(*nsec as i64)),
                raw_value: *sec,
                raw_encoding: "jbd2-commit-time",
                granularity: std::time::Duration::from_nanos(1),
            });
            (
                format!("commit_{}", ev.transid),
                EntryKind::Other,
                FsEntryStatus::Deleted {
                    recovery: RecoveryState::Unknown,
                },
                Vec::new(),
                ev.disk_offset,
                0,
            )
        }
        _ => return None,
    };
    Some(FsEntry {
        path: format!("/$JOURNAL/tx_{}/{}", ev.transid, name),
        name,
        entry_id: ev.journal_block,
        kind,
        size,
        disk_offset,
        allocated_ranges: ranges,
        timestamps,
        status,
        meta,
        magic: None,
    })
}

impl FileSystem for Ext4Fs {
    fn info(&self) -> FsInfo {
        let mut meta = HashMap::new();
        let sb = &self.sb;
        meta.insert("ext_variant".into(), sb.variant.name().into());
        meta.insert("feature_compat".into(), format!("{:#x}", sb.feature_compat));
        meta.insert(
            "feature_incompat".into(),
            format!("{:#x}", sb.feature_incompat),
        );
        meta.insert(
            "feature_ro_compat".into(),
            format!("{:#x}", sb.feature_ro_compat),
        );
        for (bit, key, mask) in [
            (superblock::INCOMPAT_FILETYPE, "incompat_filetype", "i"),
            (superblock::INCOMPAT_RECOVER, "incompat_recover", "i"),
            (superblock::INCOMPAT_META_BG, "incompat_meta_bg", "i"),
            (superblock::INCOMPAT_EXTENTS, "incompat_extents", "i"),
            (superblock::INCOMPAT_64BIT, "incompat_64bit", "i"),
            (superblock::INCOMPAT_FLEX_BG, "incompat_flex_bg", "i"),
            (superblock::INCOMPAT_INLINE_DATA, "incompat_inline_data", "i"),
            (superblock::INCOMPAT_ENCRYPT, "incompat_encrypt", "i"),
            (superblock::INCOMPAT_CASEFOLD, "incompat_casefold", "i"),
            (superblock::COMPAT_HAS_JOURNAL, "compat_has_journal", "c"),
            (superblock::COMPAT_DIR_INDEX, "compat_dir_index", "c"),
            (superblock::COMPAT_EXT_ATTR, "compat_ext_attr", "c"),
            (superblock::RO_SPARSE_SUPER, "rocompat_sparse_super", "r"),
            (superblock::RO_LARGE_FILE, "rocompat_large_file", "r"),
            (superblock::RO_HUGE_FILE, "rocompat_huge_file", "r"),
            (superblock::RO_GDT_CSUM, "rocompat_gdt_csum", "r"),
            (superblock::RO_DIR_NLINK, "rocompat_dir_nlink", "r"),
            (superblock::RO_EXTRA_ISIZE, "rocompat_extra_isize", "r"),
            (superblock::RO_BIGALLOC, "rocompat_bigalloc", "r"),
            (superblock::RO_METADATA_CSUM, "rocompat_metadata_csum", "r"),
        ] {
            let v = match mask {
                "i" => sb.feature_incompat & bit,
                "c" => sb.feature_compat & bit,
                _ => sb.feature_ro_compat & bit,
            };
            meta.insert(key.into(), (v != 0).to_string());
        }
        meta.insert("inode_size".into(), sb.inode_size.to_string());
        meta.insert("block_groups".into(), sb.groups_count.to_string());
        meta.insert("blocks_per_group".into(), sb.blocks_per_group.to_string());
        meta.insert("inodes_per_group".into(), sb.inodes_per_group.to_string());
        meta.insert("desc_size".into(), sb.desc_size.to_string());
        meta.insert("mount_count".into(), sb.mnt_count.to_string());
        meta.insert("fs_state".into(), format!("{:#x}", sb.state));
        meta.insert("errors_policy".into(), sb.errors.to_string());
        meta.insert("rev_level".into(), sb.rev_level.to_string());
        meta.insert(
            "free_inodes_count".into(),
            sb.free_inodes_count.to_string(),
        );
        meta.insert("mount_time_raw".into(), sb.mtime.to_string());
        meta.insert("write_time_raw".into(), sb.wtime.to_string());
        meta.insert("mkfs_time_raw".into(), sb.mkfs_time.to_string());
        meta.insert("last_orphan".into(), sb.last_orphan.to_string());
        meta.insert("journal_inode".into(), sb.journal_inum.to_string());
        meta.insert(
            "backup_superblock_count".into(),
            sb.backup_sb_blocks().len().to_string(),
        );
        if sb.feature_incompat & superblock::INCOMPAT_FLEX_BG != 0 {
            meta.insert(
                "groups_per_flex".into(),
                (1u32 << sb.log_groups_per_flex).to_string(),
            );
        }
        if let Some(j) = &self.journal {
            meta.insert("jbd2_superblock_offset".into(), format!("{:#x}", j.disk_offset));
            meta.insert("jbd2_block_size".into(), j.block_size.to_string());
            meta.insert("jbd2_journal_blocks".into(), j.maxlen.to_string());
            meta.insert("jbd2_first_block".into(), j.first.to_string());
            meta.insert("jbd2_sequence".into(), j.sequence.to_string());
            meta.insert("jbd2_start".into(), j.start.to_string());
            meta.insert("jbd2_nr_users".into(), j.nr_users.to_string());
            meta.insert(
                "jbd2_needs_replay".into(),
                (j.start != 0).to_string(),
            );
            meta.insert(
                "jbd2_feature_compat".into(),
                format!("{:#x}", j.feature_compat),
            );
            meta.insert(
                "jbd2_feature_incompat".into(),
                format!("{:#x}", j.feature_incompat),
            );
            if !j.feature_names().is_empty() {
                meta.insert("jbd2_features".into(), j.feature_names().join(","));
            }
            if j.maxlen as u64 <= journal::MAX_SUMMARY_BLOCKS {
                let mut descriptors = 0u64;
                let mut commits = 0u64;
                let mut revokes = 0u64;
                let mut revoked = 0u64;
                let mut journaled = 0u64;
                let mut prior = 0u64;
                let mut errs = 0u64;
                let mut last_transid = 0u32;
                for item in self.journal_events() {
                    match item {
                        Ok(ev) => {
                            last_transid = last_transid.max(ev.transid);
                            match ev.kind {
                                journal::JournalEventKind::Descriptor { .. } => descriptors += 1,
                                journal::JournalEventKind::Commit { .. } => commits += 1,
                                journal::JournalEventKind::Revoke { ref blocks } => {
                                    revokes += 1;
                                    revoked += blocks.len() as u64;
                                }
                                journal::JournalEventKind::JournaledBlock(ref tag) => {
                                    journaled += 1;
                                    if tag.prior_state() {
                                        prior += 1;
                                    }
                                }
                                _ => {}
                            }
                        }
                        Err(_) => errs += 1,
                    }
                }
                meta.insert("jbd2_descriptor_blocks".into(), descriptors.to_string());
                meta.insert("jbd2_commit_blocks".into(), commits.to_string());
                meta.insert("jbd2_revoke_blocks".into(), revokes.to_string());
                meta.insert("jbd2_revoked_blocks".into(), revoked.to_string());
                meta.insert("jbd2_journaled_blocks".into(), journaled.to_string());
                meta.insert("jbd2_prior_metadata_copies".into(), prior.to_string());
                meta.insert("jbd2_transactions".into(), commits.to_string());
                meta.insert("jbd2_parse_errors".into(), errs.to_string());
                meta.insert("jbd2_last_transid".into(), last_transid.to_string());
            } else {
                meta.insert(
                    "jbd2_summary".into(),
                    format!("journal exceeds summary bound ({} blocks)", journal::MAX_SUMMARY_BLOCKS),
                );
            }
        }
        if let Some(g0) = self.groups.first() {
            meta.insert("gdt_offset".into(), format!("{:#x}", g0.disk_offset));
        }
        FsInfo {
            fs_type: sb.variant.name().to_uppercase(),
            label: if sb.label.is_empty() {
                None
            } else {
                Some(sb.label.clone())
            },
            uuid: Some(sb.uuid.clone()),
            block_size: sb.block_size,
            total_blocks: sb.blocks_count,
            free_blocks: Some(sb.free_blocks_count),
            total_nodes: Some(sb.inodes_count as u64),
            meta,
        }
    }

    fn source(&self) -> Arc<dyn ByteSource> {
        self.src.clone()
    }

    fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
        Box::new(Walk::new(self))
    }

    /// jbd2 artefacts as pseudo-entries: each journaled data copy is a
    /// readable snapshot of prior filesystem state; revoke and commit
    /// records are metadata-only transaction evidence.
    fn journal_entries(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
        let block_size = self
            .journal
            .as_ref()
            .map(|j| j.block_size as u64)
            .unwrap_or(0);
        Box::new(
            self.journal_events()
                .filter_map(move |item| match item {
                    Err(e) => Some(Err(e)),
                    Ok(ev) => journal_entry(&ev, block_size).map(Ok),
                }),
        )
    }

    /// `read_file` resolves the inode afresh (`entry_id` = inode number)
    /// so live files get hole-aware zero-filled reads and deleted files
    /// stream only their surviving extents.
    fn read_file(&self, entry: &FsEntry) -> Result<Box<dyn Read + Send>> {
        match entry.kind {
            EntryKind::File | EntryKind::Other => {}
            _ => {
                return Err(FsError::InvalidInput {
                    msg: format!("cannot read {}: not a file", entry.path),
                })
            }
        }
        let deleted = entry.is_deleted();
        match self.read_inode(entry.entry_id as u32) {
            Ok(inode) => match self.map(&inode) {
                Ok(BlockMap::Inline { .. }) | Ok(BlockMap::InlineDir) => {
                    Ok(Box::new(FlatReader::new(
                        self.src.clone(),
                        self.inline_ranges(&inode),
                        inode.size,
                    )))
                }
                Ok(BlockMap::Runs(runs)) if !deleted => Ok(Box::new(InodeReader::new(
                    self.src.clone(),
                    runs,
                    self.sb.block_size,
                    inode.size,
                ))),
                Ok(_) => Ok(Box::new(FlatReader::new(
                    self.src.clone(),
                    entry.allocated_ranges.clone(),
                    entry.size,
                ))),
                Err(e) => Err(e),
            },
            // Inode gone since walk (hostile mutation is impossible — the
            // source is read-only — but carved entries may point at
            // unreadable inodes): stream whatever ranges we recorded.
            Err(_) if deleted || !entry.allocated_ranges.is_empty() => Ok(Box::new(
                FlatReader::new(self.src.clone(), entry.allocated_ranges.clone(), entry.size),
            )),
            Err(e) => Err(e),
        }
    }

    /// Free-block byte ranges per the block bitmaps — the carving ground.
    /// Blocks whose bitmap can't be read are treated as allocated
    /// (conservative: never report allocated space as free).
    fn unallocated_ranges(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut run_start: Option<u64> = None;
        let bpg = self.sb.blocks_per_group as u64;
        for g in 0..self.groups.len() as u32 {
            let bm = match self.block_bitmap(g) {
                Ok(b) => b,
                Err(_) => {
                    if let Some(s) = run_start.take() {
                        out.push((self.block_off(s), self.block_off(g as u64 * bpg) - self.block_off(s)));
                    }
                    continue;
                }
            };
            let first = g as u64 * bpg;
            let end = (first + bpg).min(self.sb.blocks_count);
            for b in first.max(self.sb.first_data_block as u64)..end {
                let idx = (b - first) as usize;
                let free = bm.get(idx / 8).map(|v| v & (1 << (idx % 8)) == 0).unwrap_or(false);
                match (free, run_start) {
                    (true, None) => run_start = Some(b),
                    (false, Some(s)) => {
                        out.push((self.block_off(s), self.block_off(b) - self.block_off(s)));
                        run_start = None;
                    }
                    _ => {}
                }
            }
        }
        if let Some(s) = run_start {
            out.push((self.block_off(s), self.block_off(self.sb.blocks_count) - self.block_off(s)));
        }
        out
    }

    /// ext4 file data is block-aligned — carve at block boundaries
    /// (the caller's `align` is honoured when it is a block multiple).
    fn carve_region(
        &self,
        offset: u64,
        len: u64,
        align: u64,
    ) -> Result<Box<dyn Iterator<Item = Result<sutram_fs::CarveHit>> + Send + '_>> {
        if align == 0 {
            return Err(FsError::InvalidInput {
                msg: "carve alignment must be > 0".into(),
            });
        }
        let blk = self.sb.block_size;
        let step = if align % blk == 0 && align > blk {
            align
        } else {
            blk
        };
        let pos = offset.div_ceil(step) * step;
        Ok(Box::new(BlockCarve {
            src: self.src.clone(),
            pos,
            end: offset.saturating_add(len),
            step,
        }))
    }
}

// ---------------------------------------------------------------------------
// Readers
// ---------------------------------------------------------------------------

/// Sequential reader over flat byte ranges (surviving extents of a deleted
/// file, inline-data regions). Yields at most `remaining` bytes.
pub(crate) struct FlatReader {
    src: Arc<dyn ByteSource>,
    ranges: Vec<(u64, u64)>,
    idx: usize,
    off_in: u64,
    remaining: u64,
}

impl FlatReader {
    pub(crate) fn new(src: Arc<dyn ByteSource>, ranges: Vec<(u64, u64)>, size: u64) -> Self {
        FlatReader {
            src,
            ranges,
            idx: 0,
            off_in: 0,
            remaining: size,
        }
    }
}

impl Read for FlatReader {
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

/// Hole-aware sequential reader for live files: unmapped logical regions
/// (sparse holes) yield zeros; mapped runs read their physical blocks.
struct InodeReader {
    src: Arc<dyn ByteSource>,
    runs: Vec<BlockRun>,
    blk: u64,
    pos: u64,
    size: u64,
}

impl InodeReader {
    fn new(src: Arc<dyn ByteSource>, mut runs: Vec<BlockRun>, blk: u64, size: u64) -> Self {
        runs.sort_by_key(|r| r.logical);
        InodeReader {
            src,
            runs,
            blk,
            pos: 0,
            size,
        }
    }
}

impl Read for InodeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let lb = self.pos / self.blk;
        match Ext4Fs::phys_at(&self.runs, lb) {
            Some(p) => {
                // Bytes available in the current run from `pos`.
                let r = self
                    .runs
                    .iter()
                    .find(|r| lb >= r.logical && lb < r.logical + r.len)
                    .copied();
                let run_end = r
                    .map(|r| (r.logical + r.len) * self.blk)
                    .unwrap_or(self.size);
                let want = buf
                    .len()
                    .min((run_end - self.pos).min(self.size - self.pos) as usize);
                let disk = p * self.blk + self.pos % self.blk;
                let n = self.src.read_at(disk, &mut buf[..want])?;
                self.pos += n as u64;
                if n == 0 {
                    // Short source — report zeros for the rest? No: EOF.
                    return Ok(0);
                }
                Ok(n)
            }
            None => {
                // Sparse hole — emit zeros until the next mapped run or EOF.
                let next = self
                    .runs
                    .iter()
                    .map(|r| r.logical)
                    .filter(|&l| l > lb)
                    .min()
                    .map(|l| l * self.blk)
                    .unwrap_or(self.size);
                let want = buf
                    .len()
                    .min((next.min(self.size) - self.pos) as usize);
                buf[..want].fill(0);
                self.pos += want as u64;
                Ok(want)
            }
        }
    }
}

/// Block-aligned signature carver for [`Ext4Fs::carve_region`].
struct BlockCarve {
    src: Arc<dyn ByteSource>,
    pos: u64,
    end: u64,
    step: u64,
}

impl Iterator for BlockCarve {
    type Item = Result<sutram_fs::CarveHit>;

    fn next(&mut self) -> Option<Self::Item> {
        const HEADER_PROBE: usize = 4096;
        while self.pos < self.end {
            let pos = self.pos;
            self.pos = self.pos.saturating_add(self.step);
            let probe_len = HEADER_PROBE.min((self.end - pos) as usize);
            let header = match self.src.read_slice(pos, probe_len) {
                Ok(h) => h,
                Err(e) => return Some(Err(FsError::Io(e))),
            };
            if let Some(kind) = sutram_magic::detect(&header) {
                return Some(Ok(sutram_fs::CarveHit {
                    offset: pos,
                    len: probe_len as u64,
                    kind,
                    header,
                }));
            }
        }
        None
    }
}
