//! [`XfsParser`] / [`XfsFs`] — mount, live-tree scan, recovery analysis.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;

use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsError, FsInfo, FsParser, FileSystem,
    FsTimestamp, MountOptions, RecoveryState, Result, Timestamps,
};
use sutram_io::le::{u16_be, u32_be};
use sutram_io::ByteSource;

use crate::attr;
use crate::btree::{self, read_leaf, TreeKind, BNOBT, FINOBT, INOBT};
use crate::dir::{self, DirBlock, RawDirent, DIR_LEAF_OFFSET};
use crate::extent::{collect_extents, Extent};
use crate::inode::{Inode, FMT_BTREE, FMT_DEV, FMT_EXTENTS, FMT_LOCAL};
use crate::sb::{Agf, Agi, Superblock};

/// Cap on directory blocks scanned for one directory (anti-runaway).
const MAX_DIR_BLOCKS: usize = 1 << 17;
/// 'XSLM' — v5 remote symlink block magic.
const SYMLINK_MAGIC: u32 = 0x5853_4C4D;
/// 'XLOG' record magic — first word of a log record header.
const LOG_REC_MAGIC: u32 = 0xFEED_BABE;

/// Per-AG state gathered at mount.
#[derive(Debug, Default)]
pub(crate) struct AgState {
    pub agf: Option<Agf>,
    pub agi: Option<Agi>,
    /// Free-space extents from bnobt: (agbno, len), sorted by agbno.
    pub free: Vec<(u32, u32)>,
    /// Inode-chunk records from inobt.
    pub inobt: Vec<InobtRec>,
    /// finobt startinos (cross-check for recently-freed chunks).
    pub finobt: Vec<u32>,
}

/// One decoded inobt/finobt leaf record.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InobtRec {
    /// First inode number of the 64-inode chunk (AG-relative).
    pub startino: u32,
    /// Sparse-chunk hole mask (bit i = 4-inode group i is a hole).
    /// `None` on non-sparse filesystems (record is 16 bytes).
    pub holemask: Option<u32>,
    /// Free-inode bitmap, bit i ↔ inode startino+i.
    pub free: u64,
}

/// The parser entry point.
pub struct XfsParser;

impl FsParser for XfsParser {
    fn name(&self) -> &'static str {
        "xfs"
    }

    fn detect(&self, src: &dyn ByteSource) -> DetectConfidence {
        Superblock::detect(src)
    }

    fn mount_with(
        &self,
        src: Arc<dyn ByteSource>,
        opts: &MountOptions,
    ) -> Result<Box<dyn FileSystem>> {
        Ok(Box::new(XfsFs::mount(src, opts)?))
    }
}

/// A mounted XFS filesystem.
pub struct XfsFs {
    pub(crate) src: Arc<dyn ByteSource>,
    pub(crate) opts: MountOptions,
    pub(crate) sb: Superblock,
    pub(crate) ags: Vec<AgState>,
    /// Live extents claimed by reachable inodes: sorted
    /// `(start_fsb, end_fsb, owner_ino)`.
    pub(crate) live_extents: Vec<(u64, u64, u64)>,
    /// Inode numbers reachable from the live directory tree.
    pub(crate) live_inos: HashSet<u64>,
    /// Sparse-chunk inode → absolute byte offset overrides.
    sparse_map: HashMap<u64, u64>,
    /// Errors collected during mount (emitted as walk records).
    pub(crate) mount_errors: Vec<FsError>,
    /// Filesystem label/uuid info cached for `info()`.
    info: FsInfo,
}

impl XfsFs {
    /// Mount with explicit options.
    pub fn mount(src: Arc<dyn ByteSource>, opts: &MountOptions) -> Result<Self> {
        let sb = Superblock::parse(src.as_ref())?;
        if opts.strict && sb.crc_ok == Some(false) {
            return Err(FsError::corrupt(0, "superblock CRC mismatch"));
        }
        let mut fs = XfsFs {
            src,
            opts: opts.clone(),
            info: FsInfo::default(),
            ags: Vec::with_capacity(sb.agcount as usize),
            live_extents: Vec::new(),
            live_inos: HashSet::new(),
            sparse_map: HashMap::new(),
            mount_errors: Vec::new(),
            sb,
        };
        fs.scan_ags();
        fs.scan_live();
        fs.info = fs.build_info();
        Ok(fs)
    }

    /// Parse every AG's AGF/AGI, walk bnobt + inobt (+finobt) leaves.
    /// Errors are collected per-AG in lenient mode so one corrupt AG can
    /// never hide the rest of the filesystem.
    fn scan_ags(&mut self) {
        for agno in 0..self.sb.agcount {
            let mut ag = AgState::default();
            let base = self.sb.ag_off(agno);
            let sect = self.sb.sectsize as usize;
            match self
                .src
                .read_slice(base + sect as u64, sect)
                .map_err(FsError::Io)
                .and_then(|b| Agf::parse(&b, base + sect as u64, self.sb.has_crc()))
            {
                Ok(agf) => ag.agf = Some(agf),
                Err(e) => self.mount_err(e),
            }
            match self
                .src
                .read_slice(base + 2 * sect as u64, sect)
                .map_err(FsError::Io)
                .and_then(|b| Agi::parse(&b, base + 2 * sect as u64, self.sb.has_crc()))
            {
                Ok(agi) => ag.agi = Some(agi),
                Err(e) => self.mount_err(e),
            }
            // AGFL header (v5) — magic check only; the free list itself
            // duplicates bnobt information.
            if self.sb.is_v5() {
                match self
                    .src
                    .read_slice(base + 3 * sect as u64, 4)
                    .map_err(FsError::Io)
                {
                    Ok(b) if b.len() >= 4 => {
                        if u32_be(&b, 0) != Some(crate::sb::AGFL_MAGIC) {
                            self.mount_err(FsError::corrupt(
                                base + 3 * sect as u64,
                                "bad AGFL magic (want XAFL)",
                            ));
                        }
                    }
                    Ok(_) => {}
                    Err(e) => self.mount_err(e),
                }
            }
            // bnobt → free-space extents.
            if let Some(agf) = &ag.agf {
                if agf.crc_ok == Some(false) {
                    self.mount_err(FsError::corrupt(
                        base + sect as u64,
                        "AGF CRC mismatch",
                    ));
                }
                match btree::collect_leaves(
                    self.src.as_ref(),
                    &self.sb,
                    agno,
                    agf.roots[0],
                    agf.levels[0],
                    BNOBT,
                ) {
                    Ok(leaves) => {
                        let mut errs = Vec::new();
                        ag.free = self.decode_alloc_leaves(agno, &leaves, BNOBT, &mut errs);
                        for e in errs.drain(..) {
                            self.mount_err(e);
                        }
                    }
                    Err(e) => self.mount_err(e),
                }
            }
            // inobt → inode chunk records.
            if let Some(agi) = &ag.agi {
                if agi.crc_ok == Some(false) {
                    self.mount_err(FsError::corrupt(
                        base + 2 * sect as u64,
                        "AGI CRC mismatch",
                    ));
                }
                match btree::collect_leaves(
                    self.src.as_ref(),
                    &self.sb,
                    agno,
                    agi.root,
                    agi.level,
                    INOBT,
                ) {
                    Ok(leaves) => {
                        let mut errs = Vec::new();
                        let recs = self.decode_inobt_leaves(agno, &leaves, INOBT, &mut errs);
                        for e in errs.drain(..) {
                            self.mount_err(e);
                        }
                        self.index_sparse(agno, &recs);
                        ag.inobt = recs;
                    }
                    Err(e) => self.mount_err(e),
                }
                // finobt → recently-freed inode chunks.
                if self.sb.has_finobt() && agi.free_root != 0 {
                    match btree::collect_leaves(
                        self.src.as_ref(),
                        &self.sb,
                        agno,
                        agi.free_root,
                        agi.free_level,
                        FINOBT,
                    ) {
                        Ok(leaves) => {
                            let mut errs = Vec::new();
                            let recs = self.decode_inobt_leaves(agno, &leaves, FINOBT, &mut errs);
                            for e in errs.drain(..) {
                                self.mount_err(e);
                            }
                            ag.finobt = recs.iter().map(|r| r.startino).collect();
                        }
                        Err(e) => self.mount_err(e),
                    }
                }
            }
            ag.free.sort_unstable();
            self.ags.push(ag);
        }
    }

    fn mount_err(&mut self, e: FsError) {
        // In lenient mode collect; strict mounts fail on the first error.
        self.mount_errors.push(e);
    }

    /// Decode 8-byte `{startblock, blockcount}` free-space records.
    /// CRC failures are reported through `errs` but the block is still
    /// decoded (lenient forensic policy).
    fn decode_alloc_leaves(
        &self,
        agno: u32,
        leaves: &[u32],
        kind: TreeKind,
        errs: &mut Vec<FsError>,
    ) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        for &agbno in leaves {
            let (hdr, blk, off) = match read_leaf(self.src.as_ref(), &self.sb, agno, agbno, kind) {
                Ok(v) => v,
                Err(e) => {
                    errs.push(e);
                    continue;
                }
            };
            if hdr.crc_ok == Some(false) {
                errs.push(FsError::corrupt(off, "btree leaf CRC mismatch"));
            }
            let cap = (blk.len() - hdr.hdr_len) / kind.rec_len;
            let n = (hdr.numrecs as usize).min(cap);
            for i in 0..n {
                let p = hdr.hdr_len + i * kind.rec_len;
                let start = u32_be(&blk, p).unwrap_or(0);
                let len = u32_be(&blk, p + 4).unwrap_or(0);
                if len > 0 && start < self.sb.agblocks && start + len <= self.sb.agblocks {
                    out.push((start, len));
                }
            }
        }
        out.sort_unstable();
        out
    }

    /// Decode inobt/finobt leaf records. Both formats are 16 bytes —
    /// sparse chunks (spinodes) re-encode the old 4-byte freecount field
    /// as `{holemask u16, count u8, freecount u8}`; `ir_free` stays at
    /// offset 8 in every record.
    fn decode_inobt_leaves(
        &self,
        agno: u32,
        leaves: &[u32],
        kind: TreeKind,
        errs: &mut Vec<FsError>,
    ) -> Vec<InobtRec> {
        let sparse = self.sb.has_spinodes();
        const REC_LEN: usize = 16;
        let mut out = Vec::new();
        for &agbno in leaves {
            let (hdr, blk, off) = match read_leaf(self.src.as_ref(), &self.sb, agno, agbno, kind) {
                Ok(v) => v,
                Err(e) => {
                    errs.push(e);
                    continue;
                }
            };
            if hdr.crc_ok == Some(false) {
                errs.push(FsError::corrupt(off, "inode btree leaf CRC mismatch"));
            }
            let cap = (blk.len() - hdr.hdr_len) / REC_LEN;
            let n = (hdr.numrecs as usize).min(cap);
            for i in 0..n {
                let p = hdr.hdr_len + i * REC_LEN;
                let startino = u32_be(&blk, p).unwrap_or(0);
                let (holemask, free) = if sparse {
                    (
                        Some(u16_be(&blk, p + 4).unwrap_or(0) as u32),
                        u64be(&blk, p + 8),
                    )
                } else {
                    (None, u64be(&blk, p + 8))
                };
                // startino must be 64-aligned and inside the AG.
                if startino % crate::sb::INODES_PER_CHUNK != 0
                    || (startino >> self.sb.inopblog) >= self.sb.agblocks
                {
                    continue;
                }
                out.push(InobtRec {
                    startino,
                    holemask,
                    free,
                });
            }
        }
        out.sort_by_key(|r| r.startino);
        out
    }

    /// Sparse chunks break the canonical ino→disk mapping; index their
    /// physical slots so [`XfsFs::inode`] stays correct.
    fn index_sparse(&mut self, agno: u32, recs: &[InobtRec]) {
        for rec in recs {
            let Some(holes) = rec.holemask else { continue };
            let chunk_base = self.sb.ag_off(agno)
                + (rec.startino >> self.sb.inopblog) as u64 * self.sb.blocksize as u64;
            let mut phys = 0u32;
            for i in 0..64u32 {
                if holes & (1 << (i / 4)) != 0 {
                    continue;
                }
                let ino = ((agno as u64) << self.sb.agino_bits()) | (rec.startino + i) as u64;
                let off = chunk_base + phys as u64 * self.sb.inodesize as u64;
                self.sparse_map.insert(ino, off);
                phys += 1;
            }
        }
    }

    /// Absolute byte offset of an inode record (sparse-aware).
    pub(crate) fn inode_off(&self, ino: u64) -> u64 {
        self.sparse_map.get(&ino).copied().unwrap_or_else(|| self.sb.ino_off(ino))
    }

    /// Read + decode an inode.
    pub(crate) fn inode(&self, ino: u64) -> Result<Inode> {
        let (buf, off) = self.inode_bytes(ino)?;
        Inode::parse(buf, off, ino, &self.sb)
    }

    /// Raw inode record bytes + absolute offset.
    pub(crate) fn inode_bytes(&self, ino: u64) -> Result<(Vec<u8>, u64)> {
        if !self.sb.ino_valid(ino) {
            return Err(FsError::corrupt(0, format!("inode {ino:#x} out of geometry")));
        }
        let off = self.inode_off(ino);
        let buf = self
            .src
            .read_slice(off, self.sb.inodesize as usize)
            .map_err(FsError::Io)?;
        if buf.len() < self.sb.inodesize as usize {
            return Err(FsError::truncated(
                off,
                self.sb.inodesize as u64,
                buf.len() as u64,
            ));
        }
        Ok((buf, off))
    }

    /// Is this AG-relative block currently in the free-space set?
    pub(crate) fn is_free(&self, agno: u32, agbno: u32) -> bool {
        let Some(ag) = self.ags.get(agno as usize) else {
            return false;
        };
        // Binary search over sorted (start,len).
        ag.free
            .binary_search_by(|&(s, l)| {
                if agbno < s {
                    std::cmp::Ordering::Greater
                } else if agbno >= s + l {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    /// Is `fsb` claimed by a live inode's extent? Returns owner ino.
    pub(crate) fn live_claimed(&self, fsb: u64) -> Option<u64> {
        // live_extents sorted by start; find last extent with start <= fsb.
        let idx = self
            .live_extents
            .partition_point(|&(s, _, _)| s <= fsb);
        if idx == 0 {
            return None;
        }
        let (_, e, ino) = self.live_extents[idx - 1];
        if fsb < e {
            Some(ino)
        } else {
            None
        }
    }

    /// Live-scan: DFS the directory tree from rootino, recording reachable
    /// inodes and every extent they claim (for overwrite detection).
    fn scan_live(&mut self) {
        let mut stack = vec![self.sb.rootino];
        let mut seen: HashSet<u64> = HashSet::new();
        let mut dirs = 0usize;
        while let Some(ino) = stack.pop() {
            if !seen.insert(ino) || !self.sb.ino_valid(ino) {
                continue;
            }
            match self.inode(ino) {
                Ok(inode) => {
                    self.live_inos.insert(ino);
                    // Claim data-fork extents (files and dirs alike).
                    if inode.format == FMT_EXTENTS || inode.format == FMT_BTREE {
                        match collect_extents(
                            self.src.as_ref(),
                            &self.sb,
                            inode.dfork(),
                            inode.format,
                            inode.nextents,
                        ) {
                            Ok(exts) => {
                                for e in exts {
                                    self.live_extents.push((
                                        e.fsb,
                                        e.fsb.saturating_add(e.len as u64),
                                        ino,
                                    ));
                                }
                            }
                            Err(e) => self.mount_err(e),
                        }
                    }
                    if inode.kind() == EntryKind::Directory {
                        dirs += 1;
                        if dirs > MAX_DIR_BLOCKS {
                            self.mount_err(FsError::corrupt(
                                inode.disk_off,
                                "directory count cap exceeded",
                            ));
                            break;
                        }
                        match self.dir_entries(&inode) {
                            Ok(entries) => {
                                for d in entries {
                                    if d.name == b"." || d.name == b".." {
                                        continue;
                                    }
                                    self.live_inos.insert(d.ino);
                                    if self.sb.ino_valid(d.ino) && !seen.contains(&d.ino) {
                                        stack.push(d.ino);
                                    }
                                }
                            }
                            Err(e) => self.mount_err(e),
                        }
                    }
                }
                Err(e) => self.mount_err(e),
            }
        }
        self.live_extents.sort_unstable();
    }

    /// All dirents of a directory inode (live entries only; residue is
    /// handled by the walker via [`XfsFs::dir_blocks`]).
    pub(crate) fn dir_entries(&self, inode: &Inode) -> Result<Vec<RawDirent>> {
        match inode.format {
            FMT_LOCAL => {
                dir::parse_shortform(inode.dfork(), inode.disk_off + inode.core as u64, &self.sb)
                    .map(|(_, ents)| ents)
            }
            FMT_EXTENTS | FMT_BTREE => {
                let exts = collect_extents(
                    self.src.as_ref(),
                    &self.sb,
                    inode.dfork(),
                    inode.format,
                    inode.nextents,
                )?;
                let mut out = Vec::new();
                let mut first_err = None;
                for item in self.dir_blocks(inode, &exts) {
                    match item {
                        Ok((_, blk)) => out.extend(blk.entries),
                        Err(e) => {
                            if first_err.is_none() {
                                first_err = Some(e);
                            }
                        }
                    }
                }
                // Partial results win: only error when nothing parsed.
                if out.is_empty() {
                    if let Some(e) = first_err {
                        return Err(e);
                    }
                }
                Ok(out)
            }
            fmt => Err(FsError::corrupt(
                inode.disk_off + inode.core as u64,
                format!("dir inode has non-directory fork format {fmt}"),
            )),
        }
    }

    /// Read and parse every data-space block of a directory's extent map.
    /// Each block yields a `Result` so one corrupt block can never hide
    /// the rest of the directory (lenient walking).
    pub(crate) fn dir_blocks(
        &self,
        _inode: &Inode,
        exts: &[Extent],
    ) -> Vec<Result<(u64, DirBlock)>> {
        let fsbcount = 1u64 << self.sb.dirblklog; // fs blocks per dir block
        let dirbsize = self.sb.dirbsize() as usize;
        let leaf_space = DIR_LEAF_OFFSET >> self.sb.blocklog; // in fsblocks
        let bs = self.sb.blocksize as usize;
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut sorted: Vec<Extent> = exts.to_vec();
        sorted.sort_by_key(|e| e.fileoff);
        for e in &sorted {
            let db_start = e.fileoff / fsbcount;
            let db_end = (e.fileoff + e.len as u64).div_ceil(fsbcount);
            for db in db_start..db_end.min(leaf_space / fsbcount) {
                if out.len() >= MAX_DIR_BLOCKS || !seen.insert(db) {
                    continue;
                }
                // Assemble dirbsize bytes, translating each fsblock —
                // a dir block may span an extent boundary.
                let mut buf = vec![0u8; dirbsize];
                let mut blk_disk_off = 0u64;
                let mut have_any = false;
                for i in 0..fsbcount {
                    let foff = db * fsbcount + i;
                    let Some(fsblk) = sorted
                        .iter()
                        .find(|x| foff >= x.fileoff && foff < x.fileoff + x.len as u64)
                        .map(|x| x.fsb + (foff - x.fileoff))
                    else {
                        continue;
                    };
                    let off = self.sb.fsb_off(fsblk);
                    if i == 0 {
                        blk_disk_off = off;
                    }
                    let data = match self.src.read_slice(off, bs) {
                        Ok(d) => d,
                        Err(e) => {
                            out.push(Err(FsError::Io(e)));
                            have_any = true; // error recorded; skip rest
                            break;
                        }
                    };
                    let n = data.len().min(bs);
                    buf[i as usize * bs..i as usize * bs + n].copy_from_slice(&data[..n]);
                    have_any = true;
                }
                if !have_any {
                    continue;
                }
                // v5 directory blocks are CRC-validated.
                if self.sb.has_crc() {
                    let stored = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
                    if crate::crc::verify(&buf, 4, stored) == Some(false) {
                        out.push(Err(FsError::corrupt(
                            blk_disk_off,
                            "directory block CRC mismatch",
                        )));
                        continue;
                    }
                }
                match dir::parse_data_block(&buf, blk_disk_off, &self.sb) {
                    Ok(parsed) => out.push(Ok((blk_disk_off, parsed))),
                    Err(e) => out.push(Err(e)),
                }
            }
        }
        out
    }

    /// Decode the symlink target of an inode (LOCAL inline or remote
    /// 'XSLM' extents).
    pub(crate) fn symlink_target(&self, inode: &Inode) -> Result<String> {
        let bytes = match inode.format {
            FMT_LOCAL => {
                let n = (inode.size as usize).min(inode.dfork().len());
                inode.dfork()[..n].to_vec()
            }
            FMT_EXTENTS | FMT_BTREE => {
                let exts = collect_extents(
                    self.src.as_ref(),
                    &self.sb,
                    inode.dfork(),
                    inode.format,
                    inode.nextents,
                )?;
                let mut out = Vec::new();
                let mut remaining = inode.size;
                for e in &exts {
                    for b in 0..e.len {
                        if remaining == 0 {
                            break;
                        }
                        let off = self.sb.fsb_off(e.fsb + b as u64);
                        let blk = self
                            .src
                            .read_slice(off, self.sb.blocksize as usize)
                            .map_err(FsError::Io)?;
                        let (hdr_ok, skip) = if self.sb.is_v5() {
                            (
                                blk.len() >= 56 && u32_be(&blk, 0) == Some(SYMLINK_MAGIC),
                                56usize,
                            )
                        } else {
                            (true, 0)
                        };
                        if !hdr_ok {
                            return Err(FsError::corrupt(off, "bad XSLM symlink header"));
                        }
                        let take = (blk.len() - skip).min(remaining as usize);
                        out.extend_from_slice(&blk[skip..skip + take]);
                        remaining = remaining.saturating_sub(take as u64);
                    }
                }
                out
            }
            _ => return Err(FsError::corrupt(inode.disk_off, "symlink has no data")),
        };
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Extent list for an inode's data fork.
    pub(crate) fn data_extents(&self, inode: &Inode) -> Result<Vec<Extent>> {
        collect_extents(
            self.src.as_ref(),
            &self.sb,
            inode.dfork(),
            inode.format,
            inode.nextents,
        )
    }

    /// Physical `(offset, len)` ranges for a live entry's data extents.
    pub(crate) fn extent_ranges(&self, exts: &[Extent]) -> Vec<(u64, u64)> {
        let mut out: Vec<(u64, u64)> = exts
            .iter()
            .map(|e| (e.disk_off(&self.sb), e.disk_len(&self.sb)))
            .collect();
        out.sort_unstable();
        out
    }

    /// Recovery assessment for a deleted/orphan inode: compare its stale
    /// extent records against the free-space map and live allocation map.
    ///
    /// * block still in bnobt free space → data survives;
    /// * block claimed by a live inode → overwritten;
    /// * block allocated but unclaimed → treated as surviving with a note
    ///   (leaked allocation or metadata reuse — the bytes may still hold
    ///   the deleted file's data, but we flag the ambiguity).
    pub(crate) fn assess_deleted(
        &self,
        inode: &Inode,
    ) -> (RecoveryState, Vec<(u64, u64)>, Vec<String>) {
        let mut notes = Vec::new();
        let exts = match self.data_extents(inode) {
            Ok(e) => e,
            Err(e) => {
                notes.push(format!("extent decode failed: {e}"));
                return (RecoveryState::Unknown, Vec::new(), notes);
            }
        };
        if inode.size == 0 {
            return (RecoveryState::Intact, Vec::new(), notes);
        }
        let bs = self.sb.blocksize as u64;
        let mut surviving: Vec<(u64, u64)> = Vec::new();
        let mut recovered_bytes: u64 = 0;
        let mut lost = 0u64;
        let mut expected = 0u64;
        for e in &exts {
            let fb = e.file_off_bytes(&self.sb);
            if fb >= inode.size {
                continue; // extent fully past EOF
            }
            for i in 0..e.len as u64 {
                let fsb = e.fsb + i;
                let foff = e.fileoff + i;
                let fbyte = foff * bs;
                if fbyte >= inode.size {
                    break;
                }
                expected += bs.min(inode.size - fbyte);
                match self.live_claimed(fsb) {
                    Some(owner) => {
                        lost += 1;
                        notes.push(format!(
                            "fsblock {fsb:#x} reallocated to inode {owner:#x}"
                        ));
                    }
                    None => {
                        surviving.push((self.sb.fsb_off(fsb), bs));
                        recovered_bytes += bs.min(inode.size - fbyte);
                        let agno = self.sb.fsb_agno(fsb);
                        let agbno = self.sb.fsb_agbno(fsb);
                        if !self.is_free(agno, agbno) {
                            notes.push(format!(
                                "fsblock {fsb:#x} still allocated but unclaimed (leaked?)"
                            ));
                        }
                    }
                }
            }
        }
        if lost == 0 && expected > 0 && recovered_bytes >= expected.min(inode.size) {
            // All expected bytes accounted for.
            if recovered_bytes >= inode.size.min(expected.max(1)) {
                return (RecoveryState::Intact, surviving, notes);
            }
        }
        if recovered_bytes == 0 {
            return (RecoveryState::Unrecoverable, surviving, notes);
        }
        (
            RecoveryState::PartiallyOverwritten {
                recovered_bytes,
                total_bytes: inode.size,
            },
            surviving,
            notes,
        )
    }

    /// Build the FsInfo summary.
    fn build_info(&self) -> FsInfo {
        let sb = &self.sb;
        let mut meta = HashMap::new();
        meta.insert("version".into(), sb.version.to_string());
        meta.insert("agcount".into(), sb.agcount.to_string());
        meta.insert("agblocks".into(), sb.agblocks.to_string());
        meta.insert("sectsize".into(), sb.sectsize.to_string());
        meta.insert("inodesize".into(), sb.inodesize.to_string());
        meta.insert("inopblock".into(), sb.inopblock.to_string());
        meta.insert("dirblklog".into(), sb.dirblklog.to_string());
        meta.insert("rootino".into(), format!("{:#x}", sb.rootino));
        meta.insert("features2".into(), format!("{:#x}", sb.features2));
        meta.insert(
            "features_incompat".into(),
            format!("{:#x}", sb.features_incompat),
        );
        meta.insert(
            "features_ro_compat".into(),
            format!("{:#x}", sb.features_ro_compat),
        );
        meta.insert(
            "features_log_incompat".into(),
            format!("{:#x}", sb.features_log_incompat),
        );
        meta.insert("finobt".into(), sb.has_finobt().to_string());
        meta.insert("spinodes".into(), sb.has_spinodes().to_string());
        meta.insert("bigtime".into(), sb.has_bigtime().to_string());
        meta.insert("icount".into(), sb.icount.to_string());
        meta.insert("ifree".into(), sb.ifree.to_string());
        meta.insert("versionnum".into(), format!("{:#x}", sb.versionnum));
        meta.insert("features_compat".into(), format!("{:#x}", sb.features_compat));
        meta.insert("sb_lsn".into(), format!("{:#x}", sb.lsn));
        if sb.meta_uuid != sb.uuid {
            meta.insert("meta_uuid".into(), format_uuid(&sb.meta_uuid));
        }
        if sb.rblocks > 0 {
            meta.insert("realtime_blocks".into(), sb.rblocks.to_string());
        }
        // Cross-check sb_fdblocks against the summed AGF freeblks.
        let freeblks: u64 = self
            .ags
            .iter()
            .filter_map(|a| a.agf.as_ref().map(|f| f.freeblks as u64))
            .sum();
        meta.insert("agf_freeblks_total".into(), freeblks.to_string());
        let freeinos: u64 = self
            .ags
            .iter()
            .filter_map(|a| a.agi.as_ref().map(|i| i.freecount as u64))
            .sum();
        meta.insert("agi_freecount_total".into(), freeinos.to_string());
        if sb.inprogress {
            meta.insert("inprogress".into(), "true (mkfs interrupted)".into());
        }
        if let Some(ok) = sb.crc_ok {
            meta.insert("sb_crc_ok".into(), ok.to_string());
        }
        // Journal presence — replay is a documented TODO.
        if sb.logstart != 0 {
            let off = sb.fsb_off(sb.logstart);
            let magic = self
                .src
                .read_slice(off, 4)
                .ok()
                .and_then(|b| u32_be(&b, 0));
            let observed = if magic == Some(LOG_REC_MAGIC) {
                "xlog record magic observed"
            } else {
                "log region present"
            };
            meta.insert(
                "log".into(),
                format!(
                    "internal log at fsblock {:#x} ({} blocks); {}; journal replay not implemented",
                    sb.logstart, sb.logblocks, observed
                ),
            );
        } else {
            meta.insert("log".into(), "external or none (logstart=0)".into());
        }
        FsInfo {
            fs_type: format!("XFS v{}", sb.version),
            label: if sb.label.is_empty() {
                None
            } else {
                Some(sb.label.clone())
            },
            uuid: Some(format_uuid(&sb.uuid)),
            block_size: sb.blocksize as u64,
            total_blocks: sb.dblocks,
            free_blocks: Some(sb.fdblocks),
            total_nodes: Some(sb.icount),
            meta,
        }
    }

    /// Wrap an inode's fields into an [`FsEntry`].
    ///
    /// `status` drives whether `allocated_ranges` lists all extents (live)
    /// or only surviving ones (deleted); `dirent_off` is the offset of the
    /// name record when one exists.
    pub(crate) fn make_entry(
        &self,
        inode: &Inode,
        name: &str,
        path: String,
        status: FsEntryStatus,
        dirent_off: Option<u64>,
        extra: HashMap<String, String>,
    ) -> FsEntry {
        let mut meta = HashMap::new();
        meta.insert("inode".into(), inode.ino.to_string());
        meta.insert("inode_offset".into(), format!("{:#x}", inode.disk_off));
        meta.insert("mode".into(), format!("{:#o}", inode.mode));
        meta.insert("uid".into(), inode.uid.to_string());
        meta.insert("gid".into(), inode.gid.to_string());
        meta.insert("nlink".into(), inode.nlink.to_string());
        meta.insert("generation".into(), inode.gen.to_string());
        meta.insert("inode_version".into(), inode.version.to_string());
        meta.insert("flags".into(), format!("{:#x}", inode.flags));
        if inode.flags2 != 0 {
            meta.insert("flags2".into(), format!("{:#x}", inode.flags2));
        }
        meta.insert(
            "di_format".into(),
            match inode.format {
                FMT_DEV => "dev",
                FMT_LOCAL => "local",
                FMT_EXTENTS => "extents",
                FMT_BTREE => "btree",
                _ => "unknown",
            }
            .into(),
        );
        meta.insert("nblocks".into(), inode.nblocks.to_string());
        if let Some(ok) = inode.crc_ok {
            meta.insert("inode_crc_ok".into(), ok.to_string());
        }
        if inode.next_unlinked != 0 {
            meta.insert(
                "next_unlinked".into(),
                format!("{:#x}", inode.next_unlinked),
            );
        }
        if let Some(off) = dirent_off {
            meta.insert("dirent_offset".into(), format!("{off:#x}"));
        }
        // Inline-fork slack: bytes in the literal area past the used data.
        if inode.format == FMT_LOCAL {
            let used = if inode.kind() == EntryKind::Directory {
                // sf dir: header + packed entries ≈ di_size bytes used.
                inode.size.min(inode.dfork().len() as u64)
            } else {
                inode.size.min(inode.dfork().len() as u64)
            };
            let slack = inode.dfork().len() as u64 - used;
            if slack > 0 {
                meta.insert(
                    "slack_offset".into(),
                    format!("{:#x}", inode.disk_off + inode.core as u64 + used),
                );
                meta.insert("slack_len".into(), slack.to_string());
            }
        }
        if inode.kind() == EntryKind::Symlink {
            if let Ok(t) = self.symlink_target(inode) {
                meta.insert("symlink_target".into(), t);
            }
        }
        if inode.format == FMT_DEV && inode.dfork().len() >= 4 {
            meta.insert(
                "rdev".into(),
                format!("{:#x}", u32_be(inode.dfork(), 0).unwrap_or(0)),
            );
        }
        // Extended attributes.
        match attr::collect(self.src.as_ref(), &self.sb, inode) {
            Ok(attrs) if !attrs.is_empty() => {
                meta.insert("xattr_count".into(), attrs.len().to_string());
                for a in &attrs {
                    let key = format!("xattr_{}", a.name.replace(['.', '-'], "_"));
                    meta.insert(
                        key.clone(),
                        match &a.value {
                            Some(v) if v.len() <= 64 => hex(v),
                            Some(v) => format!("{} bytes (local)", v.len()),
                            None => format!("{} bytes (remote)", a.value_len),
                        },
                    );
                    meta.insert(format!("{key}_flags"), format!("{:#04x}", a.flags));
                }
            }
            _ => {}
        }
        // Extents + slack for extent-mapped forks.
        let (ranges, status_final) = match status {
            FsEntryStatus::Live => {
                let exts = self.data_extents(inode).unwrap_or_default();
                let mut uw = 0u64;
                for e in &exts {
                    if e.unwritten {
                        uw += 1;
                    }
                }
                if uw > 0 {
                    meta.insert("unwritten_extents".into(), uw.to_string());
                }
                // Last-extent slack (allocated bytes beyond EOF).
                let alloc: u64 = exts.iter().map(|e| e.disk_len(&self.sb)).sum();
                if alloc > inode.size && inode.size > 0 {
                    // Find the extent containing file byte `size`.
                    let mut foff = 0u64;
                    for e in &exts {
                        let elen = e.disk_len(&self.sb);
                        if foff + elen > inode.size {
                            let off = e.disk_off(&self.sb) + (inode.size - foff);
                            meta.insert("slack_offset".into(), format!("{off:#x}"));
                            meta.insert("slack_len".into(), (foff + elen - inode.size).to_string());
                            break;
                        }
                        foff += elen;
                    }
                }
                (self.extent_ranges(&exts), status)
            }
            FsEntryStatus::Deleted { .. } => {
                let (state, surviving, notes) = self.assess_deleted(inode);
                for (i, n) in notes.iter().enumerate() {
                    meta.insert(format!("recovery_note_{i}"), n.clone());
                }
                (surviving, FsEntryStatus::Deleted { recovery: state })
            }
        };
        meta.extend(extra);
        let enc: &'static str = if inode.bigtime {
            "xfs-bigtime-ns"
        } else {
            "xfs-sec+nsec-be"
        };
        let ts = |raw: u64, v: i64| FsTimestamp {
            value: if raw == 0 { None } else { Some(v) },
            raw_value: raw,
            raw_encoding: enc,
            granularity: std::time::Duration::from_nanos(1),
        };
        let timestamps = Timestamps {
            modified: Some(ts(inode.mtime_raw, inode.mtime)),
            accessed: Some(ts(inode.atime_raw, inode.atime)),
            changed: Some(ts(inode.ctime_raw, inode.ctime)),
            created: inode
                .crtime_raw
                .map(|r| ts(r, inode.crtime.unwrap_or(0))),
            deleted: None,
        };
        let mut entry = FsEntry {
            path,
            name: name.to_string(),
            entry_id: inode.ino,
            kind: inode.kind(),
            size: inode.size,
            disk_offset: inode.disk_off,
            allocated_ranges: ranges,
            timestamps,
            status: status_final,
            meta,
            magic: None,
        };
        if self.opts.check_magic && entry.kind == EntryKind::File {
            if let Ok(mut r) = self.read_file(&entry) {
                let mut header = vec![0u8; 4096];
                if let Ok(n) = r.read(&mut header) {
                    header.truncate(n);
                    entry.magic = Some(sutram_magic::check_entry(&entry.name, &header));
                }
            }
        }
        entry
    }
}

impl FileSystem for XfsFs {
    fn info(&self) -> FsInfo {
        self.info.clone()
    }

    fn source(&self) -> Arc<dyn ByteSource> {
        self.src.clone()
    }

    fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
        Box::new(crate::walk::Walk::new(self))
    }

    fn read_file(&self, entry: &FsEntry) -> Result<Box<dyn Read + Send>> {
        match entry.kind {
            EntryKind::File | EntryKind::Other => {}
            _ => {
                return Err(FsError::InvalidInput {
                    msg: format!("cannot read {}: not a file", entry.path),
                })
            }
        }
        if entry.is_deleted() {
            // Surviving extents only, packed contiguously (convention).
            return Ok(Box::new(ExtentReader {
                src: self.src.clone(),
                ranges: entry.allocated_ranges.clone(),
                idx: 0,
                off_in: 0,
                remaining: entry.size,
            }));
        }
        // Live file: rebuild the logical→physical map from the inode so
        // sparse files read back with correct hole placement.
        let inode = self.inode(entry.entry_id)?;
        match inode.format {
            FMT_LOCAL => {
                let off = inode.disk_off + inode.core as u64;
                let len = inode.size.min(inode.dfork().len() as u64);
                Ok(Box::new(ExtentReader {
                    src: self.src.clone(),
                    ranges: vec![(off, len)],
                    idx: 0,
                    off_in: 0,
                    remaining: entry.size.min(len),
                }))
            }
            FMT_EXTENTS | FMT_BTREE => {
                let exts = self.data_extents(&inode)?;
                let map: Vec<(u64, u64, u64)> = exts
                    .iter()
                    .map(|e| {
                        (
                            e.file_off_bytes(&self.sb),
                            e.disk_off(&self.sb),
                            e.disk_len(&self.sb),
                        )
                    })
                    .collect();
                Ok(Box::new(SparseReader {
                    src: self.src.clone(),
                    exts: map,
                    size: entry.size.min(inode.size),
                    pos: 0,
                    idx: 0,
                }))
            }
            _ => Ok(Box::new(ExtentReader {
                src: self.src.clone(),
                ranges: Vec::new(),
                idx: 0,
                off_in: 0,
                remaining: 0,
            })),
        }
    }

    /// Free-space extents from every AG's bnobt — the carving ground.
    fn unallocated_ranges(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        for (agno, ag) in self.ags.iter().enumerate() {
            let base = self.sb.ag_off(agno as u32);
            let bs = self.sb.blocksize as u64;
            for &(start, len) in &ag.free {
                out.push((base + start as u64 * bs, len as u64 * bs));
            }
        }
        out
    }
}

fn u64be(b: &[u8], off: usize) -> u64 {
    sutram_io::le::u64_be(b, off).unwrap_or(0)
}

fn format_uuid(u: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13],
        u[14], u[15]
    )
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Sequential reader over byte ranges, capped at `remaining` logical
/// bytes — live files (contiguous extents) and deleted entries
/// (surviving extents only).
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
            let avail = len.saturating_sub(self.off_in);
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

/// Sparse-aware reader for live extent/btree-mapped files: holes in the
/// logical file map read back as zeros.
struct SparseReader {
    src: Arc<dyn ByteSource>,
    /// (fileoff_bytes, disk_off, len_bytes) sorted by fileoff.
    exts: Vec<(u64, u64, u64)>,
    size: u64,
    pos: u64,
    idx: usize,
}

impl Read for SparseReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.size {
            return Ok(0);
        }
        // Advance past extents that end before pos.
        while self.idx < self.exts.len() && self.exts[self.idx].0 + self.exts[self.idx].2 <= self.pos
        {
            self.idx += 1;
        }
        let file_end = self.size.min(self.pos + buf.len() as u64);
        if self.idx >= self.exts.len() || self.exts[self.idx].0 > self.pos {
            // Hole: zero-fill up to next extent start or EOF.
            let hole_end = if self.idx < self.exts.len() {
                self.exts[self.idx].0.min(file_end)
            } else {
                file_end
            };
            let n = (hole_end - self.pos) as usize;
            buf[..n].fill(0);
            self.pos += n as u64;
            return Ok(n);
        }
        let (foff, doff, elen) = self.exts[self.idx];
        let within = self.pos - foff;
        let avail = (elen - within).min(file_end - self.pos);
        let want = buf.len().min(avail as usize);
        let n = self.src.read_at(doff + within, &mut buf[..want])?;
        self.pos += n as u64;
        Ok(n)
    }
}
