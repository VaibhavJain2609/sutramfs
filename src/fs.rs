//! [`FatFs`] — the mounted filesystem: FAT access, cluster chains,
//! directory-table reading, recovery analysis and the `FileSystem` impl.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;

use sutram_fs::util;
use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsError, FsInfo, FsParser, FileSystem, MountOptions,
    RecoveryState, Result,
};
use sutram_io::ByteSource;

use crate::boot::{BootSector, FatType};
use crate::dirent;
use crate::walk::{DirLoc, Walk};

/// The parser entry point — stateless, cheap to construct.
///
/// ```
/// use sutram_fat::FatParser;
/// use sutram_fs::FsParser;
/// let p = FatParser;
/// assert_eq!(p.name(), "fat");
/// ```
pub struct FatParser;

impl FsParser for FatParser {
    fn name(&self) -> &'static str {
        "fat"
    }

    fn detect(&self, src: &dyn ByteSource) -> DetectConfidence {
        BootSector::detect(src)
    }

    fn mount_with(
        &self,
        src: Arc<dyn ByteSource>,
        opts: &MountOptions,
    ) -> Result<Box<dyn FileSystem>> {
        Ok(Box::new(FatFs::mount(src, opts.clone())?))
    }
}

/// A mounted FAT12/16/32 volume.
pub struct FatFs {
    src: Arc<dyn ByteSource>,
    pub(crate) bs: BootSector,
    pub(crate) opts: MountOptions,
    /// Clusters claimed by *live* entries → owning path. Built once at
    /// mount by a metadata-only scan; drives deleted-overwrite analysis
    /// and orphan detection.
    pub(crate) live: HashMap<u32, String>,
    /// Label found in a root-dir volume-label entry, if any.
    dir_label: Option<String>,
}

impl FatFs {
    pub(crate) fn mount(src: Arc<dyn ByteSource>, opts: MountOptions) -> Result<Self> {
        let bs = BootSector::parse(src.as_ref())?;
        let mut fs = FatFs {
            src,
            bs,
            opts,
            live: HashMap::new(),
            dir_label: None,
        };
        fs.scan_live();
        Ok(fs)
    }

    /// Bytes offset + length of cluster `n` (n ≥ 2).
    pub(crate) fn cluster_range(&self, n: u32) -> (u64, u64) {
        let off = self.bs.data_offset + (n as u64 - 2) * self.bs.cluster_size;
        (off, self.bs.cluster_size)
    }

    /// Read one FAT entry (masked to entry width). Returns the raw value —
    /// 0 = free, ≥ EOC = end, `bad` = bad cluster.
    pub(crate) fn fat_entry(&self, cluster: u32) -> Result<u32> {
        let bits = self.bs.fat_type.entry_bits() as u64;
        let byte_off = self.bs.fat_offset + (cluster as u64 * bits) / 8;
        let raw = match self.bs.fat_type {
            FatType::Fat12 => {
                let b = self.src.read_slice(byte_off, 2).map_err(FsError::Io)?;
                if b.len() < 2 {
                    return Err(FsError::truncated(byte_off, 2, b.len() as u64));
                }
                let v = u16::from_le_bytes([b[0], b[1]]) as u32;
                if cluster & 1 == 1 {
                    v >> 4
                } else {
                    v & 0x0FFF
                }
            }
            FatType::Fat16 => {
                let b = self.src.read_slice(byte_off, 2).map_err(FsError::Io)?;
                if b.len() < 2 {
                    return Err(FsError::truncated(byte_off, 2, b.len() as u64));
                }
                u16::from_le_bytes([b[0], b[1]]) as u32
            }
            FatType::Fat32 => {
                let b = self.src.read_slice(byte_off, 4).map_err(FsError::Io)?;
                if b.len() < 4 {
                    return Err(FsError::truncated(byte_off, 4, b.len() as u64));
                }
                u32::from_le_bytes([b[0], b[1], b[2], b[3]]) & 0x0FFF_FFFF
            }
        };
        Ok(raw & self.bs.fat_type.mask())
    }

    /// Follow the FAT chain from `start`, bounded by `max` links
    /// (`usize::MAX` for "whole chain" — the real bound is
    /// `count_of_clusters`, enforced by the visited-set loop guard).
    ///
    /// Stops (without error) at EOC, free (0) or bad markers, loops, and
    /// out-of-range links — all normal on corrupt or partially-reused FATs.
    /// Hard failures (I/O) surface as `Err`.
    pub(crate) fn chain(&self, start: u32, max: usize) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut c = start;
        while out.len() < max
            && c >= 2
            && c < self.bs.count_of_clusters as u32 + 2
            && seen.insert(c)
        {
            let v = self.fat_entry(c)?;
            if v == self.bs.fat_type.bad() {
                break;
            }
            out.push(c);
            if v >= self.bs.fat_type.eoc() {
                break;
            }
            if v == 0 {
                break; // freed/zeroed link — chain ends here
            }
            c = v;
        }
        Ok(out)
    }

    /// Byte extents for a cluster chain.
    pub(crate) fn chain_ranges(&self, chain: &[u32]) -> Vec<(u64, u64)> {
        chain.iter().map(|&c| self.cluster_range(c)).collect()
    }

    /// Load a directory's raw entry table + a logical→disk offset map.
    ///
    /// Bounded: one directory's bytes at a time.
    pub(crate) fn read_dir(&self, loc: &DirLoc) -> Result<(Vec<u8>, Vec<(u64, u64, u64)>)> {
        match *loc {
            DirLoc::RootRegion => {
                let data = self
                    .src
                    .read_slice(self.bs.root_dir_offset, self.bs.root_dir_size as usize)
                    .map_err(FsError::Io)?;
                Ok((
                    data,
                    vec![(0, self.bs.root_dir_offset, self.bs.root_dir_size)],
                ))
            }
            DirLoc::Chain(start) => {
                let clusters = self.chain(start, usize::MAX)?;
                if clusters.is_empty() {
                    return Ok((Vec::new(), Vec::new()));
                }
                let mut data = Vec::with_capacity(clusters.len() * self.bs.cluster_size as usize);
                let mut map = Vec::with_capacity(clusters.len());
                let mut logical = 0u64;
                for &c in &clusters {
                    let (off, len) = self.cluster_range(c);
                    let chunk = self.src.read_slice(off, len as usize).map_err(FsError::Io)?;
                    let got = chunk.len() as u64;
                    data.extend_from_slice(&chunk);
                    map.push((logical, off, got));
                    logical += got;
                    if got < len {
                        break; // truncated image — emit what we have
                    }
                }
                Ok((data, map))
            }
        }
    }

    /// Metadata-only pass over the live tree: fills `live` (cluster → path)
    /// and captures the root volume label. Lenient — errors are ignored;
    /// the walk reports them properly.
    fn scan_live(&mut self) {
        let mut stack: Vec<(String, DirLoc)> = vec![(
            "/".into(),
            if self.bs.fat_type == FatType::Fat32 {
                DirLoc::Chain(self.bs.root_cluster)
            } else {
                DirLoc::RootRegion
            },
        )];
        // The root dir's own clusters are live too (FAT32).
        if let DirLoc::Chain(c) = stack[0].1 {
            if let Ok(chain) = self.chain(c, usize::MAX) {
                for cl in chain {
                    self.live.insert(cl, "/".to_string());
                }
            }
        }
        let mut visited_dirs: HashSet<u32> = HashSet::new();
        while let Some((path, loc)) = stack.pop() {
            if let DirLoc::Chain(c) = loc {
                if !visited_dirs.insert(c) {
                    continue;
                }
            }
            let Ok((data, _map)) = self.read_dir(&loc) else {
                continue;
            };
            for chunk in data.chunks_exact(32) {
                match dirent::parse_slot(chunk) {
                    dirent::Slot::EndOfDir => break,
                    dirent::Slot::Lfn(_) => {}
                    dirent::Slot::Entry(e) => {
                        if e.deleted || e.is_volume_label() {
                            if e.is_volume_label() && path == "/" && self.dir_label.is_none() {
                                self.dir_label =
                                    Some(String::from_utf8_lossy(&e.raw_name).trim_end().into());
                            }
                            continue;
                        }
                        let name = dirent::name83(&e);
                        if name == "." || name == ".." {
                            continue;
                        }
                        let child_path = util::join_path(&path, &name);
                        // Claim the clusters this entry actually *needs*:
                        // ceil(size/csz) for files (tail clusters of a
                        // longer surviving chain may still hold a deleted
                        // file's bytes — they stay unclaimed for the
                        // recovery analysis), whole chain for directories.
                        if e.first_cluster >= 2 {
                            let needed = if e.is_dir() {
                                usize::MAX
                            } else {
                                (e.size as u64)
                                    .div_ceil(self.bs.cluster_size)
                                    .max(1) as usize
                            };
                            if let Ok(chain) = self.chain(e.first_cluster, needed) {
                                for cl in chain {
                                    self.live.entry(cl).or_insert(child_path.clone());
                                }
                            }
                        }
                        if e.is_dir() && e.first_cluster >= 2 {
                            stack.push((child_path, DirLoc::Chain(e.first_cluster)));
                        }
                    }
                }
            }
        }
    }

    /// Recovery assessment for a deleted entry: which of its expected
    /// clusters survive vs. were reallocated to a live file.
    ///
    /// Returns `(state, surviving_extents, expected_chain_len)`.
    pub(crate) fn recovery_for(
        &self,
        first_cluster: u32,
        size: u64,
    ) -> (RecoveryState, Vec<(u64, u64)>, Vec<String>) {
        let csz = self.bs.cluster_size;
        let expected = size.div_ceil(csz) as usize;
        let mut notes = Vec::new();
        if size == 0 {
            return (RecoveryState::Intact, Vec::new(), notes);
        }
        if first_cluster < 2 {
            notes.push("entry records no start cluster".into());
            return (RecoveryState::Unrecoverable, Vec::new(), notes);
        }
        let mut chain = match self.chain(first_cluster, expected) {
            Ok(c) => c,
            Err(e) => {
                notes.push(format!("FAT read failed: {e}"));
                return (RecoveryState::Unknown, Vec::new(), notes);
            }
        };
        if chain.is_empty() {
            // FAT link freed/zeroed — the start cluster's data may persist;
            // report it as a candidate extent but flag the uncertainty.
            notes.push("cluster chain freed; start cluster is a candidate only".into());
            if self.live.contains_key(&first_cluster) {
                return (RecoveryState::Unrecoverable, Vec::new(), notes);
            }
            chain.push(first_cluster);
        } else if chain.len() < expected {
            notes.push(format!(
                "cluster chain truncated: {} of {expected} expected clusters linked",
                chain.len()
            ));
        }
        let mut surviving = Vec::new();
        let mut lost = 0usize;
        for &c in &chain {
            if self.live.contains_key(&c) {
                lost += 1;
            } else {
                surviving.push(c);
            }
        }
        if lost > 0 {
            notes.push(format!(
                "{lost} cluster(s) reallocated to live file(s): {}",
                chain
                    .iter()
                    .filter(|c| self.live.contains_key(c))
                    .map(|c| format!("{c}→{}", self.live[c]))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        let recovered_bytes = (surviving.len() as u64 * csz).min(size);
        let ranges = self.chain_ranges(&surviving);
        let state = if surviving.len() >= expected && !chain.is_empty() && lost == 0 {
            RecoveryState::Intact
        } else if recovered_bytes == 0 {
            RecoveryState::Unrecoverable
        } else {
            RecoveryState::PartiallyOverwritten {
                recovered_bytes,
                total_bytes: size,
            }
        };
        (state, ranges, notes)
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

    /// Count free clusters by streaming the FAT (bounded memory).
    fn count_free(&self) -> Option<u64> {
        let mut free = 0u64;
        for c in 2..self.bs.count_of_clusters as u32 + 2 {
            match self.fat_entry(c) {
                Ok(0) => free += 1,
                Ok(_) => {}
                Err(_) => return None,
            }
        }
        Some(free)
    }
}

impl FileSystem for FatFs {
    fn info(&self) -> FsInfo {
        let mut meta = HashMap::new();
        meta.insert("fat_variant".into(), self.bs.fat_type.name().into());
        meta.insert("oem".into(), self.bs.oem.clone());
        meta.insert("num_fats".into(), self.bs.num_fats.to_string());
        meta.insert("media".into(), format!("{:#04x}", self.bs.media));
        meta.insert("sectors_per_cluster".into(), self.bs.sectors_per_cluster.to_string());
        meta.insert("reserved_sectors".into(), self.bs.reserved_sectors.to_string());
        meta.insert(
            "root_entries".into(),
            self.bs.root_entry_count.to_string(),
        );
        meta.insert(
            "bytes_per_sector".into(),
            self.bs.bytes_per_sector.to_string(),
        );
        meta.insert(
            "fat_size_sectors".into(),
            self.bs.fat_size_sectors.to_string(),
        );
        meta.insert(
            "total_sectors".into(),
            self.bs.total_sectors.to_string(),
        );
        FsInfo {
            fs_type: self.bs.fat_type.name().into(),
            label: self.dir_label.clone().or_else(|| self.bs.volume_label.clone()),
            uuid: self
                .bs
                .volume_id
                .map(|v| format!("{:04X}-{:04X}", v >> 16, v & 0xFFFF)),
            block_size: self.bs.cluster_size,
            total_blocks: self.bs.count_of_clusters,
            free_blocks: self.count_free(),
            total_nodes: None,
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
            EntryKind::File | EntryKind::Other => {}
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

    /// Free clusters as byte ranges (the carving ground) plus — per
    /// CONVENTIONS.md — callers combine this with per-entry `slack_*`
    /// meta keys for file slack.
    fn unallocated_ranges(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut run_start: Option<u32> = None;
        for c in 2..=self.bs.count_of_clusters as u32 + 1 {
            let free = self.fat_entry(c).map(|v| v == 0).unwrap_or(false);
            match (free, run_start) {
                (true, None) => run_start = Some(c),
                (false, Some(s)) => {
                    let (off, _) = self.cluster_range(s);
                    let (end_off, clen) = self.cluster_range(c - 1);
                    out.push((off, end_off + clen - off));
                    run_start = None;
                }
                _ => {}
            }
        }
        if let Some(s) = run_start {
            let (off, _) = self.cluster_range(s);
            let (end_off, clen) = self.cluster_range(self.bs.count_of_clusters as u32 + 1);
            out.push((off, end_off + clen - off));
        }
        out
    }
}

/// Sequential reader over a list of byte extents, capped at `remaining`
/// logical bytes — used for both live files and the surviving extents of
/// deleted ones.
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
