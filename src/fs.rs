//! [`ExFatFs`] — the mounted filesystem: FAT access, the allocation bitmap,
//! directory reading, recovery analysis, and the `FileSystem` impl.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;

use sutram_fs::util;
use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsError, FsInfo, FsParser, FileSystem, MountOptions,
    RecoveryState, Result,
};
use sutram_io::ByteSource;

use crate::boot::{BootSector, BAD_CLUSTER, EOC_MIN};
use crate::dirent;
use crate::walk::{DirLoc, Walk};

/// Safety cap on one directory's byte size (guards absurd DataLength values
/// on corrupt images; a legitimate exFAT directory essentially never
/// approaches this).
const MAX_DIR_BYTES: u64 = 256 * 1024 * 1024;
/// Cap on the allocation bitmap we load into memory
/// (ClusterCount bits ≈ 32 MiB for a 32 MiB-clustered 8 TiB volume).
const MAX_BITMAP_BYTES: u64 = 512 * 1024 * 1024;

/// A directory's raw entry-table bytes plus its logical→disk offset map
/// (`(logical_start, disk_offset, len)` per extent).
pub(crate) type DirData = (Vec<u8>, Vec<(u64, u64, u64)>);

/// The parser entry point — stateless, cheap to construct.
///
/// ```
/// use sutram_exfat::ExFatParser;
/// use sutram_fs::FsParser;
/// let p = ExFatParser;
/// assert_eq!(p.name(), "exfat");
/// ```
pub struct ExFatParser;

impl FsParser for ExFatParser {
    fn name(&self) -> &'static str {
        "exfat"
    }

    fn detect(&self, src: &dyn ByteSource) -> DetectConfidence {
        BootSector::detect(src)
    }

    fn mount_with(
        &self,
        src: Arc<dyn ByteSource>,
        opts: &MountOptions,
    ) -> Result<Box<dyn FileSystem>> {
        Ok(Box::new(ExFatFs::mount(src, opts.clone())?))
    }
}

/// A mounted exFAT volume.
pub struct ExFatFs {
    src: Arc<dyn ByteSource>,
    pub(crate) bs: BootSector,
    pub(crate) opts: MountOptions,
    /// Raw allocation-bitmap bytes: bit `c - 2` of the bitmap is cluster
    /// `c`'s allocation state. `None` when the volume has none readable —
    /// recovery analysis then degrades to live-map only (documented).
    pub(crate) bitmap: Option<Vec<u8>>,
    /// Clusters claimed by *live* entries → owning path. Built once at
    /// mount by a metadata-only scan; drives overwrite analysis and the
    /// orphan pass.
    pub(crate) live: HashMap<u32, String>,
    /// Volume label from a root-directory `0x83` entry.
    label: Option<String>,
    /// `(first_cluster, data_len)` of the allocation bitmap entry.
    bitmap_loc: Option<(u32, u64)>,
    /// `(checksum, first_cluster, data_len)` of the up-case table.
    upcase: Option<(u32, u64, u32)>,
}

impl ExFatFs {
    pub(crate) fn mount(src: Arc<dyn ByteSource>, opts: MountOptions) -> Result<Self> {
        let bs = BootSector::parse(src.as_ref())?;
        if opts.strict && !bs.checksum_ok {
            return Err(FsError::corrupt(
                11 * bs.bytes_per_sector,
                "main boot-region checksum mismatch (strict mode)",
            ));
        }
        let mut fs = ExFatFs {
            src,
            bs,
            opts,
            bitmap: None,
            live: HashMap::new(),
            label: None,
            bitmap_loc: None,
            upcase: None,
        };
        fs.scan_root_meta();
        fs.load_bitmap();
        fs.scan_live();
        Ok(fs)
    }

    // ------------------------------------------------------------------
    // Cluster / FAT plumbing
    // ------------------------------------------------------------------

    /// Byte range of cluster `c` (`None` if out of range).
    pub(crate) fn cluster_range(&self, c: u32) -> Option<(u64, u64)> {
        self.bs.cluster_range(c)
    }

    pub(crate) fn valid_cluster(&self, c: u32) -> bool {
        self.bs.valid_cluster(c)
    }

    /// Read one FAT entry. Raw value: 0 = free, ≥ `0xFFFFFFF8` = EOC,
    /// `0xFFFFFFF7` = bad, else next cluster.
    pub(crate) fn fat_entry(&self, cluster: u32) -> Result<u32> {
        let off = self.bs.fat_offset + cluster as u64 * 4;
        let b = self.src.read_slice(off, 4).map_err(FsError::Io)?;
        if b.len() < 4 {
            return Err(FsError::truncated(off, 4, b.len() as u64));
        }
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Follow the FAT chain from `start`, bounded by `max` links and by the
    /// visited-set loop guard (untrusted images contain cycles).
    ///
    /// Stops without error at EOC, free (0) or bad markers, loops, and
    /// out-of-range links — all normal on corrupt or partially reused FATs.
    pub(crate) fn chain(&self, start: u32, max: usize) -> Result<Vec<u32>> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut c = start;
        while out.len() < max && self.valid_cluster(c) && seen.insert(c) {
            let v = self.fat_entry(c)?;
            if v == BAD_CLUSTER {
                break;
            }
            out.push(c);
            if v >= EOC_MIN || v == 0 {
                break;
            }
            c = v;
        }
        Ok(out)
    }

    /// Byte extents for a cluster list, merging contiguous runs.
    pub(crate) fn chain_ranges(&self, chain: &[u32]) -> Vec<(u64, u64)> {
        let mut out: Vec<(u64, u64)> = Vec::new();
        for &c in chain {
            if let Some((off, len)) = self.cluster_range(c) {
                if let Some(last) = out.last_mut() {
                    if last.0 + last.1 == off {
                        last.1 += len;
                        continue;
                    }
                }
                out.push((off, len));
            }
        }
        out
    }

    /// Contiguous extent for a `NoFatChain` object: `ceil(len/csz)`
    /// clusters starting at `fc`, clipped to the heap.
    pub(crate) fn contiguous_clusters(&self, fc: u32, len: u64) -> Vec<u32> {
        if !self.valid_cluster(fc) || len == 0 {
            return Vec::new();
        }
        let needed = len.div_ceil(self.bs.cluster_size);
        let max_n = self.bs.cluster_count as u64 + 2 - fc as u64;
        (0..needed.min(max_n)).map(|i| fc + i as u32).collect()
    }

    // ------------------------------------------------------------------
    // Allocation bitmap
    // ------------------------------------------------------------------

    /// Bitmap bit for cluster `c`: `Some(true)` = allocated.
    /// `None` when there is no bitmap or `c` is beyond it.
    pub(crate) fn bitmap_bit(&self, c: u32) -> Option<bool> {
        let bm = self.bitmap.as_ref()?;
        if !self.valid_cluster(c) {
            return None;
        }
        let idx = (c - 2) as usize;
        bm.get(idx / 8).map(|byte| (byte >> (idx % 8)) & 1 == 1)
    }

    /// Allocation status used by the orphan pass: the bitmap is
    /// authoritative; without it, a nonzero FAT entry is the fallback
    /// (documented limitation — freed-but-chained clusters then hide).
    pub(crate) fn allocated(&self, c: u32) -> bool {
        match self.bitmap_bit(c) {
            Some(b) => b,
            None => self.fat_entry(c).map(|v| v != 0).unwrap_or(false),
        }
    }

    // ------------------------------------------------------------------
    // Directory reading
    // ------------------------------------------------------------------

    /// Load a directory's raw entry bytes + a logical→disk offset map.
    /// Bounded: one directory at a time, capped at [`MAX_DIR_BYTES`].
    pub(crate) fn read_dir(&self, loc: &DirLoc) -> Result<DirData> {
        let csz = self.bs.cluster_size;
        if loc.contiguous {
            // NoFatChain directory: one extent.
            let Some((off, _)) = self.cluster_range(loc.first_cluster) else {
                return Ok((Vec::new(), Vec::new()));
            };
            let want = loc
                .len
                .div_ceil(csz)
                .saturating_mul(csz)
                .min(MAX_DIR_BYTES);
            let heap_end = self.bs.heap_offset + self.bs.cluster_count as u64 * csz;
            let want = want.min(heap_end.saturating_sub(off));
            let chunk = self.src.read_slice(off, want as usize).map_err(FsError::Io)?;
            let got = chunk.len() as u64;
            return Ok((chunk, vec![(0, off, got)]));
        }
        // FAT-chained directory: cap at the declared length when known.
        let cap = if loc.len > 0 {
            (loc.len.div_ceil(csz)).min(MAX_DIR_BYTES / csz) as usize
        } else {
            usize::MAX
        };
        let clusters = self.chain(loc.first_cluster, cap)?;
        if clusters.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let mut data = Vec::with_capacity(clusters.len() * csz as usize);
        let mut map = Vec::with_capacity(clusters.len());
        let mut logical = 0u64;
        for &c in &clusters {
            if let Some((off, len)) = self.cluster_range(c) {
                let chunk = self.src.read_slice(off, len as usize).map_err(FsError::Io)?;
                let got = chunk.len() as u64;
                data.extend_from_slice(&chunk);
                map.push((logical, off, got));
                logical += got;
                if got < len {
                    break; // truncated image — emit what we have
                }
            }
        }
        Ok((data, map))
    }

    /// First mount pass: scan the *root* directory for the well-known
    /// metadata entries — allocation bitmap, up-case table, volume label.
    fn scan_root_meta(&mut self) {
        let loc = DirLoc {
            first_cluster: self.bs.root_cluster,
            contiguous: false,
            len: 0,
        };
        let Ok((data, _)) = self.read_dir(&loc) else {
            return;
        };
        for chunk in data.chunks_exact(32) {
            if !dirent::in_use(chunk[0]) {
                continue; // deleted metadata entries are not authoritative
            }
            match dirent::code(chunk[0]) {
                dirent::CODE_BITMAP => {
                    if self.bitmap_loc.is_none() {
                        let (_flags, fc, len) = dirent::parse_bitmap(chunk);
                        self.bitmap_loc = Some((fc, len));
                        // Metadata clusters are live allocations — claim
                        // them so the orphan pass doesn't false-positive.
                        self.claim(fc, len, false, false, "/$META/bitmap");
                    }
                }
                dirent::CODE_UPCASE => {
                    let (sum, fc, len) = dirent::parse_upcase(chunk);
                    self.upcase = Some((fc, len, sum));
                    self.claim(fc, len, false, false, "/$META/upcase");
                }
                dirent::CODE_LABEL if self.label.is_none() => {
                    let l = dirent::parse_label(chunk);
                    if !l.is_empty() {
                        self.label = Some(l);
                    }
                }
                _ => {}
            }
        }
    }

    /// Load the allocation bitmap bytes (bounded by [`MAX_BITMAP_BYTES`]).
    fn load_bitmap(&mut self) {
        let Some((fc, len)) = self.bitmap_loc else {
            return;
        };
        let csz = self.bs.cluster_size;
        let want = len
            .min((self.bs.cluster_count as u64).div_ceil(8))
            .min(MAX_BITMAP_BYTES);
        if want == 0 || !self.valid_cluster(fc) {
            return;
        }
        let needed = want.div_ceil(csz) as usize;
        // The bitmap is normally contiguous; follow the FAT chain first and
        // extend contiguously if the links were damaged.
        let mut clusters = self.chain(fc, needed).unwrap_or_default();
        if clusters.len() < needed {
            let mut next = clusters.last().copied().unwrap_or(fc).saturating_add(1);
            while clusters.len() < needed && self.valid_cluster(next) {
                clusters.push(next);
                next += 1;
            }
        }
        let mut bm = Vec::with_capacity(want as usize);
        for &c in &clusters {
            if let Some((off, cl)) = self.cluster_range(c) {
                if let Ok(chunk) = self.src.read_slice(off, cl as usize) {
                    bm.extend_from_slice(&chunk);
                }
            }
        }
        bm.truncate(want as usize);
        if !bm.is_empty() {
            self.bitmap = Some(bm);
        }
    }

    /// Metadata-only pass over the live tree: fills `live` (cluster →
    /// path). Lenient — errors are ignored; the walk reports them properly.
    fn scan_live(&mut self) {
        let mut stack: Vec<(String, DirLoc)> = vec![(
            "/".into(),
            DirLoc {
                first_cluster: self.bs.root_cluster,
                contiguous: false,
                len: 0,
            },
        )];
        let mut visited: HashSet<u32> = HashSet::new();
        while let Some((path, loc)) = stack.pop() {
            if !visited.insert(loc.first_cluster) {
                continue;
            }
            // The directory's own clusters are live.
            self.claim(loc.first_cluster, loc.len, loc.contiguous, true, &path);
            let Ok((data, _)) = self.read_dir(&loc) else {
                continue;
            };
            let mut pos = 0usize;
            while pos + 32 <= data.len() {
                let t = data[pos];
                if t != 0 && dirent::in_use(t) && dirent::code(t) == dirent::CODE_FILE {
                    if let Ok((set, used)) = dirent::parse_file_set(&data, pos) {
                        let child = set
                            .name
                            .clone()
                            .map(|n| util::join_path(&path, &n))
                            .unwrap_or_else(|| path.clone());
                        self.claim(
                            set.first_cluster,
                            set.data_len,
                            set.no_fat_chain,
                            set.is_dir(),
                            &child,
                        );
                        if set.is_dir() && self.valid_cluster(set.first_cluster) {
                            stack.push((
                                child,
                                DirLoc {
                                    first_cluster: set.first_cluster,
                                    contiguous: set.no_fat_chain,
                                    len: set.data_len,
                                },
                            ));
                        }
                        pos += used * 32;
                        continue;
                    }
                }
                pos += 32;
            }
        }
    }

    /// Insert `fc..`'s clusters into the live map.
    fn claim(&mut self, fc: u32, data_len: u64, contiguous: bool, is_dir: bool, path: &str) {
        if !self.valid_cluster(fc) {
            return;
        }
        let clusters = if contiguous {
            self.contiguous_clusters(fc, data_len.max(1))
        } else {
            // For files claim only what the allocation needs; directories
            // claim their whole chain.
            let cap = if is_dir {
                usize::MAX
            } else {
                data_len.div_ceil(self.bs.cluster_size).max(1) as usize
            };
            self.chain(fc, cap).unwrap_or_default()
        };
        for c in clusters {
            self.live.entry(c).or_insert_with(|| path.to_string());
        }
    }

    // ------------------------------------------------------------------
    // Recovery analysis
    // ------------------------------------------------------------------

    /// Recovery assessment for a deleted entry set: which expected clusters
    /// survive vs. were reallocated (per the allocation bitmap, or the live
    /// map when no bitmap exists).
    ///
    /// Returns `(state, surviving_extents, notes)`.
    pub(crate) fn recovery_for(
        &self,
        first_cluster: u32,
        size: u64,
        data_len: u64,
        no_fat_chain: bool,
    ) -> (RecoveryState, Vec<(u64, u64)>, Vec<String>) {
        let csz = self.bs.cluster_size;
        let mut notes = Vec::new();
        let total = data_len.max(size);
        if total == 0 {
            return (RecoveryState::Intact, Vec::new(), notes);
        }
        if !self.valid_cluster(first_cluster) {
            notes.push("entry records no usable start cluster".into());
            return (RecoveryState::Unrecoverable, Vec::new(), notes);
        }
        let needed = total
            .div_ceil(csz)
            .min(self.bs.cluster_count as u64) as usize;

        // Expected cluster list.
        let mut expected: Vec<u32> = if no_fat_chain {
            self.contiguous_clusters(first_cluster, total)
        } else {
            match self.chain(first_cluster, needed) {
                Ok(ch) => ch,
                Err(e) => {
                    notes.push(format!("FAT read failed: {e}"));
                    return (RecoveryState::Unknown, Vec::new(), notes);
                }
            }
        };
        if expected.is_empty() {
            notes.push("start cluster not reachable; it is a candidate only".into());
            expected.push(first_cluster);
        } else if expected.len() < needed {
            // The FAT chain broke early (e.g. a link was overwritten by a
            // reallocation). exFAT allocates contiguously by default, so the
            // missing tail is assumed contiguous — each candidate cluster is
            // still verified against the bitmap before being reported.
            notes.push(format!(
                "cluster chain truncated: {} of {needed} expected clusters linked; \
                 tail assumed contiguous",
                expected.len()
            ));
            let mut next = expected.last().copied().unwrap_or(first_cluster) + 1;
            while expected.len() < needed && self.valid_cluster(next) {
                expected.push(next);
                next += 1;
            }
        }

        let mut surviving: Vec<u32> = Vec::new();
        let mut lost: Vec<u32> = Vec::new();
        for &c in &expected {
            let taken = match self.bitmap_bit(c) {
                // The bitmap is authoritative: bit set means the cluster is
                // allocated to something else now (deletion clears bits).
                Some(b) => b,
                // No bitmap — fall back to the live-claimed map.
                None => self.live.contains_key(&c),
            };
            if taken {
                lost.push(c);
            } else {
                surviving.push(c);
            }
        }
        if !lost.is_empty() {
            notes.push(format!(
                "{} cluster(s) reallocated{}",
                lost.len(),
                if self.bitmap.is_some() {
                    " (bitmap marks them allocated)"
                } else {
                    ""
                }
            ));
            let owners: Vec<String> = lost
                .iter()
                .filter_map(|c| self.live.get(c).map(|p| format!("{c}→{p}")))
                .collect();
            if !owners.is_empty() {
                notes.push(format!("now owned by: {}", owners.join(", ")));
            }
        }
        let recovered_bytes = (surviving.len() as u64 * csz).min(size.max(total));
        let ranges = self.chain_ranges(&surviving);
        let state = if lost.is_empty() && surviving.len() >= needed {
            RecoveryState::Intact
        } else if surviving.is_empty() {
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

    /// Count free clusters from the bitmap (bounded scan).
    fn count_free(&self) -> Option<u64> {
        let bm = self.bitmap.as_ref()?;
        let mut free = 0u64;
        for c in 2..self.bs.cluster_count + 2 {
            let idx = (c - 2) as usize;
            if bm
                .get(idx / 8)
                .map(|b| (b >> (idx % 8)) & 1 == 0)
                .unwrap_or(false)
            {
                free += 1;
            }
        }
        Some(free)
    }
}

impl FileSystem for ExFatFs {
    fn info(&self) -> FsInfo {
        let mut meta = HashMap::new();
        meta.insert("oem".into(), "EXFAT   ".into());
        meta.insert(
            "partition_offset_sectors".into(),
            self.bs.partition_offset_sectors.to_string(),
        );
        meta.insert(
            "bytes_per_sector".into(),
            self.bs.bytes_per_sector.to_string(),
        );
        meta.insert(
            "sectors_per_cluster".into(),
            self.bs.sectors_per_cluster.to_string(),
        );
        meta.insert(
            "total_sectors".into(),
            self.bs.volume_length_sectors.to_string(),
        );
        meta.insert(
            "fat_offset_sectors".into(),
            self.bs.fat_offset_sectors.to_string(),
        );
        meta.insert(
            "fat_length_sectors".into(),
            self.bs.fat_length_sectors.to_string(),
        );
        meta.insert(
            "cluster_heap_offset_sectors".into(),
            self.bs.heap_offset_sectors.to_string(),
        );
        meta.insert("cluster_count".into(), self.bs.cluster_count.to_string());
        meta.insert("root_cluster".into(), self.bs.root_cluster.to_string());
        meta.insert("num_fats".into(), self.bs.num_fats.to_string());
        meta.insert("media".into(), format!("{:#04x}", self.bs.drive_select));
        meta.insert(
            "percent_in_use".into(),
            self.bs.percent_in_use.to_string(),
        );
        meta.insert(
            "fs_revision".into(),
            format!("{}.{:02}", self.bs.revision >> 8, self.bs.revision & 0xFF),
        );
        meta.insert(
            "volume_flags".into(),
            format!("{:#06x}", self.bs.volume_flags),
        );
        meta.insert("boot_checksum_ok".into(), self.bs.checksum_ok.to_string());
        meta.insert("backup_boot_ok".into(), self.bs.backup_ok.to_string());
        meta.insert(
            "backup_checksum_ok".into(),
            self.bs.backup_checksum_ok.to_string(),
        );
        meta.insert("bitmap_present".into(), self.bitmap.is_some().to_string());
        if let Some((fc, len, sum)) = self.upcase {
            meta.insert("upcase_cluster".into(), fc.to_string());
            meta.insert("upcase_checksum".into(), format!("{sum:#010x}"));
            meta.insert("upcase_length".into(), len.to_string());
        }
        FsInfo {
            fs_type: "exFAT".into(),
            label: self.label.clone(),
            uuid: Some(format!(
                "{:04X}-{:04X}",
                self.bs.serial >> 16,
                self.bs.serial & 0xFFFF
            )),
            block_size: self.bs.cluster_size,
            total_blocks: self.bs.cluster_count as u64,
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

    /// Free clusters per the allocation bitmap — the carving ground.
    /// Callers combine this with per-entry `slack_*` meta keys.
    fn unallocated_ranges(&self) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut run_start: Option<u32> = None;
        for c in 2..self.bs.cluster_count + 2 {
            let free = self.bitmap_bit(c).map(|b| !b).unwrap_or(false);
            match (free, run_start) {
                (true, None) => run_start = Some(c),
                (false, Some(s)) => {
                    if let (Some((off, _)), Some((eoff, elen))) =
                        (self.cluster_range(s), self.cluster_range(c - 1))
                    {
                        out.push((off, eoff + elen - off));
                    }
                    run_start = None;
                }
                _ => {}
            }
        }
        if let Some(s) = run_start {
            let last = self.bs.cluster_count + 1;
            if let (Some((off, _)), Some((eoff, elen))) =
                (self.cluster_range(s), self.cluster_range(last))
            {
                out.push((off, eoff + elen - off));
            }
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
