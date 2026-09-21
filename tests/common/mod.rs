//! Shared test corpus for sutram-analyze.
//!
//! Two vehicles:
//!
//! * [`MockFs`] — a canned `FileSystem` (entries + byte content) for
//!   driving `walk()`/`read_file` without a disk image. Gives precise
//!   control over timestamps, statuses and meta flags.
//! * [`build_fat16`] — a minimal FAT16 image (boot sector, two FATs,
//!   root directory, consecutively-allocated clusters) for end-to-end
//!   tests through `sutram_fat::FatParser`. Same byte-at-a-time
//!   construction as `sutram-fat`'s own test corpus.

use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::Arc;
use std::time::Duration;

use sutram_fs::{
    EntryKind, FileSystem, FsEntry, FsEntryStatus, FsError, FsInfo, FsTimestamp, RecoveryState,
    Result, Timestamps,
};
use sutram_io::ByteSource;

// ---------------------------------------------------------------------------
// MockFs
// ---------------------------------------------------------------------------

/// A canned filesystem: `walk()` replays `entries` (plus injected
/// error records), `read_file` serves `data` by entry id.
pub struct MockFs {
    pub entries: Vec<FsEntry>,
    /// `Result` items injected into the walk stream at `walk_errors[i]`.
    pub walk_errors: Vec<FsError>,
    /// Inject a walk error after this many entries.
    pub inject_error_at: Option<usize>,
    pub data: HashMap<u64, Vec<u8>>,
    src: Arc<Vec<u8>>,
}

impl MockFs {
    pub fn new() -> Self {
        MockFs {
            entries: Vec::new(),
            walk_errors: Vec::new(),
            inject_error_at: None,
            data: HashMap::new(),
            src: Arc::new(Vec::new()),
        }
    }

    /// Add a file entry with contents.
    pub fn add_file(&mut self, entry: FsEntry, contents: &[u8]) {
        self.data.insert(entry.entry_id, contents.to_vec());
        self.entries.push(entry);
    }
}

impl FileSystem for MockFs {
    fn info(&self) -> FsInfo {
        FsInfo {
            fs_type: "mock".into(),
            ..Default::default()
        }
    }
    fn source(&self) -> Arc<dyn ByteSource> {
        self.src.clone()
    }
    fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
        let inject = self.inject_error_at;
        let mut items: Vec<Result<FsEntry>> = Vec::new();
        for (i, e) in self.entries.iter().enumerate() {
            if inject == Some(i) {
                items.push(Err(FsError::corrupt(0, "injected walk error")));
            }
            items.push(Ok(e.clone()));
        }
        Box::new(items.into_iter())
    }
    fn read_file(&self, entry: &FsEntry) -> Result<Box<dyn Read + Send>> {
        match self.data.get(&entry.entry_id) {
            Some(d) => Ok(Box::new(Cursor::new(d.clone()))),
            None => Err(FsError::NotFound {
                path: entry.path.clone(),
            }),
        }
    }
}

/// `FsTimestamp` with `value = Some(ns)`.
pub fn ts(ns: i64) -> FsTimestamp {
    FsTimestamp {
        value: Some(ns),
        raw_value: ns as u64,
        raw_encoding: "test",
        granularity: Duration::from_secs(1),
    }
}

/// Minimal `FsEntry` builder.
pub fn mk_entry(id: u64, path: &str, kind: EntryKind, size: u64) -> FsEntry {
    FsEntry {
        path: path.into(),
        name: path.rsplit('/').next().unwrap_or(path).into(),
        entry_id: id,
        kind,
        size,
        disk_offset: 0,
        allocated_ranges: vec![],
        timestamps: Timestamps::default(),
        status: FsEntryStatus::Live,
        meta: HashMap::new(),
        magic: None,
    }
}

/// `mk_entry` flagged deleted.
pub fn mk_deleted(id: u64, path: &str, size: u64, recovery: RecoveryState) -> FsEntry {
    let mut e = mk_entry(id, path, EntryKind::File, size);
    e.status = FsEntryStatus::Deleted { recovery };
    e
}

// ---------------------------------------------------------------------------
// Tiny FAT16 image builder
// ---------------------------------------------------------------------------

pub const BPS: usize = 512;
pub const FAT16_RESERVED: usize = 1;
pub const FAT16_FATSZ: usize = 32;
pub const FAT16_NFATS: usize = 2;
pub const FAT16_ROOT_SECS: usize = 32; // 512 root entries
pub const FAT16_DATA_SECS: usize = 4300;
pub const FAT16_TOTAL_SECS: usize =
    FAT16_RESERVED + FAT16_NFATS * FAT16_FATSZ + FAT16_ROOT_SECS + FAT16_DATA_SECS;
/// Byte offset of the root directory table.
pub const FAT16_ROOT_OFF: usize = (FAT16_RESERVED + FAT16_NFATS * FAT16_FATSZ) * BPS;
/// Byte offset of cluster `c` (2-based).
pub fn fat16_clus_off(c: usize) -> usize {
    (FAT16_RESERVED + FAT16_NFATS * FAT16_FATSZ + FAT16_ROOT_SECS) * BPS + (c - 2) * BPS
}

fn w16(img: &mut [u8], off: usize, v: u16) {
    img[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

/// DOS date/time encoders.
pub fn dos_date(y: u16, m: u16, d: u16) -> u16 {
    ((y - 1980) << 9) | (m << 5) | d
}
pub fn dos_time(h: u16, m: u16, s: u16) -> u16 {
    (h << 11) | (m << 5) | (s / 2)
}

/// One file in the FAT16 corpus. `name83` is the raw 11-byte 8.3 name
/// (e.g. `b"HELLO   TXT"`); `deleted` sets the 0xE5 marker.
pub struct FatFile {
    pub name83: [u8; 11],
    pub data: Vec<u8>,
    pub deleted: bool,
    pub wtime: u16,
    pub wdate: u16,
}

impl FatFile {
    pub fn new(name83: &[u8; 11], data: &[u8]) -> Self {
        FatFile {
            name83: *name83,
            data: data.to_vec(),
            deleted: false,
            wtime: dos_time(10, 30, 20),
            wdate: dos_date(2024, 1, 15),
        }
    }
    pub fn deleted(mut self) -> Self {
        self.deleted = true;
        self
    }
}

/// Build a FAT16 image holding `files` in the root directory. Each file
/// gets consecutive clusters starting at cluster 2 (one dirent slot
/// each, in order). Deleted files keep their FAT chain (deleted-intact).
pub fn build_fat16(files: &[FatFile]) -> Vec<u8> {
    let mut img = vec![0u8; FAT16_TOTAL_SECS * BPS];

    // boot sector
    img[0] = 0xEB;
    img[1] = 0x3C;
    img[2] = 0x90;
    img[3..11].copy_from_slice(b"SUTRAM16");
    w16(&mut img, 11, BPS as u16);
    img[13] = 1; // sectors/cluster
    w16(&mut img, 14, FAT16_RESERVED as u16);
    img[16] = FAT16_NFATS as u8;
    w16(&mut img, 17, 512); // root entries
    w16(&mut img, 19, FAT16_TOTAL_SECS as u16);
    img[21] = 0xF8;
    w16(&mut img, 22, FAT16_FATSZ as u16);
    w16(&mut img, 24, 1);
    w16(&mut img, 26, 1);
    img[38] = 0x29;
    img[43..54].copy_from_slice(b"ANALYZE    ");
    img[54..62].copy_from_slice(b"FAT16   ");
    img[510] = 0x55;
    img[511] = 0xAA;

    let fat0 = FAT16_RESERVED * BPS;
    let fat1 = (FAT16_RESERVED + FAT16_FATSZ) * BPS;
    let set_fat = |img: &mut [u8], clus: u16, val: u16| {
        for base in [fat0, fat1] {
            w16(img, base + clus as usize * 2, val);
        }
    };
    // media descriptor + reserved entry
    for base in [fat0, fat1] {
        img[base] = 0xF8;
        img[base + 1] = 0xFF;
        img[base + 2] = 0xFF;
        img[base + 3] = 0xFF;
    }

    let mut clus = 2u16;
    for (slot, f) in files.iter().enumerate() {
        let clusters = (f.data.len().max(1)).div_ceil(BPS) as u16;
        for k in 0..clusters {
            let next = if k + 1 == clusters { 0xFFFF } else { clus + k + 1 };
            set_fat(&mut img, clus + k, next);
        }
        let off = fat16_clus_off(clus as usize);
        img[off..off + f.data.len()].copy_from_slice(&f.data);

        let o = FAT16_ROOT_OFF + slot * 32;
        img[o..o + 11].copy_from_slice(&f.name83);
        if f.deleted {
            img[o] = 0xE5;
        }
        img[o + 11] = 0x20; // archive
        w16(&mut img, o + 22, f.wtime);
        w16(&mut img, o + 24, f.wdate);
        w16(&mut img, o + 26, clus);
        img[o + 28..o + 32].copy_from_slice(&(f.data.len() as u32).to_le_bytes());

        clus += clusters;
    }
    img
}
