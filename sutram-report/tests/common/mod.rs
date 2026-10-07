// Shared corpus helpers — not every test binary uses every helper.
#![allow(dead_code)]

//! Synthetic FAT12 corpus for `sutram-report` tests — the `sutram-cli`
//! image-builder pattern: byte-by-byte construction, no fixtures.
//!
//! Geometry: bps=512, spc=1, reserved=1, nfats=2, fatsz=8, root=224
//! entries at `0x2200`; cluster `n` data at `clus_off(n)`.
//!
//! ## Image A — the report corpus
//!
//! | slot/cluster | what                                              |
//! |--------------|---------------------------------------------------|
//! | root slot 0  | TESTVOL volume label                              |
//! | root slot 1  | HELLO.TXT live, cl 2, "hello world!" (12 B)       |
//! | root slot 2  | _DELETED.TXT deleted, cl 3, "deleted data" (12 B) |
//! | root slot 3  | SUBDIR dir, cl 4 → INNER.TXT live, cl 5, "TEST"   |
//! | root slot 4  | EVIL.DOC live, cl 6, MZ/PE bytes — masquerade     |
//! | cl 8         | allocated chain, no dirent → orphan artefact      |
//!
//! ## Image B — the diff target (known ops vs A)
//!
//! * HELLO.TXT: size 12→14, content "hello brave!!!" → **modified**
//! * _DELETED.TXT: dirent un-deleted (0xE5 → '_', same display name) →
//!   **deleted→live transition** at a stable path
//! * INNER.TXT: dirent zeroed → **removed**
//! * NEWFILE.TXT: new dirent, cl 7, "new file!!" → **added**
//! * cl 5's FAT entry freed (its owner is gone — keeps the diff crisp)

pub const BPS: usize = 512;
pub const ROOT_OFF: usize = 0x2200;
pub const DATA_OFF: usize = ROOT_OFF + 224 * 32;

pub fn clus_off(c: u16) -> usize {
    DATA_OFF + (c as usize - 2) * BPS
}

fn dent(img: &mut [u8], off: usize, name: &[u8], ext: &[u8], attr: u8, clus: u16, size: u32) {
    let mut n = [b' '; 8];
    n[..name.len().min(8)].copy_from_slice(&name[..name.len().min(8)]);
    img[off..off + 8].copy_from_slice(&n);
    let mut e = [b' '; 3];
    e[..ext.len().min(3)].copy_from_slice(&ext[..ext.len().min(3)]);
    img[off + 8..off + 11].copy_from_slice(&e);
    img[off + 11] = attr;
    img[off + 26..off + 28].copy_from_slice(&clus.to_le_bytes());
    img[off + 28..off + 32].copy_from_slice(&size.to_le_bytes());
}

fn set_fat12(img: &mut [u8], cluster: u16, val: u16) {
    for base in [512usize, 512 + 8 * 512] {
        let off = base + (cluster as usize) * 3 / 2;
        if cluster % 2 == 0 {
            img[off] = (val & 0xFF) as u8;
            img[off + 1] = (img[off + 1] & 0xF0) | ((val >> 8) as u8 & 0x0F);
        } else {
            img[off] = (img[off] & 0x0F) | ((val << 4) as u8 & 0xF0);
            img[off + 1] = (val >> 4) as u8;
        }
    }
}

fn boot(img: &mut [u8]) {
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"SUTRAMFS");
    img[11..13].copy_from_slice(&512u16.to_le_bytes());
    img[13] = 1;
    img[14..16].copy_from_slice(&1u16.to_le_bytes());
    img[16] = 2;
    img[17..19].copy_from_slice(&224u16.to_le_bytes());
    img[19..21].copy_from_slice(&2048u16.to_le_bytes());
    img[21] = 0xF8;
    img[22..24].copy_from_slice(&8u16.to_le_bytes());
    img[24..26].copy_from_slice(&32u16.to_le_bytes());
    img[26..28].copy_from_slice(&64u16.to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;
    for base in [512usize, 512 + 8 * 512] {
        img[base] = 0xF8;
        img[base + 1] = 0xFF;
        img[base + 2] = 0xFF;
    }
}

/// Image A — report corpus.
pub fn image_a() -> Vec<u8> {
    let mut img = vec![0u8; 1 << 20];
    boot(&mut img);
    for c in [2u16, 3, 4, 5, 6, 8] {
        set_fat12(&mut img, c, 0xFFF);
    }
    let rd = ROOT_OFF;
    dent(&mut img, rd, b"TESTVOL", b"", 0x08, 0, 0);
    dent(&mut img, rd + 32, b"HELLO", b"TXT", 0x20, 2, 12);
    dent(
        &mut img,
        rd + 64,
        &[0xE5, b'D', b'E', b'L', b'E', b'T', b'E', b'D'],
        b"TXT",
        0x20,
        3,
        12,
    );
    dent(&mut img, rd + 96, b"SUBDIR", b"", 0x10, 4, 0);
    dent(&mut img, rd + 128, b"EVIL", b"DOC", 0x20, 6, 60);

    img[clus_off(2)..clus_off(2) + 12].copy_from_slice(b"hello world!");
    img[clus_off(3)..clus_off(3) + 12].copy_from_slice(b"deleted data");
    let d = clus_off(4);
    dent(&mut img, d, b".", b"", 0x10, 4, 0);
    dent(&mut img, d + 32, b"..", b"", 0x10, 0, 0);
    dent(&mut img, d + 64, b"INNER", b"TXT", 0x20, 5, 4);
    img[clus_off(5)..clus_off(5) + 4].copy_from_slice(b"TEST");
    let f = clus_off(6);
    img[f] = b'M';
    img[f + 1] = b'Z';
    img[f + 0x3C..f + 0x40].copy_from_slice(&0x40u32.to_le_bytes());
    img[f + 0x40..f + 0x44].copy_from_slice(b"PE\0\0");
    img[clus_off(8)..clus_off(8) + 19].copy_from_slice(b"orphan chain data!!");
    img
}

/// Image B — image A after the documented ops.
pub fn image_b() -> Vec<u8> {
    let mut img = image_a();
    // HELLO.TXT: size + content change.
    img[ROOT_OFF + 32 + 28..ROOT_OFF + 32 + 32].copy_from_slice(&14u32.to_le_bytes());
    img[clus_off(2)..clus_off(2) + 14].copy_from_slice(b"hello brave!!!");
    // _DELETED.TXT: un-delete — 0xE5 marker becomes a literal '_', so the
    // rendered path "/_DELETED.TXT" is stable across the transition.
    img[ROOT_OFF + 64] = b'_';
    // INNER.TXT: wipe the dirent (0x00 = end marker).
    for b in &mut img[clus_off(4) + 64..clus_off(4) + 96] {
        *b = 0;
    }
    set_fat12(&mut img, 5, 0x000); // free INNER.TXT's cluster
    // NEWFILE.TXT: append at root slot 5.
    dent(&mut img, ROOT_OFF + 160, b"NEWFILE", b"TXT", 0x20, 7, 10);
    set_fat12(&mut img, 7, 0xFFF);
    img[clus_off(7)..clus_off(7) + 10].copy_from_slice(b"new file!!");
    img
}

// ---------------------------------------------------------------------------
// In-memory stub FileSystem — reaches report/diff branches no synthetic FAT
// image can produce (every RecoveryState, suspicious meta keys, walk errors,
// mid-read failures, symlink/other kinds, fabricated magic verdicts).
// ---------------------------------------------------------------------------

use std::collections::{HashMap, HashSet};
use std::io::{self, Cursor, Read};
use std::sync::Arc;

use sutram_fs::{
    EntryKind, FileSystem, FsEntry, FsEntryStatus, FsError, FsInfo, Result, Timestamps,
};

/// One walk item: an entry or a corruption record.
pub enum StubItem {
    /// Yielded as `Ok(entry)` (boxed — `FsEntry` is large).
    Entry(Box<FsEntry>),
    /// Yielded as `Err(FsError::Corrupt)` carrying this message.
    Error(String),
}

/// What `read_file` serves for one `entry_id`.
pub enum StubData {
    /// Clean bytes.
    Bytes(Vec<u8>),
    /// Yields `good` bytes then fails — mid-stream read error.
    Flaky {
        /// Bytes delivered successfully before the error.
        good: usize,
    },
}

/// Minimal in-memory [`FileSystem`].
pub struct StubFs {
    /// Walk items, in order.
    pub items: Vec<StubItem>,
    /// `entry_id` → readable data. Absent + not in `fail_ids` → `NotFound`.
    pub data: HashMap<u64, StubData>,
    /// `entry_id`s whose `read_file` must error at open.
    pub fail_ids: HashSet<u64>,
    /// `info()` result.
    pub info: FsInfo,
    /// `source()` backing (only its length matters).
    pub src: Arc<Vec<u8>>,
}

impl StubFs {
    /// Empty stub with a 4 KiB source and a "stub" fs_type.
    pub fn new() -> Self {
        StubFs {
            items: Vec::new(),
            data: HashMap::new(),
            fail_ids: HashSet::new(),
            info: FsInfo {
                fs_type: "stub".into(),
                label: Some("STUBVOL".into()),
                uuid: Some("deadbeef".into()),
                block_size: 512,
                total_blocks: 8,
                free_blocks: Some(4),
                total_nodes: Some(16),
                meta: HashMap::from([("stub_key".into(), "stub_val".into())]),
            },
            src: Arc::new(vec![0u8; 4096]),
        }
    }

    /// Convenience: append an entry to the walk.
    pub fn push(&mut self, e: FsEntry) {
        self.items.push(StubItem::Entry(Box::new(e)));
    }
}

/// A reader that yields `good` zeroed bytes, then an I/O error.
struct FlakyReader {
    left: usize,
}

impl Read for FlakyReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            return Err(io::Error::other("flaky read"));
        }
        let n = self.left.min(buf.len());
        for b in &mut buf[..n] {
            *b = 0xAB;
        }
        self.left -= n;
        Ok(n)
    }
}

impl FileSystem for StubFs {
    fn info(&self) -> FsInfo {
        self.info.clone()
    }
    fn source(&self) -> Arc<dyn sutram_fs::ByteSource> {
        self.src.clone()
    }
    fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
        Box::new(self.items.iter().map(|it| match it {
            StubItem::Entry(e) => Ok((**e).clone()),
            StubItem::Error(m) => Err(FsError::corrupt(0, m.clone())),
        }))
    }
    fn read_file(&self, entry: &FsEntry) -> Result<Box<dyn Read + Send>> {
        if self.fail_ids.contains(&entry.entry_id) {
            return Err(FsError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read_file denied",
            )));
        }
        match self.data.get(&entry.entry_id) {
            Some(StubData::Bytes(d)) => Ok(Box::new(Cursor::new(d.clone()))),
            Some(StubData::Flaky { good }) => Ok(Box::new(FlakyReader { left: *good })),
            None => Err(FsError::NotFound {
                path: entry.path.clone(),
            }),
        }
    }
}

/// Bare-bones live entry: `path`, `kind`, `size`; everything else default.
pub fn stub_entry(id: u64, path: &str, kind: EntryKind, size: u64) -> FsEntry {
    FsEntry {
        path: path.into(),
        name: path.rsplit('/').next().unwrap_or(path).into(),
        entry_id: id,
        kind,
        size,
        disk_offset: id * 32,
        allocated_ranges: vec![],
        timestamps: Timestamps::default(),
        status: FsEntryStatus::Live,
        meta: HashMap::new(),
        magic: None,
    }
}
