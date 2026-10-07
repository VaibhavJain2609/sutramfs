//! Synthetic images for the sutramfs CLI integration tests.
//!
//! Same pattern as `sutram-fat/tests/common`: bytes assembled in a
//! `Vec<u8>` — no fixture files. `fat12()` is a minimal-but-valid FAT12
//! volume the FAT parser will mount; `mbr_disk()` wraps it in a one-entry
//! MBR partition table so `parts` / `-p` paths can be exercised.
//!
//! FAT12 layout (512 B sectors, 64 total):
//!
//! ```text
//! sector 0   boot sector (BPB, "FAT12" label, 55AA)
//! sector 1   FAT #0 (FAT12, 1 sector)
//! sector 2   root directory (16 entries)
//! sector 3+  data: cluster c → sector c + 1
//! ```
//!
//! Cluster map:
//!
//! | cluster | contents                                        |
//! |---------|-------------------------------------------------|
//! | 2       | HELLO.TXT   live, "hello world!"                |
//! | 3       | SUBDIR      directory                           |
//! | 4       | DELETED.TXT deleted-intact, "0123456789"        |
//! | 5       | SUBDIR/INNER.TXT live, "inner"                  |
//! | 6       | FAKE.TXT    live, MZ/PE bytes → magic mismatch  |

use std::io::Write;
use std::path::PathBuf;

pub const BPS: usize = 512;
pub const TOTAL_SECTORS: u32 = 64;
pub const FAT_OFF: usize = BPS;
pub const ROOT_OFF: usize = 2 * BPS;
pub const DATA_SECTOR_0: u32 = 3;

/// Absolute byte offset of cluster `c`.
pub fn clus_off(c: u32) -> usize {
    ((DATA_SECTOR_0 + c - 2) as usize) * BPS
}

fn w16(img: &mut [u8], off: usize, v: u16) {
    img[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(img: &mut [u8], off: usize, v: u32) {
    img[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Set a FAT12 entry (packed 12-bit).
pub fn fat12_set(img: &mut [u8], cluster: u32, val: u16) {
    let off = FAT_OFF + (cluster as usize) * 3 / 2;
    if cluster % 2 == 0 {
        img[off] = (val & 0xFF) as u8;
        img[off + 1] = (img[off + 1] & 0xF0) | ((val >> 8) & 0x0F) as u8;
    } else {
        img[off] = (img[off] & 0x0F) | (((val << 4) & 0xF0) as u8);
        img[off + 1] = (val >> 4) as u8;
    }
}

/// Write a 32-byte dirent at `slot` of the table at `table_off`.
pub fn dirent(
    img: &mut [u8],
    table_off: usize,
    slot: usize,
    name11: &[u8; 11],
    attr: u8,
    cluster: u32,
    size: u32,
) {
    let o = table_off + slot * 32;
    img[o..o + 11].copy_from_slice(name11);
    img[o + 11] = attr;
    w16(img, o + 26, cluster as u16);
    w32(img, o + 28, size);
}

/// Build the FAT12 test volume.
pub fn fat12() -> Vec<u8> {
    let mut img = vec![0u8; TOTAL_SECTORS as usize * BPS];
    // Boot sector.
    img[0] = 0xEB;
    img[1] = 0x3C;
    img[2] = 0x90;
    img[3..11].copy_from_slice(b"SUTRAMFS");
    w16(&mut img, 11, BPS as u16); // bytes/sector
    img[13] = 1; // sectors/cluster
    w16(&mut img, 14, 1); // reserved
    img[16] = 1; // fats
    w16(&mut img, 17, 16); // root entries → 1 sector
    w16(&mut img, 19, TOTAL_SECTORS as u16); // total16
    img[21] = 0xF8; // media
    w16(&mut img, 22, 1); // fatsz16
    w16(&mut img, 24, 1); // sectors/track
    w16(&mut img, 26, 1); // heads
    img[38] = 0x29; // boot sig
    img[43..54].copy_from_slice(b"NO NAME    ");
    img[54..62].copy_from_slice(b"FAT12   ");
    img[510] = 0x55;
    img[511] = 0xAA;

    // FAT: [0]=media, [1]=EOC; clusters 2..=6 end-of-chain.
    img[FAT_OFF] = 0xF8;
    img[FAT_OFF + 1] = 0xFF;
    img[FAT_OFF + 2] = 0xFF;
    for c in 2..=6u32 {
        fat12_set(&mut img, c, 0xFFF);
    }

    // Root directory.
    dirent(&mut img, ROOT_OFF, 0, b"HELLO   TXT", 0x20, 2, 12);
    dirent(&mut img, ROOT_OFF, 1, b"SUBDIR     ", 0x10, 3, 0);
    dirent(&mut img, ROOT_OFF, 2, b"\xE5ELETED TXT", 0x20, 4, 10);
    // Masquerade file: .TXT extension, real MZ→PE content.
    dirent(&mut img, ROOT_OFF, 3, b"FAKE    TXT", 0x20, 6, 64);

    // File data.
    img[clus_off(2)..clus_off(2) + 12].copy_from_slice(b"hello world!");
    img[clus_off(4)..clus_off(4) + 10].copy_from_slice(b"0123456789");

    // SUBDIR cluster: "." / ".." / INNER.TXT.
    let d = clus_off(3);
    dirent(&mut img, d, 0, b".          ", 0x10, 3, 0);
    dirent(&mut img, d, 1, b"..         ", 0x10, 0, 0);
    dirent(&mut img, d, 2, b"INNER   TXT", 0x20, 5, 5);
    img[clus_off(5)..clus_off(5) + 5].copy_from_slice(b"inner");

    // FAKE.TXT data: MZ header + e_lfanew + "PE\0\0" → a real PE.
    let f = clus_off(6);
    img[f] = b'M';
    img[f + 1] = b'Z';
    w32(&mut img, f + 0x3C, 0x40); // e_lfanew
    img[f + 0x40..f + 0x44].copy_from_slice(b"PE\0\0");

    img
}

/// Wrap `inner` in a one-entry MBR partition table starting at `start_lba`.
pub fn mbr_disk(inner: &[u8], start_lba: u32) -> Vec<u8> {
    let start = start_lba as usize * BPS;
    let mut disk = vec![0u8; start + inner.len()];
    // MBR entry 0 at 446: type 0x01 (FAT12), CHS fields left as 0xFF-style.
    let e = 446;
    disk[e] = 0x00; // not bootable
    disk[e + 1] = 0x01;
    disk[e + 2] = 0x01;
    disk[e + 3] = 0x00;
    disk[e + 4] = 0x01; // FAT12
    disk[e + 5] = 0xFE;
    disk[e + 6] = 0xFF;
    disk[e + 7] = 0xFF;
    w32(&mut disk, e + 8, start_lba);
    w32(&mut disk, e + 12, (inner.len() / BPS) as u32);
    disk[510] = 0x55;
    disk[511] = 0xAA;
    disk[start..start + inner.len()].copy_from_slice(inner);
    disk
}

/// Write `img` to a temp file and return its path. The file is deleted
/// when the returned guard is dropped — safe for parallel tests since
/// each image gets a unique name.
pub struct TempImage(PathBuf);

impl TempImage {
    pub fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempImage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn temp_image(img: &[u8], tag: &str) -> TempImage {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "sutramfs-cli-test-{}-{:x}.img",
        tag,
        std::process::id()
    ));
    // Uniquify across tests in the same process.
    let mut n = 0u32;
    while p.exists() {
        n += 1;
        p.set_file_name(format!(
            "sutramfs-cli-test-{}-{:x}-{n}.img",
            tag,
            std::process::id()
        ));
    }
    let mut f = std::fs::File::create(&p).expect("create temp image");
    f.write_all(img).expect("write temp image");
    TempImage(p)
}
