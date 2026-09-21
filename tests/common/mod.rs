//! Minimal synthetic FAT32 image for FFI round-trip tests — same
//! byte-by-byte builder pattern as `sutram-fat`'s corpus, pared down to
//! one live file, one deleted file and a subdirectory.
//!
//! Layout: sector 0 boot, 32..552 FAT#0, 552..1072 FAT#1, data at 1072+
//! (cluster 2 = root dir, 3 = HELLO.TXT, 4 = deleted _OLD.TXT, 5 = SUBDIR).

pub const BPS: usize = 512;
const RESERVED: u32 = 32;
const FATSZ: u32 = 520;
const NFATS: u32 = 2;
// 66 000 data sectors → >65 525 clusters, required for the parser to
// classify the volume as FAT32 (FAT variant is decided by cluster count).
const DATA_SECTORS: u32 = 66_000;
const TOTAL_SECTORS: u32 = RESERVED + NFATS * FATSZ + DATA_SECTORS;
const FAT0_OFF: usize = RESERVED as usize * BPS;
const FAT1_OFF: usize = (RESERVED + FATSZ) as usize * BPS;
const DATA_SECTOR_0: u32 = RESERVED + NFATS * FATSZ;

const EOC: u32 = 0x0FFF_FFFF;
const ATTR_DIR: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_VOLUME: u8 = 0x08;

fn w16(img: &mut [u8], off: usize, v: u16) {
    img[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(img: &mut [u8], off: usize, v: u32) {
    img[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn clus_off(c: u32) -> usize {
    ((DATA_SECTOR_0 + c - 2) as usize) * BPS
}

fn set_fat(img: &mut [u8], cluster: u32, val: u32) {
    let off = cluster as usize * 4;
    w32(img, FAT0_OFF + off, val);
    w32(img, FAT1_OFF + off, val);
}

fn dirent(img: &mut [u8], table_off: usize, slot: usize, name: &[u8; 11], attr: u8, cluster: u32, size: u32, deleted: bool) {
    let o = table_off + slot * 32;
    img[o..o + 11].copy_from_slice(name);
    if deleted {
        img[o] = 0xE5;
    }
    img[o + 11] = attr;
    w16(img, o + 20, (cluster >> 16) as u16);
    w16(img, o + 26, cluster as u16);
    w32(img, o + 28, size);
}

/// Build the image (~2.6 MiB).
pub fn build() -> Vec<u8> {
    let mut img = vec![0u8; TOTAL_SECTORS as usize * BPS];

    img[0] = 0xEB;
    img[1] = 0x58;
    img[2] = 0x90;
    img[3..11].copy_from_slice(b"MSWIN4.1");
    w16(&mut img, 11, 512);
    img[13] = 1; // spc
    w16(&mut img, 14, RESERVED as u16);
    img[16] = NFATS as u8;
    img[21] = 0xF8;
    w16(&mut img, 24, 63);
    w16(&mut img, 26, 255);
    w32(&mut img, 32, TOTAL_SECTORS);
    w32(&mut img, 36, FATSZ);
    w32(&mut img, 44, 2); // root cluster
    w16(&mut img, 48, 1);
    w16(&mut img, 50, 6);
    img[64] = 0x80;
    img[66] = 0x29;
    w32(&mut img, 67, 0xCAFE_0001);
    img[71..82].copy_from_slice(b"CAPITEST   ");
    img[82..90].copy_from_slice(b"FAT32   ");
    img[510] = 0x55;
    img[511] = 0xAA;

    set_fat(&mut img, 0, 0x0FFF_FFF8);
    set_fat(&mut img, 1, EOC);
    set_fat(&mut img, 2, EOC); // root dir
    set_fat(&mut img, 3, EOC); // HELLO.TXT
    set_fat(&mut img, 4, EOC); // _OLD.TXT (deleted, chain intact)
    set_fat(&mut img, 5, EOC); // SUBDIR
    set_fat(&mut img, 6, EOC); // INNER.TXT

    // File data.
    let off3 = clus_off(3);
    img[off3..off3 + 12].copy_from_slice(b"hello world!");
    let off4 = clus_off(4);
    img[off4..off4 + 10].copy_from_slice(b"0123456789");
    let off6 = clus_off(6);
    img[off6..off6 + 4].copy_from_slice(b"NEST");

    // Root directory.
    let root = clus_off(2);
    dirent(&mut img, root, 0, b"CAPITEST   ", ATTR_VOLUME, 0, 0, false);
    dirent(&mut img, root, 1, b"HELLO   TXT", ATTR_ARCHIVE, 3, 12, false);
    dirent(&mut img, root, 2, b"OLD     TXT", ATTR_ARCHIVE, 4, 10, true);
    dirent(&mut img, root, 3, b"SUBDIR     ", ATTR_DIR, 5, 0, false);
    // slot 4 = 0x00 end marker.

    // SUBDIR (cluster 5).
    let sub = clus_off(5);
    dirent(&mut img, sub, 0, b".          ", ATTR_DIR, 5, 0, false);
    dirent(&mut img, sub, 1, b"..         ", ATTR_DIR, 0, 0, false);
    dirent(&mut img, sub, 2, b"INNER   TXT", ATTR_ARCHIVE, 6, 4, false);

    img
}
