//! Synthetic FAT image construction for tests.
//!
//! **This is the test-corpus pattern every SUTRAM-FS parser copies**: build
//! the filesystem byte-by-byte in a `Vec<u8>` (boot sector, FAT, directory
//! tables, file data), mount it via `Arc<Vec<u8>>` as the `ByteSource`, and
//! assert on the emitted `FsEntry` stream. No fixture files, no network —
//! corruption cases are produced by deliberately writing bad bytes.
//!
//! FAT32 layout produced by [`build_fat32`]:
//!
//! ```text
//! sector 0        boot sector (BPB, FAT32 ext, 55AA)
//! 1               (fsinfo slot — left zeroed)
//! 32..552         FAT #0  (520 sectors)
//! 552..1072       FAT #1  (mirror)
//! 1072..          data region: cluster 2 → offset (1070+c)*512
//! ```
//!
//! Cluster map of the corpus (bps=512, spc=1 → 1 cluster = 512 B):
//!
//! | cluster | contents                                        |
//! |---------|-------------------------------------------------|
//! | 2       | root directory                                  |
//! | 3       | HELLO.TXT   live, "hello world!"                |
//! | 4       | _DELETED.TXT deleted-intact, "0123456789"       |
//! | 6       | Long File Name.txt (LFN), PNG header bytes      |
//! | 7–8     | _OLDFILE.TXT deleted; 7 reallocated to NEWFILE  |
//! | 9       | _GONE.BIN deleted; reallocated to HOLDER.BIN    |
//! | 11      | SUBDIR directory containing INNER.TXT (cl 12)   |
//! | 13      | RESUME.DOCX live, PK bytes (container-ok)       |
//! | 14      | EVIL.DOC   live, MZ bytes (masquerade)          |
//! | 15      | _GHOST.TMP deleted, past the 0x00 end marker    |
//! | 20–21   | orphan chain — allocated, no directory entry    |

pub const BPS: usize = 512;
pub const RESERVED: u32 = 32;
pub const FATSZ: u32 = 520;
pub const NFATS: u32 = 2;
pub const DATA_SECTORS: u32 = 66_000;
pub const TOTAL_SECTORS: u32 = RESERVED + NFATS * FATSZ + DATA_SECTORS;
pub const FAT0_OFF: usize = (RESERVED as usize) * BPS;
pub const FAT1_OFF: usize = (RESERVED as usize + FATSZ as usize) * BPS;
pub const DATA_SECTOR_0: u32 = RESERVED + NFATS * FATSZ; // 1072

/// Absolute byte offset of cluster `c`'s first byte.
pub fn clus_off(c: u32) -> usize {
    ((DATA_SECTOR_0 + c - 2) as usize) * BPS
}

fn w16(img: &mut [u8], off: usize, v: u16) {
    img[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(img: &mut [u8], off: usize, v: u32) {
    img[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Set a FAT32 entry in both FAT copies.
pub fn set_fat(img: &mut [u8], cluster: u32, val: u32) {
    let off = cluster as usize * 4;
    w32(img, FAT0_OFF + off, val);
    w32(img, FAT1_OFF + off, val);
}

/// Write file content at a cluster.
pub fn put_data(img: &mut [u8], cluster: u32, data: &[u8]) {
    let off = clus_off(cluster);
    img[off..off + data.len()].copy_from_slice(data);
}

pub const ATTR_DIR: u8 = 0x10;
pub const ATTR_ARCHIVE: u8 = 0x20;
pub const ATTR_VOLUME: u8 = 0x08;
pub const ATTR_LFN: u8 = 0x0F;
const EOC: u32 = 0x0FFF_FFFF;

/// Write a 32-byte dirent at `slot` of the dir table at `table_off`.
#[allow(clippy::too_many_arguments)]
pub fn dirent(
    img: &mut [u8],
    table_off: usize,
    slot: usize,
    name83: &[u8; 11],
    attr: u8,
    cluster: u32,
    size: u32,
    deleted: bool,
    wtime: u16,
    wdate: u16,
    crt_tenth: u8,
    crt_time: u16,
    crt_date: u16,
    adate: u16,
) {
    let o = table_off + slot * 32;
    img[o..o + 11].copy_from_slice(name83);
    if deleted {
        img[o] = 0xE5;
    }
    img[o + 11] = attr;
    img[o + 13] = crt_tenth;
    w16(img, o + 14, crt_time);
    w16(img, o + 16, crt_date);
    w16(img, o + 18, adate);
    w16(img, o + 20, (cluster >> 16) as u16);
    w16(img, o + 22, wtime);
    w16(img, o + 24, wdate);
    w16(img, o + 26, cluster as u16);
    w32(img, o + 28, size);
}

/// Write an LFN slot: `seq` (with 0x40 for the last part), `units` = up to
/// 13 UTF-16 code units of the name fragment.
pub fn lfn(
    img: &mut [u8],
    table_off: usize,
    slot: usize,
    seq: u8,
    checksum: u8,
    units: &[u16],
    deleted: bool,
) {
    let o = table_off + slot * 32;
    img[o] = if deleted { 0xE5 } else { seq };
    img[o + 11] = ATTR_LFN;
    img[o + 13] = checksum;
    let fields = [(1usize, 5usize), (14, 6), (28, 2)];
    let mut i = 0;
    let mut padded = [0xFFFFu16; 13];
    for (k, u) in units.iter().enumerate() {
        padded[k] = *u;
    }
    if units.len() < 13 {
        padded[units.len()] = 0;
    }
    for (off, n) in fields {
        for j in 0..n {
            let u = padded.get(i).copied().unwrap_or(0xFFFF);
            w16(img, o + off + j * 2, u);
            i += 1;
        }
    }
}

/// LFN checksum over an 8.3 name (rotate-right-and-add per MS spec).
pub fn lfn_checksum(name83: &[u8; 11]) -> u8 {
    let mut sum = 0u8;
    for &b in name83 {
        sum = ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(b);
    }
    sum
}

/// DOS date/time encoders for tests: `dos_date(2024,1,15)`, `dos_time(10,30,20)`.
pub fn dos_date(y: u16, m: u16, d: u16) -> u16 {
    ((y - 1980) << 9) | (m << 5) | d
}
pub fn dos_time(h: u16, m: u16, s: u16) -> u16 {
    (h << 11) | (m << 5) | (s / 2)
}

/// Build the FAT32 corpus image (~34 MiB).
pub fn build_fat32() -> Vec<u8> {
    let mut img = vec![0u8; TOTAL_SECTORS as usize * BPS];

    // ---- boot sector --------------------------------------------------
    img[0] = 0xEB;
    img[1] = 0x58;
    img[2] = 0x90;
    img[3..11].copy_from_slice(b"MSWIN4.1");
    w16(&mut img, 11, 512); // bytes/sector
    img[13] = 1; // sectors/cluster
    w16(&mut img, 14, RESERVED as u16);
    img[16] = NFATS as u8;
    w16(&mut img, 17, 0); // root entries (0 for FAT32)
    w16(&mut img, 19, 0); // tot16
    img[21] = 0xF8; // media
    w16(&mut img, 22, 0); // fatsz16 → use fatsz32
    w16(&mut img, 24, 63);
    w16(&mut img, 26, 255);
    w32(&mut img, 28, 0);
    w32(&mut img, 32, TOTAL_SECTORS);
    w32(&mut img, 36, FATSZ);
    w16(&mut img, 40, 0);
    w16(&mut img, 42, 0);
    w32(&mut img, 44, 2); // root cluster
    w16(&mut img, 48, 1); // fsinfo
    w16(&mut img, 50, 6); // backup boot sector
    img[64] = 0x80;
    img[66] = 0x29; // ext sig
    w32(&mut img, 67, 0x1234_5678); // volume id
    img[71..82].copy_from_slice(b"NO NAME    ");
    img[82..90].copy_from_slice(b"FAT32   ");
    img[510] = 0x55;
    img[511] = 0xAA;

    // ---- FAT -----------------------------------------------------------
    set_fat(&mut img, 0, 0x0FFF_FFF8);
    set_fat(&mut img, 1, 0x0FFF_FFFF);
    set_fat(&mut img, 2, EOC); // root dir
    set_fat(&mut img, 3, EOC); // HELLO.TXT
    set_fat(&mut img, 4, EOC); // _DELETED.TXT — chain survives
    set_fat(&mut img, 6, EOC); // Long File Name.txt
    set_fat(&mut img, 7, 8); // _OLDFILE.TXT chain 7→8 survives…
    set_fat(&mut img, 8, EOC); // …but NEWFILE.TXT also claims 7
    set_fat(&mut img, 9, EOC); // _GONE.BIN / HOLDER.BIN
    set_fat(&mut img, 11, EOC); // SUBDIR
    set_fat(&mut img, 12, EOC); // INNER.TXT
    set_fat(&mut img, 13, EOC); // RESUME.DOCX
    set_fat(&mut img, 14, EOC); // EVIL.DOC
    set_fat(&mut img, 15, EOC); // _GHOST.TMP
    set_fat(&mut img, 20, 21); // orphan chain 20→21
    set_fat(&mut img, 21, EOC);

    // ---- file data -----------------------------------------------------
    put_data(&mut img, 3, b"hello world!");
    put_data(&mut img, 4, b"0123456789");
    put_data(&mut img, 6, b"\x89PNG\x0D\x0A\x1A\x0A");
    put_data(&mut img, 7, b"new file owns this cluster now");
    put_data(&mut img, 8, b"old file tail survives here!!");
    put_data(&mut img, 9, b"holder owns nine");
    put_data(&mut img, 12, b"TEST");
    let mut pk = b"PK\x03\x04\x14\0\0\0".to_vec();
    pk.resize(20, 0);
    put_data(&mut img, 13, &pk);
    let mut mz = b"MZ\x90\0\x03\0\0\0".to_vec();
    mz.resize(60, 0);
    put_data(&mut img, 14, &mz);
    put_data(&mut img, 15, b"ghosty!!");
    put_data(&mut img, 20, b"ORPHANED-CHAIN-START");
    put_data(&mut img, 21, b"ORPHANED-CHAIN-TAIL!");

    // ---- root directory (cluster 2) ------------------------------------
    let root = clus_off(2);
    let (wd, wt) = (dos_date(2024, 1, 15), dos_time(10, 30, 20));
    dirent(&mut img, root, 0, b"TESTVOL    ", ATTR_VOLUME, 0, 0, false, 0, 0, 0, 0, 0, 0);
    dirent(
        &mut img, root, 1, b"HELLO   TXT", ATTR_ARCHIVE, 3, 12, false, wt, wd,
        50, wt, wd, dos_date(2024, 1, 16),
    );
    // LFN "Long File Name.txt" (18 chars → 2 slots, stored last-part-first)
    let lfn_units: Vec<u16> = "Long File Name.txt".encode_utf16().collect();
    let sum = lfn_checksum(b"LONGFI~1TXT");
    lfn(&mut img, root, 2, 0x42, sum, &lfn_units[13..], false);
    lfn(&mut img, root, 3, 0x01, sum, &lfn_units[..13], false);
    dirent(&mut img, root, 4, b"LONGFI~1TXT", ATTR_ARCHIVE, 6, 8, false, wt, wd, 0, wt, wd, 0);
    dirent(&mut img, root, 5, b"DELETED TXT", ATTR_ARCHIVE, 4, 10, true, wt, wd, 0, wt, wd, 0);
    dirent(&mut img, root, 6, b"OLDFILE TXT", ATTR_ARCHIVE, 7, 700, true, wt, wd, 0, wt, wd, 0);
    dirent(&mut img, root, 7, b"NEWFILE TXT", ATTR_ARCHIVE, 7, 100, false, wt, wd, 0, wt, wd, 0);
    dirent(&mut img, root, 8, b"GONE    BIN", ATTR_ARCHIVE, 9, 300, true, wt, wd, 0, wt, wd, 0);
    dirent(&mut img, root, 9, b"HOLDER  BIN", ATTR_ARCHIVE, 9, 50, false, wt, wd, 0, wt, wd, 0);
    dirent(&mut img, root, 10, b"SUBDIR     ", ATTR_DIR, 11, 0, false, wt, wd, 0, wt, wd, 0);
    // LFN "RESUME.DOCX" (11 chars → 1 slot) + its 8.3 alias RESUME~1.DOC
    let r_units: Vec<u16> = "RESUME.DOCX".encode_utf16().collect();
    let sum = lfn_checksum(b"RESUME~1DOC");
    lfn(&mut img, root, 11, 0x41, sum, &r_units, false);
    dirent(&mut img, root, 12, b"RESUME~1DOC", ATTR_ARCHIVE, 13, 20, false, wt, wd, 0, wt, wd, 0);
    dirent(&mut img, root, 13, b"EVIL    DOC", ATTR_ARCHIVE, 14, 60, false, wt, wd, 0, wt, wd, 0);
    // slot 14 = 0x00 end marker (already zero)
    dirent(&mut img, root, 15, b"GHOST   TMP", ATTR_ARCHIVE, 15, 8, true, wt, wd, 0, wt, wd, 0);

    // ---- SUBDIR (cluster 11) -------------------------------------------
    let sub = clus_off(11);
    dirent(&mut img, sub, 0, b".          ", ATTR_DIR, 11, 0, false, wt, wd, 0, wt, wd, 0);
    dirent(&mut img, sub, 1, b"..         ", ATTR_DIR, 0, 0, false, wt, wd, 0, wt, wd, 0);
    dirent(&mut img, sub, 2, b"INNER   TXT", ATTR_ARCHIVE, 12, 4, false, wt, wd, 0, wt, wd, 0);

    img
}

/// Minimal FAT16 image (~2.2 MiB): 1 reserved sector, 2×32-sector FATs,
/// 512-entry root region, 4300 data sectors (4300 clusters → FAT16).
///
/// Cluster map: root region fixed. Cluster 2 = FILE16.TXT data.
pub fn build_fat16() -> Vec<u8> {
    let reserved = 1usize;
    let fatsz = 32usize;
    let nfats = 2usize;
    let root_secs = 32usize; // 512 entries * 32 = 16 KiB
    let data_secs = 4300usize;
    let total = reserved + nfats * fatsz + root_secs + data_secs;
    let mut img = vec![0u8; total * BPS];

    img[0] = 0xEB;
    img[1] = 0x3C;
    img[2] = 0x90;
    img[3..11].copy_from_slice(b"SUTRAM16");
    w16(&mut img, 11, 512);
    img[13] = 1;
    w16(&mut img, 14, 1);
    img[16] = nfats as u8;
    w16(&mut img, 17, 512); // root entries
    w16(&mut img, 19, total as u16);
    img[21] = 0xF8;
    w16(&mut img, 22, fatsz as u16);
    w16(&mut img, 24, 1);
    w16(&mut img, 26, 1);
    img[38] = 0x29;
    w32(&mut img, 39, 0x0BAD_CAFE);
    img[43..54].copy_from_slice(b"FAT16VOL   ");
    img[54..62].copy_from_slice(b"FAT16   ");
    img[510] = 0x55;
    img[511] = 0xAA;

    // FAT16: entry n at n*2. [0]=F8FF media, [1]=FFFF, [2]=FFFF EOC.
    let fat = |img: &mut [u8], base: usize| {
        img[base] = 0xF8;
        img[base + 1] = 0xFF;
        img[base + 2] = 0xFF;
        img[base + 3] = 0xFF;
        // cluster 2 → EOC
        img[base + 4] = 0xFF;
        img[base + 5] = 0xFF;
    };
    fat(&mut img, reserved * BPS);
    fat(&mut img, (reserved + fatsz) * BPS);

    let root = (reserved + nfats * fatsz) * BPS;
    let (wd, wt) = (dos_date(2001, 3, 4), dos_time(12, 0, 0));
    dirent(&mut img, root, 0, b"FILE16  TXT", ATTR_ARCHIVE, 2, 9, false, wt, wd, 0, wt, wd, 0);
    let off = (reserved + nfats * fatsz + root_secs) * BPS;
    img[off..off + 9].copy_from_slice(b"sixteen!!");
    img
}

/// Minimal FAT12 image (~64 KiB): 1 reserved sector, 2×2-sector FATs,
/// 16-entry root region, 100 data sectors.
///
/// Cluster map: root region is fixed (not a cluster). Cluster 2 = DATA.TXT.
pub fn build_fat12() -> Vec<u8> {
    let reserved = 1usize;
    let fatsz = 2usize;
    let nfats = 2usize;
    let root_secs = 1usize; // 16 entries * 32 = 512 B
    let data_secs = 100usize;
    let total = reserved + nfats * fatsz + root_secs + data_secs;
    let mut img = vec![0u8; total * BPS];

    img[0] = 0xEB;
    img[1] = 0x3C;
    img[2] = 0x90;
    img[3..11].copy_from_slice(b"SUTRAM12");
    w16(&mut img, 11, 512);
    img[13] = 1;
    w16(&mut img, 14, 1);
    img[16] = nfats as u8;
    w16(&mut img, 17, 16); // root entries
    w16(&mut img, 19, total as u16);
    img[21] = 0xF8;
    w16(&mut img, 22, fatsz as u16);
    w16(&mut img, 24, 1);
    w16(&mut img, 26, 1);
    img[38] = 0x29;
    w32(&mut img, 39, 0xAABBCCDD);
    img[43..54].copy_from_slice(b"FLOPPY     ");
    img[54..62].copy_from_slice(b"FAT12   ");
    img[510] = 0x55;
    img[511] = 0xAA;

    // FAT12: [0]=media+FF, [1]=FFF, [2]=FFF (EOC)
    let fat = |img: &mut [u8], base: usize| {
        img[base] = 0xF8;
        img[base + 1] = 0xFF;
        img[base + 2] = 0xFF;
        // cluster 2 → EOC: entry n at n*3/2; n=2 → offset 3, even → low 12 bits
        img[base + 3] = 0xFF;
        img[base + 4] = (img[base + 4] & 0xF0) | 0x0F;
    };
    fat(&mut img, reserved * BPS);
    fat(&mut img, (reserved + fatsz) * BPS);

    // root dir at sector 5 (1 + 2*2)
    let root = (reserved + nfats * fatsz) * BPS;
    let (wd, wt) = (dos_date(1995, 6, 1), dos_time(8, 0, 0));
    dirent(&mut img, root, 0, b"DATA    TXT", ATTR_ARCHIVE, 2, 7, false, wt, wd, 0, wt, wd, 0);
    // data at sector 6 (root_secs=1): cluster2 → offset (6 + (2-2))*512
    let off = (reserved + nfats * fatsz + root_secs) * BPS;
    img[off..off + 7].copy_from_slice(b"fat12ok");
    img
}
