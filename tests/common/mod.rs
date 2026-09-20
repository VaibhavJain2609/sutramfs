//! Synthetic exFAT image construction for tests.
//!
//! **This is the test-corpus pattern every SUTRAM-FS parser copies** (see
//! `sutram-fat/tests/common`): build the filesystem byte-by-byte in a
//! `Vec<u8>` (boot region, FAT, allocation bitmap, directory entry sets,
//! file data), mount via `Arc<Vec<u8>>`, assert on the `FsEntry` stream.
//! No fixture files, no network.
//!
//! Geometry (bps = 512, spc_shift = 0 → 512 B clusters):
//!
//! ```text
//! sectors 0–11    main boot region (boot sector + checksum sector 11)
//! sectors 12–23   backup boot region
//! sectors 24–27   FAT (4 sectors = 512 u32 entries)
//! sector  28+     cluster heap: cluster c → (28 + c - 2) * 512
//! ```
//!
//! Cluster map of the corpus (200 clusters):
//!
//! | cluster  | contents                                            |
//! |----------|-----------------------------------------------------|
//! | 2,31,32  | root directory (FAT chain)                          |
//! | 3        | allocation bitmap (25 bytes)                        |
//! | 4        | up-case table                                       |
//! | 5→30     | HELLO.TXT — fragmented FAT chain, 700 B             |
//! | 6        | DIR1                                                |
//! | 7        | INNER.TXT (inside DIR1)                             |
//! | 8–9      | "A Very Long File Name.TXT" contiguous (NoFatChain) |
//! | 10–11    | DELETED1.TXT — deleted, contiguous, bitmap clear    |
//! | 12       | NEWFILE.TXT live — owns OLDPARTIAL's first cluster  |
//! | 12–13    | OLDPARTIAL.BIN deleted; 12 reallocated, 13 survives |
//! | 14       | GONE.BIN deleted → reallocated to HOLDER.BIN        |
//! | 15       | GHOST.TMP deleted, past the 0x00 end marker         |
//! | 16       | RESUME.DOCX — PK bytes (container-consistent)       |
//! | 17       | EVIL.DOC — MZ bytes (masquerade)                    |
//! | 18–19    | orphan chain — bitmap-allocated, no entry set       |
//! | 20,21,33 | BIGDIR — 12 files + a stray secondary run           |
//! | 23–24    | DELCHAIN.BIN — deleted, FAT chain survives          |
//! | 25       | STRAYBIN's cluster (bitmap clear)                   |

pub const BPS: usize = 512;
pub const FAT_SECTOR: usize = 24;
pub const FAT_SECTORS: u32 = 4;
pub const HEAP_SECTOR: usize = 28;
pub const CLUSTER_COUNT: u32 = 200;
pub const VOLUME_SECTORS: usize = HEAP_SECTOR + CLUSTER_COUNT as usize; // 228
pub const EOC: u32 = 0xFFFF_FFFF;
/// Slots per cluster = 512 / 32.
pub const SLOTS_PER_CLUSTER: usize = 16;
pub const ROOT_CLUSTERS: [u32; 3] = [2, 31, 32];
pub const DIR1_CLUSTERS: [u32; 1] = [6];
pub const BIGDIR_CLUSTERS: [u32; 3] = [20, 21, 33];

/// Absolute byte offset of cluster `c`'s first byte.
pub fn clus_off(c: u32) -> usize {
    HEAP_SECTOR * BPS + (c as usize - 2) * BPS
}

/// Absolute byte offset of `slot` in a directory stored on `clus`.
pub fn doff(clus: &[u32], slot: usize) -> usize {
    clus_off(clus[slot / SLOTS_PER_CLUSTER]) + (slot % SLOTS_PER_CLUSTER) * 32
}

fn w16(img: &mut [u8], off: usize, v: u16) {
    img[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(img: &mut [u8], off: usize, v: u32) {
    img[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(img: &mut [u8], off: usize, v: u64) {
    img[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Set a FAT entry.
pub fn set_fat(img: &mut [u8], cluster: u32, val: u32) {
    w32(img, FAT_SECTOR * BPS + cluster as usize * 4, val);
}

/// Write file content at a cluster.
pub fn put_data(img: &mut [u8], cluster: u32, data: &[u8]) {
    let off = clus_off(cluster);
    img[off..off + data.len()].copy_from_slice(data);
}

/// exFAT DOS-style datetime: date (year-1980 packed) in the high u16,
/// 2-second time in the low u16.
pub fn exdt(y: u16, m: u16, d: u16, h: u16, mi: u16, s: u16) -> u32 {
    let date = ((y - 1980) << 9) | (m << 5) | d;
    let time = (h << 11) | (mi << 5) | (s / 2);
    ((date as u32) << 16) | (time as u32)
}

/// The exFAT entry-set checksum (same algorithm as the parser).
pub fn set_checksum(set: &[u8]) -> u16 {
    let mut sum = 0u16;
    for (i, &b) in set.iter().enumerate() {
        if i == 2 || i == 3 {
            continue;
        }
        sum = ((sum & 1) << 15)
            .wrapping_add(sum >> 1)
            .wrapping_add(b as u16);
    }
    sum
}

/// The exFAT boot-region checksum over 11 sectors.
pub fn boot_checksum(region: &[u8]) -> u32 {
    let mut sum = 0u32;
    for (i, &b) in region.iter().enumerate() {
        if i == 106 || i == 107 || i == 112 {
            continue;
        }
        sum = ((sum & 1) << 31)
            .wrapping_add(sum >> 1)
            .wrapping_add(b as u32);
    }
    sum
}

/// Write a file entry set at `slot` of the directory stored on `clus`.
/// `ts` = `[create, modify, access]` packed datetimes; `cs` = `[create10ms,
/// modify10ms]`; `tz` = `[create, modify, access]` UTC-offset bytes.
/// `deleted` writes the set with live types then clears every in-use bit —
/// so the checksum verifies with the bits restored, as on real media.
/// Returns the number of slots consumed.
#[allow(clippy::too_many_arguments)]
pub fn file_set(
    img: &mut [u8],
    clus: &[u32],
    slot: usize,
    name: &str,
    attr: u16,
    fc: u32,
    valid: u64,
    dlen: u64,
    no_fat: bool,
    ts: [u32; 3],
    cs: [u8; 2],
    tz: [u8; 3],
    deleted: bool,
) -> usize {
    let units: Vec<u16> = name.encode_utf16().collect();
    let nname = units.len().div_ceil(15).max(1);
    let nsec = 1 + nname;
    let poff = doff(clus, slot);
    img[poff] = 0x85;
    img[poff + 1] = nsec as u8;
    // [2..4] checksum filled in below
    w16(img, poff + 4, attr);
    w32(img, poff + 8, ts[0]);
    w32(img, poff + 12, ts[1]);
    w32(img, poff + 16, ts[2]);
    img[poff + 20] = cs[0];
    img[poff + 21] = cs[1];
    img[poff + 22] = tz[0];
    img[poff + 23] = tz[1];
    img[poff + 24] = tz[2];
    let soff = doff(clus, slot + 1);
    img[soff] = 0xC0;
    img[soff + 1] = if no_fat { 0x02 } else { 0x00 };
    img[soff + 3] = units.len() as u8;
    w16(img, soff + 4, 0); // NameHash — not verified by this parser
    w64(img, soff + 8, valid);
    w32(img, soff + 20, fc);
    w64(img, soff + 24, dlen);
    for i in 0..nname {
        let o = doff(clus, slot + 2 + i);
        img[o] = 0xC1;
        let end = units.len().min((i + 1) * 15);
        for (j, u) in units[i * 15..end].iter().enumerate() {
            w16(img, o + 2 + j * 2, *u);
        }
    }
    // Checksum over the whole set, gathered across cluster boundaries.
    let mut bytes = Vec::with_capacity(32 * (1 + nsec));
    for i in 0..=nsec {
        let o = doff(clus, slot + i);
        bytes.extend_from_slice(&img[o..o + 32]);
    }
    let sum = set_checksum(&bytes);
    w16(img, poff + 2, sum);
    if deleted {
        for i in 0..=nsec {
            let o = doff(clus, slot + i);
            img[o] &= 0x7F;
        }
    }
    1 + nsec
}

/// Write an allocation-bitmap entry (type 0x81).
pub fn ent_bitmap(img: &mut [u8], off: usize, fc: u32, len: u64) {
    img[off] = 0x81;
    w32(img, off + 20, fc);
    w64(img, off + 24, len);
}

/// Write an up-case-table entry (type 0x82).
pub fn ent_upcase(img: &mut [u8], off: usize, checksum: u32, fc: u32, len: u64) {
    img[off] = 0x82;
    w32(img, off + 4, checksum);
    w32(img, off + 20, fc);
    w64(img, off + 24, len);
}

/// Write a volume-label entry (type 0x83), max 11 UTF-16 units.
pub fn ent_label(img: &mut [u8], off: usize, label: &str) {
    img[off] = 0x83;
    let units: Vec<u16> = label.encode_utf16().take(11).collect();
    img[off + 1] = units.len() as u8;
    for (j, u) in units.iter().enumerate() {
        w16(img, off + 2 + j * 2, *u);
    }
}

/// Write a stray deleted secondary run (stream `0x40` + name `0x41`) with
/// no primary — as left behind when a deleted set's primary was reused.
pub fn stray_secondary(
    img: &mut [u8],
    clus: &[u32],
    slot: usize,
    name: &str,
    fc: u32,
    valid: u64,
    dlen: u64,
    no_fat: bool,
) {
    let units: Vec<u16> = name.encode_utf16().collect();
    let soff = doff(clus, slot);
    img[soff] = 0x40; // stream ext, in-use cleared
    img[soff + 1] = if no_fat { 0x02 } else { 0x00 };
    img[soff + 3] = units.len() as u8;
    w64(img, soff + 8, valid);
    w32(img, soff + 20, fc);
    w64(img, soff + 24, dlen);
    let noff = doff(clus, slot + 1);
    img[noff] = 0x41; // file name, in-use cleared
    for (j, u) in units.iter().take(15).enumerate() {
        w16(img, noff + 2 + j * 2, *u);
    }
}

/// Bitmap byte value for a set of allocated cluster numbers.
fn bitmap_bytes(allocated: &[u32]) -> Vec<u8> {
    let mut bm = vec![0u8; CLUSTER_COUNT.div_ceil(8) as usize];
    for &c in allocated {
        let idx = (c - 2) as usize;
        bm[idx / 8] |= 1 << (idx % 8);
    }
    bm
}

/// Build the exFAT corpus image (~114 KiB).
pub fn build_exfat() -> Vec<u8> {
    let mut img = vec![0u8; VOLUME_SECTORS * BPS];

    // ---- boot sector ---------------------------------------------------
    img[0] = 0xEB;
    img[1] = 0x76;
    img[2] = 0x90;
    img[3..11].copy_from_slice(b"EXFAT   ");
    // 0x0B..0x40 MustBeZero — already zero.
    w64(&mut img, 0x40, 0); // PartitionOffset
    w64(&mut img, 0x48, VOLUME_SECTORS as u64);
    w32(&mut img, 0x50, FAT_SECTOR as u32);
    w32(&mut img, 0x54, FAT_SECTORS);
    w32(&mut img, 0x58, HEAP_SECTOR as u32);
    w32(&mut img, 0x5C, CLUSTER_COUNT);
    w32(&mut img, 0x60, 2); // root dir cluster
    w32(&mut img, 0x64, 0x1BAD_B002); // volume serial
    w16(&mut img, 0x68, 0x0100); // revision 1.0
    w16(&mut img, 0x6A, 0); // volume flags
    img[0x6C] = 9; // bytes/sector shift → 512
    img[0x6D] = 0; // sectors/cluster shift → 1
    img[0x6E] = 1; // NumberOfFats
    img[0x6F] = 0x80; // drive select
    img[0x70] = 30; // percent in use
    // Extended boot sectors carry the 0xAA550000 signature in the last 4 B.
    for s in 1..=8usize {
        w32(&mut img, s * BPS + BPS - 4, 0xAA55_0000);
    }
    img[510] = 0x55;
    img[511] = 0xAA;

    // ---- backup boot region (sector 12 = copy of boot sector) -----------
    img.copy_within(0..BPS, 12 * BPS);
    for s in 13..=20usize {
        w32(&mut img, s * BPS + BPS - 4, 0xAA55_0000);
    }

    // ---- boot checksums (sectors 11 and 23) ------------------------------
    let sum = boot_checksum(&img[0..11 * BPS]);
    for i in 0..BPS / 4 {
        w32(&mut img, 11 * BPS + i * 4, sum);
    }
    let sum2 = boot_checksum(&img[12 * BPS..23 * BPS]);
    for i in 0..BPS / 4 {
        w32(&mut img, 23 * BPS + i * 4, sum2);
    }

    // ---- FAT --------------------------------------------------------------
    set_fat(&mut img, 0, 0xFFFF_FFF8);
    set_fat(&mut img, 1, EOC);
    set_fat(&mut img, 2, 31); // root dir chain
    set_fat(&mut img, 31, 32);
    set_fat(&mut img, 32, EOC);
    set_fat(&mut img, 3, EOC); // bitmap
    set_fat(&mut img, 4, EOC); // upcase
    set_fat(&mut img, 5, 30); // HELLO.TXT fragmented
    set_fat(&mut img, 30, EOC);
    set_fat(&mut img, 6, EOC); // DIR1
    set_fat(&mut img, 7, EOC); // INNER.TXT
    set_fat(&mut img, 8, EOC); // long-name file (contiguous anyway)
    set_fat(&mut img, 9, EOC);
    set_fat(&mut img, 12, EOC); // NEWFILE.TXT
    set_fat(&mut img, 14, EOC); // HOLDER.BIN
    set_fat(&mut img, 16, EOC); // RESUME.DOCX
    set_fat(&mut img, 17, EOC); // EVIL.DOC
    set_fat(&mut img, 18, 19); // orphan chain
    set_fat(&mut img, 19, EOC);
    set_fat(&mut img, 20, 21); // BIGDIR chain
    set_fat(&mut img, 21, 33);
    set_fat(&mut img, 33, EOC);
    set_fat(&mut img, 23, 24); // DELCHAIN.BIN deleted — links survive
    set_fat(&mut img, 24, EOC);

    // ---- allocation bitmap (cluster 3) ------------------------------------
    let allocated: &[u32] = &[
        2, 3, 4, 5, 6, 7, 8, 9, 12, 14, 16, 17, 18, 19, 20, 21, 30, 31, 32, 33,
    ];
    let bm = bitmap_bytes(allocated);
    put_data(&mut img, 3, &bm);
    // up-case table stub (parser records but does not verify it)
    put_data(&mut img, 4, b"UPCASE-TABLE-STUB");

    // ---- file data ---------------------------------------------------------
    let mut hello = b"hello, fragmented world".to_vec();
    hello.resize(512, b'.');
    put_data(&mut img, 5, &hello);
    put_data(&mut img, 30, b"the tail of hello lives on cluster 30");
    put_data(&mut img, 7, b"TEST");
    put_data(&mut img, 8, b"\x89PNG\x0D\x0A\x1A\x0A not really a text file");
    put_data(&mut img, 9, b"long name file tail");
    put_data(&mut img, 10, b"DELETED-INTACT-HEAD");
    put_data(&mut img, 11, b"DELETED-INTACT-TAIL");
    put_data(&mut img, 12, b"newfile owns cluster twelve now");
    put_data(&mut img, 13, b"oldpartial tail survives!!");
    put_data(&mut img, 14, b"holder data");
    put_data(&mut img, 15, b"ghost!!!");
    let mut pk = b"PK\x03\x04\x14\0\0\0".to_vec();
    pk.resize(32, 0);
    put_data(&mut img, 16, &pk);
    let mut mz = b"MZ\x90\0\x03\0\0\0".to_vec();
    mz.resize(60, 0);
    put_data(&mut img, 17, &mz);
    put_data(&mut img, 18, b"ORPHANED-CHAIN-START");
    put_data(&mut img, 19, b"ORPHANED-CHAIN-TAIL!");
    put_data(&mut img, 23, b"deleted chain head");
    put_data(&mut img, 24, b"deleted chain tail");
    put_data(&mut img, 25, b"stray secondary data");

    // ---- root directory (clusters 2, 31, 32) -------------------------------
    let root = &ROOT_CLUSTERS;
    let ts = [
        exdt(2024, 1, 15, 10, 30, 20),
        exdt(2024, 1, 15, 10, 30, 20),
        exdt(2024, 1, 16, 0, 0, 0),
    ];
    let tz = [0x88, 0x88, 0x80]; // UTC+2 / UTC+2 / UTC
    ent_label(&mut img, doff(root, 0), "SUTRAMEXFAT");
    ent_bitmap(&mut img, doff(root, 1), 3, bm.len() as u64);
    ent_upcase(&mut img, doff(root, 2), 0xE619_DC30, 4, 64);
    file_set(&mut img, root, 3, "HELLO.TXT", 0x20, 5, 700, 700, false, ts, [50, 50], tz, false);
    file_set(&mut img, root, 6, "DIR1", 0x10, 6, 512, 512, false, ts, [0, 0], tz, false);
    file_set(&mut img, root, 9, "A Very Long File Name.TXT", 0x20, 8, 700, 1024, true, ts, [0, 0], tz, false);
    file_set(&mut img, root, 13, "DELETED1.TXT", 0x20, 10, 600, 1024, true, ts, [0, 0], tz, true);
    file_set(&mut img, root, 16, "OLDPARTIAL.BIN", 0x20, 12, 700, 1024, true, ts, [0, 0], tz, true);
    file_set(&mut img, root, 19, "NEWFILE.TXT", 0x20, 12, 100, 512, true, ts, [0, 0], tz, false);
    file_set(&mut img, root, 22, "GONE.BIN", 0x20, 14, 300, 512, true, ts, [0, 0], tz, true);
    file_set(&mut img, root, 25, "HOLDER.BIN", 0x20, 14, 50, 512, true, ts, [0, 0], tz, false);
    file_set(&mut img, root, 28, "RESUME.DOCX", 0x20, 16, 32, 512, true, ts, [0, 0], tz, false);
    file_set(&mut img, root, 31, "EVIL.DOC", 0x20, 17, 60, 512, true, ts, [0, 0], tz, false);
    file_set(&mut img, root, 34, "BIGDIR", 0x10, 20, 1536, 1536, false, ts, [0, 0], tz, false);
    // slot 37: 0x00 end-of-directory marker (already zero)
    file_set(&mut img, root, 38, "GHOST.TMP", 0x20, 15, 8, 512, true, ts, [0, 0], tz, true);

    // ---- DIR1 (cluster 6) ---------------------------------------------------
    let d1 = &DIR1_CLUSTERS;
    file_set(&mut img, d1, 0, "INNER.TXT", 0x20, 7, 4, 512, false, ts, [0, 0], tz, false);
    file_set(&mut img, d1, 3, "DELCHAIN.BIN", 0x20, 23, 700, 1024, false, ts, [0, 0], tz, true);

    // ---- BIGDIR (clusters 20, 21, 33) ---------------------------------------
    let bd = &BIGDIR_CLUSTERS;
    let names = [
        "FILE00.DAT", "FILE01.DAT", "FILE02.DAT", "FILE03.DAT", "FILE04.DAT", "FILE05.DAT",
        "FILE06.DAT", "FILE07.DAT", "FILE08.DAT", "FILE09.DAT", "FILE10.DAT", "FILE11.DAT",
    ];
    for (i, n) in names.iter().enumerate() {
        file_set(&mut img, bd, i * 3, n, 0x20, 0, 0, 0, false, ts, [0, 0], tz, false);
    }
    // slot 36: EOD marker (zero)
    // slots 40–41: stray deleted secondary run — primary overwritten
    stray_secondary(&mut img, bd, 40, "STRAYBIN", 25, 64, 512, true);

    img
}
