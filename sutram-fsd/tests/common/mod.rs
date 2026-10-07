//! Synthetic FAT12 image for `sutram-fsd` tests — the `sutram-cli` builder
//! pattern (`tests/cli.rs` there): boot sector + 2 FATs + fixed root dir +
//! data clusters, written byte-by-byte, no fixtures, no network.
//!
//! Layout (bps=512, spc=1, reserved=1, nfats=2, fatsz=8, root=224 entries):
//!
//! ```text
//! sector 0        boot sector (55AA)
//! 1..9            FAT #0
//! 9..17           FAT #1 (mirror)
//! 0x2200..        root directory region
//! data area       cluster n → root_end + (n-2)*512
//! ```
//!
//! Corpus: HELLO.TXT live (cl 2), _ELETED.TXT deleted-intact (cl 3),
//! TESTDIR (cl 4) containing FAKE.TXT (cl 5) — MZ/PE content under a .TXT
//! name, i.e. a `Severity::High` masquerade.

/// FAT12 geometry constants shared with the tests.
pub const BPS: usize = 512;
pub const ROOT_OFF: usize = 0x2200;
pub const DATA_OFF: usize = ROOT_OFF + 224 * 32;

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

/// Set a packed 12-bit FAT entry in both FAT copies.
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

/// Byte offset of cluster `c`'s data.
pub fn clus_off(c: u16) -> usize {
    DATA_OFF + (c as usize - 2) * BPS
}

/// The test image: ~1 MiB, the corpus described in the module docs.
pub fn fat12_image() -> Vec<u8> {
    let mut img = vec![0u8; 1 << 20];
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"SUTRAMFS");
    img[11..13].copy_from_slice(&512u16.to_le_bytes()); // bps
    img[13] = 1; // spc
    img[14..16].copy_from_slice(&1u16.to_le_bytes()); // reserved
    img[16] = 2; // nfats
    img[17..19].copy_from_slice(&224u16.to_le_bytes()); // root ents
    img[19..21].copy_from_slice(&2048u16.to_le_bytes()); // total sectors
    img[21] = 0xF8;
    img[22..24].copy_from_slice(&8u16.to_le_bytes()); // fat sz
    img[24..26].copy_from_slice(&32u16.to_le_bytes());
    img[26..28].copy_from_slice(&64u16.to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;
    for base in [512usize, 512 + 8 * 512] {
        img[base] = 0xF8;
        img[base + 1] = 0xFF;
        img[base + 2] = 0xFF;
    }
    // Chains: every used cluster is a single-cluster EOC chain.
    for c in [2u16, 3, 4, 5] {
        set_fat12(&mut img, c, 0xFFF);
    }

    let rd = ROOT_OFF;
    dent(&mut img, rd, b"HELLO", b"TXT", 0x20, 2, 20);
    dent(
        &mut img,
        rd + 32,
        &[0xE5, b'D', b'E', b'L', b'E', b'T', b'E', b'D'],
        b"TXT",
        0x20,
        3,
        12,
    );
    dent(&mut img, rd + 64, b"TESTDIR", b"", 0x10, 4, 0);
    img[clus_off(2)..clus_off(2) + 20].copy_from_slice(b"hello forensic world");
    img[clus_off(3)..clus_off(3) + 12].copy_from_slice(b"deleted data");
    let d = clus_off(4);
    dent(&mut img, d, b".", b"", 0x10, 4, 0);
    dent(&mut img, d + 32, b"..", b"", 0x10, 0, 0);
    dent(&mut img, d + 64, b"FAKE", b"TXT", 0x20, 5, 64);
    let f = clus_off(5);
    img[f] = b'M';
    img[f + 1] = b'Z';
    img[f + 0x3C..f + 0x40].copy_from_slice(&0x40u32.to_le_bytes()); // e_lfanew
    img[f + 0x40..f + 0x44].copy_from_slice(b"PE\0\0"); // real PE sig
    img
}
