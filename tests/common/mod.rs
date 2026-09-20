//! Synthetic Android image builders — the test corpus is constructed in
//! memory, never loaded from fixture files (CONVENTIONS §6).

#![allow(dead_code)]

use sutram_part::sha256::sha256;

pub fn w16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn w32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn w64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
pub fn w32be(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_be_bytes());
}
pub fn w64be(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_be_bytes());
}

// ---------------------------------------------------------------------------
// Android sparse image
// ---------------------------------------------------------------------------

/// One sparse chunk spec: (type, output blocks, payload after the 12-byte
/// chunk header). Types: 0xCAC1 RAW, 0xCAC2 FILL(4-byte value), 0xCAC3
/// DONT_CARE, 0xCAC4 CRC32.
pub type SparseChunk = (u16, u32, Vec<u8>);

/// Build an Android sparse image (`img2simg` layout, 28-byte file header).
pub fn sparse_img(chunks: &[SparseChunk], block_size: u32) -> Vec<u8> {
    let mut img = Vec::new();
    let mut hdr = [0u8; 28];
    w32(&mut hdr, 0, 0xED26_FF3A);
    w16(&mut hdr, 4, 1); // major
    w16(&mut hdr, 6, 0); // minor
    w16(&mut hdr, 8, 28); // file_hdr_sz
    w16(&mut hdr, 10, 12); // chunk_hdr_sz
    w32(&mut hdr, 12, block_size);
    w32(&mut hdr, 16, chunks.iter().map(|c| c.1).sum());
    w32(&mut hdr, 20, chunks.len() as u32);
    img.extend_from_slice(&hdr);
    for (ty, blocks, payload) in chunks {
        let mut ch = [0u8; 12];
        w16(&mut ch, 0, *ty);
        w32(&mut ch, 4, *blocks);
        w32(&mut ch, 8, 12 + payload.len() as u32);
        img.extend_from_slice(&ch);
        img.extend_from_slice(payload);
    }
    img
}

/// Wrap a raw image as a sparse image with one RAW chunk per `blk` bytes;
/// the tail chunk is zero-padded to a full block like `img2simg` does.
pub fn as_sparse(raw: &[u8], block_size: u32) -> Vec<u8> {
    let blk = block_size as usize;
    let mut chunks = Vec::new();
    for c in raw.chunks(blk) {
        let mut p = c.to_vec();
        p.resize(blk, 0);
        chunks.push((0xCAC1u16, 1u32, p));
    }
    sparse_img(&chunks, block_size)
}

// ---------------------------------------------------------------------------
// liblp super image
// ---------------------------------------------------------------------------

pub const LP_MAX_SIZE: u32 = 65536;
pub const LP_SLOT_COUNT: u32 = 2;
/// First logical sector the builder uses (must clear the metadata area).
pub const LP_FIRST_SECTOR: u64 = 2048; // 1 MiB

/// A logical partition to bake into a synthetic super image.
pub struct SuperPart {
    pub name: &'static str,
    pub group: &'static str,
    /// `LP_PARTITION_ATTR_*` bits.
    pub attrs: u32,
    /// Bytes written into the partition's linear extent.
    pub data: Vec<u8>,
}

fn put36(b: &mut [u8], off: usize, s: &str) {
    let n = s.len().min(36);
    b[off..off + n].copy_from_slice(&s.as_bytes()[..n]);
}

fn geometry(max_size: u32, slots: u32, block_size: u32) -> [u8; 52] {
    let mut g = [0u8; 52];
    w32(&mut g, 0, 0x616c4467);
    w32(&mut g, 4, 52);
    w32(&mut g, 40, max_size);
    w32(&mut g, 44, slots);
    w32(&mut g, 48, block_size);
    let mut tmp = g;
    tmp[8..40].fill(0);
    g[8..40].copy_from_slice(&sha256(&tmp));
    g
}

/// Serialise one metadata blob (256-byte v1.2 header + tables) — the bytes
/// that occupy a single metadata slot.
fn metadata_blob(parts: &[SuperPart], slot: u32, image_size: u64) -> Vec<u8> {
    // Extents: one LINEAR extent per partition, laid out consecutively
    // starting at LP_FIRST_SECTOR.
    let mut extents: Vec<(u64, u64, u64, u32)> = Vec::new(); // (sectors,type,data,src)
    let mut sector = LP_FIRST_SECTOR;
    let mut part_rows = Vec::new();
    for p in parts {
        let sectors = (p.data.len() as u64).div_ceil(512);
        part_rows.push((extents.len() as u32, 1u32));
        extents.push((sectors, 0, sector, 0)); // LINEAR
        sector += sectors;
    }

    // Groups: keep insertion order, index 0 = first seen.
    let mut groups: Vec<&str> = Vec::new();
    let mut group_idx = Vec::new();
    for p in parts {
        let gi = groups
            .iter()
            .position(|g| *g == p.group)
            .unwrap_or_else(|| {
                groups.push(p.group);
                groups.len() - 1
            });
        group_idx.push(gi as u32);
    }
    if groups.is_empty() {
        groups.push("default");
    }

    // Serialise tables.
    let mut t_parts = vec![0u8; parts.len() * 52];
    for (i, p) in parts.iter().enumerate() {
        let e = &mut t_parts[i * 52..i * 52 + 52];
        put36(e, 0, p.name);
        w32(e, 36, p.attrs);
        w32(e, 40, part_rows[i].0);
        w32(e, 44, part_rows[i].1);
        w32(e, 48, group_idx[i]);
    }
    let mut t_ext = vec![0u8; extents.len() * 24];
    for (i, (sectors, ty, data, src)) in extents.iter().enumerate() {
        let e = &mut t_ext[i * 24..i * 24 + 24];
        w64(e, 0, *sectors);
        w32(e, 8, *ty as u32);
        w64(e, 12, *data);
        w32(e, 20, *src);
    }
    let mut t_grp = vec![0u8; groups.len() * 48];
    for (i, g) in groups.iter().enumerate() {
        let e = &mut t_grp[i * 48..i * 48 + 48];
        put36(e, 0, g);
        w32(e, 36, 0);
        w64(e, 40, 0);
    }
    let mut t_bdev = vec![0u8; 64];
    w64(&mut t_bdev, 0, LP_FIRST_SECTOR);
    w32(&mut t_bdev, 8, 1 << 20); // alignment 1 MiB
    w32(&mut t_bdev, 12, 0);
    w64(&mut t_bdev, 16, image_size);
    put36(&mut t_bdev, 24, "super");
    w32(&mut t_bdev, 60, 0);

    let mut tables = Vec::new();
    let parts_off = 0u32;
    tables.extend_from_slice(&t_parts);
    let ext_off = tables.len() as u32;
    tables.extend_from_slice(&t_ext);
    let grp_off = tables.len() as u32;
    tables.extend_from_slice(&t_grp);
    let bdev_off = tables.len() as u32;
    tables.extend_from_slice(&t_bdev);
    let tables_checksum = sha256(&tables);

    let mut hdr = vec![0u8; 256];
    w32(&mut hdr, 0, 0x414C_5030);
    w16(&mut hdr, 4, 10); // major
    w16(&mut hdr, 6, 2); // minor (v1.2 header)
    w32(&mut hdr, 8, 256); // header_size
    w32(&mut hdr, 44, tables.len() as u32); // tables_size
    hdr[48..80].copy_from_slice(&tables_checksum);
    let put_desc = |hdr: &mut [u8], off: usize, toff: u32, num: u32, esz: u32| {
        w32(hdr, off, toff);
        w32(hdr, off + 4, num);
        w32(hdr, off + 8, esz);
    };
    put_desc(&mut hdr, 80, parts_off, parts.len() as u32, 52);
    put_desc(&mut hdr, 92, ext_off, extents.len() as u32, 24);
    put_desc(&mut hdr, 104, grp_off, groups.len() as u32, 48);
    put_desc(&mut hdr, 116, bdev_off, 1, 64);
    w32(&mut hdr, 128, 0); // flags
    let _ = slot;
    let mut tmp = hdr.clone();
    tmp[12..44].fill(0);
    let hsum = sha256(&tmp);
    hdr[12..44].copy_from_slice(&hsum);

    let mut blob = hdr;
    blob.extend_from_slice(&tables);
    blob.resize(LP_MAX_SIZE as usize, 0);
    blob
}

/// Build a super image. `corrupt_slot` may point at a slot index whose
/// primary copy is zeroed (exercises the backup-copy fallback).
pub fn super_img(parts: &[SuperPart], corrupt_slot: Option<u32>) -> Vec<u8> {
    let data_bytes: u64 = parts
        .iter()
        .map(|p| (p.data.len() as u64).div_ceil(512) * 512)
        .sum();
    let size = (LP_FIRST_SECTOR * 512 + data_bytes + 0x1000) as usize;
    let mut img = vec![0u8; size];

    let geo = geometry(LP_MAX_SIZE, LP_SLOT_COUNT, 4096);
    img[0x1000..0x1000 + 52].copy_from_slice(&geo); // primary
    img[0x2000..0x2000 + 52].copy_from_slice(&geo); // backup

    let prim = 0x1000 + 0x2000; // 0x3000
    let back = prim + LP_MAX_SIZE as usize * LP_SLOT_COUNT as usize;
    for slot in 0..LP_SLOT_COUNT {
        let blob = metadata_blob(parts, slot, size as u64);
        if Some(slot) != corrupt_slot {
            img[prim + slot as usize * LP_MAX_SIZE as usize..][..blob.len()].copy_from_slice(&blob);
        }
        img[back + slot as usize * LP_MAX_SIZE as usize..][..blob.len()].copy_from_slice(&blob);
    }

    // Partition data at LP_FIRST_SECTOR.
    let mut off = LP_FIRST_SECTOR * 512;
    for p in parts {
        img[off as usize..off as usize + p.data.len()].copy_from_slice(&p.data);
        off += (p.data.len() as u64).div_ceil(512) * 512;
    }
    img
}

// ---------------------------------------------------------------------------
// GPT device image
// ---------------------------------------------------------------------------

pub struct GptPart {
    pub name: &'static str,
    /// Raw 16-byte type GUID (any non-zero value is fine for the parser).
    pub type_guid: [u8; 16],
    pub data: Vec<u8>,
}

/// Build a protective-MBR + GPT image; partitions are laid out from LBA 34.
pub fn gpt_img(parts: &[GptPart]) -> Vec<u8> {
    let mut lba = 34u64;
    let mut rows = Vec::new();
    for p in parts {
        let sectors = (p.data.len() as u64).div_ceil(512).max(1);
        rows.push((lba, lba + sectors - 1));
        lba += sectors;
    }
    let size = (lba + 34) as usize * 512;
    let mut img = vec![0u8; size];

    // Protective MBR.
    img[0x1BE + 4] = 0xEE;
    img[0x1FE] = 0x55;
    img[0x1FF] = 0xAA;

    // GPT header at LBA 1.
    let h = 512usize;
    img[h..h + 8].copy_from_slice(b"EFI PART");
    w32(&mut img, h + 8, 0x0001_0000);
    w32(&mut img, h + 12, 92);
    w64(&mut img, h + 72, 2); // entries_lba
    w32(&mut img, h + 80, parts.len() as u32);
    w32(&mut img, h + 84, 128);

    for (i, p) in parts.iter().enumerate() {
        let e = 2 * 512 + i * 128;
        img[e..e + 16].copy_from_slice(&p.type_guid);
        img[e + 16..e + 32].copy_from_slice(&[0x11; 16]);
        w64(&mut img, e + 32, rows[i].0);
        w64(&mut img, e + 40, rows[i].1);
        // UTF-16LE name.
        for (j, ch) in p.name.encode_utf16().take(36).enumerate() {
            w16(&mut img, e + 56 + j * 2, ch);
        }
        img[rows[i].0 as usize * 512..rows[i].0 as usize * 512 + p.data.len()]
            .copy_from_slice(&p.data);
    }
    img
}

/// A GPT type GUID that reads as "android-test" entropy — content doesn't
/// matter, only non-zero.
pub fn test_guid(seed: u8) -> [u8; 16] {
    let mut g = [seed; 16];
    g[0] = 0xA0;
    g
}

// ---------------------------------------------------------------------------
// vbmeta blob + AVB footer
// ---------------------------------------------------------------------------

/// Build a vbmeta blob with the given flags/rollback and raw descriptor
/// region (already tag/size-prefixed).
pub fn vbmeta_blob(flags: u32, rollback: u64, descriptors: &[u8]) -> Vec<u8> {
    let aux_size = descriptors.len().next_multiple_of(64).max(64) as u64;
    let mut aux = vec![0u8; aux_size as usize];
    aux[..descriptors.len()].copy_from_slice(descriptors);
    let mut hdr = vec![0u8; 256];
    hdr[0..4].copy_from_slice(b"AVB0");
    w32be(&mut hdr, 4, 1);
    w32be(&mut hdr, 8, 0);
    w64be(&mut hdr, 12, 0); // auth block size
    w64be(&mut hdr, 20, aux_size);
    w32be(&mut hdr, 28, 6); // SHA256_RSA4096-ish
    w64be(&mut hdr, 96, 0); // descriptors_offset
    w64be(&mut hdr, 104, descriptors.len() as u64);
    w64be(&mut hdr, 112, rollback);
    w32be(&mut hdr, 120, flags);
    hdr[128..141].copy_from_slice(b"avbtool 1.2.0");
    hdr.extend_from_slice(&aux);
    hdr
}

/// Kernel-cmdline descriptor for vbmeta.
pub fn kernel_cmdline_desc(cmdline: &str) -> Vec<u8> {
    let payload = 8 + cmdline.len();
    let padded = payload.next_multiple_of(8);
    let mut d = Vec::new();
    d.extend_from_slice(&3u64.to_be_bytes());
    d.extend_from_slice(&(padded as u64).to_be_bytes());
    let mut f = vec![0u8; padded];
    w32be(&mut f, 0, 0);
    w32be(&mut f, 4, cmdline.len() as u32);
    f[8..8 + cmdline.len()].copy_from_slice(cmdline.as_bytes());
    d.extend_from_slice(&f);
    d
}

/// Wrap `vbmeta` inside a boot-style image: data, vbmeta, AVBf footer.
pub fn boot_img_with_vbmeta(vbmeta: &[u8]) -> Vec<u8> {
    let mut img = vec![0u8; 0x8000];
    let voff = img.len() as u64;
    img.extend_from_slice(vbmeta);
    img.resize(voff as usize + vbmeta.len().next_multiple_of(64), 0);
    let mut footer = [0u8; 64];
    footer[0..4].copy_from_slice(b"AVBf");
    w32be(&mut footer, 4, 1);
    w32be(&mut footer, 8, 0);
    w64be(&mut footer, 12, voff);
    w64be(&mut footer, 20, voff);
    w64be(&mut footer, 28, vbmeta.len() as u64);
    img.extend_from_slice(&footer);
    img
}

/// Paint a `crypt_ftr` footer at `size - 0x4000`.
pub fn with_crypt_footer(img: &mut [u8], crypt_type: u32, cipher: &str) {
    let off = img.len() - 0x4000;
    let mut f = [0u8; 128];
    w32(&mut f, 0, 0xD0B5_B1C4);
    w16(&mut f, 4, 1);
    w16(&mut f, 6, 5);
    w32(&mut f, 8, 128);
    w32(&mut f, 16, 16);
    w32(&mut f, 20, crypt_type);
    f[36..36 + cipher.len()].copy_from_slice(cipher.as_bytes());
    img[off..off + 128].copy_from_slice(&f);
}
