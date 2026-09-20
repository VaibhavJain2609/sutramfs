//! Synthetic BTRFS image construction for tests — the same test-corpus
//! pattern as `sutram-fat`, byte-exact with valid CRC32C checksums.
//!
//! Geometry: nodesize = sectorsize = 4 KiB; a single SYSTEM chunk maps
//! logical addresses **identically** to physical (logical == physical), so
//! `logical` constants below are also absolute file offsets.
//!
//! ```text
//! 0x10000   superblock (gen 7, CRC32C valid, backup root → gen 5)
//! 0x400000  chunk tree leaf: CHUNK_ITEM (identity chunk) + DEV_ITEM
//! 0x401000  root tree leaf: ROOT_ITEMs for 2/5/257 + ROOT_REF "snap1"
//! 0x402000  OLD root tree leaf (gen 5) — reached via backup root
//! 0x410000  FS tree internal node (level 1) → leaves 0x411000/0x412000
//! 0x420000  OLD FS tree leaf (gen 5): live+deleted+prior-version inodes
//! 0x430000  snap1 subvolume leaf (gen 7)
//! 0x440000  extent tree leaf: EXTENT_ITEMs + EXTENT_DATA_REFs
//! 0x500000+ data extents (live, deleted, reallocated, compressed, inline)
//! ```
//!
//! Corpus:
//!
//! | inode | name         | status                                   |
//! |-------|--------------|------------------------------------------|
//! | 256   | /            | live root dir                            |
//! | 257   | hello.txt    | live, "hello world!"                     |
//! | 259   | (unnamed)    | ORPHAN_ITEM → Deleted, extent allocated  |
//! | 261   | newfile.bin  | live — its extent overwrote old.log's    |
//! | 262   | packed.z     | live, zlib-compressed extent             |
//! | 263   | subdir       | live directory                           |
//! | 264   | subdir/inner | live file "TEST"                         |
//! | 265   | link1        | live symlink → /hello.txt (inline)       |
//! | 266   | masq.doc     | live, MZ content (masquerade)            |
//! | 267   | second.txt   | live, in FS leaf 2 (internal-node path)  |
//! | 257@5 | hello.txt@v5 | prior version via COW history            |
//! | 258   | secret.txt   | deleted (gen-5 only), extent freed → Intact |
//! | 260   | old.log      | deleted, extent A reallocated → partial  |
//! | 270   | ghost.tmp    | dangling DIR_ITEM → name-only deleted    |
//! | 257   | snap.txt     | in snapshot subvolume snap1              |

// ---- geometry -------------------------------------------------------------
pub const NODE: usize = 4096;
pub const IMG_SIZE: usize = 0x1000_000; // 16 MiB
pub const SB: usize = 0x10000;
pub const GEN_CUR: u64 = 7;
pub const GEN_OLD: u64 = 5;

// tree block logical addresses (== physical, identity chunk)
pub const CHUNK_TREE: u64 = 0x400000;
pub const ROOT_TREE: u64 = 0x401000;
pub const OLD_ROOT_TREE: u64 = 0x402000;
pub const FS_TREE: u64 = 0x410000;
pub const FS_LEAF1: u64 = 0x411000;
pub const FS_LEAF2: u64 = 0x412000;
pub const OLD_FS_TREE: u64 = 0x420000;
pub const SNAP_TREE: u64 = 0x430000;
pub const EXTENT_TREE: u64 = 0x440000;

// data extents
pub const D_HELLO: u64 = 0x500000; // live hello.txt (4K extent, 12 used)
pub const D_HELLO_OLD: u64 = 0x501000; // freed old hello.txt version
pub const D_SECRET: u64 = 0x502000; // freed secret.txt
pub const D_OLDLOG_B: u64 = 0x503000; // freed old.log tail
pub const D_NEWFILE: u64 = 0x504000; // live newfile (reallocated over old.log A)
pub const D_ORPHAN: u64 = 0x505000; // orphan inode data
pub const D_PACKED: u64 = 0x506000; // zlib-compressed extent
pub const D_INNER: u64 = 0x507000; // subdir/inner.txt
pub const D_MASQ: u64 = 0x508000; // masq.doc (MZ)
pub const D_SECOND: u64 = 0x509000; // second.txt
pub const D_SNAP: u64 = 0x50a000; // snap.txt
pub const D_PASSWD: u64 = 0x50b000; // /etc/passwd
pub const D_GROUP: u64 = 0x50c000; // /etc/group
/// A byte range with no extent item and no data — must be unallocated.
pub const FREE_AREA: u64 = 0x600000;

// item types
pub const T_INODE_ITEM: u8 = 1;
pub const T_INODE_REF: u8 = 12;
pub const T_XATTR: u8 = 24;
pub const T_ORPHAN: u8 = 48;
pub const T_DIR_ITEM: u8 = 84;
pub const T_DIR_INDEX: u8 = 96;
pub const T_EXTENT_DATA: u8 = 108;
pub const T_ROOT_ITEM: u8 = 132;
pub const T_ROOT_REF: u8 = 156;
pub const T_EXTENT_ITEM: u8 = 168;
pub const T_EXTENT_DATA_REF: u8 = 178;
pub const T_DEV_ITEM: u8 = 216;
pub const T_CHUNK_ITEM: u8 = 228;

pub const OBJID_EXTENT_TREE: u64 = 2;
pub const OBJID_FS_TREE: u64 = 5;
pub const OBJID_ORPHAN: u64 = (-48i64) as u64;
pub const OBJID_FIRST_CHUNK_TREE: u64 = 256;

pub const EXTENT_FLAG_DATA: u64 = 1;
pub const EXTENT_FLAG_TREE: u64 = 2;
pub const SUBVOL_RDONLY: u64 = 1;

pub const FSID: [u8; 16] = *b"sutram-btrfs-tst";

// ---- little-endian writers -------------------------------------------------
pub fn w8(b: &mut [u8], off: usize, v: u8) {
    b[off] = v;
}
pub fn w16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn w32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
pub fn w64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
pub fn wkey(b: &mut [u8], off: usize, objectid: u64, ty: u8, offset: u64) {
    w64(b, off, objectid);
    w8(b, off + 8, ty);
    w64(b, off + 9, offset);
}

// ---- node builders ----------------------------------------------------------

/// Assemble a leaf node into `img[bytenr .. bytenr+NODE]`: item table grows
/// forward from 101, item data backward from NODE. `items` must be sorted
/// by key (the builder does not sort).
pub fn leaf(img: &mut [u8], bytenr: u64, owner: u64, gen: u64, items: &[(u64, u8, u64, Vec<u8>)]) {
    let base = bytenr as usize;
    let mut data_cursor = NODE;
    let mut n = 0u32;
    for (i, (obj, ty, off, body)) in items.iter().enumerate() {
        let ipos = base + 101 + i * 25;
        wkey(img, ipos, *obj, *ty, *off);
        data_cursor -= body.len();
        img[base + data_cursor..base + data_cursor + body.len()].copy_from_slice(body);
        w32(img, ipos + 17, (data_cursor - 101) as u32);
        w32(img, ipos + 21, body.len() as u32);
        n += 1;
    }
    header(img, base, bytenr, owner, gen, n, 0);
}

/// Assemble an internal node (level > 0) from `(key, blockptr)` pairs.
/// `ptr_gen` is stamped on every keyptr (child generation).
pub fn internal(
    img: &mut [u8],
    bytenr: u64,
    owner: u64,
    gen: u64,
    level: u8,
    ptrs: &[(u64, u8, u64, u64)],
    ptr_gen: u64,
) {
    let base = bytenr as usize;
    for (i, (obj, ty, off, ptr)) in ptrs.iter().enumerate() {
        let ppos = base + 101 + i * 33;
        wkey(img, ppos, *obj, *ty, *off);
        w64(img, ppos + 17, *ptr);
        w64(img, ppos + 25, ptr_gen);
    }
    header(img, base, bytenr, owner, gen, ptrs.len() as u32, level);
}

/// 101-byte node header + CRC32C (over bytes 32..NODE).
fn header(img: &mut [u8], base: usize, bytenr: u64, owner: u64, gen: u64, nritems: u32, level: u8) {
    img[base + 0x20..base + 0x30].copy_from_slice(&FSID);
    w64(img, base + 0x30, bytenr);
    w64(img, base + 0x38, 0); // flags
    img[base + 0x40..base + 0x50].copy_from_slice(&FSID); // chunk_tree_uuid (reuse fsid)
    w64(img, base + 0x50, gen);
    w64(img, base + 0x58, owner);
    w32(img, base + 0x60, nritems);
    w8(img, base + 0x64, level);
    let csum = crc32fast::hash(&img[base + 32..base + NODE]);
    img[base..base + 4].copy_from_slice(&csum.to_le_bytes());
}

// ---- item body builders -----------------------------------------------------

/// `btrfs_inode_item` (160 B).
pub fn inode_item(gen: u64, transid: u64, size: u64, mode: u32, nlink: u32, uid: u32, gid: u32) -> Vec<u8> {
    let mut b = vec![0u8; 160];
    w64(&mut b, 0, gen);
    w64(&mut b, 8, transid);
    w64(&mut b, 16, size);
    w64(&mut b, 24, size);
    w32(&mut b, 40, nlink);
    w32(&mut b, 44, uid);
    w32(&mut b, 48, gid);
    w32(&mut b, 52, mode);
    // atime/ctime/mtime/otime: 2024-01-15T10:30:20Z + distinct nsec
    let ts = 1_705_314_620u64;
    for (i, off) in [112usize, 124, 136, 148].iter().enumerate() {
        w64(&mut b, *off, ts + i as u64);
        w32(&mut b, *off + 8, (i as u32 + 1) * 100);
    }
    b
}

/// `btrfs_file_extent_item` — regular/prealloc (53 B) or inline (21 + data).
pub fn extent_regular(gen: u64, ram: u64, comp: u8, logical: u64, disk_len: u64, ext_off: u64, num: u64) -> Vec<u8> {
    let mut b = vec![0u8; 53];
    w64(&mut b, 0, gen);
    w64(&mut b, 8, ram);
    w8(&mut b, 16, comp);
    w8(&mut b, 20, 1); // regular
    w64(&mut b, 21, logical);
    w64(&mut b, 29, disk_len);
    w64(&mut b, 37, ext_off);
    w64(&mut b, 45, num);
    b
}

pub fn extent_inline(gen: u64, ram: u64, comp: u8, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 21];
    w64(&mut b, 0, gen);
    w64(&mut b, 8, ram);
    w8(&mut b, 16, comp);
    w8(&mut b, 20, 0); // inline
    b.extend_from_slice(payload);
    b
}

/// `btrfs_inode_ref`: index(8) + name_len(2) + name.
pub fn inode_ref(index: u64, name: &str) -> Vec<u8> {
    let mut b = vec![0u8; 10];
    w64(&mut b, 0, index);
    w16(&mut b, 8, name.len() as u16);
    b.extend_from_slice(name.as_bytes());
    b
}

/// `btrfs_dir_item`: location key + transid + lens + type + name[+data].
pub fn dir_item(child_ino: u64, name: &str, ftype: u8, xattr_data: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 30];
    wkey(&mut b, 0, child_ino, T_INODE_ITEM, 0);
    w64(&mut b, 17, 1); // transid
    w16(&mut b, 25, xattr_data.len() as u16);
    w16(&mut b, 27, name.len() as u16);
    w8(&mut b, 29, ftype);
    b.extend_from_slice(name.as_bytes());
    b.extend_from_slice(xattr_data);
    b
}

/// `btrfs_root_item` (439 B): embedded inode + bytenr at 176, flags at 208,
/// level at 238, generation_v2 at 239, parent_uuid at 263.
pub fn root_item(bytenr: u64, gen: u64, level: u8, flags: u64, parent_uuid: bool) -> Vec<u8> {
    let mut b = vec![0u8; 439];
    b[..160].copy_from_slice(&inode_item(gen, gen, 0, 0o40755, 1, 0, 0));
    w64(&mut b, 160, gen);
    w64(&mut b, 168, 256); // root_dirid
    w64(&mut b, 176, bytenr);
    w64(&mut b, 208, flags);
    w8(&mut b, 238, level);
    if parent_uuid {
        b[263] = 0x5A; // non-zero parent_uuid → snapshot
    }
    b
}

/// `btrfs_root_ref`: dirid(8) + sequence(8) + name_len(2) + name.
pub fn root_ref(dirid: u64, name: &str) -> Vec<u8> {
    let mut b = vec![0u8; 18];
    w64(&mut b, 0, dirid);
    w16(&mut b, 16, name.len() as u16);
    b.extend_from_slice(name.as_bytes());
    b
}

/// `btrfs_chunk`: single-stripe identity chunk.
pub fn chunk_item(length: u64, ty: u64, devid: u64, phys: u64) -> Vec<u8> {
    let mut b = vec![0u8; 48 + 32];
    w64(&mut b, 0, length);
    w64(&mut b, 8, 3); // owner = chunk tree
    w64(&mut b, 16, 0x10000); // stripe_len
    w64(&mut b, 24, ty);
    w32(&mut b, 32, 4096);
    w32(&mut b, 36, 4096);
    w32(&mut b, 40, 4096);
    w16(&mut b, 44, 1); // num_stripes
    w64(&mut b, 48, devid);
    w64(&mut b, 56, phys);
    b
}

/// `btrfs_dev_item` (98 B) — only the fields we read.
pub fn dev_item(devid: u64, total: u64) -> Vec<u8> {
    let mut b = vec![0u8; 98];
    w64(&mut b, 0, devid);
    w64(&mut b, 8, total);
    w64(&mut b, 16, total / 2); // bytes_used
    w32(&mut b, 40, 4096);
    b
}

/// `btrfs_extent_item` fixed part: refs(8) + generation(8) + flags(8).
pub fn extent_item(gen: u64, flags: u64) -> Vec<u8> {
    let mut b = vec![0u8; 24];
    w64(&mut b, 0, 1); // refs
    w64(&mut b, 8, gen);
    w64(&mut b, 16, flags);
    b
}

/// `btrfs_extent_data_ref` (28 B): root + inode + file offset + count.
pub fn extent_data_ref(root: u64, inode: u64, file_offset: u64) -> Vec<u8> {
    let mut b = vec![0u8; 28];
    w64(&mut b, 0, root);
    w64(&mut b, 8, inode);
    w64(&mut b, 16, file_offset);
    w32(&mut b, 24, 1);
    b
}

// ---- the corpus image -------------------------------------------------------

/// Build the 16 MiB synthetic BTRFS volume.
pub fn build_image() -> Vec<u8> {
    let mut img = vec![0u8; IMG_SIZE];

    // ======================== superblock @0x10000 ===========================
    {
        let s = SB;
        img[s + 0x20..s + 0x30].copy_from_slice(&FSID);
        w64(&mut img, s + 0x30, SB as u64); // bytenr
        img[s + 0x40..s + 0x48].copy_from_slice(b"_BHRfS_M");
        w64(&mut img, s + 0x48, GEN_CUR); // generation
        w64(&mut img, s + 0x50, ROOT_TREE);
        w64(&mut img, s + 0x58, CHUNK_TREE);
        w64(&mut img, s + 0x70, IMG_SIZE as u64); // total_bytes
        w64(&mut img, s + 0x78, 0x200000); // bytes_used
        w64(&mut img, s + 0x80, 6); // root_dir_objectid
        w64(&mut img, s + 0x88, 1); // num_devices
        w32(&mut img, s + 0x90, 4096); // sectorsize
        w32(&mut img, s + 0x94, 4096); // nodesize
        w32(&mut img, s + 0x9C, 4096); // stripesize
        w32(&mut img, s + 0xA0, 17 + 80); // sys_chunk_array_size
        w64(&mut img, s + 0xA4, GEN_CUR); // chunk_root_generation
        w16(&mut img, s + 0xC4, 0); // csum_type = CRC32C
        img[s + 0x12B..s + 0x12B + 6].copy_from_slice(b"TESTFS");

        // embedded DEV_ITEM at 0xC9
        let di = dev_item(1, IMG_SIZE as u64);
        img[s + 0xC9..s + 0xC9 + 98].copy_from_slice(&di);

        // sys_chunk_array at 0x32B: key(256,CHUNK_ITEM,0) + chunk(identity)
        let ca = s + 0x32B;
        wkey(&mut img, ca, OBJID_FIRST_CHUNK_TREE, T_CHUNK_ITEM, 0);
        let ci = chunk_item(IMG_SIZE as u64, 1 | 2, 1, 0); // DATA|SYSTEM
        img[ca + 17..ca + 17 + 80].copy_from_slice(&ci);

        // backup root[0] at 0xB2B: gen-5 tree_root + fs_root
        let b0 = s + 0xB2B;
        w64(&mut img, b0 + 0, OLD_ROOT_TREE); // tree_root
        w64(&mut img, b0 + 8, GEN_OLD); // tree_root_gen
        w64(&mut img, b0 + 16, CHUNK_TREE); // chunk_root
        w64(&mut img, b0 + 24, GEN_OLD);
        w64(&mut img, b0 + 32, EXTENT_TREE); // extent_root
        w64(&mut img, b0 + 40, GEN_OLD);
        w64(&mut img, b0 + 48, OLD_FS_TREE); // fs_root ← gen-5 FS tree
        w64(&mut img, b0 + 56, GEN_OLD); // fs_root_gen

        // csum last: CRC32C over [32..4096]
        let csum = crc32fast::hash(&img[s + 32..s + 4096]);
        img[s..s + 4].copy_from_slice(&csum.to_le_bytes());
    }

    // ======================== chunk tree @0x400000 ==========================
    leaf(
        &mut img,
        CHUNK_TREE,
        3,
        GEN_CUR,
        &[
            (1, T_DEV_ITEM, 1, dev_item(1, IMG_SIZE as u64)),
            (
                OBJID_FIRST_CHUNK_TREE,
                T_CHUNK_ITEM,
                0,
                chunk_item(IMG_SIZE as u64, 1 | 2, 1, 0),
            ),
        ],
    );

    // ======================== root tree @0x401000 ===========================
    leaf(
        &mut img,
        ROOT_TREE,
        1,
        GEN_CUR,
        &[
            (OBJID_EXTENT_TREE, T_ROOT_ITEM, 0, root_item(EXTENT_TREE, GEN_CUR, 0, 0, false)),
            (OBJID_FS_TREE, T_ROOT_ITEM, 0, root_item(FS_TREE, GEN_CUR, 1, 0, false)),
            (5, T_ROOT_REF, 257, root_ref(256, "snap1")),
            (257, T_ROOT_ITEM, 0, root_item(SNAP_TREE, GEN_CUR, 0, SUBVOL_RDONLY, true)),
        ],
    );

    // ==================== OLD root tree @0x402000 (gen 5) ===================
    leaf(
        &mut img,
        OLD_ROOT_TREE,
        1,
        GEN_OLD,
        &[
            (OBJID_EXTENT_TREE, T_ROOT_ITEM, 0, root_item(EXTENT_TREE, GEN_OLD, 0, 0, false)),
            (OBJID_FS_TREE, T_ROOT_ITEM, 0, root_item(OLD_FS_TREE, GEN_OLD, 0, 0, false)),
            (5, T_ROOT_REF, 257, root_ref(256, "snap1")),
            (257, T_ROOT_ITEM, 0, root_item(SNAP_TREE, GEN_OLD, 0, SUBVOL_RDONLY, true)),
        ],
    );

    // ==================== FS tree: internal + 2 leaves ======================
    internal(
        &mut img,
        FS_TREE,
        OBJID_FS_TREE,
        GEN_CUR,
        1,
        &[
            (256, 0, 0, FS_LEAF1),
            (262, 0, 0, FS_LEAF2),
        ],
        GEN_CUR,
    );

    // FS leaf 1: inodes 256..261 + orphan record
    let dir_mode = 0o40755u32;
    let file_mode = 0o100644u32;
    leaf(
        &mut img,
        FS_LEAF1,
        OBJID_FS_TREE,
        GEN_CUR,
        &[
            (256, T_INODE_ITEM, 0, inode_item(1, GEN_CUR, 0, dir_mode, 1, 0, 0)),
            // dir items of root dir
            (256, T_DIR_ITEM, 100, dir_item(257, "hello.txt", 1, &[])),
            (256, T_DIR_ITEM, 101, dir_item(259, "pending.txt", 1, &[])),
            (256, T_DIR_ITEM, 102, dir_item(261, "newfile.bin", 1, &[])),
            (256, T_DIR_ITEM, 103, dir_item(262, "packed.z", 1, &[])),
            (256, T_DIR_ITEM, 104, dir_item(263, "subdir", 2, &[])),
            (256, T_DIR_ITEM, 105, dir_item(265, "link1", 7, &[])),
            (256, T_DIR_ITEM, 106, dir_item(266, "masq.doc", 1, &[])),
            (256, T_DIR_ITEM, 107, dir_item(267, "second.txt", 1, &[])),
            (256, T_DIR_ITEM, 108, dir_item(268, "etc", 2, &[])),
            (256, T_DIR_INDEX, 2, dir_item(257, "hello.txt", 1, &[])),
            // hello.txt — live file
            (257, T_INODE_ITEM, 0, inode_item(2, GEN_CUR, 12, file_mode, 1, 1000, 1000)),
            (257, T_INODE_REF, 256, inode_ref(0, "hello.txt")),
            (257, T_XATTR, 88, dir_item(0, "user.origin", 8, b"sutram")),
            (257, T_EXTENT_DATA, 0, extent_regular(GEN_CUR, 4096, 0, D_HELLO, 4096, 0, 12)),
            // orphan inode 259: has inode+extent but an ORPHAN_ITEM
            (259, T_INODE_ITEM, 0, inode_item(3, GEN_CUR, 11, file_mode, 0, 0, 0)),
            (259, T_EXTENT_DATA, 0, extent_regular(GEN_CUR, 4096, 0, D_ORPHAN, 4096, 0, 11)),
            // newfile.bin — live; its extent reallocated over old.log's
            (261, T_INODE_ITEM, 0, inode_item(4, GEN_CUR, 22, file_mode, 1, 0, 0)),
            (261, T_INODE_REF, 256, inode_ref(0, "newfile.bin")),
            (261, T_EXTENT_DATA, 0, extent_regular(GEN_CUR, 4096, 0, D_NEWFILE, 4096, 0, 22)),
        ],
    );

    // FS leaf 2: inodes 262..267 (compressed, subdir, symlink, masq, second)
    let packed_plain = b"PACKED-BTRFS-ZLIB-CONTENT-payload-0123456789abcdef".to_vec();
    let packed_comp = {
        use std::io::Write;
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&packed_plain).unwrap();
        e.finish().unwrap()
    };
    let plen = packed_plain.len() as u64;
    let clen = packed_comp.len() as u64;
    img[D_PACKED as usize..D_PACKED as usize + packed_comp.len()].copy_from_slice(&packed_comp);

    leaf(
        &mut img,
        FS_LEAF2,
        OBJID_FS_TREE,
        GEN_CUR,
        &[
            (262, T_INODE_ITEM, 0, inode_item(5, GEN_CUR, plen, file_mode, 1, 0, 0)),
            (262, T_INODE_REF, 256, inode_ref(0, "packed.z")),
            (262, T_EXTENT_DATA, 0, extent_regular(GEN_CUR, plen, 1, D_PACKED, clen, 0, plen)),
            (263, T_INODE_ITEM, 0, inode_item(6, GEN_CUR, 0, dir_mode, 1, 0, 0)),
            (263, T_INODE_REF, 256, inode_ref(0, "subdir")),
            (263, T_DIR_ITEM, 200, dir_item(264, "inner.txt", 1, &[])),
            (264, T_INODE_ITEM, 0, inode_item(7, GEN_CUR, 4, file_mode, 1, 0, 0)),
            (264, T_INODE_REF, 263, inode_ref(0, "inner.txt")),
            (264, T_EXTENT_DATA, 0, extent_regular(GEN_CUR, 4096, 0, D_INNER, 4096, 0, 4)),
            (265, T_INODE_ITEM, 0, inode_item(8, GEN_CUR, 10, 0o120777, 1, 0, 0)),
            (265, T_INODE_REF, 256, inode_ref(0, "link1")),
            (265, T_EXTENT_DATA, 0, extent_inline(GEN_CUR, 10, 0, b"/hello.txt")),
            (266, T_INODE_ITEM, 0, inode_item(9, GEN_CUR, 60, file_mode, 1, 0, 0)),
            (266, T_INODE_REF, 256, inode_ref(0, "masq.doc")),
            (266, T_EXTENT_DATA, 0, extent_regular(GEN_CUR, 4096, 0, D_MASQ, 4096, 0, 60)),
            (267, T_INODE_ITEM, 0, inode_item(10, GEN_CUR, 16, file_mode, 1, 0, 0)),
            (267, T_INODE_REF, 256, inode_ref(0, "second.txt")),
            (267, T_EXTENT_DATA, 0, extent_regular(GEN_CUR, 4096, 0, D_SECOND, 4096, 0, 16)),
            (268, T_INODE_ITEM, 0, inode_item(11, GEN_CUR, 0, dir_mode, 1, 0, 0)),
            (268, T_INODE_REF, 256, inode_ref(0, "etc")),
            (268, T_DIR_ITEM, 200, dir_item(269, "passwd", 1, &[])),
            (268, T_DIR_ITEM, 201, dir_item(271, "group", 1, &[])),
            (269, T_INODE_ITEM, 0, inode_item(12, GEN_CUR, 70, file_mode, 1, 0, 0)),
            (269, T_INODE_REF, 268, inode_ref(0, "passwd")),
            (269, T_EXTENT_DATA, 0, extent_regular(GEN_CUR, 4096, 0, D_PASSWD, 4096, 0, 70)),
            (271, T_INODE_ITEM, 0, inode_item(13, GEN_CUR, 24, file_mode, 1, 0, 0)),
            (271, T_INODE_REF, 268, inode_ref(0, "group")),
            (271, T_EXTENT_DATA, 0, extent_regular(GEN_CUR, 4096, 0, D_GROUP, 4096, 0, 24)),
            // ORPHAN_ITEM: objectid -48, offset = orphan inode 259
            (OBJID_ORPHAN, T_ORPHAN, 259, Vec::new()),
        ],
    );

    // ==================== OLD FS tree @0x420000 (gen 5) =====================
    leaf(
        &mut img,
        OLD_FS_TREE,
        OBJID_FS_TREE,
        GEN_OLD,
        &[
            // root dir — identical to live (transid 1, no extents) → skipped
            (256, T_INODE_ITEM, 0, inode_item(1, 1, 0, dir_mode, 1, 0, 0)),
            (256, T_DIR_ITEM, 100, dir_item(257, "hello.txt", 1, &[])),
            (256, T_DIR_ITEM, 110, dir_item(258, "secret.txt", 1, &[])),
            (256, T_DIR_ITEM, 111, dir_item(260, "old.log", 1, &[])),
            (256, T_DIR_ITEM, 112, dir_item(270, "ghost.tmp", 1, &[])),
            // old hello.txt — same inode, different transid/extent → prior ver
            (257, T_INODE_ITEM, 0, inode_item(2, GEN_OLD, 7, file_mode, 1, 1000, 1000)),
            (257, T_INODE_REF, 256, inode_ref(0, "hello.txt")),
            (257, T_EXTENT_DATA, 0, extent_regular(GEN_OLD, 4096, 0, D_HELLO_OLD, 4096, 0, 7)),
            // secret.txt — deleted outright (absent from live tree)
            (258, T_INODE_ITEM, 0, inode_item(3, GEN_OLD, 18, file_mode, 1, 0, 0)),
            (258, T_INODE_REF, 256, inode_ref(0, "secret.txt")),
            (258, T_EXTENT_DATA, 0, extent_regular(GEN_OLD, 4096, 0, D_SECRET, 4096, 0, 18)),
            // old.log — extent A at 0x504000 was reallocated to newfile.bin
            (260, T_INODE_ITEM, 0, inode_item(4, GEN_OLD, 8192, file_mode, 1, 0, 0)),
            (260, T_INODE_REF, 256, inode_ref(0, "old.log")),
            (260, T_EXTENT_DATA, 0, extent_regular(GEN_OLD, 4096, 0, D_NEWFILE, 4096, 0, 4096)),
            (260, T_EXTENT_DATA, 4096, extent_regular(GEN_OLD, 4096, 0, D_OLDLOG_B, 4096, 0, 4096)),
            // ghost.tmp (ino 270): dangling dir item — no inode item exists
        ],
    );

    // ==================== snap1 subvolume @0x430000 ==========================
    leaf(
        &mut img,
        SNAP_TREE,
        257,
        GEN_CUR,
        &[
            (256, T_INODE_ITEM, 0, inode_item(1, GEN_CUR, 0, dir_mode, 1, 0, 0)),
            (256, T_DIR_ITEM, 100, dir_item(257, "snap.txt", 1, &[])),
            (257, T_INODE_ITEM, 0, inode_item(2, GEN_CUR, 8, file_mode, 1, 0, 0)),
            (257, T_INODE_REF, 256, inode_ref(0, "snap.txt")),
            (257, T_EXTENT_DATA, 0, extent_regular(GEN_CUR, 4096, 0, D_SNAP, 4096, 0, 8)),
        ],
    );

    // ==================== extent tree @0x440000 ==============================
    // Allocated: every metadata block + live data extents. NOT allocated:
    // D_HELLO_OLD, D_SECRET, D_OLDLOG_B (freed gen-5 remnants) — and the old
    // FS tree block itself (a freed COW block still readable).
    let meta_flags = EXTENT_FLAG_TREE;
    let data_flags = EXTENT_FLAG_DATA;
    leaf(
        &mut img,
        EXTENT_TREE,
        OBJID_EXTENT_TREE,
        GEN_CUR,
        &[
            (CHUNK_TREE, T_EXTENT_ITEM, NODE as u64, extent_item(GEN_CUR, meta_flags)),
            (ROOT_TREE, T_EXTENT_ITEM, NODE as u64, extent_item(GEN_CUR, meta_flags)),
            (OLD_ROOT_TREE, T_EXTENT_ITEM, NODE as u64, extent_item(GEN_OLD, meta_flags)),
            (FS_TREE, T_EXTENT_ITEM, NODE as u64, extent_item(GEN_CUR, meta_flags)),
            (FS_LEAF1, T_EXTENT_ITEM, NODE as u64, extent_item(GEN_CUR, meta_flags)),
            (FS_LEAF2, T_EXTENT_ITEM, NODE as u64, extent_item(GEN_CUR, meta_flags)),
            (SNAP_TREE, T_EXTENT_ITEM, NODE as u64, extent_item(GEN_CUR, meta_flags)),
            (EXTENT_TREE, T_EXTENT_ITEM, NODE as u64, extent_item(GEN_CUR, meta_flags)),
            (D_HELLO, T_EXTENT_ITEM, 4096, extent_item(GEN_CUR, data_flags)),
            (D_HELLO, T_EXTENT_DATA_REF, 0x1234, extent_data_ref(OBJID_FS_TREE, 257, 0)),
            (D_NEWFILE, T_EXTENT_ITEM, 4096, extent_item(GEN_CUR, data_flags)),
            (D_NEWFILE, T_EXTENT_DATA_REF, 0x2345, extent_data_ref(OBJID_FS_TREE, 261, 0)),
            (D_ORPHAN, T_EXTENT_ITEM, 4096, extent_item(GEN_CUR, data_flags)),
            (D_ORPHAN, T_EXTENT_DATA_REF, 0x3456, extent_data_ref(OBJID_FS_TREE, 259, 0)),
            (D_PACKED, T_EXTENT_ITEM, 4096, extent_item(GEN_CUR, data_flags)),
            (D_PACKED, T_EXTENT_DATA_REF, 0x4567, extent_data_ref(OBJID_FS_TREE, 262, 0)),
            (D_INNER, T_EXTENT_ITEM, 4096, extent_item(GEN_CUR, data_flags)),
            (D_INNER, T_EXTENT_DATA_REF, 0x5678, extent_data_ref(OBJID_FS_TREE, 264, 0)),
            (D_MASQ, T_EXTENT_ITEM, 4096, extent_item(GEN_CUR, data_flags)),
            (D_MASQ, T_EXTENT_DATA_REF, 0x6789, extent_data_ref(OBJID_FS_TREE, 266, 0)),
            (D_SECOND, T_EXTENT_ITEM, 4096, extent_item(GEN_CUR, data_flags)),
            (D_SECOND, T_EXTENT_DATA_REF, 0x789a, extent_data_ref(OBJID_FS_TREE, 267, 0)),
            (D_SNAP, T_EXTENT_ITEM, 4096, extent_item(GEN_CUR, data_flags)),
            (D_SNAP, T_EXTENT_DATA_REF, 0x89ab, extent_data_ref(257, 257, 0)),
            (D_PASSWD, T_EXTENT_ITEM, 4096, extent_item(GEN_CUR, data_flags)),
            (D_PASSWD, T_EXTENT_DATA_REF, 0x9abc, extent_data_ref(OBJID_FS_TREE, 269, 0)),
            (D_GROUP, T_EXTENT_ITEM, 4096, extent_item(GEN_CUR, data_flags)),
            (D_GROUP, T_EXTENT_DATA_REF, 0xabcd, extent_data_ref(OBJID_FS_TREE, 271, 0)),
        ],
    );

    // ==================== data payloads ======================================
    let put = |img: &mut [u8], at: u64, data: &[u8]| {
        img[at as usize..at as usize + data.len()].copy_from_slice(data);
    };
    put(&mut img, D_HELLO, b"hello world!");
    put(&mut img, D_HELLO_OLD, b"HELLO-V");
    put(&mut img, D_SECRET, b"TOPSECRET-DELETED!");
    put(&mut img, D_OLDLOG_B, b"TAIL-OF-OLD-LOG-BLOCK");
    put(&mut img, D_NEWFILE, b"newfile overwrote this");
    put(&mut img, D_ORPHAN, b"orphan-data");
    put(&mut img, D_INNER, b"TEST");
    let mut mz = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
    mz.resize(60, 0);
    put(&mut img, D_MASQ, &mz);
    put(&mut img, D_SECOND, b"second file data");
    put(&mut img, D_SNAP, b"SNAPDATA");
    let pw = b"root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:A,,,:/home/admin:/bin/sh\n";
    put(&mut img, D_PASSWD, pw);
    put(&mut img, D_GROUP, b"root:x:0:\nadmin:x:1000:\n");

    img
}
