//! Synthetic HFS+ volume construction for tests — the `sutram-fat` corpus
//! pattern applied to B-trees. **All on-disk fields are big-endian.**
//!
//! Layout (`BLOCK = 4096`, `TOTAL_BLOCKS = 80`, image = 320 KiB):
//!
//! ```text
//! offset 1024     volume header ("H+")
//! block 4         allocation file (bitmap: blocks 0..=30 + 40 allocated)
//! blocks 5-6      extents-overflow B-tree (header + 1 leaf)
//! blocks 7-11     catalog B-tree: node0 header, nodes 1-2 leaf chain,
//!                 node3 = DEAD leaf (freed, full of deleted records),
//!                 node4 = map node
//! blocks 12-13    attributes B-tree (decmpfs xattr + FinderInfo xattr)
//! blocks 14-37    file data (see table)
//! block 40        JournalInfoBlock; block 41 = journal buffer w/ 'JNLx'
//! ```
//!
//! File/data map:
//!
//! | block | contents                                                  |
//! |-------|-----------------------------------------------------------|
//! | 14    | hello.txt (cnid 20) live "hello world!" + FinderInfo xattr|
//! | 15    | /subdir/inner.bin (cnid 31)                             |
//! | 16    | /Uniçødé Nåme.txt (cnid 23)                             |
//! | 17    | /EVIL.DOC (cnid 24) MZ bytes → masquerade               |
//! | 18    | /RESUME.DOCX (cnid 25) PK bytes → container-consistent    |
//! | 19    | iNode50 (cnid 50) — hardlink inode data                 |
//! | 20    | /NEWFILE.TXT (cnid 26) — also claimed by dead OLDFILE   |
//! | 21    | /HOLDER.BIN (cnid 27) — claims dead GONE.BIN's block    |
//! | 22-29 | /BIGFILE.BIN (cnid 28) inline extents                 |
//! | 30    | BIGFILE overflow extent (via extents-overflow file)     |
//! | 31    | DELETED.TXT residue data (free block)                   |
//! | 32    | OLDFILE.TXT residue tail (free block)                   |
//! | 33    | orphan extents data (cnid 99, no catalog record)        |
//! | 35    | /LINK symlink target bytes                              |
//! | 36/37 | /RICHES.TXT data + resource fork                      |

pub const BLOCK: usize = 4096;
pub const TOTAL_BLOCKS: u32 = 80;
pub const IMG_SIZE: usize = TOTAL_BLOCKS as usize * BLOCK;
pub const VH_OFF: usize = 1024;
pub const NODE_SIZE: usize = 4096;

/// Special-file block placement.
pub const ALLOC_BLOCK: u32 = 4;
pub const EXT_BLOCK: u32 = 5; // 2 nodes: 5,6
pub const CAT_BLOCK: u32 = 7; // 5 nodes: 7..11
pub const ATTR_BLOCK: u32 = 12; // 2 nodes: 12,13
pub const JIB_BLOCK: u32 = 40;
pub const JOURNAL_BLOCK: u32 = 41;

/// HFS+ epoch (1904) ↔ unix helper: raw u32 for unix seconds `s`.
pub const fn hfs_time(unix_secs: u32) -> u32 {
    unix_secs + 2_082_844_800
}

/// Absolute byte offset of allocation block `b`.
pub fn block_off(b: u32) -> usize {
    b as usize * BLOCK
}

// ---- big-endian writers -------------------------------------------------

pub fn w16(img: &mut [u8], off: usize, v: u16) {
    img[off..off + 2].copy_from_slice(&v.to_be_bytes());
}
pub fn w32(img: &mut [u8], off: usize, v: u32) {
    img[off..off + 4].copy_from_slice(&v.to_be_bytes());
}
pub fn w64(img: &mut [u8], off: usize, v: u64) {
    img[off..off + 8].copy_from_slice(&v.to_be_bytes());
}

// ---- on-disk structure builders (return owned byte vecs) ----------------

/// Catalog key `(parentID, name)`.
pub fn cat_key(parent: u32, name: &str) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut v = Vec::new();
    v.extend_from_slice(&(6 + 2 * units.len() as u16).to_be_bytes());
    v.extend_from_slice(&parent.to_be_bytes());
    v.extend_from_slice(&(units.len() as u16).to_be_bytes());
    for u in units {
        v.extend_from_slice(&u.to_be_bytes());
    }
    v
}

/// `HFSPlusForkData` (80 bytes).
pub fn fork_data(logical_size: u64, extents: &[(u32, u32)]) -> [u8; 80] {
    let mut f = [0u8; 80];
    f[0..8].copy_from_slice(&logical_size.to_be_bytes());
    let blocks: u32 = extents.iter().map(|e| e.1).sum();
    f[8..12].copy_from_slice(&4096u32.to_be_bytes());
    f[12..16].copy_from_slice(&blocks.to_be_bytes());
    for (i, &(s, c)) in extents.iter().enumerate().take(8) {
        f[16 + i * 8..20 + i * 8].copy_from_slice(&s.to_be_bytes());
        f[20 + i * 8..24 + i * 8].copy_from_slice(&c.to_be_bytes());
    }
    f
}

const DATES: [u32; 5] = [
    // create, content_mod, attr_mod, access, backup
    hfs_time(1_705_314_620),
    hfs_time(1_705_400_000),
    hfs_time(1_705_410_000),
    hfs_time(1_705_420_000),
    0,
];

/// Folder record body (88 bytes).
pub fn folder_rec(cnid: u32, valence: u32) -> Vec<u8> {
    let mut d = vec![0u8; 88];
    d[0..2].copy_from_slice(&1i16.to_be_bytes());
    d[4..8].copy_from_slice(&valence.to_be_bytes());
    d[8..12].copy_from_slice(&cnid.to_be_bytes());
    for (i, t) in DATES.iter().enumerate() {
        d[12 + i * 4..16 + i * 4].copy_from_slice(&t.to_be_bytes());
    }
    d[32..36].copy_from_slice(&0u32.to_be_bytes()); // owner
    d[36..40].copy_from_slice(&80u32.to_be_bytes()); // group
    d[42..44].copy_from_slice(&0o40755u16.to_be_bytes()); // mode
    d
}

/// File record body (248 bytes).
#[allow(clippy::too_many_arguments)]
pub fn file_rec(
    cnid: u32,
    flags: u16,
    user_flags: u8,
    special: u32,
    fd_type: u32,
    fd_creator: u32,
    data: &[(u32, u32)],
    data_size: u64,
    rsrc: &[(u32, u32)],
    rsrc_size: u64,
) -> Vec<u8> {
    let mut d = vec![0u8; 248];
    d[0..2].copy_from_slice(&2i16.to_be_bytes());
    d[2..4].copy_from_slice(&flags.to_be_bytes());
    d[8..12].copy_from_slice(&cnid.to_be_bytes());
    for (i, t) in DATES.iter().enumerate() {
        d[12 + i * 4..16 + i * 4].copy_from_slice(&t.to_be_bytes());
    }
    d[32..36].copy_from_slice(&501u32.to_be_bytes()); // owner
    d[36..40].copy_from_slice(&20u32.to_be_bytes()); // group
    d[41] = user_flags;
    d[42..44].copy_from_slice(&0o100644u16.to_be_bytes()); // mode
    d[44..48].copy_from_slice(&special.to_be_bytes());
    d[48..52].copy_from_slice(&fd_type.to_be_bytes());
    d[52..56].copy_from_slice(&fd_creator.to_be_bytes());
    d[88..168].copy_from_slice(&fork_data(data_size, data));
    d[168..248].copy_from_slice(&fork_data(rsrc_size, rsrc));
    d
}

/// Thread record body: type i16, reserved i16, parentID u32, name unistr.
pub fn thread_rec(folder_thread: bool, parent: u32, name: &str) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut d = Vec::new();
    d.extend_from_slice(&(if folder_thread { 3i16 } else { 4i16 }).to_be_bytes());
    d.extend_from_slice(&0i16.to_be_bytes());
    d.extend_from_slice(&parent.to_be_bytes());
    d.extend_from_slice(&(units.len() as u16).to_be_bytes());
    for u in units {
        d.extend_from_slice(&u.to_be_bytes());
    }
    d
}

/// A whole catalog leaf record (key + data).
pub fn leaf_record(parent: u32, name: &str, data: &[u8]) -> Vec<u8> {
    let mut r = cat_key(parent, name);
    r.extend_from_slice(data);
    r
}

/// Build a B-tree node: descriptor + records + trailing offset table.
/// `residue` bytes are appended after the last record — inside the node's
/// free space, invisible to the offset table (deleted-record residue).
pub fn node(
    kind: i8,
    height: u8,
    next: u32,
    prev: u32,
    records: &[Vec<u8>],
    residue: &[u8],
) -> Vec<u8> {
    let mut n = vec![0u8; NODE_SIZE];
    n[0..4].copy_from_slice(&next.to_be_bytes());
    n[4..8].copy_from_slice(&prev.to_be_bytes());
    n[8] = kind as u8;
    n[9] = height;
    n[10..12].copy_from_slice(&(records.len() as u16).to_be_bytes());
    let mut pos = 14usize;
    let mut offs = Vec::new();
    for r in records {
        assert!(pos + r.len() < NODE_SIZE - 2 * (records.len() + 1));
        offs.push(pos as u16);
        n[pos..pos + r.len()].copy_from_slice(r);
        pos += r.len();
    }
    offs.push(pos as u16);
    // Residue sits in free space (between records end and offset table).
    if !residue.is_empty() {
        assert!(pos + residue.len() < NODE_SIZE - 2 * (records.len() + 1));
        n[pos..pos + residue.len()].copy_from_slice(residue);
    }
    // Offset table at the tail, growing backwards.
    let table = NODE_SIZE - 2 * offs.len();
    for (i, o) in offs.iter().enumerate() {
        n[table + i * 2..table + i * 2 + 2].copy_from_slice(&o.to_be_bytes());
    }
    n
}

/// B-tree header node (node 0): descriptor kind=1 + BTHeaderRec @14.
#[allow(clippy::too_many_arguments)] // mirrors the on-disk header record fields
pub fn header_node(
    depth: u16,
    root: u32,
    leaf_records: u32,
    first_leaf: u32,
    last_leaf: u32,
    total_nodes: u32,
    free_nodes: u32,
    btree_type: u8,
) -> Vec<u8> {
    let mut n = vec![0u8; NODE_SIZE];
    n[8] = 1; // header node
    n[10..12].copy_from_slice(&3u16.to_be_bytes());
    let h = 14usize;
    n[h..h + 2].copy_from_slice(&depth.to_be_bytes());
    n[h + 2..h + 6].copy_from_slice(&root.to_be_bytes());
    n[h + 6..h + 10].copy_from_slice(&leaf_records.to_be_bytes());
    n[h + 10..h + 14].copy_from_slice(&first_leaf.to_be_bytes());
    n[h + 14..h + 18].copy_from_slice(&last_leaf.to_be_bytes());
    n[h + 18..h + 20].copy_from_slice(&(NODE_SIZE as u16).to_be_bytes());
    n[h + 20..h + 22].copy_from_slice(&516u16.to_be_bytes()); // maxKeyLength
    n[h + 22..h + 26].copy_from_slice(&total_nodes.to_be_bytes());
    n[h + 26..h + 30].copy_from_slice(&free_nodes.to_be_bytes());
    n[h + 32..h + 36].copy_from_slice(&(NODE_SIZE as u32).to_be_bytes()); // clump
    n[h + 36] = btree_type;
    n[h + 37] = 0xCF; // case-folding compare
    n[h + 38..h + 42].copy_from_slice(&2u32.to_be_bytes()); // big keys
                                                            // 3 record offsets (header rec, user data, map) + free-space pointer.
    let offs = [14u16, 14 + 106, 14 + 106 + 128, 14 + 106 + 128];
    let table = NODE_SIZE - 8;
    for (i, o) in offs.iter().enumerate() {
        n[table + i * 2..table + i * 2 + 2].copy_from_slice(&o.to_be_bytes());
    }
    n
}

/// Extents-overflow leaf record: key (fork, cnid, startBlock) + 8 extents.
pub fn ext_record(fork: u8, cnid: u32, start_block: u32, exts: &[(u32, u32)]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&10u16.to_be_bytes());
    r.push(fork);
    r.push(0);
    r.extend_from_slice(&cnid.to_be_bytes());
    r.extend_from_slice(&start_block.to_be_bytes());
    for i in 0..8 {
        let (s, c) = exts.get(i).copied().unwrap_or((0, 0));
        r.extend_from_slice(&s.to_be_bytes());
        r.extend_from_slice(&c.to_be_bytes());
    }
    r
}

/// Attributes-file leaf record: key (cnid, startBlock, name) + attr data.
/// `value` is stored inline (record type 0x10).
pub fn attr_inline_record(cnid: u32, name: &str, value: &[u8]) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let klen = 12 + 2 * units.len() as u16;
    let mut r = Vec::new();
    r.extend_from_slice(&klen.to_be_bytes());
    r.extend_from_slice(&0u16.to_be_bytes()); // pad
    r.extend_from_slice(&cnid.to_be_bytes());
    r.extend_from_slice(&0u32.to_be_bytes()); // startBlock
    r.extend_from_slice(&(units.len() as u16).to_be_bytes());
    for u in units {
        r.extend_from_slice(&u.to_be_bytes());
    }
    // Inline attr record: type 0x10, reserved u32, reserved2[6], len u16, data.
    r.extend_from_slice(&0x10u32.to_be_bytes());
    r.extend_from_slice(&0u32.to_be_bytes());
    r.extend_from_slice(&[0u8; 6]);
    r.extend_from_slice(&(value.len() as u16).to_be_bytes());
    r.extend_from_slice(value);
    r
}

/// Write a node vector into the image at `file_block + idx` nodes.
pub fn put_node(img: &mut [u8], first_block: u32, idx: u32, n: &[u8]) {
    let off = block_off(first_block) + idx as usize * NODE_SIZE;
    img[off..off + NODE_SIZE].copy_from_slice(n);
}

/// Write raw bytes at a block.
pub fn put_block(img: &mut [u8], b: u32, data: &[u8]) {
    let off = block_off(b);
    img[off..off + data.len()].copy_from_slice(data);
}

/// Set the allocation-bitmap bit for block `b` (MSB-first per byte).
fn alloc_bit(img: &mut [u8], b: u32) {
    let off = block_off(ALLOC_BLOCK) + (b / 8) as usize;
    img[off] |= 0x80 >> (b % 8);
}

// ---- the corpus ---------------------------------------------------------

/// Build the main HFS+ corpus image.
pub fn build_hfsplus() -> Vec<u8> {
    let mut img = vec![0u8; IMG_SIZE];

    // ---- volume header -------------------------------------------------
    let v = VH_OFF;
    w16(&mut img, v, 0x482B); // "H+"
    w16(&mut img, v + 2, 4); // version
    w32(&mut img, v + 4, 1 << 13 | 1 << 8); // journaled + unmounted
    w32(&mut img, v + 8, 0x482B4C78); // lastMounted "H+Lx"
    w32(&mut img, v + 12, JIB_BLOCK); // journalInfoBlock
    w32(&mut img, v + 16, hfs_time(1_700_000_000)); // createDate
    w32(&mut img, v + 20, hfs_time(1_705_500_000)); // modifyDate
    w32(&mut img, v + 32, 12); // fileCount (approx)
    w32(&mut img, v + 36, 4); // folderCount
    w32(&mut img, v + 40, BLOCK as u32); // blockSize
    w32(&mut img, v + 44, TOTAL_BLOCKS); // totalBlocks
    w32(&mut img, v + 48, 48); // freeBlocks
    w32(&mut img, v + 64, 100); // nextCatalogID
                                // Special-file forks at +112/+192/+272/+352/+432.
    img[v + 112..v + 192].copy_from_slice(&fork_data(BLOCK as u64, &[(ALLOC_BLOCK, 1)]));
    img[v + 192..v + 272].copy_from_slice(&fork_data((2 * NODE_SIZE) as u64, &[(EXT_BLOCK, 2)]));
    img[v + 272..v + 352].copy_from_slice(&fork_data((5 * NODE_SIZE) as u64, &[(CAT_BLOCK, 5)]));
    img[v + 352..v + 432].copy_from_slice(&fork_data((2 * NODE_SIZE) as u64, &[(ATTR_BLOCK, 2)]));

    // ---- allocation bitmap ---------------------------------------------
    for b in 0..=30u32 {
        alloc_bit(&mut img, b);
    }
    alloc_bit(&mut img, JIB_BLOCK);

    // ---- catalog B-tree -------------------------------------------------
    let cat_hdr = header_node(1, 1, 19, 1, 2, 5, 0, 0xFF);
    put_node(&mut img, CAT_BLOCK, 0, &cat_hdr);

    let meta_name = "\u{2400}\u{2400}\u{2400}\u{2400}HFS+ Private Data";
    let node1 = node(
        -1,
        1,
        2,
        0,
        &[
            leaf_record(1, "", &folder_rec(2, 11)), // root folder
            leaf_record(2, "", &thread_rec(true, 1, "TestVol")), // root thread
            leaf_record(2, meta_name, &folder_rec(18, 1)), // hardlink dir
            leaf_record(
                2,
                "BIGFILE.BIN",
                &file_rec(
                    28,
                    0,
                    0,
                    0,
                    0,
                    0,
                    &[(22, 4), (26, 4)], // 8 inline blocks…
                    9 * BLOCK as u64,    // …but 9 blocks of data → overflow
                    &[],
                    0,
                ),
            ),
            leaf_record(
                2,
                "COMPRESSED.BIN",
                &file_rec(45, 0x0004, 0x20, 0, 0, 0, &[], 0, &[], 0),
            ),
            leaf_record(
                2,
                "EVIL.DOC",
                &file_rec(24, 0, 0, 0, 0, 0, &[(17, 1)], 60, &[], 0),
            ),
            leaf_record(
                2,
                "hello.txt",
                &file_rec(20, 0x0004, 0, 0, 0, 0, &[(14, 1)], 12, &[], 0),
            ),
        ],
        &[],
    );
    put_node(&mut img, CAT_BLOCK, 1, &node1);

    // decmpfs type-4: `RSRCCOMP.BIN`'s compressed bytes live in a
    // CmpfRsrcHead block table inside its resource fork (block 38).
    let rsrc_plain = b"resource fork compressed payload hello hello";
    let rz = miniz_oxide::deflate::compress_to_vec_zlib(rsrc_plain, 6);
    let rsrc_size = 32 + rz.len();
    let mut decmpfs4_val = Vec::new();
    decmpfs4_val.extend_from_slice(&0x636D7066u32.to_le_bytes());
    decmpfs4_val.extend_from_slice(&4u32.to_le_bytes()); // zlib resource fork
    decmpfs4_val.extend_from_slice(&(rsrc_plain.len() as u64).to_le_bytes());

    let node2 = node(
        -1,
        1,
        0,
        1,
        &[
            leaf_record(
                2,
                "HOLDER.BIN",
                &file_rec(27, 0, 0, 0, 0, 0, &[(21, 1)], 50, &[], 0),
            ),
            leaf_record(
                2,
                "LINK",
                &file_rec(
                    46,
                    0,
                    0,
                    0,
                    u32::from_be_bytes(*b"slnk"),
                    u32::from_be_bytes(*b"rhap"),
                    &[(35, 1)],
                    10,
                    &[],
                    0,
                ),
            ),
            leaf_record(
                2,
                "NEWFILE.TXT",
                &file_rec(26, 0, 0, 0, 0, 0, &[(20, 1)], 100, &[], 0),
            ),
            leaf_record(
                2,
                "RESUME.DOCX",
                &file_rec(25, 0, 0, 0, 0, 0, &[(18, 1)], 20, &[], 0),
            ),
            leaf_record(
                2,
                "RICHES.TXT",
                &file_rec(47, 0, 0, 0, 0, 0, &[(36, 1)], 12, &[(37, 1)], 18),
            ),
            leaf_record(
                2,
                "RSRCCOMP.BIN",
                &file_rec(49, 0, 0x20, 0, 0, 0, &[], 0, &[(38, 1)], rsrc_size as u64),
            ),
            leaf_record(2, "subdir", &folder_rec(30, 1)),
            leaf_record(
                2,
                "hardlink.txt",
                &file_rec(
                    48,
                    0,
                    0,
                    50, // special = iNode50
                    u32::from_be_bytes(*b"hlnk"),
                    u32::from_be_bytes(*b"hfs+"),
                    &[],
                    0,
                    &[],
                    0,
                ),
            ),
            leaf_record(
                2,
                "Uniçødé Nåme.txt",
                &file_rec(23, 0, 0, 0, 0, 0, &[(16, 1)], 8, &[], 0),
            ),
            leaf_record(18, "", &thread_rec(true, 2, meta_name)),
            leaf_record(
                18,
                "iNode50",
                &file_rec(50, 0, 0, 0, 0, 0, &[(19, 1)], 18, &[], 0),
            ),
            leaf_record(30, "", &thread_rec(true, 2, "subdir")),
            leaf_record(
                30,
                "inner.bin",
                &file_rec(31, 0, 0, 0, 0, 0, &[(15, 1)], 10, &[], 0),
            ),
            // Unreachable-from-root records (parent cnid 77 has no folder
            // record): the OrphanLive pass emits them under /$ORPHANED/.
            leaf_record(
                77,
                "ORPHAN.TXT",
                &file_rec(70, 0, 0, 0, 0, 0, &[(39, 1)], 20, &[], 0),
            ),
            leaf_record(77, "ORPHDIR", &folder_rec(71, 0)),
        ],
        // Residue: a deleted file record rotting in node 2's free space.
        &leaf_record(
            2,
            "DELETED.TXT",
            &file_rec(60, 0, 0, 0, 0, 0, &[(31, 1)], 14, &[], 0),
        ),
    );
    put_node(&mut img, CAT_BLOCK, 2, &node2);

    // Dead leaf node (freed by a past compaction; not in the leaf chain).
    let dead = node(
        -1,
        1,
        0,
        0,
        &[
            leaf_record(
                2,
                "OLDFILE.TXT",
                &file_rec(
                    61,
                    0,
                    0,
                    0,
                    0,
                    0,
                    &[(20, 1), (32, 1)], // block 20 reallocated to NEWFILE
                    5000,
                    &[],
                    0,
                ),
            ),
            leaf_record(
                2,
                "GONE.BIN",
                &file_rec(62, 0, 0, 0, 0, 0, &[(21, 1)], 100, &[], 0),
            ),
            leaf_record(2, "OLDDIR", &folder_rec(63, 0)),
        ],
        &[],
    );
    put_node(&mut img, CAT_BLOCK, 3, &dead);

    // Map node (kind 2) — must be skipped by the dead-node scan.
    let map = node(2, 0, 0, 0, &[], &[]);
    put_node(&mut img, CAT_BLOCK, 4, &map);

    // ---- extents overflow ----------------------------------------------
    let ext_hdr = header_node(1, 1, 2, 1, 1, 2, 0, 0xFF);
    put_node(&mut img, EXT_BLOCK, 0, &ext_hdr);
    let ext_leaf = node(
        -1,
        1,
        0,
        0,
        &[
            // BIGFILE's 9th block.
            ext_record(0, 28, 8, &[(30, 1)]),
            // Orphaned extents: cnid 99 has no catalog record.
            ext_record(0, 99, 0, &[(33, 1)]),
        ],
        &[],
    );
    put_node(&mut img, EXT_BLOCK, 1, &ext_leaf);

    // ---- attributes file -------------------------------------------------
    // decmpfs xattr for COMPRESSED.BIN (cnid 45): zlib-inline type 3.
    let plain = b"decmpfs compressed payload hello hello hello";
    let z = miniz_oxide::deflate::compress_to_vec_zlib(plain, 6);
    let mut decmpfs_val = Vec::new();
    decmpfs_val.extend_from_slice(&0x636D7066u32.to_le_bytes()); // 'cmpf' LE
    decmpfs_val.extend_from_slice(&3u32.to_le_bytes()); // zlib inline
    decmpfs_val.extend_from_slice(&(plain.len() as u64).to_le_bytes());
    decmpfs_val.extend_from_slice(&z);

    let finder_info_val = [0xABu8; 32]; // synthetic FinderInfo xattr
    let attr_hdr = header_node(1, 1, 2, 1, 1, 2, 0, 0xFF);
    put_node(&mut img, ATTR_BLOCK, 0, &attr_hdr);
    let attr_leaf = node(
        -1,
        1,
        0,
        0,
        &[
            attr_inline_record(45, "com.apple.decmpfs", &decmpfs_val),
            attr_inline_record(20, "com.apple.FinderInfo", &finder_info_val),
            attr_inline_record(49, "com.apple.decmpfs", &decmpfs4_val),
        ],
        &[],
    );
    put_node(&mut img, ATTR_BLOCK, 1, &attr_leaf);

    // ---- file data -------------------------------------------------------
    put_block(&mut img, 14, b"hello world!");
    put_block(&mut img, 15, b"INNER-DATA");
    put_block(&mut img, 16, b"\x89PNG\x0D\x0A\x1A\x0A");
    let mut mz = b"MZ\x90\0\x03\0\0\0".to_vec();
    mz.resize(60, 0);
    put_block(&mut img, 17, &mz);
    let mut pk = b"PK\x03\x04\x14\0\0\0".to_vec();
    pk.resize(20, 0);
    put_block(&mut img, 18, &pk);
    put_block(&mut img, 19, b"HARDLINK-DATA-HERE");
    put_block(&mut img, 20, b"newfile owns block twenty");
    put_block(&mut img, 21, b"holder owns block twentyone");
    for b in 22..=30u32 {
        put_block(&mut img, b, format!("BIGFILE-BLOCK-{b:02}").as_bytes());
    }
    put_block(&mut img, 31, b"DELETED-BYTES!");
    put_block(&mut img, 32, b"OLDFILE-TAIL-SURVIVES");
    put_block(&mut img, 33, b"ORPHAN-EXTENT-DATA");
    put_block(&mut img, 35, b"/hello.txt");
    put_block(&mut img, 36, b"RICHES-DATA!");
    put_block(&mut img, 37, b"RESOURCE-FORK-DATA");
    put_block(&mut img, 39, b"ORPHANED-FILE-DATA!");

    // CmpfRsrcHead @ block 38: BE headerSize/totalSize/dataSize/flags,
    // then @headerSize: BE dataSize + LE numBlocks + LE (off,size) table,
    // payloads relative to headerSize.
    let rb = block_off(38);
    w32(&mut img, rb, 16); // headerSize
    w32(&mut img, rb + 4, rsrc_size as u32); // totalSize
    w32(&mut img, rb + 8, rsrc_plain.len() as u32); // dataSize
    // flags @12 left 0
    w32(&mut img, rb + 16, rsrc_plain.len() as u32); // block-table dataSize
    img[rb + 20..rb + 24].copy_from_slice(&1u32.to_le_bytes()); // numBlocks LE
    img[rb + 24..rb + 28].copy_from_slice(&16u32.to_le_bytes()); // off (rel.)
    img[rb + 28..rb + 32].copy_from_slice(&(rz.len() as u32).to_le_bytes());
    img[rb + 32..rb + 32 + rz.len()].copy_from_slice(&rz);

    // ---- journal ---------------------------------------------------------
    // JournalInfoBlock at block 40: flags, device_sig[8], offset, size.
    let jib = block_off(JIB_BLOCK);
    w32(&mut img, jib, 0x1); // flags: journaling enabled
    w64(&mut img, jib + 36, block_off(JOURNAL_BLOCK) as u64);
    w64(&mut img, jib + 44, BLOCK as u64);
    let jb = block_off(JOURNAL_BLOCK);
    w32(&mut img, jb, 0x4A4E4C78); // 'JNLx'
    w32(&mut img, jb + 4, 0x67656C64); // 'geld' little-endian flag

    img
}

/// Wrap the HFS+ corpus in an HFS "BD" wrapper: the embedded volume starts
/// at allocation block 2 of the wrapper (`drAlBlSt`=0, `xdrStABNt`=2,
/// `drAlBlkSiz`=4096 → embed offset 8192).
pub fn build_wrapped() -> Vec<u8> {
    const EMBED: usize = 8192;
    let inner = build_hfsplus();
    let mut img = vec![0u8; EMBED + inner.len()];
    let m = VH_OFF;
    w16(&mut img, m, 0x4244); // "BD"
    w32(&mut img, m + 0x14, 4096); // drAlBlkSiz
    w16(&mut img, m + 0x1C, 0); // drAlBlSt
    img[m + 0x24] = 11; // drVN len
    img[m + 0x25..m + 0x25 + 11].copy_from_slice(b"HFSWrapper ");
    img[m + 0x25 + 11] = 0;
    w16(&mut img, m + 0x7C, 0x482B); // drEmbedSigWord "H+"
    w16(&mut img, m + 0x7E, 2); // xdrStABNt (wrapper alloc blocks)
    w16(&mut img, m + 0x80, 90); // xdrNumABlks
    img[EMBED..EMBED + inner.len()].copy_from_slice(&inner);
    img
}
