// Each integration-test file gets its own copy of this module; not every
// helper is used by every test file.
#![allow(dead_code)]

//! Synthetic ext4/ext2 image construction for tests — the test-corpus
//! pattern: bytes written field-by-field into a `Vec<u8>`, mounted via
//! `Arc<Vec<u8>>` as the `ByteSource`. No fixture files, no network.
//!
//! `build_ext4` layout (1 KiB blocks, 256 blocks, 64 inodes × 256 B):
//!
//! ```text
//! block 0        zeroed boot sector area
//! block 1        superblock (offset 0x400)
//! block 2        GDT — one 32-byte descriptor
//! block 3        block bitmap   block 4  inode bitmap
//! blocks 5..=20  inode table
//! ```
//!
//! Block/inode map of the corpus:
//!
//! | ino | name          | blocks | state                                   |
//! |-----|---------------|--------|------------------------------------------|
//! | 2   | /             | 40     | live root dir                            |
//! | 8   | (journal)     | 30-37  | allocated, unreferenced → orphan+journal |
//! | 11  | hello.txt     | 41     | live, hardlinked, xattrs, crtime+nsec    |
//! | 12  | subdir        | 42     | live dir (inner.txt, buried.tmp slack)   |
//! | 13  | gone.dat      | 43     | DELETED inode, block free → Intact       |
//! | 14  | inner.txt     | 44     | live in /subdir                          |
//! | 15  | old.log       | 45,46  | DELETED; 45 reallocated → Partial        |
//! | 16  | newfile.bin   | 45     | live — owns the stolen block             |
//! | 17  | link          | —      | fast symlink → hello.txt                 |
//! | 18  | big.dat       | 47,48  | live, 2 extents                          |
//! | 19  | dead.txt      | 49     | DELETED; 49 reallocated → Unrecoverable  |
//! | 20  | (none)        | 50     | allocated orphan inode                   |
//! | 21  | shadow.bin    | 49     | live                                     |
//! | 22  | docs.docx     | 51     | PK content (container-ok)                |
//! | 23  | evil.doc      | 52     | MZ content (masquerade)                  |
//! | 24  | notes.txt     | 53     | DELETED; dirent carved from slack        |
//! | 26  | (none)        | 58     | s_last_orphan chain head                 |
//! | 27  | big2.dat      | 54→55,56| depth-1 extent tree (interior node)     |
//! | 28  | café.txt      | 57     | UTF-8 name                               |
//! | 29  | x             | 60     | live; rec_len covers slack dirent        |
//! | 30  | tiny          | —      | EXT4_INLINE_DATA_FL — data inside inode  |
//! | 31  | slowlink      | 61     | slow symlink (target in data block)      |
//!
//! Free blocks holding deleted data: 43, 46, 53.

pub const BLK: usize = 1024;
pub const TOTAL_BLOCKS: u32 = 256;
pub const INODE_SIZE: usize = 256;
pub const IPG: u32 = 64;
pub const BPG: u32 = 8192;
/// Inode table starts at block 5 in group 0.
pub const ITABLE_BLK: u32 = 5;
pub const BBM_BLK: u32 = 3;
pub const IBM_BLK: u32 = 4;
pub const GDT_BLK: u32 = 2;

pub const FT_REG: u8 = 1;
pub const FT_DIR: u8 = 2;
pub const FT_SYMLINK: u8 = 7;

/// Absolute byte offset of block `b`.
pub fn blk_off(b: u32) -> usize {
    b as usize * BLK
}
/// Absolute byte offset of inode `ino`.
pub fn inode_off(ino: u32) -> usize {
    ITABLE_BLK as usize * BLK + (ino as usize - 1) * INODE_SIZE
}
/// Absolute byte offset of a dirent at `pos` within directory block `b`.
pub fn dirent_off(b: u32, pos: usize) -> usize {
    blk_off(b) + pos
}

pub fn w16(img: &mut [u8], off: usize, v: u16) {
    img[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
pub fn w32(img: &mut [u8], off: usize, v: u32) {
    img[off..off + 4].copy_from_slice(&v.to_le_bytes());
}


/// Set bit `i` in the bitmap block at `blk`.
fn set_bit(img: &mut [u8], blk: u32, i: u32) {
    let off = blk_off(blk) + i as usize / 8;
    img[off] |= 1 << (i % 8);
}
/// Mark filesystem block `b` allocated in the group-0 block bitmap.
pub fn set_block(img: &mut [u8], b: u32) {
    set_bit(img, BBM_BLK, b);
}
/// Mark inode `ino` allocated in the inode bitmap.
pub fn set_inode_bit(img: &mut [u8], ino: u32) {
    set_bit(img, IBM_BLK, ino - 1);
}


// ---------------------------------------------------------------------------
// Inode / dirent / extent writers
// ---------------------------------------------------------------------------

pub const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
pub const EXT4_INLINE_DATA_FL: u32 = 0x1000_0000;

/// A 60-byte `i_block` holding a depth-0 extent root.
pub fn extent_root(entries: &[(u32, u16, u64)]) -> [u8; 60] {
    let mut b = [0u8; 60];
    w16(&mut b, 0, 0xF30A);
    w16(&mut b, 2, entries.len() as u16);
    w16(&mut b, 4, 4); // eh_max = (60-12)/12
    for (i, &(l, len, p)) in entries.iter().enumerate() {
        let e = 12 + i * 12;
        w32(&mut b, e, l);
        w16(&mut b, e + 4, len);
        w16(&mut b, e + 6, (p >> 32) as u16);
        w32(&mut b, e + 8, p as u32);
    }
    b
}

/// A 60-byte `i_block` holding a depth-1 extent root (index entries).
pub fn extent_idx_root(children: &[u64]) -> [u8; 60] {
    let mut b = [0u8; 60];
    w16(&mut b, 0, 0xF30A);
    w16(&mut b, 2, children.len() as u16);
    w16(&mut b, 4, 4);
    w16(&mut b, 6, 1); // depth 1
    for (i, &c) in children.iter().enumerate() {
        let e = 12 + i * 12;
        w32(&mut b, e, 0); // ei_block — first logical block covered
        w32(&mut b, e + 4, c as u32);
        w16(&mut b, e + 8, (c >> 32) as u16);
    }
    b
}

/// A whole fs block holding leaf extent entries (an extent-tree leaf node).
pub fn extent_leaf(entries: &[(u32, u16, u64)]) -> [u8; BLK] {
    let mut b = [0u8; BLK];
    w16(&mut b, 0, 0xF30A);
    w16(&mut b, 2, entries.len() as u16);
    w16(&mut b, 4, ((BLK - 12) / 12) as u16);
    for (i, &(l, len, p)) in entries.iter().enumerate() {
        let e = 12 + i * 12;
        w32(&mut b, e, l);
        w16(&mut b, e + 4, len);
        w16(&mut b, e + 6, (p >> 32) as u16);
        w32(&mut b, e + 8, p as u32);
    }
    b
}

/// Write an inode. `block60` is the raw i_block array (extent root,
/// direct/indirect map, or fast-symlink target).
#[allow(clippy::too_many_arguments)]
pub fn put_inode(
    img: &mut [u8],
    ino: u32,
    mode: u16,
    size: u64,
    links: u16,
    blocks_512: u32,
    flags: u32,
    block60: [u8; 60],
    dtime: u32,
    mtime: u32,
    mtime_extra: u32,
    crtime: Option<(u32, u32)>,
    file_acl: u64,
) {
    put_inode_at(
        img, inode_off(ino), mode, size, links, blocks_512, flags, block60, dtime, mtime,
        mtime_extra, crtime, file_acl,
    );
}

/// Like [`put_inode`] but writes at an explicit byte offset — needed for
/// inodes living in a non-zero group's inode table.
#[allow(clippy::too_many_arguments)]
pub fn put_inode_at(
    img: &mut [u8],
    o: usize,
    mode: u16,
    size: u64,
    links: u16,
    blocks_512: u32,
    flags: u32,
    block60: [u8; 60],
    dtime: u32,
    mtime: u32,
    mtime_extra: u32,
    crtime: Option<(u32, u32)>,
    file_acl: u64,
) {
    w16(img, o, mode);
    w16(img, o + 2, 1000); // uid
    w32(img, o + 4, size as u32);
    w32(img, o + 8, mtime); // atime = mtime for simplicity
    w32(img, o + 12, mtime); // ctime
    w32(img, o + 16, mtime);
    w32(img, o + 20, dtime);
    w16(img, o + 24, 1000); // gid
    w16(img, o + 26, links);
    w32(img, o + 28, blocks_512);
    w32(img, o + 32, flags);
    img[o + 0x28..o + 0x28 + 60].copy_from_slice(&block60);
    w32(img, o + 0x64, 1); // generation
    w32(img, o + 0x68, file_acl as u32);
    w32(img, o + 0x6C, (size >> 32) as u32);
    w16(img, o + 0x80, 32); // i_extra_isize: fields to 0xA0
    w32(img, o + 0x84, mtime_extra); // ctime_extra
    w32(img, o + 0x88, mtime_extra); // mtime_extra
    w32(img, o + 0x8C, mtime_extra); // atime_extra
    if let Some((s, x)) = crtime {
        w32(img, o + 0x90, s);
        w32(img, o + 0x94, x);
    }
}

/// Write a dirent into directory block `blk` at byte position `pos`.
pub fn put_dirent(
    img: &mut [u8],
    blk: u32,
    pos: usize,
    ino: u32,
    rec_len: u16,
    name: &[u8],
    ft: u8,
) {
    let o = dirent_off(blk, pos);
    w32(img, o, ino);
    w16(img, o + 4, rec_len);
    img[o + 6] = name.len() as u8;
    img[o + 7] = ft;
    img[o + 8..o + 8 + name.len()].copy_from_slice(name);
}

/// Write file data at a block.
pub fn put_data(img: &mut [u8], blk: u32, data: &[u8]) {
    let o = blk_off(blk);
    img[o..o + data.len()].copy_from_slice(data);
}

/// Fill in the superblock, GDT and bitmaps' fixed parts shared by both
/// corpus builders. Returns the image.
fn base_image(feature_compat: u32, feature_incompat: u32, feature_ro: u32) -> Vec<u8> {
    let mut img = vec![0u8; TOTAL_BLOCKS as usize * BLK];
    let sb = 1024usize;
    w32(&mut img, sb, IPG); // s_inodes_count = 64
    w32(&mut img, sb + 4, TOTAL_BLOCKS);
    w32(&mut img, sb + 0x14, 1); // s_first_data_block
    // s_log_block_size (0x18) = 0 → 1 KiB
    w32(&mut img, sb + 0x20, BPG); // s_blocks_per_group
    w32(&mut img, sb + 0x24, BPG); // s_clusters_per_group
    w32(&mut img, sb + 0x28, IPG); // s_inodes_per_group
    w32(&mut img, sb + 0x2C, 1_705_314_620); // s_mtime
    w32(&mut img, sb + 0x30, 1_705_314_620); // s_wtime
    w16(&mut img, sb + 0x34, 3); // s_mnt_count
    w16(&mut img, sb + 0x38, 0xEF53); // s_magic
    w16(&mut img, sb + 0x3A, 1); // s_state = clean
    w16(&mut img, sb + 0x3C, 1); // s_errors = continue
    w32(&mut img, sb + 0x4C, 1); // s_rev_level = dynamic
    w32(&mut img, sb + 0x54, 11); // s_first_ino
    w16(&mut img, sb + 0x58, INODE_SIZE as u16);
    w32(&mut img, sb + 0x5C, feature_compat);
    w32(&mut img, sb + 0x60, feature_incompat);
    w32(&mut img, sb + 0x64, feature_ro);
    // UUID bytes 00..0f
    for i in 0..16 {
        img[sb + 0x68 + i] = (i * 0x11) as u8;
    }
    img[sb + 0x78..sb + 0x78 + 8].copy_from_slice(b"EXT4TEST");
    img[sb + 0x88..sb + 0x88 + 13].copy_from_slice(b"/mnt/evidence");
    w32(&mut img, sb + 0xE8, 26); // s_last_orphan
    w16(&mut img, sb + 0xFE, 32); // s_desc_size
    w32(&mut img, sb + 0x108, 1_705_000_000); // s_mkfs_time

    // GDT: one descriptor — block_bitmap 3, inode_bitmap 4, itable 5.
    let gd = blk_off(GDT_BLK);
    w32(&mut img, gd, BBM_BLK);
    w32(&mut img, gd + 4, IBM_BLK);
    w32(&mut img, gd + 8, ITABLE_BLK);
    w16(&mut img, gd + 0x10, 3); // used_dirs

    // Block bitmap: metadata 0..=20 + tail padding beyond the image.
    for b in 0..=20u32 {
        set_block(&mut img, b);
    }
    for b in TOTAL_BLOCKS..BPG {
        set_block(&mut img, b);
    }
    // Reserved inodes 1..=8 allocated (incl. journal ino 8).
    for i in 1..=8u32 {
        set_inode_bit(&mut img, i);
    }
    img
}

/// Finish the superblock's free counts after all bitmap edits.
fn finalize_counts(img: &mut [u8]) {
    let bbm = &img[blk_off(BBM_BLK)..blk_off(BBM_BLK) + BLK];
    let free_blocks = (0..TOTAL_BLOCKS)
        .filter(|&b| bbm[b as usize / 8] & (1 << (b % 8)) == 0)
        .count() as u32;
    let ibm = &img[blk_off(IBM_BLK)..blk_off(IBM_BLK) + BLK];
    let free_inodes = (0..IPG)
        .filter(|&i| ibm[i as usize / 8] & (1 << (i % 8)) == 0)
        .count() as u32;
    w32(img, 1024 + 0x0C, free_blocks);
    w32(img, 1024 + 0x10, free_inodes);
    let gd = blk_off(GDT_BLK);
    w16(img, gd + 0x0C, free_blocks as u16);
    w16(img, gd + 0x0E, free_inodes as u16);
}

/// Write an ibody xattr entry (in-inode region after extra fields) and an
/// xattr block for inode 11.
fn write_xattrs(img: &mut [u8]) {
    // In-inode region at inode_off(11) + 160 (extra_isize=32 → 128+32).
    let o = inode_off(11) + 160;
    w32(img, o, 0xEA02_0000); // xattr magic
    // entry header (16 bytes) at o+4: security.selinux
    img[o + 4] = 7; // e_name_len
    img[o + 5] = 6; // e_name_index = security
    w32(img, o + 12, 16); // e_value_size (value bytes irrelevant to listing)
    img[o + 20..o + 27].copy_from_slice(b"selinux"); // e_name @ +16
    // terminator: zeros follow
    // Dedicated xattr block at 59: header + user.comment entry.
    let b = blk_off(59);
    w32(img, b, 0xEA02_0000);
    w32(img, b + 4, 1); // refcount
    w32(img, b + 8, 1); // blocks
    img[b + 32] = 7; // e_name_len
    img[b + 33] = 1; // e_name_index = user
    w32(img, b + 40, 5); // e_value_size
    img[b + 48..b + 48 + 7].copy_from_slice(b"comment"); // e_name @ +16
}

// ---- jbd2 journal writers (all big-endian) --------------------------------

const JBD2_MAGIC: u32 = 0xC03B_3998;

/// Big-endian u32 write — jbd2 structures are the only big-endian
/// structures on an ext filesystem.
pub fn wj(img: &mut [u8], off: usize, v: u32) {
    img[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

/// Common 12-byte journal block header.
pub fn jbd2_header(img: &mut [u8], blk: u32, blocktype: u32, seq: u32) {
    let b = blk_off(blk);
    wj(img, b, JBD2_MAGIC);
    wj(img, b + 4, blocktype);
    wj(img, b + 8, seq);
}

/// One 8-byte journal_block_tag (32-bit tags): blocknr be32 + flags be32.
pub fn jbd2_tag(img: &mut [u8], blk: u32, pos: usize, fs_block: u32, flags: u32) {
    let o = blk_off(blk) + pos;
    wj(img, o, fs_block);
    wj(img, o + 4, flags);
}

/// One 12-byte journal_block_tag used when the journal advertises
/// `INCOMPAT_64BIT`: blocknr_lo be32 + flags be32 + blocknr_hi be32.
pub fn jbd2_tag64(img: &mut [u8], blk: u32, pos: usize, fs_block: u64, flags: u32) {
    let o = blk_off(blk) + pos;
    wj(img, o, fs_block as u32);
    wj(img, o + 4, flags);
    wj(img, o + 8, (fs_block >> 32) as u32);
}

/// Rewrite the jbd2 superblock's `s_feature_incompat` (offset 0x28 of the
/// journal superblock at fs block 30).
pub fn jbd2_set_feature_incompat(img: &mut [u8], v: u32) {
    wj(img, blk_off(30) + 0x28, v);
}

/// jbd2 superblock at block 30 (all big-endian) plus a small transaction
/// history in the log region (blocks 31..37):
///
/// ```text
/// 31 descriptor tx 0x100: tags → fs 5 (inode table), fs 43 (free data)
/// 32 data: prior inode-table copy     33 data: prior copy of block 43
/// 34 revoke tx 0x100: fs block 44     35 commit tx 0x100 (seals it)
/// 36 descriptor tx 0x101: tag → fs 3 (block bitmap)
/// 37 data: prior block-bitmap copy    (no commit → incomplete tail tx)
/// ```
fn write_journal(img: &mut [u8]) {
    let b = blk_off(30);
    wj(img, b, JBD2_MAGIC);
    wj(img, b + 4, 4); // superblock v2
    wj(img, b + 8, 0); // h_sequence
    wj(img, b + 12, 1024); // s_blocksize
    wj(img, b + 16, 8); // s_maxlen
    wj(img, b + 20, 1); // s_first
    wj(img, b + 24, 0x102); // s_sequence
    wj(img, b + 28, 1); // s_start = replay pending
    wj(img, b + 0x28, 1); // s_feature_incompat = revoke
    wj(img, b + 0x40, 1); // s_nr_users

    // Descriptor tx 0x100: tag 5 (uuid follows — no SAME_UUID) then
    // tag 43 (SAME_UUID|LAST).
    jbd2_header(img, 31, 1, 0x100);
    jbd2_tag(img, 31, 12, 5, 0x0);
    // 16-byte journal uuid after the first tag.
    img[blk_off(31) + 20..blk_off(31) + 36].copy_from_slice(b"0123456789abcdef");
    jbd2_tag(img, 31, 36, 43, 0xA); // SAME_UUID(0x2)|LAST(0x8)
    put_data(img, 32, b"JOURNALED-INODE-TABLE-BLOCK-5-PRIOR-STATE");
    put_data(img, 33, b"JOURNALED-COPY-OF-BLOCK-43");

    // Revocation tx 0x100: r_count = 16 + 4 bytes of block numbers.
    jbd2_header(img, 34, 5, 0x100);
    wj(img, blk_off(34) + 12, 20); // r_count (bytes used)
    wj(img, blk_off(34) + 16, 44); // revoked fs block 44

    // Commit tx 0x100: timestamp at 0x30/0x38.
    jbd2_header(img, 35, 2, 0x100);
    img[blk_off(35) + 0x30..blk_off(35) + 0x38]
        .copy_from_slice(&1_705_315_000u64.to_be_bytes());
    wj(img, blk_off(35) + 0x38, 123_456_789);

    // Descriptor tx 0x101: single tag → block bitmap (fs 3). The trailing
    // commit never landed — an incomplete transaction.
    jbd2_header(img, 36, 1, 0x101);
    jbd2_tag(img, 36, 12, 3, 0xA); // SAME_UUID|LAST
    put_data(img, 37, b"JOURNALED-BLOCK-BITMAP-3-PRIOR-STATE");
}

/// Build the ext4 corpus image (256 KiB).
pub fn build_ext4() -> Vec<u8> {
    const COMPAT: u32 = 0x0004 | 0x0008 | 0x0020; // journal|ext_attr|dir_index
    const INCOMPAT: u32 = 0x0002 | 0x0040; // filetype|extents
    const RO: u32 = 0x0001 | 0x0002 | 0x0040; // sparse|large_file|extra_isize
    let mut img = base_image(COMPAT, INCOMPAT, RO);
    w32(&mut img, 1024 + 0xE0, 8); // s_journal_inum

    // ---- allocated data blocks ----------------------------------------
    for b in [30u32, 31, 32, 33, 34, 35, 36, 37, 40, 41, 42, 44, 45, 47, 48, 49, 50, 51, 52, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64] {
        set_block(&mut img, b);
    }
    // Allocated inodes (beyond reserved 1..=8).
    for i in [11u32, 12, 14, 16, 17, 18, 20, 21, 22, 23, 26, 27, 28, 29, 30, 31, 32, 33, 36] {
        set_inode_bit(&mut img, i);
    }
    // Inodes 13, 15, 19, 24, 34, 35 stay FREE (deleted/stale).

    // ---- inodes ---------------------------------------------------------
    let t = 1_705_314_620u32;
    let half_sec = 500_000_000u32 << 2;
    // ino 2: root dir → block 40
    put_inode(&mut img, 2, 0o40755, 1024, 3, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 40)]), 0, t, 0, None, 0);
    // ino 8: journal → blocks 30-37
    put_inode(&mut img, 8, 0o100600, 8192, 1, 16, EXT4_EXTENTS_FL, extent_root(&[(0, 8, 30)]), 0, t, 0, None, 0);
    // ino 11: hello.txt → 41, hardlinked (2), xattr block 59, nsec+crtime
    put_inode(&mut img, 11, 0o100644, 12, 2, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 41)]), 0, t, half_sec, Some((1_705_310_000, 250_000_000 << 2)), 59);
    // ino 12: subdir → 42
    put_inode(&mut img, 12, 0o40755, 1024, 2, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 42)]), 0, t, 0, None, 0);
    // ino 13: gone.dat — DELETED (bitmap clear), extent→43, dtime set
    put_inode(&mut img, 13, 0o100644, 10, 0, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 43)]), 1_705_320_000, t, 0, None, 0);
    // ino 14: inner.txt → 44
    put_inode(&mut img, 14, 0o100644, 4, 1, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 44)]), 0, t, 0, None, 0);
    // ino 15: old.log — DELETED, blocks 45 (reallocated) + 46 (free)
    put_inode(&mut img, 15, 0o100644, 1400, 0, 4, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 45), (1, 1, 46)]), 1_705_320_100, t, 0, None, 0);
    // ino 16: newfile.bin → 45 (reallocated from old.log)
    put_inode(&mut img, 16, 0o100644, 100, 1, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 45)]), 0, t, 0, None, 0);
    // ino 17: fast symlink "hello.txt" — no extents, i_block = target
    let mut sym = [0u8; 60];
    sym[..9].copy_from_slice(b"hello.txt");
    put_inode(&mut img, 17, 0o120777, 9, 1, 0, 0, sym, 0, t, 0, None, 0);
    // ino 18: big.dat → 47,48
    put_inode(&mut img, 18, 0o100644, 1500, 1, 4, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 47), (1, 1, 48)]), 0, t, 0, None, 0);
    // ino 19: dead.txt — DELETED, block 49 reallocated to shadow.bin
    put_inode(&mut img, 19, 0o100644, 500, 0, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 49)]), 1_705_320_200, t, 0, None, 0);
    // ino 20: orphan artefact — allocated, no dirent
    put_inode(&mut img, 20, 0o100644, 20, 1, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 50)]), 0, t, 0, None, 0);
    // ino 21: shadow.bin → 49
    put_inode(&mut img, 21, 0o100644, 50, 1, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 49)]), 0, t, 0, None, 0);
    // ino 22: docs.docx → 51
    put_inode(&mut img, 22, 0o100644, 20, 1, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 51)]), 0, t, 0, None, 0);
    // ino 23: evil.doc → 52
    put_inode(&mut img, 23, 0o100644, 60, 1, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 52)]), 0, t, 0, None, 0);
    // ino 24: notes.txt — DELETED; dirent survives only in slack
    put_inode(&mut img, 24, 0o100644, 9, 0, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 53)]), 1_705_320_300, t, 0, None, 0);
    // ino 26: orphan-list head — allocated, links 0, s_last_orphan → 26
    put_inode(&mut img, 26, 0o100644, 16, 0, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 58)]), 0, t, 0, None, 0);
    // ino 27: big2.dat — depth-1 extent tree, leaf at block 54
    put_inode(&mut img, 27, 0o100644, 1500, 1, 6, EXT4_EXTENTS_FL, extent_idx_root(&[54]), 0, t, 0, None, 0);
    // ino 28: café.txt → 57
    put_inode(&mut img, 28, 0o100644, 5, 1, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 57)]), 0, t, 0, None, 0);
    // ino 29: x → 60
    put_inode(&mut img, 29, 0o100644, 4, 1, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 60)]), 0, t, 0, None, 0);
    // ino 30: tiny — inline data: i_block[0..60] holds the first 60 file
    // bytes (no length prefix); the tail spills into the "system.data"
    // ibody xattr, per the kernel inline-data layout.
    let mut inl = [0u8; 60];
    for (i, b) in inl.iter_mut().enumerate() {
        *b = b'A' + (i % 26) as u8; // "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD…" ×60
    }
    put_inode(&mut img, 30, 0o100644, 75, 1, 0, EXT4_INLINE_DATA_FL, inl, 0, t, 0, None, 0);
    // ibody xattr region (extra_isize=32 → region at +160): one
    // system.data entry, value = last 15 bytes at inode offset 241.
    let o = inode_off(30) + 160;
    w32(&mut img, o, 0xEA02_0000);
    img[o + 4] = 11; // e_name_len
    img[o + 5] = 7; // e_name_index = system
    w16(&mut img, o + 6, 241); // e_value_offs (inode-relative)
    w32(&mut img, o + 12, 15); // e_value_size
    img[o + 20..o + 31].copy_from_slice(b"system.data");
    // e_value_offs is relative to the inode start, not the xattr region.
    img[inode_off(30) + 241..inode_off(30) + 256].copy_from_slice(b"SPILLOVER-TAIL!");
    // ino 31: slowlink — slow symlink, target stored in block 61.
    put_inode(&mut img, 31, 0o120777, 10, 1, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 61)]), 0, t, 0, None, 0);
    // ino 32: inlinedir — inline-data directory: i_block[0..4] is the
    // parent inode number, dirent records live in i_block[4..60].
    let mut idir = [0u8; 60];
    w32(&mut idir, 0, 2); // parent inode ("/")
    let mut ip = 4usize;
    let mut ide = |ino: u32, rec: usize, name: &[u8], ft: u8| {
        w32(&mut idir, ip, ino);
        w16(&mut idir, ip + 4, rec as u16);
        idir[ip + 6] = name.len() as u8;
        idir[ip + 7] = ft;
        idir[ip + 8..ip + 8 + name.len()].copy_from_slice(name);
        ip += rec;
    };
    ide(32, 12, b".", FT_DIR);
    ide(2, 12, b"..", FT_DIR);
    ide(14, 32, b"inner.txt", FT_REG);
    put_inode(&mut img, 32, 0o40755, 56, 2, 0, EXT4_INLINE_DATA_FL, idir, 0, t, 0, None, 0);
    // ino 33: sparse.bin — hole at logical blocks 0-1, data at block 62.
    put_inode(&mut img, 33, 0o100644, 3072, 1, 2, EXT4_EXTENTS_FL, extent_root(&[(2, 1, 62)]), 0, t, 0, None, 0);
    // ino 34: phantom.txt — live dirent but inode bit clear (stale inode).
    put_inode(&mut img, 34, 0o100644, 7, 1, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 63)]), 0, t, 0, None, 0);
    // ino 35: gone-inline — DELETED inline-data file (unallocated inode).
    let mut ginl = [0u8; 60];
    ginl[..20].copy_from_slice(b"GONE-INLINE-DATA-123");
    put_inode(&mut img, 35, 0o100644, 20, 0, 0, EXT4_INLINE_DATA_FL, ginl, 1_705_320_400, t, 0, None, 0);
    // ino 36: allocated, unreferenced DIR → orphan artefact with extents.
    put_inode(&mut img, 36, 0o40755, 1024, 2, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 64)]), 0, t, 0, None, 0);

    // ---- directory blocks -------------------------------------------------
    // Root dir (block 40): entries + slack containing deleted "notes.txt".
    let mut pos = 0usize;
    let mut de = |img: &mut Vec<u8>, ino: u32, name: &[u8], ft: u8| {
        let rec = ((8 + name.len() + 3) & !3) as u16;
        put_dirent(img, 40, pos, ino, rec, name, ft);
        pos += rec as usize;
    };
    de(&mut img, 2, b".", FT_DIR);
    de(&mut img, 2, b"..", FT_DIR);
    de(&mut img, 11, b"hello.txt", FT_REG);
    de(&mut img, 11, b"hello2.txt", FT_REG);
    de(&mut img, 12, b"subdir", FT_DIR);
    de(&mut img, 16, b"newfile.bin", FT_REG);
    de(&mut img, 21, b"shadow.bin", FT_REG);
    de(&mut img, 22, b"docs.docx", FT_REG);
    de(&mut img, 23, b"evil.doc", FT_REG);
    de(&mut img, 17, b"link", FT_SYMLINK);
    de(&mut img, 18, b"big.dat", FT_REG);
    de(&mut img, 27, b"big2.dat", FT_REG);
    de(&mut img, 28, "café.txt".as_bytes(), FT_REG);
    de(&mut img, 30, b"tiny", FT_REG);
    de(&mut img, 31, b"slowlink", FT_SYMLINK);
    de(&mut img, 32, b"inlinedir", FT_DIR);
    de(&mut img, 33, b"sparse.bin", FT_REG);
    de(&mut img, 34, b"phantom.txt", FT_REG);
    // Final live entry "x": rec_len covers the rest of the block. Inside
    // its slack sits the deleted "notes.txt" dirent (ino 24).
    let x_pos = pos;
    put_dirent(&mut img, 40, x_pos, 29, (1024 - x_pos) as u16, b"x", FT_REG);
    // Deleted dirent at x_pos + 12 (min rec_len for "x").
    put_dirent(&mut img, 40, x_pos + 12, 24, 24, b"notes.txt", FT_REG);
    // Stale dirent pointing at an *allocated* inode (reused slot) and one
    // pointing at a zeroed inode slot — exercise both carved-outcome arms.
    put_dirent(&mut img, 40, x_pos + 36, 21, 20, b"stale.lnk", FT_REG);
    put_dirent(&mut img, 40, x_pos + 56, 40, 20, b"zeroed.de", FT_REG);

    // Subdir (block 42): ".", "..", "inner.txt" (rec_len to block end),
    // then a deleted dirent with ino=0 (cleared-on-delete) in its slack.
    let mut sp = 0usize;
    let mut sde = |img: &mut Vec<u8>, ino: u32, name: &[u8], ft: u8| {
        let rec = ((8 + name.len() + 3) & !3) as u16;
        put_dirent(img, 42, sp, ino, rec, name, ft);
        sp += rec as usize;
    };
    sde(&mut img, 12, b".", FT_DIR);
    sde(&mut img, 2, b"..", FT_DIR);
    let inner_pos = sp;
    put_dirent(&mut img, 42, inner_pos, 14, (1024 - inner_pos) as u16, b"inner.txt", FT_REG);
    // Carved dirent with inode field cleared — name-only recovery.
    put_dirent(&mut img, 42, inner_pos + 20, 0, 20, b"buried.tmp", FT_REG);

    // ---- file data ---------------------------------------------------------
    put_data(&mut img, 41, b"hello ext4!\n");
    put_data(&mut img, 43, b"deadbeef42");
    put_data(&mut img, 44, b"INNR");
    put_data(&mut img, 45, b"NEWFILE OWNS THIS BLOCK NOW");
    put_data(&mut img, 46, b"OLD LOG TAIL SURVIVES HERE");
    put_data(&mut img, 47, b"BIG-DAT-A");
    put_data(&mut img, 48, b"BIG-DAT-B");
    put_data(&mut img, 49, b"shadow data");
    put_data(&mut img, 50, b"ORPHAN-INODE-DATA-HERE!");
    let mut pk = b"PK\x03\x04\x14\0\0\0".to_vec();
    pk.resize(20, 0);
    put_data(&mut img, 51, &pk);
    let mut mz = b"MZ\x90\0\x03\0\0\0".to_vec();
    mz.resize(60, 0);
    put_data(&mut img, 52, &mz);
    put_data(&mut img, 53, b"NOTESDATA");
    img[blk_off(54)..blk_off(54) + BLK].copy_from_slice(&extent_leaf(&[(0, 1, 55), (1, 1, 56)]));
    put_data(&mut img, 55, b"BIG2-FIRST");
    put_data(&mut img, 56, b"BIG2-SECOND");
    put_data(&mut img, 57, "CAFÉ!".as_bytes());
    put_data(&mut img, 58, b"ORPHAN-LIST-DATA!");
    put_data(&mut img, 60, b"XDAT");
    put_data(&mut img, 61, b"/hello.txt");
    put_data(&mut img, 62, b"SPARSE-DATA!");
    put_data(&mut img, 63, b"PHANTOM");

    write_journal(&mut img);
    write_xattrs(&mut img);
    finalize_counts(&mut img);
    img
}

/// Minimal ext2 corpus: no journal, no extents — legacy direct/indirect
/// block maps. Layout mirrors `build_ext4` at smaller scale:
/// root ino 2 → block 30; data.txt ino 11 → blocks 31-33 (direct);
/// big.bin ino 12 → 12 direct (34-45) + single-indirect 46 → 47,48;
/// old.txt ino 13 → block 49, inode free (deleted), block free.
pub fn build_ext2() -> Vec<u8> {
    let mut img = base_image(0, 0x0002, 0x0003); // filetype only; sparse+large
    w32(&mut img, 1024 + 0xE8, 0); // no orphan list
    w32(&mut img, 1024 + 0xE0, 0); // no journal inode

    for b in [30u32, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48] {
        set_block(&mut img, b);
    }
    for i in [11u32, 12] {
        set_inode_bit(&mut img, i);
    }

    let t = 1_705_314_620u32;
    // ino 2: root dir → direct block 30.
    let mut root = [0u8; 60];
    w32(&mut root, 0, 30);
    put_inode(&mut img, 2, 0o40755, 1024, 2, 2, 0, root, 0, t, 0, None, 0);
    // ino 11: data.txt — 3 direct blocks.
    let mut d = [0u8; 60];
    w32(&mut d, 0, 31);
    w32(&mut d, 4, 32);
    w32(&mut d, 8, 33);
    put_inode(&mut img, 11, 0o100644, 2500, 1, 6, 0, d, 0, t, 0, None, 0);
    // ino 12: big.bin — 12 direct + single indirect.
    let mut bb = [0u8; 60];
    for i in 0..12 {
        w32(&mut bb, i * 4, 34 + i as u32);
    }
    w32(&mut bb, 48, 46); // single-indirect block
    put_inode(&mut img, 12, 0o100644, 14 * 1024, 1, 28, 0, bb, 0, t, 0, None, 0);
    // ino 13: old.txt — deleted (inode bit clear), direct block 49.
    let mut dd = [0u8; 60];
    w32(&mut dd, 0, 49);
    put_inode(&mut img, 13, 0o100644, 700, 0, 2, 0, dd, 1_705_320_000, t, 0, None, 0);

    // Indirect block 46 → data blocks 47, 48.
    w32(&mut img, blk_off(46), 47);
    w32(&mut img, blk_off(46) + 4, 48);

    // Root dir block 30.
    put_dirent(&mut img, 30, 0, 2, 12, b".", FT_DIR);
    put_dirent(&mut img, 30, 12, 2, 12, b"..", FT_DIR);
    put_dirent(&mut img, 30, 24, 11, 20, b"data.txt", FT_REG);
    put_dirent(&mut img, 30, 44, 12, 1024 - 44, b"big.bin", FT_REG);

    put_data(&mut img, 31, b"EXT2-DIRECT-DATA");
    put_data(&mut img, 34, b"BIGBIN-D0");
    put_data(&mut img, 47, b"BIGBIN-INDIRECT-0");
    put_data(&mut img, 48, b"BIGBIN-INDIRECT-1");
    put_data(&mut img, 49, b"EXT2-DELETED-DATA");

    finalize_counts(&mut img);
    img
}

/// Two-group ext4 image: `blocks_per_group = 128`, `inodes_per_group = 64`
/// (128 inodes, 256 blocks). Exercises group>0 inode addressing, a second
/// GDT descriptor, and the sparse backup superblock in group 1.
///
/// ```text
/// group 0 (blocks   0..127): sb@1 gdt@2 bbm@3 ibm@4 itable@5..20 root dir@40
/// group 1 (blocks 128..255): backup sb@129, gdt@130, bbm@131, ibm@132,
///                            itable@133..148, data@150
/// ```
///
/// Inode 65 (first inode of group 1) = g1file.txt → block 150.
pub fn build_ext4_two_groups() -> Vec<u8> {
    const COMPAT: u32 = 0x0004 | 0x0008; // journal|ext_attr
    const INCOMPAT: u32 = 0x0002 | 0x0040; // filetype|extents
    const RO: u32 = 0x0001 | 0x0002 | 0x0040; // sparse|large|extra_isize
    let mut img = vec![0u8; TOTAL_BLOCKS as usize * BLK];
    let sb = 1024usize;
    w32(&mut img, sb, 128); // s_inodes_count
    w32(&mut img, sb + 4, TOTAL_BLOCKS);
    w32(&mut img, sb + 0x14, 1); // first_data_block
    w32(&mut img, sb + 0x20, 128); // blocks_per_group = 128 → 2 groups
    w32(&mut img, sb + 0x24, 128);
    w32(&mut img, sb + 0x28, 64); // inodes_per_group
    w32(&mut img, sb + 0x2C, 1_705_314_620);
    w32(&mut img, sb + 0x30, 1_705_314_620);
    w16(&mut img, sb + 0x34, 1);
    w16(&mut img, sb + 0x38, 0xEF53);
    w16(&mut img, sb + 0x3A, 1);
    w16(&mut img, sb + 0x3C, 1);
    w32(&mut img, sb + 0x4C, 1);
    w32(&mut img, sb + 0x54, 11);
    w16(&mut img, sb + 0x58, INODE_SIZE as u16);
    w32(&mut img, sb + 0x5C, COMPAT);
    w32(&mut img, sb + 0x60, INCOMPAT);
    w32(&mut img, sb + 0x64, RO);
    img[sb + 0x78..sb + 0x78 + 8].copy_from_slice(b"TWOGROUP");

    // GDT (block 2): two descriptors.
    let gd = blk_off(GDT_BLK);
    w32(&mut img, gd, 3); // g0 block_bitmap
    w32(&mut img, gd + 4, 4); // g0 inode_bitmap
    w32(&mut img, gd + 8, 5); // g0 inode_table
    w16(&mut img, gd + 0x10, 1); // g0 used_dirs
    w32(&mut img, gd + 32, 131); // g1 block_bitmap
    w32(&mut img, gd + 36, 132); // g1 inode_bitmap
    w32(&mut img, gd + 40, 133); // g1 inode_table

    // Backup superblock + GDT at group 1 (sparse_super covers groups 0,1).
    img.copy_within(1024..2048, blk_off(129));
    img.copy_within(2048..3072, blk_off(130));

    // Group-0 block bitmap: metadata 0..=20 + root dir 40.
    for b in 0..=20u32 {
        set_block(&mut img, b);
    }
    set_block(&mut img, 40);
    // Group-1 block bitmap (block 131): metadata 128..=148 + data 150,
    // plus padding for every block ≥ 256 (bit idx = b - 128).
    let set_g1 = |img: &mut [u8], b: u32| {
        let off = blk_off(131) + (b - 128) as usize / 8;
        img[off] |= 1 << ((b - 128) % 8);
    };
    for b in 128..=148u32 {
        set_g1(&mut img, b);
    }
    set_g1(&mut img, 150);
    for b in TOTAL_BLOCKS..128 + BLK as u32 * 8 {
        set_g1(&mut img, b);
    }
    // Inode bitmaps: reserved 1..=8 in group 0; ino 2 + ino 65 allocated.
    for i in 1..=8u32 {
        set_inode_bit(&mut img, i);
    }
    // Group-1 inode bitmap is at block 132; ino 65 → bit 0.
    img[blk_off(132)] |= 1;

    // Inodes: root dir (ino 2) → block 40; g1file (ino 65) → block 150.
    // ino 65 is the first inode of group 1's table at block 133.
    let t = 1_705_314_620u32;
    put_inode(&mut img, 2, 0o40755, 1024, 2, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 40)]), 0, t, 0, None, 0);
    put_inode_at(&mut img, blk_off(133), 0o100644, 14, 1, 2, EXT4_EXTENTS_FL, extent_root(&[(0, 1, 150)]), 0, t, 0, None, 0);

    // Root dir (block 40): ".", "..", "g1file.txt".
    put_dirent(&mut img, 40, 0, 2, 12, b".", FT_DIR);
    put_dirent(&mut img, 40, 12, 2, 12, b"..", FT_DIR);
    put_dirent(&mut img, 40, 24, 65, 1024 - 24, b"g1file.txt", FT_REG);
    put_data(&mut img, 150, b"GROUP-ONE-FILE");

    // Free counts: 256 blocks, 44 allocated → 212 free;
    // 128 inodes, 8 reserved + ino 2 + ino 65 = 10 used → 118 free.
    w32(&mut img, 1024 + 0x0C, 212);
    w32(&mut img, 1024 + 0x10, 118);
    img
}
