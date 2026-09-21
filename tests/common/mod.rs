//! Synthetic in-memory APFS container for integration tests.
//!
//! Builds a 4 KiB-block container with a contiguous checkpoint descriptor
//! area holding **two checkpoints** (xid 1 and xid 2). The older generation
//! contains a file (`old.txt`) that is absent from the live generation —
//! the deleted-recovery fixture. The live generation carries one file
//! (`photo.png`, PNG-signed for magic checks), a directory (`docs`), an
//! xattr, a hardlink pair, and a snapshot name record.
//!
//! Every object block is Fletcher-64-sealed via [`seal`].
//!
//! Block map (bs = 4096, `BLOCKS` total):
//! ```text
//!   0        nx_superblock (block-0 copy, xid 2)
//!   1..9     descriptor area:  [1]=nxsb@xid1 [2]=cpmap@xid1
//!              [3]=nxsb@xid2 [4]=cpmap@xid2, rest unused
//!   9..      data area
//!   9        container omap obj @xid1 (ephemeral oid O_CMAP)
//!   10       container omap root @xid1 (ephemeral oid O_CMAP_TREE)
//!   11       apsb @xid1        (virtual oid O_APSB via omap)
//!   12       vol omap obj @xid1 (physical)
//!   13       vol omap root @xid1 (physical)
//!   14       fs tree root @xid1 (virtual oid O_FSTREE)
//!   15..20   same for xid 2
//!   21       spaceman (ephemeral oid O_SPACEMAN, xid 2)
//!   22       snap-meta tree root (physical, xid 2)
//!   30,32    photo.png extents
//!   31,32    old.txt extents   (block 32 is shared → partial overwrite)
//! ```
#![allow(dead_code)]

use std::collections::BTreeMap;

pub const BS: usize = 4096;
pub const BLOCKS: u64 = 64;

pub const O_NXSB: u64 = 1;
pub const O_CMAP: u64 = 0x100;
pub const O_CMAP_TREE: u64 = 0x101;
pub const O_SPACEMAN: u64 = 0x102;
pub const O_APSB: u64 = 0x200;
pub const O_FSTREE: u64 = 0x300;

// Object type codes / storage flags.
const T_NXSB: u32 = 0x0001;
const T_BTREE: u32 = 0x0002;
const T_BTREE_NODE: u32 = 0x0003;
const T_SPACEMAN: u32 = 0x0005;
const T_OMAP: u32 = 0x000b;
const T_CPMAP: u32 = 0x000c;
const T_FS: u32 = 0x000d;
const T_FSTREE: u32 = 0x000e;
const T_SNAPMETA: u32 = 0x0010;
const F_PHYS: u32 = 0x4000_0000;
const F_EPH: u32 = 0x8000_0000;

// jrecord types.
pub const JT_SNAP_META: u64 = 0x1;
pub const JT_INODE: u64 = 0x3;
pub const JT_XATTR: u64 = 0x4;
pub const JT_SIBLING_LINK: u64 = 0x5;
pub const JT_FILE_EXTENT: u64 = 0x8;
pub const JT_DREC: u64 = 0x9;
pub const JT_DIR_STATS: u64 = 0xa;
pub const JT_SNAP_NAME: u64 = 0xb;
pub const JT_SIBLING_MAP: u64 = 0xc;

pub const ROOT_DIR: u64 = 2;

// ---------------------------------------------------------------------------
// Fletcher-64 (same algorithm as src/checksum.rs — duplicated so the test
// corpus doesn't depend on crate internals).
// ---------------------------------------------------------------------------
pub fn fletcher64(block: &mut [u8]) {
    let n = block.len() / 4;
    let mut sum1: u64 = 0;
    let mut sum2: u64 = 0;
    for i in 2..n {
        let w = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        sum1 = (sum1 + w as u64) % 0xffff_ffff;
        sum2 = (sum2 + sum1) % 0xffff_ffff;
    }
    let c1 = 0xffff_ffffu64 - ((sum1 + sum2) % 0xffff_ffff);
    let c2 = 0xffff_ffffu64 - ((sum1 + c1) % 0xffff_ffff);
    let c = (c2 << 32) | c1;
    block[0..8].copy_from_slice(&c.to_le_bytes());
}

/// Recompute and store the checksum of `block` (zeroing the field first).
pub fn seal(block: &mut [u8]) {
    block[..8].fill(0);
    fletcher64(block);
}

// ---------------------------------------------------------------------------
// Raw write helpers
// ---------------------------------------------------------------------------
fn w16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// 32-byte object header + caller seals afterwards.
fn obj_hdr(b: &mut [u8], oid: u64, xid: u64, otype: u32, osubtype: u32) {
    w64(b, 8, oid);
    w64(b, 16, xid);
    w32(b, 24, otype);
    w32(b, 28, osubtype);
}

/// jkey header: oid in low 60 bits, type in high 4.
pub fn jhdr(oid: u64, jtype: u64) -> u64 {
    (oid & 0x0fff_ffff_ffff_ffff) | (jtype << 60)
}

// ---------------------------------------------------------------------------
// Record builders (fs-tree leaf payloads)
// ---------------------------------------------------------------------------
/// `xf_blob_t` for one xfield.
pub fn xblob(xtype: u8, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&1u16.to_le_bytes()); // num_exts
    v.extend_from_slice(&4u16.to_le_bytes()); // used_data (hdr+desc)
    v.push(xtype);
    v.push(0); // flags
    v.extend_from_slice(&(data.len() as u16).to_le_bytes());
    v.extend_from_slice(data);
    v
}

/// `j_inode_val_t`.
pub fn inode_val(
    parent: u64,
    private_id: u64,
    mode: u16,
    nlinks: u32,
    xfields: &[Vec<u8>],
) -> Vec<u8> {
    let mut v = vec![0u8; 92];
    w64(&mut v, 0, parent);
    w64(&mut v, 8, private_id);
    for (i, t) in [0x55AA_0000u64, 0x55AB_0000, 0x55AC_0000, 0x55AD_0000]
        .iter()
        .enumerate()
    {
        w64(&mut v, 16 + i * 8, *t);
    }
    w64(&mut v, 48, 0); // internal_flags
    w32(&mut v, 56, nlinks);
    w32(&mut v, 72, 501); // owner
    w32(&mut v, 76, 20); // group
    w16(&mut v, 80, mode);
    // Multi-xfield blob: u16 num, u16 used, then `num` descriptors
    // {u8 type, u8 flags, u16 size}, then values 8-aligned within the blob.
    let num = xfields.len() as u16;
    let mut blob = Vec::new();
    blob.extend_from_slice(&num.to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes());
    for xf in xfields {
        blob.push(xf[4]); // x_type
        blob.push(0); // flags
        let sz = u16::from_le_bytes([xf[6], xf[7]]);
        blob.extend_from_slice(&sz.to_le_bytes());
    }
    let mut rel = 0usize;
    for xf in xfields {
        let sz = u16::from_le_bytes([xf[6], xf[7]]) as usize;
        let data = &xf[8..8 + sz];
        let pad = ((rel + 7) & !7) - rel;
        blob.extend(std::iter::repeat_n(0, pad));
        blob.extend_from_slice(data);
        rel += pad + sz;
    }
    v.extend_from_slice(&blob);
    v
}

/// `j_dstream_t` xfield data (type 8).
pub fn xf_dstream(size: u64, alloced: u64, crypto_id: u64) -> Vec<u8> {
    let mut d = vec![0u8; 40];
    w64(&mut d, 0, size);
    w64(&mut d, 8, alloced);
    w64(&mut d, 16, crypto_id);
    d
}

/// `j_drec_hashed_key_t` key + `j_drec_val_t` value.
pub fn drec_kv(parent: u64, name: &str, file_id: u64, ftype: u16, hash: u32) -> (Vec<u8>, Vec<u8>) {
    let nlen = name.len() as u32 + 1; // includes NUL
    let mut k = Vec::new();
    k.extend_from_slice(&jhdr(parent, JT_DREC).to_le_bytes());
    k.extend_from_slice(&(((hash & 0x3f_ffff) << 10) | nlen).to_le_bytes());
    k.extend_from_slice(name.as_bytes());
    k.push(0);
    let mut v = Vec::new();
    v.extend_from_slice(&file_id.to_le_bytes());
    v.extend_from_slice(&0x55A0_0000u64.to_le_bytes()); // date_added
    v.extend_from_slice(&ftype.to_le_bytes()); // flags low nibble = type
    (k, v)
}

/// `j_file_extent_key_t` + `j_file_extent_val_t`.
pub fn extent_kv(
    private_id: u64,
    logical: u64,
    len: u64,
    phys: u64,
    crypto: u64,
) -> (Vec<u8>, Vec<u8>) {
    let mut k = Vec::new();
    k.extend_from_slice(&jhdr(private_id, JT_FILE_EXTENT).to_le_bytes());
    k.extend_from_slice(&logical.to_le_bytes());
    let mut v = Vec::new();
    v.extend_from_slice(&len.to_le_bytes()); // len_and_flags (flags=0)
    v.extend_from_slice(&phys.to_le_bytes());
    v.extend_from_slice(&crypto.to_le_bytes());
    (k, v)
}

/// `j_xattr_key_t` + embedded `j_xattr_val_t`.
pub fn xattr_kv(oid: u64, name: &str, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut k = Vec::new();
    k.extend_from_slice(&jhdr(oid, JT_XATTR).to_le_bytes());
    k.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
    k.extend_from_slice(name.as_bytes());
    k.push(0);
    let mut v = Vec::new();
    v.extend_from_slice(&0x0002u16.to_le_bytes()); // XATTR_DATA_EMBEDDED
    v.extend_from_slice(&(data.len() as u16).to_le_bytes());
    v.extend_from_slice(data);
    (k, v)
}

/// `j_xattr_key_t` + streamed `j_xattr_val_t` (XATTR_DATA_STREAM).
pub fn xattr_stream_kv(oid: u64, name: &str, stream_oid: u64) -> (Vec<u8>, Vec<u8>) {
    let mut k = Vec::new();
    k.extend_from_slice(&jhdr(oid, JT_XATTR).to_le_bytes());
    k.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
    k.extend_from_slice(name.as_bytes());
    k.push(0);
    let mut v = Vec::new();
    v.extend_from_slice(&0x0001u16.to_le_bytes()); // XATTR_DATA_STREAM
    v.extend_from_slice(&48u16.to_le_bytes()); // j_xattr_dstream_t len
    v.extend_from_slice(&stream_oid.to_le_bytes());
    v.extend_from_slice(&[0u8; 40]); // j_dstream_t
    (k, v)
}

/// `j_sibling_link_key_t` + `j_sibling_val_t`.
pub fn sibling_link_kv(oid: u64, sibling_id: u64, parent: u64, name: &str) -> (Vec<u8>, Vec<u8>) {
    let mut k = Vec::new();
    k.extend_from_slice(&jhdr(oid, JT_SIBLING_LINK).to_le_bytes());
    k.extend_from_slice(&sibling_id.to_le_bytes());
    let mut v = Vec::new();
    v.extend_from_slice(&parent.to_le_bytes());
    v.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
    v.extend_from_slice(name.as_bytes());
    v.push(0);
    (k, v)
}

/// `j_sibling_map_key_t` + `j_sibling_map_val_t`.
pub fn sibling_map_kv(sibling_id: u64, file_id: u64) -> (Vec<u8>, Vec<u8>) {
    (
        jhdr(sibling_id, JT_SIBLING_MAP).to_le_bytes().to_vec(),
        file_id.to_le_bytes().to_vec(),
    )
}

/// `j_dir_stats_key_t` + `j_dir_stats_val_t`.
pub fn dir_stats_kv(oid: u64, children: u64, size: u64) -> (Vec<u8>, Vec<u8>) {
    let mut v = vec![0u8; 32];
    w64(&mut v, 0, children);
    w64(&mut v, 8, size);
    (jhdr(oid, JT_DIR_STATS).to_le_bytes().to_vec(), v)
}

/// `j_snap_name_key_t` + `j_snap_name_val_t`.
pub fn snap_name_kv(name: &str, xid: u64) -> (Vec<u8>, Vec<u8>) {
    let mut k = Vec::new();
    k.extend_from_slice(&jhdr(0x0fff_ffff_ffff_ffff, JT_SNAP_NAME).to_le_bytes());
    k.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
    k.extend_from_slice(name.as_bytes());
    k.push(0);
    (k, xid.to_le_bytes().to_vec())
}

/// `j_snap_metadata_val_t` (snap-meta tree record; key hdr = snap_xid,1).
pub fn snap_meta_kv(snap_xid: u64, sblock_oid: u64, name: &str) -> (Vec<u8>, Vec<u8>) {
    let k = jhdr(snap_xid, JT_SNAP_META).to_le_bytes().to_vec();
    let mut v = vec![0u8; 50];
    w64(&mut v, 8, sblock_oid);
    w64(&mut v, 16, 0x55E0_0000); // create_time
    w64(&mut v, 24, 0x55E1_0000); // change_time
    w16(&mut v, 48, name.len() as u16 + 1);
    v.extend_from_slice(name.as_bytes());
    v.push(0);
    (k, v)
}

// ---------------------------------------------------------------------------
// B-tree node builder (single-node ROOT|LEAF trees suffice for tests)
// ---------------------------------------------------------------------------
/// `bt_flags` for `btree_info_t`: physical trees carry 0x10, ephemeral 0x8,
/// virtual (fs/snap trees resolved via omap) carry neither.
pub const BT_EPH: u32 = 0x8;
pub const BT_PHYS: u32 = 0x10;

/// Serialize a leaf/root node carrying `entries` (already key-sorted).
/// `fixed`: Some((klen,vlen)) → kvoff_t table + FIXED_KV flag.
pub fn btree_leaf(
    oid: u64,
    xid: u64,
    subtype: u32,
    entries: &[(Vec<u8>, Vec<u8>)],
    fixed: Option<(u16, u16)>,
    bt_flags: u32,
) -> Vec<u8> {
    let mut b = vec![0u8; BS];
    let fixed_kv = fixed.is_some();
    let flags = 0x0001u16 | 0x0002 | if fixed_kv { 0x0004 } else { 0 };
    // Node o_type carries the tree's storage class (ephemeral/physical/
    // virtual=none); o_subtype carries the tree's object type.
    let storage = if bt_flags & BT_EPH != 0 {
        F_EPH
    } else if bt_flags & BT_PHYS != 0 {
        F_PHYS
    } else {
        0 // virtual
    };
    obj_hdr(&mut b, oid, xid, T_BTREE_NODE | storage, subtype);
    w16(&mut b, 32, flags);
    w16(&mut b, 34, 0); // level 0
    w32(&mut b, 36, entries.len() as u32);
    let esz = if fixed_kv { 4 } else { 8 };
    w16(&mut b, 42, (entries.len() * esz) as u16); // table_space len
    let vals_end = BS - 40; // root → trailing btree_info_t
    let keys_start = 56 + entries.len() * esz;
    let mut kcur = keys_start;
    let mut vend = vals_end;
    for (i, (k, v)) in entries.iter().enumerate() {
        let e = 56 + i * esz;
        vend -= v.len();
        if fixed_kv {
            w16(&mut b, e, (kcur - keys_start) as u16);
            w16(&mut b, e + 2, (vals_end - vend) as u16);
        } else {
            w16(&mut b, e, (kcur - keys_start) as u16);
            w16(&mut b, e + 2, k.len() as u16);
            w16(&mut b, e + 4, (vals_end - vend) as u16);
            w16(&mut b, e + 6, v.len() as u16);
        }
        b[kcur..kcur + k.len()].copy_from_slice(k);
        b[vend..vend + v.len()].copy_from_slice(v);
        kcur += k.len();
    }
    // btree_info_t at block end: flags, node_size, key_size, val_size,
    // longest key/val, key_count, node_count.
    let t = BS - 40;
    w32(&mut b, t, bt_flags);
    w32(&mut b, t + 4, BS as u32);
    if let Some((kl, vl)) = fixed {
        w32(&mut b, t + 8, kl as u32);
        w32(&mut b, t + 12, vl as u32);
    }
    w64(&mut b, t + 24, entries.len() as u64);
    w64(&mut b, t + 32, 1);
    seal(&mut b);
    b
}

/// An `omap_val_t` leaf value.
pub fn omap_val(paddr: u64) -> Vec<u8> {
    let mut v = vec![0u8; 16];
    w32(&mut v, 4, BS as u32); // size
    w64(&mut v, 8, paddr);
    v
}

/// `omap_phys_t` block.
pub fn omap_obj(oid: u64, xid: u64, tree_oid: u64, tree_ephemeral: bool) -> Vec<u8> {
    let mut b = vec![0u8; BS];
    let st = if tree_ephemeral { F_EPH } else { F_PHYS };
    obj_hdr(&mut b, oid, xid, T_OMAP | st, 0);
    w32(&mut b, 40, T_BTREE | st); // tree_type
    w64(&mut b, 48, tree_oid);
    seal(&mut b);
    b
}

/// `checkpoint_map_phys_t` block. `entries`: `(oid, paddr)` (fs_oid 0).
pub fn cpmap_block(xid: u64, entries: &[(u64, u64)]) -> Vec<u8> {
    let mut b = vec![0u8; BS];
    obj_hdr(&mut b, 0, xid, T_CPMAP | F_EPH, 0);
    w32(&mut b, 36, entries.len() as u32);
    for (i, (oid, paddr)) in entries.iter().enumerate() {
        let e = 40 + i * 40;
        w32(&mut b, e, F_EPH);
        w32(&mut b, e + 8, BS as u32);
        w64(&mut b, e + 24, *oid);
        w64(&mut b, e + 32, *paddr);
    }
    seal(&mut b);
    b
}

/// `nx_superblock_t` block.
#[allow(clippy::too_many_arguments)]
pub fn nxsb(xid: u64, fs_oids: &[u64]) -> Vec<u8> {
    let mut b = vec![0u8; BS];
    obj_hdr(&mut b, O_NXSB, xid, T_NXSB | F_EPH, 0);
    b[32..36].copy_from_slice(b"NXSB");
    w32(&mut b, 36, BS as u32);
    w64(&mut b, 40, BLOCKS);
    w32(&mut b, 104, 8); // xp_desc_blocks (contiguous)
    w32(&mut b, 108, 40); // xp_data_blocks
    w64(&mut b, 112, 1); // xp_desc_base
    w64(&mut b, 120, 9); // xp_data_base
    w32(&mut b, 128, 1); // xp_desc_next
    w32(&mut b, 136, 1); // xp_desc_index
    w32(&mut b, 140, 1); // xp_desc_len
    w64(&mut b, 152, O_SPACEMAN);
    w64(&mut b, 160, O_CMAP);
    w64(&mut b, 1296, 50); // nx_keybag_base → claims blocks 50..52
    w64(&mut b, 1304, 2); // nx_keybag_blocks
    w32(&mut b, 180, fs_oids.len() as u32);
    for (i, o) in fs_oids.iter().enumerate() {
        w64(&mut b, 184 + i * 8, *o);
    }
    seal(&mut b);
    b
}

/// `apfs_superblock_t` block.
pub fn apsb(
    oid: u64,
    xid: u64,
    omap_paddr: u64,
    root_tree_oid: u64,
    snap_tree_paddr: u64,
    encrypted: bool,
) -> Vec<u8> {
    let mut b = vec![0u8; BS];
    obj_hdr(&mut b, oid, xid, T_FS, 0);
    b[32..36].copy_from_slice(b"APSB");
    w64(&mut b, 56, 1); // incompat: CASE_INSENSITIVE → hashed drecs
    w64(&mut b, 64, 0x5600_0000); // unmount_time
    w32(&mut b, 116, T_FSTREE); // root_tree_type
    w64(&mut b, 128, omap_paddr);
    w64(&mut b, 136, root_tree_oid);
    w64(&mut b, 152, snap_tree_paddr);
    w64(&mut b, 184, 2); // num_files
    w64(&mut b, 192, 2); // num_directories
    w64(&mut b, 216, 1); // num_snapshots
    let uuid = [0xABu8; 16];
    b[240..256].copy_from_slice(&uuid);
    w64(&mut b, 264, if encrypted { 0 } else { 1 }); // fs_flags UNENCRYPTED
    let name = b"TestVol\0";
    b[704..704 + name.len()].copy_from_slice(name);
    seal(&mut b);
    b
}

/// `spaceman_phys_t` block (header fields only).
pub fn spaceman(oid: u64, xid: u64, free: u64) -> Vec<u8> {
    let mut b = vec![0u8; BS];
    obj_hdr(&mut b, oid, xid, T_SPACEMAN | F_EPH, 0);
    w32(&mut b, 32, BS as u32);
    w32(&mut b, 36, 8); // blocks_per_chunk
    w32(&mut b, 40, 32); // chunks_per_cib
    w64(&mut b, 48, BLOCKS);
    w64(&mut b, 72, free); // dev_free_count
    seal(&mut b);
    b
}

// ---------------------------------------------------------------------------
// The container image
// ---------------------------------------------------------------------------
/// Build the two-checkpoint test image. `encrypted` flips the volume's
/// UNENCRYPTED flag (FileVault fixture — no actual crypto is exercised).
pub fn build_image(encrypted: bool) -> Vec<u8> {
    let mut img: BTreeMap<u64, Vec<u8>> = BTreeMap::new();

    // ---- fs-tree records --------------------------------------------------
    // Shared in both generations.
    let root_inode = inode_val(1, ROOT_DIR, 0o040755, 3, &[]);
    let photo_inode = inode_val(
        ROOT_DIR,
        200,
        0o100644,
        2, // hardlinked twice
        &[xblob(8, &xf_dstream(8192, 8192, 0))],
    );

    // docs carries every inode xfield the decoder interprets.
    let docs_inode = inode_val(
        ROOT_DIR,
        300,
        0o040755,
        1,
        &[
            xblob(1, &0x55u64.to_le_bytes()),         // snap_xid
            xblob(3, &77u32.to_le_bytes()),           // document_id
            xblob(5, &9999u64.to_le_bytes()),         // prev_fsize
            xblob(7, &[0xABu8; 32]),                  // finder_info
            xblob(13, &128u64.to_le_bytes()),         // sparse_bytes
            xblob(14, &0x0102_0304u64.to_le_bytes()), // rdev
        ],
    );

    // Generation B (live, xid 2).
    let mut gen_b: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (
            jhdr(ROOT_DIR, JT_INODE).to_le_bytes().to_vec(),
            root_inode.clone(),
        ),
        (
            jhdr(300, JT_INODE).to_le_bytes().to_vec(),
            docs_inode.clone(),
        ),
        (
            jhdr(200, JT_INODE).to_le_bytes().to_vec(),
            photo_inode.clone(),
        ),
        drec_kv(ROOT_DIR, "docs", 300, 0x4, 0x1234),
        drec_kv(ROOT_DIR, "photo.png", 200, 0x8, 0x5678),
        drec_kv(300, "inner.txt", 200, 0x8, 0x9abc), // second name for oid 200
        dir_stats_kv(ROOT_DIR, 3, 8192),
        extent_kv(200, 0, BS as u64, 30, 0),
        extent_kv(200, BS as u64, BS as u64, 32, 0),
        xattr_kv(200, "com.apple.quarantine", &[1, 2, 3, 4]),
        // Streamed (non-embedded) xattr on photo.png.
        xattr_stream_kv(200, "com.apple.ResourceFork", 0xBEEF),
        // photo.png's hardlink via sibling link + sibling map.
        sibling_link_kv(200, 500, 300, "alias.png"),
        sibling_map_kv(500, 200),
        snap_name_kv("test-snap", 1),
        // sparse.bin: extents at logical 0 (block 33) and 8192 (block 34),
        // logical hole 4096..8192 must read as zeros.
        (
            jhdr(400, JT_INODE).to_le_bytes().to_vec(),
            inode_val(
                ROOT_DIR,
                400,
                0o100644,
                1,
                &[xblob(8, &xf_dstream(12288, 8192, 0))],
            ),
        ),
        drec_kv(ROOT_DIR, "sparse.bin", 400, 0x8, 0x7777),
        extent_kv(400, 0, BS as u64, 33, 0),
        extent_kv(400, 2 * BS as u64, BS as u64, 34, 0x99),
        // tiny.txt: 100 bytes in one 4K extent → slack.
        (
            jhdr(401, JT_INODE).to_le_bytes().to_vec(),
            inode_val(
                ROOT_DIR,
                401,
                0o100644,
                1,
                &[xblob(8, &xf_dstream(100, 4096, 0))],
            ),
        ),
        drec_kv(ROOT_DIR, "tiny.txt", 401, 0x8, 0xaaaa),
        extent_kv(401, 0, BS as u64, 35, 0),
        // link: symlink with embedded com.apple.fs.symlink xattr.
        (
            jhdr(402, JT_INODE).to_le_bytes().to_vec(),
            inode_val(ROOT_DIR, 402, 0o120777, 1, &[]),
        ),
        drec_kv(ROOT_DIR, "link", 402, 0xa, 0xbbbb),
        xattr_kv(402, "com.apple.fs.symlink", b"docs/target\0"),
        // Crypto-state record → extent_encrypted meta on oid 200.
        (jhdr(200, 0x7).to_le_bytes().to_vec(), Vec::new()),
        // Physical extent record (jtype 0x2): claims block 36.
        (jhdr(36, 0x2).to_le_bytes().to_vec(), {
            let mut v = vec![0u8; 20];
            w64(&mut v, 0, BS as u64); // len_and_kind
            v
        }),
        // Unknown jtype (dstream-id 0x6) → unhandled_jrec_types meta.
        (jhdr(999, 0x6).to_le_bytes().to_vec(), vec![1u8; 4]),
        // Orphan inode: no directory record → /$ORPHANED/ bucket.
        (
            jhdr(403, JT_INODE).to_le_bytes().to_vec(),
            inode_val(ROOT_DIR, 403, 0o100644, 1, &[]),
        ),
        // Broken parent chain: parent oid 999 has no inode/drec.
        drec_kv(999, "stray.txt", 403, 0x8, 0xcccc),
        // Truly orphaned inode (no drec at all).
        (
            jhdr(404, JT_INODE).to_le_bytes().to_vec(),
            inode_val(
                ROOT_DIR,
                404,
                0o100644,
                1,
                &[xblob(8, &xf_dstream(50, 0, 0))],
            ),
        ),
        // Second hardlink whose sibling_map entry is missing.
        sibling_link_kv(200, 501, 300, "alias2.png"),
        // Third hardlink whose sibling_map resolves to the wrong oid.
        sibling_link_kv(200, 502, 300, "alias3.png"),
        sibling_map_kv(502, 999),
        // Fourth hardlink with a broken parent chain.
        sibling_link_kv(200, 503, 999, "alias4.png"),
        sibling_map_kv(503, 200),
    ];
    gen_b.sort_by(|a, b| a.0.cmp(&b.0));

    // Generation A (xid 1) = gen B + the since-deleted `old.txt` (inode 100,
    // private_id 100 → extents at blocks 31 and 32).
    let old_inode = inode_val(
        ROOT_DIR,
        100,
        0o100644,
        1,
        &[xblob(8, &xf_dstream(8192, 8192, 0))],
    );
    let mut gen_a: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (
            jhdr(ROOT_DIR, JT_INODE).to_le_bytes().to_vec(),
            root_inode.clone(),
        ),
        (
            jhdr(300, JT_INODE).to_le_bytes().to_vec(),
            docs_inode.clone(),
        ),
        (
            jhdr(200, JT_INODE).to_le_bytes().to_vec(),
            photo_inode.clone(),
        ),
        (jhdr(100, JT_INODE).to_le_bytes().to_vec(), old_inode),
        drec_kv(ROOT_DIR, "docs", 300, 0x4, 0x1234),
        drec_kv(ROOT_DIR, "photo.png", 200, 0x8, 0x5678),
        drec_kv(ROOT_DIR, "old.txt", 100, 0x8, 0xbeef),
        dir_stats_kv(ROOT_DIR, 4, 16384),
        extent_kv(200, 0, BS as u64, 30, 0),
        extent_kv(200, BS as u64, BS as u64, 32, 0),
        extent_kv(100, 0, BS as u64, 31, 0),
        extent_kv(100, BS as u64, BS as u64, 32, 0),
        // lost.txt: deleted AND its parent chain is broken in the old
        // generation → orphan-path fallback in deleted emission.
        (
            jhdr(500, JT_INODE).to_le_bytes().to_vec(),
            inode_val(
                ROOT_DIR,
                500,
                0o100644,
                1,
                &[xblob(8, &xf_dstream(4096, 4096, 0))],
            ),
        ),
        drec_kv(999, "lost.txt", 500, 0x8, 0xdddd),
        extent_kv(500, 0, BS as u64, 37, 0),
        // empty.bin: deleted inode with a size but no extents →
        // Unrecoverable recovery state.
        (
            jhdr(501, JT_INODE).to_le_bytes().to_vec(),
            inode_val(
                ROOT_DIR,
                501,
                0o100644,
                1,
                &[xblob(8, &xf_dstream(100, 0, 0))],
            ),
        ),
        drec_kv(ROOT_DIR, "empty.bin", 501, 0x8, 0xeeee),
    ];
    gen_a.sort_by(|a, b| a.0.cmp(&b.0));

    // ---- per-checkpoint object graphs -------------------------------------
    // xid 1 → blocks 9..14 ; xid 2 → blocks 15..20.
    let gen = |xid: u64, base: u64, records: &[(Vec<u8>, Vec<u8>)]| {
        // container omap (ephemeral): O_APSB → apsb block
        let cmap_tree = btree_leaf(
            O_CMAP_TREE,
            xid,
            T_OMAP,
            &[(
                {
                    let mut k = vec![0u8; 16];
                    w64(&mut k, 0, O_APSB);
                    w64(&mut k, 8, xid);
                    k
                },
                omap_val(base + 2),
            )],
            Some((16, 16)),
            BT_EPH,
        );
        let cmap = omap_obj(O_CMAP, xid, O_CMAP_TREE, true);
        let vomap_tree = btree_leaf(
            base + 4,
            xid,
            T_OMAP,
            &[(
                {
                    let mut k = vec![0u8; 16];
                    w64(&mut k, 0, O_FSTREE);
                    w64(&mut k, 8, xid);
                    k
                },
                omap_val(base + 5),
            )],
            Some((16, 16)),
            BT_PHYS,
        );
        let vomap = omap_obj(base + 3, xid, base + 4, false);
        let ap = apsb(O_APSB, xid, base + 3, O_FSTREE, 22, encrypted);
        let fstree = btree_leaf(O_FSTREE, xid, T_FSTREE, records, None, 0);
        (cmap, cmap_tree, ap, vomap, vomap_tree, fstree)
    };
    let (ca, cat, aa, va, vat, fa) = gen(1, 9, &gen_a);
    let (cb, cbt, ab, vb, vbt, fb) = gen(2, 15, &gen_b);
    img.insert(9, ca);
    img.insert(10, cat);
    img.insert(11, aa);
    img.insert(12, va);
    img.insert(13, vat);
    img.insert(14, fa);
    img.insert(15, cb);
    img.insert(16, cbt);
    img.insert(17, ab);
    img.insert(18, vb);
    img.insert(19, vbt);
    img.insert(20, fb);

    // Spaceman + snap-meta tree (live generation only).
    img.insert(21, spaceman(O_SPACEMAN, 2, 20));
    img.insert(
        22,
        btree_leaf(
            22,
            2,
            T_SNAPMETA,
            &[snap_meta_kv(1, 23, "test-snap"), snap_meta_kv(5, 23, "")],
            None,
            BT_PHYS,
        ),
    );

    // ---- descriptor area --------------------------------------------------
    img.insert(0, nxsb(2, &[O_APSB]));
    img.insert(1, nxsb(1, &[O_APSB]));
    img.insert(
        2,
        cpmap_block(1, &[(O_CMAP, 9), (O_CMAP_TREE, 10), (O_SPACEMAN, 21)]),
    );
    img.insert(3, nxsb(2, &[O_APSB]));
    img.insert(
        4,
        cpmap_block(2, &[(O_CMAP, 15), (O_CMAP_TREE, 16), (O_SPACEMAN, 21)]),
    );

    // ---- file data --------------------------------------------------------
    let mut photo0 = vec![0u8; BS];
    photo0[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
    photo0[8..16].copy_from_slice(b"IHDRtest");
    img.insert(30, photo0);
    let mut photo1 = vec![0u8; BS];
    photo1[..8].copy_from_slice(b"PNGDATA2");
    img.insert(32, photo1);
    let mut old0 = vec![0u8; BS];
    old0[..12].copy_from_slice(b"deleted-data");
    img.insert(31, old0);
    let mut sp0 = vec![0u8; BS];
    sp0[..8].copy_from_slice(b"SPARSE-1");
    img.insert(33, sp0);
    let mut sp1 = vec![0u8; BS];
    sp1[..8].copy_from_slice(b"SPARSE-2");
    img.insert(34, sp1);

    // ---- assemble ----------------------------------------------------------
    let mut out = vec![0u8; (BLOCKS as usize) * BS];
    for (blk, data) in img {
        out[blk as usize * BS..blk as usize * BS + BS].copy_from_slice(&data);
    }
    out
}

/// Flip bytes at `block` so its Fletcher-64 no longer verifies.
pub fn corrupt_block(img: &mut [u8], block: u64) {
    let off = block as usize * BS;
    img[off + 64] ^= 0x5A;
}
