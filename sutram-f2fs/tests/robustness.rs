//! Fault-injection coverage: mutate the synthetic image to reach the
//! defensive arms — node-chain walking (direct/indirect/double-indirect),
//! stale-NAT and free-segment residue, checkpoint fallbacks, recovery
//! assessment edge states, and strict/lenient error handling.

mod common;

use std::io::Read;
use std::sync::Arc;

use common::*;
use sutram_f2fs::F2fsParser;
use sutram_fs::{
    DetectConfidence, EntryKind, FileSystem, FsEntry, FsEntryStatus, FsParser, MountOptions,
    RecoveryState,
};
use sutram_io::{into_arc, ByteSource};

const FT_FILE: u8 = 1;
const FT_DIR: u8 = 2;

fn src(v: Vec<u8>) -> Arc<dyn ByteSource> {
    into_arc(v)
}
fn img() -> Vec<u8> {
    (*image()).clone()
}
fn mount(v: Vec<u8>) -> Box<dyn FileSystem> {
    F2fsParser.mount(src(v)).expect("mount")
}
fn mount_opts(v: Vec<u8>, o: MountOptions) -> Box<dyn FileSystem> {
    F2fsParser.mount_with(src(v), &o).expect("mount")
}
fn walk(v: Vec<u8>) -> (Vec<FsEntry>, usize) {
    let mut ok = Vec::new();
    let mut err = 0;
    for r in mount(v).walk() {
        match r {
            Ok(e) => ok.push(e),
            Err(_) => err += 1,
        }
    }
    (ok, err)
}
fn by_path<'a>(entries: &'a [FsEntry], path: &str) -> &'a FsEntry {
    entries
        .iter()
        .find(|e| e.path == path)
        .unwrap_or_else(|| panic!("no entry at {path}"))
}
fn by_id(entries: &[FsEntry], nid: u64) -> &FsEntry {
    entries
        .iter()
        .find(|e| e.entry_id == nid)
        .unwrap_or_else(|| panic!("no entry nid {nid}"))
}

// --- low-level writers (all little-endian, explicit) -------------------------

fn w16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn blk(img: &mut [u8], n: u64) -> &mut [u8] {
    let s = n as usize * BLK;
    &mut img[s..s + BLK]
}

/// Current-copy NAT entry for `nid` (block 2560). `stale` selects the
/// previous-checkpoint copy (block 3072).
fn nat_set(img: &mut [u8], nid: u32, blk_addr: u32, stale: bool) {
    let base = if stale { 3072 * BLK } else { 2560 * BLK };
    let o = base + nid as usize * 9;
    img[o] = 1; // version
    w32(&mut img[o..], 1, nid);
    w32(&mut img[o..], 5, blk_addr);
}

/// Node footer at the tail of a node block.
fn node_footer(b: &mut [u8], nid: u32, ino: u32, cp_ver: u64, next: u32) {
    w32(b, BLK - 24, nid);
    w32(b, BLK - 20, ino);
    w32(b, BLK - 16, 0);
    w64(b, BLK - 12, cp_ver);
    w32(b, BLK - 4, next);
}

/// Write a dnode/indirect node: ptr array + footer (nid != ino).
fn dnode(img: &mut [u8], blkno: u64, nid: u32, ino: u32, ptrs: &[u32], cp_ver: u64) {
    let b = blk(img, blkno);
    b.fill(0);
    for (i, &p) in ptrs.iter().enumerate() {
        w32(b, i * 4, p);
    }
    node_footer(b, nid, ino, cp_ver, 0);
}

/// Write an inode-node block (subset of common::inode_node, exposed here
/// so the test can place inodes the fixture builder doesn't know about).
#[allow(clippy::too_many_arguments)]
fn inode_node(
    img: &mut [u8],
    blkno: u64,
    nid: u32,
    mode: u16,
    size: u64,
    links: u32,
    flags: u32,
    inline: u8,
    name: &[u8],
    pino: u32,
    addrs: &[u32],
    i_nids: &[u32; 5],
    cp_ver: u64,
    extra_isize: u16,
    next_blkaddr: u32,
) {
    let b = blk(img, blkno);
    b.fill(0);
    w16(b, 0, mode);
    b[2] = 7; // advise
    b[3] = inline;
    w32(b, 4, 1000);
    w32(b, 8, 1000);
    w32(b, 12, links);
    w64(b, 16, size);
    w64(b, 24, size / BLK as u64 + 1);
    w64(b, 32, MTIME_SEC);
    w64(b, 40, MTIME_SEC);
    w64(b, 48, MTIME_SEC);
    w32(b, 56, MTIME_NSEC);
    w32(b, 60, MTIME_NSEC);
    w32(b, 64, MTIME_NSEC);
    w32(b, 68, 9); // generation
    w32(b, 72, 3); // current_depth
    w32(b, 80, flags);
    w32(b, 84, pino);
    w32(b, 88, name.len() as u32);
    b[92..92 + name.len()].copy_from_slice(name);
    b[347] = 2; // dir_level
    if inline & 0x20 != 0 {
        w16(b, 360, extra_isize);
        if extra_isize >= 24 {
            w64(b, 372, CRTIME_SEC);
            w32(b, 380, CRTIME_NSEC);
        }
    }
    let base = 360 + (extra_isize as usize / 4) * 4;
    for (i, &a) in addrs.iter().enumerate() {
        w32(b, base + i * 4, a);
    }
    for (i, &n) in i_nids.iter().enumerate() {
        w32(b, 4052 + i * 4, n);
    }
    node_footer(b, nid, nid, cp_ver, next_blkaddr);
}

/// Dentry-block layout offsets for a 4 KiB region (214 slots).
const DE_BITMAP: usize = 0;
const DE_OFF: usize = 30;
const DE_NAME: usize = 2384;

/// Write a full dentry block (live entries get bitmap bits).
fn dentry_block(img: &mut [u8], blkno: u64, entries: &[(&[u8], u32, u8, bool)]) {
    let b = blk(img, blkno);
    b.fill(0);
    write_dentries_into(b, 0, entries);
}

fn write_dentries_into(b: &mut [u8], base: usize, entries: &[(&[u8], u32, u8, bool)]) {
    let mut slot = 0usize;
    for &(name, ino, ft, live) in entries {
        let name: &[u8] = name;
        let slots = name.len().div_ceil(8).max(1);
        let de = base + DE_OFF + slot * 11;
        w32(b, de, 0xCAFE);
        w32(b, de + 4, ino);
        w16(b, de + 8, name.len() as u16);
        b[de + 10] = ft;
        let fo = base + DE_NAME + slot * 8;
        b[fo..fo + name.len()].copy_from_slice(name);
        if live {
            for s in slot..slot + slots {
                b[base + DE_BITMAP + s / 8] |= 1 << (s % 8);
            }
        }
        slot += slots;
    }
}

/// Append one dentry to the existing root dentry block (13 slots used).
fn root_dentry_add(img: &mut [u8], slot: usize, name: &[u8], ino: u32, ft: u8, live: bool) {
    let b = blk(img, ROOT_DENTRY_BLK);
    let de = DE_OFF + slot * 11;
    w32(b, de, 0xBEEF);
    w32(b, de + 4, ino);
    w16(b, de + 8, name.len() as u16);
    b[de + 10] = ft;
    let fo = DE_NAME + slot * 8;
    b[fo..fo + name.len()].copy_from_slice(name);
    if live {
        for s in slot..slot + name.len().div_ceil(8).max(1) {
            b[DE_BITMAP + s / 8] |= 1 << (s % 8);
        }
    }
}

// --- the "weird" image --------------------------------------------------------

/// Extend the canonical image:
///
/// ```text
/// nids 20-33   big.bin's extent chain (dnodes, indirects, double-indirect)
/// nid 26       big.bin inode (flags/advise/dir_level/next_blkaddr/compr)
/// nid 40       phantom.bin — dead dentry, no inode anywhere
/// nid 41       weird.bin  — live dentry → non-inode node
/// nid 42       far.bin    — live dentry → NAT block outside segments
/// nid 50       notype     — inode with no mode bits (file_type fallback)
/// nid 51/52    xfile      — block xattrs (fscrypt ctx + verity)
/// nid 53-55    bigdir     — two dentry blocks
/// nid 56       holeblk    — extent beyond the image
/// nid 57       ghost2     — live dentry, free NAT entry
/// nid 58       empty.dat  — zero-size file
/// nid 59/62    stalexattr — xattr via stale NAT only
/// nid 44-48,60-61 — free-segment residue in seg 3 (blocks 6144+)
/// nid 63       stale NAT → a dnode (not an inode)
/// nid 70       second orphan (no node anywhere)
/// ```
fn weird_image() -> Vec<u8> {
    let mut v = img();

    // -- big.bin's extent tree -------------------------------------------------
    // direct: i_addr[0] → 4700.
    // i_nid[0] → 20: dnode at 4630 → [4701, 4702, COMPRESS_ADDR].
    dnode(&mut v, 4630, 20, 26, &[4701, 4702, u32::MAX - 1], CKPT_VER);
    nat_set(&mut v, 20, 4630, false);
    // i_nid[1] → 20 again → "visited twice" cycle note.
    // i_nid[2] → 21: indirect at 4631 → [22] → dnode 4632 → [4703].
    dnode(&mut v, 4631, 21, 26, &[22], CKPT_VER);
    nat_set(&mut v, 21, 4631, false);
    dnode(&mut v, 4632, 22, 26, &[4703], CKPT_VER);
    nat_set(&mut v, 22, 4632, false);
    // i_nid[3] → 32: indirect at 4638 → [31 (bad owner), 33 (an inode)].
    dnode(&mut v, 4638, 32, 26, &[31, 33], CKPT_VER);
    nat_set(&mut v, 32, 4638, false);
    dnode(&mut v, 4640, 31, 999, &[4705], CKPT_VER); // ino mismatch
    nat_set(&mut v, 31, 4640, false);
    inode_node(
        &mut v, 4641, 33, 0o100644, 4, 1, 0, 0, b"notadnode", ROOT_NID, &[4706], &[0; 5],
        CKPT_VER, 0, 0,
    );
    nat_set(&mut v, 33, 4641, false);
    // i_nid[4] → 23: double-indirect at 4633 → [24] → indirect 4634 → [25]
    //   → dnode 4635 → [4704].
    dnode(&mut v, 4633, 23, 26, &[24], CKPT_VER);
    nat_set(&mut v, 23, 4633, false);
    dnode(&mut v, 4634, 24, 26, &[25], CKPT_VER);
    nat_set(&mut v, 24, 4634, false);
    dnode(&mut v, 4635, 25, 26, &[4704], CKPT_VER);
    nat_set(&mut v, 25, 4635, false);

    // big.bin inode at 4636 — every flag knob set.
    inode_node(
        &mut v,
        4636,
        26,
        0o100644,
        8 * BLK as u64 + 5,
        1,
        0x10 | 0x20 | 0x40 | 0x100000 | 0x04, // IMMUTABLE|APPEND|NODUMP|VERITY|COMPR
        0x20, // EXTRA_ATTR
        b"big.bin",
        ROOT_NID,
        &[4700, u32::MAX - 1], // direct + COMPRESS_ADDR sentinel
        &[20, 20, 21, 32, 23],
        CKPT_VER,
        36,
        8888, // footer.next_blkaddr
    );
    {
        // compression bookkeeping inside i_extra_isize ≥36
        let b = blk(&mut v, 4636);
        w64(b, 384, 3); // compr_blocks
        b[392] = 2; // compress_algorithm
        b[393] = 4; // log_cluster_size
        w16(b, 394, 0x51); // compress_flag
        // extent cache: fofs 0 → 4700 len 1
        w32(b, 348, 0);
        w32(b, 352, 4700);
        w32(b, 356, 1);
    }
    nat_set(&mut v, 26, 4636, false);
    for (i, s) in [b"BIGDATA0".as_ref(), b"BIGDATA1", b"BIGDATA2", b"BIGDATA3", b"BIGDATA4"]
        .iter()
        .enumerate()
    {
        blk(&mut v, 4700 + i as u64)[..8].copy_from_slice(s);
    }

    // -- live/residue dentries in the root block -------------------------------
    // Fixture uses slots 0-11; ours start at 13 (12 stays an empty gap).
    // Multi-slot names occupy ceil(len/8) consecutive slots.
    root_dentry_add(&mut v, 13, b"big.bin", 26, FT_FILE, true);
    root_dentry_add(&mut v, 14, b"phantom.bin", 40, FT_FILE, false); // residue, no inode (2 slots)
    root_dentry_add(&mut v, 16, b"weird.bin", 41, FT_FILE, true); // 2 slots
    nat_set(&mut v, 41, 4640, false); // → the ino=999 dnode (non-inode)
    root_dentry_add(&mut v, 18, b"far.bin", 42, FT_FILE, true);
    nat_set(&mut v, 42, 99_999, false); // outside segment space
    root_dentry_add(&mut v, 19, b"ghost2", 57, FT_FILE, true); // free NAT entry
    root_dentry_add(&mut v, 20, b"notype", 50, FT_FILE, true);
    root_dentry_add(&mut v, 21, b"xfile", 51, FT_FILE, true);
    root_dentry_add(&mut v, 22, b"bigdir", 53, FT_DIR, true);
    root_dentry_add(&mut v, 23, b"holeblk", 56, FT_FILE, true);
    root_dentry_add(&mut v, 24, b"empty.dat", 58, FT_FILE, true);
    root_dentry_add(&mut v, 26, b"stalexattr", 59, FT_FILE, true); // 2 slots

    // notype: mode 0 → kind decided by the dentry's file_type byte.
    inode_node(&mut v, 4650, 50, 0, 3, 1, 0, 0, b"notype", ROOT_NID, &[4709], &[0; 5], CKPT_VER, 0, 0);
    nat_set(&mut v, 50, 4650, false);

    // xfile: block xattrs via i_xattr_nid → 52 → blk 4708.
    inode_node(&mut v, 4651, 51, 0o100600, 9, 1, 0x800, 0, b"xfile", ROOT_NID, &[4710], &[0; 5], CKPT_VER, 0, 0);
    {
        let b = blk(&mut v, 4651);
        w32(b, 76, 52); // i_xattr_nid
    }
    nat_set(&mut v, 51, 4651, false);
    nat_set(&mut v, 52, 4708, false);
    {
        let b = blk(&mut v, 4708);
        w32(b, 0, 0xF2F5_2011); // XATTR_MAGIC
        // index 9 "c" → fscrypt ctx v2 (28 bytes)
        b[24] = 9;
        b[25] = 1;
        w16(b, 26, 28);
        b[28] = b'c';
        b[32] = 2;
        b[33] = 4;
        b[34] = 2;
        // index 11 "v" → verity
        let e2 = 24 + 8 + 28;
        b[e2] = 11;
        b[e2 + 1] = 1;
        w16(b, e2 + 2, 4);
        b[e2 + 4] = b'v';
        // user xattr
        let e3 = e2 + 8 + 4;
        b[e3] = 1;
        b[e3 + 1] = 4;
        w16(b, e3 + 2, 3);
        b[e3 + 4..e3 + 8].copy_from_slice(b"mine");
    }
    blk(&mut v, 4710)[..9].copy_from_slice(b"x-content");

    // bigdir: two dentry blocks at 4653/4654.
    inode_node(&mut v, 4652, 53, 0o40755, 2 * BLK as u64, 2, 0, 0, b"bigdir", ROOT_NID, &[4653, 4654], &[0; 5], CKPT_VER, 0, 0);
    nat_set(&mut v, 53, 4652, false);
    dentry_block(&mut v, 4653, &[(b".", 53, 2, true), (b"..", ROOT_NID, 2, true), (b"one.txt", 54, 1, true)]);
    dentry_block(&mut v, 4654, &[(b"two.txt", 55, 1, true)]);
    inode_node(&mut v, 4655, 54, 0o100644, 4, 1, 0, 0, b"one.txt", 53, &[4712], &[0; 5], CKPT_VER, 0, 0);
    nat_set(&mut v, 54, 4655, false);
    inode_node(&mut v, 4656, 55, 0o100644, 4, 1, 0, 0, b"two.txt", 53, &[4713], &[0; 5], CKPT_VER, 0, 0);
    nat_set(&mut v, 55, 4656, false);
    blk(&mut v, 4712)[..4].copy_from_slice(b"one!");
    blk(&mut v, 4713)[..4].copy_from_slice(b"two!");

    // holeblk: extent beyond the image end → reads stop at EOF.
    inode_node(&mut v, 4657, 56, 0o100644, BLK as u64, 1, 0, 0, b"holeblk", ROOT_NID, &[60000], &[0; 5], CKPT_VER, 0, 0);
    nat_set(&mut v, 56, 4657, false);

    // empty.dat: zero-size file.
    inode_node(&mut v, 4658, 58, 0o100644, 0, 1, 0, 0, b"empty.dat", ROOT_NID, &[0], &[0; 5], CKPT_VER, 0, 0);
    nat_set(&mut v, 58, 4658, false);

    // chain2: every NAT-resolution failure arm in one chain —
    //   nid 950 → beyond the NAT (no entry), nid 20 → visited twice,
    //   nid 91 → NAT → unreadable block.
    inode_node(
        &mut v, 4660, 64, 0o100644, BLK as u64, 1, 0, 0, b"chain2", ROOT_NID,
        &[4715], &[950, 20, 20, 91, 0], CKPT_VER, 0, 0,
    );
    nat_set(&mut v, 64, 4660, false);
    nat_set(&mut v, 91, 99_999, false);
    blk(&mut v, 4715)[..4].copy_from_slice(b"c2!!");
    root_dentry_add(&mut v, 28, b"chain2", 64, FT_FILE, true);

    // chain3: i_nid → a nid with a free (zeroed) NAT entry → blk==0 arm.
    inode_node(
        &mut v, 4662, 66, 0o100644, BLK as u64, 1, 0, 0, b"chain3", ROOT_NID,
        &[4716], &[90, 0, 0, 0, 0], CKPT_VER, 0, 0,
    );
    nat_set(&mut v, 66, 4662, false);
    blk(&mut v, 4716)[..4].copy_from_slice(b"c3!!");
    root_dentry_add(&mut v, 29, b"chain3", 66, FT_FILE, true);

    // inlink: symlink with the target stored inline.
    inode_node(
        &mut v, 4663, 67, 0o120777, 18, 1, 0, 0x02, b"inlink", ROOT_NID,
        &[0], &[0; 5], CKPT_VER, 0, 0,
    );
    blk(&mut v, 4663)[364..364 + 18].copy_from_slice(b"/subdir/deep.txt  ");
    nat_set(&mut v, 67, 4663, false);
    root_dentry_add(&mut v, 30, b"inlink", 67, 7, true);

    // badddir: dir whose dentry block can't be read.
    inode_node(
        &mut v, 4664, 68, 0o40755, BLK as u64, 2, 0, 0, b"badddir", ROOT_NID,
        &[99_999], &[0; 5], CKPT_VER, 0, 0,
    );
    nat_set(&mut v, 68, 4664, false);
    root_dentry_add(&mut v, 31, b"badddir", 68, FT_DIR, true);

    // stalexattr: xattr_nid resolves only through the stale NAT copy.
    inode_node(&mut v, 4659, 59, 0o100644, 5, 1, 0, 0, b"stalexattr", ROOT_NID, &[4714], &[0; 5], CKPT_VER, 0, 0);
    {
        let b = blk(&mut v, 4659);
        w32(b, 76, 62); // i_xattr_nid
    }
    nat_set(&mut v, 59, 4659, false);
    // xattr_nid resolves to a block outside the image → read fails.
    nat_set(&mut v, 62, 99_999, false);
    blk(&mut v, 4714)[..5].copy_from_slice(b"sx!!!");

    // -- free-segment residue (seg 3, blocks 6144+) ------------------------------
    // Deleted inline-data inode → recovery_for INLINE arm.
    inode_node(&mut v, 6144, 44, 0o100644, 20, 1, 0, 0x02, b"inline-dead", ROOT_NID, &[0], &[0; 5], OLD_CKPT_VER, 0, 0);
    blk(&mut v, 6144)[364..364 + 10].copy_from_slice(b"inline-bye");
    // A dnode (nid != ino) in the free segment → skipped by the scan.
    dnode(&mut v, 6145, 45, 44, &[4705], OLD_CKPT_VER);
    // Prior version of hello's inode (cp_ver 3 < 5) → segment-scan arm.
    inode_node(&mut v, 6146, 4, 0o100644, 5, 1, 0, 0, b"hello.txt", ROOT_NID, &[5124], &[0; 5], 3, 0, 0);
    // nid 46: past-EOF extent + out-of-main extent → notes.
    inode_node(&mut v, 6147, 46, 0o100644, BLK as u64, 1, 0, 0, b"edgecase", ROOT_NID, &[4705, 4706, 100], &[0; 5], OLD_CKPT_VER, 0, 0);
    // nid 47: size 3 blocks, one extent → "extent info lost" note.
    inode_node(&mut v, 6150, 47, 0o100644, 3 * BLK as u64, 1, 0, 0, b"halfmapped", ROOT_NID, &[4707], &[0; 5], OLD_CKPT_VER, 0, 0);
    // Stale dentry block: live "." anchor + two dead names.
    dentry_block(
        &mut v,
        6148,
        &[
            (b".", ROOT_NID, 2, true),
            (b"lostname.bin", 60, 1, false),
            (b"found.bin", 61, 1, false),
            (b"oldhello.txt", 4, 1, false), // nid live → resolves current NAT
        ],
    );
    inode_node(&mut v, 6149, 61, 0o100644, 8, 1, 0, 0, b"found.bin", ROOT_NID, &[4711], &[0; 5], OLD_CKPT_VER, 0, 0);
    nat_set(&mut v, 61, 6149, true); // stale NAT only
    blk(&mut v, 4711)[..8].copy_from_slice(b"founddat");
    // nid 63: stale NAT entry pointing at a dnode → "unreadable" arm.
    nat_set(&mut v, 63, 4640, true);

    // Second orphan inode with no node block anywhere.
    {
        let o = 513 * BLK;
        w32(&mut v[o..], 4, 70); // ino slot 1
        let tail = o + BLK - 16;
        w32(&mut v[tail..], 8, 2); // entry_count
    }

    v
}

// ---- mount / checkpoint ------------------------------------------------------

#[test]
fn parser_name_and_detect() {
    assert_eq!(F2fsParser.name(), "f2fs");
    assert!(F2fsParser.detect(src(img()).as_ref()) >= DetectConfidence::High);
}

#[test]
fn mount_uses_backup_superblock() {
    let mut v = img();
    // Corrupt the primary sb magic; the backup at 0x1400 still parses.
    v[0x400..0x404].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let fs = mount(v);
    assert_eq!(fs.info().fs_type, "F2FS");
}

#[test]
fn mount_fails_when_both_superblocks_bad() {
    let mut v = img();
    v[0x400..0x404].copy_from_slice(&[0; 4]);
    v[0x1400..0x1404].copy_from_slice(&[0; 4]);
    assert!(F2fsParser.mount(src(v)).is_err());
}

#[test]
fn checkpoint_pack_fallback() {
    let mut v = img();
    // Corrupt pack 0's trailing copy → pack 1 (ver 4) wins.
    v[514 * BLK..515 * BLK].fill(0xAB);
    let fs = mount(v);
    assert_eq!(fs.info().meta.get("checkpoint_ver").map(String::as_str), Some("4"));
    // No orphan flag on the older pack → no orphan pass.
    assert_eq!(fs.info().meta.get("orphan_inodes").map(String::as_str), Some("0"));
}

#[test]
fn checkpoint_all_garbage_fails() {
    let mut v = img();
    // Zeroed checkpoint blocks → no version, no fallback candidate.
    for b in [512usize, 513, 514, 1024, 1025] {
        v[b * BLK..(b + 1) * BLK].fill(0);
    }
    assert!(F2fsParser.mount(src(v)).is_err());
}

#[test]
fn sit_block_unreadable_lenient() {
    // Image ends inside the SIT block → truncated-read arm.
    let v = img();
    let short = v[..1536 * BLK + 2048].to_vec();
    let fs = mount(short);
    let meta = &fs.info().meta;
    assert!(
        meta.values().any(|x| x.contains("SIT partially unreadable")),
        "meta: {meta:?}"
    );
    // And before the SIT block entirely → Io error arm.
    let v2 = img();
    let short2 = v2[..1536 * BLK].to_vec();
    let fs2 = mount(short2);
    assert!(fs2.info().meta.values().any(|x| x.contains("SIT partially unreadable")));
}

#[test]
fn sit_unreadable_strict_aborts_mount() {
    let v = img();
    let short = v[..1536 * BLK].to_vec();
    assert!(F2fsParser
        .mount_with(
            src(short),
            &MountOptions { strict: true, check_magic: false, include_orphans: true },
        )
        .is_err());
}

#[test]
fn sb_cp_payload_layout() {
    // cp_payload = 1 → NAT bitmap inside block 0, SIT bitmap in block 1.
    let mut v = img();
    w32(&mut v[0x400..], 1664, 1); // sb.cp_payload
    // Rechecksum the superblock (SB_CHKSUM at offset 3068).
    let crc = {
        let sb = &v[0x400..0x400 + 0xC00];
        sb_crc(&sb[..3068])
    };
    w32(&mut v[0x400..], 3068, crc);
    let _ = mount(v).info();
}

fn sb_crc(b: &[u8]) -> u32 {
    let mut c = !0xF2F5_2010u32;
    for &x in b {
        c ^= x as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

#[test]
fn checkpoint_crc_at_last_valid_offset() {
    // checksum_offset = block_size - 5 → CRC continues to the final byte.
    let mut v = img();
    for blkno in [512usize, 514, 1024, 1025] {
        let b = blk(&mut v, blkno as u64);
        w32(b, 164, (BLK - 5) as u32);
        let crc = {
            let c = sb_crc(&b[..BLK - 5]);
            sb_crc_continue(c, &b[BLK - 1..])
        };
        w32(b, BLK - 5, crc);
    }
    let fs = mount(v);
    assert_eq!(fs.info().meta.get("checkpoint_crc_ok").map(String::as_str), Some("true"));
}

fn sb_crc_continue(seed: u32, data: &[u8]) -> u32 {
    let mut c = !seed;
    for &x in data {
        c ^= x as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

// ---- live tree + extent chain -------------------------------------------------

#[test]
fn big_file_extent_chain() {
    let fs = mount(weird_image());
    let entries: Vec<_> = fs.walk().filter_map(|r| r.ok()).collect();
    let big = by_path(&entries, "/big.bin");
    // Notes from the degenerate chain: compress sentinel, nid cycle,
    // owner mismatch, inode-node-as-dnode.
    let notes: Vec<_> = big
        .meta
        .iter()
        .filter(|(k, _)| k.starts_with("recovery_note_"))
        .map(|(_, v)| v.clone())
        .collect();
    assert!(notes.iter().any(|n| n.contains("compressed")), "{notes:?}");
    assert!(notes.iter().any(|n| n.contains("visited twice")), "{notes:?}");
    // The source() accessor is part of the FileSystem contract.
    let _ = fs.source();
    assert!(notes.iter().any(|n| n.contains("mismatches inode")), "{notes:?}");
    assert!(notes.iter().any(|n| n.contains("inode node")), "{notes:?}");
    // Flag/meta arms.
    assert_eq!(big.meta.get("immutable").map(String::as_str), Some("true"));
    assert_eq!(big.meta.get("append").map(String::as_str), Some("true"));
    assert_eq!(big.meta.get("nodump").map(String::as_str), Some("true"));
    assert_eq!(big.meta.get("fsverity").map(String::as_str), Some("true"));
    assert_eq!(big.meta.get("compressed").map(String::as_str), Some("true"));
    assert_eq!(big.meta.get("extra_isize").map(String::as_str), Some("36"));
    assert_eq!(big.meta.get("fsync_next_blk").map(String::as_str), Some("8888"));
    assert_eq!(big.meta.get("ext_cache").map(String::as_str), Some("0:0x125c+1"));
    assert_eq!(big.meta.get("advise").map(String::as_str), Some("0x7"));
    assert_eq!(big.meta.get("dir_level").map(String::as_str), Some("2"));
    // First direct block still reads.
    let mut buf = vec![0u8; 8];
    let mut r = fs.read_file(big).unwrap();
    let n = r.read(&mut buf).unwrap();
    assert_eq!(&buf[..n.min(8)], b"BIGDATA0");
}

#[test]
fn live_dentry_error_paths() {
    let (_entries, errs) = walk(weird_image());
    // weird.bin → non-inode node; far.bin → out-of-range NAT block.
    assert!(errs >= 2, "expected ≥2 error records, got {errs}");
}

#[test]
fn residue_and_phantom_arms() {
    let (entries, _errs) = walk(weird_image());
    // phantom.bin: residue dentry, no inode in either NAT copy.
    let p = by_path(&entries, "/phantom.bin");
    assert!(p.is_deleted());
    assert!(
        p.meta.values().any(|x| x.contains("no node block survives")),
        "meta: {:?}",
        p.meta
    );
    // ghost2: live dentry whose nid has a free NAT entry.
    let g = by_path(&entries, "/ghost2");
    assert!(g.is_deleted());
    assert!(
        g.meta.values().any(|x| x.contains("no current NAT entry")),
        "meta: {:?}",
        g.meta
    );
}

#[test]
fn notype_and_empty_entries() {
    let (entries, _) = walk(weird_image());
    let n = by_path(&entries, "/notype");
    assert_eq!(n.kind, EntryKind::File); // from dentry file_type, not mode
    let e = by_path(&entries, "/empty.dat");
    assert_eq!(e.size, 0);
}

#[test]
fn xattr_block_and_stale_fallback() {
    let (entries, _) = walk(weird_image());
    let x = by_path(&entries, "/xfile");
    let m = &x.meta;
    assert!(
        m.get("fscrypt_context").map(String::as_str).unwrap_or("").contains("v2"),
        "meta: {m:?}"
    );
    assert_eq!(m.get("fsverity_xattr").map(String::as_str), Some("true"));
    assert!(m.get("xattrs").is_some());
    // stalexattr's xattr block is unreadable → no xattrs meta, no panic.
    let s = by_path(&entries, "/stalexattr");
    assert!(!s.meta.contains_key("xattrs"), "meta: {:?}", s.meta);
    assert_eq!(s.kind, EntryKind::File);
}

#[test]
fn multidir_reads_both_blocks() {
    let (entries, _) = walk(weird_image());
    by_path(&entries, "/bigdir/one.txt");
    by_path(&entries, "/bigdir/two.txt");
}

#[test]
fn hole_block_read_stops_at_eof() {
    let fs = mount(weird_image());
    let entries: Vec<_> = fs.walk().filter_map(|r| r.ok()).collect();
    let h = by_path(&entries, "/holeblk");
    let mut buf = Vec::new();
    fs.read_file(h).unwrap().read_to_end(&mut buf).unwrap();
    // Extent points past the image → zero bytes (or the OS returns early).
    assert!(buf.len() < BLK);
}

#[test]
fn extent_chain_error_arms() {
    let (entries, errs) = walk(weird_image());
    let c2 = by_path(&entries, "/chain2");
    let notes: Vec<_> = c2
        .meta
        .iter()
        .filter(|(k, _)| k.starts_with("recovery_note_"))
        .map(|(_, v)| v.clone())
        .collect();
    assert!(notes.iter().any(|n| n.contains("visited twice")), "{notes:?}");
    let _ = by_path(&entries, "/chain3");
    let _ = by_path(&entries, "/badddir");
    // inlink: inline symlink target decodes.
    let l = by_path(&entries, "/inlink");
    assert_eq!(l.kind, EntryKind::Symlink);
    assert!(
        l.meta
            .get("symlink_target")
            .map(String::as_str)
            .unwrap_or("")
            .starts_with("/subdir/deep.txt"),
        "meta: {:?}",
        l.meta
    );
    assert!(errs >= 1); // badddir's dentry block is unreadable
}

#[test]
fn read_dir_entry_fails() {
    let fs = mount(weird_image());
    let entries: Vec<_> = fs.walk().filter_map(|r| r.ok()).collect();
    let d = by_path(&entries, "/bigdir");
    assert!(fs.read_file(d).is_err());
}

// ---- free-segment / stale-NAT residue -----------------------------------------

#[test]
fn free_segment_residue_arms() {
    let (entries, _) = walk(weird_image());

    // Deleted inline-data inode → Intact through the INLINE arm.
    let il = by_id(&entries, 44);
    assert!(il.is_deleted());
    assert!(
        matches!(il.status, FsEntryStatus::Deleted { recovery: RecoveryState::Intact }),
        "status {:?}",
        il.status
    );

    // Prior version of hello's inode found by the segment scan.
    let pv = entries
        .iter()
        .find(|e| e.name == "nid_4_v3")
        .expect("prior-version entry");
    assert_eq!(pv.meta.get("prior_version").map(String::as_str), Some("cp_ver 3"));
    assert!(pv.meta.contains_key("seg_mtime"));

    // found.bin: deleted nid whose node survives via the stale NAT copy.
    let f = entries
        .iter()
        .find(|e| e.name == "found.bin")
        .expect("found.bin residue");
    assert!(f.is_deleted());
    assert_eq!(
        f.meta.get("recovery_source").map(String::as_str),
        Some("stale-nat")
    );
    // oldhello.txt: residue name whose nid is live → resolved via the
    // current NAT inside the free-segment scan.
    let oh = entries
        .iter()
        .find(|e| e.name == "oldhello.txt")
        .expect("oldhello residue");
    assert!(oh.is_deleted());
    assert_eq!(
        oh.meta.get("recovery_source").map(String::as_str),
        Some("stale-dentry-block")
    );
    assert!(oh.meta.contains_key("stale_dentry_block"));

    // lostname.bin: name-only residue (no node anywhere).
    let l = entries
        .iter()
        .find(|e| e.name == "lostname.bin")
        .expect("lostname residue");
    assert!(l.is_deleted());
    assert!(l.meta.values().any(|x| x.contains("name residue")));

    // nid 63: stale NAT points at a dnode → metadata-only entry.
    let n63 = by_id(&entries, 63);
    assert!(
        n63.meta.values().any(|x| x.contains("node block unreadable")),
        "meta: {:?}",
        n63.meta
    );
}

#[test]
fn recovery_note_arms() {
    let (entries, _) = walk(weird_image());
    // nid 46: beyond-EOF + out-of-main extents.
    let e46 = by_id(&entries, 46);
    let notes46: Vec<_> = e46
        .meta
        .values()
        .filter(|v| v.contains("beyond EOF") || v.contains("SIT state unknown"))
        .collect();
    assert!(notes46.len() >= 2, "meta: {:?}", e46.meta);
    // nid 47: lost extent map → "extent info lost".
    let e47 = by_id(&entries, 47);
    assert!(
        e47.meta.values().any(|v| v.contains("extent info lost")),
        "meta: {:?}",
        e47.meta
    );
}

#[test]
fn second_orphan_without_node() {
    let (entries, _) = walk(weird_image());
    let o = by_id(&entries, 70);
    assert_eq!(o.meta.get("orphan").map(String::as_str), Some("true"));
    assert!(o.meta.values().any(|x| x.contains("no node block in either NAT copy")));
}

// ---- modes / flags -----------------------------------------------------------

#[test]
fn strict_walk_aborts_on_first_error() {
    let opts = MountOptions { strict: true, check_magic: true, include_orphans: true };
    let mut count = 0;
    let mut saw_err = false;
    for r in mount_opts(weird_image(), opts).walk() {
        count += 1;
        if r.is_err() {
            saw_err = true;
        }
    }
    assert!(saw_err);
    // Strict aborts at the first error — far fewer items than lenient.
    let (lenient, _) = walk(weird_image());
    assert!(count < lenient.len() + 5, "count {count}");
}

#[test]
fn walk_without_orphans() {
    let opts = MountOptions { strict: false, check_magic: true, include_orphans: false };
    let entries: Vec<_> = mount_opts(weird_image(), opts)
        .walk()
        .filter_map(|r| r.ok())
        .collect();
    assert!(entries.iter().all(|e| !e.path.starts_with("/$ORPHANED")));
    assert!(entries.iter().all(|e| e.meta.get("orphan") != Some(&"true".to_string())));
    // Live tree still complete.
    by_path(&entries, "/big.bin");
}

#[test]
fn packed_ssa_hides_summary_notes() {
    let mut v = weird_image();
    // Set PACKED_SSA in the superblock feature word + rechecksum.
    let feat_off = 0x400 + 2180;
    let cur = u32::from_le_bytes(v[feat_off..feat_off + 4].try_into().unwrap());
    w32(&mut v[feat_off..], 0, cur | 0x1_0000);
    let crc = sb_crc(&v[0x400..0x400 + 3068]);
    w32(&mut v[0x400..], 3068, crc);
    let (entries, _) = walk(v);
    // partial.bin (nid 11): "reallocated to live data" without ssa detail.
    let p = by_id(&entries, 11);
    assert!(
        p.meta.values().any(|x| x.contains("reallocated to live data")),
        "meta: {:?}",
        p.meta
    );
}

#[test]
fn corrupt_root_nat_fails_gracefully() {
    let mut v = img();
    nat_set(&mut v, ROOT_NID, 99_999, false);
    let (entries, errs) = walk(v);
    assert!(errs >= 1);
    // No live tree — but residue passes still emit what they find.
    assert!(entries.iter().all(|e| e.path != "/"));
}
