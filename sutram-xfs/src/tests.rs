//! Unit tests — focused on explicit big-endian decoding correctness on
//! little-endian hosts: every assertion feeds BE byte patterns and checks
//! the decoded value, plus one deliberately-LE-encoded negative case.

use crate::crc;
use crate::extent::Extent;
use crate::inode::{Inode, DINODE_MAGIC};
use crate::sb::Superblock;

fn be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}
fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}
fn be64(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

#[test]
fn crc32c_matches_catalog_vector() {
    // Standard CRC-32C("123456789") = 0xE3069283.  XFS stores
    // ~crc32c(!0, buf) — i.e. the standard CRC-32C value.
    let raw = crc::crc32c(crc::CRC_SEED, b"123456789");
    assert_eq!(!raw, 0xE306_9283);
}

#[test]
fn crc_roundtrip_via_field() {
    let mut buf = vec![0xABu8; 512];
    buf[10..14].copy_from_slice(&be32(0xDEAD_BEEF));
    let c = crc::xfs_cksum(&buf, 100).unwrap();
    buf[100..104].copy_from_slice(&c.to_le_bytes());
    let stored = u32::from_le_bytes([buf[100], buf[101], buf[102], buf[103]]);
    assert_eq!(crc::verify(&buf, 100, stored), Some(true));
    // flip a bit → must fail
    buf[300] ^= 0x01;
    assert_eq!(crc::verify(&buf, 100, stored), Some(false));
}

#[test]
fn extent_decode_is_big_endian() {
    // fileoff=3, fsb=0x12345, len=2, unwritten=1
    let flag = 1u64 << 63;
    let fileoff = 3u64;
    let fsb = 0x1_2345u64;
    let len = 2u64;
    let l0 = flag | (fileoff << 9) | (fsb >> 43);
    let l1 = (fsb << 21) | len;
    let mut rec = [0u8; 16];
    rec[..8].copy_from_slice(&be64(l0));
    rec[8..].copy_from_slice(&be64(l1));
    let e = Extent::decode(&rec).unwrap();
    assert!(e.unwritten);
    assert_eq!(e.fileoff, fileoff);
    assert_eq!(e.fsb, fsb);
    assert_eq!(e.len as u64, len);
    // Same bit pattern written little-endian must NOT decode the same.
    let mut bad = [0u8; 16];
    bad[..8].copy_from_slice(&l0.to_le_bytes());
    bad[8..].copy_from_slice(&l1.to_le_bytes());
    let e2 = Extent::decode(&bad).unwrap();
    assert_ne!(e2.fsb, fsb);
}

#[test]
fn inode_fields_big_endian() {
    // Hand-build a minimal v3 inode core (256 B).
    let mut ino = vec![0u8; 256];
    ino[0..2].copy_from_slice(&be16(DINODE_MAGIC));
    ino[2..4].copy_from_slice(&be16(0o100644)); // regular, 0644
    ino[4] = 3; // version
    ino[5] = 2; // EXTENTS
    ino[8..12].copy_from_slice(&be32(1000)); // uid
    ino[12..16].copy_from_slice(&be32(100)); // gid
    ino[16..20].copy_from_slice(&be32(1)); // nlink
    // atime = 1700000000.5s
    ino[32..40].copy_from_slice(&be64((1700000000u64 << 32) | 500_000_000));
    ino[56..64].copy_from_slice(&be64(12345)); // size
    ino[76..80].copy_from_slice(&be32(1)); // nextents
    ino[152..160].copy_from_slice(&be64(0x0102_0304_0506_0708)); // di_ino
    let sb = test_sb();
    let i = Inode::parse(ino, 0x8000, 0x0102_0304_0506_0708, &sb).unwrap();
    assert_eq!(i.mode, 0o100644);
    assert_eq!(i.uid, 1000);
    assert_eq!(i.size, 12345);
    assert_eq!(i.ino, 0x0102_0304_0506_0708);
    assert_eq!(i.atime, 1700000000 * 1_000_000_000 + 500_000_000);
}

#[test]
fn inode_rejects_le_encoded_magic() {
    let mut ino = vec![0u8; 256];
    // 'IN' written little-endian — must be rejected.
    ino[0..2].copy_from_slice(&DINODE_MAGIC.to_le_bytes());
    let sb = test_sb();
    assert!(Inode::parse(ino, 0, 1, &sb).is_err());
}

fn test_sb() -> Superblock {
    // Minimal synthetic superblock buffer with sane geometry.
    let mut b = vec![0u8; 512];
    b[0..4].copy_from_slice(&be32(0x5846_5342)); // XFSB
    b[4..8].copy_from_slice(&be32(4096));
    b[8..16].copy_from_slice(&be64(128));
    b[84..88].copy_from_slice(&be32(64));
    b[88..92].copy_from_slice(&be32(2));
    b[100..102].copy_from_slice(&be16(0xB4E5)); // versionnum: v5 + feature bits
    b[102..104].copy_from_slice(&be16(512));
    b[104..106].copy_from_slice(&be16(256));
    b[106..108].copy_from_slice(&be16(16));
    b[120] = 12; // blocklog
    b[121] = 9;
    b[122] = 8;
    b[123] = 4; // inopblog
    b[124] = 6; // agblklog
    b[56..64].copy_from_slice(&be64(128)); // rootino
    b[216..220].copy_from_slice(&be32(1)); // incompat = FTYPE
    Superblock::parse_buf(&b, 0).unwrap()
}

#[test]
fn superblock_geometry_be() {
    let sb = test_sb();
    assert_eq!(sb.version, 5);
    assert_eq!(sb.blocksize, 4096);
    assert_eq!(sb.dblocks, 128);
    assert_eq!(sb.agblocks, 64);
    assert_eq!(sb.agcount, 2);
    // ino→byte mapping: ino 128 → ag0, agbno 8, slot 0 → 8*4096
    assert_eq!(sb.ino_agno(128), 0);
    assert_eq!(sb.ino_agbno(128), 8);
    assert_eq!(sb.ino_off(128), 8 * 4096);
    // AG1 inode: (1<<10)|128 = 1152 → ag1 agbno 8 → 64*4096 + 8*4096
    assert_eq!(sb.ino_agno(1152), 1);
    assert_eq!(sb.ino_off(1152), (64 + 8) * 4096);
}

#[test]
fn superblock_rejects_garbage() {
    let mut b = vec![0u8; 512];
    b[0..4].copy_from_slice(&be32(0x5846_5342));
    // everything else zero → bad version/blocksize
    assert!(Superblock::parse_buf(&b, 0).is_err());
    // wrong magic
    b[0..4].copy_from_slice(&be32(0xDEAD_BEEF));
    assert!(Superblock::parse_buf(&b, 0).is_err());
}

#[test]
fn attr_shortform_decodes() {
    // xfs_attr_sf_hdr = {totsize u16, count u8} then entries
    // {namelen u8, valuelen u8, flags u8, name[], value[]}.
    let mut b = Vec::new();
    b.extend_from_slice(&0u16.to_be_bytes()); // totsize (unused)
    b.push(2); // count
    // entry 0: user.lang = en_US
    b.extend_from_slice(&[4, 5, 0]);
    b.extend_from_slice(b"lang");
    b.extend_from_slice(b"en_US");
    // entry 1: trusted.key = 0xAA (ROOT flag)
    b.extend_from_slice(&[3, 1, 2]);
    b.extend_from_slice(b"key");
    b.push(0xAA);
    let attrs = crate::attr::parse_local(&b);
    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs[0].name, "user.lang");
    assert_eq!(attrs[0].value.as_deref(), Some(b"en_US".as_slice()));
    assert_eq!(attrs[1].name, "trusted.key");
    assert_eq!(attrs[1].value.as_deref(), Some(&[0xAA][..]));
}

#[test]
fn remote_attr_reads_xarm_blocks() {
    // v5 remote value: each block carries a 56-byte 'XARM' header; the
    // value spans block0's payload (4040 B) + 4 bytes of block1's.
    let mut img = vec![0u8; 2 * 4096];
    img[0..4].copy_from_slice(&0x5841_524Du32.to_be_bytes()); // XARM
    img[56..4096].fill(b'A');
    img[4096..4100].copy_from_slice(&0x5841_524Du32.to_be_bytes());
    img[4096 + 56..4096 + 60].copy_from_slice(b"done");
    let sb = test_sb();
    let e = crate::extent::Extent {
        fileoff: 0,
        fsb: 0,
        len: 2,
        unwritten: false,
    };
    let v = crate::attr::remote_read(&img, &sb, &[e], 0, 4044).unwrap();
    assert_eq!(v.len(), 4044);
    assert!(v[..4040].iter().all(|&b| b == b'A'));
    assert_eq!(&v[4040..], b"done");
}

#[test]
fn attr_v2_leaf_layout() {
    // v2 attr leaf: xfs_da_blkinfo = 12 B (magic u16 @8), leaf hdr =
    // 32 B (count @12, freemap[3] @20), entries @32 — 8 B each.
    let mut blk = vec![0u8; 4096];
    blk[8..10].copy_from_slice(&0xFBEEu16.to_be_bytes()); // XFS_ATTR_LEAF_MAGIC
    blk[12..14].copy_from_slice(&1u16.to_be_bytes()); // count = 1
    // entry 0 @32: hashval, nameidx=100, flags=LOCAL(1), pad.
    blk[36..38].copy_from_slice(&100u16.to_be_bytes());
    blk[38] = 1;
    // name block @100: {valuelen u16, namelen u8, name, value}.
    blk[100..102].copy_from_slice(&5u16.to_be_bytes());
    blk[102] = 4;
    blk[103..107].copy_from_slice(b"lang");
    blk[107..112].copy_from_slice(b"en_US");
    let sb = test_sb();
    let e = crate::extent::Extent {
        fileoff: 0,
        fsb: 0,
        len: 1,
        unwritten: false,
    };
    let attrs = crate::attr::collect_leaf(&blk, &sb, &[e]).unwrap();
    assert_eq!(attrs.len(), 1);
    assert_eq!(attrs[0].name, "user.lang");
    assert_eq!(attrs[0].value.as_deref(), Some(b"en_US".as_slice()));
}

#[test]
fn attr3_leaf_crc_is_big_endian() {
    // dir3/da3-style blk hdrs store their crc field big-endian —
    // unlike sb/inode/btree crcs. Build a v3 attr leaf with a valid
    // BE crc at offset 12; collect_leaf must not report a CRC error.
    let mut blk = vec![0u8; 4096];
    blk[8..10].copy_from_slice(&0x3BEEu16.to_be_bytes()); // ATTR3_LEAF_MAGIC
    blk[56..58].copy_from_slice(&0u16.to_be_bytes()); // count = 0
    // crc over the block with bytes 12..16 zeroed, stored BE.
    let c = crc::xfs_cksum(&blk, 12).unwrap();
    blk[12..16].copy_from_slice(&c.to_be_bytes());
    let sb = test_sb();
    let e = crate::extent::Extent {
        fileoff: 0,
        fsb: 0,
        len: 1,
        unwritten: false,
    };
    let attrs = crate::attr::collect_leaf(&blk, &sb, &[e]).unwrap();
    assert!(attrs.is_empty());
    // And the same block with the crc stored little-endian must FAIL —
    // guards against regressing to a uniform little-endian crc read.
    let mut bad = blk.clone();
    bad[12..16].copy_from_slice(&c.to_le_bytes());
    assert!(crate::attr::collect_leaf(&bad, &sb, &[e]).is_err());
}

// ---------------------------------------------------------------------------
// Coverage sweep: decoder error arms and edge cases. These use the same
// hand-rolled BE writers as the tests above — corrupt fixtures are made by
// writing bad bytes, never by mutating parser state.
// ---------------------------------------------------------------------------

use crate::btree;
use crate::dir;
use crate::extent::collect_extents;
use crate::inode::{FMT_BTREE, FMT_EXTENTS};
use crate::sb::{Agf, Agi, AGF_MAGIC, AGI_MAGIC};

/// A v4-featureset superblock (no ftype, no CRC, no finobt) — exercises
/// the pre-v5 decode paths.
fn test_sb_v4() -> Superblock {
    let mut b = vec![0u8; 512];
    b[0..4].copy_from_slice(&be32(0x5846_5342));
    b[4..8].copy_from_slice(&be32(4096));
    b[8..16].copy_from_slice(&be64(128));
    b[84..88].copy_from_slice(&be32(64));
    b[88..92].copy_from_slice(&be32(2));
    b[100..102].copy_from_slice(&be16(0xB4B4)); // version 4
    b[102..104].copy_from_slice(&be16(512));
    b[104..106].copy_from_slice(&be16(256));
    b[106..108].copy_from_slice(&be16(16));
    b[120] = 12;
    b[121] = 9;
    b[122] = 8;
    b[123] = 4;
    b[124] = 6;
    b[56..64].copy_from_slice(&be64(128));
    Superblock::parse_buf(&b, 0).unwrap()
}

fn w16be(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&be16(v));
}
fn w32be(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&be32(v));
}
fn w64be(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&be64(v));
}

// ---- extent.rs --------------------------------------------------------

#[test]
fn extent_decode_short_input() {
    assert!(Extent::decode(&[0u8; 15]).is_none());
    assert!(Extent::decode(&[]).is_none());
}

#[test]
fn extent_accessors() {
    let sb = test_sb();
    let e = Extent {
        fileoff: 2,
        fsb: 5,
        len: 3,
        unwritten: true,
    };
    assert_eq!(e.disk_off(&sb), 5 * 4096);
    assert_eq!(e.disk_len(&sb), 3 * 4096);
    assert_eq!(e.file_off_bytes(&sb), 2 * 4096);
}

#[test]
fn collect_extents_local_and_dev_are_empty() {
    let sb = test_sb();
    let src: &[u8] = &[0u8; 64];
    assert!(collect_extents(&src, &sb, &[0; 32], 1, 0).unwrap().is_empty());
    assert!(collect_extents(&src, &sb, &[0; 32], 0, 0).unwrap().is_empty());
    assert!(collect_extents(&src, &sb, &[0; 32], 4, 0).unwrap().is_empty());
}

#[test]
fn collect_extents_bounds_and_null_skip() {
    let sb = test_sb();
    let src: &[u8] = &[0u8; 64];
    // nextents claims more than the fork can hold → clamped to capacity.
    let mut fork = vec![0u8; 32];
    let mkrec = |fileoff: u64, fsb: u64, len: u32| {
        let mut r = [0u8; 16];
        r[..8].copy_from_slice(&be64(fileoff << 9));
        r[8..].copy_from_slice(&be64((fsb << 21) | len as u64));
        r
    };
    fork[..16].copy_from_slice(&mkrec(0, 24, 1));
    fork[16..32].copy_from_slice(&mkrec(1, 30, 2));
    let exts = collect_extents(&src, &sb, &fork, FMT_EXTENTS, 9).unwrap();
    assert_eq!(exts.len(), 2);
    assert_eq!(exts[0].fsb, 24);
    assert_eq!(exts[1].fileoff, 1);
    // Zero-length records are still decoded (callers filter).
    let exts = collect_extents(&src, &sb, &fork, FMT_EXTENTS, 1).unwrap();
    assert_eq!(exts.len(), 1);
}

#[test]
fn bmdr_root_error_arms() {
    let sb = test_sb();
    let src: &[u8] = &[0u8; 64];
    // Fork too short for the bmdr header.
    assert!(collect_extents(&src, &sb, &[0u8; 3], FMT_BTREE, 0).is_err());
    // level > MAX_BMBT_DEPTH.
    let mut fork = vec![0u8; 80];
    w16be(&mut fork, 0, 99);
    assert!(collect_extents(&src, &sb, &fork, FMT_BTREE, 0).is_err());
    // numrecs exceeds fork capacity.
    w16be(&mut fork, 0, 1);
    w16be(&mut fork, 2, 0xFFFF);
    assert!(collect_extents(&src, &sb, &fork, FMT_BTREE, 0).is_err());
    // level 0 → records decoded inline from the root.
    w16be(&mut fork, 0, 0);
    w16be(&mut fork, 2, 1);
    let rec = {
        let mut r = [0u8; 16];
        r[..8].copy_from_slice(&be64(0));
        r[8..].copy_from_slice(&be64((7u64 << 21) | 2));
        r
    };
    fork[4..20].copy_from_slice(&rec);
    let exts = collect_extents(&src, &sb, &fork, FMT_BTREE, 0).unwrap();
    assert_eq!(exts.len(), 1);
    assert_eq!(exts[0].fsb, 7);
    assert_eq!(exts[0].len, 2);
    // level 1 node whose only pointer is NULLFSBLOCK → no blocks walked.
    let mut fork2 = vec![0u8; 80];
    w16be(&mut fork2, 0, 1);
    w16be(&mut fork2, 2, 1);
    let maxrecs = (fork2.len() - 4) / 16;
    w64be(&mut fork2, 4, 0);
    w64be(&mut fork2, 4 + maxrecs * 8, u64::MAX);
    assert!(collect_extents(&src, &sb, &fork2, FMT_BTREE, 0)
        .unwrap()
        .is_empty());
}

#[test]
fn bmbt_block_error_arms() {
    let sb = test_sb();
    // Root: level 1, one ptr → fsb 0.
    let mut fork = vec![0u8; 80];
    w16be(&mut fork, 0, 1);
    w16be(&mut fork, 2, 1);
    let maxrecs = (fork.len() - 4) / 16;
    w64be(&mut fork, 4 + maxrecs * 8, 0);

    // fsb out of geometry (≥ dblocks) → skipped silently.
    let mut fork_oob = fork.clone();
    w64be(&mut fork_oob, 4 + maxrecs * 8, 0xFFFF_FFFF);
    let src: &[u8] = &[0u8; 64];
    assert!(collect_extents(&src, &sb, &fork_oob, FMT_BTREE, 0)
        .unwrap()
        .is_empty());

    // Block truncated (image smaller than the pointed block).
    assert!(collect_extents(&src, &sb, &fork, FMT_BTREE, 0).is_err());

    // Bad block magic.
    let mut img = vec![0u8; 4096];
    assert!(collect_extents(&img, &sb, &fork, FMT_BTREE, 0).is_err());

    // v4 magic accepted (BMAP), level 0, one record.
    w32be(&mut img, 0, 0x424D_4150);
    w16be(&mut img, 4, 0);
    w16be(&mut img, 6, 1);
    img[24..40].copy_from_slice(&{
        let mut r = [0u8; 16];
        r[..8].copy_from_slice(&be64(0));
        r[8..].copy_from_slice(&be64((9u64 << 21) | 1));
        r
    });
    let exts = collect_extents(&img, &sb, &fork, FMT_BTREE, 0).unwrap();
    assert_eq!(exts.len(), 1);
    assert_eq!(exts[0].fsb, 9);

    // Leaf claiming more records than capacity → corrupt.
    w16be(&mut img, 6, 0xFFFF);
    assert!(collect_extents(&img, &sb, &fork, FMT_BTREE, 0).is_err());

    // Level above the expected one → corrupt.
    w16be(&mut img, 4, 5);
    w16be(&mut img, 6, 0);
    assert!(collect_extents(&img, &sb, &fork, FMT_BTREE, 0).is_err());
}

#[test]
fn bmbt_v5_crc_checked() {
    let sb = test_sb(); // v5 → has_crc
    let mut fork = vec![0u8; 80];
    w16be(&mut fork, 0, 1);
    w16be(&mut fork, 2, 1);
    let maxrecs = (fork.len() - 4) / 16;
    w64be(&mut fork, 4 + maxrecs * 8, 0);

    let mut img = vec![0u8; 4096];
    w32be(&mut img, 0, 0x424D_4133); // BMA3
    w16be(&mut img, 4, 0);
    w16be(&mut img, 6, 1);
    img[72..88].copy_from_slice(&{
        let mut r = [0u8; 16];
        r[8..].copy_from_slice(&be64((9u64 << 21) | 1));
        r
    });
    // No/invalid CRC → error on a v5 fs.
    assert!(collect_extents(&img, &sb, &fork, FMT_BTREE, 0).is_err());
    // Fix the CRC → decodes.
    let c = crc::xfs_cksum(&img, 64).unwrap();
    img[64..68].copy_from_slice(&c.to_le_bytes());
    let exts = collect_extents(&img, &sb, &fork, FMT_BTREE, 0).unwrap();
    assert_eq!(exts.len(), 1);
}

// ---- sb.rs ------------------------------------------------------------

fn sb_buf() -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[0..4].copy_from_slice(&be32(0x5846_5342));
    b[4..8].copy_from_slice(&be32(4096));
    b[8..16].copy_from_slice(&be64(128));
    b[56..64].copy_from_slice(&be64(128));
    b[84..88].copy_from_slice(&be32(64));
    b[88..92].copy_from_slice(&be32(2));
    b[100..102].copy_from_slice(&be16(0xB4B5));
    b[102..104].copy_from_slice(&be16(512));
    b[104..106].copy_from_slice(&be16(256));
    b[106..108].copy_from_slice(&be16(16));
    b[120] = 12;
    b[121] = 9;
    b[122] = 8;
    b[123] = 4;
    b[124] = 6;
    b
}

#[test]
fn superblock_validation_arms() {
    // version neither 4 nor 5.
    let mut b = sb_buf();
    b[100..102].copy_from_slice(&be16(0xB4B3));
    assert!(Superblock::parse_buf(&b, 0).is_err());
    // blocksize not power-of-two / out of range.
    let mut b = sb_buf();
    b[4..8].copy_from_slice(&be32(1000));
    assert!(Superblock::parse_buf(&b, 0).is_err());
    let mut b = sb_buf();
    b[4..8].copy_from_slice(&be32(128));
    assert!(Superblock::parse_buf(&b, 0).is_err());
    // sectsize bad / larger than blocksize.
    let mut b = sb_buf();
    b[102..104].copy_from_slice(&be16(8192));
    assert!(Superblock::parse_buf(&b, 0).is_err());
    let mut b = sb_buf();
    b[102..104].copy_from_slice(&be16(100));
    assert!(Superblock::parse_buf(&b, 0).is_err());
    // inodesize bad.
    let mut b = sb_buf();
    b[104..106].copy_from_slice(&be16(128));
    assert!(Superblock::parse_buf(&b, 0).is_err());
    // inopblock zero / non-power-of-two.
    let mut b = sb_buf();
    b[106..108].copy_from_slice(&be16(0));
    assert!(Superblock::parse_buf(&b, 0).is_err());
    let mut b = sb_buf();
    b[106..108].copy_from_slice(&be16(3));
    assert!(Superblock::parse_buf(&b, 0).is_err());
    // impossible geometry: dblocks/agblocks/agcount zero.
    let mut b = sb_buf();
    b[8..16].copy_from_slice(&be64(0));
    assert!(Superblock::parse_buf(&b, 0).is_err());
    let mut b = sb_buf();
    b[84..88].copy_from_slice(&be32(0));
    assert!(Superblock::parse_buf(&b, 0).is_err());
    // blocklog inconsistent.
    let mut b = sb_buf();
    b[120] = 9;
    assert!(Superblock::parse_buf(&b, 0).is_err());
    // inopblog inconsistent.
    let mut b = sb_buf();
    b[123] = 5;
    assert!(Superblock::parse_buf(&b, 0).is_err());
    // agblklog too small for agblocks.
    let mut b = sb_buf();
    b[124] = 3;
    assert!(Superblock::parse_buf(&b, 0).is_err());
    // inopblock != blocksize/inodesize.
    let mut b = sb_buf();
    b[106..108].copy_from_slice(&be16(8));
    b[123] = 3;
    assert!(Superblock::parse_buf(&b, 0).is_err());
    // (agcount-1)*agblocks >= dblocks → too many AGs for the device.
    let mut b = sb_buf();
    b[88..92].copy_from_slice(&be32(3));
    assert!(Superblock::parse_buf(&b, 0).is_err());
}

#[test]
fn superblock_validate_source_arms() {
    // Image smaller than one block → truncated.
    let b = sb_buf();
    let short = vec![0u8; 512];
    assert!(Superblock::parse(&short.as_slice()).is_err());
    // rootino out of geometry.
    let mut b2 = sb_buf();
    b2[56..64].copy_from_slice(&be64(0xFFFF_FFFF));
    assert!(Superblock::parse(&b2.as_slice()).is_err());
    // sectlog inconsistent with sectsize.
    let mut b3 = sb_buf();
    b3[121] = 10;
    assert!(Superblock::parse(&b3.as_slice()).is_err());
    let _ = b;
}

#[test]
fn detect_score_tiers() {
    use sutram_fs::DetectConfidence;
    // Empty / tiny source → None.
    let empty: &[u8] = &[];
    assert_eq!(Superblock::detect(&empty), DetectConfidence::None);
    let tiny = vec![0u8; 100];
    assert_eq!(Superblock::detect(&tiny.as_slice()), DetectConfidence::None);
    // Magic only, no plausible fields → Low.
    let mut b = vec![0u8; 512];
    b[0..4].copy_from_slice(&be32(0x5846_5342));
    assert_eq!(Superblock::detect(&b.as_slice()), DetectConfidence::Low);
    // v4 sb without the CRC bonus → still confident.
    let b4 = {
        let mut v = sb_buf();
        v[100..102].copy_from_slice(&be16(0xB4B4));
        v
    };
    assert!(Superblock::detect(&b4.as_slice()) >= DetectConfidence::High);
}

#[test]
fn agf_parse_arms() {
    let mut b = vec![0u8; 512];
    // truncated
    assert!(Agf::parse(&b[..100], 0, false).is_err());
    // bad magic
    assert!(Agf::parse(&b, 0, false).is_err());
    // bad version
    w32be(&mut b, 0, AGF_MAGIC);
    assert!(Agf::parse(&b, 0, false).is_err());
    // valid
    w32be(&mut b, 4, 1);
    let agf = Agf::parse(&b, 0, false).unwrap();
    assert_eq!(agf.crc_ok, None);
    // crc requested but wrong → Some(false)
    let agf2 = Agf::parse(&b, 0, true).unwrap();
    assert_eq!(agf2.crc_ok, Some(false));
}

#[test]
fn agi_parse_arms() {
    let mut b = vec![0u8; 512];
    assert!(Agi::parse(&b[..100], 0, false).is_err());
    assert!(Agi::parse(&b, 0, false).is_err());
    w32be(&mut b, 0, AGI_MAGIC);
    assert!(Agi::parse(&b, 0, false).is_err());
    w32be(&mut b, 4, 1);
    let agi = Agi::parse(&b, 0, false).unwrap();
    assert_eq!(agi.unlinked.len(), 64);
    assert_eq!(agi.crc_ok, None);
    let agi2 = Agi::parse(&b, 0, true).unwrap();
    assert_eq!(agi2.crc_ok, Some(false));
}

// ---- inode.rs ---------------------------------------------------------

#[test]
fn inode_v12_core_decodes() {
    // v1 inode: 100-byte core, nlink from di_onlink, no di_ino/crtime.
    let mut ino = vec![0u8; 256];
    ino[0..2].copy_from_slice(&be16(DINODE_MAGIC));
    ino[2..4].copy_from_slice(&be16(0o100644));
    ino[4] = 1; // version 1
    ino[5] = 2;
    ino[6..8].copy_from_slice(&be16(3)); // onlink
    let sb = test_sb();
    let i = Inode::parse(ino, 0, 42, &sb).unwrap();
    assert_eq!(i.nlink, 3);
    assert_eq!(i.ino, 42); // hint used — v1 carries no di_ino
    assert_eq!(i.crtime, None);
    assert_eq!(i.crc_ok, None);
    assert_eq!(i.core, 100);
    // v2 inode: nlink read from the u32 di_nlink field at offset 16.
    let mut ino2 = vec![0u8; 256];
    ino2[0..2].copy_from_slice(&be16(DINODE_MAGIC));
    ino2[4] = 2;
    ino2[16..20].copy_from_slice(&be32(7));
    let i2 = Inode::parse(ino2, 0, 42, &sb).unwrap();
    assert_eq!(i2.nlink, 7);
}

#[test]
fn inode_truncation_arms() {
    let sb = test_sb();
    assert!(Inode::parse(vec![0u8; 50], 0, 1, &sb).is_err());
    // v3 inode truncated below the 176-byte core.
    let mut ino = vec![0u8; 120];
    ino[0..2].copy_from_slice(&be16(DINODE_MAGIC));
    ino[4] = 3;
    assert!(Inode::parse(ino, 0, 1, &sb).is_err());
}

#[test]
fn inode_nsec_clamped_and_bigtime() {
    let sb = test_sb();
    let mut ino = vec![0u8; 256];
    ino[0..2].copy_from_slice(&be16(DINODE_MAGIC));
    ino[4] = 3;
    // nsec field out of range → clamped to whole seconds.
    ino[32..40].copy_from_slice(&be64((1_700_000_000u64 << 32) | 4_000_000_000));
    let i = Inode::parse(ino.clone(), 0, 1, &sb).unwrap();
    assert_eq!(i.atime, 1_700_000_000 * 1_000_000_000);
    // bigtime inode on a non-bigtime sb → legacy decode.
    assert!(!i.bigtime);
}

#[test]
fn inode_has_residue_matrix() {
    let sb = test_sb();
    let mk = |mode: u16, size: u64, nextents: u32| {
        let mut ino = vec![0u8; 256];
        ino[0..2].copy_from_slice(&be16(DINODE_MAGIC));
        ino[2..4].copy_from_slice(&be16(mode));
        ino[4] = 3;
        ino[56..64].copy_from_slice(&be64(size));
        ino[76..80].copy_from_slice(&be32(nextents));
        Inode::parse(ino, 0, 1, &sb).unwrap()
    };
    assert!(!mk(0, 0, 0).has_residue()); // zeroed slot
    assert!(mk(0o100644, 0, 0).has_residue());
    assert!(mk(0, 42, 0).has_residue());
    assert!(mk(0, 0, 2).has_residue());
}

#[test]
fn inode_fork_split() {
    let sb = test_sb();
    let mut ino = vec![0u8; 256];
    ino[0..2].copy_from_slice(&be16(DINODE_MAGIC));
    ino[4] = 3;
    ino[5] = 1; // LOCAL
    ino[82] = 8; // forkoff: attr fork at lit+64
    ino[83] = 1;
    let i = Inode::parse(ino, 0, 1, &sb).unwrap();
    assert_eq!(i.dfork().len(), 64);
    assert_eq!(i.afork().unwrap().len(), 256 - 176 - 64);
    // forkoff beyond lit → clamps: dfork spans all, afork empty.
    let mut ino2 = vec![0u8; 256];
    ino2[0..2].copy_from_slice(&be16(DINODE_MAGIC));
    ino2[4] = 3;
    ino2[82] = 0xFF;
    let i2 = Inode::parse(ino2, 0, 1, &sb).unwrap();
    assert_eq!(i2.dfork().len(), 256 - 176);
    assert!(i2.afork().unwrap().is_empty());
}

// ---- dir.rs -----------------------------------------------------------

#[test]
fn shortform_i8count_and_bounds() {
    let sb = test_sb();
    // i8count → 8-byte inode numbers.
    let mut b = Vec::new();
    b.push(1); // count
    b.push(1); // i8count
    b.extend_from_slice(&be64(999)); // parent
    b.push(3); // namelen
    b.extend_from_slice(&be16(0));
    b.extend_from_slice(b"abc");
    b.push(1); // ftype
    b.extend_from_slice(&be64(0x1_0000_0042 | (1 << 62))); // 8-byte ino (masked)
    let (parent, ents) = dir::parse_shortform(&b, 0, &sb).unwrap();
    assert_eq!(parent, 999);
    assert_eq!(ents.len(), 1);
    assert_eq!(ents[0].ino, (0x1_0000_0042 | (1 << 62)) & 0x3FFF_FFFF_FFFF_FFFF);
    // Truncated mid-entry → partial list, no panic.
    let (.., ents2) = dir::parse_shortform(&b[..b.len() - 2], 0, &sb).unwrap();
    assert!(ents2.is_empty());
    // Buffer under minimum → truncated error.
    assert!(dir::parse_shortform(&[0u8; 4], 0, &sb).is_err());
    // i8count set but buffer too short for the u64 parent.
    assert!(dir::parse_shortform(&[1u8, 1, 0, 0, 0, 0], 0, &sb).is_err());
}

#[test]
fn shortform_without_ftype() {
    let sb = test_sb_v4(); // no FTYPE → no ftype byte in entries
    let mut b = Vec::new();
    b.push(1);
    b.push(0);
    b.extend_from_slice(&be32(64));
    b.push(3);
    b.extend_from_slice(&be16(0));
    b.extend_from_slice(b"abc");
    b.extend_from_slice(&be32(77));
    let (_, ents) = dir::parse_shortform(&b, 0, &sb).unwrap();
    assert_eq!(ents[0].ino, 77);
    assert_eq!(ents[0].ftype, 0);
}

#[test]
fn data_block_error_arms() {
    let sb = test_sb();
    // Too small.
    assert!(dir::parse_data_block(&[0u8; 16], 0, &sb).is_err());
    // Bad magic.
    let mut blk = vec![0u8; 4096];
    assert!(dir::parse_data_block(&blk, 0, &sb).is_err());
    // Block-dir leaf count larger than the block → corrupt.
    w32be(&mut blk, 0, dir::MAGIC_DIR3_BLOCK);
    w32be(&mut blk, 4096 - 8, 0xFFFF);
    assert!(dir::parse_data_block(&blk, 0, &sb).is_err());
    // Free run with length < 8 → corrupt.
    w32be(&mut blk, 4096 - 8, 0);
    w16be(&mut blk, 64, 0xFFFF);
    w16be(&mut blk, 66, 4);
    assert!(dir::parse_data_block(&blk, 0, &sb).is_err());
    // Free run whose back-tag doesn't point at its start → corrupt.
    w16be(&mut blk, 64, 0xFFFF);
    w16be(&mut blk, 66, 16);
    w16be(&mut blk, 64 + 14, 0xBEEF);
    assert!(dir::parse_data_block(&blk, 0, &sb).is_err());
    // Entry with namelen 0 → corrupt.
    w16be(&mut blk, 64, 0);
    w64be(&mut blk, 64, 65);
    blk[64 + 8] = 0;
    assert!(dir::parse_data_block(&blk, 0, &sb).is_err());
    // Entry whose tag doesn't repeat its offset → corrupt.
    blk[64 + 8] = 4;
    blk[64 + 9..64 + 13].copy_from_slice(b"name");
    blk[64 + 13] = 1;
    w16be(&mut blk, 64 + 22, 0xDEAD); // tag at entsize(4,ft=1)=24-2
    assert!(dir::parse_data_block(&blk, 0, &sb).is_err());
}

#[test]
fn data_block_v2_layout() {
    let sb = test_sb_v4(); // ftype off → entsize without ftype byte
    let mut blk = vec![0u8; 4096];
    w32be(&mut blk, 0, dir::MAGIC_DIR2_DATA); // XD2D: data_entry_offset=16
    // one entry at 16: ino 65, name "abc".
    w64be(&mut blk, 16, 65);
    blk[24] = 3;
    blk[25..28].copy_from_slice(b"abc");
    w16be(&mut blk, 16 + 14, 16); // tag at entsize(3,false)=16-2
    // terminating free run to the block end.
    w16be(&mut blk, 32, 0xFFFF);
    w16be(&mut blk, 34, (4096 - 32) as u16);
    w16be(&mut blk, 4096 - 2, 32);
    let db = dir::parse_data_block(&blk, 0, &sb).unwrap();
    assert_eq!(db.entries.len(), 1);
    assert_eq!(db.entries[0].ino, 65);
    assert_eq!(db.entries[0].name, b"abc");
    assert!(!db.is_block_dir);
}

#[test]
fn residue_scan_arms() {
    let sb = test_sb();
    // Run shorter than 16 → nothing.
    assert!(dir::scan_residue(&[0u8; 64], (0, 8), 0, &sb).is_empty());

    // Build a data block with one live entry then a freed run covering a
    // deleted entry whose first 4 bytes were overwritten by the run hdr.
    let mut blk = vec![0u8; 4096];
    w32be(&mut blk, 0, dir::MAGIC_DIR3_BLOCK);
    // live entry at 64: ino 65 "live"
    w64be(&mut blk, 64, 65);
    blk[72] = 4;
    blk[73..77].copy_from_slice(b"live");
    blk[77] = 1;
    let esz = (9 + 4 + 1 + 2 + 7) & !7; // 24
    w16be(&mut blk, 64 + esz - 2, 64);
    // deleted entry at 88: ino 130 "gone" — then freed.
    let dstart = 64 + esz;
    w64be(&mut blk, dstart, 130);
    blk[dstart + 8] = 4;
    blk[dstart + 9..dstart + 13].copy_from_slice(b"gone");
    blk[dstart + 13] = 1;
    let dlen = esz;
    // stamp the free run over its head (destroys high ino bytes).
    w16be(&mut blk, dstart, 0xFFFF);
    w16be(&mut blk, dstart + 2, dlen as u16);
    w16be(&mut blk, dstart + dlen - 2, dstart as u16);
    // terminate the chain.
    w16be(&mut blk, dstart + dlen, 0xFFFF);
    w16be(&mut blk, dstart + dlen + 2, (4096 - 8 - dstart - dlen) as u16);
    w16be(&mut blk, 4096 - 8 - 2, (dstart + dlen) as u16);
    let db = dir::parse_data_block(&blk, 0, &sb).unwrap();
    assert_eq!(db.unused.len(), 2);
    let stale = dir::scan_residue(&db.raw, db.unused[0], 0, &sb);
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0].name, b"gone");
    assert!(stale[0].ino_truncated);
    assert_eq!(stale[0].ino, 130);

    // Residue with ino_lo == 0 → rejected.
    let mut blk2 = vec![0u8; 64];
    let run = (0u32, 32u32);
    w16be(&mut blk2, 0, 0xFFFF);
    w16be(&mut blk2, 2, 32);
    assert!(dir::scan_residue(&blk2, run, 0, &sb).is_empty());
    // Residue with an implausible name (control bytes) → rejected.
    let mut blk3 = vec![0u8; 64];
    w32be(&mut blk3, 4, 130); // ino_lo
    blk3[8] = 3;
    blk3[9..12].copy_from_slice(&[0x01, 0x02, 0x03]);
    blk3[12] = 1;
    assert!(dir::scan_residue(&blk3, (0, 32), 0, &sb).is_empty());
    // namelen = 0 head → rejected.
    let mut blk4 = vec![0u8; 64];
    w32be(&mut blk4, 4, 130);
    assert!(dir::scan_residue(&blk4, (0, 32), 0, &sb).is_empty());
}

#[test]
fn residue_intact_entry_in_run() {
    let sb = test_sb();
    // A free run covering TWO merged entries: first truncated, second
    // fully intact — the intact one needs its tag to verify.
    let mut blk = vec![0u8; 128];
    // run at 0, len 48.
    w16be(&mut blk, 0, 0xFFFF);
    w16be(&mut blk, 2, 48);
    w32be(&mut blk, 4, 130); // truncated head ino_lo
    blk[8] = 3;
    blk[9..12].copy_from_slice(b"one");
    blk[12] = 1;
    // second (intact) entry at 24: ino 131 "two"
    w64be(&mut blk, 24, 131);
    blk[32] = 3;
    blk[33..36].copy_from_slice(b"two");
    blk[36] = 1;
    w16be(&mut blk, 24 + 14, 24); // tag → 24 (entsize(3,ftype)=16)
    let stale = dir::scan_residue(&blk, (0, 48), 0, &sb);
    assert_eq!(stale.len(), 2);
    assert_eq!(stale[0].ino, 130);
    assert!(stale[0].ino_truncated);
    assert_eq!(stale[1].ino, 131);
    assert!(!stale[1].ino_truncated);
    assert_eq!(stale[1].name, b"two");
}

// ---- btree.rs ---------------------------------------------------------

#[test]
fn sblock_parse_arms() {
    let sb = test_sb();
    // Truncated below 16.
    assert!(btree::parse_sblock(&[0u8; 8], 0, &sb, btree::INOBT).is_err());
    // Bad magic.
    let blk = vec![0u8; 4096];
    assert!(btree::parse_sblock(&blk, 0, &sb, btree::INOBT).is_err());
    // v5 magic but block shorter than the 56-byte CRC header.
    let mut blk2 = vec![0u8; 32];
    w32be(&mut blk2, 0, 0x4941_4233); // IAB3
    assert!(btree::parse_sblock(&blk2, 0, &sb, btree::INOBT).is_err());
    // v4 magic → 16-byte header, no crc.
    let mut blk3 = vec![0u8; 64];
    w32be(&mut blk3, 0, 0x4941_4254); // IABT
    w16be(&mut blk3, 4, 0);
    w16be(&mut blk3, 6, 2);
    let h = btree::parse_sblock(&blk3, 0, &sb, btree::INOBT).unwrap();
    assert_eq!(h.hdr_len, 16);
    assert_eq!(h.crc_ok, None);
    assert_eq!(h.numrecs, 2);
}

#[test]
fn collect_leaves_arms() {
    let sb = test_sb();
    // NULLAGBLOCK / out-of-range roots → empty, no error.
    let src = vec![0u8; 512 * 4096];
    let leaves = btree::collect_leaves(&src.as_slice(), &sb, 0, u32::MAX, 1, btree::INOBT).unwrap();
    assert!(leaves.is_empty());
    let leaves = btree::collect_leaves(&src.as_slice(), &sb, 0, 0xFFFF, 1, btree::INOBT).unwrap();
    assert!(leaves.is_empty());
    // Root block bad magic → corrupt.
    assert!(btree::collect_leaves(&src.as_slice(), &sb, 0, 2, 1, btree::INOBT).is_err());
    // Node with level > MAX_BTREE_DEPTH.
    let mut img = vec![0u8; 512 * 4096];
    let b2 = &mut img[2 * 4096..3 * 4096];
    w32be(b2, 0, 0x4941_4233);
    w16be(b2, 4, 99); // level
    w16be(b2, 6, 1);
    assert!(btree::collect_leaves(&img.as_slice(), &sb, 0, 2, 1, btree::INOBT).is_err());
    // Node with numrecs exceeding capacity.
    let b2 = &mut img[2 * 4096..3 * 4096];
    w16be(b2, 4, 1);
    w16be(b2, 6, 0xFFFF);
    assert!(btree::collect_leaves(&img.as_slice(), &sb, 0, 2, 1, btree::INOBT).is_err());
    // Root agbno inside geometry but past the end of the image →
    // truncated read error.
    let short = vec![0u8; 4 * 4096];
    assert!(btree::collect_leaves(&short.as_slice(), &sb, 0, 30, 1, btree::INOBT).is_err());
}

#[test]
fn read_leaf_arms() {
    let sb = test_sb();
    let src = vec![0u8; 512 * 4096];
    // Block shorter than blocksize (root past EOF) → truncated.
    let short = vec![0u8; 100 * 4096];
    assert!(btree::read_leaf(&short.as_slice(), &sb, 0, 200, btree::INOBT).is_err());
    // Non-leaf level → corrupt.
    let mut img = src.clone();
    let b = &mut img[2 * 4096..3 * 4096];
    w32be(b, 0, 0x4941_4233);
    w16be(b, 4, 1);
    assert!(btree::read_leaf(&img.as_slice(), &sb, 0, 2, btree::INOBT).is_err());
}

// ---- attr.rs ----------------------------------------------------------

#[test]
fn attr_local_bounds() {
    // Buffer under the 4-byte header → empty.
    assert!(crate::attr::parse_local(&[0u8; 2]).is_empty());
    // count exceeds the data → stops at buffer end.
    let mut b = Vec::new();
    b.extend_from_slice(&be16(0));
    b.push(9); // claims 9 entries
    b.extend_from_slice(&[3, 2, 4]); // flags=4 → "system."? (bit2 secure)
    b.extend_from_slice(b"key");
    b.extend_from_slice(b"v1");
    let attrs = crate::attr::parse_local(&b);
    assert_eq!(attrs.len(), 1);
    assert_eq!(attrs[0].name, "security.key");
    // Truncated mid-entry header → break without entry.
    let b2 = [0u8, 0, 1, 5];
    assert!(crate::attr::parse_local(&b2).is_empty());
}

#[test]
fn attr_remote_error_arms() {
    let sb = test_sb();
    let img = vec![0u8; 2 * 4096];
    let e = Extent {
        fileoff: 0,
        fsb: 0,
        len: 2,
        unwritten: false,
    };
    // valueblk past the extent map → "extent gap" error.
    assert!(crate::attr::remote_read(&img.as_slice(), &sb, &[e], 9, 10).is_err());
    // v5 remote block without the XARM magic → error.
    assert!(crate::attr::remote_read(&img.as_slice(), &sb, &[e], 0, 10).is_err());
    // v4 remote read needs no XARM header.
    let sb4 = test_sb_v4();
    let v = crate::attr::remote_read(&img.as_slice(), &sb4, &[e], 0, 10).unwrap();
    assert_eq!(v.len(), 10);
}

#[test]
fn attr_leaf_skip_and_remote_entry() {
    let sb = test_sb();
    let e = Extent {
        fileoff: 0,
        fsb: 0,
        len: 2,
        unwritten: false,
    };
    // Block without a leaf magic → skipped (not an error).
    let img = vec![0u8; 2 * 4096];
    let attrs = crate::attr::collect_leaf(&img.as_slice(), &sb, &[e]).unwrap();
    assert!(attrs.is_empty());
    // Truncated block → skipped.
    let tiny = vec![0u8; 20];
    let attrs = crate::attr::collect_leaf(&tiny.as_slice(), &sb, &[e]).unwrap();
    assert!(attrs.is_empty());

    // v2 leaf with a REMOTE (non-local) name block.
    let mut blk = vec![0u8; 4096];
    blk[8..10].copy_from_slice(&be16(0xFBEE));
    blk[12..14].copy_from_slice(&be16(1)); // count
    blk[36..38].copy_from_slice(&be16(200)); // nameidx
    blk[38] = 0; // flags — remote
    // remote nameblk: {valueblk u32, valuelen u32, namelen u8, name}
    blk[200..204].copy_from_slice(&be32(1)); // valueblk
    blk[204..208].copy_from_slice(&be32(9)); // valuelen
    blk[208] = 6;
    blk[209..215].copy_from_slice(b"secret");
    // The remote value read will fail (no XARM) → value stays None.
    let attrs = crate::attr::collect_leaf(&blk.as_slice(), &sb, &[e]).unwrap();
    assert_eq!(attrs.len(), 1);
    assert_eq!(attrs[0].name, "user.secret");
    assert!(attrs[0].remote);
    assert_eq!(attrs[0].value_len, 9);
    // nameidx out of bounds → entry skipped.
    let mut blk2 = vec![0u8; 4096];
    blk2[8..10].copy_from_slice(&be16(0xFBEE));
    blk2[12..14].copy_from_slice(&be16(1));
    blk2[36..38].copy_from_slice(&be16(4094));
    blk2[38] = 1;
    let attrs = crate::attr::collect_leaf(&blk2.as_slice(), &sb, &[e]).unwrap();
    assert!(attrs.is_empty());
}
