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
