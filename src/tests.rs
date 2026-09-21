//! Unit tests for the pure decoders (no image needed).

use super::*;

#[test]
fn crc32_vector() {
    // zlib CRC-32 of "123456789" is the canonical check value.
    assert_eq!(crc32::crc32(0, b"123456789"), 0xCBF4_3926);
    // Chaining: crc32(seed, a+b) == crc32(crc32(seed, a), b).
    let a = crc32::crc32(0xF2F5_2010, b"hello");
    let b = crc32::crc32(a, b" world");
    assert_eq!(b, crc32::f2fs_crc32(0xF2F5_2010, b"hello world"));
}

#[test]
fn bit_le_order() {
    let map = [0b0000_0101u8, 0x80];
    assert!(tables::bit_le(&map, 0));
    assert!(!tables::bit_le(&map, 1));
    assert!(tables::bit_le(&map, 2));
    assert!(tables::bit_le(&map, 15));
    assert!(!tables::bit_le(&map, 8));
    assert!(!tables::bit_le(&map, 4096)); // out of range → false
}

#[test]
fn dentry_layout_4k() {
    let l = dentry::DentryLayout::for_len(4096).unwrap();
    assert_eq!(l.nr_slots, 214);
    assert_eq!(l.bitmap_len, 27);
    assert_eq!(l.dentry_off, 30); // 27 bitmap + 3 reserved
    assert_eq!(l.filename_off, 30 + 214 * 11); // 2384
}

#[test]
fn dentry_layout_inline() {
    // A 640-byte inline region → nr = 640*8/153 = 33.
    let l = dentry::DentryLayout::for_len(640).unwrap();
    assert_eq!(l.nr_slots, 33);
    assert_eq!(l.bitmap_len, 5);
}

#[test]
fn dentry_parse_live_and_residue() {
    let mut b = vec![0u8; 4096];
    let l = dentry::DentryLayout::for_len(4096).unwrap();
    // live dentry at slot 0, name "ab" (1 slot)
    let de = l.dentry_off;
    b[de + 4..de + 8].copy_from_slice(&42u32.to_le_bytes()); // ino
    b[de + 8..de + 10].copy_from_slice(&2u16.to_le_bytes()); // name_len
    b[de + 10] = 1; // file_type
    b[0] |= 1; // bitmap bit 0
    b[l.filename_off] = b'a';
    b[l.filename_off + 1] = b'b';
    // residue at slot 1: dirent present, bitmap clear
    let de1 = l.dentry_off + 11;
    b[de1 + 4..de1 + 8].copy_from_slice(&77u32.to_le_bytes());
    b[de1 + 8..de1 + 10].copy_from_slice(&3u16.to_le_bytes());
    b[de1 + 10] = 2;
    b[l.filename_off + 8] = b'x';
    b[l.filename_off + 9] = b'y';
    b[l.filename_off + 10] = b'z';
    let (des, errs) = dentry::parse_dentries(&b, 0, 4096, 10_000).unwrap();
    assert!(errs.is_empty());
    assert_eq!(des.len(), 2);
    assert!(des[0].live && des[0].ino == 42 && des[0].name == b"ab");
    assert!(!des[1].live && des[1].ino == 77 && des[1].name == b"xyz");
    // provenance: rec_off points at the 11-byte dirent
    assert_eq!(des[0].rec_off, l.dentry_off as u64);
    assert_eq!(des[1].rec_off, (l.dentry_off + 11) as u64);
}

#[test]
fn dentry_multi_slot_name() {
    let mut b = vec![0u8; 4096];
    let l = dentry::DentryLayout::for_len(4096).unwrap();
    let name = b"seventeen_chars.dat"; // 19 bytes → 3 slots
    let de = l.dentry_off;
    b[de + 4..de + 8].copy_from_slice(&7u32.to_le_bytes());
    b[de + 8..de + 10].copy_from_slice(&(name.len() as u16).to_le_bytes());
    b[de + 10] = 1;
    b[0] |= 0b111; // 3 slots marked
    b[l.filename_off..l.filename_off + name.len()].copy_from_slice(name);
    let (des, _) = dentry::parse_dentries(&b, 0, 4096, 10_000).unwrap();
    assert_eq!(des.len(), 1);
    assert_eq!(des[0].name, name);
}

#[test]
fn dentry_insane_marked_slot_reports_error() {
    let mut b = vec![0u8; 4096];
    let l = dentry::DentryLayout::for_len(4096).unwrap();
    b[0] |= 1; // marked, but dirent is insane (name_len 0)
    let (_, errs) = dentry::parse_dentries(&b, 0, 4096, 10_000).unwrap();
    assert_eq!(errs.len(), 1);
    let _ = l;
}

#[test]
fn node_footer_parse() {
    let mut b = vec![0u8; 4096];
    let o = 4096 - 24;
    b[o..o + 4].copy_from_slice(&123u32.to_le_bytes());
    b[o + 4..o + 8].copy_from_slice(&123u32.to_le_bytes());
    b[o + 8..o + 12].copy_from_slice(&9u32.to_le_bytes());
    b[o + 12..o + 20].copy_from_slice(&77u64.to_le_bytes());
    let f = node::NodeFooter::parse(&b).unwrap();
    assert_eq!((f.nid, f.ino, f.cp_ver), (123, 123, 77));
    assert!(node::NodeFooter::parse(&b[..23]).is_none());
}

#[test]
fn inode_decode_basics() {
    let mut b = vec![0u8; 4096];
    b[0..2].copy_from_slice(&0o100644u16.to_le_bytes());
    b[3] = 0x20; // EXTRA_ATTR
    b[16..24].copy_from_slice(&4096u64.to_le_bytes()); // size
    b[48..56].copy_from_slice(&1_700_000_000u64.to_le_bytes()); // mtime
    b[64..68].copy_from_slice(&123_456_789u32.to_le_bytes());
    b[76..80].copy_from_slice(&0u32.to_le_bytes()); // xattr_nid
    b[88..92].copy_from_slice(&4u32.to_le_bytes());
    b[92..96].copy_from_slice(b"name");
    // extra attrs: isize 36 → i_addr base at 396; crtime at 372/380
    b[360..362].copy_from_slice(&36u16.to_le_bytes());
    b[372..380].copy_from_slice(&1_699_000_000u64.to_le_bytes());
    b[380..384].copy_from_slice(&987_654_321u32.to_le_bytes());
    b[396..400].copy_from_slice(&0xBEEFu32.to_le_bytes()); // i_addr[extra+0]
    let inode = node::Inode::decode(&b[..4072], 0).unwrap();
    assert_eq!(inode.mode & 0o170000, 0o100000);
    assert_eq!(inode.crtime, Some((1_699_000_000, 987_654_321)));
    let def = (4096 - 360 - 20 - 24) / 4; // 923
    assert_eq!(inode.addrs_count(def), 923 - 9);
    assert_eq!(inode.i_addr(0, def), Some(0xBEEF));
}

#[test]
fn looks_like_node_guards() {
    let mut b = vec![0u8; 4096];
    let o = 4096 - 24;
    // zeros → nid 0 → reject
    assert!(node::looks_like_node(&b, 10_000, 10).is_none());
    b[o..o + 4].copy_from_slice(&55u32.to_le_bytes());
    b[o + 4..o + 8].copy_from_slice(&55u32.to_le_bytes());
    b[o + 12..o + 20].copy_from_slice(&7u64.to_le_bytes());
    assert!(node::looks_like_node(&b, 10_000, 10).is_some());
    // cp_ver wildly ahead → reject
    b[o + 12..o + 20].copy_from_slice(&10_000u64.to_le_bytes());
    assert!(node::looks_like_node(&b, 10_000, 10).is_none());
}

#[test]
fn xattr_entries_encrypt() {
    // index 9 name "c" value 8 bytes, aligned to 4
    let mut b = vec![0u8; 64];
    b[0] = 9; // name_index
    b[1] = 1; // name_len
    b[2..4].copy_from_slice(&8u16.to_le_bytes()); // value_size
    b[4] = b'c';
    let entry_sz = (4 + 1 + 3) & !3; // 8
    b[entry_sz..entry_sz + 8].copy_from_slice(b"ctxbytes");
    let x = node::parse_xattr_entries(&b);
    assert_eq!(x.encrypt_ctx.as_deref(), Some(b"ctxbytes".as_ref()));
    assert!(!x.verity);
}

// ---------------------------------------------------------------------------
// Coverage sweep: decoder error arms and edge cases.
// ---------------------------------------------------------------------------

use crate::checkpoint;
use crate::dentry::{looks_like_dentry_block, parse_dentries, DentryLayout};
use crate::node::{
    looks_like_node, parse_node, parse_xattr_block, parse_xattr_entries, Inode, NodeView,
};
use crate::sb::{feature, SuperBlock, F2FS_MAGIC, SB_OFF, SB_SIZE};
use crate::tables::{NatEntry, SitEntry, Tables};

fn w16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// A minimal valid superblock (the same geometry as tests/common).
fn sb_buf() -> Vec<u8> {
    let mut b = vec![0u8; SB_SIZE];
    w32(&mut b, 0, F2FS_MAGIC);
    w16(&mut b, 4, 1);
    w16(&mut b, 6, 15);
    w32(&mut b, 8, 9); // log_sectorsize
    w32(&mut b, 12, 3); // log_sectors_per_block
    w32(&mut b, 16, 12); // log_blocksize
    w32(&mut b, 20, 9); // log_blocks_per_seg
    w32(&mut b, 24, 1);
    w32(&mut b, 28, 1);
    w32(&mut b, 32, 3068); // checksum_offset
    w64(&mut b, 36, 12800); // block_count
    w32(&mut b, 44, 24);
    w32(&mut b, 48, 24); // segment_count
    w32(&mut b, 52, 2);
    w32(&mut b, 56, 2);
    w32(&mut b, 60, 2);
    w32(&mut b, 64, 2);
    w32(&mut b, 68, 16); // segment_count_main
    w32(&mut b, 72, 512);
    w32(&mut b, 76, 512);
    w32(&mut b, 80, 1536);
    w32(&mut b, 84, 2560);
    w32(&mut b, 88, 3584);
    w32(&mut b, 92, 4608);
    w32(&mut b, 96, 3); // root_ino
    b
}

/// A source whose superblock sits at SB_OFF (and a copy at SB2_OFF).
fn sb_src(sb: &[u8], backup: Option<&[u8]>) -> Vec<u8> {
    let mut v = vec![0u8; 0x1400 + SB_SIZE];
    v[SB_OFF as usize..SB_OFF as usize + SB_SIZE].copy_from_slice(sb);
    let zeros = vec![0u8; SB_SIZE];
    let b2 = backup.unwrap_or(&zeros);
    v[0x1400..0x1400 + SB_SIZE].copy_from_slice(b2);
    v
}

/// A SuperBlock value built directly (no parse) for table/fs helpers.
fn test_sb() -> SuperBlock {
    SuperBlock {
        major_ver: 1,
        minor_ver: 15,
        block_size: 4096,
        log_blocks_per_seg: 9,
        blks_per_seg: 512,
        segs_per_sec: 1,
        secs_per_zone: 1,
        block_count: 12800,
        section_count: 24,
        segment_count: 24,
        segment_count_ckpt: 2,
        segment_count_sit: 2,
        segment_count_nat: 2,
        segment_count_ssa: 2,
        segment_count_main: 16,
        segment0_blkaddr: 512,
        cp_blkaddr: 512,
        sit_blkaddr: 1536,
        nat_blkaddr: 2560,
        ssa_blkaddr: 3584,
        main_blkaddr: 4608,
        root_ino: 3,
        node_ino: 1,
        meta_ino: 2,
        uuid: "test".into(),
        volume_name: None,
        extension_count: 1,
        cp_payload: 0,
        feature: feature::SB_CHKSUM,
        version: "test".into(),
        crc_ok: true,
    }
}

// ---- sb.rs -----------------------------------------------------------------

#[test]
fn superblock_validation_arms() {
    // bad magic
    let mut b = sb_buf();
    w32(&mut b, 0, 0);
    assert!(SuperBlock::parse(&sb_src(&b, None).as_slice()).is_err());
    // implausible sector size
    let mut b = sb_buf();
    w32(&mut b, 8, 17);
    assert!(SuperBlock::parse(&sb_src(&b, None).as_slice()).is_err());
    // log_blocksize != log_sector + log_sectors_per_block
    let mut b = sb_buf();
    w32(&mut b, 16, 13);
    assert!(SuperBlock::parse(&sb_src(&b, None).as_slice()).is_err());
    // unsupported log_blocksize
    let mut b = sb_buf();
    w32(&mut b, 12, 8); // log_sectors_per_block 8 → 17
    assert!(SuperBlock::parse(&sb_src(&b, None).as_slice()).is_err());
    // log_blocks_per_seg zero / >9
    let mut b = sb_buf();
    w32(&mut b, 20, 0);
    assert!(SuperBlock::parse(&sb_src(&b, None).as_slice()).is_err());
    let mut b = sb_buf();
    w32(&mut b, 20, 10);
    assert!(SuperBlock::parse(&sb_src(&b, None).as_slice()).is_err());
    // zero counts
    let mut b = sb_buf();
    w64(&mut b, 36, 0);
    assert!(SuperBlock::parse(&sb_src(&b, None).as_slice()).is_err());
    let mut b = sb_buf();
    w32(&mut b, 48, 0);
    assert!(SuperBlock::parse(&sb_src(&b, None).as_slice()).is_err());
    // per-area segment counts exceed segment_count
    let mut b = sb_buf();
    w32(&mut b, 68, 30); // seg_main too big
    assert!(SuperBlock::parse(&sb_src(&b, None).as_slice()).is_err());
    // block addresses out of order
    let mut b = sb_buf();
    w32(&mut b, 80, 4000); // sit_blkaddr > nat_blkaddr
    assert!(SuperBlock::parse(&sb_src(&b, None).as_slice()).is_err());
    // main area past segment space
    let mut b = sb_buf();
    w32(&mut b, 92, 12000); // main_blkaddr near end
    assert!(SuperBlock::parse(&sb_src(&b, None).as_slice()).is_err());
    // root_ino zero
    let mut b = sb_buf();
    w32(&mut b, 96, 0);
    assert!(SuperBlock::parse(&sb_src(&b, None).as_slice()).is_err());
    // zero section/zone geometry
    let mut b = sb_buf();
    w32(&mut b, 24, 0);
    assert!(SuperBlock::parse(&sb_src(&b, None).as_slice()).is_err());
}

#[test]
fn superblock_backup_and_crc() {
    // Primary corrupt → backup at 0x1400 parses.
    let mut bad = sb_buf();
    w32(&mut bad, 0, 0xDEAD_BEEF);
    let good = sb_buf();
    let src = sb_src(&bad, Some(&good));
    let sb = SuperBlock::parse(&src.as_slice()).unwrap();
    assert_eq!(sb.block_size, 4096);
    // CRC feature set but wrong stored crc → crc_ok false (still parses).
    let mut b = sb_buf();
    w32(&mut b, 2180, feature::SB_CHKSUM);
    w32(&mut b, 3068, 0xDEAD_BEEF);
    let src = sb_src(&b, None);
    let sb = SuperBlock::parse(&src.as_slice()).unwrap();
    assert!(!sb.crc_ok);
}

#[test]
fn detect_tiers() {
    use sutram_fs::DetectConfidence;
    let empty: &[u8] = &[];
    assert_eq!(SuperBlock::detect(&empty), DetectConfidence::None);
    let short = vec![0u8; 0x400];
    assert_eq!(SuperBlock::detect(&short.as_slice()), DetectConfidence::None);
    // Magic but unparseable geometry → Medium.
    let mut v = vec![0u8; 0x1400 + SB_SIZE];
    w32(&mut v[SB_OFF as usize..], 0, F2FS_MAGIC);
    assert_eq!(SuperBlock::detect(&v.as_slice()), DetectConfidence::Medium);
    // Magic + truncated sb → High.
    let mut v = vec![0u8; SB_OFF as usize + 16];
    w32(&mut v[SB_OFF as usize..], 0, F2FS_MAGIC);
    assert_eq!(SuperBlock::detect(&v.as_slice()), DetectConfidence::High);
}

#[test]
fn sb_geometry_helpers() {
    let sb = test_sb();
    // main_segno: below main area → None; inside → seg index; past end → None.
    assert_eq!(sb.main_segno(100), None);
    assert_eq!(sb.main_segno(4608), Some(0));
    assert_eq!(sb.main_segno(4608 + 512), Some(1));
    assert_eq!(sb.main_segno(4608 + 16 * 512), None);
    assert_eq!(sb.sit_block_count(), 1); // ceil(16 / 55)
    assert_eq!(sb.sit_blocks(), 512);
    assert_eq!(sb.nat_blocks(), 512);
    assert_eq!(sb.max_nid(), (4096 / 9) * 512);
}

// ---- node.rs ----------------------------------------------------------------

#[test]
fn inode_decode_too_small() {
    assert!(Inode::decode(&[0u8; 100], 0).is_err());
}

#[test]
fn inode_addr_helpers_bounds() {
    let mut b = vec![0u8; 4072];
    b[0..2].copy_from_slice(&0o100644u16.to_le_bytes());
    b[3] = 0x20 | 0x01; // EXTRA_ATTR | INLINE_XATTR
    w16(&mut b, 360, 36); // extra_isize
    w16(&mut b, 362, 10); // inline_xattr_size
    let inode = Inode::decode(&b, 0).unwrap();
    let def = (4096 - 360 - 20 - 24) / 4; // 923
    // addrs_count clamps for extra + xattr.
    assert_eq!(inode.addrs_count(def), 923 - 9 - 10);
    assert_eq!(inode.i_addr(923 - 19, def), None); // past count
    assert_eq!(inode.i_nid(5), None);
    // inline xattr region = last 40 bytes of i_addr.
    let (off, len) = inode.inline_xattr_region(4096).unwrap();
    assert_eq!(len, 40);
    assert_eq!(off, 360 + (923 - 10) * 4);
    // No xattr → None.
    let mut b2 = vec![0u8; 4072];
    b2[0..2].copy_from_slice(&0o100644u16.to_le_bytes());
    let i2 = Inode::decode(&b2, 0).unwrap();
    assert!(i2.inline_xattr_region(4096).is_none());
}

#[test]
fn parse_node_indirect_view() {
    let mut b = vec![0u8; 4096];
    // footer nid != ino → Indirect pointer array.
    let o = 4096 - 24;
    w32(&mut b[o..], 0, 50);
    w32(&mut b[o..], 4, 60);
    w64(&mut b[o..], 12, 5);
    w32(&mut b, 0, 777);
    w32(&mut b, 4, 888);
    let (f, v) = parse_node(&b, 100, 4096).unwrap();
    assert_eq!(f.nid, 50);
    match v {
        NodeView::Indirect(ptrs) => {
            assert_eq!(ptrs[0], 777);
            assert_eq!(ptrs[1], 888);
        }
        _ => panic!("expected Indirect"),
    }
    // Short buffer → error.
    assert!(parse_node(&b[..10], 0, 4096).is_err());
}

#[test]
fn looks_like_node_arms() {
    let mut b = vec![0u8; 4096];
    // Footer parse fails on short input.
    assert!(looks_like_node(&b[..10], 1000, 10).is_none());
    let o = 4096 - 24;
    // nid 0
    w32(&mut b[o..], 4, 5);
    assert!(looks_like_node(&b, 1000, 10).is_none());
    // ino 0
    let mut b2 = vec![0u8; 4096];
    w32(&mut b2[o..], 0, 5);
    assert!(looks_like_node(&b2, 1000, 10).is_none());
    // nid beyond max
    let mut b3 = vec![0u8; 4096];
    w32(&mut b3[o..], 0, 5000);
    w32(&mut b3[o..], 4, 5000);
    assert!(looks_like_node(&b3, 100, 10).is_none());
    // ino beyond max
    let mut b4 = vec![0u8; 4096];
    w32(&mut b4[o..], 0, 5);
    w32(&mut b4[o..], 4, 5000);
    assert!(looks_like_node(&b4, 100, 10).is_none());
    let _ = b;
}

#[test]
fn xattr_parsing_arms() {
    // verity index (11) → flag set; other index → list only.
    let mut b = vec![0u8; 128];
    b[0] = 11;
    b[1] = 1;
    w16(&mut b, 2, 4);
    b[4] = b'v';
    b[8..12].copy_from_slice(b"veri");
    b[12] = 1; // second entry: user index
    b[13] = 3;
    w16(&mut b, 14, 0);
    b[16..19].copy_from_slice(b"usr");
    let x = parse_xattr_entries(&b);
    assert!(x.verity);
    assert_eq!(x.list.len(), 2);
    // Oversized entry that overruns the buffer → stop.
    let mut b2 = vec![0u8; 64];
    b2[0] = 1;
    b2[1] = 2;
    w16(&mut b2, 2, 0xFFFF);
    let x2 = parse_xattr_entries(&b2);
    assert_eq!(x2.list.len(), 1);
    // parse_xattr_block: short, bad magic, valid.
    assert!(parse_xattr_block(&[0u8; 10]).is_none());
    let mut blk = vec![0u8; 64];
    assert!(parse_xattr_block(&blk).is_none());
    w32(&mut blk, 0, crate::node::XATTR_MAGIC);
    blk[24] = 9;
    blk[25] = 1;
    w16(&mut blk, 26, 4);
    blk[28] = b'c';
    blk[32..36].copy_from_slice(b"ctx!");
    let xb = parse_xattr_block(&blk).unwrap();
    assert_eq!(xb.encrypt_ctx.as_deref(), Some(b"ctx!".as_ref()));
}

// ---- dentry.rs ---------------------------------------------------------------

#[test]
fn dentry_layout_bounds() {
    assert!(DentryLayout::for_len(10).is_none());
    assert!(DentryLayout::for_len(19).is_none());
}

#[test]
fn parse_dentries_error_arms() {
    let b = vec![0u8; 4096];
    // Region out of bounds.
    assert!(parse_dentries(&b, 8000, 4096, 10_000).is_err());
    // Region too small for a layout.
    assert!(parse_dentries(&b, 0, 10, 10_000).is_err());
    // Residue slot whose name byte is 0 → skipped silently.
    let l = DentryLayout::for_len(4096).unwrap();
    let mut b2 = vec![0u8; 4096];
    let de = l.dentry_off;
    w32(&mut b2, de + 4, 55);
    w16(&mut b2, de + 8, 3); // plausible, but name byte 0
    let (des, errs) = parse_dentries(&b2, 0, 4096, 10_000).unwrap();
    assert!(des.is_empty() && errs.is_empty());
    // Residue ino beyond max_nid → skipped.
    let mut b3 = vec![0u8; 4096];
    w32(&mut b3, de + 4, 99_999);
    w16(&mut b3, de + 8, 3);
    b3[l.filename_off] = b'x';
    let (des, _) = parse_dentries(&b3, 0, 4096, 100).unwrap();
    assert!(des.is_empty());
}

#[test]
fn looks_like_dentry_arms() {
    assert!(!looks_like_dentry_block(&[0u8; 16], 10_000));
    // A block with no marked slots → false.
    let b = vec![0u8; 4096];
    assert!(!looks_like_dentry_block(&b, 10_000));
    // Marked but insane → false.
    let mut b2 = vec![0u8; 4096];
    b2[0] |= 1;
    assert!(!looks_like_dentry_block(&b2, 10_000));
    // Marked and sane → true.
    let l = DentryLayout::for_len(4096).unwrap();
    let mut b3 = vec![0u8; 4096];
    let de = l.dentry_off;
    w32(&mut b3, de + 4, 42);
    w16(&mut b3, de + 8, 2);
    b3[0] |= 1;
    assert!(looks_like_dentry_block(&b3, 10_000));
}

// ---- tables.rs ---------------------------------------------------------------

#[test]
fn sit_entry_semantics() {
    let mut e = SitEntry {
        vblocks: 0x3FF & 5,
        valid_map: [0u8; 64],
        mtime: 9,
    };
    assert_eq!(e.valid_blocks(), 5);
    assert!(e.is_free()); // vblocks 5 but empty map → free
    e.valid_map[0] = 1;
    assert!(!e.is_free());
    let free = SitEntry { vblocks: 0, valid_map: [0u8; 64], mtime: 0 };
    assert!(free.is_free());
    assert!(NatEntry { version: 0, ino: 0, block_addr: 0 }.is_free());
    assert!(!NatEntry { version: 0, ino: 0, block_addr: 7 }.is_free());
}

#[test]
fn tables_bitmap_selection() {
    let sb = test_sb();
    let src = vec![0u8; 8000 * 4096];
    let sit_b = [0u8; 64];
    let nat_b = [0b1u8]; // boff 0 → copy B
    let t = Tables { src: &src.as_slice(), sb: &sb, sit_bitmap: &sit_b, nat_bitmap: &[] };
    // bitmap clear → copy A
    assert_eq!(t.sit_blk(0), 1536);
    // bitmap bit set → copy B (+sit_blocks)
    let sit_b2 = [0b1u8];
    let t2 = Tables { src: &src.as_slice(), sb: &sb, sit_bitmap: &sit_b2, nat_bitmap: &nat_b };
    assert_eq!(t2.sit_blk(0), 1536 + 512);
    // nat_blk copy A: nat_blkaddr + (0<<1) - 0 = 2560; copy B: +512.
    assert_eq!(t2.nat_blk(0), 2560 + 512);
    assert_eq!(t.nat_blk(0), 2560);
    // stale is the *other* copy.
    assert_eq!(t2.stale_nat_blk(0), 2560);
    assert_eq!(t.stale_nat_blk(0), 2560 + 512);
    // nat_entry for a nid past the table → None.
    assert!(t.nat_entry(1_000_000).unwrap().is_none());
    assert!(t.stale_nat_entry(1_000_000).unwrap().is_none());
}

#[test]
fn tables_nat_entry_and_block() {
    let sb = test_sb();
    let mut src = vec![0u8; 8000 * 4096];
    // NAT copy A blk 0 at 2560: entry 7 → {ver 2, ino 7, blk 4700}.
    let o = 2560 * 4096 + 7 * 9;
    src[o] = 2;
    w32(&mut src[o..], 1, 7);
    w32(&mut src[o..], 5, 4700);
    // stale copy B at 3072: entry 7 → {ver 1, ino 7, blk 4900}.
    let o2 = 3072 * 4096 + 7 * 9;
    src[o2] = 1;
    w32(&mut src[o2..], 1, 7);
    w32(&mut src[o2..], 5, 4900);
    let t = Tables { src: &src.as_slice(), sb: &sb, sit_bitmap: &[], nat_bitmap: &[] };
    let e = t.nat_entry(7).unwrap().unwrap();
    assert_eq!(e.block_addr, 4700);
    let s = t.stale_nat_entry(7).unwrap().unwrap();
    assert_eq!(s.block_addr, 4900);
    let (cur, stale) = t.nat_block_pair(0).unwrap();
    assert_eq!(cur[7].block_addr, 4700);
    assert_eq!(stale[7].block_addr, 4900);
    // Truncated source → Io/truncated errors, not panic.
    let short = vec![0u8; 2560 * 4096 + 64];
    let t2 = Tables { src: &short.as_slice(), sb: &sb, sit_bitmap: &[], nat_bitmap: &[] };
    assert!(t2.nat_entry(7).is_err());
    assert!(t2.stale_nat_entry(7).is_err());
    assert!(t2.nat_block_pair(0).is_err());
}

#[test]
fn sum_entry_arms() {
    let mut sb = test_sb();
    let src = vec![0u8; 8000 * 4096];
    let t = Tables { src: &src.as_slice(), sb: &sb, sit_bitmap: &[], nat_bitmap: &[] };
    // Block below main area → None.
    assert!(t.sum_entry(100).unwrap().is_none());
    // PACKED_SSA → always None.
    sb.feature |= feature::PACKED_SSA;
    let t2 = Tables { src: &src.as_slice(), sb: &sb, sit_bitmap: &[], nat_bitmap: &[] };
    assert!(t2.sum_entry(4608).unwrap().is_none());
    // Valid main block → reads 7-byte entry from ssa_blkaddr+seg.
    let mut src2 = vec![0u8; 8000 * 4096];
    let o = 3584 * 4096 + 3 * 7; // seg 0, blkoff 3
    w32(&mut src2[o..], 0, 42);
    src2[o + 4] = 9;
    w16(&mut src2[o..], 5, 7);
    let t3 = Tables { src: &src2.as_slice(), sb: &test_sb(), sit_bitmap: &[], nat_bitmap: &[] };
    let se = t3.sum_entry(4608 + 3).unwrap().unwrap();
    assert_eq!((se.nid, se.version, se.ofs_in_node), (42, 9, 7));
    // blkoff ≥ 512 → None (blkoff can't exceed seg anyway via main_segno,
    // but the guard is there).
    // Truncated source → error.
    let short = vec![0u8; 3584 * 4096];
    let t4 = Tables { src: &short.as_slice(), sb: &test_sb(), sit_bitmap: &[], nat_bitmap: &[] };
    assert!(t4.sum_entry(4608).is_err());
}

// ---- checkpoint.rs ------------------------------------------------------------

/// Write a checkpoint block into `src` at `blk`.
fn write_cp(src: &mut [u8], blk: usize, ver: u64, flags: u32, start_sum: u32, total: u32) {
    let b = &mut src[blk * 4096..(blk + 1) * 4096];
    b.fill(0);
    w64(b, 0, ver);
    w64(b, 8, 8192);
    w64(b, 16, 20);
    w32(b, 28, 0);
    w32(b, 32, 13);
    w32(b, 132, flags);
    w32(b, 136, total);
    w32(b, 140, start_sum);
    w32(b, 144, 20);
    w32(b, 148, 12);
    w32(b, 152, 20);
    w32(b, 156, 64);
    w32(b, 160, 256);
    let cso = 512u32;
    w32(b, 164, cso);
    w64(b, 168, 12_345);
    let crc = {
        let c = crate::crc32::f2fs_crc32(F2FS_MAGIC, &b[..cso as usize]);
        crate::crc32::crc32(c, &b[cso as usize + 4..])
    };
    w32(b, cso as usize, crc);
}

#[test]
fn checkpoint_pack_selection() {
    let sb = test_sb();
    let mut src = vec![0u8; 2000 * 4096];
    // pack0 ver 5, pack1 ver 4 → picks pack0.
    write_cp(&mut src, 512, 5, 0x1, 2, 3);
    write_cp(&mut src, 514, 5, 0x1, 2, 3);
    write_cp(&mut src, 1024, 4, 0x1, 1, 2);
    write_cp(&mut src, 1025, 4, 0x1, 1, 2);
    let cp = checkpoint::read_checkpoint(&src.as_slice(), &sb).unwrap();
    assert_eq!((cp.checkpoint_ver, cp.pack_blk), (5, 512));
    assert!(cp.crc_ok);

    // Tie version, pack1 has valid CRC and pack0 doesn't → picks pack1.
    let mut src2 = vec![0u8; 2000 * 4096];
    write_cp(&mut src2, 512, 5, 0x1, 2, 3);
    write_cp(&mut src2, 514, 5, 0x1, 2, 3);
    write_cp(&mut src2, 1024, 5, 0x1, 1, 2);
    write_cp(&mut src2, 1025, 5, 0x1, 1, 2);
    // Corrupt pack0's first-block CRC field.
    w32(&mut src2[512 * 4096 + 512..], 0, 0xDEAD_BEEF);
    let cp2 = checkpoint::read_checkpoint(&src2.as_slice(), &sb).unwrap();
    assert_eq!(cp2.pack_blk, 1024);
    assert!(cp2.crc_ok);
}

#[test]
fn checkpoint_pack_invalid_and_fallback() {
    let sb = test_sb();
    // pack0 trailing copy version differs → invalid; pack1 wins.
    let mut src = vec![0u8; 2000 * 4096];
    write_cp(&mut src, 512, 5, 0x1, 2, 3);
    write_cp(&mut src, 514, 9, 0x1, 2, 3); // mismatched version
    write_cp(&mut src, 1024, 4, 0x1, 1, 2);
    write_cp(&mut src, 1025, 4, 0x1, 1, 2);
    let cp = checkpoint::read_checkpoint(&src.as_slice(), &sb).unwrap();
    assert_eq!((cp.checkpoint_ver, cp.pack_blk), (4, 1024));
    assert!(cp.notes.iter().any(|n| n.contains("did not validate")));

    // Both packs invalid but readable first blocks → lenient fallback.
    let mut src2 = vec![0u8; 2000 * 4096];
    write_cp(&mut src2, 512, 5, 0x1, 2, 3);
    src2[514 * 4096..515 * 4096].fill(0xAB); // tail garbage
    write_cp(&mut src2, 1024, 4, 0x1, 1, 2);
    src2[1025 * 4096..1026 * 4096].fill(0xAB);
    let cp2 = checkpoint::read_checkpoint(&src2.as_slice(), &sb).unwrap();
    assert_eq!(cp2.checkpoint_ver, 5);
    assert!(cp2
        .notes
        .iter()
        .any(|n| n.contains("no checkpoint pack fully validated")));

    // pack_total < 2 → pack invalid.
    let mut src3 = vec![0u8; 2000 * 4096];
    write_cp(&mut src3, 512, 5, 0x1, 2, 1); // total 1 → meaningless
    write_cp(&mut src3, 1024, 4, 0x1, 1, 2);
    write_cp(&mut src3, 1025, 4, 0x1, 1, 2);
    let cp3 = checkpoint::read_checkpoint(&src3.as_slice(), &sb).unwrap();
    assert_eq!(cp3.pack_blk, 1024);

    // Nothing readable → error.
    let src4 = vec![0u8; 2000 * 4096];
    assert!(checkpoint::read_checkpoint(&src4.as_slice(), &sb).is_err());
}

#[test]
fn checkpoint_orphan_blocks() {
    let sb = test_sb();
    let mut src = vec![0u8; 2000 * 4096];
    write_cp(&mut src, 512, 5, 0x1 | 0x2, 2, 3); // ORPHAN_PRESENT
    write_cp(&mut src, 514, 5, 0x1 | 0x2, 2, 3);
    // Orphan block at 513: two inos + sane tail.
    let o = 513 * 4096;
    w32(&mut src[o..], 0, 13);
    w32(&mut src[o..], 4, 14);
    w32(&mut src[o..], 8, 0); // zero ino skipped
    let tail = o + 4096 - 16;
    w16(&mut src[tail..], 4, 0); // blk_addr
    w16(&mut src[tail..], 6, 1); // blk_count
    w32(&mut src[tail..], 8, 2); // entry_count
    let cp = checkpoint::read_checkpoint(&src.as_slice(), &sb).unwrap();
    assert_eq!(cp.orphan_inos, vec![13, 14]);

    // Insane tail (blk_addr ≥ count) → block skipped.
    w16(&mut src[tail..], 4, 99);
    let cp2 = checkpoint::read_checkpoint(&src.as_slice(), &sb).unwrap();
    assert!(cp2.orphan_inos.is_empty());

    // No ORPHAN_PRESENT → no orphan blocks read at all.
    write_cp(&mut src, 512, 5, 0x1, 2, 3);
    write_cp(&mut src, 514, 5, 0x1, 2, 3);
    let cp3 = checkpoint::read_checkpoint(&src.as_slice(), &sb).unwrap();
    assert!(cp3.orphan_inos.is_empty());
}

#[test]
fn checkpoint_bitmap_layouts() {
    let sb = test_sb();
    // LARGE_NAT_BITMAP flag → checksum-prefixed bitmap decode.
    let mut src = vec![0u8; 2000 * 4096];
    write_cp(&mut src, 512, 5, 0x1 | 0x80, 2, 3);
    write_cp(&mut src, 514, 5, 0x1 | 0x80, 2, 3);
    write_cp(&mut src, 1024, 4, 0x1, 1, 2);
    write_cp(&mut src, 1025, 4, 0x1, 1, 2);
    let cp = checkpoint::read_checkpoint(&src.as_slice(), &sb).unwrap();
    assert_eq!(cp.nat_bitmap.len(), 256);
    assert_eq!(cp.sit_bitmap.len(), 64);
}

// ---- crc32.rs ------------------------------------------------------------------

#[test]
fn f2fs_crc_vector() {
    // Continuity: crc(seed, a+b) == crc(crc(seed, a), b).
    let c = crate::crc32::f2fs_crc32(F2FS_MAGIC, b"abc");
    let c2 = crate::crc32::crc32(crate::crc32::f2fs_crc32(F2FS_MAGIC, b"a"), b"bc");
    assert_eq!(c, c2);
}
