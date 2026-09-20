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
