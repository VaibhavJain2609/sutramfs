//! Unit tests for the format primitives (synthetic-image integration tests
//! live in `tests/forensic.rs`).

use crate::btree::BtreeNode;
use crate::checksum;
use crate::jrec;
use crate::nx::NxSuperblock;
use crate::object::{oflags, otype, ObjHdr};
use crate::omap::OmapIndex;

/// Compute a valid Fletcher-64 for `block` in place (checksum field = 0).
fn seal(block: &mut [u8]) {
    block[..8].fill(0);
    let c = checksum::fletcher64(block);
    block[..8].copy_from_slice(&c.to_le_bytes());
}

#[test]
fn fletcher64_roundtrip() {
    let mut b = vec![0u8; 4096];
    for (i, byte) in b.iter_mut().enumerate().skip(8) {
        *byte = (i % 251) as u8;
    }
    seal(&mut b);
    assert!(checksum::verify(&b));
}

#[test]
fn fletcher64_detects_corruption() {
    let mut b = vec![0u8; 4096];
    b[100] = 0xAA;
    seal(&mut b);
    b[100] ^= 0x01;
    assert!(!checksum::verify(&b));
    // Zero / all-ones checksums are rejected sentinels.
    b[..8].fill(0);
    assert!(!checksum::verify(&b));
}

#[test]
fn fletcher64_rejects_odd_lengths() {
    assert!(!checksum::verify(&[0u8; 100]));
    assert!(!checksum::verify(&[]));
}

#[test]
fn object_header_decode() {
    let mut b = vec![0u8; 4096];
    b[8..16].copy_from_slice(&42u64.to_le_bytes()); // oid
    b[16..24].copy_from_slice(&7u64.to_le_bytes()); // xid
    let t = otype::OMAP | oflags::PHYSICAL;
    b[24..28].copy_from_slice(&t.to_le_bytes());
    seal(&mut b);
    let h = ObjHdr::parse(&b, 0, true).unwrap();
    assert_eq!(h.oid, 42);
    assert_eq!(h.xid, 7);
    assert_eq!(h.type_code(), otype::OMAP);
    assert_eq!(h.storage(), crate::object::Storage::Physical);
}

#[test]
fn object_header_checksum_enforced() {
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::NX_SUPERBLOCK | oflags::PHYSICAL).to_le_bytes());
    // Deliberately bad checksum; verify=true must fail, false must pass.
    let assert_err = ObjHdr::parse(&b, 0, true);
    assert!(assert_err.is_err());
    assert!(ObjHdr::parse(&b, 0, false).is_ok());
}

/// Minimal 4096-byte NX superblock for parse-level tests.
fn nx_block(block_size: u32, block_count: u64) -> Vec<u8> {
    let mut b = vec![0u8; block_size as usize];
    b[24..28].copy_from_slice(&(otype::NX_SUPERBLOCK | oflags::EPHEMERAL).to_le_bytes());
    b[32..36].copy_from_slice(b"NXSB");
    b[36..40].copy_from_slice(&block_size.to_le_bytes());
    b[40..48].copy_from_slice(&block_count.to_le_bytes());
    b[96..104].copy_from_slice(&0u64.to_le_bytes()); // next_oid
    b[104..108].copy_from_slice(&8u32.to_le_bytes()); // xp_desc_blocks
    b[108..112].copy_from_slice(&16u32.to_le_bytes()); // xp_data_blocks
    b[112..120].copy_from_slice(&1u64.to_le_bytes()); // xp_desc_base
    b[120..128].copy_from_slice(&9u64.to_le_bytes()); // xp_data_base
    b[128..132].copy_from_slice(&1u32.to_le_bytes()); // xp_desc_next
    b[132..136].copy_from_slice(&1u32.to_le_bytes()); // xp_data_next
    b[136..140].copy_from_slice(&1u32.to_le_bytes()); // xp_desc_index
    b[140..144].copy_from_slice(&1u32.to_le_bytes()); // xp_desc_len
    b[144..148].copy_from_slice(&1u32.to_le_bytes()); // xp_data_index
    b[148..152].copy_from_slice(&1u32.to_le_bytes()); // xp_data_len
    b[152..160].copy_from_slice(&1u64.to_le_bytes()); // spaceman_oid
    b[160..168].copy_from_slice(&2u64.to_le_bytes()); // omap_oid
    b[180..184].copy_from_slice(&1u32.to_le_bytes()); // max_file_systems
    b[184..192].copy_from_slice(&100u64.to_le_bytes()); // fs_oid[0]
    seal(&mut b);
    b
}

#[test]
fn nx_parse() {
    let b = nx_block(4096, 1000);
    let nx = NxSuperblock::parse(&b, 0).unwrap();
    assert_eq!(nx.block_size, 4096);
    assert_eq!(nx.block_count, 1000);
    assert_eq!(nx.omap_oid, 2);
    assert_eq!(nx.fs_oids, vec![100]);
    assert!(nx.xp_desc_contiguous);
}

#[test]
fn nx_rejects_bad_magic() {
    let mut b = nx_block(4096, 1000);
    b[32] = b'X';
    seal(&mut b);
    assert!(NxSuperblock::parse(&b, 0).is_err());
}

#[test]
fn nx_rejects_bad_block_size() {
    let mut b = nx_block(4096, 1000);
    b[36..40].copy_from_slice(&1234u32.to_le_bytes());
    seal(&mut b);
    assert!(NxSuperblock::parse(&b, 0).is_err());
}

#[test]
fn btree_node_leaf_decode() {
    // Build a 2-entry leaf node with variable kvloc table.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::BTREE_NODE | oflags::PHYSICAL).to_le_bytes());
    b[28..32].copy_from_slice(&otype::FSTREE.to_le_bytes());
    b[32..34].copy_from_slice(&2u16.to_le_bytes()); // BTNODE_LEAF
    b[36..40].copy_from_slice(&2u32.to_le_bytes()); // nkeys
    b[42..44].copy_from_slice(&16u16.to_le_bytes()); // table_space len = 2×8
    // ToC at offset 56: two kvloc_t entries {koff u16, klen u16, voff u16, vlen u16}
    b[56..58].copy_from_slice(&0u16.to_le_bytes());
    b[58..60].copy_from_slice(&8u16.to_le_bytes());
    b[60..62].copy_from_slice(&24u16.to_le_bytes()); // val0 at vals_end-24
    b[62..64].copy_from_slice(&16u16.to_le_bytes());
    b[64..66].copy_from_slice(&8u16.to_le_bytes());
    b[66..68].copy_from_slice(&8u16.to_le_bytes());
    b[68..70].copy_from_slice(&8u16.to_le_bytes()); // val1 at vals_end-8
    b[70..72].copy_from_slice(&8u16.to_le_bytes());
    // Keys at keys_start=72; values grow down from vals_end=4096.
    b[72..80].copy_from_slice(&0xAAAAu64.to_le_bytes()); // key0
    b[80..88].copy_from_slice(&0xBBBBu64.to_le_bytes()); // key1
    b[4072..4080].copy_from_slice(&0x1111u64.to_le_bytes()); // val0
    b[4088..4096].copy_from_slice(&0x2222u64.to_le_bytes()); // val1
    seal(&mut b);

    let node = BtreeNode::parse(&b, 0).unwrap();
    assert!(node.is_leaf());
    let entries: Vec<_> = node.entries((0, 0)).collect::<Result<_, _>>().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(u64::from_le_bytes(entries[0].1[..8].try_into().unwrap()), 0xAAAA);
    assert_eq!(u64::from_le_bytes(entries[0].2[..8].try_into().unwrap()), 0x1111);
    assert_eq!(u64::from_le_bytes(entries[1].2[..8].try_into().unwrap()), 0x2222);
}

#[test]
fn btree_rejects_bad_toc() {
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::BTREE_NODE | oflags::PHYSICAL).to_le_bytes());
    b[32..34].copy_from_slice(&1u16.to_le_bytes());
    b[36..40].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // absurd nkeys
    seal(&mut b);
    assert!(BtreeNode::parse(&b, 0).is_err());
}

#[test]
fn omap_lookup_xid_bounded() {
    let mut idx = OmapIndex::default();
    // oid 100 seen at xids 3, 7, 12 → paddr 10, 20, 30.
    for (xid, paddr) in [(3u64, 10u64), (7, 20), (12, 30)] {
        idx.insert(crate::omap::OmapEntry {
            oid: 100,
            xid,
            flags: 0,
            paddr,
            size: 4096,
        });
    }
    assert!(idx.lookup(100, 2).is_none());
    assert_eq!(idx.lookup(100, 3).unwrap().paddr, 10);
    assert_eq!(idx.lookup(100, 6).unwrap().paddr, 10);
    assert_eq!(idx.lookup(100, 7).unwrap().paddr, 20);
    assert_eq!(idx.lookup(100, 11).unwrap().paddr, 20);
    assert_eq!(idx.lookup(100, u64::MAX).unwrap().paddr, 30);
}

#[test]
fn jrec_key_split() {
    // oid 0x123, type 0x9 (dir-rec) packed into the top nibble.
    let key = (0x9u64 << jrec::OBJ_TYPE_SHIFT) | 0x123;
    let (oid, jt) = jrec::split_key(&key.to_le_bytes()).unwrap();
    assert_eq!(oid, 0x123);
    assert_eq!(jt, 0x9);
}
