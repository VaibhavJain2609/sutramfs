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
    assert_eq!(
        u64::from_le_bytes(entries[0].1[..8].try_into().unwrap()),
        0xAAAA
    );
    assert_eq!(
        u64::from_le_bytes(entries[0].2[..8].try_into().unwrap()),
        0x1111
    );
    assert_eq!(
        u64::from_le_bytes(entries[1].2[..8].try_into().unwrap()),
        0x2222
    );
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

#[test]
fn omap_tombstone_hides_object() {
    use crate::omap::{OmapEntry, OMAP_VAL_DELETED};
    let mut idx = OmapIndex::default();
    idx.insert(OmapEntry {
        oid: 7,
        xid: 3,
        flags: 0,
        paddr: 10,
        size: 4096,
    });
    idx.insert(OmapEntry {
        oid: 7,
        xid: 5,
        flags: OMAP_VAL_DELETED,
        paddr: 0,
        size: 0,
    });
    // At/after the tombstone xid the object is absent — the stale paddr
    // must NOT be resurrected (its block may have been reallocated).
    assert!(idx.lookup(7, 5).is_none());
    assert!(idx.lookup(7, 9).is_none());
    assert_eq!(idx.lookup(7, 4).unwrap().paddr, 10);
}

// ---- coverage: decoder edges -------------------------------------------------

/// Internal (non-leaf) node: `klen`-byte keys + 8-byte child refs.
fn internal_node(children: &[(Vec<u8>, u64)]) -> Vec<u8> {
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::BTREE_NODE | oflags::PHYSICAL).to_le_bytes());
    b[28..32].copy_from_slice(&otype::OMAP.to_le_bytes());
    b[32..34].copy_from_slice(&0u16.to_le_bytes()); // not leaf
    b[34..36].copy_from_slice(&1u16.to_le_bytes()); // level 1
    b[36..40].copy_from_slice(&(children.len() as u32).to_le_bytes());
    b[42..44].copy_from_slice(&(children.len() as u16 * 8).to_le_bytes());
    let klen = children[0].0.len();
    let keys_start = 56 + children.len() * 8;
    let mut kcur = keys_start;
    for (i, (k, child)) in children.iter().enumerate() {
        let e = 56 + i * 8;
        let vend = 4096 - (i + 1) * 8;
        b[e..e + 2].copy_from_slice(&((kcur - keys_start) as u16).to_le_bytes());
        b[e + 2..e + 4].copy_from_slice(&(k.len() as u16).to_le_bytes());
        b[e + 4..e + 6].copy_from_slice(&((4096 - vend) as u16).to_le_bytes());
        b[e + 6..e + 8].copy_from_slice(&8u16.to_le_bytes());
        b[kcur..kcur + k.len()].copy_from_slice(k);
        b[vend..vend + 8].copy_from_slice(&child.to_le_bytes());
        kcur += klen;
    }
    seal(&mut b);
    b
}

#[test]
fn btree_internal_child_refs() {
    let k = |o: u64| {
        let mut v = vec![0u8; 8];
        v.copy_from_slice(&o.to_le_bytes());
        v
    };
    let b = internal_node(&[(k(0xAA), 77), (k(0xBB), 88)]);
    let node = BtreeNode::parse(&b, 0).unwrap();
    assert!(!node.is_leaf());
    let (k, v) = node.child_at(0, 8).unwrap();
    assert_eq!(u64::from_le_bytes(k[..8].try_into().unwrap()), 0xAA);
    assert_eq!(v, 77);
    let (_k, v) = node.child_at(1, 8).unwrap();
    assert_eq!(v, 88);
    // Out of range / ghost entry errors.
    assert!(node.child_at(2, 8).is_err());
    // Child ref whose voff pushes it outside the value area → error.
    let mut b2 = b.clone();
    b2[56 + 8 + 4..56 + 8 + 6].copy_from_slice(&4u16.to_le_bytes()); // voff=4
    b2[..8].fill(0);
    let c = checksum::fletcher64(&b2);
    b2[..8].copy_from_slice(&c.to_le_bytes());
    let node = BtreeNode::parse(&b2, 0).unwrap();
    assert!(node.child_at(1, 8).is_err());
}

#[test]
fn collect_tree_two_level_physical() {
    use crate::fs::{collect_tree, ChildResolver, Ctx};
    // Three-block physical tree: internal root @1, leaves @2/@3.
    let mut img = vec![0u8; 4 * 4096];
    // Non-root leaf with one 16-byte key/value entry.
    let leaf2 = {
        let mut b = vec![0u8; 4096];
        b[24..28].copy_from_slice(&(otype::BTREE_NODE | oflags::PHYSICAL).to_le_bytes());
        b[28..32].copy_from_slice(&otype::OMAP.to_le_bytes());
        b[32..34].copy_from_slice(&0x2u16.to_le_bytes()); // LEAF
        b[36..40].copy_from_slice(&1u32.to_le_bytes());
        b[42..44].copy_from_slice(&8u16.to_le_bytes()); // table_space
                                                        // kvloc @56: koff/klen/voff/vlen.
        b[58..60].copy_from_slice(&16u16.to_le_bytes());
        b[60..62].copy_from_slice(&16u16.to_le_bytes());
        b[62..64].copy_from_slice(&16u16.to_le_bytes());
        b[64..72].copy_from_slice(&0x1234u64.to_le_bytes()); // key oid
        b[4080..4088].copy_from_slice(&0xDEADu64.to_le_bytes()); // val
        seal(&mut b);
        b
    };
    let key16 = |o: u64| {
        let mut k = vec![0u8; 16];
        k[..8].copy_from_slice(&o.to_le_bytes());
        k
    };
    img[4096..8192].copy_from_slice(&internal_node(&[(key16(1), 2), (key16(2), 3)]));
    img[8192..12288].copy_from_slice(&leaf2);
    img[12288..16384].copy_from_slice(&leaf2);
    let mut ctx = Ctx::new(&img, 4096);
    let (leafs, _info) =
        collect_tree(&mut ctx, 1, &ChildResolver::Physical, (16, 16), otype::OMAP).unwrap();
    assert_eq!(leafs.len(), 2);
    // Cycle: a child pointing back at the root is skipped by visited set.
    img[4096..8192].copy_from_slice(&internal_node(&[(key16(1), 1)]));
    let mut ctx = Ctx::new(&img, 4096);
    let (leafs, _) =
        collect_tree(&mut ctx, 1, &ChildResolver::Physical, (16, 16), otype::OMAP).unwrap();
    assert!(leafs.is_empty());
    // Resolve errors: virtual child not in omap / ephemeral not in map.
    let omap = OmapIndex::default();
    let r = ChildResolver::Virtual(&omap, u64::MAX);
    assert!(r.resolve(7).is_err());
    let cp = crate::nx::Checkpoint {
        nx: NxSuperblock::parse(&nx_block(4096, 1000), 0).unwrap(),
        xid: 1,
        map: Vec::new(),
    };
    assert!(ChildResolver::Ephemeral(&cp).resolve(7).is_err());
}

#[test]
fn btree_entry_bounds_errors() {
    // v.off = 0xffff ghost → empty value.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::BTREE_NODE | oflags::PHYSICAL).to_le_bytes());
    b[32..34].copy_from_slice(&3u16.to_le_bytes()); // ROOT|LEAF
    b[36..40].copy_from_slice(&1u32.to_le_bytes());
    b[42..44].copy_from_slice(&8u16.to_le_bytes());
    b[56..58].copy_from_slice(&0u16.to_le_bytes());
    b[58..60].copy_from_slice(&8u16.to_le_bytes());
    b[60..62].copy_from_slice(&0xffffu16.to_le_bytes()); // ghost
    b[62..64].copy_from_slice(&0u16.to_le_bytes());
    b[64..72].copy_from_slice(&0xCCu64.to_le_bytes());
    seal(&mut b);
    let node = BtreeNode::parse(&b, 0).unwrap();
    let (_o, _k, v) = node.entry_at(0, (0, 0)).unwrap();
    assert!(v.is_empty());
    // index beyond nkeys.
    assert!(node.entry_at(1, (0, 0)).is_err());
}

#[test]
fn jrec_decode_variants() {
    use crate::jrec::{decode_record, JRecord};
    // Sibling link.
    let mut k = Vec::new();
    k.extend_from_slice(&(0x200u64 | (5u64 << 60)).to_le_bytes());
    k.extend_from_slice(&0x999u64.to_le_bytes()); // sibling_id
    let mut v = Vec::new();
    v.extend_from_slice(&2u64.to_le_bytes()); // parent
    v.extend_from_slice(&4u16.to_le_bytes()); // name_len incl NUL
    v.extend_from_slice(b"alt\0");
    match decode_record(&k, &v, None).unwrap() {
        JRecord::SiblingLink {
            oid,
            sibling_id,
            parent_id,
            name,
        } => {
            assert_eq!(
                (oid, sibling_id, parent_id, name.as_str()),
                (0x200, 0x999, 2, "alt")
            );
        }
        other => panic!("{other:?}"),
    }
    // Sibling map.
    let k = (0x999u64 | (0xcu64 << 60)).to_le_bytes();
    match decode_record(&k, &0x200u64.to_le_bytes(), None).unwrap() {
        JRecord::SiblingMap {
            sibling_id,
            file_id,
        } => {
            assert_eq!((sibling_id, file_id), (0x999, 0x200));
        }
        other => panic!("{other:?}"),
    }
    // Dir stats.
    let k = (2u64 | (0xau64 << 60)).to_le_bytes();
    let mut v = vec![0u8; 16];
    v[0..8].copy_from_slice(&7u64.to_le_bytes());
    v[8..16].copy_from_slice(&99u64.to_le_bytes());
    assert!(matches!(
        decode_record(&k, &v, None).unwrap(),
        JRecord::DirStats {
            oid: 2,
            num_children: 7,
            total_size: 99
        }
    ));
    // Snap name.
    let mut k = Vec::new();
    k.extend_from_slice(&(0xbu64 << 60).to_le_bytes());
    k.extend_from_slice(&6u16.to_le_bytes());
    k.extend_from_slice(b"snap1\0");
    match decode_record(&k, &0x88u64.to_le_bytes(), None).unwrap() {
        JRecord::SnapName { name, snap_xid } => {
            assert_eq!((name.as_str(), snap_xid), ("snap1", 0x88));
        }
        other => panic!("{other:?}"),
    }
    // Crypto state.
    let k = (0x200u64 | (7u64 << 60)).to_le_bytes();
    assert!(matches!(
        decode_record(&k, &[], None).unwrap(),
        JRecord::CryptoState { oid: 0x200 }
    ));
    // Phys extent: 60-bit len.
    let k = (0x300u64 | (2u64 << 60)).to_le_bytes();
    let mut v = vec![0u8; 20];
    v[0..8].copy_from_slice(&8192u64.to_le_bytes());
    assert!(matches!(
        decode_record(&k, &v, None).unwrap(),
        JRecord::PhysExtent {
            oid: 0x300,
            len: 8192
        }
    ));
    // Unknown type → Other.
    let k = (0x200u64 | (0xdu64 << 60)).to_le_bytes();
    assert!(matches!(
        decode_record(&k, &[], None).unwrap(),
        JRecord::Other { jtype: 0xd, .. }
    ));
    // Inode value too short → error.
    let k = (0x200u64 | (3u64 << 60)).to_le_bytes();
    assert!(decode_record(&k, &[0u8; 40], None).is_err());
    // Key too short → error.
    assert!(decode_record(&[0u8; 4], &[], None).is_err());
}

#[test]
fn jrec_drec_layout_sniffing() {
    use crate::jrec::{decode_record, JRecord};
    // Plain (unhashed) drec key: u16 name_len + name.
    let mut k = Vec::new();
    k.extend_from_slice(&(2u64 | (9u64 << 60)).to_le_bytes());
    k.extend_from_slice(&6u16.to_le_bytes());
    k.extend_from_slice(b"plain\0");
    let mut v = vec![0u8; 18];
    v[0..8].copy_from_slice(&0x42u64.to_le_bytes());
    v[16..18].copy_from_slice(&8u16.to_le_bytes());
    match decode_record(&k, &v, Some(false)).unwrap() {
        JRecord::Drec { name, file_id, .. } => {
            assert_eq!((name.as_str(), file_id), ("plain", 0x42));
        }
        other => panic!("{other:?}"),
    }
    // Sniff: plain key fits exactly → decoded as plain.
    match decode_record(&k, &v, None).unwrap() {
        JRecord::Drec { name, .. } => assert_eq!(name, "plain"),
        other => panic!("{other:?}"),
    }
    // Undecodable name length → error.
    let mut bad = Vec::new();
    bad.extend_from_slice(&(2u64 | (9u64 << 60)).to_le_bytes());
    bad.extend_from_slice(&0xffffu16.to_le_bytes());
    assert!(decode_record(&bad, &v, None).is_err());
}

#[test]
fn xattr_stream_decode() {
    use crate::jrec::{decode_record, JRecord};
    let mut k = Vec::new();
    k.extend_from_slice(&(0x200u64 | (4u64 << 60)).to_le_bytes());
    k.extend_from_slice(&5u16.to_le_bytes());
    k.extend_from_slice(b"attr\0");
    let mut v = Vec::new();
    v.extend_from_slice(&0x0001u16.to_le_bytes()); // STREAM
    v.extend_from_slice(&48u16.to_le_bytes());
    v.extend_from_slice(&0xBEEFu64.to_le_bytes());
    v.extend_from_slice(&[0u8; 40]);
    match decode_record(&k, &v, None).unwrap() {
        JRecord::Xattr {
            oid,
            name,
            flags,
            stream_oid,
            embedded,
            ..
        } => {
            assert_eq!(
                (oid, name.as_str(), flags, stream_oid),
                (0x200, "attr", 1, Some(0xBEEF))
            );
            assert!(embedded.is_none());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn snap_metadata_decode() {
    use crate::jrec::{decode_record, JRecord};
    let k = (7u64 | (1u64 << 60)).to_le_bytes();
    let mut v = vec![0u8; 50];
    v[0..8].copy_from_slice(&0xAAu64.to_le_bytes());
    v[8..16].copy_from_slice(&0xBBu64.to_le_bytes());
    v[16..24].copy_from_slice(&0x11u64.to_le_bytes());
    v[24..32].copy_from_slice(&0x22u64.to_le_bytes());
    v[44..48].copy_from_slice(&3u32.to_le_bytes());
    v[48..50].copy_from_slice(&5u16.to_le_bytes());
    v.extend_from_slice(b"snm1\0");
    match decode_record(&k, &v, None).unwrap() {
        JRecord::SnapMetadata {
            snap_xid,
            extentref_tree_oid,
            sblock_oid,
            flags,
            name,
            ..
        } => {
            assert_eq!(
                (
                    snap_xid,
                    extentref_tree_oid,
                    sblock_oid,
                    flags,
                    name.as_str()
                ),
                (7, 0xAA, 0xBB, 3, "snm1")
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn parse_wrappers_reject_wrong_types() {
    // apsb / omap / spaceman parse wrappers enforce o_type.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::FS).to_le_bytes());
    b[32..36].copy_from_slice(b"XXXX"); // bad magic
    seal(&mut b);
    assert!(crate::apsb::Apsb::parse(&b, 0).is_err());
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::BTREE).to_le_bytes()); // wrong type
    seal(&mut b);
    assert!(crate::apsb::Apsb::parse(&b, 0).is_err());
    assert!(crate::omap::OmapPhys::parse(&b, 0).is_err());
    assert!(crate::spaceman::Spaceman::parse(&b, 0).is_err());
    // omap entry decode needs ≥16+16.
    assert!(crate::omap::OmapEntry::decode(&[0; 8], &[0; 16]).is_err());
    // ObjHdr rejects short blocks.
    assert!(ObjHdr::parse(&[0u8; 20], 0, false).is_err());
    // Storage + encrypted flags.
    let mut b = vec![0u8; 64];
    b[24..28].copy_from_slice(&(otype::OMAP | oflags::EPHEMERAL | oflags::ENCRYPTED).to_le_bytes());
    let h = ObjHdr::parse(&b, 0, false).unwrap();
    assert_eq!(h.storage(), crate::object::Storage::Ephemeral);
    assert!(h.encrypted());
    assert_eq!(h.type_name(), "omap");
    let mut b = vec![0u8; 64];
    b[24..28].copy_from_slice(&(otype::NX_SUPERBLOCK | oflags::PHYSICAL).to_le_bytes());
    let h = ObjHdr::parse(&b, 0, false).unwrap();
    assert_eq!(h.type_name(), "nx_superblock");
}

#[test]
fn nx_parse_edge_errors() {
    // Wrong object type.
    let mut b = nx_block(4096, 1000);
    b[24..28].copy_from_slice(&(otype::OMAP | oflags::EPHEMERAL).to_le_bytes());
    seal(&mut b);
    assert!(NxSuperblock::parse(&b, 0).is_err());
    // Block shorter than declared block_size → truncated.
    let mut b = nx_block(4096, 1000);
    b.truncate(2048);
    assert!(NxSuperblock::parse(&b, 0).is_err());
    // block_count == 0 → corrupt.
    let mut b = nx_block(4096, 0);
    seal(&mut b);
    assert!(NxSuperblock::parse(&b, 0).is_err());
    // Empty fs_oid slots skipped.
    let b = nx_block(4096, 1000);
    let nx = NxSuperblock::parse(&b, 0).unwrap();
    assert_eq!(nx.fs_oids, vec![100]);
}

#[test]
fn detect_confidence_ladder() {
    use sutram_fs::DetectConfidence;
    // Valid sealed block → Certain.
    let b = nx_block(4096, 1000);
    assert_eq!(crate::nx::detect(&b), DetectConfidence::Certain);
    // Corrupt checksum → Medium (magic + sane geometry, no valid cksum).
    let mut b = nx_block(4096, 1000);
    b[100] ^= 0xFF;
    assert_eq!(crate::nx::detect(&b), DetectConfidence::Medium);
    // Bad block size → Low.
    let mut b = nx_block(4096, 1000);
    b[36..40].copy_from_slice(&999u32.to_le_bytes());
    seal(&mut b);
    assert_eq!(crate::nx::detect(&b), DetectConfidence::Low);
    // No magic → None.
    assert_eq!(crate::nx::detect(&vec![0u8; 4096]), DetectConfidence::None);
    // Tiny source → None.
    assert_eq!(crate::nx::detect(&vec![0u8; 64]), DetectConfidence::None);
}

#[test]
fn fletcher64_short_block() {
    // < 8 bytes → checksum of empty payload.
    assert_eq!(
        checksum::fletcher64(&[0u8; 4]),
        checksum::fletcher64_payload(&[])
    );
}

#[test]
fn xfields_bounds() {
    use crate::jrec::parse_xfields;
    assert!(parse_xfields(&[0u8; 3]).is_empty());
    // num_exts * 4 exceeds buffer → empty.
    let mut b = vec![0u8; 8];
    b[0..2].copy_from_slice(&100u16.to_le_bytes());
    assert!(parse_xfields(&b).is_empty());
    // Field data past end → truncated iteration.
    let mut b = vec![0u8; 12];
    b[0..2].copy_from_slice(&1u16.to_le_bytes());
    b[4] = 8;
    b[6..8].copy_from_slice(&64u16.to_le_bytes()); // size runs past buf
    assert!(parse_xfields(&b).is_empty());
}

#[test]
fn btree_parse_edge_cases() {
    // Smaller than the node header.
    assert!(BtreeNode::parse(&[0u8; 40], 0).is_err());
    // Not a btree node.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&otype::NX_SUPERBLOCK.to_le_bytes());
    seal(&mut b);
    assert!(BtreeNode::parse(&b, 0).is_err());
    // otype::BTREE (the tree object itself) is accepted.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&otype::BTREE.to_le_bytes());
    b[32..34].copy_from_slice(&0x1u16.to_le_bytes()); // ROOT
    seal(&mut b);
    assert!(BtreeNode::parse(&b, 0).is_ok());
    // ToC collides with the footer (root): table_space extends past vals_end.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&otype::BTREE_NODE.to_le_bytes());
    b[32..34].copy_from_slice(&0x3u16.to_le_bytes()); // ROOT|LEAF
    b[36..40].copy_from_slice(&1u32.to_le_bytes());
    b[42..44].copy_from_slice(&0xFF00u16.to_le_bytes()); // table_space len
    seal(&mut b);
    assert!(BtreeNode::parse(&b, 0).is_err());
    // Non-root node: info() is None; fixed sizes fall back to caller's.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::BTREE_NODE | oflags::PHYSICAL).to_le_bytes());
    b[32..34].copy_from_slice(&0x2u16.to_le_bytes()); // LEAF
    seal(&mut b);
    let node = BtreeNode::parse(&b, 0).unwrap();
    assert!(node.info().is_none());
}

#[test]
fn btree_entry_at_bounds() {
    // Key extending past the value area → error.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::BTREE_NODE | oflags::PHYSICAL).to_le_bytes());
    b[32..34].copy_from_slice(&0x3u16.to_le_bytes()); // ROOT|LEAF
    b[36..40].copy_from_slice(&1u32.to_le_bytes());
    b[42..44].copy_from_slice(&8u16.to_le_bytes());
    b[56..58].copy_from_slice(&0u16.to_le_bytes()); // koff
    b[58..60].copy_from_slice(&0xFF00u16.to_le_bytes()); // klen runs past vals_end
    b[60..62].copy_from_slice(&16u16.to_le_bytes());
    b[62..64].copy_from_slice(&8u16.to_le_bytes());
    seal(&mut b);
    let node = BtreeNode::parse(&b, 0).unwrap();
    assert!(node.entry_at(0, (0, 0)).is_err());
    // Value offset beyond the value area → error.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::BTREE_NODE | oflags::PHYSICAL).to_le_bytes());
    b[32..34].copy_from_slice(&0x3u16.to_le_bytes());
    b[36..40].copy_from_slice(&1u32.to_le_bytes());
    b[42..44].copy_from_slice(&8u16.to_le_bytes());
    b[56..58].copy_from_slice(&0u16.to_le_bytes());
    b[58..60].copy_from_slice(&8u16.to_le_bytes());
    b[60..62].copy_from_slice(&0xFFF0u16.to_le_bytes()); // voff → vstart underflow
    b[62..64].copy_from_slice(&8u16.to_le_bytes());
    seal(&mut b);
    let node = BtreeNode::parse(&b, 0).unwrap();
    assert!(node.entry_at(0, (0, 0)).is_err());
    // vend > vals_end (voff small) → error.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::BTREE_NODE | oflags::PHYSICAL).to_le_bytes());
    b[32..34].copy_from_slice(&0x3u16.to_le_bytes());
    b[36..40].copy_from_slice(&1u32.to_le_bytes());
    b[42..44].copy_from_slice(&8u16.to_le_bytes());
    b[56..58].copy_from_slice(&0u16.to_le_bytes());
    b[58..60].copy_from_slice(&8u16.to_le_bytes());
    b[60..62].copy_from_slice(&2u16.to_le_bytes()); // voff=2 → vend past vals_end
    b[62..64].copy_from_slice(&8u16.to_le_bytes());
    seal(&mut b);
    let node = BtreeNode::parse(&b, 0).unwrap();
    assert!(node.entry_at(0, (0, 0)).is_err());
}

// ---------------------------------------------------------------------------
// Additional defensive-arm coverage
// ---------------------------------------------------------------------------

#[test]
fn obj_hdr_edges() {
    use crate::object::Storage;
    // Shorter than the 32-byte object header.
    assert!(ObjHdr::parse(&[0u8; 16], 0, false).is_err());
    // Checksum enforcement.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&otype::BTREE_NODE.to_le_bytes());
    seal(&mut b);
    assert!(ObjHdr::parse(&b, 0, true).is_ok());
    b[64] ^= 0xFF;
    assert!(ObjHdr::parse(&b, 0, true).is_err());
    // Storage classes + encrypted flag.
    let mk = |otype: u32| {
        let mut b = vec![0u8; 4096];
        b[24..28].copy_from_slice(&otype.to_le_bytes());
        ObjHdr::parse(&b, 0, false).unwrap()
    };
    assert_eq!(mk(otype::OMAP | oflags::EPHEMERAL).storage(), Storage::Ephemeral);
    assert_eq!(mk(otype::OMAP | oflags::PHYSICAL).storage(), Storage::Physical);
    assert_eq!(mk(otype::FSTREE).storage(), Storage::Virtual);
    assert!(mk(otype::OMAP | oflags::ENCRYPTED).encrypted());
    // type_name for every code this parser knows + the fallback.
    let named = |code: u32| {
        let mut b = vec![0u8; 4096];
        b[24..28].copy_from_slice(&code.to_le_bytes());
        ObjHdr::parse(&b, 0, false).unwrap().type_name()
    };
    assert_eq!(named(otype::NX_SUPERBLOCK), "nx_superblock");
    assert_eq!(named(otype::BTREE), "btree");
    assert_eq!(named(otype::BTREE_NODE), "btree_node");
    assert_eq!(named(otype::SPACEMAN), "spaceman");
    assert_eq!(named(otype::OMAP), "omap");
    assert_eq!(named(otype::CHECKPOINT_MAP), "checkpoint_map");
    assert_eq!(named(otype::FS), "apfs_superblock");
    assert_eq!(named(otype::FSTREE), "fs_tree");
    assert_eq!(named(otype::SNAPMETATREE), "snapmeta_tree");
    assert_eq!(named(0xDEAD), "unknown");
}

/// One-entry leaf-node block with caller-controlled ToC fields.
fn leaf_node(koff: u16, klen: u16, voff: u16, vlen: u16) -> Vec<u8> {
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::BTREE_NODE | oflags::PHYSICAL).to_le_bytes());
    b[32..34].copy_from_slice(&0x3u16.to_le_bytes()); // ROOT|LEAF
    b[36..40].copy_from_slice(&1u32.to_le_bytes());
    b[42..44].copy_from_slice(&8u16.to_le_bytes()); // toc len
    b[56..58].copy_from_slice(&koff.to_le_bytes());
    b[58..60].copy_from_slice(&klen.to_le_bytes());
    b[60..62].copy_from_slice(&voff.to_le_bytes());
    b[62..64].copy_from_slice(&vlen.to_le_bytes());
    seal(&mut b);
    b
}

#[test]
fn btree_parse_error_arms() {
    // ToC offset beyond the block.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&otype::BTREE_NODE.to_le_bytes());
    b[32..34].copy_from_slice(&0x3u16.to_le_bytes());
    b[40..42].copy_from_slice(&0xFFF0u16.to_le_bytes()); // toc_off
    seal(&mut b);
    assert!(BtreeNode::parse(&b, 0).is_err());
    // nkeys exceeding the declared table space.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&otype::BTREE_NODE.to_le_bytes());
    b[32..34].copy_from_slice(&0x3u16.to_le_bytes());
    b[36..40].copy_from_slice(&100u32.to_le_bytes()); // nkeys
    b[42..44].copy_from_slice(&8u16.to_le_bytes()); // tiny table
    seal(&mut b);
    assert!(BtreeNode::parse(&b, 0).is_err());
    // ToC index beyond nkeys.
    let b = leaf_node(0, 8, 8, 8);
    let node = BtreeNode::parse(&b, 0).unwrap();
    assert!(node.entry_at(7, (0, 0)).is_err());
    // Ghost entry (voff = BTOFF_INVALID) → empty value.
    let b = leaf_node(0, 4, 0xFFFF, 8);
    let node = BtreeNode::parse(&b, 0).unwrap();
    let (_, k, v) = node.entry_at(0, (0, 0)).unwrap();
    assert_eq!(k.len(), 4);
    assert!(v.is_empty());
    // Value offset underflow.
    let b = leaf_node(0, 4, 0xF000, 8);
    let node = BtreeNode::parse(&b, 0).unwrap();
    assert!(node.entry_at(0, (0, 0)).is_err());
}

#[test]
fn btree_child_at_error_arms() {
    use crate::jrec;
    let _ = jrec::ROOT_DIR_INODE;
    // Internal node with a ghost entry → "internal entry is a ghost".
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::BTREE_NODE | oflags::PHYSICAL).to_le_bytes());
    b[34..36].copy_from_slice(&1u16.to_le_bytes()); // level 1, not leaf
    b[36..40].copy_from_slice(&1u32.to_le_bytes());
    b[42..44].copy_from_slice(&8u16.to_le_bytes());
    b[56..58].copy_from_slice(&0u16.to_le_bytes()); // koff
    b[58..60].copy_from_slice(&8u16.to_le_bytes()); // klen
    b[60..62].copy_from_slice(&0xFFFFu16.to_le_bytes()); // voff ghost
    b[62..64].copy_from_slice(&8u16.to_le_bytes());
    seal(&mut b);
    let node = BtreeNode::parse(&b, 0).unwrap();
    assert!(node.child_at(0, 8).is_err());
    // Child key beyond the value area.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::BTREE_NODE | oflags::PHYSICAL).to_le_bytes());
    b[34..36].copy_from_slice(&1u16.to_le_bytes());
    b[36..40].copy_from_slice(&1u32.to_le_bytes());
    b[42..44].copy_from_slice(&8u16.to_le_bytes());
    b[56..58].copy_from_slice(&0xFFF0u16.to_le_bytes()); // koff
    b[58..60].copy_from_slice(&64u16.to_le_bytes()); // klen runs off
    b[60..62].copy_from_slice(&8u16.to_le_bytes());
    b[62..64].copy_from_slice(&8u16.to_le_bytes());
    seal(&mut b);
    let node = BtreeNode::parse(&b, 0).unwrap();
    assert!(node.child_at(0, 8).is_err());
    // Child offset underflow (voff > vals_end).
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::BTREE_NODE | oflags::PHYSICAL).to_le_bytes());
    b[34..36].copy_from_slice(&1u16.to_le_bytes());
    b[36..40].copy_from_slice(&1u32.to_le_bytes());
    b[42..44].copy_from_slice(&8u16.to_le_bytes());
    b[56..58].copy_from_slice(&0u16.to_le_bytes());
    b[58..60].copy_from_slice(&8u16.to_le_bytes());
    b[60..62].copy_from_slice(&0x8000u16.to_le_bytes()); // voff >> vals_end
    b[62..64].copy_from_slice(&8u16.to_le_bytes());
    seal(&mut b);
    let node = BtreeNode::parse(&b, 0).unwrap();
    assert!(node.child_at(0, 8).is_err());
}

#[test]
fn btree_fixed_kv_fallback_arms() {
    // A non-root FIXED_KV node uses the caller's sizes (no footer).
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&(otype::BTREE_NODE | oflags::PHYSICAL).to_le_bytes());
    b[28..32].copy_from_slice(&otype::OMAP.to_le_bytes());
    b[32..34].copy_from_slice(&(0x0002u16 | 0x0004).to_le_bytes()); // LEAF|FIXED
    b[36..40].copy_from_slice(&1u32.to_le_bytes());
    b[42..44].copy_from_slice(&4u16.to_le_bytes()); // 1 x kvoff_t
    b[56..58].copy_from_slice(&0u16.to_le_bytes()); // koff
    b[58..60].copy_from_slice(&16u16.to_le_bytes()); // voff → [4080..4096]
    // key 16 B at keys_start (60+4=60? keys_start=56+4=60); val 16 B before block end.
    let ks = 60usize;
    b[ks..ks + 16].copy_from_slice(&[0xAAu8; 16]);
    b[4096 - 16..].copy_from_slice(&[0xBBu8; 16]);
    seal(&mut b);
    let node = BtreeNode::parse(&b, 0).unwrap();
    let (_off, k, v) = node.entry_at(0, (16, 16)).unwrap();
    assert_eq!(k.len(), 16);
    assert_eq!(v.len(), 16);
}

#[test]
fn omap_decode_and_insert_arms() {
    use crate::omap::{OmapEntry, OmapPhys};
    assert!(OmapEntry::decode(&[0u8; 8], &[0u8; 16]).is_err());
    assert!(OmapEntry::decode(&[0u8; 16], &[0u8; 8]).is_err());
    // Insert ordering: equal xid replaces position (binary_search Ok arm).
    let mut idx = OmapIndex::default();
    let e = |xid: u64, paddr: u64| OmapEntry {
        oid: 7,
        xid,
        flags: 0,
        size: 4096,
        paddr,
    };
    idx.insert(e(3, 30));
    idx.insert(e(1, 10)); // out-of-order → Err(pos) arm
    idx.insert(e(1, 11)); // dup xid → Ok(pos) arm
    assert_eq!(idx.record_count, 3);
    assert_eq!(idx.lookup(7, 2).unwrap().paddr, 10);
    assert_eq!(idx.lookup(7, 5).unwrap().paddr, 30);
    // Wrong o_type rejected.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&otype::FSTREE.to_le_bytes());
    assert!(OmapPhys::parse(&b, 0).is_err());
}

#[test]
fn nx_parse_error_arms() {
    // Not an NXSB object.
    let mut b = nx_block(4096, 64);
    b[24..28].copy_from_slice(&otype::OMAP.to_le_bytes());
    seal(&mut b);
    assert!(NxSuperblock::parse(&b, 0).is_err());
    // Missing NXSB magic.
    let mut b = nx_block(4096, 64);
    b[32..36].fill(0);
    seal(&mut b);
    assert!(NxSuperblock::parse(&b, 0).is_err());
    // Absurd block size.
    let mut b = nx_block(4096, 64);
    b[36..40].copy_from_slice(&3u32.to_le_bytes());
    seal(&mut b);
    assert!(NxSuperblock::parse(&b, 0).is_err());
    // Declared block size exceeds the buffer → truncated.
    let mut b = nx_block(8192, 64);
    b.truncate(4096);
    assert!(NxSuperblock::parse(&b, 0).is_err());
    // block_count == 0.
    let mut b = nx_block(4096, 0);
    seal(&mut b);
    assert!(NxSuperblock::parse(&b, 0).is_err());
    // Zeroed fs_oid entries are skipped.
    let mut b = nx_block(4096, 64);
    b[180..184].copy_from_slice(&2u32.to_le_bytes()); // max_fs = 2
    b[184..192].copy_from_slice(&0u64.to_le_bytes()); // slot 0 empty
    b[192..200].copy_from_slice(&0x77u64.to_le_bytes());
    seal(&mut b);
    let nx = NxSuperblock::parse(&b, 0).unwrap();
    assert_eq!(nx.fs_oids, vec![0x77]);
    // Non-contiguous descriptor area flag.
    let mut b = nx_block(4096, 64);
    b[104..108].copy_from_slice(&0x8000_0008u32.to_le_bytes());
    seal(&mut b);
    let nx = NxSuperblock::parse(&b, 0).unwrap();
    assert!(!nx.xp_desc_contiguous);
}

#[test]
fn nx_read_block0_and_detect_arms() {
    use sutram_fs::DetectConfidence;
    // Tiny source → truncated.
    assert!(NxSuperblock::read_block0(&vec![0u8; 64]).is_err());
    // No magic at all.
    let mut img = vec![0u8; 8192];
    assert!(NxSuperblock::read_block0(&img).is_err());
    // Magic but bad block size → read_block0 errors, detect → Low.
    img[32..36].copy_from_slice(&crate::nx::NX_MAGIC.to_le_bytes());
    img[36..40].copy_from_slice(&3u32.to_le_bytes());
    assert!(NxSuperblock::read_block0(&img).is_err());
    assert_eq!(crate::nx::detect(&img), DetectConfidence::Low);
    // Good block size, block_count 0 → detect Low.
    img[36..40].copy_from_slice(&4096u32.to_le_bytes());
    assert_eq!(crate::nx::detect(&img), DetectConfidence::Low);
    // Valid superblock, bad checksum → Medium.
    let mut img = nx_block(4096, 64);
    img.resize(8192, 0);
    img[64] ^= 0xA5;
    assert_eq!(crate::nx::detect(&img), DetectConfidence::Medium);
    // Physical-storage nxsb → High (not ephemeral).
    let mut img = nx_block(4096, 64);
    img.resize(8192, 0);
    img[24..28].copy_from_slice(&(otype::NX_SUPERBLOCK | oflags::PHYSICAL).to_le_bytes());
    seal(&mut img[..4096]);
    assert_eq!(crate::nx::detect(&img), DetectConfidence::High);
    // uuid_be on a short buffer.
    assert!(crate::nx::uuid_be(&[0u8; 8], 0).is_none());
    assert!(crate::nx::uuid_be(&[0xABu8; 16], 0).is_some());
}

#[test]
fn apsb_spaceman_type_errors() {
    use crate::apsb::Apsb;
    use crate::spaceman::Spaceman;
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&otype::OMAP.to_le_bytes());
    assert!(Apsb::parse(&b, 0).is_err());
    assert!(Spaceman::parse(&b, 0).is_err());
    // Right type, missing APSB magic.
    let mut b = vec![0u8; 4096];
    b[24..28].copy_from_slice(&otype::FS.to_le_bytes());
    assert!(Apsb::parse(&b, 0).is_err());
}

#[test]
fn jrec_decode_error_arms() {
    use crate::jrec::xtype;
    // Key shorter than j_key_t.
    assert!(jrec::decode_record(&[0u8; 4], &[], None).is_err());
    // Inode value under the 92-byte fixed header.
    let k = (3u64 << 60 | 7).to_le_bytes();
    assert!(jrec::decode_record(&k, &[0u8; 40], None).is_err());
    // Drec: forced hashed layout, undecodable name field.
    let k = (9u64 << 60 | 2).to_le_bytes();
    assert!(jrec::decode_record(&k, &[0u8; 24], Some(true)).is_err());
    // Drec: forced plain layout, undecodable.
    assert!(jrec::decode_record(&k, &[0u8; 24], Some(false)).is_err());
    // Drec: auto-sniff, undecodable both ways.
    assert!(jrec::decode_record(&k, &[0u8; 24], None).is_err());
    // Drec: plain layout decodes (u16 name_len + name + NUL).
    let mut k = (9u64 << 60 | 2).to_le_bytes().to_vec();
    k.extend_from_slice(&4u16.to_le_bytes()); // name_len incl NUL
    k.extend_from_slice(b"abc\0");
    let mut v = vec![0u8; 24];
    v[..8].copy_from_slice(&200u64.to_le_bytes());
    let rec = jrec::decode_record(&k, &v, None).unwrap();
    match rec {
        jrec::JRecord::Drec {
            name,
            file_id,
            name_hash,
            ..
        } => {
            assert_eq!(name, "abc");
            assert_eq!(file_id, 200);
            assert!(name_hash.is_none());
        }
        _ => panic!("expected drec"),
    }
    // Drec with a DREC_SIBLING_ID xfield → sibling_id populated.
    let mut v = vec![0u8; 18];
    v[..8].copy_from_slice(&200u64.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes()); // xf num
    v.extend_from_slice(&0u16.to_le_bytes());
    v.push(xtype::DREC_SIBLING_ID);
    v.push(0);
    v.extend_from_slice(&8u16.to_le_bytes());
    v.extend_from_slice(&0xBEEFu64.to_le_bytes());
    let rec = jrec::decode_record(&k, &v, None).unwrap();
    match rec {
        jrec::JRecord::Drec { sibling_id, .. } => assert_eq!(sibling_id, Some(0xBEEF)),
        _ => panic!("expected drec"),
    }
    // Xattr: neither stream nor embedded flag and no data → embedded None.
    let mut k = (4u64 << 60 | 200).to_le_bytes().to_vec();
    k.extend_from_slice(&3u16.to_le_bytes());
    k.extend_from_slice(b"x\0");
    let v = [0u8; 8];
    match jrec::decode_record(&k, &v, None).unwrap() {
        jrec::JRecord::Xattr {
            embedded,
            stream_oid,
            ..
        } => {
            assert!(embedded.is_none());
            assert!(stream_oid.is_none());
        }
        _ => panic!("expected xattr"),
    }
    // Sibling link record.
    let mut k = (5u64 << 60 | 200).to_le_bytes().to_vec();
    k.extend_from_slice(&500u64.to_le_bytes());
    let mut v = vec![0u8; 10];
    v[..8].copy_from_slice(&300u64.to_le_bytes());
    v[8..10].copy_from_slice(&6u16.to_le_bytes());
    v.extend_from_slice(b"alias\0");
    match jrec::decode_record(&k, &v, None).unwrap() {
        jrec::JRecord::SiblingLink {
            sibling_id,
            parent_id,
            name,
            ..
        } => {
            assert_eq!(sibling_id, 500);
            assert_eq!(parent_id, 300);
            assert_eq!(name, "alias");
        }
        _ => panic!("expected sibling link"),
    }
}

#[test]
fn jrec_xfield_and_dstream_arms() {
    use crate::jrec::xtype;
    // parse_xfields: too short / oversized count / out-of-bounds size.
    assert!(jrec::parse_xfields(&[0u8; 2]).is_empty());
    let mut b = vec![0u8; 8];
    b[..2].copy_from_slice(&100u16.to_le_bytes()); // num*4 > len
    assert!(jrec::parse_xfields(&b).is_empty());
    let mut b = vec![0u8; 12];
    b[..2].copy_from_slice(&1u16.to_le_bytes());
    b[4] = 8; // type
    b[6..8].copy_from_slice(&0xFFFu16.to_le_bytes()); // size runs off
    assert!(jrec::parse_xfields(&b).is_empty());
    // Inode xfields: INO_NAME + a short DSTREAM (<40 B → None) + unknown.
    let mut blob = vec![0u8; 92];
    blob.extend_from_slice(&3u16.to_le_bytes()); // 3 xfields
    blob.extend_from_slice(&0u16.to_le_bytes());
    for (t, sz) in [(xtype::INO_NAME, 4u16), (xtype::INO_DSTREAM, 8u16), (0xEEu8, 4u16)] {
        blob.push(t);
        blob.push(0);
        blob.extend_from_slice(&sz.to_le_bytes());
    }
    blob.extend_from_slice(b"nm\0\0\0\0\0"); // 8-aligned name
    blob.extend_from_slice(&[0u8; 8]); // short dstream
    blob.extend_from_slice(&[0u8; 4]); // unknown payload
    let iv = jrec::InodeVal::decode(&blob).unwrap();
    assert_eq!(iv.xf_name.as_deref(), Some("nm"));
    assert!(iv.dstream.is_none());
    // Snap metadata record with a name_len beyond the value tail.
    let k = (1u64 << 60 | 5).to_le_bytes();
    let mut v = vec![0u8; 50];
    v[48..50].copy_from_slice(&0xFFFFu16.to_le_bytes());
    match jrec::decode_record(&k, &v, None).unwrap() {
        jrec::JRecord::SnapMetadata { name, .. } => assert!(name.is_empty()),
        _ => panic!("expected snap metadata"),
    }
}
