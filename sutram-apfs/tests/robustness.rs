//! Mutated-image tests: every corruption keeps the Fletcher-64 valid unless
//! the point is specifically to break it, so each mount exercises one
//! defensive arm rather than the checksum gate.
//!
//! Block map reminder (see tests/common/mod.rs):
//!   0      nxsb block-0 copy (xid 2)
//!   1,3    descriptor nxsb copies (xid 1, xid 2)
//!   2,4    checkpoint maps (xid 1, xid 2)
//!   9..14  xid-1 objects (cmap, cmap_tree, apsb, vomap, vomap_tree, fstree)
//!   15..20 xid-2 objects (same order)
//!   21     spaceman, 22 snap-meta tree, 30+ file data

mod common;

use std::io::Read;
use std::sync::Arc;

use common::*;
use sutram_apfs::ApfsParser;
use sutram_fs::{EntryKind, FileSystem, FsEntry, FsEntryStatus, FsParser, MountOptions, RecoveryState};
use sutram_io::ByteSource;

fn mount_img(img: Vec<u8>) -> Box<dyn FileSystem> {
    let src: Arc<dyn ByteSource> = Arc::new(img);
    ApfsParser.mount(src).expect("mount should succeed")
}

fn mount_opts(img: Vec<u8>, opts: MountOptions) -> sutram_fs::Result<Box<dyn FileSystem>> {
    let src: Arc<dyn ByteSource> = Arc::new(img);
    ApfsParser.mount_with(src, &opts)
}

/// Walk collecting (live entries, errors) without panicking on Err items.
fn collect(fs: &dyn FileSystem) -> (Vec<FsEntry>, Vec<String>) {
    let mut ok = Vec::new();
    let mut err = Vec::new();
    for r in fs.walk() {
        match r {
            Ok(e) => ok.push(e),
            Err(e) => err.push(e.to_string()),
        }
    }
    (ok, err)
}

fn blk(img: &mut [u8], b: u64) -> &mut [u8] {
    &mut img[b as usize * BS..b as usize * BS + BS]
}

fn w16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn w64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

// ---------------------------------------------------------------------------
// collect_tree warning arms — all in one mount
// ---------------------------------------------------------------------------

#[test]
fn btree_warning_arms_surface_in_walk() {
    let mut img = build_image(false);
    // fs-tree root (blk 20): wrong o_subtype → "expected" warning.
    w32(blk(&mut img, 20), 28, 0x99);
    // … plus a btree_info node_size that disagrees with the container.
    w32(blk(&mut img, 20), BS - 36, 8192);
    // volume-omap tree (blk 19): leaf claims level 2.
    w16(blk(&mut img, 19), 34, 2);
    // … and its btree_info drops the physical-storage bit.
    w32(blk(&mut img, 19), BS - 40, 0);
    // container-omap tree (blk 16): flagged OBJ_ENCRYPTED.
    w32(blk(&mut img, 16), 24, 0x0003 | 0x1000_0000 | 0x8000_0000);
    // Reseal all touched blocks.
    for b in [16u64, 19, 20] {
        seal(blk(&mut img, b));
    }
    let fs = mount_img(img);
    let (entries, errs) = collect(fs.as_ref());
    assert!(entries.len() > 5, "entries: {}", entries.len());
    let joined = errs.join("\n");
    assert!(joined.contains("o_subtype"), "{joined}");
    assert!(joined.contains("node_size"), "{joined}");
    assert!(joined.contains("level"), "{joined}");
    assert!(joined.contains("storage bit"), "{joined}");
    assert!(joined.contains("OBJ_ENCRYPTED"), "{joined}");
}

#[test]
fn omap_encrypted_val_warns() {
    let mut img = build_image(false);
    // blk 19 = volume omap tree leaf, single entry; the 16-byte omap_val_t
    // sits just before the 40-byte root footer → flags at BS-56.
    w32(blk(&mut img, 19), BS - 56, 0x4); // OMAP_VAL_ENCRYPTED
    seal(blk(&mut img, 19));
    let fs = mount_img(img);
    let (_, errs) = collect(fs.as_ref());
    assert!(
        errs.iter().any(|e| e.contains("OMAP_VAL_ENCRYPTED")),
        "{errs:?}"
    );
}

// ---------------------------------------------------------------------------
// Internal nodes, cycles, resolution failures
// ---------------------------------------------------------------------------

/// Serialize a one-level internal btree node (root, not leaf).
fn internal_node(oid: u64, xid: u64, subtype: u32, children: &[(u64, u64)]) -> Vec<u8> {
    let mut b = vec![0u8; BS];
    w64(&mut b, 8, oid);
    w64(&mut b, 16, xid);
    w32(&mut b, 24, 0x0003); // BTREE_NODE, virtual storage
    w32(&mut b, 28, subtype);
    w16(&mut b, 32, 0x0001); // ROOT
    w16(&mut b, 34, 1); // level 1
    w32(&mut b, 36, children.len() as u32);
    w16(&mut b, 42, (children.len() * 8) as u16); // kvloc ToC
    let keys_start = 56 + children.len() * 8;
    let vals_end = BS - 40;
    for (i, (key, child)) in children.iter().enumerate() {
        let e = 56 + i * 8;
        let voff = vals_end - (vals_end - (i + 1) * 8); // = (i+1)*8
        w16(&mut b, e, (i * 8) as u16); // koff
        w16(&mut b, e + 2, 8); // klen
        w16(&mut b, e + 4, voff as u16); // voff
        w16(&mut b, e + 6, 8); // vlen
        w64(&mut b, keys_start + i * 8, *key);
        w64(&mut b, vals_end - (i + 1) * 8, *child);
    }
    w32(&mut b, BS - 40, 0); // btree_info flags (virtual)
    w32(&mut b, BS - 36, BS as u32);
    seal(&mut b);
    b
}

#[test]
fn fstree_cycle_and_bad_child_roll_back() {
    let mut img = build_image(false);
    // Internal fs-tree root: child[0] = itself (cycle → visited set),
    // child[1] = an oid the volume omap doesn't know (resolve error).
    let node = internal_node(
        O_FSTREE,
        2,
        0x000e,
        &[(1, O_FSTREE), (2, 0x999)],
    );
    blk(&mut img, 20).copy_from_slice(&node);
    let fs = mount_img(img);
    let (entries, errs) = collect(fs.as_ref());
    // The xid-2 view failed; the mount rolled back to the xid-1 checkpoint.
    assert!(!errs.is_empty());
    assert!(
        entries.iter().any(|e| e.path.ends_with("old.txt")),
        "rolled-back view should contain old.txt: {:?}",
        entries.iter().map(|e| &e.path).collect::<Vec<_>>()
    );
}

#[test]
fn leaf_toc_corruption_rolls_back() {
    let mut img = build_image(false);
    // First ToC entry of the live fs tree: absurd key length.
    w16(blk(&mut img, 20), 58, 0xFF00);
    seal(blk(&mut img, 20));
    let fs = mount_img(img);
    let (entries, errs) = collect(fs.as_ref());
    assert!(!errs.is_empty());
    assert!(entries.iter().any(|e| e.path.ends_with("old.txt")));
}

// ---------------------------------------------------------------------------
// Mount-path error arms
// ---------------------------------------------------------------------------

#[test]
fn omap_tree_oid_missing_from_cpmap_rolls_back() {
    let mut img = build_image(false);
    // cpmap@2 without the O_CMAP_TREE entry → ephemeral resolve fails.
    blk(&mut img, 4).copy_from_slice(&cpmap_block(2, &[(O_CMAP, 15), (O_SPACEMAN, 21)]));
    let fs = mount_img(img);
    let (entries, errs) = collect(fs.as_ref());
    assert!(errs.iter().any(|e| e.contains("omap tree oid")), "{errs:?}");
    assert!(entries.iter().any(|e| e.path.ends_with("old.txt")));
}

#[test]
fn omap_paddr_fallback_path() {
    let mut img = build_image(false);
    // Container omap oid not in the checkpoint map → treated as a paddr.
    // Point nx_omap_oid at a physical omap object we plant at block 40 whose
    // tree (physical, at 41) resolves O_APSB → block 17.
    blk(&mut img, 4).copy_from_slice(&cpmap_block(2, &[(O_SPACEMAN, 21)]));
    w64(blk(&mut img, 3), 160, 40); // nx_omap_oid = 40
    seal(blk(&mut img, 3));
    blk(&mut img, 40).copy_from_slice(&omap_obj(40, 2, 41, false));
    let leaf = btree_leaf(
        41,
        2,
        0x000b, // OMAP subtype
        &[(
            {
                let mut k = vec![0u8; 16];
                w64(&mut k, 0, O_APSB);
                w64(&mut k, 8, 2);
                k
            },
            omap_val(17),
        )],
        Some((16, 16)),
        BT_PHYS,
    );
    blk(&mut img, 41).copy_from_slice(&leaf);
    let fs = mount_img(img);
    let (entries, errs) = collect(fs.as_ref());
    assert!(entries.len() > 5, "errs: {errs:?}");
}

#[test]
fn empty_fs_oid_table_rolls_back() {
    let mut img = build_image(false);
    w32(blk(&mut img, 3), 180, 0); // max_file_systems = 0 in the xid-2 nxsb
    seal(blk(&mut img, 3));
    let fs = mount_img(img);
    let (entries, errs) = collect(fs.as_ref());
    assert!(errs.iter().any(|e| e.contains("nx_fs_oid")), "{errs:?}");
    assert!(entries.iter().any(|e| e.path.ends_with("old.txt")));
}

#[test]
fn root_tree_oid_missing_rolls_back() {
    let mut img = build_image(false);
    w64(blk(&mut img, 17), 136, 0x999); // apsb.root_tree_oid
    seal(blk(&mut img, 17));
    let fs = mount_img(img);
    let (entries, errs) = collect(fs.as_ref());
    assert!(!errs.is_empty());
    assert!(entries.iter().any(|e| e.path.ends_with("old.txt")));
}

#[test]
fn corrupt_vol_omap_rolls_back() {
    let mut img = build_image(false);
    corrupt_block(&mut img, 18); // xid-2 volume omap object
    let fs = mount_img(img);
    let (entries, errs) = collect(fs.as_ref());
    assert!(!errs.is_empty());
    assert!(entries.iter().any(|e| e.path.ends_with("old.txt")));
}

#[test]
fn corrupt_prior_view_warns_but_mounts() {
    let mut img = build_image(false);
    corrupt_block(&mut img, 14); // xid-1 fs tree
    let fs = mount_img(img);
    let (entries, errs) = collect(fs.as_ref());
    assert!(!errs.is_empty());
    // Nothing deleted can be recovered without the prior generation.
    assert!(
        entries
            .iter()
            .all(|e| !matches!(e.status, FsEntryStatus::Deleted { .. })),
        "expected no deleted entries"
    );
}

#[test]
fn corrupt_spaceman_falls_back_to_free_ranges() {
    let mut img = build_image(false);
    corrupt_block(&mut img, 21);
    let fs = mount_img(img);
    let info = fs.info();
    assert!(info.free_blocks.is_some());
    assert!(!info.meta.contains_key("sm_block_size"));
    let (_, errs) = collect(fs.as_ref());
    assert!(errs.iter().any(|e| e.contains("checksum")), "{errs:?}");
}

#[test]
fn malformed_descriptor_slot_reported() {
    let mut img = build_image(false);
    corrupt_block(&mut img, 1); // nxsb@xid1
    let fs = mount_img(img);
    let info = fs.info();
    // Zeroed tail slots are already malformed; slot 0 (the xid-1 nxsb)
    // joins the list.
    assert!(
        info.meta
            .get("malformed_desc_slots")
            .map(String::as_str)
            .unwrap_or("")
            .starts_with("0,"),
        "meta: {:?}",
        info.meta.get("malformed_desc_slots")
    );
}

#[test]
fn both_generations_corrupt_fails() {
    let mut img = build_image(false);
    corrupt_block(&mut img, 14);
    corrupt_block(&mut img, 20);
    let src: Arc<dyn ByteSource> = Arc::new(img);
    assert!(ApfsParser.mount(src).is_err());
}

#[test]
fn truncated_descriptor_area_errors() {
    let img = build_image(false);
    // Only block 0 + a sliver → descriptor scan finds nothing.
    let src: Arc<dyn ByteSource> = Arc::new(img[..BS + 10].to_vec());
    assert!(ApfsParser.mount(src).is_err());
    // Truncated right after the live fs tree: the spaceman block read
    // fails → warning + free-space fallback, but the mount succeeds.
    let mut img = build_image(false);
    img.truncate(21 * BS);
    let fs = mount_img(img);
    let info = fs.info();
    assert_eq!(info.meta.get("checkpoint_xid").map(String::as_str), Some("2"));
    assert!(!info.meta.contains_key("sm_block_size"));
    assert!(info.free_blocks.is_some());
}

#[test]
fn strict_mount_aborts_on_checkpoint_error() {
    let mut img = build_image(false);
    corrupt_block(&mut img, 20);
    let opts = MountOptions {
        strict: true,
        ..MountOptions::default()
    };
    assert!(mount_opts(img, opts).is_err());
}

// ---------------------------------------------------------------------------
// Record-injection walk arms
// ---------------------------------------------------------------------------

fn inode(oid: u64, mode: u16, private_id: u64, xfields: &[Vec<u8>]) -> (Vec<u8>, Vec<u8>) {
    (
        jhdr(oid, JT_INODE).to_le_bytes().to_vec(),
        inode_val(ROOT_DIR, private_id, mode, 1, xfields),
    )
}

#[test]
fn record_injection_covers_walk_arms() {
    // drec with a sibling-id xfield; inode carrying the private/sparse flags;
    // a FIFO-mode inode (EntryKind::Other); a drec with no inode; a slack
    // record whose last extent is shorter than the slack; dir stats on a
    // subdirectory; a snap-metadata record misplaced in the fs tree; an
    // extent whose physical block is past the image tail.
    let mut priv_inode = inode_val(ROOT_DIR, 610, 0o100644, 1, &[
        xblob(8, &xf_dstream(4096, 4096, 0)),
        xblob(13, &128u64.to_le_bytes()), // sparse_bytes
        xblob(1, &0x55u64.to_le_bytes()), // snap_xid
    ]);
    priv_inode[48..56].copy_from_slice(&(0x201u64).to_le_bytes()); // APFS_PRIVATE|IS_SPARSE
    let sib_drec_val = {
        let mut v = Vec::new();
        v.extend_from_slice(&200u64.to_le_bytes()); // file_id
        v.extend_from_slice(&0x55A0_0000u64.to_le_bytes());
        v.extend_from_slice(&0x8u16.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes()); // xf num
        v.extend_from_slice(&0u16.to_le_bytes());
        v.push(1); // DREC_SIBLING_ID
        v.push(0);
        v.extend_from_slice(&8u16.to_le_bytes());
        v.extend_from_slice(&0xF00Du64.to_le_bytes());
        v
    };
    let mut sib_key = jhdr(ROOT_DIR, JT_DREC).to_le_bytes().to_vec();
    sib_key.extend_from_slice(&(((0x11u32 & 0x3f_ffff) << 10) | 8).to_le_bytes());
    sib_key.extend_from_slice(b"sibdrec\0");

    let extra_b: Vec<(Vec<u8>, Vec<u8>)> = vec![
        // Directory loop: loopa's parent is loopb and vice versa.
        inode(600, 0o040755, 600, &[]),
        inode(601, 0o040755, 601, &[]),
        drec_kv(601, "loopa", 600, 0x4, 0x1),
        drec_kv(600, "loopb", 601, 0x4, 0x2),
        // Private + sparse inode.
        (jhdr(610, JT_INODE).to_le_bytes().to_vec(), priv_inode),
        drec_kv(ROOT_DIR, "priv.bin", 610, 0x8, 0x3),
        extent_kv(610, 0, BS as u64, 38, 0),
        // No-dstream inode → size from extents; flagged + encrypted extent.
        inode(611, 0o100644, 611, &[]),
        drec_kv(ROOT_DIR, "nostream.bin", 611, 0x8, 0x4),
        extent_kv(611, 0, BS as u64, 39, 0xDEAD),
        // FIFO inode → EntryKind::Other.
        inode(612, 0o010600, 612, &[]),
        drec_kv(ROOT_DIR, "fifo", 612, 0x8, 0x5),
        // drec without a matching inode.
        drec_kv(ROOT_DIR, "ghost.txt", 9999, 0x8, 0x6),
        // Slack larger than the last extent.
        inode(
            613,
            0o100644,
            613,
            &[xblob(8, &xf_dstream(100, 3 * BS as u64, 0))],
        ),
        drec_kv(ROOT_DIR, "slack.bin", 613, 0x8, 0x7),
        extent_kv(613, 0, BS as u64, 42, 0),
        extent_kv(613, BS as u64, BS as u64, 43, 0),
        extent_kv(613, 2 * BS as u64, BS as u64, 44, 0),
        // dir_stats on the docs subdirectory.
        dir_stats_kv(300, 7, 12345),
        // SNAP_METADATA record inside the fs tree (collected but unused).
        snap_meta_kv(9, 23, "in-fstree"),
        // Extent pointing past the image tail.
        inode(
            614,
            0o100644,
            614,
            &[xblob(8, &xf_dstream(4096, 4096, 0))],
        ),
        drec_kv(ROOT_DIR, "beyond.bin", 614, 0x8, 0x9),
        extent_kv(614, 0, BS as u64, 200, 0),
        // drec with a sibling-id xfield.
        (sib_key, sib_drec_val),
    ];
    // Deleted-generation extras: a deleted directory, a deleted inode with
    // no dstream (size from extents), zeroed timestamps.
    let extra_a: Vec<(Vec<u8>, Vec<u8>)> = vec![
        inode(510, 0o040755, 510, &[]),
        drec_kv(ROOT_DIR, "deldir", 510, 0x4, 0xa),
        inode(511, 0o100644, 511, &[]),
        drec_kv(ROOT_DIR, "nodata.bin", 511, 0x8, 0xb),
        extent_kv(511, 0, BS as u64, 45, 0),
    ];
    let fs = mount_img(build_image_with(false, &extra_b, &extra_a));
    let (entries, errs) = collect(fs.as_ref());
    let by_path = |p: &str| entries.iter().find(|e| e.path == p).unwrap_or_else(|| panic!("missing {p}"));

    // Orphaned cyclic directories keep their drec names in the orphan bucket.
    assert!(entries.iter().any(|e| e.name == "loopa"));
    assert!(entries.iter().any(|e| e.name == "loopb"));
    // Private/sparse meta.
    let p = by_path("/priv.bin");
    assert_eq!(p.meta.get("apfs_private").map(String::as_str), Some("true"));
    assert_eq!(p.meta.get("sparse").map(String::as_str), Some("true"));
    assert_eq!(p.meta.get("sparse_bytes").map(String::as_str), Some("128"));
    assert_eq!(p.meta.get("inode_snap_xid").map(String::as_str), Some("85"));
    // Extent flags + crypto id + size-from-extents.
    let n = by_path("/nostream.bin");
    assert_eq!(n.size, BS as u64);
    assert_eq!(
        n.meta.get("extent_0_crypto_id").map(String::as_str),
        Some("0xdead")
    );
    assert_eq!(n.meta.get("extent_encrypted").map(String::as_str), Some("true"));
    // fifo → Other kind.
    assert_eq!(by_path("/fifo").kind, EntryKind::Other);
    // drec with no inode → note.
    let g = by_path("/ghost.txt");
    assert_eq!(g.kind, EntryKind::Other);
    assert!(g.meta.contains_key("note"));
    // Slack beyond the last extent → offset falls back to extent start.
    let s = by_path("/slack.bin");
    assert_eq!(
        s.meta.get("slack_len").map(String::as_str),
        Some((3 * BS as u64 - 100).to_string()).as_deref()
    );
    // dir_stats on /docs.
    let d = by_path("/docs");
    assert_eq!(d.meta.get("dir_stats_children").map(String::as_str), Some("7"));
    // sibling-id drec meta.
    let sd = entries.iter().find(|e| e.name == "sibdrec").expect("sibdrec");
    assert_eq!(sd.meta.get("sibling_id").map(String::as_str), Some("0xf00d"));
    // Deleted entries from the prior generation.
    assert!(
        entries
            .iter()
            .filter(|e| matches!(e.status, FsEntryStatus::Deleted { .. }))
            .count()
            >= 4
    );
    assert!(entries.iter().any(|e| e.path.ends_with("deldir")));
    // Read the out-of-image extent → zeros, not a hang.
    let b = by_path("/beyond.bin");
    let mut r = fs.read_file(b).unwrap();
    let mut buf = vec![0u8; 16];
    let n = r.read(&mut buf).unwrap();
    assert!(n <= 16);
    let _ = errs; // warnings may or may not be present
}

// ---------------------------------------------------------------------------
// Parser-level accessors and snapshot/volume mounts
// ---------------------------------------------------------------------------

#[test]
fn snapshot_mount_bounds_resolution() {
    let img = build_image(false);
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = ApfsParser
        .mount_snapshot(src, &MountOptions::default(), 1)
        .expect("snapshot mount");
    let info = fs.info();
    assert_eq!(info.meta.get("snapshot_view_xid").map(String::as_str), Some("1"));
    assert_eq!(info.meta.get("checkpoint_xid").map(String::as_str), Some("1"));
    let (entries, _) = collect(fs.as_ref());
    // In the xid-1 view old.txt is still live and nothing is deleted.
    assert!(entries.iter().any(|e| e.path.ends_with("old.txt")));
    assert!(
        entries
            .iter()
            .all(|e| !matches!(e.status, FsEntryStatus::Deleted { .. }))
    );
}

#[test]
fn mount_volume_and_accessors() {
    let img = build_image(false);
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = ApfsParser
        .mount_volume(src, &MountOptions::default(), 0)
        .expect("volume mount");
    let (entries, _) = collect(fs.as_ref());
    assert!(entries.len() > 5);
    // Out-of-range index clamps to the last volume.
    let src: Arc<dyn ByteSource> = Arc::new(build_image(false));
    let fs = ApfsParser
        .mount_volume(src, &MountOptions::default(), 9)
        .expect("clamped volume mount");
    assert_eq!(fs.info().meta.get("volume_index").map(String::as_str), Some("0"));
}

#[test]
fn sealed_volume_meta() {
    let mut img = build_image(false);
    // SEALED_VOLUME | CASE_INSENSITIVE in the xid-2 apsb.
    w64(blk(&mut img, 17), 56, 0x21);
    seal(blk(&mut img, 17));
    let fs = mount_img(img);
    assert_eq!(fs.info().meta.get("sealed").map(String::as_str), Some("true"));
    let (entries, _) = collect(fs.as_ref());
    assert!(entries
        .iter()
        .filter(|e| matches!(e.status, FsEntryStatus::Live))
        .all(|e| e.meta.contains_key("volume_sealed")));
}

#[test]
fn plain_drec_layout_falls_back_to_sniff() {
    let mut img = build_image(false);
    w64(blk(&mut img, 17), 56, 0); // clear CASE_INSENSITIVE → Plain layout
    seal(blk(&mut img, 17));
    let fs = mount_img(img);
    // Hashed keys decode via the sniff fallback anyway.
    let (entries, _) = collect(fs.as_ref());
    assert!(entries.len() > 5);
}

#[test]
fn deleted_recovery_states() {
    let fs = mount_img(build_image(false));
    let (entries, _) = collect(fs.as_ref());
    let deleted: Vec<_> = entries
        .iter()
        .filter(|e| matches!(e.status, FsEntryStatus::Deleted { .. }))
        .collect();
    assert!(deleted.len() >= 3);
    // old.txt: extent block 32 reclaimed → partial.
    let old = deleted.iter().find(|e| e.path.ends_with("old.txt")).unwrap();
    match old.status {
        FsEntryStatus::Deleted {
            recovery: RecoveryState::PartiallyOverwritten { .. },
        } => {}
        ref other => panic!("old.txt recovery: {other:?}"),
    }
    // empty.bin: no extents at all → Unrecoverable.
    let empty = deleted
        .iter()
        .find(|e| e.path.ends_with("empty.bin"))
        .unwrap();
    assert!(matches!(
        empty.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unrecoverable
        }
    ));
}
