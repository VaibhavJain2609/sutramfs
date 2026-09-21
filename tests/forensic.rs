//! End-to-end forensic tests on synthetic XFS v5 images.
//!
//! The builder in `common/` produces structurally real images (BE fields,
//! valid CRC32C, real btree/dir3 layouts), so these tests exercise the
//! whole pipeline: mount → AG scan → inobt/finobt → inode decode →
//! directories → recovery analysis → read_file.

mod common;

use std::io::Read;
use std::sync::Arc;

use common::*;
use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsParser, FileSystem, MountOptions,
    RecoveryState,
};
use sutram_io::{into_arc, ByteSource};
use sutram_xfs::XfsParser;

const T_FILE: u8 = 1;
const T_DIR: u8 = 2;
const T_SYMLINK: u8 = 7;

fn src(img: Vec<u8>) -> Arc<dyn ByteSource> {
    into_arc(img)
}

fn mount(img: Vec<u8>) -> Box<dyn FileSystem> {
    XfsParser.mount(src(img)).expect("mount")
}

/// Build the canonical test image.
///
/// AG0 layout (4 KiB blocks):
///   blk0  sb+agf+agi+agfl; blk1 bnobt; blk2 inobt; blk3 finobt
///   blk4-7   inode chunk inos 64..127 (live set + orphan)
///   blk8-11  inode chunk inos 128..191 (deleted set + unlinked)
///   blk16-23 internal log (XLOG magic at blk16)
///   blk24 hello.txt data, blk25 subdir XDB3, blk26 inner.txt,
///   blk27 pic.png data, blk32-33 deleted file data
fn test_image() -> Vec<u8> {
    let mut i = Img::new();

    // --- live tree ---
    // root dir (ino 64), shortform: hello.txt, subdir, link, pic.png
    let root_sf = sf_dir(
        ROOTINO,
        &[
            ("hello.txt", 65, T_FILE),
            ("subdir", 66, T_DIR),
            ("link", 67, T_SYMLINK),
            ("pic.png", 70, T_FILE),
        ],
    );
    i.write_inode(
        ROOTINO,
        &InodeSpec {
            mode: 0o40755,
            format: 1, // local
            size: root_sf.len() as u64,
            nlink: 3,
            inline_data: root_sf,
            ..Default::default()
        },
    );
    // hello.txt → blk24, "hello world\n" (12 B)
    let hello = b"hello world\n";
    i.write_data(24, hello);
    i.write_inode(
        65,
        &InodeSpec {
            format: 2,
            size: hello.len() as u64,
            nblocks: 1,
            extents: vec![ExtentSpec {
                fileoff: 0,
                fsb: 24,
                len: 1,
                unwritten: false,
            }],
            ..Default::default()
        },
    );
    // subdir (ino 66) → XDB3 block dir at blk25
    i.write_block_dir(
        25,
        66,
        &[
            (".", 66, T_DIR),
            ("..", ROOTINO, T_DIR),
            ("inner.txt", 68, T_FILE),
        ],
        &[("oldname.txt", 130, T_FILE)], // freed residue
    );
    i.write_inode(
        66,
        &InodeSpec {
            mode: 0o40755,
            format: 2,
            size: BS as u64,
            nlink: 2,
            nblocks: 1,
            extents: vec![ExtentSpec {
                fileoff: 0,
                fsb: 25,
                len: 1,
                unwritten: false,
            }],
            ..Default::default()
        },
    );
    // link (ino 67) → local symlink
    i.write_inode(
        67,
        &InodeSpec {
            mode: 0o120777,
            format: 1,
            size: 10,
            inline_data: b"/hello.txt".to_vec(),
            ..Default::default()
        },
    );
    // inner.txt (ino 68) → blk26
    let inner = b"inner file payload";
    i.write_data(26, inner);
    i.write_inode(
        68,
        &InodeSpec {
            format: 2,
            size: inner.len() as u64,
            nblocks: 1,
            extents: vec![ExtentSpec {
                fileoff: 0,
                fsb: 26,
                len: 1,
                unwritten: false,
            }],
            ..Default::default()
        },
    );
    // orphan ino 69: allocated, unreachable (no dirent points here).
    i.write_inode(
        69,
        &InodeSpec {
            format: 2,
            size: 42,
            nblocks: 1,
            extents: vec![ExtentSpec {
                fileoff: 0,
                fsb: 34,
                len: 1,
                unwritten: false,
            }],
            ..Default::default()
        },
    );
    // pic.png (ino 70) → blk27 with real PNG signature (magic verdict).
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    png.extend_from_slice(&[0u8; 100]);
    i.write_data(27, &png);
    i.write_inode(
        70,
        &InodeSpec {
            format: 2,
            size: png.len() as u64,
            nblocks: 1,
            extents: vec![ExtentSpec {
                fileoff: 0,
                fsb: 27,
                len: 1,
                unwritten: false,
            }],
            ..Default::default()
        },
    );

    // --- deleted / recovery set (chunk 128) ---
    // ino 130: deleted file, extents still free → Intact.
    i.write_data(32, b"DELETED-DATA-1");
    i.write_data(33, b"DELETED-DATA-2");
    i.write_inode(
        130,
        &InodeSpec {
            format: 2,
            size: 5000,
            nlink: 0,
            nblocks: 2,
            extents: vec![ExtentSpec {
                fileoff: 0,
                fsb: 32,
                len: 2,
                unwritten: false,
            }],
            ..Default::default()
        },
    );
    // ino 131: deleted file, extent reallocated to hello.txt (blk24)
    // → Unrecoverable.
    i.write_inode(
        131,
        &InodeSpec {
            format: 2,
            size: 4096,
            nlink: 0,
            nblocks: 1,
            extents: vec![ExtentSpec {
                fileoff: 0,
                fsb: 24,
                len: 1,
                unwritten: false,
            }],
            ..Default::default()
        },
    );
    // ino 128: unlinked-but-allocated in agi_unlinked bucket 0
    // (ino%64=0) — regression: bucket 0 must be walked, not skipped.
    i.write_inode(
        128,
        &InodeSpec {
            format: 2,
            size: 64,
            nlink: 0,
            nblocks: 1,
            next_unlinked: NULLAGINO,
            extents: vec![ExtentSpec {
                fileoff: 0,
                fsb: 36,
                len: 1,
                unwritten: false,
            }],
            ..Default::default()
        },
    );
    // ino 132: unlinked-but-allocated (agi_unlinked bucket 4, ino%64=4).
    i.write_inode(
        132,
        &InodeSpec {
            format: 2,
            size: 100,
            nlink: 0,
            nblocks: 1,
            next_unlinked: NULLAGINO,
            extents: vec![ExtentSpec {
                fileoff: 0,
                fsb: 35,
                len: 1,
                unwritten: false,
            }],
            ..Default::default()
        },
    );

    // inobt: chunk 64 — inos 64-70 allocated, rest free.
    // bits: bit i ↔ ino 64+i; allocated = bit clear in `free`.
    let mut free0 = u64::MAX;
    for ino in 0..7u32 {
        free0 &= !(1 << ino); // 64..=70 allocated
    }
    i.inobt.push(ChunkRec {
        startino: 64,
        freecount: free0.count_ones(),
        free: free0,
    });
    // chunk 128 — 130,131 free w/ residue; 128,132 allocated; rest free.
    let mut free1 = u64::MAX;
    free1 &= !(1 << 0); // ino 128 allocated (unlinked, bucket 0)
    free1 &= !(1 << 4); // ino 132 allocated (unlinked)
    i.inobt.push(ChunkRec {
        startino: 128,
        freecount: free1.count_ones(),
        free: free1,
    });
    // finobt tracks the recently-freed chunk.
    i.finobt.push(ChunkRec {
        startino: 128,
        freecount: free1.count_ones(),
        free: free1,
    });
    i.unlinked[0] = 128; // bucket 0 — was skipped by an off-by-one cursor
    i.unlinked[4] = 132;

    // Free space: everything not in use.
    i.free = vec![(28, 4), (32, 2), (34, 30), (64, 448)];
    i.icount = 64 + 128; // two chunks
    i.ifree = (free0.count_ones() + free1.count_ones()) as u64;

    i.finish()
}

#[test]
fn detect_and_mount() {
    let img = test_image();
    let p = XfsParser;
    let conf = p.detect(src(img.clone()).as_ref());
    assert!(
        conf >= DetectConfidence::High,
        "detect confidence {conf:?} too low"
    );
    let fs = mount(img);
    let info = fs.info();
    assert_eq!(info.fs_type, "XFS v5");
    assert_eq!(info.block_size, 4096);
    assert_eq!(info.total_blocks, AGBLOCKS as u64);
    assert_eq!(info.label.as_deref(), Some("TESTXFS"));
    // Journal flagging.
    let log = info.meta.get("log").expect("log meta");
    assert!(log.contains("internal log"), "log meta: {log}");
    assert!(log.contains("replay not implemented"));
}

#[test]
fn live_tree_and_read() {
    let fs = mount(test_image());
    let entries: Vec<FsEntry> = fs.walk().map(|r| r.expect("walk err")).collect();
    let by_path = |p: &str| entries.iter().find(|e| e.path == p).unwrap_or_else(|| panic!("missing {p}"));
    assert_eq!(by_path("/").kind, EntryKind::Directory);
    let hello = by_path("/hello.txt");
    assert_eq!(hello.kind, EntryKind::File);
    assert_eq!(hello.size, 12);
    assert!(!hello.is_deleted());
    assert_eq!(hello.entry_id, 65);
    // disk offset points at the inode record.
    // ino 65 → chunk at agbno 4, slot 1 → 4*4096 + 256
    assert_eq!(hello.disk_offset, 4 * 4096 + 256);

    let mut r = fs.read_file(hello).unwrap();
    let mut s = String::new();
    r.read_to_string(&mut s).unwrap();
    assert_eq!(s, "hello world\n");

    assert_eq!(by_path("/subdir").kind, EntryKind::Directory);
    let inner = by_path("/subdir/inner.txt");
    let mut buf = Vec::new();
    fs.read_file(inner).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"inner file payload");

    let link = by_path("/link");
    assert_eq!(link.kind, EntryKind::Symlink);
    assert_eq!(
        link.meta.get("symlink_target").map(String::as_str),
        Some("/hello.txt")
    );

    // magic verdict on the PNG.
    let pic = by_path("/pic.png");
    assert!(pic.magic.is_some(), "expected magic verdict on pic.png");

    // allocated ranges populated.
    assert_eq!(hello.allocated_ranges, vec![(24 * 4096, 4096)]);
}

#[test]
fn deleted_inode_recovery() {
    let fs = mount(test_image());
    let entries: Vec<_> = fs.walk().collect::<Result<_, _>>().expect("walk");
    let deleted: Vec<&FsEntry> = entries.iter().filter(|e| e.is_deleted()).collect();
    assert!(!deleted.is_empty(), "no deleted entries emitted");

    // ino 130: extent still free → Intact, data recoverable.
    let d130 = deleted
        .iter()
        .find(|e| e.entry_id == 130)
        .expect("ino 130 deleted entry");
    assert!(
        matches!(d130.status, FsEntryStatus::Deleted { recovery: RecoveryState::Intact }),
        "ino 130 status {:?}",
        d130.status
    );
    assert_eq!(d130.allocated_ranges, vec![(32 * 4096, 4096), (33 * 4096, 4096)]);
    let mut buf = Vec::new();
    fs.read_file(d130).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(&buf[..14], b"DELETED-DATA-1");
    assert!(buf.len() <= 5000);

    // ino 131: extent claimed by live file → Unrecoverable.
    let d131 = deleted
        .iter()
        .find(|e| e.entry_id == 131)
        .expect("ino 131 deleted entry");
    assert!(
        matches!(
            d131.status,
            FsEntryStatus::Deleted {
                recovery: RecoveryState::Unrecoverable
            }
        ),
        "ino 131 status {:?}",
        d131.status
    );
    assert!(
        d131
            .meta
            .values()
            .any(|v| v.contains("reallocated")),
        "expected reallocation note: {:?}",
        d131.meta
    );
}

#[test]
fn stale_dirent_residue() {
    let fs = mount(test_image());
    let entries: Vec<_> = fs.walk().collect::<Result<_, _>>().expect("walk");
    let stale = entries
        .iter()
        .find(|e| e.name == "oldname.txt")
        .expect("residue entry");
    assert!(stale.is_deleted());
    assert_eq!(stale.path, "/subdir/oldname.txt");
    assert_eq!(stale.meta.get("stale_residue").map(String::as_str), Some("dirent"));
    // The inode still has residue → full metadata recovered.
    assert_eq!(stale.entry_id, 130);
}

#[test]
fn unlinked_and_orphan_inodes() {
    let fs = mount(test_image());
    let entries: Vec<_> = fs.walk().collect::<Result<_, _>>().expect("walk");

    let unl = entries
        .iter()
        .find(|e| e.entry_id == 132 && e.is_deleted())
        .expect("unlinked inode 132");
    assert_eq!(unl.meta.get("inode_source").map(String::as_str), Some("agi_unlinked"));

    // Bucket-0 chain head — previously skipped by an off-by-one cursor.
    let unl0 = entries
        .iter()
        .find(|e| e.entry_id == 128 && e.is_deleted())
        .expect("unlinked inode 128 (bucket 0)");
    assert_eq!(
        unl0.meta.get("inode_source").map(String::as_str),
        Some("agi_unlinked")
    );

    let orph = entries
        .iter()
        .find(|e| e.entry_id == 69)
        .expect("orphan inode 69");
    assert!(orph.is_deleted());
    assert_eq!(orph.meta.get("orphan").map(String::as_str), Some("true"));
    assert!(orph.path.starts_with("/$ORPHANED/"));

    // Orphan off → not emitted.
    let fs2 = XfsParser
        .mount_with(
            src(test_image()),
            &MountOptions {
                strict: false,
                check_magic: true,
                include_orphans: false,
            },
        )
        .unwrap();
    assert!(
        !fs2
            .walk()
            .filter_map(|r| r.ok())
            .any(|e| e.entry_id == 69)
    );
}

#[test]
fn free_space_and_unallocated() {
    let fs = mount(test_image());
    let ranges = fs.unallocated_ranges();
    assert_eq!(
        ranges,
        vec![
            (28 * 4096, 4 * 4096),
            (32 * 4096, 2 * 4096),
            (34 * 4096, 30 * 4096),
            (64 * 4096, 448 * 4096)
        ]
    );
}

#[test]
fn lenient_vs_strict_on_corruption() {
    let mut img = test_image();
    // Corrupt a byte inside the inobt leaf (blk2) → CRC fails, but the
    // record bytes still decode (lenient) or mount fails (strict).
    let off = 2 * 4096 + 100;
    img[off] ^= 0xFF;

    // Lenient: entries still walk; error records surface.
    let fs = mount(img.clone());
    let mut errs = 0;
    let mut ok = 0;
    for r in fs.walk() {
        match r {
            Ok(_) => ok += 1,
            Err(_) => errs += 1,
        }
    }
    assert!(errs >= 1, "expected at least one error record");
    assert!(ok >= 5, "expected live entries, got {ok}");

    // Strict: mount still succeeds (sb is fine) but the walk stops on
    // the first error record.
    let strict = XfsParser
        .mount_with(
            src(img),
            &MountOptions {
                strict: true,
                check_magic: true,
                include_orphans: true,
            },
        )
        .unwrap();
    let mut items = 0;
    let mut saw_err = false;
    for r in strict.walk() {
        items += 1;
        if r.is_err() {
            saw_err = true;
        }
    }
    assert!(saw_err);
    assert!(items <= 2, "strict walk should stop early, got {items}");
}

#[test]
fn corrupt_superblock_handling() {
    let mut img = test_image();
    img[10] ^= 0xFF; // inside sb_dblocks → CRC mismatch, geometry plausible
    // Lenient mount tolerates: records sb_crc_ok=false.
    let fs = XfsParser.mount(src(img.clone())).expect("lenient mount");
    assert_eq!(
        fs.info().meta.get("sb_crc_ok").map(String::as_str),
        Some("false")
    );
    // Strict mount fails.
    let r = XfsParser.mount_with(
        src(img),
        &MountOptions {
            strict: true,
            check_magic: true,
            include_orphans: true,
        },
    );
    assert!(r.is_err(), "strict mount should fail on bad sb CRC");
    // Garbage magic → detect None, mount fails.
    let mut img2 = test_image();
    img2[0] = 0;
    assert_eq!(
        XfsParser.detect(src(img2.clone()).as_ref()),
        DetectConfidence::None
    );
    assert!(XfsParser.mount(src(img2)).is_err());
}

#[test]
fn truncation_is_graceful() {
    // Image truncated inside the inode chunk area: parser must return
    // errors, never panic.
    let img = test_image();
    let short = img[..64 * 1024].to_vec();
    let fs = XfsParser.mount(src(short));
    if let Ok(fs) = fs {
        let _n = fs.walk().count(); // must not panic
    } // early rejection is also acceptable
}

#[test]
fn second_btree_level_walked() {
    // Force inobt to two levels: root node at blk2 (IAB3 level 1) with
    // one child leaf at blk3 carrying the chunk record.
    let mut i = Img::new();
    i.write_inode(
        ROOTINO,
        &InodeSpec {
            mode: 0o40755,
            format: 1,
            size: 6,
            inline_data: sf_dir(ROOTINO, &[("a", 65, T_FILE)]),
            ..Default::default()
        },
    );
    i.write_data(24, b"data!\0");
    i.write_inode(
        65,
        &InodeSpec {
            format: 2,
            size: 6,
            extents: vec![ExtentSpec {
                fileoff: 0,
                fsb: 24,
                len: 1,
                unwritten: false,
            }],
            ..Default::default()
        },
    );
    // inobt record for chunk 64 (inos 64..127): bit0,1 allocated.
    let free = !0b11u64;
    i.inobt.push(ChunkRec {
        startino: 64,
        freecount: 62,
        free,
    });
    i.free = vec![(28, 36), (64, 448)];
    let mut img = i.finish();
    // Rewrite blk2 as a level-1 node pointing at a leaf at blk40 (blk40
    // sits inside the bnobt free range — btree blocks aren't claimed via
    // extents so no conflict). blk3 keeps the finobt leaf.
    let blk40 = &mut img[40 * 4096..41 * 4096];
    w32(blk40, 0, IAB3);
    w16(blk40, 4, 0);
    w16(blk40, 6, 1);
    w32(blk40, 8, NULLAGBLOCK);
    w32(blk40, 12, NULLAGBLOCK);
    w64(blk40, 16, 40);
    blk40[32..48].copy_from_slice(&UUID);
    w64(blk40, 48, 0);
    let rec: Vec<u8> = [64u32.to_be_bytes(), 62u32.to_be_bytes()]
        .iter()
        .flat_map(|a| a.iter().copied())
        .chain(free.to_be_bytes())
        .collect();
    blk40[56..56 + 16].copy_from_slice(&rec);
    write_crc(blk40, 52);
    // Node at blk2: IAB3 level 1, 1 rec: key=startino 64, ptr→blk40.
    // Node layout: hdr(56) + keys[maxrecs*4] + ptrs — the pointer area
    // begins after the FULL key area (maxrecs = (4096-56)/8 = 505).
    let maxrecs = (4096 - 56) / (4 + 4);
    let blk2 = &mut img[2 * 4096..3 * 4096];
    blk2.fill(0);
    w32(blk2, 0, IAB3);
    w16(blk2, 4, 1); // level 1 = node
    w16(blk2, 6, 1); // numrecs
    w32(blk2, 8, NULLAGBLOCK);
    w32(blk2, 12, NULLAGBLOCK);
    w64(blk2, 16, 2);
    blk2[32..48].copy_from_slice(&UUID);
    w64(blk2, 48, 0);
    w32(blk2, 56, 64); // key[0] = startino 64
    let ptr_area = 56 + maxrecs * 4;
    w32(blk2, ptr_area, 40); // ptr[0] → agbno 40
    write_crc(blk2, 52);
    // AGF bnobt leaf says blk5 is free — doesn't matter for inobt walk.

    let fs = mount(img);
    let paths: Vec<String> = fs
        .walk()
        .filter_map(|r| r.ok())
        .map(|e| e.path)
        .collect();
    assert!(paths.contains(&"/".to_string()), "{paths:?}");
    assert!(paths.contains(&"/a".to_string()), "{paths:?}");
}
