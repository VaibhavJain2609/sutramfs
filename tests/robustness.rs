//! Fault-injection coverage: corrupt the synthetic image builders in
//! targeted ways to reach the defensive arms — per-AG parse failures,
//! CRC mismatches, residue variants, sparse chunks, bigtime/dev/xattr
//! inode forks and recovery-assessment states the happy path never hits.

mod common;

use std::io::Read;
use std::sync::Arc;

use common::*;
use sutram_fs::{DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsParser, FileSystem, MountOptions, RecoveryState};
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
fn walk(img: Vec<u8>) -> Vec<FsEntry> {
    mount(img).walk().filter_map(|r| r.ok()).collect()
}
fn by_id(entries: &[FsEntry], ino: u64) -> &FsEntry {
    entries
        .iter()
        .find(|e| e.entry_id == ino)
        .unwrap_or_else(|| panic!("missing ino {ino:#x}"))
}

/// Recompute the v5 superblock CRC after patching fields.
fn fix_sb_crc(img: &mut [u8]) {
    img[224..228].fill(0);
    let c = crc32c(0xFFFF_FFFF, 0, &img[..512]);
    img[224..228].copy_from_slice(&(!c).to_le_bytes());
}

/// Recompute a v3 inode's LE CRC after patching fields.
fn fix_ino_crc(img: &mut [u8], ino: u64) {
    let pos = ((ino >> 4) as usize) * BS + ((ino % INOPB as u64) as usize) * ISZ;
    let ib = &mut img[pos..pos + ISZ];
    ib[100..104].fill(0);
    let c = crc32c(0xFFFF_FFFF, 0, ib);
    ib[100..104].copy_from_slice(&(!c).to_le_bytes());
}

fn ino_pos_of(ino: u64) -> usize {
    ((ino >> 4) as usize) * BS + ((ino % INOPB as u64) as usize) * ISZ
}

/// The canonical "weird inodes" image. Chunk 64 inos 64–84 allocated;
/// chunk 128 holds only free slots (ino 130 is garbage residue).
///
/// ```text
/// 64 root(sf)   65 dev    66 big(unwritten+slack)  67 rlink(XSLM)
/// 68 inline(bigtime)      69 xattr-local           70 blkdir(residue)
/// 71 ok.txt(fsb40)        72 empty-ino  73 garbage 74 leak-del(fsb50)
/// 75 empty-del(size0)     76 partial(40 lost,41 free) 77 pastEOF-del
/// 78/79 unlinked pair     80 multidir   81 baddir   82 oobdir
/// 83 rlink-badhdr         84 slink-dev  90 garbage-free 91 empty-free
/// ```
fn weird_image() -> Vec<u8> {
    let mut i = Img::new();

    // Root: block dir at fsb 24 (11 entries don't fit an in-inode sf).
    i.write_block_dir(
        24,
        ROOTINO,
        &[
            (".", ROOTINO, T_DIR),
            ("..", ROOTINO, T_DIR),
            ("dev", 65, T_FILE),
            ("big", 66, T_FILE),
            ("rlink", 67, T_SYMLINK),
            ("rlink2", 83, T_SYMLINK),
            ("slinkdev", 84, T_SYMLINK),
            ("inline", 68, T_FILE),
            ("xattr", 69, T_FILE),
            ("blkdir", 70, T_DIR),
            ("multidir", 80, T_DIR),
            ("baddir", 81, T_DIR),
            ("oobdir", 82, T_DIR),
        ],
        &[],
    );
    i.write_inode(
        ROOTINO,
        &InodeSpec {
            mode: 0o40755,
            format: 2,
            size: BS as u64,
            nlink: 5,
            nblocks: 1,
            extents: vec![ExtentSpec { fileoff: 0, fsb: 24, len: 1, unwritten: false }],
            ..Default::default()
        },
    );

    // 65: char-device inode — FMT_DEV with an rdev in the fork.
    i.write_inode(
        65,
        &InodeSpec {
            mode: 0o20666,
            format: 0,
            nlink: 1,
            ..Default::default()
        },
    );

    // 66: file with an unwritten extent + allocated slack past EOF.
    i.write_data(30, b"BIGHEAD!");
    i.write_inode(
        66,
        &InodeSpec {
            format: 2,
            size: 5000,
            nblocks: 3,
            extents: vec![
                ExtentSpec { fileoff: 0, fsb: 30, len: 2, unwritten: false },
                ExtentSpec { fileoff: 2, fsb: 32, len: 1, unwritten: true },
            ],
            ..Default::default()
        },
    );

    // 67: remote symlink via XSLM block at fsb 33.
    {
        let blk = i.blk_mut(33);
        w32(blk, 0, 0x5853_4C4D); // XSLM
        blk[24..40].copy_from_slice(&UUID);
        blk[56..56 + 12].copy_from_slice(b"/subdir/deep");
        write_crc_be(blk, 4);
    }
    i.write_inode(
        67,
        &InodeSpec {
            mode: 0o120777,
            format: 2,
            size: 12,
            nblocks: 1,
            extents: vec![ExtentSpec { fileoff: 0, fsb: 33, len: 1, unwritten: false }],
            ..Default::default()
        },
    );

    // 83: remote symlink whose block lacks the XSLM magic.
    i.write_data(34, b"not-a-symlink-block!");
    i.write_inode(
        83,
        &InodeSpec {
            mode: 0o120777,
            format: 2,
            size: 10,
            nblocks: 1,
            extents: vec![ExtentSpec { fileoff: 0, fsb: 34, len: 1, unwritten: false }],
            ..Default::default()
        },
    );

    // 84: symlink with FMT_DEV fork → "symlink has no data".
    i.write_inode(
        84,
        &InodeSpec {
            mode: 0o120777,
            format: 0,
            size: 8,
            ..Default::default()
        },
    );

    // 68: inline file — flags2 patched to BIGTIME below.
    i.write_inode(
        68,
        &InodeSpec {
            format: 1,
            size: 4,
            inline_data: b"tiny".to_vec(),
            ..Default::default()
        },
    );

    // 69: file with a LOCAL attr fork — patched below.
    i.write_inode(
        69,
        &InodeSpec {
            format: 1,
            size: 4,
            inline_data: b"data".to_vec(),
            ..Default::default()
        },
    );

    // 70: block directory — live ok.txt + four residue variants.
    i.write_block_dir(
        25,
        70,
        &[
            (".", 70, T_DIR),
            ("..", ROOTINO, T_DIR),
            ("ok.txt", 71, T_FILE),
        ],
        &[
            ("realloc.txt", 65, T_FILE),   // ino reallocated to a live entry
            ("empty.txt", 72, T_FILE),     // ino slot parses but has no residue
            ("scrubbed.txt", 73, T_FILE),  // ino slot unreadable
            ("faraway.txt", 100, T_FILE),  // ino slot zeroed → unreadable
        ],
    );
    i.write_inode(
        70,
        &InodeSpec {
            mode: 0o40755,
            format: 2,
            size: BS as u64,
            nlink: 2,
            nblocks: 1,
            extents: vec![ExtentSpec { fileoff: 0, fsb: 25, len: 1, unwritten: false }],
            ..Default::default()
        },
    );

    // 71: ok.txt claims fsb 40 (which deleted ino 76 also wants).
    i.write_data(40, b"OK-FILE-DATA");
    i.write_inode(
        71,
        &InodeSpec {
            format: 2,
            size: 12,
            nblocks: 1,
            extents: vec![ExtentSpec { fileoff: 0, fsb: 40, len: 1, unwritten: false }],
            ..Default::default()
        },
    );

    // 72: free slot carrying a *valid-magic* but all-zero inode —
    // "magic ok but nothing residual" skip arm.
    {
        let pos = i.ino_pos(72);
        let ib = &mut i.b[pos..pos + ISZ];
        w16(ib, 0, INO_MAGIC);
        ib[4] = 3;
        write_crc(ib, 100);
    }
    // 73: free slot with garbage — inode parse fails.
    {
        let pos = i.ino_pos(73);
        i.b[pos..pos + 16].copy_from_slice(b"GARBAGE-GARBAGE!");
    }

    // 74: deleted inode whose extent is allocated but unclaimed (leak).
    i.write_data(50, b"LEAKED-BLOCK");
    i.write_inode(
        74,
        &InodeSpec {
            format: 2,
            size: 4096,
            nlink: 0,
            nblocks: 1,
            extents: vec![ExtentSpec { fileoff: 0, fsb: 50, len: 1, unwritten: false }],
            ..Default::default()
        },
    );

    // 75: deleted inode with size 0 → immediate Intact.
    i.write_inode(
        75,
        &InodeSpec {
            format: 2,
            size: 0,
            nlink: 0,
            ..Default::default()
        },
    );

    // 76: partially overwritten — fsb40 live-claimed, fsb41 free.
    i.write_data(41, b"SURVIVING-TAIL");
    i.write_inode(
        76,
        &InodeSpec {
            format: 2,
            size: 5000,
            nlink: 0,
            nblocks: 2,
            extents: vec![
                ExtentSpec { fileoff: 0, fsb: 40, len: 1, unwritten: false },
                ExtentSpec { fileoff: 1, fsb: 41, len: 1, unwritten: false },
            ],
            ..Default::default()
        },
    );

    // 77: extent fully past EOF → Unrecoverable (nothing expected).
    i.write_inode(
        77,
        &InodeSpec {
            format: 2,
            size: 4096,
            nlink: 0,
            nblocks: 1,
            extents: vec![ExtentSpec { fileoff: 4, fsb: 42, len: 1, unwritten: false }],
            ..Default::default()
        },
    );

    // 78/79: unlinked pair pointing at each other — chain must terminate.
    i.write_inode(
        78,
        &InodeSpec {
            format: 2,
            size: 10,
            nlink: 0,
            next_unlinked: 79 % 64,
            extents: vec![ExtentSpec { fileoff: 0, fsb: 44, len: 1, unwritten: false }],
            ..Default::default()
        },
    );
    i.write_inode(
        79,
        &InodeSpec {
            format: 2,
            size: 10,
            nlink: 0,
            next_unlinked: 78 % 64,
            extents: vec![ExtentSpec { fileoff: 0, fsb: 45, len: 1, unwritten: false }],
            ..Default::default()
        },
    );

    // 80: multi-block directory — two XDD3 blocks + a third extent at the
    // leaf-space boundary (its db range clamps to empty).
    for (blkno, owner, live, dead) in [
        (26u32, 80u64, vec![(".", 80u64, T_DIR), ("..", ROOTINO, T_DIR), ("first.txt", 71u64, T_FILE)], vec![("ghost1.txt", 74u64, T_FILE)]),
        (27u32, 80u64, vec![(".", 80u64, T_DIR), ("second.txt", 71u64, T_FILE)], vec![("ghost2.txt", 75u64, T_FILE)]),
    ] {
        let blk = i.blk_mut(blkno);
        w32(blk, 0, 0x5844_4433); // XDD3
        w64(blk, 8, blkno as u64);
        w64(blk, 16, 0x3333);
        blk[24..40].copy_from_slice(&UUID);
        w64(blk, 40, owner);
        let mut off = 64usize;
        for (name, ino, ftype) in live.iter().chain(dead.iter()) {
            let esize = ((9 + name.len() + 1 + 2) + 7) & !7;
            w64(blk, off, *ino);
            blk[off + 8] = name.len() as u8;
            blk[off + 9..off + 9 + name.len()].copy_from_slice(name.as_bytes());
            blk[off + 9 + name.len()] = *ftype;
            w16(blk, off + esize - 2, off as u16);
            off += esize;
        }
        // Free the deleted tail entries.
        let dstart = off - dead
            .iter()
            .map(|(n, _, _)| ((9 + n.len() + 1 + 2) + 7) & !7)
            .sum::<usize>();
        let dlen = off - dstart;
        if dlen > 0 {
            w16(blk, dstart, 0xFFFF);
            w16(blk, dstart + 2, dlen as u16);
            w16(blk, dstart + dlen - 2, dstart as u16);
        }
        if off < BS {
            w16(blk, off, 0xFFFF);
            w16(blk, off + 2, (BS - off) as u16);
            w16(blk, BS - 2, off as u16);
        }
        write_crc_be(blk, 4);
    }
    i.write_inode(
        80,
        &InodeSpec {
            mode: 0o40755,
            format: 2,
            size: 3 * BS as u64,
            nlink: 2,
            nblocks: 3,
            extents: vec![
                ExtentSpec { fileoff: 0, fsb: 26, len: 1, unwritten: false },
                ExtentSpec { fileoff: 1, fsb: 27, len: 1, unwritten: false },
                // Past the leaf-space boundary → clamped out.
                ExtentSpec { fileoff: 8_388_608, fsb: 28, len: 1, unwritten: false },
            ],
            ..Default::default()
        },
    );

    // 81: directory whose BTREE fork is corrupt (numrecs > maxrecs).
    i.write_inode(
        81,
        &InodeSpec {
            mode: 0o40755,
            format: 3,
            size: BS as u64,
            nlink: 2,
            ..Default::default()
        },
    );
    {
        let pos = i.ino_pos(81);
        let ib = &mut i.b[pos..pos + ISZ];
        let fork = &mut ib[176..];
        fork.fill(0);
        w16(fork, 0, 1); // level 1
        w16(fork, 2, 0xFFFF); // numrecs way over capacity
        write_crc(ib, 100);
    }

    // 82: directory with an extent beyond the image end → read error.
    i.write_inode(
        82,
        &InodeSpec {
            mode: 0o40755,
            format: 2,
            size: BS as u64,
            nlink: 2,
            nblocks: 1,
            extents: vec![ExtentSpec { fileoff: 0, fsb: 600, len: 1, unwritten: false }],
            ..Default::default()
        },
    );

    // Free-inode residue in chunk 64: garbage at 90, empty inode at 91.
    {
        let pos = i.ino_pos(90);
        i.b[pos..pos + 16].copy_from_slice(b"RESIDUE-GARBAGE!");
    }
    {
        let pos = i.ino_pos(91);
        let ib = &mut i.b[pos..pos + ISZ];
        w16(ib, 0, INO_MAGIC);
        ib[4] = 3;
        write_crc(ib, 100);
    }
    // Chunk 128: garbage residue at ino 130.
    {
        let pos = i.ino_pos(130);
        i.b[pos..pos + 16].copy_from_slice(b"SCRUBBED-RESIDUE");
    }

    // inobt: chunk 64 → inos 64-71 + 78-84 allocated; 72-77 are "deleted"
    // (free bits set so the freed-inode scan emits their residue).
    let mut free0 = u64::MAX;
    for b in (0..=7u64).chain(14..=20u64) {
        free0 &= !(1 << b);
    }
    i.inobt.push(ChunkRec { startino: 64, freecount: free0.count_ones(), free: free0 });
    // chunk 128 — all free (ino 130 slot is garbage residue).
    i.inobt.push(ChunkRec { startino: 128, freecount: 64, free: u64::MAX });
    i.finobt.push(ChunkRec { startino: 128, freecount: 64, free: u64::MAX });
    // Unlinked list: bucket for ino 78 → chain 78 → 79 → 78 (loop-cut).
    i.unlinked[78 % 64] = 78;
    i.icount = 128;
    i.ifree = free0.count_ones() as u64 + 64;

    // bnobt: 41 free (partial survivor), 50 NOT free (leak), 42 free.
    i.free = vec![(35, 5), (41, 1), (42, 1), (43, 7), (51, 13), (64, 448)];

    let mut img = i.finish();

    // --- post-finish patches ---
    // dev inode rdev bytes (fork area is extent records from write_inode).
    {
        let pos = ino_pos_of(65);
        img[pos + 176..pos + 180].copy_from_slice(&0x0801u32.to_be_bytes());
    }
    // ino 68: bigtime flag (flags2 bit 3).
    {
        let pos = ino_pos_of(68);
        w64(&mut img[pos..pos + ISZ], 120, 8); // DIFLAG2_BIGTIME
    }
    fix_ino_crc(&mut img, 68);
    // ino 69: attr fork — forkoff 8 (dfork 64 B), LOCAL attr list at lit+64.
    {
        let pos = ino_pos_of(69);
        img[pos + 82] = 8; // di_forkoff
        img[pos + 83] = 1; // di_aformat = LOCAL
        let a = pos + 176 + 64;
        // {totsize u16, count u8} + {namelen, valuelen, flags, name, val}
        img[a] = 0;
        img[a + 1] = 0;
        img[a + 2] = 2; // count
        img[a + 3] = 1;
        img[a + 4] = 1;
        img[a + 5] = 0; // user.
        img[a + 6] = b'a';
        img[a + 7] = b'1';
        img[a + 8] = 3;
        img[a + 9] = 2;
        img[a + 10] = 4; // security.
        img[a + 11..a + 14].copy_from_slice(b"key");
        img[a + 14..a + 16].copy_from_slice(b"v9");
    }
    fix_ino_crc(&mut img, 69);
    // sb: BIGTIME incompat bit (for ino 68's flags2).
    w32(&mut img[0..512], 216, 0x9); // incompat = FTYPE|BIGTIME
    fix_sb_crc(&mut img);

    img
}

// ---- mount-error collection -----------------------------------------------

#[test]
fn parser_name_and_detect() {
    assert_eq!(XfsParser.name(), "xfs");
    assert!(XfsParser.detect(src(weird_image()).as_ref()) >= DetectConfidence::High);
}

#[test]
fn agf_parse_error_collected_lenient() {
    let mut img = weird_image();
    img[512..516].copy_from_slice(&[0, 0, 0, 0]); // AGF magic → bad
    let fs = mount(img);
    let mut errs = 0;
    let mut oks = 0;
    for r in fs.walk() {
        match r {
            Ok(_) => oks += 1,
            Err(_) => errs += 1,
        }
    }
    assert!(errs >= 1, "AGF error should surface as a walk record");
    assert!(oks > 3, "live tree should still walk");
}

#[test]
fn agi_parse_error_collected_lenient() {
    let mut img = weird_image();
    img[1024..1028].copy_from_slice(&[0, 0, 0, 0]); // AGI magic → bad
    let fs = mount(img);
    assert!(fs.walk().any(|r| r.is_err()));
}

#[test]
fn bad_agfl_magic_collected() {
    let mut img = weird_image();
    img[1536..1540].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let fs = mount(img);
    assert!(fs.walk().any(|r| r.is_err()));
}

#[test]
fn agf_crc_mismatch_collected() {
    let mut img = weird_image();
    img[512 + 100] ^= 0xFF; // flip a non-structural byte → CRC fails
    let fs = mount(img);
    assert!(fs.walk().any(|r| r.is_err()));
}

#[test]
fn agi_crc_mismatch_collected() {
    let mut img = weird_image();
    img[1024 + 100] ^= 0xFF;
    let fs = mount(img);
    assert!(fs.walk().any(|r| r.is_err()));
}

#[test]
fn bnobt_leaf_bad_magic() {
    let mut img = weird_image();
    img[4096..4100].copy_from_slice(&[0; 4]); // blk1 AB3B → bad
    let fs = mount(img);
    assert!(fs.walk().any(|r| r.is_err()));
    assert!(fs.unallocated_ranges().is_empty());
}

#[test]
fn inobt_leaf_bad_magic() {
    let mut img = weird_image();
    img[2 * 4096..2 * 4096 + 4].copy_from_slice(&[0; 4]); // blk2 IAB3 → bad
    let fs = mount(img);
    assert!(fs.walk().any(|r| r.is_err()));
}

#[test]
fn finobt_leaf_bad_magic() {
    let mut img = weird_image();
    img[3 * 4096..3 * 4096 + 4].copy_from_slice(&[0; 4]); // blk3 FIB3 → bad
    let fs = mount(img);
    assert!(fs.walk().any(|r| r.is_err()));
}

#[test]
fn dir_block_crc_mismatch_is_a_walk_error() {
    let mut img = weird_image();
    img[25 * 4096 + 100] ^= 0xFF; // inside blkdir's XDB3 → CRC fails
    let fs = mount(img);
    assert!(fs.walk().any(|r| r.is_err()));
}

#[test]
fn strict_mount_fails_on_collected_errors() {
    // Strict mode: a corrupt AGF aborts the walk early.
    let mut img = weird_image();
    img[512..516].copy_from_slice(&[0; 4]);
    let fs = XfsParser
        .mount_with(
            src(img),
            &MountOptions { strict: true, check_magic: true, include_orphans: true },
        )
        .unwrap();
    let mut items = 0;
    for r in fs.walk() {
        items += 1;
        let _ = r;
    }
    assert!(items <= 2, "strict walk should stop early, got {items}");
}

// ---- inode-format / recovery variants --------------------------------------

#[test]
fn dev_inode_reports_rdev() {
    let entries = walk(weird_image());
    let dev = by_id(&entries, 65);
    assert_eq!(dev.kind, EntryKind::Other);
    assert_eq!(dev.meta.get("rdev").map(String::as_str), Some("0x801"));
    assert_eq!(dev.meta.get("di_format").map(String::as_str), Some("dev"));
}

#[test]
fn unwritten_extent_and_slack_meta() {
    let entries = walk(weird_image());
    let big = by_id(&entries, 66);
    assert_eq!(big.meta.get("unwritten_extents").map(String::as_str), Some("1"));
    assert!(big.meta.contains_key("slack_offset"), "expected slack meta: {:?}", big.meta);
    assert!(big.meta.contains_key("slack_len"));
    // Read still returns the head bytes then zeros.
    let fs = mount(weird_image());
    let mut buf = Vec::new();
    fs.read_file(big).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(&buf[..8], b"BIGHEAD!");
}

#[test]
fn remote_symlink_decodes_and_bad_hdr_is_tolerated() {
    let entries = walk(weird_image());
    let link = by_id(&entries, 67);
    assert_eq!(
        link.meta.get("symlink_target").map(String::as_str),
        Some("/subdir/deep")
    );
    // rlink2 (bad XSLM header) → no target meta, still an entry.
    let bad = by_id(&entries, 83);
    assert_eq!(bad.kind, EntryKind::Symlink);
    assert!(!bad.meta.contains_key("symlink_target"));
    // slinkdev (FMT_DEV fork) → also no target.
    let d = by_id(&entries, 84);
    assert!(!d.meta.contains_key("symlink_target"));
}

#[test]
fn inline_file_and_bigtime() {
    let entries = walk(weird_image());
    let e = by_id(&entries, 68);
    assert_eq!(e.kind, EntryKind::File);
    let fs = mount(weird_image());
    let mut buf = Vec::new();
    fs.read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"tiny");
    // bigtime encoding recorded on the timestamps.
    let ts = e.timestamps.modified.as_ref().unwrap();
    assert_eq!(ts.raw_encoding, "xfs-bigtime-ns");
}

#[test]
fn local_xattrs_listed() {
    let entries = walk(weird_image());
    let e = by_id(&entries, 69);
    assert_eq!(e.meta.get("xattr_count").map(String::as_str), Some("2"));
    assert_eq!(e.meta.get("xattr_user_a").map(String::as_str), Some("31"));
    assert_eq!(e.meta.get("xattr_security_key").map(String::as_str), Some("7639"));
    assert_eq!(e.meta.get("xattr_security_key_flags").map(String::as_str), Some("0x04"));
}

#[test]
fn read_dir_entry_rejected() {
    let fs = mount(weird_image());
    let entries: Vec<_> = fs.walk().filter_map(|r| r.ok()).collect();
    let dir = entries.iter().find(|e| e.path == "/blkdir").unwrap();
    assert!(fs.read_file(dir).is_err());
}

#[test]
fn residue_variants_emit() {
    let entries = walk(weird_image());
    let find = |name: &str| entries.iter().find(|e| e.name == name).unwrap_or_else(|| panic!("missing {name}"));

    // realloc.txt → ino 65 is live → minimal entry with reallocation note.
    let r = find("realloc.txt");
    assert!(r.is_deleted());
    assert_eq!(r.kind, EntryKind::File);
    assert!(
        r.meta.values().any(|v| v.contains("reallocated")),
        "meta: {:?}",
        r.meta
    );

    // empty.txt → inode parses but carries no residue.
    let e = find("empty.txt");
    assert!(e.is_deleted());
    assert!(
        e.meta.values().any(|v| v.contains("no residual content")),
        "meta: {:?}",
        e.meta
    );

    // scrubbed.txt → inode slot is garbage → unreadable.
    let s = find("scrubbed.txt");
    assert!(
        s.meta.values().any(|v| v.contains("unreadable or scrubbed")),
        "meta: {:?}",
        s.meta
    );

    // faraway.txt is the LAST entry in the freed run — the run's own
    // tail tag overwrites its entry tag, so intact-decode rejects it.
    // (Documents a real blind spot of the residue protocol.)
    assert!(entries.iter().all(|e| e.name != "faraway.txt"));

    // ghost entries in the multidir free runs.
    assert!(entries.iter().any(|e| e.name == "ghost1.txt"));
    assert!(entries.iter().any(|e| e.name == "ghost2.txt"));
}

#[test]
fn recovery_states() {
    let fs = mount(weird_image());
    let entries: Vec<_> = fs.walk().filter_map(|r| r.ok()).collect();

    // ino 74: allocated-but-unclaimed extent → Intact with a leak note.
    let leak = by_id(&entries, 74);
    assert!(
        matches!(leak.status, FsEntryStatus::Deleted { recovery: RecoveryState::Intact }),
        "status {:?}",
        leak.status
    );
    assert!(
        leak.meta.values().any(|v| v.contains("unclaimed")),
        "meta: {:?}",
        leak.meta
    );

    // ino 75: size 0 → Intact trivially.
    let empty = by_id(&entries, 75);
    assert!(matches!(
        empty.status,
        FsEntryStatus::Deleted { recovery: RecoveryState::Intact }
    ));

    // ino 76: one block lost, one survives → PartiallyOverwritten.
    let part = by_id(&entries, 76);
    match part.status {
        FsEntryStatus::Deleted {
            recovery: RecoveryState::PartiallyOverwritten { recovered_bytes, total_bytes },
        } => {
            // Only the fsb41 tail survives: file bytes 4096..5000 = 904.
            assert_eq!(recovered_bytes, 904);
            assert_eq!(total_bytes, 5000);
        }
        ref s => panic!("expected PartiallyOverwritten, got {s:?}"),
    }
    // Surviving range is only fsb 41.
    assert_eq!(part.allocated_ranges, vec![(41 * 4096, 4096)]);

    // ino 77: extent past EOF → Unrecoverable.
    let past = by_id(&entries, 77);
    assert!(matches!(
        past.status,
        FsEntryStatus::Deleted { recovery: RecoveryState::Unrecoverable }
    ));
}

#[test]
fn unlinked_chain_terminates_on_loop() {
    let entries = walk(weird_image());
    // Both members of the 78↔79 loop appear exactly once.
    let a = entries.iter().filter(|e| e.entry_id == 78).count();
    let b = entries.iter().filter(|e| e.entry_id == 79).count();
    assert_eq!(a, 1, "ino 78 emitted {a} times");
    assert_eq!(b, 1, "ino 79 emitted {b} times");
}

#[test]
fn free_slot_residue_variants() {
    let entries = walk(weird_image());
    // ino 90 (garbage bytes) → minimal ino entry with bad-magic note.
    let g = entries.iter().find(|e| e.entry_id == 90).expect("ino 90 residue");
    assert!(g.is_deleted());
    assert!(g.meta.contains_key("inode_magic_bad"), "meta: {:?}", g.meta);
    // ino 91 (valid magic, zero fields) and the zeroed slots → skipped.
    assert!(entries.iter().all(|e| e.entry_id != 91));
    assert!(entries.iter().all(|e| e.entry_id != 92));
    // ino 130 in chunk 128 → garbage residue emitted.
    let g2 = entries.iter().find(|e| e.entry_id == 130).expect("ino 130 residue");
    assert!(g2.meta.contains_key("inode_magic_bad"));
    assert!(g2.path.starts_with("/$ORPHANED/"));
}

#[test]
fn multidir_and_bad_dirs() {
    let fs = mount(weird_image());
    let mut oks = Vec::new();
    let mut errs = 0;
    for r in fs.walk() {
        match r {
            Ok(e) => oks.push(e),
            Err(_) => errs += 1,
        }
    }
    // Two XDD3 blocks → first.txt and second.txt live.
    assert!(oks.iter().any(|e| e.path == "/multidir/first.txt"));
    assert!(oks.iter().any(|e| e.path == "/multidir/second.txt"));
    // baddir (corrupt btree) + oobdir (extent past EOF) → error records.
    assert!(errs >= 2, "expected dir errors, got {errs}");
}

#[test]
fn orphan_scan_skips_live_and_emits_residue() {
    // Orphan detection already covered by forensic.rs; here the
    // empty-inode slot (72) is skipped and garbage slot (73) lands in the
    // orphan scan too — both via allocated-bit-clear paths.
    let entries = walk(weird_image());
    assert!(entries.iter().all(|e| e.entry_id != 72 || e.is_deleted()));
}

// ---- superblock / info variants ---------------------------------------------

#[test]
fn info_meta_variants() {
    let mut img = weird_image();
    // inprogress + rblocks + distinct meta_uuid + no-log flag patches.
    img[126] = 1; // sb_inprogress
    img[16..24].copy_from_slice(&7u64.to_be_bytes()); // rblocks
    img[248..264].copy_from_slice(&[0x5Au8; 16]); // meta_uuid ≠ uuid
    fix_sb_crc(&mut img);
    let fs = mount(img);
    let m = &fs.info().meta;
    assert_eq!(m.get("inprogress").map(String::as_str), Some("true (mkfs interrupted)"));
    assert_eq!(m.get("realtime_blocks").map(String::as_str), Some("7"));
    assert!(m.contains_key("meta_uuid"), "meta_uuid should differ: {m:?}");
}

#[test]
fn log_variants() {
    // logstart=0 → "external or none".
    let mut img = weird_image();
    img[48..56].copy_from_slice(&0u64.to_be_bytes());
    fix_sb_crc(&mut img);
    let m = mount(img).info().meta;
    assert_eq!(m.get("log").map(String::as_str), Some("external or none (logstart=0)"));

    // logstart pointing at a zeroed block → "log region present".
    let mut img2 = weird_image();
    img2[48..56].copy_from_slice(&60u64.to_be_bytes());
    fix_sb_crc(&mut img2);
    let m2 = mount(img2).info().meta;
    let log = m2.get("log").map(String::as_str).unwrap_or("");
    assert!(log.contains("log region present"), "log meta: {log}");
}

#[test]
fn v4_filesystem_variant() {
    // Downgrade to v4: no CRC checks, FTYPE via features2, no finobt.
    let mut img = weird_image();
    img[100..102].copy_from_slice(&0xB4B4u16.to_be_bytes()); // version 4
    img[200..204].copy_from_slice(&0x2A08u32.to_be_bytes()); // features2 |FTYPE
    img[212..216].copy_from_slice(&0u32.to_be_bytes()); // ro_compat = 0
    // v4 superblocks don't verify the v5 CRC field — no re-checksum needed.
    let fs = mount(img);
    let info = fs.info();
    assert_eq!(info.fs_type, "XFS v4");
    assert_eq!(info.meta.get("finobt").map(String::as_str), Some("false"));
    assert!(!info.meta.contains_key("sb_crc_ok"));
    let entries: Vec<_> = fs.walk().filter_map(|r| r.ok()).collect();
    assert!(entries.iter().any(|e| e.path == "/inline"));
}

// ---- sparse chunks -----------------------------------------------------------

#[test]
fn sparse_inobt_chunks() {
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
            extents: vec![ExtentSpec { fileoff: 0, fsb: 24, len: 1, unwritten: false }],
            ..Default::default()
        },
    );
    let free = !0b11u64;
    i.inobt.push(ChunkRec { startino: 64, freecount: 62, free });
    i.free = vec![(28, 36), (64, 448)];
    let mut img = i.finish();

    // Enable sparse inode chunks and re-encode the inobt record with a
    // holemask covering inode groups 12..15 (inos 112..127 are "holes").
    w32(&mut img[0..512], 216, 0x1 | 0x2); // incompat = FTYPE|SPINODES
    fix_sb_crc(&mut img);
    // Rewrite the leaf record at blk2+56: {startino u32, holemask u16,
    // count u8, freecount u8, free u64}.
    let rec = 2 * 4096 + 56;
    w16(&mut img[rec..rec + 16], 4, 0xF000); // holemask: groups 12-15
    img[rec + 6] = 0; // count
    img[rec + 7] = 62; // freecount
    fix_crc_at(&mut img, 2 * 4096, 52);

    let fs = mount(img);
    let entries: Vec<_> = fs.walk().filter_map(|r| r.ok()).collect();
    assert!(entries.iter().any(|e| e.path == "/a"));
    // Hole inos (112..127) never emit even though their free bits are set.
    assert!(entries.iter().all(|e| !(112..=127).contains(&e.entry_id)));
}

/// Recompute an LE crc at `blk + crc_off`.
fn fix_crc_at(img: &mut [u8], blk: usize, crc_off: usize) {
    img[blk + crc_off..blk + crc_off + 4].fill(0);
    let c = crc32c(0xFFFF_FFFF, 0, &img[blk..blk + 4096]);
    img[blk + crc_off..blk + crc_off + 4].copy_from_slice(&(!c).to_le_bytes());
}

// ---- multi-AG -----------------------------------------------------------------

#[test]
fn second_allocation_group_scanned() {
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
    i.write_inode(
        65,
        &InodeSpec {
            format: 2,
            size: 6,
            extents: vec![ExtentSpec { fileoff: 0, fsb: 24, len: 1, unwritten: false }],
            ..Default::default()
        },
    );
    i.inobt.push(ChunkRec { startino: 64, freecount: 62, free: !0b11u64 });
    i.free = vec![(28, 36)];
    let mut img = i.finish();

    // Repartition into 2 AGs of 256 blocks (dblocks stays 512).
    img[84..88].copy_from_slice(&256u32.to_be_bytes()); // agblocks
    img[88..92].copy_from_slice(&2u32.to_be_bytes()); // agcount
    img[124] = 8; // agblklog = log2(256)
    fix_sb_crc(&mut img);

    // AG1 headers at ag_off(1) = 256*4096.
    let ag1 = 256 * 4096;
    {
        let b = &mut img[ag1 + 512..ag1 + 1024];
        w32(b, 0, AGF_MAGIC);
        w32(b, 4, 1);
        w32(b, 12, 256); // length
        w32(b, 16, 1); // bnobt root
        w32(b, 20, 1); // cntbt root
        w32(b, 28, 1); // bnobt level
        w32(b, 32, 1);
        w32(b, 52, 100); // freeblks
        b[64..80].copy_from_slice(&UUID);
        write_crc_be(b, 216);
    }
    {
        let b = &mut img[ag1 + 1024..ag1 + 1536];
        w32(b, 0, AGI_MAGIC);
        w32(b, 4, 1);
        w32(b, 12, 256);
        w32(b, 16, 0); // count
        w32(b, 20, 2); // inobt root
        w32(b, 24, 1); // level
        w32(b, 28, 64); // freecount
        w32(b, 32, 0); // newino
        for k in 0..64 {
            w32(b, 40 + k * 4, NULLAGINO);
        }
        b[296..312].copy_from_slice(&UUID);
        w32(b, 328, 3); // free_root
        w32(b, 332, 1); // free_level
        write_crc_be(b, 312);
    }
    {
        let b = &mut img[ag1 + 1536..ag1 + 2048];
        w32(b, 0, AGFL_MAGIC);
        b[24..40].copy_from_slice(&UUID);
        write_crc_be(b, 4);
    }
    // AG1 blk1: bnobt leaf {start 10, len 100}.
    {
        let blk = &mut img[ag1 + 4096..ag1 + 2 * 4096];
        w32(blk, 0, AB3B);
        w16(blk, 4, 0);
        w16(blk, 6, 1);
        w32(blk, 8, NULLAGBLOCK);
        w32(blk, 12, NULLAGBLOCK);
        w64(blk, 16, 1);
        blk[32..48].copy_from_slice(&UUID);
        w64(blk, 48, 0);
        w32(blk, 56, 10);
        w32(blk, 60, 100);
        write_crc(blk, 52);
    }
    // AG1 blk2: inobt leaf — all 64 inos free.
    {
        let blk = &mut img[ag1 + 2 * 4096..ag1 + 3 * 4096];
        w32(blk, 0, IAB3);
        w16(blk, 4, 0);
        w16(blk, 6, 1);
        w32(blk, 8, NULLAGBLOCK);
        w32(blk, 12, NULLAGBLOCK);
        w64(blk, 16, 2);
        blk[32..48].copy_from_slice(&UUID);
        w64(blk, 48, 0);
        w32(blk, 56, 64); // startino
        w32(blk, 60, 64); // freecount
        w64(blk, 64, u64::MAX); // free mask
        write_crc(blk, 52);
    }
    // AG1 blk3: finobt leaf — same record.
    {
        let blk = &mut img[ag1 + 3 * 4096..ag1 + 4 * 4096];
        w32(blk, 0, FIB3);
        w16(blk, 4, 0);
        w16(blk, 6, 1);
        w32(blk, 8, NULLAGBLOCK);
        w32(blk, 12, NULLAGBLOCK);
        w64(blk, 16, 3);
        blk[32..48].copy_from_slice(&UUID);
        w64(blk, 48, 0);
        w32(blk, 56, 64);
        w32(blk, 60, 64);
        w64(blk, 64, u64::MAX);
        write_crc(blk, 52);
    }

    let fs = mount(img);
    let entries: Vec<_> = fs.walk().filter_map(|r| r.ok()).collect();
    assert!(entries.iter().any(|e| e.path == "/a"));
    // AG1's free extent shows up in unallocated space (ag1 base + 10*bs).
    let ranges = fs.unallocated_ranges();
    assert!(
        ranges.contains(&((256 + 10) * 4096, 100 * 4096)),
        "ranges: {ranges:?}"
    );
}

// ---- bmbt interior nodes + reader/recovery edges -----------------------------

#[test]
fn bmbt_interior_node_walked() {
    // format=BTREE data fork whose in-inode root is level 2:
    // root → interior 'BMA3' node (fsb 40) → leaf (fsb 42) → extent.
    let mut i = Img::new();
    i.write_inode(
        ROOTINO,
        &InodeSpec {
            mode: 0o40755,
            format: 1,
            size: 6,
            inline_data: sf_dir(ROOTINO, &[("deep", 65, T_FILE)]),
            ..Default::default()
        },
    );
    i.write_data(41, b"deep-btree!");
    i.write_inode(
        65,
        &InodeSpec {
            format: 3,
            size: 11,
            nblocks: 1,
            ..Default::default()
        },
    );
    {
        let pos = i.ino_pos(65);
        let ib = &mut i.b[pos..pos + ISZ];
        let fork = &mut ib[176..];
        fork.fill(0);
        w16(fork, 0, 2); // level 2 → children are interior nodes
        w16(fork, 2, 1); // numrecs
        let maxrecs = (fork.len() - 4) / 16;
        w64(fork, 4, 0); // key[0] = fileoff 0
        w64(fork, 4 + maxrecs * 8, 40); // ptr[0] → fsb 40
        write_crc(ib, 100);
    }
    // Interior node at fsb 40: BMA3 level 1, 1 rec → ptr to leaf fsb 42.
    {
        let blk = i.blk_mut(40);
        w32(blk, 0, 0x424D_4133); // 'BMA3'
        w16(blk, 4, 1); // level 1 = interior
        w16(blk, 6, 1); // numrecs
        w64(blk, 8, u64::MAX); // leftsib
        w64(blk, 16, u64::MAX); // rightsib
        w64(blk, 24, 40); // blkno
        blk[40..56].copy_from_slice(&UUID);
        w64(blk, 56, 65); // owner
        let maxrecs = (BS - 72) / 16; // key/ptr pairs
        w64(blk, 72, 0); // key[0] = fileoff 0
        w64(blk, 72 + maxrecs * 8, 42); // ptr[0] → leaf at fsb 42
        write_crc(blk, 64); // lblock crc is __le32
    }
    // Leaf at fsb 42 with the real extent record → fsb 41.
    {
        let blk = i.blk_mut(42);
        w32(blk, 0, 0x424D_4133);
        w16(blk, 4, 0); // leaf
        w16(blk, 6, 1);
        w64(blk, 8, u64::MAX);
        w64(blk, 16, u64::MAX);
        w64(blk, 24, 42);
        blk[40..56].copy_from_slice(&UUID);
        w64(blk, 56, 65);
        let rec = extent_rec(&ExtentSpec { fileoff: 0, fsb: 41, len: 1, unwritten: false });
        blk[72..88].copy_from_slice(&rec);
        write_crc(blk, 64);
    }
    let free = !0b11u64;
    i.inobt.push(ChunkRec { startino: 64, freecount: 62, free });
    i.free = vec![(28, 12), (43, 21), (64, 448)];
    let fs = mount(i.finish());
    let entries: Vec<_> = fs.walk().collect::<Result<_, _>>().expect("walk");
    let e = entries.iter().find(|e| e.path == "/deep").expect("deep file");
    assert_eq!(e.allocated_ranges, vec![(41 * 4096, 4096)]);
    let mut buf = Vec::new();
    fs.read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"deep-btree!");
}

#[test]
fn bmbt_leaf_numrecs_over_capacity_is_lenient() {
    // Leaf 'BMA3' claims more records than the block can hold → a walk
    // error record, but the file entry is still emitted (lenient) and
    // read_file surfaces the decode error instead of panicking.
    let mut i = Img::new();
    i.write_inode(
        ROOTINO,
        &InodeSpec {
            mode: 0o40755,
            format: 1,
            size: 6,
            inline_data: sf_dir(ROOTINO, &[("over", 65, T_FILE)]),
            ..Default::default()
        },
    );
    i.write_inode(
        65,
        &InodeSpec {
            format: 3,
            size: 11,
            nblocks: 1,
            ..Default::default()
        },
    );
    {
        let pos = i.ino_pos(65);
        let ib = &mut i.b[pos..pos + ISZ];
        let fork = &mut ib[176..];
        fork.fill(0);
        w16(fork, 0, 1);
        w16(fork, 2, 1);
        let maxrecs = (fork.len() - 4) / 16;
        w64(fork, 4 + maxrecs * 8, 40);
        write_crc(ib, 100);
    }
    {
        let blk = i.blk_mut(40);
        w32(blk, 0, 0x424D_4133);
        w16(blk, 4, 0);
        w16(blk, 6, 0xFFFF); // numrecs way over leaf capacity
        w64(blk, 8, u64::MAX);
        w64(blk, 16, u64::MAX);
        w64(blk, 24, 40);
        blk[40..56].copy_from_slice(&UUID);
        w64(blk, 56, 65);
        write_crc(blk, 64);
    }
    let free = !0b11u64;
    i.inobt.push(ChunkRec { startino: 64, freecount: 62, free });
    i.free = vec![(28, 36), (64, 448)];
    let fs = mount(i.finish());
    let mut oks = 0;
    let mut errs = 0;
    let mut over = None;
    for r in fs.walk() {
        match r {
            Ok(e) => {
                if e.path == "/over" {
                    over = Some(e);
                }
                oks += 1;
            }
            Err(_) => errs += 1,
        }
    }
    assert!(errs >= 1, "expected a walk error record");
    let over = over.expect("/over entry still emitted");
    assert!(over.allocated_ranges.is_empty());
    assert!(fs.read_file(&over).is_err(), "read of bad bmbt must error");
    let _ = oks;
}

#[test]
fn bmbt_interior_numrecs_over_capacity_is_lenient() {
    // Same fault one level up: the *interior* node claims more children
    // than the block's key/ptr capacity → walk error, entry survives.
    let mut i = Img::new();
    i.write_inode(
        ROOTINO,
        &InodeSpec {
            mode: 0o40755,
            format: 1,
            size: 6,
            inline_data: sf_dir(ROOTINO, &[("over2", 65, T_FILE)]),
            ..Default::default()
        },
    );
    i.write_inode(
        65,
        &InodeSpec {
            format: 3,
            size: 11,
            nblocks: 1,
            ..Default::default()
        },
    );
    {
        let pos = i.ino_pos(65);
        let ib = &mut i.b[pos..pos + ISZ];
        let fork = &mut ib[176..];
        fork.fill(0);
        w16(fork, 0, 2); // level 2 → children are interior nodes
        w16(fork, 2, 1);
        let maxrecs = (fork.len() - 4) / 16;
        w64(fork, 4 + maxrecs * 8, 40);
        write_crc(ib, 100);
    }
    {
        let blk = i.blk_mut(40);
        w32(blk, 0, 0x424D_4133);
        w16(blk, 4, 1); // interior
        w16(blk, 6, 0xFFFF); // numrecs way over node capacity
        w64(blk, 8, u64::MAX);
        w64(blk, 16, u64::MAX);
        w64(blk, 24, 40);
        blk[40..56].copy_from_slice(&UUID);
        w64(blk, 56, 65);
        write_crc(blk, 64);
    }
    let free = !0b11u64;
    i.inobt.push(ChunkRec { startino: 64, freecount: 62, free });
    i.free = vec![(28, 36), (64, 448)];
    let fs = mount(i.finish());
    assert!(fs.walk().any(|r| r.is_err()), "expected a walk error record");
}

#[test]
fn dir_with_non_dir_fork_format_is_walk_error() {
    // A directory inode whose di_format is DEV — dir_entries and the
    // walker's process_dir must both turn it into error records.
    let mut i = Img::new();
    i.write_inode(
        ROOTINO,
        &InodeSpec {
            mode: 0o40755,
            format: 1,
            size: 6,
            inline_data: sf_dir(ROOTINO, &[("weirddir", 65, T_DIR)]),
            ..Default::default()
        },
    );
    i.write_inode(
        65,
        &InodeSpec {
            mode: 0o40755,
            format: 0, // DEV — nonsense for a directory
            size: BS as u64,
            nlink: 2,
            ..Default::default()
        },
    );
    let free = !0b11u64;
    i.inobt.push(ChunkRec { startino: 64, freecount: 62, free });
    i.free = vec![(28, 36), (64, 448)];
    let fs = mount(i.finish());
    let mut errs = 0;
    let mut dir_seen = false;
    for r in fs.walk() {
        match r {
            Ok(e) if e.path == "/weirddir" => dir_seen = true,
            Ok(_) => {}
            Err(_) => errs += 1,
        }
    }
    assert!(dir_seen, "the dir entry itself is still emitted");
    assert!(errs >= 1, "non-dir fork format must error, not panic");
}

#[test]
fn deleted_btree_fork_decode_failure_is_unknown() {
    // Deleted inode (free bit set, residue present) whose data fork is a
    // corrupt bmbt root → RecoveryState::Unknown with an honest note.
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
    i.write_inode(
        65,
        &InodeSpec {
            format: 2,
            size: 6,
            extents: vec![ExtentSpec { fileoff: 0, fsb: 24, len: 1, unwritten: false }],
            ..Default::default()
        },
    );
    // ino 130 (chunk 128, all-free): format=BTREE, numrecs > capacity.
    i.write_inode(
        130,
        &InodeSpec {
            format: 3,
            size: 4096,
            nlink: 0,
            nblocks: 1,
            ..Default::default()
        },
    );
    {
        let pos = i.ino_pos(130);
        let ib = &mut i.b[pos..pos + ISZ];
        let fork = &mut ib[176..];
        fork.fill(0);
        w16(fork, 0, 1);
        w16(fork, 2, 0xFFFF);
        write_crc(ib, 100);
    }
    i.inobt.push(ChunkRec { startino: 64, freecount: 62, free: !0b11u64 });
    i.inobt.push(ChunkRec { startino: 128, freecount: 64, free: u64::MAX });
    i.free = vec![(28, 36), (64, 448)];
    let fs = mount(i.finish());
    let entries: Vec<_> = fs.walk().filter_map(|r| r.ok()).collect();
    let d = entries
        .iter()
        .find(|e| e.entry_id == 130)
        .expect("deleted ino 130");
    assert!(
        matches!(d.status, FsEntryStatus::Deleted { recovery: RecoveryState::Unknown }),
        "status {:?}",
        d.status
    );
    assert!(
        d.meta.values().any(|v| v.contains("extent decode failed")),
        "meta: {:?}",
        d.meta
    );
}

#[test]
fn sparse_tail_hole_zero_fills() {
    // Extent covers fileoff 0 only; size spans two blocks → the tail is a
    // hole that must read back as zeros (SparseReader's no-extent arm).
    let mut i = Img::new();
    i.write_inode(
        ROOTINO,
        &InodeSpec {
            mode: 0o40755,
            format: 1,
            size: 6,
            inline_data: sf_dir(ROOTINO, &[("tail", 65, T_FILE)]),
            ..Default::default()
        },
    );
    i.write_data(24, b"EDGE");
    i.write_inode(
        65,
        &InodeSpec {
            format: 2,
            size: 2 * BS as u64,
            nblocks: 1,
            extents: vec![ExtentSpec { fileoff: 0, fsb: 24, len: 1, unwritten: false }],
            ..Default::default()
        },
    );
    let free = !0b11u64;
    i.inobt.push(ChunkRec { startino: 64, freecount: 62, free });
    i.free = vec![(28, 36), (64, 448)];
    let fs = mount(i.finish());
    let entries: Vec<_> = fs.walk().collect::<Result<_, _>>().expect("walk");
    let e = entries.iter().find(|e| e.path == "/tail").expect("tail file");
    let mut buf = Vec::new();
    fs.read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 2 * BS);
    assert_eq!(&buf[..4], b"EDGE");
    assert!(buf[BS..].iter().all(|&b| b == 0), "tail hole not zeros");
}

#[test]
fn slack_when_eof_lands_in_second_extent() {
    // Two 1-block extents, size lands inside the second → slack_offset
    // must be computed against that extent, not the first.
    let mut i = Img::new();
    i.write_inode(
        ROOTINO,
        &InodeSpec {
            mode: 0o40755,
            format: 1,
            size: 6,
            inline_data: sf_dir(ROOTINO, &[("s", 65, T_FILE)]),
            ..Default::default()
        },
    );
    i.write_data(24, b"DATA");
    i.write_data(25, b"TAIL");
    i.write_inode(
        65,
        &InodeSpec {
            format: 2,
            size: BS as u64 + 10,
            nblocks: 2,
            extents: vec![
                ExtentSpec { fileoff: 0, fsb: 24, len: 1, unwritten: false },
                ExtentSpec { fileoff: 1, fsb: 25, len: 1, unwritten: false },
            ],
            ..Default::default()
        },
    );
    let free = !0b11u64;
    i.inobt.push(ChunkRec { startino: 64, freecount: 62, free });
    i.free = vec![(28, 36), (64, 448)];
    let fs = mount(i.finish());
    let entries: Vec<_> = fs.walk().collect::<Result<_, _>>().expect("walk");
    let e = entries.iter().find(|e| e.path == "/s").expect("s file");
    assert_eq!(
        e.meta.get("slack_offset").map(String::as_str),
        Some(format!("{:#x}", 25 * BS + 10).as_str())
    );
    assert_eq!(
        e.meta.get("slack_len").map(String::as_str),
        Some(format!("{}", BS - 10).as_str())
    );
}

#[test]
fn dirent_with_out_of_geometry_ino_is_walk_error() {
    // A dirent pointing at an inode number beyond the filesystem's
    // geometry → error record via inode_bytes' ino_valid check.
    let mut i = Img::new();
    i.write_inode(
        ROOTINO,
        &InodeSpec {
            mode: 0o40755,
            format: 1,
            size: 6,
            inline_data: sf_dir(ROOTINO, &[("ghost", 0xFFFF_FFFF, T_FILE)]),
            ..Default::default()
        },
    );
    i.inobt.push(ChunkRec { startino: 64, freecount: 63, free: !0b1u64 });
    i.free = vec![(28, 36), (64, 448)];
    let fs = mount(i.finish());
    assert!(fs.walk().any(|r| r.is_err()));
}

#[test]
fn btree_leaf_crc_mismatch_still_decodes_lenient() {
    // bnobt leaf CRC fails → error record, but records are still decoded
    // (lenient forensic policy) so unallocated_ranges stays populated.
    let mut img = weird_image();
    img[4096 + 100] ^= 0xFF; // inside the bnobt leaf's record area
    let fs = mount(img);
    assert!(fs.walk().any(|r| r.is_err()));
    assert!(
        !fs.unallocated_ranges().is_empty(),
        "leaf must still be decoded despite the bad CRC"
    );
    // Same for the inobt leaf: free-inode residue scan still runs.
    let mut img2 = weird_image();
    img2[2 * 4096 + 100] ^= 0xFF;
    let fs2 = mount(img2);
    let entries: Vec<_> = fs2.walk().filter_map(|r| r.ok()).collect();
    assert!(entries.iter().any(|e| e.entry_id == 74));
}

#[test]
fn source_returns_the_mounted_bytes() {
    let img = weird_image();
    let len = img.len() as u64;
    let fs = mount(img);
    let s = fs.source();
    assert_eq!(s.len(), len);
    // And it is actually readable — the superblock magic survives.
    let b = s.read_slice(0, 4).unwrap();
    assert_eq!(b, 0x5846_5342u32.to_be_bytes());
}

#[test]
fn remote_xattr_value_is_reported_not_fetched() {
    // Attr leaf with a *remote* value bigger than the eager-fetch bound →
    // meta reports "N bytes (remote)" without reading XARM blocks.
    let mut i = Img::new();
    i.write_inode(
        ROOTINO,
        &InodeSpec {
            mode: 0o40755,
            format: 1,
            size: 6,
            inline_data: sf_dir(ROOTINO, &[("x", 65, T_FILE)]),
            ..Default::default()
        },
    );
    i.write_data(24, b"data");
    i.write_inode(
        65,
        &InodeSpec {
            format: 2,
            size: 4,
            extents: vec![ExtentSpec { fileoff: 0, fsb: 24, len: 1, unwritten: false }],
            ..Default::default()
        },
    );
    // Split the fork: forkoff=2 (16 B dfork = the single data extent rec),
    // afork at 176+16 holds one extent rec → attr leaf at fsb 43.
    {
        let pos = i.ino_pos(65);
        let ib = &mut i.b[pos..pos + ISZ];
        ib[82] = 2; // di_forkoff (8-byte units)
        ib[83] = 2; // di_aformat = EXTENTS
        w16(ib, 80, 1); // anextents
        let rec = extent_rec(&ExtentSpec { fileoff: 0, fsb: 43, len: 1, unwritten: false });
        ib[176 + 16..176 + 32].copy_from_slice(&rec);
        write_crc(ib, 100);
    }
    // Attr leaf v3 at fsb 43: count 1, one remote entry named "user.huge".
    {
        let blk = i.blk_mut(43);
        w16(blk, 8, 0x3BEE); // XFS_ATTR3_LEAF_MAGIC in da3 blkinfo
        w64(blk, 24, 43); // blkno
        blk[40..56].copy_from_slice(&UUID);
        w16(blk, 56, 1); // hdr count
        // entry[0] at 80: {hash u32, nameidx u16, flags u8, pad u8}
        w32(blk, 80, 0xDEAD_BEEF);
        w16(blk, 84, 256); // nameidx
        blk[86] = 0; // flags: remote, user namespace
        // name block at 256: {valueblk u32, valuelen u32, namelen u8, name}
        w32(blk, 256, 1); // valueblk
        w32(blk, 260, 5000); // valuelen > eager-fetch bound
        blk[264] = 4;
        blk[265..269].copy_from_slice(b"huge");
        write_crc_be(blk, 12); // da3 crc is __be32 at blkinfo+4
    }
    let free = !0b11u64;
    i.inobt.push(ChunkRec { startino: 64, freecount: 62, free });
    i.free = vec![(28, 15), (44, 20), (64, 448)];
    let fs = mount(i.finish());
    let entries: Vec<_> = fs.walk().collect::<Result<_, _>>().expect("walk");
    let e = entries.iter().find(|e| e.path == "/x").expect("x file");
    assert_eq!(e.meta.get("xattr_count").map(String::as_str), Some("1"));
    assert_eq!(
        e.meta.get("xattr_user_huge").map(String::as_str),
        Some("5000 bytes (remote)")
    );
}

#[test]
fn truncated_image_surfaces_error_records() {
    // Keep the sb + AG headers + btree leaves (blocks 0-3) but cut the
    // inode chunk (block 4+) — mount succeeds leniently and the inode
    // reads arrive as Truncated error records in the walk stream.
    let img = weird_image();
    let short = img[..4 * BS].to_vec();
    let fs = XfsParser.mount(src(short)).expect("lenient mount");
    let mut errs = 0;
    let mut saw_truncated = false;
    for r in fs.walk() {
        if let Err(e) = r {
            errs += 1;
            saw_truncated |= matches!(e, sutram_fs::FsError::Truncated { .. });
        }
    }
    assert!(errs > 0, "expected error records");
    assert!(saw_truncated, "expected a Truncated record, got {errs} errors");
}
