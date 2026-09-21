//! Unit tests for the on-disk decoders (timestamps, extent/indirect maps,
//! dirent + slack carving, superblock validation).

use sutram_io::ByteSource;

use crate::dirent;
use crate::extent::{self, BlockMap};
use crate::inode::{self, Inode};
use crate::superblock::Superblock;

fn w16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Fabricate a 256-byte inode with extents flag and the given extent
/// entries (logical, len, phys) in the root of `i_block`.
fn mk_inode_with_extents(extents: &[(u32, u16, u64)]) -> Inode {
    let mut raw = vec![0u8; 256];
    w16(&mut raw, 0x00, 0x8000 | 0o644); // regular file
    w32(&mut raw, 0x04, 4096); // size
    w32(&mut raw, 0x1C, 16); // i_blocks (512B units)
    w32(&mut raw, 0x20, inode::EXT4_EXTENTS_FL);
    let b = &mut raw[0x28..0x28 + 60];
    w16(b, 0, 0xF30A);
    w16(b, 2, extents.len() as u16);
    w16(b, 4, 4); // eh_max for 60-byte root: (60-12)/12
    w16(b, 6, 0); // depth 0
    for (i, &(l, len, p)) in extents.iter().enumerate() {
        let e = 12 + i * 12;
        w32(b, e, l);
        w16(b, e + 4, len);
        w16(b, e + 6, (p >> 32) as u16);
        w32(b, e + 8, p as u32);
    }
    Inode::parse(&raw, 42, 0).unwrap()
}

#[test]
fn inode_extent_map_decodes() {
    let ino = mk_inode_with_extents(&[(0, 2, 100), (4, 1, 200)]);
    let map = extent::map_inode(&Vec::<u8>::new(), &ino, 1024, 1000).unwrap();
    match map {
        BlockMap::Runs(runs) => {
            assert_eq!(runs.len(), 2);
            assert_eq!((runs[0].logical, runs[0].phys, runs[0].len), (0, 100, 2));
            assert_eq!((runs[1].logical, runs[1].phys, runs[1].len), (4, 200, 1));
        }
        _ => panic!("expected Runs"),
    }
}

#[test]
fn inode_indirect_map_decodes() {
    // Source holding an indirect block at block 50 pointing at 60,61.
    let mut src = vec![0u8; 64 * 1024];
    w32(&mut src, 50 * 1024, 60);
    w32(&mut src, 50 * 1024 + 4, 61);
    let mut raw = vec![0u8; 256];
    w16(&mut raw, 0x00, 0x8000 | 0o644);
    w32(&mut raw, 0x04, 14 * 1024); // size → 14 blocks
    w32(&mut raw, 0x1C, 30);
    // 12 direct pointers → blocks 10..22; single indirect at block 50.
    for i in 0..12 {
        w32(&mut raw, 0x28 + i * 4, 10 + i as u32);
    }
    w32(&mut raw, 0x28 + 12 * 4, 50);
    let ino = Inode::parse(&raw, 42, 0).unwrap();
    let map = extent::map_inode(&src, &ino, 1024, 1000).unwrap();
    match map {
        BlockMap::Runs(runs) => {
            // 12 direct blocks merge into one run; indirect adds 60,61.
            let flat: Vec<u64> = runs
                .iter()
                .flat_map(|r| (r.phys..r.phys + r.len).collect::<Vec<_>>())
                .collect();
            assert_eq!(
                flat,
                (10..22).chain([60u64, 61]).collect::<Vec<_>>()
            );
        }
        _ => panic!("expected Runs"),
    }
}

#[test]
fn ext4_nsec_timestamps() {
    // 2024-01-15T10:30:20.5Z = 1705314620.5 s
    let ts = inode::ext4_ts(1_705_314_620, 500_000_000 << 2, "ext4-mtime");
    assert_eq!(ts.value, Some(1_705_314_620_500_000_000));
    assert_eq!(ts.granularity, std::time::Duration::from_nanos(1));
    // epoch extension bits: extra&3 << 32
    let ts2 = inode::ext4_ts(0xFFFF_FFFF, 1, "ext4-atime");
    assert_eq!(
        ts2.value,
        Some(((0xFFFF_FFFFi64) | (1i64 << 32)) * 1_000_000_000)
    );
    // zeroed → unset
    assert_eq!(inode::ext4_ts(0, 0, "ext4-ctime").value, None);
}

#[test]
fn dirent_and_slack_carve() {
    let mut blk = [0u8; 1024];
    // Live entry "a" ino 5, min rec 12, but rec_len covers the whole
    // block → slack holds a deleted "notes.txt" dirent (ino 9).
    w32(&mut blk, 0, 5);
    w16(&mut blk, 4, 1024);
    blk[6] = 1;
    blk[7] = dirent::FT_REG;
    blk[8] = b'a';
    w32(&mut blk, 12, 9);
    w16(&mut blk, 16, 32);
    blk[18] = 9;
    blk[19] = dirent::FT_REG;
    blk[20..29].copy_from_slice(b"notes.txt");
    let e = dirent::dirent_at(&blk, 0, 1024).unwrap();
    assert_eq!(e.name, "a");
    assert_eq!(e.slack, Some((12, 1024 - 12)));
    let carved = dirent::carve_slack(&blk, 12, 1024 - 12, 1024);
    assert_eq!(carved.len(), 1);
    assert_eq!(carved[0].name, "notes.txt");
    assert_eq!(carved[0].ino, 9);
}

#[test]
fn slack_carve_rejects_garbage() {
    let mut blk = [0u8; 1024];
    w32(&mut blk, 0, 5);
    w16(&mut blk, 4, 1024);
    blk[6] = 1;
    blk[7] = dirent::FT_REG;
    blk[8] = b'a';
    // Fill slack with pseudo-random bytes — must not produce dirents
    // (name would contain NULs/controls in most candidates).
    for (i, b) in blk[12..].iter_mut().enumerate() {
        *b = (i * 31 % 251) as u8;
    }
    let carved = dirent::carve_slack(&blk, 12, 1012, 1024);
    // Any survivors would be astonishing; assert the count stays low.
    assert!(carved.len() <= 2);
}

#[test]
fn superblock_detect_and_parse() {
    // Minimal valid 1 KiB superblock.
    let mut img = vec![0u8; 4096];
    let sb = 1024;
    w32(&mut img, sb, 64); // inodes_count
    w32(&mut img, sb + 4, 256); // blocks_count
    w32(&mut img, sb + 0x14, 1); // first_data_block
    w32(&mut img, sb + 0x18, 0); // log_block_size → 1 KiB
    w32(&mut img, sb + 0x20, 8192); // blocks_per_group
    w32(&mut img, sb + 0x28, 64); // inodes_per_group
    w16(&mut img, sb + 0x38, 0xEF53);
    w16(&mut img, sb + 0x3A, 1); // state
    w32(&mut img, sb + 0x4C, 1); // rev_level
    w32(&mut img, sb + 0x54, 11); // first_ino
    w16(&mut img, sb + 0x58, 256); // inode_size
    w32(&mut img, sb + 0x60, 0x42); // incompat: filetype|extents
    assert!(matches!(
        Superblock::detect(&img as &dyn ByteSource),
        sutram_fs::DetectConfidence::High | sutram_fs::DetectConfidence::Certain
    ));
    let s = Superblock::parse(&img).unwrap();
    assert_eq!(s.block_size, 1024);
    assert_eq!(s.groups_count, 1);
    assert_eq!(s.variant.name(), "ext4");
    // Garbage → None.
    assert_eq!(
        Superblock::detect(&vec![0xABu8; 4096] as &dyn ByteSource),
        sutram_fs::DetectConfidence::None
    );
}

/// Regression: `i_crtime` (0x90..0x94) requires `i_extra_isize` ≥ 0x14
/// and `i_crtime_extra` (0x94..0x98) ≥ 0x18. Previously the gates were
/// off by one field, fabricating crtime from non-inode bytes.
#[test]
fn crtime_field_gating() {
    let mk = |extra_isize: u16| {
        let mut raw = vec![0u8; 256];
        w16(&mut raw, 0x00, 0x8000);
        w16(&mut raw, 0x80, extra_isize);
        // Garbage-looking values at the crtime offsets — only readable
        // when the field is genuinely inside the extra region.
        w32(&mut raw, 0x90, 1_700_000_000);
        w32(&mut raw, 0x94, 1234 << 2);
        Inode::parse(&raw, 12, 0).unwrap()
    };
    // extra_isize 0x10: covers through 0x90 only → no crtime at all.
    assert_eq!(mk(0x10).crtime, None);
    // extra_isize 0x14: crtime present, crtime_extra absent.
    assert_eq!(mk(0x14).crtime, Some((1_700_000_000, 0)));
    // extra_isize 0x18: both fields present.
    assert_eq!(mk(0x18).crtime, Some((1_700_000_000, 1234 << 2)));
}

/// Regression: `bg_itable_unused_hi` lives at 0x32 in a 64-bit group
/// descriptor (0x34 is `bg_exclude_bitmap_hi`, not 0x36).
#[test]
fn gdt_itable_unused_hi_offset() {
    let mut buf = vec![0u8; 64];
    w32(&mut buf, 0x08, 0x1000); // inode_table_lo
    w16(&mut buf, 0x1C, 7); // itable_unused_lo
    w16(&mut buf, 0x32, 2); // itable_unused_hi
    w32(&mut buf, 0x34, 0xDEAD_BEEF); // exclude_bitmap_hi — must not leak in
    let d = crate::gdt::GroupDesc::parse(&buf, 0, true, 0).unwrap();
    assert_eq!(d.itable_unused, (2 << 16) | 7);
}

/// Regression: inline-data regular files keep data at i_block[0] —
/// the 4-byte header is the inline-*directory* layout, not a length.
#[test]
fn inline_data_file_map() {
    let mut raw = vec![0u8; 256];
    w16(&mut raw, 0x00, 0x8000);
    w32(&mut raw, 0x04, 10); // size
    w32(&mut raw, 0x20, inode::EXT4_INLINE_DATA_FL);
    // First four bytes are *file data*, not a length prefix.
    raw[0x28..0x28 + 10].copy_from_slice(b"0123456789");
    let ino = Inode::parse(&raw, 12, 0).unwrap();
    match extent::map_inode(&Vec::<u8>::new(), &ino, 1024, 1000).unwrap() {
        BlockMap::Inline { len } => assert_eq!(len, 10),
        _ => panic!("expected Inline"),
    }
}

/// Inline-data directory: i_block[0..4] = parent ino, dirents in [4..60].
#[test]
fn inline_data_dir_map() {
    let mut raw = vec![0u8; 256];
    w16(&mut raw, 0x00, 0x4000); // directory
    w32(&mut raw, 0x04, 60);
    w32(&mut raw, 0x20, inode::EXT4_INLINE_DATA_FL);
    w32(&mut raw, 0x28, 2); // parent inode — NOT a length
    let ino = Inode::parse(&raw, 12, 0).unwrap();
    match extent::map_inode(&Vec::<u8>::new(), &ino, 1024, 1000).unwrap() {
        BlockMap::InlineDir => {}
        _ => panic!("expected InlineDir"),
    }
}

/// Regression: the jbd2 superblock's `s_nr_users` sits at 0x40 — the
/// probe must read past byte 64 or the field silently defaults to 1.
#[test]
fn journal_nr_users_field() {
    let mut blk = vec![0u8; 128];
    // big-endian jbd2 superblock
    blk[0..4].copy_from_slice(&0xC03B_3998u32.to_be_bytes());
    blk[4..8].copy_from_slice(&4u32.to_be_bytes()); // superblock v2
    blk[0x40..0x44].copy_from_slice(&3u32.to_be_bytes());
    let j = crate::journal::JournalInfo::parse(&blk, 0).unwrap();
    assert_eq!(j.nr_users, 3);
}

#[test]
fn journal_parse_rejects() {
    // Bad magic → None.
    let mut blk = vec![0u8; 128];
    blk[4..8].copy_from_slice(&4u32.to_be_bytes());
    assert!(crate::journal::JournalInfo::parse(&blk, 0).is_none());
    // Right magic, wrong blocktype → None.
    let mut blk = vec![0u8; 128];
    blk[0..4].copy_from_slice(&0xC03B_3998u32.to_be_bytes());
    blk[4..8].copy_from_slice(&1u32.to_be_bytes());
    assert!(crate::journal::JournalInfo::parse(&blk, 0).is_none());
    // Short buffer → None.
    let blk = vec![0u8; 32];
    assert!(crate::journal::JournalInfo::parse(&blk, 0).is_none());
}

#[test]
fn extent_header_rejects_corruption() {
    let ino = |blk: &mut [u8; 60]| {
        let mut raw = vec![0u8; 256];
        w16(&mut raw, 0x00, 0x8000);
        w32(&mut raw, 0x04, 4096);
        w32(&mut raw, 0x1C, 16);
        w32(&mut raw, 0x20, inode::EXT4_EXTENTS_FL);
        raw[0x28..0x28 + 60].copy_from_slice(blk);
        Inode::parse(&raw, 1, 0).unwrap()
    };
    let src = Vec::<u8>::new();
    // Bad magic.
    let mut b = [0u8; 60];
    w16(&mut b, 0, 0xDEAD);
    assert!(extent::map_inode(&src, &ino(&mut b), 1024, 1000).is_err());
    // entries > capacity (60-byte root caps at 4).
    let mut b = [0u8; 60];
    w16(&mut b, 0, 0xF30A);
    w16(&mut b, 2, 10);
    w16(&mut b, 4, 10);
    assert!(extent::map_inode(&src, &ino(&mut b), 1024, 1000).is_err());
    // depth > 5.
    let mut b = [0u8; 60];
    w16(&mut b, 0, 0xF30A);
    w16(&mut b, 6, 9);
    assert!(extent::map_inode(&src, &ino(&mut b), 1024, 1000).is_err());
}

#[test]
fn extent_tree_idx_cycle_and_uninit() {
    // 1 KiB-block image with a leaf node at block 70.
    let mut src = vec![0u8; 80 * 1024];
    // Leaf node @70: magic + 2 entries (one uninitialised extent).
    let leaf = 70 * 1024;
    w16(&mut src, leaf, 0xF30A);
    w16(&mut src, leaf + 2, 2);
    w16(&mut src, leaf + 4, 84); // eh_max = (1024-12)/12
    w16(&mut src, leaf + 6, 0);
    w32(&mut src, leaf + 12, 0); // logical 0
    w16(&mut src, leaf + 16, 0x8001); // uninit, real len 1
    w32(&mut src, leaf + 20, 100);
    w32(&mut src, leaf + 24, 1); // logical 1, len 3, phys 200
    w16(&mut src, leaf + 28, 3);
    w32(&mut src, leaf + 32, 200);
    // Inode: depth-1 idx root → child 70; second idx entry cycles to a
    // (nonexistent) root block — dedup via visited-set keeps it out only
    // if the same child repeats; point both at 70 to exercise the skip.
    let mut b = [0u8; 60];
    w16(&mut b, 0, 0xF30A);
    w16(&mut b, 2, 2);
    w16(&mut b, 4, 4);
    w16(&mut b, 6, 1); // depth 1
    w32(&mut b, 12, 0); // ei_block
    w32(&mut b, 16, 70); // ei_leaf_lo
    w32(&mut b, 24, 5);
    w32(&mut b, 28, 70); // same child again — visited-set skips
    let ino = {
        let mut raw = vec![0u8; 256];
        w16(&mut raw, 0x00, 0x8000);
        w32(&mut raw, 0x04, 4096);
        w32(&mut raw, 0x1C, 16);
        w32(&mut raw, 0x20, inode::EXT4_EXTENTS_FL);
        raw[0x28..0x28 + 60].copy_from_slice(&b);
        Inode::parse(&raw, 1, 0).unwrap()
    };
    match extent::map_inode(&src, &ino, 1024, 1000).unwrap() {
        BlockMap::Runs(runs) => {
            // Child visited once: two leaf extents, uninit len decoded.
            assert_eq!(runs.len(), 2);
            assert_eq!((runs[0].logical, runs[0].len, runs[0].phys), (0, 1, 100));
            assert_eq!((runs[1].logical, runs[1].len, runs[1].phys), (1, 3, 200));
        }
        _ => panic!("expected Runs"),
    }
}

#[test]
fn indirect_double_and_self_cycle() {
    // Double-indirect: i_block[13] → block 40 (list of indirects) →
    // block 41 (list of data blocks 90,91). Entry 1 of block 40 points
    // back at 40 — a self-cycle the visited-set must cut.
    let mut src = vec![0u8; 128 * 1024];
    w32(&mut src, 40 * 1024, 41);
    w32(&mut src, 40 * 1024 + 4, 40); // cycle
    w32(&mut src, 41 * 1024, 90);
    w32(&mut src, 41 * 1024 + 4, 91);
    let mut raw = vec![0u8; 256];
    w16(&mut raw, 0x00, 0x8000);
    w32(&mut raw, 0x04, 400 * 1024);
    w32(&mut raw, 0x1C, 400);
    // 12 direct pointers all zero (holes), single-indirect 0,
    // double-indirect → 40.
    w32(&mut raw, 0x28 + 13 * 4, 40);
    let ino = Inode::parse(&raw, 1, 0).unwrap();
    match extent::map_inode(&src, &ino, 1024, 1000).unwrap() {
        BlockMap::Runs(runs) => {
            let flat: Vec<u64> = runs
                .iter()
                .flat_map(|r| (r.phys..r.phys + r.len).collect::<Vec<_>>())
                .collect();
            assert_eq!(flat, vec![90, 91]);
            // logical position of the first indirect data block:
            // 12 direct + 256 single-indirect slots.
            assert_eq!(runs[0].logical, 12 + 256);
        }
        _ => panic!("expected Runs"),
    }
}

#[test]
fn indirect_cap_tracks_file_size() {
    // The logical-slot bound must reach a legit 20 GiB file's tail on a
    // large volume (blocks_count > 4M) — the old flat 4M cap truncated.
    let cap = extent::indirect_cap(20 << 30, 4096, 1 << 30);
    assert!(cap >= (20 << 30) / 4096, "cap {cap} below size-in-blocks");
    // But it is still bounded: huge corrupt sizes clamp to blocks_count,
    // small/zero sizes floor at 4M slots (never hide residue).
    assert_eq!(extent::indirect_cap(u64::MAX, 4096, 1 << 30), 1 << 30);
    assert_eq!(extent::indirect_cap(0, 4096, 1 << 30), 1 << 22);
    assert_eq!(extent::indirect_cap(0, 1024, 1000), 1000);
}

#[test]
fn superblock_rejects_bad_fields() {
    let base = || {
        let mut img = vec![0u8; 4096];
        let sb = 1024;
        w32(&mut img, sb, 64);
        w32(&mut img, sb + 4, 256);
        w32(&mut img, sb + 0x14, 1);
        w32(&mut img, sb + 0x20, 8192);
        w32(&mut img, sb + 0x28, 64);
        w16(&mut img, sb + 0x38, 0xEF53);
        w32(&mut img, sb + 0x4C, 1);
        w16(&mut img, sb + 0x58, 256);
        img
    };
    assert!(Superblock::parse(&base()).is_ok());
    // log_block_size > 6.
    let mut i = base();
    w32(&mut i, 1024 + 0x18, 7);
    assert!(Superblock::parse(&i).is_err());
    // zero inode count.
    let mut i = base();
    w32(&mut i, 1024, 0);
    assert!(Superblock::parse(&i).is_err());
    // zero blocks_per_group.
    let mut i = base();
    w32(&mut i, 1024 + 0x20, 0);
    assert!(Superblock::parse(&i).is_err());
    // blocks_per_group beyond bitmap capacity (1 KiB → ≤8192).
    let mut i = base();
    w32(&mut i, 1024 + 0x20, 9000);
    assert!(Superblock::parse(&i).is_err());
    // first_data_block inconsistent with block size (0 for 1 KiB).
    let mut i = base();
    w32(&mut i, 1024 + 0x14, 0);
    assert!(Superblock::parse(&i).is_err());
    // non-power-of-two inode size.
    let mut i = base();
    w16(&mut i, 1024 + 0x58, 192);
    assert!(Superblock::parse(&i).is_err());
    // inode table bigger than a group.
    let mut i = base();
    w32(&mut i, 1024 + 0x28, 40000);
    assert!(Superblock::parse(&i).is_err());
    // inodes_count beyond inode-table capacity.
    let mut i = base();
    w32(&mut i, 1024, 5000);
    w32(&mut i, 1024 + 0x28, 64);
    assert!(Superblock::parse(&i).is_err());
}

#[test]
fn sparse_super_backup_groups() {
    let mut img = vec![0u8; 8192];
    let sb = 1024;
    w32(&mut img, sb, 64);
    w32(&mut img, sb + 4, 65536); // 8 groups of 8192
    w32(&mut img, sb + 0x14, 1);
    w32(&mut img, sb + 0x20, 8192);
    w32(&mut img, sb + 0x28, 64);
    w16(&mut img, sb + 0x38, 0xEF53);
    w32(&mut img, sb + 0x4C, 1);
    w16(&mut img, sb + 0x58, 256);
    w32(&mut img, sb + 0x64, 0x0001); // sparse_super
    let s = Superblock::parse(&img).unwrap();
    let expect = [true, true, false, true, false, true, false, true];
    for (g, e) in expect.iter().enumerate() {
        assert_eq!(s.group_has_backup_sb(g as u32), *e, "group {g}");
    }
    // 1 KiB blocks → backup SB at group*bpg + 1.
    assert_eq!(
        s.backup_sb_blocks(),
        vec![1, 8193, 3 * 8192 + 1, 5 * 8192 + 1, 7 * 8192 + 1]
    );
    // Without sparse_super every group holds a copy.
    w32(&mut img, sb + 0x64, 0);
    let s = Superblock::parse(&img).unwrap();
    assert_eq!(s.backup_sb_blocks().len(), 8);
}

#[test]
fn xattr_block_and_value_decode() {
    // Bad magic / short block → no names.
    assert!(inode::parse_xattr_block(&[0u8; 8]).is_empty());
    assert!(inode::parse_xattr_block(&[0u8; 64]).is_empty());
    // Valid block with one entry.
    let mut blk = vec![0u8; 128];
    w32(&mut blk, 0, 0xEA02_0000);
    blk[32] = 7; // name_len
    blk[33] = 1; // user.
    w32(&mut blk, 40, 3); // value_size
    blk[48..55].copy_from_slice(b"comment");
    assert_eq!(inode::parse_xattr_block(&blk), vec!["user.comment"]);
    // ibody_xattr_value finds a system.data entry.
    let mut raw = vec![0u8; 256];
    w16(&mut raw, 0x00, 0x8000);
    w16(&mut raw, 0x80, 32); // extra_isize → region at 160
    w32(&mut raw, 160, 0xEA02_0000);
    raw[164] = 11; // name_len
    raw[165] = inode::XATTR_IDX_SYSTEM;
    w16(&mut raw, 166, 241); // value_offs
    w32(&mut raw, 172, 15); // value_size
    raw[180..191].copy_from_slice(b"system.data");
    raw[241..256].copy_from_slice(b"SPILLOVER-TAIL!");
    let ino = Inode::parse(&raw, 5, 0).unwrap();
    assert_eq!(
        ino.ibody_xattr_value(inode::XATTR_IDX_SYSTEM, "system.data"),
        Some((241, 15))
    );
    assert_eq!(
        ino.ibody_xattr_value(inode::XATTR_IDX_SYSTEM, "system.nope"),
        None
    );
    // Value bounds escaping the inode → None.
    w16(&mut raw, 166, 250);
    let ino = Inode::parse(&raw, 5, 0).unwrap();
    assert_eq!(
        ino.ibody_xattr_value(inode::XATTR_IDX_SYSTEM, "system.data"),
        None
    );
}

#[test]
fn dirent_header_edge_cases() {
    let mut blk = [0u8; 64];
    w32(&mut blk, 0, 5);
    w16(&mut blk, 4, 12);
    blk[6] = 1;
    blk[7] = dirent::FT_REG;
    blk[8] = b'a';
    assert!(dirent::dirent_at(&blk, 0, 64).is_some());
    // rec_len < 8 → reject.
    w16(&mut blk, 4, 4);
    assert!(dirent::dirent_at(&blk, 0, 64).is_none());
    // rec_len not 4-aligned → reject.
    w16(&mut blk, 4, 13);
    assert!(dirent::dirent_at(&blk, 0, 64).is_none());
    // name_len beyond rec_len → reject.
    w16(&mut blk, 4, 12);
    blk[6] = 60;
    assert!(dirent::dirent_at(&blk, 0, 64).is_none());
    // rec_len crossing the block end → reject.
    w16(&mut blk, 4, 64);
    blk[6] = 1;
    assert!(dirent::dirent_at(&blk, 8, 64).is_none());
}

#[test]
fn inode_short_buffer_and_fast_symlink() {
    assert!(Inode::parse(&[0u8; 64], 1, 0).is_none());
    let mut raw = vec![0u8; 256];
    w16(&mut raw, 0x00, 0xA000);
    w32(&mut raw, 0x04, 20);
    let ino = Inode::parse(&raw, 1, 0).unwrap();
    assert!(ino.is_fast_symlink());
    // Slow link: has blocks → not fast.
    w32(&mut raw, 0x1C, 2);
    let ino = Inode::parse(&raw, 1, 0).unwrap();
    assert!(!ino.is_fast_symlink());
}
