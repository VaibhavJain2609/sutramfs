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
    w16(&mut blk, 4, 1024 - 0);
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
