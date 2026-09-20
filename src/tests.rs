//! Unit tests for the on-disk decoders and the chunk map.

use crate::chunk::{parse_sys_chunk_array, ChunkMap};
use crate::ondisk::*;

fn w64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

#[test]
fn key_parses() {
    let mut b = [0u8; 17];
    w64(&mut b, 0, 0x1122);
    b[8] = 84;
    w64(&mut b, 9, 0x3344);
    let k = Key::parse(&b, 0).unwrap();
    assert_eq!((k.objectid, k.ty, k.offset), (0x1122, 84, 0x3344));
    assert!(Key::parse(&b[..10], 0).is_none());
}

#[test]
fn timespec_to_fs() {
    let ts = Timespec {
        sec: 1_700_000_000,
        nsec: 123,
    };
    let f = ts.to_fs();
    assert_eq!(f.value, Some(1_700_000_000_000_000_123));
    assert_eq!(f.raw_encoding, "btrfs-timespec");
    // zero → unset (BTRFS leaves unknown times zeroed)
    assert_eq!(Timespec::default().to_fs().value, None);
}

#[test]
fn inode_item_layout() {
    let mut b = vec![0u8; 160];
    w64(&mut b, 16, 12345); // size
    b[52..56].copy_from_slice(&0o100644u32.to_le_bytes()); // regular file
    w64(&mut b, 112, 1_700_000_000); // atime sec
    let i = InodeItem::parse(&b, 0).unwrap();
    assert_eq!(i.size, 12345);
    assert!(matches!(i.kind(), sutram_fs::EntryKind::File));
    assert_eq!(i.atime.sec, 1_700_000_000);
    assert!(InodeItem::parse(&b[..100], 0).is_none());
}

#[test]
fn file_extent_regular_and_inline() {
    let mut b = vec![0u8; 60];
    w64(&mut b, 0, 7); // generation
    w64(&mut b, 8, 100); // ram_bytes
    b[16] = compression::NONE;
    b[20] = extent_ty::REGULAR;
    w64(&mut b, 21, 0x500000); // disk_bytenr
    w64(&mut b, 29, 100); // disk_num_bytes
    w64(&mut b, 37, 0); // offset
    w64(&mut b, 45, 100); // num_bytes
    let fe = FileExtentItem::parse(&b).unwrap();
    assert_eq!(fe.disk_bytenr, 0x500000);
    assert_eq!(fe.num_bytes, 100);

    // inline: only 21-byte header + data
    let mut b2 = vec![0u8; 30];
    w64(&mut b2, 8, 9);
    b2[20] = extent_ty::INLINE;
    let fe2 = FileExtentItem::parse(&b2).unwrap();
    assert_eq!(fe2.ty, extent_ty::INLINE);
    assert_eq!(fe2.num_bytes, 9);
    assert_eq!(fe2.disk_bytenr, 0);
}

#[test]
fn chunk_identity_and_striped() {
    let mut m = ChunkMap::default();
    m.add_chunk(0x1000, 0x100000, 0x2000);
    assert_eq!(m.logical_to_physical(0x1000), Some(0x2000));
    assert_eq!(m.logical_to_physical(0x1800), Some(0x2800));
    assert_eq!(m.logical_to_physical(0x101000), None);

    // RAID0: two stripes, stripe_len 64K
    m.add(crate::chunk::ChunkEntry {
        logical: 0x200000,
        length: 0x40000,
        ty: block_group::DATA | block_group::RAID0,
        stripe_len: 0x10000,
        stripe_offsets: vec![0x900000, 0xA00000],
        parity: false,
    });
    assert_eq!(m.logical_to_physical(0x200000), Some(0x900000));
    assert_eq!(m.logical_to_physical(0x210000), Some(0xA00000)); // band 1 → stripe 1
    assert_eq!(m.logical_to_physical(0x220000), Some(0x910000)); // band 2 → stripe 0 + s
}

#[test]
fn sys_chunk_array_parse() {
    // one key + one single-stripe chunk
    let mut b = vec![0u8; 17 + CHUNK_ITEM_FIXED_SIZE + STRIPE_SIZE];
    w64(&mut b, 0, objid::FIRST_CHUNK_TREE);
    b[8] = ty::CHUNK_ITEM;
    w64(&mut b, 9, 0); // logical 0
    let c = 17;
    w64(&mut b, c, 0x800000); // length 8MiB
    w64(&mut b, c + 8, 3); // owner
    w64(&mut b, c + 16, 0x10000); // stripe_len
    w64(&mut b, c + 24, block_group::SYSTEM);
    b[c + 44..c + 46].copy_from_slice(&1u16.to_le_bytes()); // 1 stripe
    w64(&mut b, c + 48, 1); // devid
    w64(&mut b, c + 56, 0); // physical offset
    let map = parse_sys_chunk_array(&b);
    assert_eq!(map.chunks.len(), 1);
    assert_eq!(map.logical_to_physical(0x1234), Some(0x1234));
}

#[test]
fn superblock_mirror_fallback() {
    // primary corrupt, mirror at 64MiB valid
    let mut img = vec![0u8; (0x4000000 + SUPERBLOCK_SIZE) as usize];
    let sb = 0x4000000usize;
    img[sb + MAGIC_OFFSET..sb + MAGIC_OFFSET + 8].copy_from_slice(BTRFS_MAGIC);
    w64(&mut img, sb + 0x50, 0x401000); // root
    w64(&mut img, sb + 0x58, 0x400000); // chunk_root
    w64(&mut img, sb + 0x70, 0x800000); // total_bytes
    img[sb + 0x90..sb + 0x94].copy_from_slice(&4096u32.to_le_bytes());
    img[sb + 0x94..sb + 0x98].copy_from_slice(&4096u32.to_le_bytes());
    w64(&mut img, sb + 0x48, 9); // generation
    let csum = crc32fast::hash(&img[sb + CSUM_SIZE..sb + SUPERBLOCK_SIZE]);
    img[sb..sb + 4].copy_from_slice(&csum.to_le_bytes());
    let (s, mirror) = crate::superblock::read_superblock(&img.as_slice()).unwrap();
    assert!(mirror);
    assert_eq!(s.generation, 9);
    assert_eq!(s.csum_ok, Some(true));

    // corrupt the mirror too → mount fails
    let mut img2 = img.clone();
    img2[sb + MAGIC_OFFSET] = b'X';
    assert!(crate::superblock::read_superblock(&img2.as_slice()).is_err());
}

#[test]
fn dir_item_parse() {
    let mut b = vec![0u8; DIR_ITEM_FIXED_SIZE + 8];
    // location key
    w64(&mut b, 0, 257);
    b[8] = 1;
    w64(&mut b, 9, 0);
    w64(&mut b, 17, 5); // transid
    b[25..27].copy_from_slice(&0u16.to_le_bytes()); // data_len
    b[27..29].copy_from_slice(&8u16.to_le_bytes()); // name_len
    b[29] = ft::REG_FILE;
    b[30..38].copy_from_slice(b"file.txt");
    let d = DirItem::parse(&b, 0).unwrap();
    assert_eq!(d.location.objectid, 257);
    assert_eq!(d.name(&b).unwrap(), b"file.txt");
    assert_eq!(d.total, 38);
}

#[test]
fn root_backup_parse() {
    let mut b = vec![0u8; ROOT_BACKUP_SIZE];
    w64(&mut b, 0, 0x401000);
    w64(&mut b, 8, 5);
    w64(&mut b, 48, 0x420000); // fs_root
    w64(&mut b, 56, 5); // fs_root_gen
    let rb = RootBackup::parse(&b, 0).unwrap();
    assert!(rb.valid());
    assert_eq!(rb.fs_root, 0x420000);
}
