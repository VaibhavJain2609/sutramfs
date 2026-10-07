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
        sub_stripes: 0,
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
    let mut img = vec![0u8; 0x4000000 + SUPERBLOCK_SIZE];
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

#[test]
fn raid_profiles_translate() {
    use crate::chunk::ChunkEntry;
    let entry = |ty, sub, offsets: Vec<u64>| ChunkEntry {
        logical: 0x100000,
        length: 0x40000, // 4 stripe units of 64K
        ty,
        stripe_len: 0x10000,
        sub_stripes: sub,
        stripe_offsets: offsets,
        parity: !block_group::translatable(ty),
    };
    // DUP (2 stripes): every byte reads stripe 0.
    let dup = entry(block_group::METADATA | block_group::DUP, 0, vec![0xA0000, 0xB0000]);
    assert_eq!(dup.stripe_map(0x12345), (0, 0x12345));
    assert_eq!(dup.stripe_map(0x30000), (0, 0x30000));
    // RAID1 (2 stripes): identical copies → stripe 0.
    let r1 = entry(block_group::DATA | block_group::RAID1, 0, vec![0xA0000, 0xB0000]);
    assert_eq!(r1.stripe_map(0x1FFFF), (0, 0x1FFFF));
    // RAID0 (2 stripes): bands alternate stripes; offset advances within
    // each stripe.
    let r0 = entry(block_group::DATA | block_group::RAID0, 0, vec![0xA0000, 0xB0000]);
    assert_eq!(r0.stripe_map(0), (0, 0));
    assert_eq!(r0.stripe_map(0x10000), (1, 0));
    assert_eq!(r0.stripe_map(0x20000), (0, 0x10000));
    assert_eq!(r0.stripe_map(0x21000), (0, 0x11000));
    // RAID10 (4 stripes, sub=2): groups of 2 mirrors; primary at group*2.
    let r10 = entry(
        block_group::DATA | block_group::RAID10,
        2,
        vec![0xA0000, 0xB0000, 0xC0000, 0xD0000],
    );
    assert_eq!(r10.stripe_map(0), (0, 0));
    assert_eq!(r10.stripe_map(0x10000), (2, 0));
    assert_eq!(r10.stripe_map(0x20000), (0, 0x10000));
    assert_eq!(r10.stripe_map(0x30000), (2, 0x10000));
}

/// Minimal leaf builder for `index_extent_tree` tests (item data grows
/// backward from the 4 KiB node end; checksum left unverifiable).
fn extent_tree_src(items: &[(u64, u8, u64, Vec<u8>)]) -> Vec<u8> {
    let mut img = vec![0u8; 0x4000 + 4096];
    let base = 0x4000usize;
    let mut cur = 4096;
    for (i, (obj, ty, off, body)) in items.iter().enumerate() {
        let ip = base + 101 + i * 25;
        w64(&mut img, ip, *obj);
        img[ip + 8] = *ty;
        w64(&mut img, ip + 9, *off);
        cur -= body.len();
        img[base + cur..base + cur + body.len()].copy_from_slice(body);
        img[ip + 17..ip + 21].copy_from_slice(&((cur - 101) as u32).to_le_bytes());
        img[ip + 21..ip + 25].copy_from_slice(&(body.len() as u32).to_le_bytes());
    }
    w64(&mut img, base + 0x30, 0x4000); // bytenr
    w64(&mut img, base + 0x50, 7); // generation
    w64(&mut img, base + 0x58, 2); // owner = extent tree
    img[base + 0x60..base + 0x64].copy_from_slice(&(items.len() as u32).to_le_bytes());
    img
}

#[test]
fn inline_backrefs_do_not_desync() {
    use crate::index::{index_extent_tree, ExtentRef};
    // extent_item(24B) + inline TREE_BLOCK_REF(1+8) + inline
    // EXTENT_DATA_REF(1+28) — the kernel sizes these payloads at 8 and 28;
    // any drift desyncs the second ref.
    let mut body = vec![0u8; 24];
    w64(&mut body, 0, 2); // refs
    w64(&mut body, 8, 7); // generation
    w64(&mut body, 16, 1); // DATA flag
    body.push(ty::TREE_BLOCK_REF);
    body.extend_from_slice(&300u64.to_le_bytes()); // referencing root
    body.push(ty::EXTENT_DATA_REF);
    body.extend_from_slice(&5u64.to_le_bytes()); // root = FS_TREE
    body.extend_from_slice(&999u64.to_le_bytes()); // inode
    body.extend_from_slice(&0u64.to_le_bytes()); // file offset
    body.extend_from_slice(&1u32.to_le_bytes()); // count
    let img = extent_tree_src(&[(0x500000, ty::EXTENT_ITEM, 4096, body)]);
    let mut map = ChunkMap::default();
    map.add_chunk(0, 0x1000000, 0);
    let idx = index_extent_tree(&img, &map, 4096, 1 /* non-CRC32C: skip verify */, 0x4000);
    let rec = idx.recs.get(&0x500000).expect("extent record");
    assert!(rec
        .refs
        .iter()
        .any(|r| matches!(r, ExtentRef::TreeBlock { root } if *root == 300)));
    assert!(rec.refs.iter().any(|r| matches!(
        r,
        ExtentRef::Data { root: 5, inode: 999, .. }
    )));

    // SHARED_DATA_REF payload = parent(8) + count(4) = 12 bytes.
    let mut body = vec![0u8; 24];
    w64(&mut body, 8, 7);
    w64(&mut body, 16, 1);
    body.push(ty::SHARED_DATA_REF);
    body.extend_from_slice(&0x9000u64.to_le_bytes()); // parent bytenr
    body.extend_from_slice(&3u32.to_le_bytes()); // count
    body.push(ty::EXTENT_DATA_REF);
    body.extend_from_slice(&5u64.to_le_bytes());
    body.extend_from_slice(&777u64.to_le_bytes());
    body.extend_from_slice(&8u64.to_le_bytes());
    body.extend_from_slice(&2u32.to_le_bytes());
    let img = extent_tree_src(&[(0x501000, ty::EXTENT_ITEM, 4096, body)]);
    let idx = index_extent_tree(&img, &map, 4096, 1, 0x4000);
    let rec = idx.recs.get(&0x501000).expect("extent record");
    assert!(rec
        .refs
        .iter()
        .any(|r| matches!(r, ExtentRef::SharedData { parent } if *parent == 0x9000)));
    assert!(rec.refs.iter().any(|r| matches!(
        r,
        ExtentRef::Data { root: 5, inode: 777, .. }
    )));
}

// ---------------------------------------------------------------------------
// Coverage expansion: decoders, chunk map, trees, reader, recovery helpers.
// ---------------------------------------------------------------------------

fn w16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
#[allow(dead_code)]
fn w8(b: &mut [u8], off: usize, v: u8) {
    b[off] = v;
}

/// Leaf builder writing a node at `at` (identity-mapped by tests' ChunkMap).
/// `level` 0 → items are (objid, ty, key_offset, body); >0 → keyptrs.
fn leaf_src(at: usize, owner: u64, gen: u64, items: &[(u64, u8, u64, Vec<u8>)]) -> Vec<u8> {
    let mut img = vec![0u8; at + 4096];
    let mut cur = 4096usize;
    for (i, (obj, ty, off, body)) in items.iter().enumerate() {
        let ip = at + 101 + i * 25;
        w64(&mut img, ip, *obj);
        img[ip + 8] = *ty;
        w64(&mut img, ip + 9, *off);
        cur -= body.len();
        img[at + cur..at + cur + body.len()].copy_from_slice(body);
        w32(&mut img, ip + 17, (cur - 101) as u32);
        w32(&mut img, ip + 21, body.len() as u32);
    }
    w64(&mut img, at + 0x30, at as u64);
    w64(&mut img, at + 0x50, gen);
    w64(&mut img, at + 0x58, owner);
    w32(&mut img, at + 0x60, items.len() as u32);
    img
}

fn internal_src(
    img: &mut Vec<u8>,
    at: usize,
    owner: u64,
    gen: u64,
    level: u8,
    ptrs: &[(u64, u8, u64, u64)],
    ptr_gen: u64,
) {
    img.resize(at + 4096, 0);
    for (i, (obj, ty, off, ptr)) in ptrs.iter().enumerate() {
        let pp = at + 101 + i * 33;
        w64(img, pp, *obj);
        img[pp + 8] = *ty;
        w64(img, pp + 9, *off);
        w64(img, pp + 17, *ptr);
        w64(img, pp + 25, ptr_gen);
    }
    w64(img, at + 0x30, at as u64);
    w64(img, at + 0x50, gen);
    w64(img, at + 0x58, owner);
    w32(img, at + 0x60, ptrs.len() as u32);
    img[at + 0x64] = level;
}

fn ident_map() -> ChunkMap {
    let mut m = ChunkMap::default();
    m.add_chunk(0, 0x100_0000, 0);
    m
}

// ---- decompress -------------------------------------------------------------

#[test]
fn decompress_zlib_and_errors() {
    use crate::decompress::{decompress, supported};
    use std::io::Write;
    let plain = b"hello btrfs zlib world hello btrfs zlib world";
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(plain).unwrap();
    let comp = e.finish().unwrap();
    assert_eq!(decompress(1, &comp, plain.len()).unwrap(), plain);
    // short/truncated stream → Ok(partial) or Err, never panic.
    let _ = decompress(1, &comp[..5], plain.len());
    assert!(decompress(9, b"x", 10).is_err()); // unsupported algo
    assert!(decompress(2, b"x", 10).is_err()); // lzo shorter than header
    assert!(!supported(9));
    assert!(supported(1) && supported(2) && supported(3));
    // NONE truncates to expected.
    assert_eq!(decompress(0, b"abcdef", 3).unwrap(), b"abc");
}

#[test]
fn decompress_zstd_raw_frame() {
    use crate::decompress::decompress;
    // Minimal zstd frame: magic + FHD(0x00: single_seg=0,fcs=0) +
    // window desc(0x00) + one RAW block (last=1,type=0,size=3) + "ABC".
    let frame: &[u8] = &[
        0x28, 0xB5, 0x2F, 0xFD, // magic
        0x00, // frame header descriptor
        0x00, // window descriptor
        0x19, 0x00, 0x00, // block header: last=1, raw, size=3
        b'A', b'B', b'C',
    ];
    let out = decompress(3, frame, 3);
    match out {
        Ok(v) => assert_eq!(v, b"ABC"),
        Err(e) => panic!("zstd raw frame failed: {e}"),
    }
    let _ = decompress(3, b"\x28\xb5garbage", 10); // corrupt → no panic
}

#[test]
fn decompress_lzo_framing() {
    use crate::decompress::decompress;
    // LZO1X literal-only stream: byte 17+n → copy n literals; end 17 0 0.
    let mut lzo = Vec::new();
    lzo.push(17 + 5);
    lzo.extend_from_slice(b"HELLO");
    lzo.extend_from_slice(&[17, 0, 0]);
    // BTRFS framing: tot_len(4) then [in_len(4)][data] sub-blocks.
    let mut input = Vec::new();
    let tot = (4 + 4 + lzo.len()) as u32;
    input.extend_from_slice(&tot.to_le_bytes());
    input.extend_from_slice(&(lzo.len() as u32).to_le_bytes());
    input.extend_from_slice(&lzo);
    match decompress(2, &input, 5) {
        Ok(v) => assert_eq!(&v[..5], b"HELLO"),
        Err(e) => panic!("lzo literal stream failed: {e}"),
    }
    // tot_len longer than input → bounded by input.len(), still no panic.
    let mut bad = input.clone();
    bad[0] = 0xFF;
    let _ = decompress(2, &bad, 5);
}

// ---- ondisk decoders --------------------------------------------------------

#[test]
fn misc_decoders() {
    assert_eq!(ft::name(ft::REG_FILE), "file");
    assert_eq!(ft::name(ft::XATTR), "xattr");
    assert_eq!(ft::name(99), "unknown");
    assert_eq!(ft::entry_kind(ft::DIR), Some(sutram_fs::EntryKind::Directory));
    assert_eq!(ft::entry_kind(ft::FIFO), None);
    assert_eq!(compression::name(2), "lzo");
    assert_eq!(compression::name(9), "unknown");
    // InodeItem kind Other + is_dir.
    let mut b = vec![0u8; 160];
    w32(&mut b, 52, 0o060000); // socket-ish → Other
    let i = InodeItem::parse(&b, 0).unwrap();
    assert_eq!(i.kind(), sutram_fs::EntryKind::Other);
    assert!(!i.is_dir());
    w32(&mut b, 52, 0o040755);
    assert!(InodeItem::parse(&b, 0).unwrap().is_dir());
    // FreeSpaceEntry.
    let mut f = [0u8; 16];
    w64(&mut f, 0, 0x9000);
    w64(&mut f, 8, 0x4000);
    let fe = FreeSpaceEntry::parse(&f).unwrap();
    assert_eq!((fe.offset, fe.length), (0x9000, 0x4000));
    assert!(FreeSpaceEntry::parse(&f[..8]).is_none());
    // RootItem generation_v2 preference + short buffer.
    let mut r = vec![0u8; 439];
    w64(&mut r, 160, 5);
    w64(&mut r, 239, 9); // generation_v2
    let ri = RootItem::parse(&r).unwrap();
    assert_eq!(ri.tree_gen(), 9);
    assert!(RootItem::parse(&r[..100]).is_none());
    // DevItem + ExtentItem + ExtentDataRef shorts.
    assert!(DevItem::parse(&[0u8; 10]).is_none());
    assert!(ExtentItem::parse(&[0u8; 10]).is_none());
    assert!(ExtentDataRef::parse(&[0u8; 10], 0).is_none());
    // Multi-stripe chunk.
    let mut c = vec![0u8; 48 + 64];
    w64(&mut c, 0, 0x8000); // length
    w64(&mut c, 16, 0x4000); // stripe_len
    w64(&mut c, 24, 0x19); // DATA|RAID10
    w16(&mut c, 44, 2); // num_stripes
    w16(&mut c, 46, 2); // sub_stripes
    w64(&mut c, 48, 1); // devid
    w64(&mut c, 56, 0x1000); // stripe0 offset
    w64(&mut c, 80, 2);
    w64(&mut c, 88, 0x2000); // stripe1 offset
    let ch = Chunk::parse(&c, 0).unwrap();
    assert_eq!(ch.stripes.len(), 2);
    assert_eq!(ch.stripes[1].offset, 0x2000);
    assert_eq!(ch.total_size(), 48 + 64);
}

// ---- chunk map --------------------------------------------------------------

#[test]
fn translate_range_striped_and_holes() {
    let mut m = ChunkMap::default();
    m.add(crate::chunk::ChunkEntry {
        logical: 0x100000,
        length: 0x40000,
        ty: block_group::DATA | block_group::RAID0,
        stripe_len: 0x10000,
        sub_stripes: 0,
        stripe_offsets: vec![0x900000, 0xA00000],
        parity: false,
    });
    // A 3-band read splits at band boundaries.
    let pieces = m.translate_range(0x100000, 0x28000);
    assert_eq!(
        pieces,
        vec![(0x900000, 0x10000), (0xA00000, 0x10000), (0x910000, 0x8000)]
    );
    // Unmapped region inside a mapped range → pieces only for coverage.
    m.add_chunk(0x300000, 0x10000, 0xB00000);
    let pieces = m.translate_range(0x2FF000, 0x3000);
    assert_eq!(pieces, vec![(0xB00000, 0x2000)]);
    // Entirely unmapped → empty.
    assert!(m.translate_range(0x900000, 100).is_empty());
}

#[test]
fn sys_chunk_array_dev_item_and_stripe() {
    // KEY+DEV_ITEM then KEY+CHUNK_ITEM — dev item must be skipped by size.
    let mut a = Vec::new();
    a.extend_from_slice(&256u64.to_le_bytes());
    a.push(ty::DEV_ITEM);
    a.extend_from_slice(&1u64.to_le_bytes());
    a.extend_from_slice(&[0u8; DEV_ITEM_SIZE]);
    a.extend_from_slice(&256u64.to_le_bytes());
    a.push(ty::CHUNK_ITEM);
    a.extend_from_slice(&0x4000u64.to_le_bytes());
    let mut c = vec![0u8; 48 + 32];
    w64(&mut c, 0, 0x80000);
    w64(&mut c, 16, 0x10000);
    w16(&mut c, 44, 1);
    w64(&mut c, 56, 0x1234);
    a.extend_from_slice(&c);
    let m = parse_sys_chunk_array(&a);
    assert_eq!(m.chunks.len(), 1);
    assert_eq!(m.chunks[0].logical, 0x4000);
    assert_eq!(m.logical_to_physical(0x4000), Some(0x1234));
    // Unknown item type → stop.
    let mut a2 = a[..17].to_vec();
    a2[8] = 99;
    let m2 = parse_sys_chunk_array(&a2);
    assert!(m2.chunks.is_empty());
}

#[test]
fn read_chunk_tree_and_dev_items() {
    use crate::chunk::{dev_items, read_chunk_tree};
    // Chunk-tree leaf at 0x8000 with a CHUNK_ITEM + DEV_ITEM; internal
    // node at 0x9000 pointing at it (level-1 traversal) plus a bogus ptr.
    let mut c = vec![0u8; 48 + 32];
    w64(&mut c, 0, 0x10000);
    w16(&mut c, 44, 1);
    w64(&mut c, 56, 0x4000);
    let mut di = vec![0u8; DEV_ITEM_SIZE];
    w64(&mut di, 0, 1);
    w64(&mut di, 8, 0x100_0000);
    let mut img = leaf_src(
        0x8000,
        3,
        7,
        &[
            (1, ty::DEV_ITEM, 1, di),
            (256, ty::CHUNK_ITEM, 0x80000, c),
        ],
    );
    internal_src(
        &mut img,
        0x9000,
        3,
        7,
        1,
        &[(256, 0, 0, 0x8000), (300, 0, 0, 0xFF000000)],
        7,
    );
    let mut map = ident_map();
    let _errs = read_chunk_tree(&img, 0x9000, &mut map, 4096);
    // Bogus child maps (identity) but is garbage → header parse may fail or
    // yields zero items; either way traversal completes.
    // The chunk item registered logical 0x80000 → stripe offset 0x4000.
    assert_eq!(map.logical_to_physical(0x80000), Some(0x4000));
    let devs = dev_items(&img, 0x9000, &map, 4096);
    assert_eq!(devs.len(), 1);
    assert_eq!(devs[0].total_bytes, 0x100_0000);
    // Missing chunk coverage → error recorded.
    let mut empty = ChunkMap::default();
    let errs = read_chunk_tree(&img, 0x9000, &mut empty, 4096);
    assert_eq!(errs.len(), 1);
}

// ---- btree error paths ------------------------------------------------------

#[test]
fn treewalk_errors_and_gen_mismatch() {
    use crate::btree::TreeWalk;
    let map = ident_map();
    // Leaf at 0x4000 with corrupt item descriptor (offset past end).
    let mut img = leaf_src(0x4000, 5, 7, &[(256, 1, 0, vec![0u8; 160])]);
    // Corrupt the item's data offset → body out of bounds error.
    w32(&mut img, 0x4000 + 101 + 17, 0xFFFF00);
    let mut tw = TreeWalk::new(&img, &map, 4096, 1);
    let mut items = 0;
    tw.for_each_item(0x4000, &mut |_| items += 1);
    assert_eq!(items, 0);
    assert!(tw.errors.iter().any(|e| matches!(e, sutram_fs::FsError::Corrupt { .. })));
    // Unmapped root → error.
    let empty = ChunkMap::default();
    let mut tw = TreeWalk::new(&img, &empty, 4096, 1);
    tw.for_each_item(0x4000, &mut |_| {});
    assert_eq!(tw.errors.len(), 1);
    // Internal node with bad keyptr (truncated mid-ptr) + generation
    // mismatch on the child.
    let mut img2 = leaf_src(0x4000, 5, 9, &[(256, 1, 0, vec![0u8; 160])]);
    internal_src(&mut img2, 0x5000, 5, 9, 1, &[(256, 0, 0, 0x4000)], 7); // ptr gen 7, leaf gen 9
    let mut tw = TreeWalk::new(&img2, &map, 4096, 1);
    let mut mismatched = 0;
    tw.for_each_item(0x5000, &mut |it| {
        if it.gen_mismatch {
            mismatched += 1;
        }
    });
    assert_eq!(mismatched, 1);
    assert!(!tw.errors.is_empty()); // generation mismatch recorded
}

#[test]
fn treewalk_csum_mismatch_flagged() {
    use crate::btree::TreeWalk;
    let map = ident_map();
    // CRC32C csum_type + wrong checksum → csum_ok=false flagged on items.
    let mut img = leaf_src(0x4000, 5, 7, &[(256, 1, 0, vec![0u8; 160])]);
    img[0x4000] = 0xDE;
    img[0x4001] = 0xAD; // bogus stored csum
    let mut tw = TreeWalk::new(&img, &map, 4096, 0);
    let mut bad = 0;
    tw.for_each_item(0x4000, &mut |it| {
        if it.csum_ok == Some(false) {
            bad += 1;
        }
    });
    assert_eq!(bad, 1);
    assert!(!tw.errors.is_empty());
}

// ---- fs tree items ----------------------------------------------------------

#[test]
fn index_fs_tree_extref_xattr_orphan() {
    use crate::index::index_fs_tree;
    let mut extref = Vec::new();
    // btrfs_inode_extref: parent_objectid@0, index@8, name_len@16, name@18
    extref.extend_from_slice(&256u64.to_le_bytes()); // parent
    extref.extend_from_slice(&0u64.to_le_bytes()); // index
    extref.extend_from_slice(&8u16.to_le_bytes()); // name_len
    extref.extend_from_slice(b"linkname");
    let mut xattr = Vec::new();
    // btrfs_dir_item: location(17) + transid(8) + data_len(2) + name_len(2) + type(1)
    xattr.extend_from_slice(&[0u8; 30]);
    w64(&mut xattr, 17, 1);
    w16(&mut xattr, 25, 3); // data_len
    w16(&mut xattr, 27, 9); // name_len
    xattr[29] = 8;
    xattr.extend_from_slice(b"user.meta");
    xattr.extend_from_slice(b"abc");
    let mut inode = vec![0u8; 160];
    w32(&mut inode, 52, 0o100644);
    let mut inline = vec![0u8; 21];
    w64(&mut inline, 0, 7);
    w64(&mut inline, 8, 5);
    inline[20] = 0; // inline
    inline.extend_from_slice(b"DATA!");
    let mut hole = vec![0u8; 53];
    w64(&mut hole, 8, 4096); // ram_bytes
    hole[20] = 1;
    w64(&mut hole, 45, 4096); // num_bytes; disk_bytenr=0 → hole
    let img = leaf_src(
        0x4000,
        5,
        7,
        &[
            (256, ty::INODE_ITEM, 0, inode),
            (257, ty::INODE_EXTREF, 256, extref),
            (257, ty::XATTR_ITEM, 99, xattr),
            (257, ty::EXTENT_DATA, 0, inline),
            (257, ty::EXTENT_DATA, 5, hole),
            (objid::ORPHAN, ty::ORPHAN_ITEM, 257, Vec::new()),
        ],
    );
    let map = ident_map();
    let t = index_fs_tree(&img, &map, 4096, 1, 5, String::new(), 0x4000, 7, true, false, false);
    let rec = t.inodes.get(&257).unwrap();
    assert_eq!(rec.names[0].name, "linkname");
    assert_eq!(rec.names[0].parent, 256);
    assert_eq!(rec.xattrs.len(), 1);
    assert_eq!(rec.xattrs[0].name, "user.meta");
    assert_eq!(rec.extents.len(), 2);
    assert!(rec.extents[1].is_hole());
    assert!(rec.orphan);
    assert!(t.orphans.contains(&257));
}

#[test]
fn build_path_fallbacks() {
    use crate::index::{DirChild, InodeRec, NameRef, TreeIndex};
    let mut t = TreeIndex {
        objectid: 5,
        root_logical: 0x4000,
        generation: 7,
        mount_name: String::new(),
        is_live: true,
        readonly: false,
        is_snapshot: false,
        inodes: Default::default(),
        dir_children: Default::default(),
        orphans: Default::default(),
        errors: Vec::new(),
    };
    // ino 300: no inode record; dir item in parent 256 gives the name.
    t.dir_children.insert(
        256,
        vec![DirChild { ino: 300, name: "found.txt".into(), ty: 1, phys: 0 }],
    );
    // parent 256 names itself via INODE_REF-less root → path stops at 256.
    t.inodes.insert(256, InodeRec {
        names: vec![NameRef { parent: 256, name: "root".into(), phys: 0 }],
        ..Default::default()
    });
    let (path, name) = t.build_path(300);
    assert_eq!(name, "found.txt");
    assert!(path.contains("found.txt"));
    // Cycle guard: 400's parent is 400.
    t.inodes.insert(400, InodeRec {
        names: vec![NameRef { parent: 400, name: "self".into(), phys: 0 }],
        ..Default::default()
    });
    let (p, _) = t.build_path(400);
    assert!(p.contains("self"));
    // Completely unknown inode → ino_ placeholder.
    let (p, n) = t.build_path(999);
    assert!(n.starts_with("ino_"));
    assert!(p.contains("ino_"));
    // Root dir itself.
    let (p, _) = t.build_path(256);
    assert!(p.starts_with('/'));
}

// ---- root tree / free-space tree --------------------------------------------

#[test]
fn index_root_tree_refs() {
    use crate::index::index_root_tree;
    let mut ri = vec![0u8; 439];
    w64(&mut ri, 160, 7); // generation
    w64(&mut ri, 176, 0x8000); // bytenr
    ri[238] = 0; // level
    let mut backref = Vec::new();
    backref.extend_from_slice(&256u64.to_le_bytes()); // dirid
    backref.extend_from_slice(&3u64.to_le_bytes()); // sequence
    backref.extend_from_slice(&5u16.to_le_bytes());
    backref.extend_from_slice(b"vol_a");
    let img = leaf_src(
        0x4000,
        1,
        7,
        &[
            // ROOT_BACKREF sorts before ROOT_ITEM by key (objid 300 < ... )
            (300, ty::ROOT_BACKREF, 1, backref),
            (300, ty::ROOT_ITEM, 0, ri),
        ],
    );
    let map = ident_map();
    let idx = index_root_tree(&img, &map, 4096, 1, 0x4000);
    let e = idx.roots.get(&300).unwrap();
    assert_eq!(e.bytenr, 0x8000);
    assert_eq!(e.name.as_deref(), Some("vol_a"));
    assert_eq!(e.parent, Some(1));
}

#[test]
fn index_free_space_tree_extents_and_bitmap() {
    use crate::index::index_free_space_tree;
    let mut extent = vec![0u8; 16];
    w64(&mut extent, 0, 0x500000);
    w64(&mut extent, 8, 0x3000);
    let mut bitmap = vec![0u8; 16];
    w64(&mut bitmap, 0, 0x600000);
    w64(&mut bitmap, 8, 0x8000);
    bitmap.extend_from_slice(&[0b0000_0101u8]); // bits 0 and 2
    let img = leaf_src(
        0x4000,
        10,
        7,
        &[
            (0x400000, ty::FREE_SPACE_EXTENT, 0, extent),
            (0x500000, ty::FREE_SPACE_BITMAP, 0, bitmap),
        ],
    );
    let map = ident_map();
    let (free, _) = index_free_space_tree(&img, &map, 4096, 1, 0x4000, 4096);
    assert!(free.contains(&(0x500000, 0x3000)));
    assert!(free.contains(&(0x600000, 4096)));
    assert!(free.contains(&(0x600000 + 2 * 4096, 4096)));
}

#[test]
fn extent_tree_separate_refs_and_metadata() {
    use crate::index::{index_extent_tree, rec_references, rec_references_other, ExtentRef};
    let mut ei = vec![0u8; 24];
    w64(&mut ei, 8, 7);
    w64(&mut ei, 16, 2); // TREE_BLOCK flag
    let mut edr = vec![0u8; 28];
    w64(&mut edr, 0, 5); // root
    w64(&mut edr, 8, 42); // inode
    w32(&mut edr, 24, 1);
    let mut edr2 = vec![0u8; 28];
    w64(&mut edr2, 0, 5); // root
    w64(&mut edr2, 8, 43); // a *different* inode shares the extent
    w32(&mut edr2, 24, 1);
    let mut sdr = vec![0u8; 8];
    w64(&mut sdr, 0, 0x9000);
    let mut bg = vec![0u8; 24];
    w64(&mut bg, 0, 0x10000); // used
    w64(&mut bg, 16, 1); // DATA flag
    let img = leaf_src(
        0x4000,
        2,
        7,
        &[
            (0x500000, ty::EXTENT_ITEM, 4096, ei),
            (0x500000, ty::EXTENT_DATA_REF, 0x99, edr),
            (0x500000, ty::EXTENT_DATA_REF, 0x77, edr2),
            (0x500000, ty::SHARED_DATA_REF, 0x88, sdr),
            (0x500000, ty::TREE_BLOCK_REF, 5, Vec::new()),
            (0x500000, ty::SHARED_BLOCK_REF, 0x9000, Vec::new()),
            (0x700000, ty::METADATA_ITEM, 0, Vec::new()),
            (0x800000, ty::BLOCK_GROUP_ITEM, 0x100000, bg),
            // Ref items with NO EXTENT_ITEM → or_insert_with placeholder.
            (0x900000, ty::EXTENT_DATA_REF, 0x55, {
                let mut d = vec![0u8; 28];
                w64(&mut d, 0, 5);
                w64(&mut d, 8, 77);
                w32(&mut d, 24, 1);
                d
            }),
            (0x900000, ty::SHARED_DATA_REF, 0x44, {
                let mut d = vec![0u8; 8];
                w64(&mut d, 0, 0x9000);
                d
            }),
            (0x900000, ty::TREE_BLOCK_REF, 2, Vec::new()),
            (0x900000, ty::SHARED_BLOCK_REF, 0x6000, Vec::new()),
        ],
    );
    let map = ident_map();
    let idx = index_extent_tree(&img, &map, 4096, 1, 0x4000);
    let rec = idx.recs.get(&0x500000).unwrap();
    assert!(rec.is_metadata); // TREE_BLOCK flag from item
    assert!(rec_references(rec, 5, 42));
    assert!(rec_references(rec, 5, 43));
    assert!(!rec_references(rec, 5, 44));
    assert!(rec_references_other(rec, 5, 42));
    assert!(rec_references_other(rec, 5, 43));
    // every ref is "other" than (5,44) → true
    assert!(rec_references_other(rec, 5, 44));
    assert!(rec.refs.iter().any(|r| matches!(r, ExtentRef::SharedData { parent } if *parent == 0x9000)));
    assert!(rec.refs.iter().any(|r| matches!(r, ExtentRef::TreeBlock { root: 5 })));
    assert!(rec.refs.iter().any(|r| matches!(r, ExtentRef::SharedBlock { parent: 0x9000 })));
    // METADATA_ITEM → len = nodesize, is_metadata.
    let m = idx.recs.get(&0x700000).unwrap();
    assert!(m.is_metadata && m.len == 4096);
    // BLOCK_GROUP_ITEM recorded.
    assert_eq!(idx.block_groups.len(), 1);
    assert_eq!(idx.block_groups[0].2, 0x10000);
    // Ref-only record (placeholder merged via or_insert_with).
    let ph = idx.recs.get(&0x900000).unwrap();
    assert!(ph.refs.iter().any(|r| matches!(r, ExtentRef::SharedData { parent: 0x9000 })));
    assert!(ph.refs.iter().any(|r| matches!(r, ExtentRef::SharedBlock { parent: 0x6000 })));
    // overlapping() coverage.
    assert_eq!(idx.overlapping(0x500000, 1).len(), 1);
    assert!(idx.overlapping(0x400000, 1).is_empty());
    assert!(idx.overlapping(0x4FE000, 0x1000).is_empty()); // gap
    assert_eq!(idx.overlapping(0x500000, 0x400000).len(), 2); // 0x500000 + 0x700000
}

// ---- ExtentReader -----------------------------------------------------------

#[test]
fn extent_reader_modes() {
    use crate::index::Extent;
    use crate::read::ExtentReader;
    use std::io::Read;
    use std::sync::Arc;
    let mut img = vec![0u8; 0x8000];
    img[0x4000..0x4008].copy_from_slice(b"BLOCKONE");
    img[0x5000..0x5004].copy_from_slice(b"TWO!");
    let src: Arc<dyn sutram_io::ByteSource> = Arc::new(img);
    let map = ident_map();
    let ext = |file_off, num, logical, disk_len, ext_off| Extent {
        file_offset: file_off,
        num_bytes: num,
        ty: extent_ty::REGULAR,
        compression: compression::NONE,
        encryption: 0,
        generation: 7,
        logical,
        disk_len,
        extent_offset: ext_off,
        ram_bytes: disk_len,
        inline_data: None,
        phys_ranges: if logical == 0 { vec![] } else { vec![(logical, disk_len)] },
        item_phys: 0,
    };
    // Live mode: extent at file_off 8 → 8 zero bytes first (gap), then data.
    let segs = vec![
        (ext(0, 4, 0, 4096, 0), vec![]),      // hole: 4 zeros
        (ext(8, 4, 0x4000, 4096, 0), vec![(0x4000, 4096)]), // gap 4..8 → zeros
        (ext(12, 4, 0x5000, 4096, 0), vec![(0x5000, 4096)]),
    ];
    let mut r = ExtentReader::new(src.clone(), &map, segs, 16);
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 16);
    assert_eq!(&buf[..8], &[0u8; 8]);
    assert_eq!(&buf[8..12], b"BLOC"); // capped at num_bytes=4? num=4 → "BLOC"
    assert_eq!(&buf[12..16], b"TWO!");
    // Deleted mode (cap=u64::MAX): segments concatenate, no zero gaps.
    let segs = vec![
        (ext(0, 4, 0x4000, 4096, 0), vec![(0x4000, 4096)]),
        (ext(12, 4, 0x5000, 4096, 0), vec![(0x5000, 4096)]),
    ];
    let mut r = ExtentReader::new(src.clone(), &map, segs, u64::MAX);
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(&buf, b"BLOCTWO!");
    // Short physical range → zero-fill tail.
    let segs = vec![(ext(0, 8, 0x4000, 8, 0), vec![(0x4000, 4)])];
    let mut r = ExtentReader::new(src.clone(), &map, segs, 8);
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(&buf[..4], b"BLOC");
    assert_eq!(&buf[4..8], &[0u8; 4]);
}

#[test]
fn extent_reader_compressed() {
    use crate::index::Extent;
    use crate::read::ExtentReader;
    use std::io::{Read, Write};
    use std::sync::Arc;
    let plain = b"compressed-btrfs-payload-data!!";
    let comp = {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(plain).unwrap();
        e.finish().unwrap()
    };
    let mut img = vec![0u8; 0x8000];
    img[0x4000..0x4000 + comp.len()].copy_from_slice(&comp);
    let src: Arc<dyn sutram_io::ByteSource> = Arc::new(img);
    let map = ident_map();
    // Blob: compressed extent, skip 11 bytes of output.
    let ex = Extent {
        file_offset: 0,
        num_bytes: 5,
        ty: extent_ty::REGULAR,
        compression: compression::ZLIB,
        encryption: 0,
        generation: 7,
        logical: 0x4000,
        disk_len: comp.len() as u64,
        extent_offset: 11,
        ram_bytes: plain.len() as u64,
        inline_data: None,
        phys_ranges: vec![(0x4000, comp.len() as u64)],
        item_phys: 0,
    };
    let mut r = ExtentReader::new(src.clone(), &map, vec![(ex, vec![(0x4000, comp.len() as u64)])], 5);
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, &plain[11..16]);
    // Inline uncompressed.
    let ex = Extent {
        file_offset: 0,
        num_bytes: 4,
        ty: extent_ty::INLINE,
        compression: compression::NONE,
        encryption: 0,
        generation: 7,
        logical: 0,
        disk_len: 0,
        extent_offset: 0,
        ram_bytes: 4,
        inline_data: Some(b"INLN".to_vec()),
        phys_ranges: vec![],
        item_phys: 0,
    };
    let mut r = ExtentReader::new(src.clone(), &map, vec![(ex, vec![])], 4);
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"INLN");
    // Compressed inline (zlib in place).
    let ex = Extent {
        file_offset: 0,
        num_bytes: 31,
        ty: extent_ty::INLINE,
        compression: compression::ZLIB,
        encryption: 0,
        generation: 7,
        logical: 0,
        disk_len: 0,
        extent_offset: 0,
        ram_bytes: 29,
        inline_data: Some(comp.clone()),
        phys_ranges: vec![],
        item_phys: 0,
    };
    let mut r = ExtentReader::new(src.clone(), &map, vec![(ex, vec![])], 31);
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, plain);
}

// ---- fs.rs helpers ----------------------------------------------------------

#[test]
fn fs_helpers() {
    use crate::fs::*;
    use crate::index::{Extent, InodeRec};
    // clone_err preserves variants.
    let e = clone_err(&sutram_fs::FsError::NotFound { path: "/x".into() });
    assert!(matches!(e, sutram_fs::FsError::NotFound { .. }));
    let e = clone_err(&sutram_fs::FsError::Io(std::io::Error::other("disk")));
    assert!(matches!(e, sutram_fs::FsError::Corrupt { .. }));
    // unique_inode packs subvol<<48 | ino.
    assert_eq!(unique_inode(0x1234, 0x5678), 0x1234_0000_0000_5678);
    // same_version: transid/size/extents compare.
    let mk = |transid, size| {
        let mut item = vec![0u8; 160];
        w64(&mut item, 8, transid);
        w64(&mut item, 16, size);
        InodeRec {
            item: crate::ondisk::InodeItem::parse(&item, 0),
            ..Default::default()
        }
    };
    assert!(same_version(&mk(7, 100), Some(&mk(7, 100))));
    assert!(!same_version(&mk(7, 100), Some(&mk(9, 100))));
    assert!(!same_version(&mk(7, 100), Some(&mk(7, 200))));
    assert!(!same_version(&mk(7, 100), None));
    // extents differing → not same.
    let mut a = mk(7, 100);
    a.extents.push(Extent {
        file_offset: 0, num_bytes: 10, ty: 1, compression: 0, encryption: 0,
        generation: 7, logical: 0x5000, disk_len: 4096, extent_offset: 0,
        ram_bytes: 4096, inline_data: None, phys_ranges: vec![], item_phys: 0,
    });
    assert!(!same_version(&a, Some(&mk(7, 100))));
    // inode_timestamps: None → default; Some → 4 fields.
    let t = inode_timestamps(None);
    assert!(t.modified.is_none());
    let mut raw = vec![0u8; 160];
    w64(&mut raw, 112, 1_700_000_000);
    let i = crate::ondisk::InodeItem::parse(&raw, 0).unwrap();
    let t = inode_timestamps(Some(&i));
    assert_eq!(t.accessed.unwrap().value, Some(1_700_000_000_000_000_000));
    assert!(t.created.unwrap().value.is_none()); // otime zeroed
    // intersect_ranges.
    let x = intersect_ranges(
        vec![(0, 100), (200, 100), (400, 50)],
        vec![(50, 100), (250, 200)],
    );
    assert_eq!(x, vec![(50, 50), (250, 50), (400, 50)]);
    assert!(intersect_ranges(vec![(0, 10)], vec![(20, 10)]).is_empty());
    // parse_id_file.
    let v = parse_id_file(b"root:x:0:0:::/bin/sh\n# comment\nadmin:x:1000:::\nno-id:x:abc\n");
    assert_eq!(v, vec![(0, "root".to_string()), (1000, "admin".to_string())]);
}

#[test]
fn superblock_rejects_and_csum_variants() {
    use crate::superblock::Superblock;
    // Short buffer → truncated error.
    assert!(Superblock::parse(&[0u8; 128], 0).is_err());
    // Bad magic → corrupt.
    let mut b = vec![0u8; 4096];
    assert!(Superblock::parse(&b, 0).is_err());
    // Valid magic + non-CRC32C csum → csum_ok None; invalid backup slots
    // skipped.
    b[0x40..0x48].copy_from_slice(BTRFS_MAGIC);
    w16(&mut b, 0xC4, 1); // xxhash — can't verify
    let sb = Superblock::parse(&b, 0x10000).unwrap();
    assert_eq!(sb.csum_ok, None);
    assert!(sb.backup_roots.is_empty());
    // Implausible geometry → read_superblock rejects.
    let sb2 = Superblock::parse(&b, 0x10000).unwrap();
    assert!(!sb2.plausible());
    // Plausible copy: nodesize/sectorsize 4K, roots set.
    w32(&mut b, 0x90, 4096);
    w32(&mut b, 0x94, 4096);
    w64(&mut b, 0x50, 0x4000);
    w64(&mut b, 0x58, 0x5000);
    w64(&mut b, 0x70, 0x100_0000);
    let sb3 = Superblock::parse(&b, 0x10000).unwrap();
    assert!(sb3.plausible());
}

#[test]
fn treewalk_visited_skip() {
    use crate::btree::TreeWalk;
    let map = ident_map();
    // Two keyptrs to the SAME child → visited-set skips the second.
    let mut img = leaf_src(0x4000, 5, 7, &[(256, 1, 0, vec![0u8; 160])]);
    internal_src(
        &mut img, 0x5000, 5, 7, 1,
        &[(256, 0, 0, 0x4000), (300, 0, 0, 0x4000)],
        7,
    );
    let mut tw = TreeWalk::new(&img, &map, 4096, 1);
    let mut n = 0;
    tw.for_each_item(0x5000, &mut |_| n += 1);
    assert_eq!(n, 1); // leaf visited once despite two pointers
}

#[test]
fn chunk_tree_error_paths() {
    use crate::chunk::{dev_items, read_chunk_tree};
    // nodesize smaller than header → "short chunk-tree node".
    let img = vec![0u8; 0x8000];
    let mut map = ident_map();
    let errs = read_chunk_tree(&img, 0x4000, &mut map, 64);
    assert_eq!(errs.len(), 1);
    // Internal node whose keyptrs are truncated (nritems beyond buffer).
    let mut img = vec![0u8; 0xA000];
    // fake level-1 header claiming 200 items → keyptr reads fail fast.
    w64(&mut img, 0x4000 + 0x50, 7);
    w32(&mut img, 0x4000 + 0x60, 200);
    img[0x4000 + 0x64] = 1;
    let mut map = ident_map();
    let errs = read_chunk_tree(&img, 0x4000, &mut map, 4096);
    // KeyPtr::parse fails at first pos beyond 4096 → break with items read.
    assert!(errs.len() <= 1);
    // Leaf item descriptor truncated mid-table.
    img[0x4000 + 0x64] = 0;
    w32(&mut img, 0x4000 + 0x60, 200);
    let errs = read_chunk_tree(&img, 0x4000, &mut map, 4096);
    assert!(errs.len() <= 1);
    // dev_items on unmapped root → empty.
    let empty = ChunkMap::default();
    assert!(dev_items(&img, 0x4000, &empty, 4096).is_empty());
}

#[test]
fn sys_chunk_array_malformed() {
    // Too short for key+chunk → empty map.
    assert!(parse_sys_chunk_array(&[0u8; 30]).chunks.is_empty());
    // DEV_ITEM entry past the end → break.
    let mut a = Vec::new();
    a.extend_from_slice(&256u64.to_le_bytes());
    a.push(ty::DEV_ITEM);
    a.extend_from_slice(&1u64.to_le_bytes());
    a.extend_from_slice(&[0u8; 10]); // truncated dev_item
    assert!(parse_sys_chunk_array(&a).chunks.is_empty());
    // CHUNK_ITEM with absurd stripe count → Chunk::parse fails → break.
    let mut a = Vec::new();
    a.extend_from_slice(&256u64.to_le_bytes());
    a.push(ty::CHUNK_ITEM);
    a.extend_from_slice(&0u64.to_le_bytes());
    let mut c = vec![0u8; 48];
    w16(&mut c, 44, 200); // 200 stripes won't fit
    a.extend_from_slice(&c);
    assert!(parse_sys_chunk_array(&a).chunks.is_empty());
}

#[test]
fn fs_tree_malformed_items() {
    use crate::index::index_fs_tree;
    // INODE_REF with name_len overrunning the body → truncated mid-record.
    let mut badref = Vec::new();
    badref.extend_from_slice(&0u64.to_le_bytes());
    badref.extend_from_slice(&999u16.to_le_bytes()); // name_len huge
    // DIR_ITEM with name_len overrunning → parse fails.
    let mut baddir = vec![0u8; 30];
    w16(&mut baddir, 27, 999);
    // ORPHAN_ITEM under a non-orphan objectid → ignored.
    let mut inode = vec![0u8; 160];
    w32(&mut inode, 52, 0o100644);
    let img = leaf_src(
        0x4000,
        5,
        7,
        &[
            (256, ty::INODE_ITEM, 0, inode),
            (256, ty::INODE_REF, 255, badref),
            (256, ty::DIR_ITEM, 1, baddir),
            (999, ty::ORPHAN_ITEM, 256, Vec::new()),
        ],
    );
    let map = ident_map();
    let t = index_fs_tree(&img, &map, 4096, 1, 5, String::new(), 0x4000, 7, true, false, false);
    assert!(t.inodes.get(&256).unwrap().names.is_empty());
    assert!(t.orphans.is_empty());
    assert!(t.dir_children.values().all(|c| c.is_empty()));
    // Root tree with malformed ROOT_ITEM / ROOT_REF → skipped.
    use crate::index::index_root_tree;
    let img = leaf_src(
        0x4000,
        1,
        7,
        &[
            (300, ty::ROOT_ITEM, 0, vec![0u8; 100]), // < 239 bytes
            (1, ty::ROOT_REF, 300, vec![0u8; 4]),   // < 18 bytes
        ],
    );
    let idx = index_root_tree(&img, &map, 4096, 1, 0x4000);
    assert!(idx.roots.is_empty());
}

#[test]
fn reader_error_and_pad_paths() {
    use crate::index::Extent;
    use crate::read::ExtentReader;
    use std::io::Read;
    use std::sync::Arc;
    // Source too small for the declared range → read error surfaces.
    let img = vec![0u8; 0x1000];
    let src: Arc<dyn sutram_io::ByteSource> = Arc::new(img);
    let map = ident_map();
    let ex = Extent {
        file_offset: 0, num_bytes: 8, ty: extent_ty::REGULAR,
        compression: compression::NONE, encryption: 0, generation: 7,
        logical: 0x8000, disk_len: 8, extent_offset: 0, ram_bytes: 8,
        inline_data: None, phys_ranges: vec![(0x8000, 8)], item_phys: 0,
    };
    let mut r = ExtentReader::new(src.clone(), &map, vec![(ex, vec![(0x8000, 8)])], 8);
    let mut buf = vec![0u8; 8];
    // ByteSource clamps at EOF → Ok(0) → early EOF (not an error).
    assert_eq!(r.read(&mut buf).unwrap(), 0);
    // Blob extent whose physical ranges run past the source → io error.
    let ex = Extent {
        file_offset: 0, num_bytes: 8, ty: extent_ty::REGULAR,
        compression: compression::ZLIB, encryption: 0, generation: 7,
        logical: 0x8000, disk_len: 8, extent_offset: 0, ram_bytes: 8,
        inline_data: None, phys_ranges: vec![(0x8000, 8)], item_phys: 0,
    };
    let mut r = ExtentReader::new(src.clone(), &map, vec![(ex, vec![(0x8000, 8)])], 8);
    assert!(r.read(&mut buf).is_err());
    // Decompressed shorter than declared → zero-pad the remainder.
    use std::io::Write;
    let comp = {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(b"AB").unwrap();
        e.finish().unwrap()
    };
    let mut img = vec![0u8; 0x8000];
    img[0x4000..0x4000 + comp.len()].copy_from_slice(&comp);
    let src: Arc<dyn sutram_io::ByteSource> = Arc::new(img);
    let ex = Extent {
        file_offset: 0, num_bytes: 8, ty: extent_ty::REGULAR,
        compression: compression::ZLIB, encryption: 0, generation: 7,
        logical: 0x4000, disk_len: comp.len() as u64, extent_offset: 0,
        ram_bytes: 8, inline_data: None,
        phys_ranges: vec![(0x4000, comp.len() as u64)], item_phys: 0,
    };
    let mut r = ExtentReader::new(src, &map, vec![(ex, vec![(0x4000, comp.len() as u64)])], 8);
    let mut buf = Vec::new();
    r.read_to_end(&mut buf).unwrap();
    assert_eq!(&buf[..2], b"AB");
    assert_eq!(&buf[2..8], &[0u8; 6]);
}

// ---------------------------------------------------------------------------
// Coverage expansion round 2: descriptor guards, ref merges, io-error
// latching, detection ladder, chunk-map edges, path cycles.
// ---------------------------------------------------------------------------

/// A ByteSource whose reads always fail — exercises the `FsError::Io`
/// propagation paths (tree walk, chunk-tree scan, extent reader).
struct FailSrc;

impl sutram_io::ByteSource for FailSrc {
    fn len(&self) -> u64 {
        0x100_0000
    }
    fn read_at(&self, _off: u64, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("simulated disk failure"))
    }
}

/// A ByteSource that works below `fail_at` and errors above — drives the
/// mid-stream latch (partial Ok then Err on the next read).
struct GapSrc {
    fail_at: u64,
}

impl sutram_io::ByteSource for GapSrc {
    fn len(&self) -> u64 {
        0x100_0000
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if off >= self.fail_at {
            return Err(std::io::Error::other("bad sector"));
        }
        buf.fill(0xAA);
        Ok(buf.len())
    }
}

#[test]
fn treewalk_truncated_descriptors() {
    use crate::btree::TreeWalk;
    use sutram_fs::FsError;
    let map = ident_map();
    // Leaf whose block read ends mid-item-table: nritems says 10, the
    // source holds only ~60 bytes of descriptors → "bad item descriptor".
    let mut img = vec![0u8; 0x4000 + 160];
    w64(&mut img, 0x4000 + 0x50, 7);
    w32(&mut img, 0x4000 + 0x60, 10);
    let mut tw = TreeWalk::new(&img, &map, 4096, 1);
    tw.for_each_item(0x4000, &mut |_| {});
    assert!(tw
        .errors
        .iter()
        .any(|e| matches!(e, FsError::Corrupt { msg, .. } if msg.contains("item descriptor"))));
    // Internal node — same truncation hits the keyptr loop instead.
    let mut img = vec![0u8; 0x4000 + 140];
    w64(&mut img, 0x4000 + 0x50, 7);
    w32(&mut img, 0x4000 + 0x60, 8);
    img[0x4000 + 0x64] = 1;
    let mut tw = TreeWalk::new(&img, &map, 4096, 1);
    tw.for_each_item(0x4000, &mut |_| {});
    assert!(tw
        .errors
        .iter()
        .any(|e| matches!(e, FsError::Corrupt { msg, .. } if msg.contains("key pointer"))));
    // Block shorter than the 101-byte header → truncated error.
    let img = vec![0u8; 0x4000 + 40];
    let mut tw = TreeWalk::new(&img, &map, 4096, 1);
    tw.for_each_item(0x4000, &mut |_| {});
    assert_eq!(tw.errors.len(), 1);
}

#[test]
fn treewalk_and_chunk_tree_io_errors() {
    use crate::btree::TreeWalk;
    use crate::chunk::{dev_items, read_chunk_tree};
    use sutram_fs::FsError;
    let src = FailSrc;
    let map = ident_map();
    // Tree walk: read failure becomes a recorded error, walk continues.
    let mut tw = TreeWalk::new(&src, &map, 4096, 1);
    tw.for_each_item(0x4000, &mut |_| {});
    assert_eq!(tw.errors.len(), 1);
    // Chunk tree: read failure → FsError::Io.
    let mut m = ChunkMap::default();
    m.add_chunk(0, 0x100_0000, 0);
    let errs = read_chunk_tree(&src, 0x4000, &mut m, 4096);
    assert!(errs.iter().any(|e| matches!(e, FsError::Io(_))));
    // dev_items swallows the read error and yields nothing.
    assert!(dev_items(&src, 0x4000, &m, 4096).is_empty());
}

#[test]
fn chunk_map_edges() {
    use crate::chunk::{ChunkEntry, ChunkMap};
    let mut m = ChunkMap::default();
    // Zero-length chunk is refused by add().
    m.add(ChunkEntry {
        logical: 0,
        length: 0,
        ty: block_group::DATA,
        stripe_len: 0,
        sub_stripes: 0,
        stripe_offsets: vec![0],
        parity: false,
    });
    assert!(m.chunks.is_empty());
    // Identical logical+length registered twice keeps the first.
    m.add_chunk(0, 0x1000, 0);
    m.add_chunk(0, 0x1000, 0x9999);
    assert_eq!(m.chunks.len(), 1);
    assert_eq!(m.logical_to_physical(0), Some(0));
    // Parity chunk: untranslatable → hole.
    m.add(ChunkEntry {
        logical: 0x100000,
        length: 0x4000,
        ty: block_group::DATA | block_group::RAID5,
        stripe_len: 0x1000,
        sub_stripes: 0,
        stripe_offsets: vec![0x200000, 0x300000],
        parity: true,
    });
    assert_eq!(m.logical_to_physical(0x100000), None);
    // translate_range skips the parity hole and resumes at the next chunk.
    m.add_chunk(0x104000, 0x1000, 0x500000);
    assert_eq!(m.translate_range(0x100000, 0x5000), vec![(0x500000, 0x1000)]);
    // Chunk with no stripes at all → untranslatable.
    m.add(ChunkEntry {
        logical: 0x200000,
        length: 0x1000,
        ty: block_group::DATA,
        stripe_len: 0,
        sub_stripes: 0,
        stripe_offsets: vec![],
        parity: false,
    });
    assert_eq!(m.logical_to_physical(0x200000), None);
    // covered_ranges reports every registered chunk.
    assert_eq!(m.covered_ranges().len(), 4);
}

#[test]
fn index_extent_tree_inline_shared_owner_and_merge() {
    use crate::index::{index_extent_tree, ExtentRef};
    // EXTENT_ITEM body carrying inline SHARED_BLOCK_REF + EXTENT_OWNER_REF
    // then an unknown ref tag that must stop the scan.
    let mut body = vec![0u8; 24];
    w64(&mut body, 8, 7);
    w64(&mut body, 16, 1);
    body.push(ty::SHARED_BLOCK_REF);
    body.extend_from_slice(&0x9000u64.to_le_bytes());
    body.push(ty::EXTENT_OWNER_REF);
    body.extend_from_slice(&5u64.to_le_bytes());
    body.push(0xEE); // unknown inline ref → break
    body.extend_from_slice(&[0u8; 8]);
    let mut edr = vec![0u8; 28];
    w64(&mut edr, 0, 5);
    w64(&mut edr, 8, 42);
    w32(&mut edr, 24, 1);
    let img = leaf_src(
        0x4000,
        2,
        7,
        &[
            (0x500000, ty::EXTENT_ITEM, 4096, body),
            // Ref items for objectids with no EXTENT_ITEM → placeholder
            // records via or_insert_with.
            (0xA00000, ty::SHARED_DATA_REF, 0, {
                let mut d = vec![0u8; 8];
                w64(&mut d, 0, 0x9000);
                d
            }),
            (0xB00000, ty::TREE_BLOCK_REF, 5, Vec::new()),
            (0xC00000, ty::SHARED_BLOCK_REF, 0x9000, Vec::new()),
            // A ref arriving *before* its EXTENT_ITEM → the item must
            // merge into the placeholder via and_modify.
            (0xD00000, ty::EXTENT_DATA_REF, 0x11, edr),
            (0xD00000, ty::EXTENT_ITEM, 4096, {
                let mut e = vec![0u8; 24];
                w64(&mut e, 8, 7);
                w64(&mut e, 16, 1);
                e
            }),
        ],
    );
    let map = ident_map();
    let idx = index_extent_tree(&img, &map, 4096, 1, 0x4000);
    let rec = idx.recs.get(&0x500000).unwrap();
    assert!(rec.refs.iter().any(|r| matches!(r, ExtentRef::SharedBlock { parent: 0x9000 })));
    assert!(rec.refs.iter().any(|r| matches!(r, ExtentRef::Owner { root: 5 })));
    assert_eq!(rec.refs.len(), 2, "unknown inline ref must stop the scan");
    assert!(idx.recs[&0xA00000]
        .refs
        .iter()
        .any(|r| matches!(r, ExtentRef::SharedData { parent: 0x9000 })));
    assert!(idx.recs[&0xB00000]
        .refs
        .iter()
        .any(|r| matches!(r, ExtentRef::TreeBlock { root: 5 })));
    assert!(idx.recs[&0xC00000]
        .refs
        .iter()
        .any(|r| matches!(r, ExtentRef::SharedBlock { parent: 0x9000 })));
    let merged = &idx.recs[&0xD00000];
    assert_eq!(merged.len, 4096); // EXTENT_ITEM merged over the placeholder
    assert!(merged.refs.iter().any(|r| matches!(r, ExtentRef::Data { inode: 42, .. })));
    // root_logical == 0 → empty indexes, no walk attempted.
    assert!(index_extent_tree(&img, &map, 4096, 1, 0).recs.is_empty());
    use crate::index::{index_free_space_tree, index_root_tree};
    assert!(index_root_tree(&img, &map, 4096, 1, 0).roots.is_empty());
    assert!(index_free_space_tree(&img, &map, 4096, 1, 0, 4096).0.is_empty());
}

#[test]
fn build_path_two_node_cycle() {
    use crate::index::{InodeRec, NameRef, TreeIndex};
    let mut t = TreeIndex {
        objectid: 5,
        root_logical: 0x4000,
        generation: 7,
        mount_name: String::new(),
        is_live: true,
        readonly: false,
        is_snapshot: false,
        inodes: Default::default(),
        dir_children: Default::default(),
        orphans: Default::default(),
        errors: Vec::new(),
    };
    // a → b → a: the visited set must terminate the parent walk.
    t.inodes.insert(300, InodeRec {
        names: vec![NameRef { parent: 301, name: "aaa".into(), phys: 0 }],
        ..Default::default()
    });
    t.inodes.insert(301, InodeRec {
        names: vec![NameRef { parent: 300, name: "bbb".into(), phys: 0 }],
        ..Default::default()
    });
    let (path, _) = t.build_path(300);
    assert!(path.contains("aaa"), "{path}");
    // subvolume mount prefix is prepended to non-root paths.
    t.mount_name = "vol".into();
    let (path, _) = t.build_path(300);
    assert!(path.starts_with("/vol/"), "{path}");
    let (path, name) = t.build_path(256);
    assert_eq!(name, "vol");
    assert_eq!(path, "/vol");
}

#[test]
fn extent_reader_latched_error_and_empty_seg() {
    use crate::index::Extent;
    use crate::read::ExtentReader;
    use std::io::Read;
    use std::sync::Arc;
    let map = ident_map();
    let mk = |num: u64| Extent {
        file_offset: 0,
        num_bytes: num,
        ty: extent_ty::REGULAR,
        compression: compression::NONE,
        encryption: 0,
        generation: 7,
        logical: 0x4000,
        disk_len: num,
        extent_offset: 0,
        ram_bytes: num,
        inline_data: None,
        phys_ranges: vec![(0x4000, 8), (0x8000, 8)],
        item_phys: 0,
    };
    // Second range faults after partial production → Ok(8) then the
    // latched error surfaces on the next read.
    let src: Arc<dyn sutram_io::ByteSource> = Arc::new(GapSrc { fail_at: 0x8000 });
    let ex = mk(16);
    let mut r = ExtentReader::new(src, &map, vec![(ex, vec![(0x4000, 8), (0x8000, 8)])], 16);
    let mut buf = [0u8; 16];
    assert_eq!(r.read(&mut buf).unwrap(), 8);
    assert_eq!(&buf[..8], &[0xAA; 8]);
    assert!(r.read(&mut buf).is_err());
    // A zero-length extent is skipped by the segment advance loop.
    let src: Arc<dyn sutram_io::ByteSource> = Arc::new(vec![0u8; 0x1000]);
    let ex = Extent { num_bytes: 0, phys_ranges: vec![], ..mk(0) };
    let mut r = ExtentReader::new(src, &map, vec![(ex, vec![])], 4);
    let mut buf = [0u8; 4];
    assert_eq!(r.read(&mut buf).unwrap(), 0);
}

#[test]
fn decompress_lzo_terminator_and_bad_subblock() {
    use crate::decompress::decompress;
    // in_len == 0 is the stream terminator — clean empty output.
    let mut input = Vec::new();
    input.extend_from_slice(&8u32.to_le_bytes());
    input.extend_from_slice(&0u32.to_le_bytes());
    assert!(decompress(2, &input, 64).unwrap().is_empty());
    // A sub-block that fails lzokay and is too short for the raw-copy
    // fallback → Corrupt, never panic.
    let mut input = Vec::new();
    input.extend_from_slice(&16u32.to_le_bytes());
    input.extend_from_slice(&4u32.to_le_bytes());
    input.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00]);
    let r = decompress(2, &input, 4096);
    assert!(r.is_err() || r.unwrap().len() < 4096);
}

#[test]
fn detect_confidence_ladder() {
    use crate::superblock::detect;
    use sutram_fs::DetectConfidence;
    // Garbage → None.
    assert_eq!(detect(&vec![0u8; 0x20000]), DetectConfidence::None);
    // Magic + plausible geometry + bad checksum → High.
    let mut img = vec![0u8; 0x20000];
    let s = 0x10000usize;
    img[s + MAGIC_OFFSET..s + MAGIC_OFFSET + 8].copy_from_slice(BTRFS_MAGIC);
    w32(&mut img, s + 0x90, 4096);
    w32(&mut img, s + 0x94, 4096);
    w64(&mut img, s + 0x50, 0x4000);
    w64(&mut img, s + 0x58, 0x5000);
    w64(&mut img, s + 0x70, 0x100_0000);
    assert_eq!(detect(&img), DetectConfidence::High);
    // + valid checksum → Certain.
    let c = crc32fast::hash(&img[s + CSUM_SIZE..s + SUPERBLOCK_SIZE]);
    img[s..s + 4].copy_from_slice(&c.to_le_bytes());
    assert_eq!(detect(&img), DetectConfidence::Certain);
    // Implausible geometry → Medium even with a good checksum.
    w32(&mut img, s + 0x94, 1234);
    let c = crc32fast::hash(&img[s + CSUM_SIZE..s + SUPERBLOCK_SIZE]);
    img[s..s + 4].copy_from_slice(&c.to_le_bytes());
    assert_eq!(detect(&img), DetectConfidence::Medium);
    // Foreign csum type → unverifiable → High.
    w32(&mut img, s + 0x94, 4096);
    w16(&mut img, s + 0xC4, 1);
    assert_eq!(detect(&img), DetectConfidence::High);
}

#[test]
fn parser_name_and_clone_err_variants() {
    use crate::fs::clone_err;
    use sutram_fs::{FsError, FsParser};
    assert_eq!(crate::BtrfsParser.name(), "btrfs");
    for e in [
        FsError::Unsupported { msg: "x".into() },
        FsError::InvalidInput { msg: "x".into() },
        FsError::Corrupt { offset: 1, msg: "x".into() },
        FsError::Truncated { offset: 1, needed: 2, available: 1 },
    ] {
        let c = clone_err(&e);
        assert_eq!(std::mem::discriminant(&c), std::mem::discriminant(&e));
    }
}
