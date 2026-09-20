//! Unit tests for the leaf decoders — big-endian reads, timestamp math,
//! key/record parsing, residue sniffing.

use super::catalog::{self, hfs_ts, HFS_EPOCH_DELTA};
use super::vh::{ForkData, VolumeHeader};
use sutram_io::le;

fn be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}
fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

#[test]
fn volume_header_big_endian() {
    let mut b = vec![0u8; 512];
    b[0..2].copy_from_slice(&be16(0x482B)); // "H+"
    b[2..4].copy_from_slice(&be16(4));
    b[40..44].copy_from_slice(&be32(4096));
    b[44..48].copy_from_slice(&be32(100));
    // catalog fork @272: logicalSize, clump, totalBlocks, extents
    b[272..280].copy_from_slice(&8192u64.to_be_bytes());
    b[280..284].copy_from_slice(&be32(4096));
    b[284..288].copy_from_slice(&be32(2));
    b[288..292].copy_from_slice(&be32(7)); // extent 0 start
    b[292..296].copy_from_slice(&be32(2)); // count
    let vh = VolumeHeader::parse_vh(&b, 0, false, None).unwrap();
    assert_eq!(vh.signature, 0x482B);
    assert_eq!(vh.block_size, 4096);
    assert_eq!(vh.total_blocks, 100);
    assert_eq!(vh.cat_fork.logical_size, 8192);
    assert_eq!(vh.cat_fork.extents[0].start, 7);
    assert_eq!(vh.cat_fork.extents[0].count, 2);
}

#[test]
fn volume_header_rejects_garbage() {
    let mut b = vec![0u8; 512];
    b[0..2].copy_from_slice(&be16(0x482B));
    b[2..4].copy_from_slice(&be16(9)); // bad version
    assert!(VolumeHeader::parse_vh(&b, 0, false, None).is_err());
    b[2..4].copy_from_slice(&be16(4));
    b[40..44].copy_from_slice(&be32(4097)); // not power of two
    assert!(VolumeHeader::parse_vh(&b, 0, false, None).is_err());
}

#[test]
fn hfs_epoch_math() {
    // 1904-01-01T00:00:00Z is -2082844800 unix seconds.
    assert_eq!(HFS_EPOCH_DELTA, 2_082_844_800);
    let t = hfs_ts(HFS_EPOCH_DELTA as u32 + 1_705_314_620);
    // 2024-01-15T10:30:20Z in unix nanos.
    assert_eq!(t.value, Some(1_705_314_620_000_000_000));
    assert_eq!(t.raw_value, (HFS_EPOCH_DELTA as u32 + 1_705_314_620) as u64);
    assert_eq!(t.raw_encoding, "hfs+-u32-1904-local");
    // Zero = unset → value None, never fabricated.
    assert_eq!(hfs_ts(0).value, None);
}

#[test]
fn catalog_key_parse() {
    // key_len=6+2*3=12, parent=2, name "abc"
    let mut rec = Vec::new();
    rec.extend_from_slice(&be16(12));
    rec.extend_from_slice(&be32(2));
    rec.extend_from_slice(&be16(3));
    for c in "abc".chars() {
        rec.extend_from_slice(&be16(c as u16));
    }
    let key = catalog::parse_key(&rec).unwrap();
    assert_eq!(key.parent, 2);
    assert_eq!(key.name, "abc");
    assert_eq!(key.total_len, 14);
    // Inconsistent key_len rejected.
    let mut bad = rec.clone();
    bad[0..2].copy_from_slice(&be16(10));
    assert!(catalog::parse_key(&bad).is_none());
}

#[test]
fn file_record_parse() {
    let mut data = vec![0u8; 248];
    data[0..2].copy_from_slice(&be16(2)); // file
    data[8..12].copy_from_slice(&be32(42)); // cnid
    data[12..16].copy_from_slice(&be32(0x6C00_0000)); // createDate
    data[88..96].copy_from_slice(&1234u64.to_be_bytes()); // dataFork size
    data[88 + 12..88 + 16].copy_from_slice(&be32(1)); // totalBlocks
    data[88 + 16..88 + 20].copy_from_slice(&be32(9)); // extent start
    data[88 + 20..88 + 24].copy_from_slice(&be32(1));
    let rec = catalog::parse_record(&data).unwrap();
    let catalog::CatRecord::File(f) = rec else {
        panic!()
    };
    assert_eq!(f.cnid, 42);
    assert_eq!(f.data_fork.logical_size, 1234);
    assert_eq!(f.data_fork.extents[0].start, 9);
}

#[test]
fn thread_record_parse() {
    let mut data = Vec::new();
    data.extend_from_slice(&be16(3)); // folder thread
    data.extend_from_slice(&be16(0)); // reserved
    data.extend_from_slice(&be32(2)); // parentID
    data.extend_from_slice(&be16(7)); // name len
    for c in "subdir".chars().chain("x".chars()) {
        data.extend_from_slice(&be16(c as u16));
    }
    let rec = catalog::parse_record(&data).unwrap();
    let catalog::CatRecord::Thread { parent, name } = rec else {
        panic!()
    };
    assert_eq!(parent, 2);
    assert_eq!(name, "subdirx");
}

#[test]
fn residue_sniff_is_conservative() {
    // Craft a full keyed file record, then check sniff_record finds it.
    let mut rec = Vec::new();
    rec.extend_from_slice(&be16(10)); // key_len: 6 + 2*2
    rec.extend_from_slice(&be32(2)); // parent
    rec.extend_from_slice(&be16(2)); // name len 2
    rec.extend_from_slice(&be16('D' as u16));
    rec.extend_from_slice(&be16('F' as u16));
    let mut data = vec![0u8; 248];
    data[0..2].copy_from_slice(&be16(2));
    rec.extend_from_slice(&data);
    let (len, key) = catalog::sniff_record(&rec, 0).unwrap();
    assert_eq!(len, rec.len());
    assert_eq!(key.name, "DF");
    // Garbage at offset 1 shouldn't parse.
    assert!(catalog::sniff_record(&rec, 1).is_none());
    // Zeroed buffer never parses.
    assert!(catalog::sniff_record(&[0u8; 512], 0).is_none());
}

#[test]
fn decmpfs_header_parse() {
    let mut x = Vec::new();
    x.extend_from_slice(&0x636D7066u32.to_le_bytes()); // 'cmpf' LE
    x.extend_from_slice(&3u32.to_le_bytes()); // zlib inline
    x.extend_from_slice(&999u64.to_le_bytes());
    x.extend_from_slice(b"payload");
    let h = super::attrs::parse_decmpfs(&x).unwrap();
    assert_eq!(h.compression_type, 3);
    assert_eq!(h.uncompressed_size, 999);
    assert_eq!(h.inline, b"payload");
    assert!(super::attrs::parse_decmpfs(&x[..8]).is_err());
}

#[test]
fn decmpfs_inline_zlib_roundtrip() {
    let payload = b"hello hello hello hello";
    let z = miniz_oxide::deflate::compress_to_vec_zlib(payload, 6);
    let h = super::attrs::DecmpfsHeader {
        compression_type: 3,
        uncompressed_size: payload.len() as u64,
        inline: z,
    };
    let out = super::attrs::decompress(&h, None).unwrap();
    assert_eq!(out, payload);
    // type 7 (LZVN) → Unsupported, not a panic.
    let h = super::attrs::DecmpfsHeader {
        compression_type: 7,
        uncompressed_size: 10,
        inline: vec![1, 2, 3],
    };
    assert!(super::attrs::decompress(&h, None).is_err());
}

#[test]
fn extents_overflow_key() {
    let mut rec = Vec::new();
    rec.extend_from_slice(&be16(10));
    rec.push(0); // fork_type data
    rec.push(0); // pad
    rec.extend_from_slice(&be32(77)); // cnid
    rec.extend_from_slice(&be32(16)); // startBlock
    let (k, len) = super::extents::parse_key(&rec).unwrap();
    assert_eq!(len, 12);
    assert_eq!(k.cnid, 77);
    assert_eq!(k.start_block, 16);
    assert_eq!(k.fork, 0);
}

#[test]
fn attr_key_and_inline_record() {
    let mut rec = Vec::new();
    let name = "com.apple.test";
    let klen = 12 + 2 * name.len();
    rec.extend_from_slice(&be16(klen as u16));
    rec.extend_from_slice(&be16(0)); // pad
    rec.extend_from_slice(&be32(55)); // cnid
    rec.extend_from_slice(&be32(0)); // startBlock
    rec.extend_from_slice(&be16(name.len() as u16));
    for c in name.encode_utf16() {
        rec.extend_from_slice(&be16(c));
    }
    let key = super::attrs::parse_key(&rec).unwrap();
    assert_eq!(key.cnid, 55);
    assert_eq!(key.name, name);
    // Inline record: type 0x10, reserved, reserved2[6], len u16, data.
    let mut d = Vec::new();
    d.extend_from_slice(&be32(0x10));
    d.extend_from_slice(&be32(0));
    d.extend_from_slice(&[0u8; 6]);
    d.extend_from_slice(&be16(5));
    d.extend_from_slice(b"VALUE");
    let super::attrs::AttrData::Inline { data_off, len } = super::attrs::parse_record(&d).unwrap()
    else {
        panic!()
    };
    assert_eq!(data_off, 16);
    assert_eq!(len, 5);
    assert_eq!(&d[data_off..data_off + len as usize], b"VALUE");
}

#[test]
fn fork_data_parse_le_vs_be() {
    // Guard against an accidental LE decode: a fork whose logical size is
    // 0x1122334455667788 must come back identical, not byte-swapped.
    let mut b = [0u8; 80];
    b[0..8].copy_from_slice(&0x1122334455667788u64.to_be_bytes());
    b[16..20].copy_from_slice(&0xAABBCCDDu32.to_be_bytes());
    let f = ForkData::parse(&b, 0).unwrap();
    assert_eq!(f.logical_size, 0x1122334455667788);
    assert_eq!(f.extents[0].start, 0xAABBCCDD);
    // le helpers exist and differ — sanity.
    assert_eq!(le::u32_be(&b, 16), Some(0xAABBCCDD));
    assert_eq!(le::u32(&b, 16), Some(0xDDCCBBAA));
}
