//! Unit tests for the leaf decoders — big-endian reads, timestamp math,
//! key/record parsing, residue sniffing.

use super::attrs::{self, DecmpfsHeader};
use super::btree::{self, Btree};
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

// ---- attrs: decmpfs 资源叉块表 / 错误路径 -------------------------------

/// 搭一个 CmpfRsrcHead + 块表 + payload 的资源叉字节串。
fn rsrc_table(blocks: &[(u32, &[u8])]) -> Vec<u8> {
    let header_size = 16usize;
    let table_start = header_size + 8;
    let payload_start = table_start + blocks.len() * 8;
    let mut r = vec![0u8; payload_start];
    r[0..4].copy_from_slice(&(header_size as u32).to_be_bytes());
    r[header_size + 4..header_size + 8]
        .copy_from_slice(&(blocks.len() as u32).to_le_bytes()); // numBlocks LE
    let mut cursor = payload_start;
    let mut data = Vec::new();
    for (i, (_, payload)) in blocks.iter().enumerate() {
        let off = (cursor - header_size) as u32;
        r[table_start + i * 8..table_start + i * 8 + 4]
            .copy_from_slice(&off.to_le_bytes());
        r[table_start + i * 8 + 4..table_start + i * 8 + 8]
            .copy_from_slice(&(payload.len() as u32).to_le_bytes());
        data.extend_from_slice(payload);
        cursor += payload.len();
    }
    r.extend_from_slice(&data);
    r
}

#[test]
fn decmpfs_type4_rsrc_table_inflates() {
    let plain = b"block one hello hello hello";
    let z = miniz_oxide::deflate::compress_to_vec_zlib(plain, 6);
    let rsrc = rsrc_table(&[(0, &z)]);
    let hdr = DecmpfsHeader {
        compression_type: 4,
        uncompressed_size: plain.len() as u64,
        inline: Vec::new(),
    };
    let out = attrs::decompress(&hdr, Some(&rsrc)).unwrap();
    assert_eq!(out, plain);
}

#[test]
fn decmpfs_type4_ff_prefix_is_verbatim() {
    // 块首字节 0xFF → 剩余字节原样存储，不走 zlib。
    let mut block = vec![0xFF];
    block.extend_from_slice(b"VERBATIM-STORED");
    let rsrc = rsrc_table(&[(0, &block)]);
    let hdr = DecmpfsHeader {
        compression_type: 4,
        uncompressed_size: 15,
        inline: Vec::new(),
    };
    let out = attrs::decompress(&hdr, Some(&rsrc)).unwrap();
    assert_eq!(out, b"VERBATIM-STORED");
}

#[test]
fn decmpfs_type10_raw_table() {
    // 类型 10：同样的表结构，但块内容是未压缩的原始字节。
    let rsrc = rsrc_table(&[(0, b"RAW-CHUNK-ONE"), (0, b"RAW-CHUNK-TWO")]);
    let hdr = DecmpfsHeader {
        compression_type: 10,
        uncompressed_size: 26,
        inline: Vec::new(),
    };
    let out = attrs::decompress(&hdr, Some(&rsrc)).unwrap();
    assert_eq!(out, b"RAW-CHUNK-ONERAW-CHUNK-TWO");
}

#[test]
fn decmpfs_types_1_9_verbatim_inline() {
    for t in [1u32, 9] {
        let hdr = DecmpfsHeader {
            compression_type: t,
            uncompressed_size: 4,
            inline: b"DATA".to_vec(),
        };
        assert_eq!(attrs::decompress(&hdr, None).unwrap(), b"DATA");
    }
}

#[test]
fn decmpfs_type3_ff_prefix_skips_inflate() {
    // 类型 3 内联 payload 首字节 0xFF → 尾部原样。
    let hdr = DecmpfsHeader {
        compression_type: 3,
        uncompressed_size: 3,
        inline: {
            let mut v = vec![0xFF];
            v.extend_from_slice(b"RAW");
            v
        },
    };
    assert_eq!(attrs::decompress(&hdr, None).unwrap(), b"RAW");
}

#[test]
fn decmpfs_rsrc_types_need_fork() {
    // 4/8/10/12 没有 rsrc 就报错；8/12 即便有 rsrc 也是 Unsupported。
    for t in [4u32, 10] {
        let hdr = DecmpfsHeader {
            compression_type: t,
            uncompressed_size: 1,
            inline: Vec::new(),
        };
        assert!(attrs::decompress(&hdr, None).is_err());
    }
    for t in [8u32, 12] {
        let hdr = DecmpfsHeader {
            compression_type: t,
            uncompressed_size: 1,
            inline: Vec::new(),
        };
        assert!(attrs::decompress(&hdr, Some(&[0u8; 64])).is_err());
    }
}

#[test]
fn decmpfs_rsrc_table_bounds() {
    // header_size 太小 / 越界 → Corrupt。
    let mut r = vec![0u8; 64];
    r[0..4].copy_from_slice(&8u32.to_be_bytes()); // header_size < 16
    let hdr = DecmpfsHeader {
        compression_type: 4,
        uncompressed_size: 10,
        inline: Vec::new(),
    };
    assert!(attrs::decompress(&hdr, Some(&r)).is_err());
    // numBlocks 爆表。
    let mut r2 = vec![0u8; 64];
    r2[0..4].copy_from_slice(&16u32.to_be_bytes());
    r2[20..24].copy_from_slice(&9_999_999u32.to_le_bytes());
    assert!(attrs::decompress(&hdr, Some(&r2)).is_err());
}

#[test]
fn decmpfs_type_name_covers_known() {
    assert_eq!(attrs::decmpfs_type_name(3), "zlib-inline");
    assert_eq!(attrs::decmpfs_type_name(4), "zlib-resource-fork");
    assert_eq!(attrs::decmpfs_type_name(11), "lzfse-inline");
    assert_eq!(attrs::decmpfs_type_name(99), "unknown");
}

#[test]
fn attr_key_rejects_bad_shape() {
    // key_len 太短 → None。
    let mut rec = vec![0u8; 20];
    rec[0..2].copy_from_slice(&8u16.to_be_bytes());
    assert!(attrs::parse_key(&rec).is_none());
    // nlen > 127 → None。
    let mut rec = vec![0u8; 20];
    rec[0..2].copy_from_slice(&300u16.to_be_bytes());
    rec[12..14].copy_from_slice(&200u16.to_be_bytes());
    assert!(attrs::parse_key(&rec).is_none());
}

#[test]
fn attr_record_forkdata_and_extents() {
    // 0x20 fork data: type u32 + reserved u32 + ForkData @8。
    let mut d = vec![0u8; 96];
    d[0..4].copy_from_slice(&0x20u32.to_be_bytes());
    d[8..16].copy_from_slice(&4096u64.to_be_bytes()); // logicalSize
    d[8 + 12..8 + 16].copy_from_slice(&1u32.to_be_bytes()); // totalBlocks
    let attrs::AttrData::ForkData(f) = attrs::parse_record(&d).unwrap() else {
        panic!()
    };
    assert_eq!(f.logical_size, 4096);
    // 0x30 extents: type + reserved + start/count @8/@12。
    let mut d = vec![0u8; 16];
    d[0..4].copy_from_slice(&0x30u32.to_be_bytes());
    d[8..12].copy_from_slice(&55u32.to_be_bytes());
    d[12..16].copy_from_slice(&3u32.to_be_bytes());
    let attrs::AttrData::Extents(e) = attrs::parse_record(&d).unwrap() else {
        panic!()
    };
    assert_eq!((e.start, e.count), (55, 3));
    // 未知类型 → Other。
    let mut d = vec![0u8; 8];
    d[0..4].copy_from_slice(&0x99u32.to_be_bytes());
    assert!(matches!(
        attrs::parse_record(&d).unwrap(),
        attrs::AttrData::Other(0x99)
    ));
}

// ---- btree: open/Node 校验 + 链路保护 -----------------------------------

/// 最小合法 B 树头节点（512 B）。
fn header_node512(node_size: u16, total: u32) -> Vec<u8> {
    let mut n = vec![0u8; 512];
    n[8] = 1; // header kind
    let h = 14;
    n[h + 18..h + 20].copy_from_slice(&node_size.to_be_bytes());
    n[h + 22..h + 26].copy_from_slice(&total.to_be_bytes());
    n
}

#[test]
fn btree_open_rejects_bad_header() {
    // kind 不是 header。
    let mut n = header_node512(512, 4);
    n[8] = 0xFF;
    assert!(Btree::open(&n, vec![(0, 512)], 0).is_err());
    // node_size 不是 2 的幂。
    assert!(Btree::open(&header_node512(300, 4), vec![(0, 512)], 0).is_err());
    // total_nodes 为 0。
    assert!(Btree::open(&header_node512(512, 0), vec![(0, 512)], 0).is_err());
}

/// 合法叶子节点：kind=0xFF, height=1, numRecs 条记录顺序摆放。
fn leaf_node512(records: &[&[u8]]) -> Vec<u8> {
    let mut n = vec![0u8; 512];
    n[8] = 0xFF;
    n[9] = 1;
    n[10..12].copy_from_slice(&(records.len() as u16).to_be_bytes());
    let mut pos = 14usize;
    let mut offs = Vec::new();
    for r in records {
        offs.push(pos as u16);
        n[pos..pos + r.len()].copy_from_slice(r);
        pos += r.len();
    }
    offs.push(pos as u16);
    let table = 512 - offs.len() * 2;
    for (i, o) in offs.iter().enumerate() {
        n[table + i * 2..table + i * 2 + 2].copy_from_slice(&o.to_be_bytes());
    }
    n
}

#[test]
fn node_parse_offset_table_rules() {
    // numRecs 爆表（偏移表长度超过节点）。
    let mut n = leaf_node512(&[]);
    n[10..12].copy_from_slice(&500u16.to_be_bytes());
    assert!(btree::Node::parse(n, 0).is_err());
    // record 0 偏移低于 14 → Corrupt。
    let mut n = leaf_node512(&[]);
    let table = 512 - 4;
    n[table..table + 2].copy_from_slice(&4u16.to_be_bytes());
    n[10..12].copy_from_slice(&1u16.to_be_bytes());
    assert!(btree::Node::parse(n, 0).is_err());
    // 非单调偏移 → Corrupt。
    let mut n = leaf_node512(&[]);
    n[10..12].copy_from_slice(&2u16.to_be_bytes());
    let table = 512 - 6;
    n[table..table + 2].copy_from_slice(&100u16.to_be_bytes());
    n[table + 2..table + 4].copy_from_slice(&50u16.to_be_bytes());
    n[table + 4..table + 6].copy_from_slice(&120u16.to_be_bytes());
    assert!(btree::Node::parse(n, 0).is_err());
}

#[test]
fn node_record_and_free_space() {
    let rec = b"RECORD-BYTES!";
    let node = btree::Node::parse(leaf_node512(&[rec]), 0).unwrap();
    assert_eq!(node.record(0), Some(&rec[..]));
    assert_eq!(node.record(1), None);
    assert_eq!(node.record_at(14), Some(&rec[..]));
    let (s, e) = node.free_space().unwrap();
    assert!(s < e && e <= 512);
    // 满节点无空闲 → None。
    let mut full = leaf_node512(&[]);
    let table = 512 - 2;
    full[table..table + 2].copy_from_slice(&(table as u16).to_be_bytes());
    let node = btree::Node::parse(full, 0).unwrap();
    assert!(node.free_space().is_none());
}

#[test]
fn map_logical_and_range_span() {
    let ranges = vec![(1000u64, 100u64), (2000, 100)];
    assert_eq!(btree::map_logical(&ranges, 0), Some(1000));
    assert_eq!(btree::map_logical(&ranges, 150), Some(2050));
    assert_eq!(btree::map_logical(&ranges, 999), None);
    // 跨 extent 读：第二段起点的内容。
    let mut img = vec![0u8; 4096];
    img[1000..1100].copy_from_slice(&[0xAA; 100]);
    img[2000..2100].copy_from_slice(&[0xBB; 100]);
    let out = btree::read_range_span(&img, &ranges, 90, 20).unwrap();
    assert_eq!(&out[..10], &[0xAA; 10]);
    assert_eq!(&out[10..], &[0xBB; 10]);
    // 超出映射 → None。
    assert!(btree::read_range_span(&img, &ranges, 500, 10).is_none());
}

#[test]
fn leaf_chain_terminates_on_cycle() {
    // 自环链：1→2→1，必须停，不能死循环。
    let mut img = vec![0u8; 512 * 4];
    img[..512].copy_from_slice(&header_node512(512, 4));
    // header first_leaf=1。
    img[14 + 10..14 + 14].copy_from_slice(&1u32.to_be_bytes());
    let mut n1 = leaf_node512(&[]);
    n1[0..4].copy_from_slice(&2u32.to_be_bytes()); // fLink → 2
    img[512..1024].copy_from_slice(&n1);
    let mut n2 = leaf_node512(&[]);
    n2[0..4].copy_from_slice(&1u32.to_be_bytes()); // fLink → 1 (回环)
    img[1024..1536].copy_from_slice(&n2);
    let t = Btree::open(&img, vec![(0, 512 * 4)], 0).unwrap();
    let mut visited = 0;
    t.for_each_leaf(&img, |_, _| {
        visited += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(visited, 2); // 1、2 各一次，第三次 seen 命中退出
}

#[test]
fn leaf_chain_rejects_wrong_kind() {
    let mut img = vec![0u8; 512 * 2];
    img[..512].copy_from_slice(&header_node512(512, 2));
    img[14 + 10..14 + 14].copy_from_slice(&1u32.to_be_bytes());
    // 节点 1 kind=0（index 节点）→ for_each_leaf 报错。
    let mut n1 = leaf_node512(&[]);
    n1[8] = 0;
    img[512..1024].copy_from_slice(&n1);
    let t = Btree::open(&img, vec![(0, 512 * 2)], 0).unwrap();
    assert!(t.for_each_leaf(&img, |_, _| Ok(())).is_err());
}

// ---- vh: detect 分层 + wrapped 分支 --------------------------------------

#[test]
fn detect_confidence_tiers() {
    // 完整字段 → Certain。
    let mut b = vec![0u8; 512];
    b[0..2].copy_from_slice(&be16(0x482B));
    b[2..4].copy_from_slice(&be16(4));
    b[40..44].copy_from_slice(&be32(4096));
    b[44..48].copy_from_slice(&be32(100));
    b[272..280].copy_from_slice(&8192u64.to_be_bytes());
    b[284..288].copy_from_slice(&be32(2));
    b[288..292].copy_from_slice(&be32(7));
    b[292..296].copy_from_slice(&be32(2));
    let img = [&vec![0u8; 1024][..], &b[..]].concat();
    assert_eq!(
        VolumeHeader::detect(&img),
        sutram_fs::DetectConfidence::Certain
    );
    // 只有签名 → Low（版本/块大小/目录全不达标）。
    let mut b2 = vec![0u8; 512];
    b2[0..2].copy_from_slice(&be16(0x482B));
    let img2 = [&vec![0u8; 1024][..], &b2[..]].concat();
    assert_eq!(
        VolumeHeader::detect(&img2),
        sutram_fs::DetectConfidence::Low
    );
    // BD 无嵌入 → Low。
    let mut b3 = vec![0u8; 512];
    b3[0..2].copy_from_slice(&be16(0x4244));
    let img3 = [&vec![0u8; 1024][..], &b3[..]].concat();
    assert_eq!(
        VolumeHeader::detect(&img3),
        sutram_fs::DetectConfidence::Low
    );
}

#[test]
fn wrapped_rejects_pure_hfs() {
    // BD + drEmbedSigWord ≠ H+ → Unsupported。
    let mut img = vec![0u8; 4096];
    img[1024..1026].copy_from_slice(&be16(0x4244));
    img[1024 + 0x14..1024 + 0x18].copy_from_slice(&be32(4096));
    img[1024 + 0x7C..1024 + 0x7E].copy_from_slice(&be16(0x1234));
    assert!(VolumeHeader::parse(&img).is_err());
    // BD + drAlBlkSiz=0 → Corrupt。
    let mut img = vec![0u8; 4096];
    img[1024..1026].copy_from_slice(&be16(0x4244));
    img[1024 + 0x7C..1024 + 0x7E].copy_from_slice(&be16(0x482B));
    assert!(VolumeHeader::parse(&img).is_err());
}

// ---- catalog: is_hardlink / is_symlink 分支 ------------------------------

#[test]
fn file_rec_hardlink_symlink_flags() {
    // slnk/rhap → symlink。
    let mut d = vec![0u8; 248];
    d[0..2].copy_from_slice(&be16(2));
    d[48..52].copy_from_slice(&u32::from_be_bytes(*b"slnk").to_be_bytes());
    d[52..56].copy_from_slice(&u32::from_be_bytes(*b"rhap").to_be_bytes());
    let catalog::CatRecord::File(f) = catalog::parse_record(&d).unwrap() else {
        panic!()
    };
    assert!(f.is_symlink());
    assert!(!f.is_hardlink());
    // hlnk/hfs+ → hardlink。
    let mut d = vec![0u8; 248];
    d[0..2].copy_from_slice(&be16(2));
    d[48..52].copy_from_slice(&u32::from_be_bytes(*b"hlnk").to_be_bytes());
    d[52..56].copy_from_slice(&u32::from_be_bytes(*b"hfs+").to_be_bytes());
    let catalog::CatRecord::File(f) = catalog::parse_record(&d).unwrap() else {
        panic!()
    };
    assert!(f.is_hardlink());
    assert!(!f.is_symlink());
    // 普通文件两者都不是。
    let mut d = vec![0u8; 248];
    d[0..2].copy_from_slice(&be16(2));
    let catalog::CatRecord::File(f) = catalog::parse_record(&d).unwrap() else {
        panic!()
    };
    assert!(!f.is_hardlink() && !f.is_symlink());
}

#[test]
fn extents_record_parse_bounds() {
    // 数据不足 64 B → None。
    let short = vec![0u8; 32];
    assert!(super::extents::parse_record(&short).is_none());
    // 64 B：8 组 (start,count)。
    let mut d = vec![0u8; 64];
    d[0..4].copy_from_slice(&be32(11));
    d[4..8].copy_from_slice(&be32(5));
    let exts = super::extents::parse_record(&d).unwrap();
    assert_eq!((exts[0].start, exts[0].count), (11, 5));
}

// ---- vh: journal info + catalog timestamps/sniff 分支 ---------------------

fn bare_vh() -> VolumeHeader {
    let mut b = vec![0u8; 512];
    b[0..2].copy_from_slice(&be16(0x482B));
    b[2..4].copy_from_slice(&be16(4));
    b[40..44].copy_from_slice(&be32(4096));
    b[44..48].copy_from_slice(&be32(100));
    b[272..280].copy_from_slice(&8192u64.to_be_bytes());
    b[284..288].copy_from_slice(&be32(2));
    b[288..292].copy_from_slice(&be32(7));
    b[292..296].copy_from_slice(&be32(2));
    VolumeHeader::parse_vh(&b, 0, false, None).unwrap()
}

#[test]
fn vh_parse_short_and_alt_errors() {
    // 源不够长 → Truncated（没有 alt 回退余地）。
    let img = vec![0u8; 800];
    assert!(VolumeHeader::parse(&img).is_err());
    // 主签名坏 + 卷太小放不下 alt → "volume too small"。
    let img = vec![0u8; 2000];
    let e = VolumeHeader::parse(&img).unwrap_err();
    assert!(e.to_string().contains("volume too small") || e.to_string().contains("signature"));
    // alt 签名非法 → Err。
    let mut img = vec![0u8; 4096];
    img[3072..3074].copy_from_slice(&be16(0x9999));
    assert!(VolumeHeader::parse(&img).is_err());
}

#[test]
fn vh_parse_vh_validation_errors() {
    let mut b = vec![0u8; 512];
    b[0..2].copy_from_slice(&be16(0x482B));
    b[2..4].copy_from_slice(&be16(4));
    // 块大小非 2 的幂 → Corrupt。
    b[40..44].copy_from_slice(&be32(1000));
    assert!(VolumeHeader::parse_vh(&b, 0, false, None).is_err());
    // 零 total_blocks。
    let mut b2 = b.clone();
    b2[40..44].copy_from_slice(&be32(4096));
    assert!(VolumeHeader::parse_vh(&b2, 0, false, None).is_err());
    // catalog fork 为空 → "no extents"。
    let mut b3 = b2.clone();
    b3[44..48].copy_from_slice(&be32(100));
    assert!(VolumeHeader::parse_vh(&b3, 0, false, None).is_err());
}

#[test]
fn detect_short_and_medium() {
    // 源太短 → None。
    let img = vec![0u8; 100];
    assert_eq!(
        VolumeHeader::detect(&img),
        sutram_fs::DetectConfidence::None
    );
    // wrapper BD + 嵌入签名坏 → detect 走 Medium（parse 失败）。
    let mut img = vec![0u8; 8192];
    img[1024..1026].copy_from_slice(&be16(0x4244));
    img[1024 + 0x14..1024 + 0x18].copy_from_slice(&be32(4096));
    img[1024 + 0x7C..1024 + 0x7E].copy_from_slice(&be16(0x482B));
    img[1024 + 0x7E..1024 + 0x80].copy_from_slice(&be16(4)); // start block
    img[1024 + 0x80..1024 + 0x82].copy_from_slice(&be16(2)); // block count
    assert_eq!(
        VolumeHeader::detect(&img),
        sutram_fs::DetectConfidence::Medium
    );
    // parse 同样失败（嵌入 alt 也没有合法头）。
    assert!(VolumeHeader::parse(&img).is_err());
}

#[test]
fn wrapped_embedded_alt_fallback() {
    // wrapper：嵌入主头坏、嵌入 alt 好 → 回退到嵌入 alt。
    let mut img = vec![0u8; 20 * 4096];
    img[1024..1026].copy_from_slice(&be16(0x4244)); // 'BD'
    img[1024 + 0x14..1024 + 0x18].copy_from_slice(&be32(4096)); // drAlBlkSiz
    img[1024 + 0x7C..1024 + 0x7E].copy_from_slice(&be16(0x482B));
    img[1024 + 0x7E..1024 + 0x80].copy_from_slice(&be16(3)); // embed start = blk 3
    img[1024 + 0x80..1024 + 0x82].copy_from_slice(&be16(10)); // 10 al-blks = 40960
    let embed_off = 3 * 4096usize;
    // 嵌入主头签名坏。
    img[embed_off + 1024..embed_off + 1026].copy_from_slice(&be16(0xDEAD));
    // 嵌入 alt @ embed_end - 1024：合法 H+。
    let alt = embed_off + 10 * 4096 - 1024;
    img[alt..alt + 2].copy_from_slice(&be16(0x482B));
    img[alt + 2..alt + 4].copy_from_slice(&be16(4));
    img[alt + 40..alt + 44].copy_from_slice(&be32(4096));
    img[alt + 44..alt + 48].copy_from_slice(&be32(24));
    img[alt + 272..alt + 352].copy_from_slice(&{
        let mut f = [0u8; 80];
        put_fork(&mut f, 0, 12288, &[(5, 3)]);
        f
    });
    let vh = VolumeHeader::parse(&img).unwrap();
    assert!(vh.used_alt_vh);
    assert_eq!(vh.block0_offset, embed_off as u64);
}

#[test]
fn journal_info_read_failures() {
    // jib 指向源外 → None。
    let mut vh = bare_vh();
    vh.journal_info_block = 999;
    let img = vec![0u8; 4096 * 4];
    assert!(super::vh::read_journal_info(&img, &vh).is_none());
    // JIB 里 buffer_offset 出界 → 整个 journal 信息被丢弃（.ok()? 短路）。
    let mut vh = bare_vh();
    vh.journal_info_block = 1;
    let mut img = vec![0u8; 4096 * 4];
    let jib = 4096;
    img[jib + 36..jib + 44].copy_from_slice(&999_999u64.to_be_bytes());
    img[jib + 44..jib + 52].copy_from_slice(&4096u64.to_be_bytes());
    let info = super::vh::read_journal_info(&img, &vh).unwrap();
    assert!(info.journal_magic.is_none());
    // buffer_size=0 → magic None。
    let mut vh = bare_vh();
    vh.journal_info_block = 1;
    let info = super::vh::read_journal_info(&img, &vh).unwrap();
    assert!(info.journal_magic.is_none());
}

#[test]
fn journal_info_none_when_unset() {
    // journal_info_block = 0 → 直接 None，不读盘。
    let vh = bare_vh();
    let img = vec![0u8; 4096];
    assert!(super::vh::read_journal_info(&img, &vh).is_none());
}

#[test]
fn journal_info_reads_jib() {
    // JIB: flags @0, device_signature[8] @4..36, offset @36, size @44。
    let mut vh = bare_vh();
    vh.journal_info_block = 40;
    let mut img = vec![0u8; 4096 * 42];
    let jib = 40 * 4096;
    img[jib..jib + 4].copy_from_slice(&1u32.to_be_bytes());
    img[jib + 36..jib + 44].copy_from_slice(&(41 * 4096u64).to_be_bytes());
    img[jib + 44..jib + 52].copy_from_slice(&4096u64.to_be_bytes());
    let jb = 41 * 4096;
    img[jb..jb + 4].copy_from_slice(&0x4A4E4C78u32.to_be_bytes()); // 'JNLx'
    let info = super::vh::read_journal_info(&img, &vh).unwrap();
    assert_eq!(info.jib_block, 40);
    assert_eq!(info.buffer_offset, 41 * 4096);
    assert_eq!(info.journal_magic, Some(0x4A4E4C78));
}

#[test]
fn catalog_timestamps_maps_macb() {
    let dates = [
        HFS_EPOCH_DELTA as u32 + 100,
        HFS_EPOCH_DELTA as u32 + 200,
        HFS_EPOCH_DELTA as u32 + 300,
        HFS_EPOCH_DELTA as u32 + 400,
        0,
    ];
    let t = catalog::timestamps(&dates);
    assert_eq!(t.created.unwrap().value, Some(100_000_000_000));
    assert_eq!(t.modified.unwrap().value, Some(200_000_000_000));
    assert_eq!(t.changed.unwrap().value, Some(300_000_000_000));
    assert_eq!(t.accessed.unwrap().value, Some(400_000_000_000));
    // backup 占 dates[4]=0 → raw 0 → value None，不捏造。
    assert!(t.deleted.is_none());
}

#[test]
fn clean_name_strips_separators() {
    let n = catalog::clean_name("a/b\\c");
    assert!(!n.contains('/') && !n.contains('\\'));
}

#[test]
fn sniff_record_thread_and_rejects() {
    // 线程记录（类型 3）：变量长度也能算出总长。
    let mut rec = Vec::new();
    rec.extend_from_slice(&be16(8)); // key_len = 6+2*1
    rec.extend_from_slice(&be32(2));
    rec.extend_from_slice(&be16(1));
    rec.extend_from_slice(&be16('x' as u16));
    rec.extend_from_slice(&be16(3)); // folder thread
    rec.extend_from_slice(&be16(0));
    rec.extend_from_slice(&be32(2));
    rec.extend_from_slice(&be16(2));
    rec.extend_from_slice(&be16('a' as u16));
    rec.extend_from_slice(&be16('b' as u16));
    let (len, key) = catalog::sniff_record(&rec, 0).unwrap();
    assert_eq!(len, rec.len());
    assert_eq!(key.parent, 2);
    // parent=0 → None（垃圾键）。
    let mut rec = Vec::new();
    rec.extend_from_slice(&be16(10));
    rec.extend_from_slice(&be32(0));
    rec.extend_from_slice(&be16(2));
    rec.extend_from_slice(&be16('a' as u16));
    rec.extend_from_slice(&be16('b' as u16));
    rec.extend_from_slice(&[0u8; 248]);
    assert!(catalog::sniff_record(&rec, 0).is_none());
    // 奇数 key_len → None。
    let mut rec = Vec::new();
    rec.extend_from_slice(&be16(11));
    rec.extend_from_slice(&[0u8; 260]);
    assert!(catalog::sniff_record(&rec, 0).is_none());
}

// ---- 最小可挂载镜像：mount 管线 + walk 全阶段 -----------------------------

const TB: usize = 4096;

fn put_fork(b: &mut [u8], off: usize, logical: u64, extents: &[(u32, u32)]) {
    b[off..off + 8].copy_from_slice(&logical.to_be_bytes());
    let tb: u32 = extents.iter().map(|e| e.1).sum();
    b[off + 12..off + 16].copy_from_slice(&tb.to_be_bytes());
    for (i, &(s, c)) in extents.iter().enumerate() {
        b[off + 16 + i * 8..off + 20 + i * 8].copy_from_slice(&s.to_be_bytes());
        b[off + 20 + i * 8..off + 24 + i * 8].copy_from_slice(&c.to_be_bytes());
    }
}

fn cat_key(parent: u32, name: &str) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut v = Vec::new();
    v.extend_from_slice(&(6 + 2 * units.len() as u16).to_be_bytes());
    v.extend_from_slice(&parent.to_be_bytes());
    v.extend_from_slice(&(units.len() as u16).to_be_bytes());
    for u in units {
        v.extend_from_slice(&u.to_be_bytes());
    }
    v
}

fn file248(cnid: u32, extents: &[(u32, u32)], size: u64) -> Vec<u8> {
    let mut d = vec![0u8; 248];
    d[0..2].copy_from_slice(&be16(2));
    d[8..12].copy_from_slice(&be32(cnid));
    d[12..16].copy_from_slice(&be32(HFS_EPOCH_DELTA as u32 + 500));
    put_fork(&mut d, 88, size, extents);
    d
}

fn folder88(cnid: u32) -> Vec<u8> {
    let mut d = vec![0u8; 88];
    d[0..2].copy_from_slice(&be16(1));
    d[8..12].copy_from_slice(&be32(cnid));
    d[12..16].copy_from_slice(&be32(HFS_EPOCH_DELTA as u32 + 500));
    d
}

fn thread_body(parent: u32, name: &str) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut d = Vec::new();
    d.extend_from_slice(&be16(3));
    d.extend_from_slice(&be16(0));
    d.extend_from_slice(&be32(parent));
    d.extend_from_slice(&(units.len() as u16).to_be_bytes());
    for u in units {
        d.extend_from_slice(&u.to_be_bytes());
    }
    d
}

const TNODE: usize = 4096;

fn leaf_residue(records: &[Vec<u8>], residue: &[u8]) -> Vec<u8> {
    let mut n = vec![0u8; TNODE];
    n[8] = 0xFF;
    n[9] = 1;
    n[10..12].copy_from_slice(&(records.len() as u16).to_be_bytes());
    let mut pos = 14usize;
    let mut offs = Vec::new();
    for r in records {
        offs.push(pos as u16);
        n[pos..pos + r.len()].copy_from_slice(r);
        pos += r.len();
    }
    offs.push(pos as u16);
    if !residue.is_empty() {
        n[pos..pos + residue.len()].copy_from_slice(residue);
    }
    let table = TNODE - offs.len() * 2;
    for (i, o) in offs.iter().enumerate() {
        n[table + i * 2..table + i * 2 + 2].copy_from_slice(&o.to_be_bytes());
    }
    n
}

fn attr_key_rec(cnid: u32, start: u32, name: &str, data: &[u8]) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let klen = 12 + 2 * units.len() as u16;
    let mut r = Vec::new();
    r.extend_from_slice(&klen.to_be_bytes());
    r.extend_from_slice(&[0, 0]);
    r.extend_from_slice(&cnid.to_be_bytes());
    r.extend_from_slice(&start.to_be_bytes());
    r.extend_from_slice(&(units.len() as u16).to_be_bytes());
    for u in units {
        r.extend_from_slice(&u.to_be_bytes());
    }
    r.extend_from_slice(data);
    r
}

fn attr_inline(value: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&0x10u32.to_be_bytes());
    d.extend_from_slice(&0u32.to_be_bytes());
    d.extend_from_slice(&[0u8; 6]);
    d.extend_from_slice(&(value.len() as u16).to_be_bytes());
    d.extend_from_slice(value);
    d
}

fn file248f(
    cnid: u32,
    special: u32,
    fdt: u32,
    fdc: u32,
    extents: &[(u32, u32)],
    size: u64,
) -> Vec<u8> {
    let mut d = file248(cnid, extents, size);
    d[44..48].copy_from_slice(&be32(special));
    d[48..52].copy_from_slice(&be32(fdt));
    d[52..56].copy_from_slice(&be32(fdc));
    d
}

fn ext_rec(fork: u8, cnid: u32, start_block: u32, exts: &[(u32, u32)]) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(&10u16.to_be_bytes());
    r.push(fork);
    r.push(0);
    r.extend_from_slice(&cnid.to_be_bytes());
    r.extend_from_slice(&start_block.to_be_bytes());
    for i in 0..8 {
        let (s, c) = exts.get(i).copied().unwrap_or((0, 0));
        r.extend_from_slice(&s.to_be_bytes());
        r.extend_from_slice(&c.to_be_bytes());
    }
    r
}

fn decmpfs_val(t: u32, usize_: u64, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x636D7066u32.to_le_bytes()); // 'cmpf'
    v.extend_from_slice(&t.to_le_bytes());
    v.extend_from_slice(&usize_.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

/// 20 块 × 4096 的迷你 HFS+：VH@1024，alloc@4，cat@5（3 节点），attr@6，
/// 数据@10-14。
fn tiny_image() -> Vec<u8> {
    let mut img = vec![0u8; 24 * TB];
    let v = 1024usize;
    img[v..v + 2].copy_from_slice(&be16(0x482B));
    img[v + 2..v + 4].copy_from_slice(&be16(4));
    img[v + 40..v + 44].copy_from_slice(&be32(4096));
    img[v + 44..v + 48].copy_from_slice(&be32(24));
    img[v + 72..v + 80].copy_from_slice(&0xA5u64.to_be_bytes()); // encodings
    img[v + 80..v + 84].copy_from_slice(&be32(7)); // finder_info 非零
    img[v + 112..v + 192].copy_from_slice(&{
        let mut f = [0u8; 80];
        put_fork(&mut f, 0, 512, &[(4, 1)]);
        f
    });
    img[v + 272..v + 352].copy_from_slice(&{
        let mut f = [0u8; 80];
        put_fork(&mut f, 0, 12288, &[(5, 3)]);
        f
    });
    img[v + 192..v + 272].copy_from_slice(&{
        let mut f = [0u8; 80];
        put_fork(&mut f, 0, 8192, &[(10, 2)]);
        f
    });
    img[v + 352..v + 432].copy_from_slice(&{
        let mut f = [0u8; 80];
        put_fork(&mut f, 0, 8192, &[(8, 2)]);
        f
    });
    // alloc bitmap @block4：块 0-9 已分配。
    img[4 * TB] = 0xFF;
    img[4 * TB + 1] = 0xC0;
    // cat btree：node0 header（node_size 1024, total 3, first_leaf 1）。
    let mut h = header_node512(4096, 3);
    h[14 + 10..14 + 14].copy_from_slice(&1u32.to_be_bytes()); // first_leaf
    img[5 * TB..5 * TB + 512].copy_from_slice(&h);
    // node1 leaf：root thread + root folder + F.TXT + 孤儿 ORPH.TXT；
    // GONE.TXT 留在空闲区。
    let mut rec_thread = cat_key(2, "");
    rec_thread.extend_from_slice(&thread_body(1, "TinyVol"));
    let mut rec_root = cat_key(1, "");
    rec_root.extend_from_slice(&{
        let mut d = folder88(2);
        d[2..4].copy_from_slice(&0x00FFu16.to_be_bytes()); // flags
        d[41] = 0x20; // user_flags
        d[28..32].copy_from_slice(&be32(0xBEEF)); // backup_date
        d[48] = 0x11; // finder_info 非零
        d[80..84].copy_from_slice(&be32(7)); // text_encoding
        d
    });
    let mut rec_file = cat_key(2, "F.TXT");
    rec_file.extend_from_slice(&{
        let mut d = file248(20, &[(12, 1)], 9);
        d[2..4].copy_from_slice(&0x00FFu16.to_be_bytes()); // 全标志位 → meta 分支
        d[28..32].copy_from_slice(&be32(0xDEAD)); // backup_date
        d[56..58].copy_from_slice(&be16(0x1234)); // fd_flags
        d[52..56].copy_from_slice(&u32::from_be_bytes(*b"RCh ").to_be_bytes());
        d[41] = 0x20; // UF_COMPRESSED（它确实是压缩文件）
        d[64] = 0x22; // ext_info 非零
        d[80..84].copy_from_slice(&be32(9)); // text_encoding
        d[96..100].copy_from_slice(&be32(4096)); // data clump_size
        d
    });
    let mut rec_orph = cat_key(77, "ORPH.TXT");
    rec_orph.extend_from_slice(&file248f(70, 0, 0, 0xDEADBEEF, &[(14, 1)], 10));
    // symlink：slnk/rhap，目标在 data fork。
    let mut rec_link = cat_key(2, "LINK");
    rec_link.extend_from_slice(&file248f(
        46,
        0,
        u32::from_be_bytes(*b"slnk"),
        u32::from_be_bytes(*b"rhap"),
        &[(17, 1)],
        9,
    ));
    // hardlink 但 iNode 记录不存在 → meta-only 分支。
    let mut rec_hl = cat_key(2, "HL.TXT");
    rec_hl.extend_from_slice(&file248f(
        40,
        50,
        u32::from_be_bytes(*b"hlnk"),
        u32::from_be_bytes(*b"hfs+"),
        &[],
        0,
    ));
    // 坏 decmpfs：BADZ 的 zlib 流损坏（probe fail），BADZ2 连 cmpf 头都不是。
    let mut rec_badz = cat_key(2, "BADZ.BIN");
    rec_badz.extend_from_slice(&file248(55, &[(21, 1)], 5));
    let mut rec_badz2 = cat_key(2, "BADZ2.BIN");
    rec_badz2.extend_from_slice(&file248(56, &[(21, 1)], 5));
    // 畸形记录：key 合法但数据体太短 → index_catalog 的 continue 分支。
    let mut rec_trunc = cat_key(2, "TRUNC");
    rec_trunc.extend_from_slice(&be16(2)); // 只有记录类型字段
    // 与活键碰撞的残渣：residue_entry 的 live_keys 跳过分支。
    let mut residue = cat_key(2, "GONE.TXT");
    residue.extend_from_slice(&file248(30, &[(13, 1)], 100));
    let mut residue_live = cat_key(2, "F.TXT");
    residue_live.extend_from_slice(&file248(99, &[(13, 1)], 10));
    residue.extend_from_slice(&residue_live);
    let leaf = leaf_residue(
        &[
            rec_thread,
            rec_root,
            rec_file,
            rec_orph,
            rec_link,
            rec_hl,
            rec_badz,
            rec_badz2,
            rec_trunc,
        ],
        &residue,
    );
    img[5 * TB + TNODE..5 * TB + TNODE * 2].copy_from_slice(&leaf);
    // node2：死叶子（不在叶链），文件夹记录 + 空闲区里另一条文件残留。
    let mut dead_rec = cat_key(2, "OLDDIR");
    dead_rec.extend_from_slice(&folder88(63));
    let mut dead_res = cat_key(2, "GONE2.TXT");
    dead_res.extend_from_slice(&file248(64, &[(20, 1)], 50));
    let dead = leaf_residue(&[dead_rec], &dead_res);
    img[5 * TB + TNODE * 2..5 * TB + TNODE * 3].copy_from_slice(&dead);
    // attr btree @block8：header + leaf。
    let mut ah = header_node512(4096, 2);
    ah[14 + 10..14 + 14].copy_from_slice(&1u32.to_be_bytes());
    img[8 * TB..8 * TB + 512].copy_from_slice(&ah);
    // cnid20 的 decmpfs inline（zlib 类型 3）+ 续块记录 + ForkData + Extents。
    let z = miniz_oxide::deflate::compress_to_vec_zlib(b"DECMPFS-INLINE", 6);
    let dv = decmpfs_val(3, 14, &z);
    let a1 = attr_key_rec(20, 0, "com.apple.decmpfs", &attr_inline(&dv));
    let a2 = attr_key_rec(20, 1, "com.apple.decmpfs", &attr_inline(b"CONT"));
    let a3 = attr_key_rec(20, 0, "big.attr", &{
        let mut d = Vec::new();
        d.extend_from_slice(&0x20u32.to_be_bytes());
        d.extend_from_slice(&0u32.to_be_bytes());
        let mut f = [0u8; 80];
        put_fork(&mut f, 0, 8, &[(15, 1)]);
        d.extend_from_slice(&f);
        d
    });
    let a4 = attr_key_rec(20, 2, "cont.attr", &{
        let mut d = Vec::new();
        d.extend_from_slice(&0x30u32.to_be_bytes());
        d.extend_from_slice(&0u32.to_be_bytes());
        d.extend_from_slice(&16u32.to_be_bytes()); // start
        d.extend_from_slice(&1u32.to_be_bytes()); // count
        d
    });
    // BADZ.BIN 的"decmpfs"值是坏 zlib；BADZ2 连 cmpf 头都没有。
    let a5 = attr_key_rec(
        55,
        0,
        "com.apple.decmpfs",
        &attr_inline(&decmpfs_val(3, 5, &[0xDE, 0xAD, 0xBE, 0xEF])),
    );
    let a6 = attr_key_rec(56, 0, "com.apple.decmpfs", &{
        let mut d = Vec::new();
        d.extend_from_slice(&0x20u32.to_be_bytes());
        d.extend_from_slice(&0u32.to_be_bytes());
        let mut f = [0u8; 80];
        put_fork(&mut f, 0, 100, &[(999, 1)]);
        d.extend_from_slice(&f);
        d
    });
    let aleaf = leaf_residue(&[a1, a2, a3, a4, a5, a6, vec![0xAA; 10]], &[]);
    img[8 * TB + TNODE..8 * TB + TNODE * 2].copy_from_slice(&aleaf);
    // 数据。
    // ext btree @block9：F.TXT 的 data 溢出处 + cnid99 孤儿 rsrc 记录。
    let mut eh = header_node512(4096, 2);
    eh[14 + 10..14 + 14].copy_from_slice(&1u32.to_be_bytes());
    img[10 * TB..10 * TB + 512].copy_from_slice(&eh);
    let e1 = ext_rec(0, 20, 1, &[(19, 1)]);
    let e2 = ext_rec(0xFF, 99, 0, &[(18, 1)]);
    let eleaf = leaf_residue(&[e1, e2], &[]);
    img[10 * TB + TNODE..10 * TB + TNODE * 2].copy_from_slice(&eleaf);
    // 数据。
    img[12 * TB..12 * TB + 9].copy_from_slice(b"TINY-DATA");
    img[13 * TB..13 * TB + 12].copy_from_slice(b"GONE-SURVIVE");
    img[14 * TB..14 * TB + 10].copy_from_slice(b"ORPH-DATA!");
    img[15 * TB..15 * TB + 8].copy_from_slice(b"BIG-ATTR");
    img[16 * TB..16 * TB + 8].copy_from_slice(b"CONT-EXT");
    img[17 * TB..17 * TB + 9].copy_from_slice(b"LNK-TARGT");
    img[18 * TB..18 * TB + 9].copy_from_slice(b"RSRC-ORPH");
    img[19 * TB..19 * TB + 9].copy_from_slice(b"OVERFLOW!");
    img[20 * TB..20 * TB + 10].copy_from_slice(b"DEAD2-DATA");
    img
}

fn tiny_fs() -> super::fs::HfsFs {
    use std::sync::Arc;
    use sutram_fs::MountOptions;
    super::fs::HfsFs::mount(
        Arc::new(tiny_image()) as Arc<dyn sutram_io::ByteSource>,
        MountOptions::default(),
    )
    .unwrap()
}

#[test]
fn tiny_mount_walks_all_phases() {
    use sutram_fs::{FileSystem, FsEntryStatus};
    let fs = tiny_fs();
    let items: Vec<_> = fs.walk().collect();
    let entries: Vec<_> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"/"));
    assert!(names.contains(&"F.TXT"));
    // 空闲区残留 → deleted entry。
    let gone = entries.iter().find(|e| e.name == "GONE.TXT").unwrap();
    assert!(matches!(gone.status, FsEntryStatus::Deleted { .. }));
    // 卷标来自根线程。
    assert_eq!(fs.info().label.as_deref(), Some("TinyVol"));
}

#[test]
fn tiny_read_file_and_provenance() {
    use std::io::Read;
    use sutram_fs::FileSystem;
    let fs = tiny_fs();
    let e = fs
        .walk()
        .filter_map(|i| i.ok())
        .find(|e| e.name == "F.TXT")
        .unwrap();
    // decmpfs 条目：allocated_ranges = xattr 存储字节（attr 树内）。
    let (off, len) = e.allocated_ranges[0];
    assert!(off >= 8 * TB as u64 && off < (8 * TB + 8192) as u64 && len > 0);
    let mut buf = Vec::new();
    fs.read_file(&e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"DECMPFS-INLINE");
    // 目录条目 → InvalidInput。
    let root = fs
        .walk()
        .filter_map(|i| i.ok())
        .find(|e| e.path == "/")
        .unwrap();
    assert!(fs.read_file(&root).is_err());
}

#[test]
fn recovery_for_edge_states() {
    use super::vh::Extent;
    use sutram_fs::RecoveryState;
    let fs = tiny_fs();
    // size 0 → Intact。
    let (s, _, _) = fs.recovery_for(&[], 0);
    assert!(matches!(s, RecoveryState::Intact));
    // 无 extent 且 size>0 → Unrecoverable + note。
    let (s, _, notes) = fs.recovery_for(&[], 100);
    assert!(matches!(s, RecoveryState::Unrecoverable));
    assert!(!notes.is_empty());
    // 块被活文件占据（F.TXT 拥有 block10）→ 全损。
    let (s, ranges, _) = fs.recovery_for(&[Extent { start: 12, count: 1 }], 4096);
    assert!(matches!(s, RecoveryState::Unrecoverable));
    assert!(ranges.is_empty());
    // 块未被占据 → Intact。
    let (s, ranges, _) = fs.recovery_for(&[Extent { start: 13, count: 1 }], 100);
    assert!(matches!(s, RecoveryState::Intact));
    assert_eq!(ranges, vec![(13 * TB as u64, 4096)]);
    // 部分被占：block10 被 F.TXT 占据、block11 幸存 → PartiallyOverwritten。
    let (s, ranges, notes) = fs.recovery_for(
        &[Extent { start: 12, count: 1 }, Extent { start: 13, count: 1 }],
        8192,
    );
    assert!(matches!(s, RecoveryState::PartiallyOverwritten { .. }));
    assert_eq!(ranges, vec![(13 * TB as u64, 4096)]);
    assert!(!notes.is_empty());
}

#[test]
fn extents_to_ranges_edges() {
    use super::vh::Extent;
    let fs = tiny_fs();
    // count==0 的 extent 被跳过；logical 截断。
    let r = fs.extents_to_ranges(
        &[
            Extent { start: 0, count: 0 },
            Extent { start: 10, count: 2 },
        ],
        4096,
    );
    assert_eq!(r, vec![(10 * TB as u64, 4096)]);
    // logical=0 → 空。
    assert!(fs.extents_to_ranges(&[Extent { start: 10, count: 1 }], 0).is_empty());
}

#[test]
fn decmpfs_note_paths() {
    use sutram_fs::FileSystem;
    let fs = tiny_fs();
    let entries: Vec<_> = fs.walk().filter_map(|i| i.ok()).collect();
    // BADZ2：cmpf 头都不合法 → decmpfs-unparseable。
    let b2 = entries.iter().find(|e| e.name == "BADZ2.BIN").unwrap();
    assert_eq!(b2.meta["compressed"], "decmpfs-unparseable");
    assert!(b2.meta.contains_key("compression_note"));
    // BADZ：probe decompress 失败 → compression_note。
    let b = entries.iter().find(|e| e.name == "BADZ.BIN").unwrap();
    assert!(b.meta.contains_key("compression_note"));
}

#[test]
fn bitmap_and_unallocated() {
    use sutram_fs::FileSystem;
    let fs = tiny_fs();
    assert_eq!(fs.block_allocated(3), Some(true));
    assert_eq!(fs.block_allocated(15), Some(false));
    let free = fs.unallocated_ranges();
    // 块 10..19 空闲 → 至少一个区间覆盖 block15。
    let t = 15 * TB as u64;
    assert!(free.iter().any(|(o, l)| *o <= t && t < o + l));
}

#[test]
fn path_of_guards_cycles() {
    let mut fs = tiny_fs();
    assert_eq!(fs.path_of(2), Some("/".to_string()));
    assert_eq!(fs.path_of(999), None);
    // 循环：90→91→90 → None。
    fs.folders.insert(90, (91, "x".into()));
    fs.folders.insert(91, (90, "y".into()));
    assert_eq!(fs.path_of(90), None);
}

#[test]
fn fork_extents_merge_overflow() {
    use super::vh::Extent;
    let mut fs = tiny_fs();
    fs.overflow.insert(
        (20, 0u8),
        vec![(1u32, vec![Extent { start: 12, count: 1 }])],
    );
    let fork = ForkData::parse(&{
        let mut f = [0u8; 80];
        put_fork(&mut f, 0, 8192, &[(10, 1)]);
        f
    }, 0)
    .unwrap();
    let exts = fs.fork_extents(&fork, 20, 0);
    assert_eq!(exts.len(), 2);
    assert_eq!(exts[1].start, 12);
}

#[test]
fn magic_for_early_exits() {
    use sutram_fs::{EntryKind, FsEntry, FsEntryStatus};
    let fs = tiny_fs();
    let mut e = FsEntry {
        path: "/x".into(),
        name: "x".into(),
        entry_id: 0,
        kind: EntryKind::File,
        size: 0,
        disk_offset: 0,
        allocated_ranges: vec![],
        timestamps: Default::default(),
        status: FsEntryStatus::Live,
        meta: Default::default(),
        magic: None,
    };
    assert!(fs.magic_for(&e).is_none()); // size 0
    e.size = 10;
    e.kind = EntryKind::Directory;
    assert!(fs.magic_for(&e).is_none()); // not a file
}

#[test]
fn tiny_decmpfs_inline_zlib() {
    use std::io::Read;
    use sutram_fs::FileSystem;
    let fs = tiny_fs();
    let e = fs
        .walk()
        .filter_map(|i| i.ok())
        .find(|e| e.name == "F.TXT")
        .unwrap();
    assert_eq!(e.meta["compressed"], "decmpfs");
    assert_eq!(e.meta["decmpfs_type"], "3");
    assert_eq!(e.meta["decmpfs_codec"], "zlib-inline");
    assert_eq!(e.size, 14);
    let mut buf = Vec::new();
    fs.read_file(&e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"DECMPFS-INLINE");
}

#[test]
fn tiny_orphan_live_and_dead_node() {
    use sutram_fs::{EntryKind, FileSystem};
    let fs = tiny_fs();
    let entries: Vec<_> = fs.walk().filter_map(|i| i.ok()).collect();
    // 父链断裂的 live 记录 → /$ORPHANED/。
    let o = entries.iter().find(|e| e.name == "ORPH.TXT").unwrap();
    assert!(o.path.starts_with("/$ORPHANED/"));
    assert_eq!(o.meta["orphan"], "true");
    // 死节点中的文件夹 + 文件残留（死节点空闲区也要嗅探）。
    let d = entries.iter().find(|e| e.name == "OLDDIR").unwrap();
    assert_eq!(d.kind, EntryKind::Directory);
    assert_eq!(d.meta["residue"], "dead_node");
    let d2 = entries.iter().find(|e| e.name == "GONE2.TXT").unwrap();
    assert_eq!(d2.kind, EntryKind::File);
    assert_eq!(d2.meta["residue"], "dead_node_free_space");
}

#[test]
fn tiny_symlink_and_hardlink() {
    use sutram_fs::FileSystem;
    let fs = tiny_fs();
    let entries: Vec<_> = fs.walk().filter_map(|i| i.ok()).collect();
    let l = entries.iter().find(|e| e.name == "LINK").unwrap();
    assert_eq!(l.meta["symlink_target"], "LNK-TARGT");
    let h = entries.iter().find(|e| e.name == "HL.TXT").unwrap();
    assert_eq!(h.meta["hardlink"], "true");
    assert_eq!(h.meta["inode_ref"], "iNode50");
}

#[test]
fn tiny_orphan_extents_rsrc_fork() {
    use sutram_fs::FileSystem;
    let fs = tiny_fs();
    let entries: Vec<_> = fs.walk().filter_map(|i| i.ok()).collect();
    // cnid99 的 extents-overflow rsrc 记录 → orphan_extent 条目，rsrc 标记。
    let o = entries
        .iter()
        .find(|e| e.name == "extents_99")
        .expect("orphan extent not emitted");
    assert!(o.path.starts_with("/$ORPHANED/0x63/"));
    assert_eq!(o.meta["cnid"], "99");
    assert_eq!(o.meta["fork"], "rsrc");
    assert_eq!(o.allocated_ranges, vec![(18 * TB as u64, 4096)]);
}

#[test]
fn tiny_lenient_replays_mount_note() {
    // 损坏 attr 树头 → mount 记录 note，attr=None → lenient walk 首项 Err 后继续。
    use sutram_fs::{FileSystem, MountOptions};
    let mut img = tiny_image();
    img[8 * TB + 8] = 0xFF; // attr header kind 非法
    use std::sync::Arc;
    let fs = super::fs::HfsFs::mount(
        Arc::new(img) as Arc<dyn sutram_io::ByteSource>,
        MountOptions::default(),
    )
    .unwrap();
    let items: Vec<_> = fs.walk().collect();
    assert!(items[0].is_err());
    assert!(items.iter().any(|i| i.is_ok()));
}

#[test]
fn tiny_hx_signature_and_no_root() {
    // HFSX 签名也能挂载 → info() 的 HX 分支。
    use sutram_fs::{FileSystem, MountOptions};
    let mut img = tiny_image();
    img[1024..1026].copy_from_slice(&be16(0x4858)); // 'HX'
    use std::sync::Arc;
    let fs = super::fs::HfsFs::mount(
        Arc::new(img) as Arc<dyn sutram_io::ByteSource>,
        MountOptions::default(),
    )
    .unwrap();
    assert_eq!(fs.info().meta["signature"], "HX");
    // 无根文件夹记录 → "/" 合成条目（disk_off=1024）。
    let mut img2 = tiny_image();
    // 抹掉 leaf 里的根文件夹记录：改其记录体 cnid → 合成根。
    let leaf_off = 5 * TB + TNODE;
    let num_recs = u16::from_be_bytes([img2[leaf_off + 10], img2[leaf_off + 11]]) as usize;
    let table = leaf_off + TNODE - 2 * (num_recs + 1);
    // 第 2 条记录（索引 1）是根文件夹；改记录体 cnid @key(8)+8=16。
    let rec2_off = leaf_off
        + u16::from_be_bytes([img2[table + 2], img2[table + 3]]) as usize;
    img2[rec2_off + 16..rec2_off + 20].copy_from_slice(&99u32.to_be_bytes());
    let fs2 = super::fs::HfsFs::mount(
        Arc::new(img2) as Arc<dyn sutram_io::ByteSource>,
        MountOptions::default(),
    )
    .unwrap();
    let root = fs2.walk().next().unwrap().unwrap();
    assert_eq!(root.disk_offset, 1024); // 合成根
}

#[test]
fn magic_for_read_failure() {
    use sutram_fs::{EntryKind, FsEntry, FsEntryStatus};
    let fs = tiny_fs();
    let e = FsEntry {
        path: "/x".into(),
        name: "x".into(),
        entry_id: 0,
        kind: EntryKind::File,
        size: 100,
        disk_offset: 0,
        allocated_ranges: vec![(999 * TB as u64, 100)],
        timestamps: Default::default(),
        status: FsEntryStatus::Live,
        meta: Default::default(),
        magic: None,
    };
    assert!(fs.magic_for(&e).is_none());
}

#[test]
fn parser_name_and_detect() {
    use sutram_fs::FsParser;
    let p = super::fs::HfsParser;
    assert_eq!(p.name(), "hfs");
    let img = tiny_image();
    assert_eq!(
        p.detect(&img),
        sutram_fs::DetectConfidence::Certain
    );
}

#[test]
fn tiny_xattr_pseudo_entries() {
    use sutram_fs::FileSystem;
    let fs = tiny_fs();
    let names: Vec<String> = fs
        .walk()
        .filter_map(|i| i.ok())
        .map(|e| e.name)
        .collect();
    assert!(names.iter().any(|n| n.contains("xattr:com.apple.decmpfs")));
    assert!(names.iter().any(|n| n.contains("xattr:big.attr")));
    assert!(names.iter().any(|n| n.contains("xattr:cont.attr")));
    // 续块记录在 meta 中标记。
    let cont = fs
        .walk()
        .filter_map(|i| i.ok())
        .find(|e| e.name.contains("xattr:com.apple.decmpfs") && e.meta.contains_key("xattr_continuation"));
    assert!(cont.is_some());
}
