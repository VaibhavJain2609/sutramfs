use std::sync::Arc;

use crate::*;

fn vec_src(v: Vec<u8>) -> Arc<dyn ByteSource> {
    Arc::new(v)
}

#[test]
fn slice_source_reads_and_clamps() {
    let data: &[u8] = &[1, 2, 3, 4, 5];
    assert_eq!(data.len(), 5);
    let mut buf = [0u8; 4];
    assert_eq!(data.read_at(1, &mut buf).unwrap(), 4);
    assert_eq!(buf, [2, 3, 4, 5]);
    // short read at EOF
    assert_eq!(data.read_at(4, &mut buf).unwrap(), 1);
    assert_eq!(data.read_at(10, &mut buf).unwrap(), 0);
    // read_slice clamps, never errors past EOF
    assert_eq!(data.read_slice(3, 100).unwrap(), vec![4, 5]);
    assert!(data.read_slice(99, 4).unwrap().is_empty());
}

#[test]
fn reader_at_streams() {
    use std::io::Read;
    let data: Vec<u8> = (0..=255).collect();
    let mut r = data.reader_at(10);
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    assert_eq!(out.len(), 246);
    assert_eq!(out[0], 10);
}

#[test]
fn offset_view_windows() {
    let backing: Vec<u8> = (0..100).collect();
    let view = OffsetView::new(vec_src(backing), 10, 20).unwrap();
    assert_eq!(view.len(), 20);
    assert_eq!(view.base_offset(), 10);
    assert_eq!(view.read_slice(0, 4).unwrap(), vec![10, 11, 12, 13]);
    // cannot reach outside the window
    assert_eq!(view.read_slice(18, 10).unwrap(), vec![28, 29]);
    assert!(view.read_slice(20, 1).unwrap().is_empty());
    // window starting past EOF is an error
    assert!(OffsetView::new(view.inner().clone(), 1000, 10).is_err());
}

#[test]
fn concat_source_glues() {
    let a: Arc<dyn ByteSource> = Arc::new(b"hello".to_vec());
    let b: Arc<dyn ByteSource> = Arc::new(b"world!!".to_vec());
    let c = ConcatSource::new(vec![a, b]);
    assert_eq!(c.len(), 12);
    assert_eq!(c.read_slice(0, 12).unwrap(), b"helloworld!!");
    // read across the seam
    assert_eq!(c.read_slice(3, 5).unwrap(), b"lowor");
}

#[test]
fn sparse_file_extents() {
    let backing: Arc<dyn ByteSource> = Arc::new(b"ABCDEFGH".to_vec());
    let s = SparseFile::new(
        20,
        vec![
            SparseExtent {
                out_offset: 0,
                len: 4,
                kind: SparseKind::Data {
                    source: backing.clone(),
                    src_offset: 0,
                },
            },
            SparseExtent {
                out_offset: 8,
                len: 4,
                kind: SparseKind::Fill(0x11223344),
            },
            SparseExtent {
                out_offset: 16,
                len: 4,
                kind: SparseKind::Data {
                    source: backing,
                    src_offset: 4,
                },
            },
        ],
    )
    .unwrap();
    // holes read as zero; extents map correctly
    assert_eq!(s.read_slice(0, 20).unwrap()[..], *b"ABCD\0\0\0\0\x44\x33\x22\x11\0\0\0\0EFGH");
    // overlap is rejected
    assert!(SparseFile::new(
        8,
        vec![
            SparseExtent {
                out_offset: 0,
                len: 6,
                kind: SparseKind::Zero,
            },
            SparseExtent {
                out_offset: 4,
                len: 4,
                kind: SparseKind::Zero,
            },
        ],
    )
    .is_err());
}

fn le16(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

#[test]
fn android_sparse_decode() {
    // Build a minimal Android sparse image: 4KiB blocks, RAW + FILL + DONT_CARE.
    let blk = 4096u32;
    let mut img = Vec::new();
    img.extend_from_slice(&le32(0xED26_FF3A)); // magic
    img.extend_from_slice(&le16(1)); // major
    img.extend_from_slice(&le16(0)); // minor
    img.extend_from_slice(&le16(28)); // file hdr
    img.extend_from_slice(&le16(12)); // chunk hdr
    img.extend_from_slice(&le32(blk));
    img.extend_from_slice(&le32(3)); // total blocks
    img.extend_from_slice(&le32(3)); // total chunks
    img.extend_from_slice(&le32(0)); // crc
    // RAW: 1 block
    img.extend_from_slice(&le16(0xCAC1));
    img.extend_from_slice(&le16(0));
    img.extend_from_slice(&le32(1));
    img.extend_from_slice(&le32(12 + blk));
    img.extend_from_slice(&vec![0xAB; blk as usize]);
    // FILL: 1 block of 0xDEADBEEF
    img.extend_from_slice(&le16(0xCAC2));
    img.extend_from_slice(&le16(0));
    img.extend_from_slice(&le32(1));
    img.extend_from_slice(&le32(12 + 4));
    img.extend_from_slice(&le32(0xDEADBEEF));
    // DONT_CARE: 1 block
    img.extend_from_slice(&le16(0xCAC3));
    img.extend_from_slice(&le16(0));
    img.extend_from_slice(&le32(1));
    img.extend_from_slice(&le32(12));

    let s = SparseFile::from_android_sparse(vec_src(img)).unwrap();
    assert_eq!(s.len(), 3 * blk as u64);
    let out = s.read_slice(0, s.len() as usize).unwrap();
    assert!(out[..blk as usize].iter().all(|&b| b == 0xAB));
    assert_eq!(out[blk as usize..blk as usize + 4], [0xEF, 0xBE, 0xAD, 0xDE]);
    assert!(out[2 * blk as usize..].iter().all(|&b| b == 0));
}

#[test]
fn mbr_partitions() {
    let mut disk = vec![0u8; 512 * 4];
    disk[0x1FE] = 0x55;
    disk[0x1FF] = 0xAA;
    // entry 0: type 0x0B FAT32, bootable, LBA 1, 2 sectors
    disk[0x1BE] = 0x80;
    disk[0x1BE + 4] = 0x0B;
    disk[0x1BE + 8..0x1BE + 12].copy_from_slice(&le32(1));
    disk[0x1BE + 12..0x1BE + 16].copy_from_slice(&le32(2));
    let parts = partitions(&disk.as_slice()).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].ptype, Some(0x0B));
    assert_eq!(parts[0].offset, 512);
    assert_eq!(parts[0].size, 1024);
    assert!(parts[0].bootable);
    assert_eq!(parts[0].table, TableKind::Mbr);

    // open_partitions gives mounted views
    let src = vec_src(disk);
    let mounted = open_partitions(src).unwrap();
    assert_eq!(mounted.len(), 1);
    assert_eq!(mounted[0].source.len(), 1024);
}

#[test]
fn gpt_partitions() {
    let mut disk = vec![0u8; 512 * 64];
    // protective MBR
    disk[0x1FE] = 0x55;
    disk[0x1FF] = 0xAA;
    disk[0x1BE + 4] = 0xEE;
    disk[0x1BE + 8..0x1BE + 12].copy_from_slice(&le32(1));
    disk[0x1BE + 12..0x1BE + 16].copy_from_slice(&le32(63));
    // GPT header at LBA 1
    let h = 512;
    disk[h..h + 8].copy_from_slice(b"EFI PART");
    disk[h + 72..h + 80].copy_from_slice(&(2u64).to_le_bytes()); // entries lba
    disk[h + 80..h + 84].copy_from_slice(&le32(128)); // count
    disk[h + 84..h + 88].copy_from_slice(&le32(128)); // entry size
    // entry 0 at LBA 2: type guid 16B nonzero, first=4 last=7, name "root"
    let e = 1024;
    disk[e] = 1; // nonzero type guid
    disk[e + 32..e + 40].copy_from_slice(&(4u64).to_le_bytes());
    disk[e + 40..e + 48].copy_from_slice(&(7u64).to_le_bytes());
    let name = "root".encode_utf16().collect::<Vec<u16>>();
    for (i, u) in name.iter().enumerate() {
        disk[e + 56 + i * 2..e + 58 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    let parts = partitions(&disk.as_slice()).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].table, TableKind::Gpt);
    assert_eq!(parts[0].offset, 4 * 512);
    assert_eq!(parts[0].size, 4 * 512);
    assert_eq!(parts[0].label.as_deref(), Some("root"));
    assert!(parts[0].type_guid.is_some());
}

#[test]
fn le_helpers_never_panic() {
    let buf = [0x01, 0x02, 0x03];
    assert_eq!(le::u16(&buf, 0), Some(0x0201));
    assert_eq!(le::u32(&buf, 0), None); // short buffer → None, no panic
    assert_eq!(le::u8(&buf, 5), None);
    assert_eq!(le::u32(&buf, usize::MAX - 1), None); // overflow-safe
}

#[test]
fn gpt_entry_lba_overflow_is_skipped() {
    // Regression: a corrupt GPT entry whose LBA*sector math overflows u64
    // must be skipped, not wrap and alias low offsets of the disk.
    let mut disk = vec![0u8; 512 * 64];
    disk[0x1FE] = 0x55;
    disk[0x1FF] = 0xAA;
    disk[0x1BE + 4] = 0xEE;
    let h = 512;
    disk[h..h + 8].copy_from_slice(b"EFI PART");
    disk[h + 72..h + 80].copy_from_slice(&(2u64).to_le_bytes());
    disk[h + 80..h + 84].copy_from_slice(&le32(128));
    disk[h + 84..h + 88].copy_from_slice(&le32(128));
    // entry 0: absurd LBAs that overflow when scaled by 512
    let e0 = 1024;
    disk[e0] = 0xAA; // nonzero type guid
    disk[e0 + 32..e0 + 40].copy_from_slice(&u64::MAX.to_le_bytes());
    disk[e0 + 40..e0 + 48].copy_from_slice(&u64::MAX.to_le_bytes());
    // entry 1: sane
    let e1 = 1024 + 128;
    disk[e1] = 0xBB;
    disk[e1 + 32..e1 + 40].copy_from_slice(&(4u64).to_le_bytes());
    disk[e1 + 40..e1 + 48].copy_from_slice(&(9u64).to_le_bytes());
    let parts = partitions(&disk.as_slice()).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].index, 1);
    assert_eq!(parts[0].offset, 4 * 512);
    assert_eq!(parts[0].size, 6 * 512);
}

#[test]
fn gpt_rejects_implausible_entry_geometry() {
    let mut disk = vec![0u8; 512 * 64];
    disk[0x1FE] = 0x55;
    disk[0x1FF] = 0xAA;
    disk[0x1BE + 4] = 0xEE;
    disk[0x1BE + 8..0x1BE + 12].copy_from_slice(&le32(1));
    disk[0x1BE + 12..0x1BE + 16].copy_from_slice(&le32(63));
    let h = 512;
    disk[h..h + 8].copy_from_slice(b"EFI PART");
    disk[h + 72..h + 80].copy_from_slice(&(2u64).to_le_bytes());
    disk[h + 80..h + 84].copy_from_slice(&le32(128));
    disk[h + 84..h + 88].copy_from_slice(&le32(64)); // entry size too small
    // Protective MBR but broken GPT → falls back to the MBR view
    // (the protective entry itself is reported).
    let parts = partitions(&disk.as_slice()).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].ptype, Some(0xEE));
    assert_eq!(parts[0].table, TableKind::Mbr);
}

#[test]
fn android_sparse_bad_total_sz_is_corrupt() {
    // Regression: total_sz < chunk header size used to silently continue
    // with the cursor re-reading earlier bytes as later chunks.
    let blk = 4096u32;
    let mut img = Vec::new();
    img.extend_from_slice(&le32(0xED26_FF3A));
    img.extend_from_slice(&le16(1));
    img.extend_from_slice(&le16(0));
    img.extend_from_slice(&le16(28));
    img.extend_from_slice(&le16(12));
    img.extend_from_slice(&le32(blk));
    img.extend_from_slice(&le32(1));
    img.extend_from_slice(&le32(1));
    img.extend_from_slice(&le32(0));
    img.extend_from_slice(&le16(0xCAC1)); // RAW
    img.extend_from_slice(&le16(0));
    img.extend_from_slice(&le32(1));
    img.extend_from_slice(&le32(4)); // total_sz < header → corrupt
    let res = SparseFile::from_android_sparse(vec_src(img));
    assert!(matches!(res, Err(Error::Corrupt { .. })));
}

#[test]
fn android_sparse_truncated_chunk_header() {
    let blk = 4096u32;
    let mut img = Vec::new();
    img.extend_from_slice(&le32(0xED26_FF3A));
    img.extend_from_slice(&le16(1));
    img.extend_from_slice(&le16(0));
    img.extend_from_slice(&le16(28));
    img.extend_from_slice(&le16(12));
    img.extend_from_slice(&le32(blk));
    img.extend_from_slice(&le32(1));
    img.extend_from_slice(&le32(1));
    img.extend_from_slice(&le32(0));
    img.extend_from_slice(&le16(0xCAC1)); // half a chunk header only
    let res = SparseFile::from_android_sparse(vec_src(img));
    assert!(matches!(res, Err(Error::Truncated { .. })));
}

#[test]
fn android_sparse_short_raw_payload_zero_fills() {
    // Regression: a RAW chunk whose declared payload is shorter than its
    // output extent must zero-fill the tail, not leak the next chunk's
    // bytes into the logical image.
    let blk = 4096u32;
    let mut img = Vec::new();
    img.extend_from_slice(&le32(0xED26_FF3A));
    img.extend_from_slice(&le16(1));
    img.extend_from_slice(&le16(0));
    img.extend_from_slice(&le16(28));
    img.extend_from_slice(&le16(12));
    img.extend_from_slice(&le32(blk));
    img.extend_from_slice(&le32(2));
    img.extend_from_slice(&le32(2));
    img.extend_from_slice(&le32(0));
    // RAW chunk claiming 1 block out but only 16 bytes of payload.
    img.extend_from_slice(&le16(0xCAC1));
    img.extend_from_slice(&le16(0));
    img.extend_from_slice(&le32(1));
    img.extend_from_slice(&le32(12 + 16));
    img.extend_from_slice(&[0xCC; 16]);
    // DONT_CARE for the second block.
    img.extend_from_slice(&le16(0xCAC3));
    img.extend_from_slice(&le16(0));
    img.extend_from_slice(&le32(1));
    img.extend_from_slice(&le32(12));
    let s = SparseFile::from_android_sparse(vec_src(img)).unwrap();
    let out = s.read_slice(0, blk as usize).unwrap();
    assert_eq!(&out[..16], &[0xCC; 16]);
    // Tail of the block is zeros — NOT the bytes of the next chunk header.
    assert!(out[16..].iter().all(|&b| b == 0));
}

#[test]
fn sparse_file_zero_and_fill_only() {
    // Extent-less tail reads as zeros; Fill pattern is offset-aligned.
    let s = SparseFile::new(
        16,
        vec![SparseExtent {
            out_offset: 4,
            len: 4,
            kind: SparseKind::Fill(0x01020304),
        }],
    )
    .unwrap();
    let out = s.read_slice(0, 16).unwrap();
    assert_eq!(&out[..4], &[0; 4]);
    assert_eq!(&out[4..8], &[0x04, 0x03, 0x02, 0x01]);
    assert!(out[8..].iter().all(|&b| b == 0));
    // Fill pattern must phase correctly when read starts mid-extent.
    let mid = s.read_slice(6, 2).unwrap();
    assert_eq!(mid, [0x02, 0x01]);
}

#[test]
fn concat_source_past_end() {
    let a: Arc<dyn ByteSource> = Arc::new(vec![1u8; 4]);
    let c = ConcatSource::new(vec![a]);
    assert_eq!(c.read_slice(4, 8).unwrap().len(), 0);
    assert_eq!(c.read_slice(0, 0).unwrap().len(), 0);
}

#[test]
fn le_be_helpers_and_ascii_uuid() {
    let buf = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
    assert_eq!(le::u16_be(&buf, 0), Some(0x1234));
    assert_eq!(le::u32_be(&buf, 0), Some(0x12345678));
    assert_eq!(le::u64_be(&buf, 0), Some(0x123456789ABCDEF0));
    assert_eq!(le::u64(&buf, 0), Some(0xF0DEBC9A78563412));
    assert_eq!(le::u64_be(&buf, 4), None);
    // GPT-style mixed-endian GUID
    let mut g = [0u8; 20];
    g[4..20].copy_from_slice(&[
        0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
        0xEE, 0xFF,
    ]);
    let s = le::uuid_le(&g, 4).unwrap();
    assert_eq!(s, "00112233-4455-7766-8899-aabbccddeeff");
    assert_eq!(le::uuid_le(&g, 8), None); // short
    // ascii: NUL- and space-terminated
    let name = *b"VOL   \0\xFF";
    assert_eq!(le::ascii(&name, 0, 8), Some("VOL".to_string()));
    let nul = *b"AB\0CD";
    assert_eq!(le::ascii(&nul, 0, 5), Some("AB".to_string()));
    assert_eq!(le::ascii(&nul, 0, 99), None);
}

#[test]
fn file_backed_sources() {
    // File (positioned reads) and FileSource (mutex cursor) over a real file.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let f = std::fs::File::open(&path).unwrap();
    let file_len = f.len();
    assert!(file_len > 4);
    let mut buf = [0u8; 4];
    assert_eq!(f.read_at(0, &mut buf).unwrap(), 4);
    assert_eq!(&buf, b"[pac");

    let fs = FileSource::open(&path).unwrap();
    assert_eq!(fs.len(), file_len);
    assert_eq!(fs.read_slice(0, 4).unwrap(), b"[pac");
    assert_eq!(fs.read_slice(file_len, 8).unwrap().len(), 0);

    let f2 = std::fs::File::open(&path).unwrap();
    let fs2 = FileSource::new(f2).unwrap();
    assert_eq!(fs2.read_slice(0, 4).unwrap(), b"[pac");
}

#[test]
fn read_exact_at_eof_and_errors() {
    let data: &[u8] = &[1, 2, 3];
    let mut buf = [0u8; 8];
    let e = data.read_exact_at(0, &mut buf).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
    // exact fill succeeds
    let mut small = [0u8; 3];
    data.read_exact_at(0, &mut small).unwrap();
    assert_eq!(small, [1, 2, 3]);
    // empty buffer is trivially Ok
    data.read_exact_at(0, &mut []).unwrap();
}

#[test]
fn reader_position_and_box_arc() {
    use std::io::Read;
    let data: Box<dyn ByteSource> = Box::new(vec![9u8, 8, 7, 6]);
    assert_eq!(data.len(), 4);
    let arc = into_arc(vec![1u8, 2, 3]);
    assert_eq!(arc.len(), 3);
    assert!(!arc.is_empty());
    let mut r = SourceReader::new(&arc, 1);
    assert_eq!(r.position(), 1);
    let mut buf = [0u8; 2];
    assert_eq!(r.read(&mut buf).unwrap(), 2);
    assert_eq!(r.position(), 3);
}

#[test]
fn error_display_and_source() {
    let io_err = Error::Io(std::io::Error::other("x"));
    assert!(io_err.to_string().contains("i/o error"));
    assert!(std::error::Error::source(&io_err).is_some());
    let c = Error::corrupt(0x10, "bad");
    assert!(c.to_string().contains("0x10"));
    let u = Error::unsupported("ewf");
    assert!(u.to_string().contains("ewf"));
    let t = Error::Truncated {
        offset: 4,
        requested: 8,
        available: 2,
    };
    let s = t.to_string();
    assert!(s.contains("truncated"));
    assert!(std::error::Error::source(&t).is_none());
    // From<io::Error>
    let e: Error = std::io::Error::other("y").into();
    assert!(matches!(e, Error::Io(_)));
}

#[test]
fn ewf_stub_reports_unsupported() {
    let mut e01 = vec![0u8; 512];
    e01[..ewf::EWF_SIGNATURE.len()].copy_from_slice(ewf::EWF_SIGNATURE);
    assert!(ewf::EwfSource::is_ewf(&e01.as_slice()));
    let res = ewf::EwfSource::open(vec![vec_src(e01)]);
    assert!(matches!(res, Err(Error::Unsupported { .. })));
    // non-EWF input → corrupt, not unsupported
    let res = ewf::EwfSource::open(vec![vec_src(vec![0u8; 64])]);
    assert!(matches!(res, Err(Error::Corrupt { .. })));
}
