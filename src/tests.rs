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
fn ewf_signature_without_volume_is_corrupt() {
    // Bare EVF signature but no section chain → parses, then fails on the
    // missing volume/disk geometry.
    let mut e01 = vec![0u8; 512];
    e01[..ewf::EWF_SIGNATURE.len()].copy_from_slice(ewf::EWF_SIGNATURE);
    e01[8] = 0x01;
    e01[9..11].copy_from_slice(&1u16.to_le_bytes());
    assert!(ewf::EwfSource::is_ewf(&e01.as_slice()));
    let res = ewf::EwfSource::open(vec![vec_src(e01)]);
    assert!(matches!(res, Err(Error::Corrupt { .. })));
    // non-EWF input → corrupt, not unsupported
    let res = ewf::EwfSource::open(vec![vec_src(vec![0u8; 64])]);
    assert!(matches!(res, Err(Error::Corrupt { .. })));
    // two garbage segments → corrupt on segment 1 (multi-segment parses
    // each supplied source, so the bad signature is reported)
    let res = ewf::EwfSource::open(vec![vec_src(vec![0u8; 64]), vec_src(vec![0u8; 64])]);
    match res {
        Err(Error::Corrupt { msg, .. }) => assert!(msg.contains("segment 1")),
        Err(e) => panic!("expected Corrupt naming segment 1, got {e:?}"),
        Ok(_) => panic!("expected Corrupt naming segment 1, got an opened image"),
    }
}

// ---------------------------------------------------------------------------
// EWF (E01) synthetic-image corpus
// ---------------------------------------------------------------------------

/// Byte-at-a-time EWF segment writer: appends 76-byte section descriptors
/// and data, patching each descriptor's `next` offset and Adler-32 checksum
/// as the chain grows.
struct E01 {
    img: Vec<u8>,
    last_desc: Option<usize>,
}

impl E01 {
    fn new() -> Self {
        Self::new_seg(1)
    }

    fn new_seg(segment_number: u16) -> Self {
        let mut img = Vec::new();
        img.extend_from_slice(ewf::EWF_SIGNATURE);
        img.push(0x01); // start of fields
        img.extend_from_slice(&segment_number.to_le_bytes());
        img.extend_from_slice(&0u16.to_le_bytes()); // end of fields
        Self {
            img,
            last_desc: None,
        }
    }

    /// Append `name` section carrying `data`; returns the descriptor offset.
    fn section(&mut self, name: &str, data: &[u8]) -> usize {
        let off = self.img.len();
        if let Some(p) = self.last_desc {
            self.set_next(p, off as u64);
        }
        let mut d = vec![0u8; 76];
        let n = name.len().min(16);
        d[..n].copy_from_slice(&name.as_bytes()[..n]);
        d[24..32].copy_from_slice(&(data.len() as u64).to_le_bytes());
        self.img.extend_from_slice(&d);
        self.img.extend_from_slice(data);
        self.last_desc = Some(off);
        off
    }

    /// Write `next` into a descriptor and refresh its checksum.
    fn set_next(&mut self, desc: usize, next: u64) {
        self.img[desc + 16..desc + 24].copy_from_slice(&next.to_le_bytes());
        let sum = ewf::adler32(&self.img[desc..desc + 72]);
        self.img[desc + 72..desc + 76].copy_from_slice(&sum.to_le_bytes());
    }

    /// Terminate the chain: the last descriptor's `next` points at itself.
    fn finish(mut self) -> Vec<u8> {
        if let Some(p) = self.last_desc {
            let self_off = p as u64;
            self.set_next(p, self_off);
        }
        self.img
    }
}

const E01_BPS: u32 = 512;
const E01_SPC: u32 = 64;
const E01_CS: usize = (E01_BPS * E01_SPC) as usize; // 32 KiB chunks

/// 1052-byte EnCase-style `volume`/`data` section payload.
fn e01_volume(chunk_count: u32, sector_count: u64) -> Vec<u8> {
    let mut v = vec![0u8; 1052];
    v[0] = 0x01; // fixed media
    v[4..8].copy_from_slice(&chunk_count.to_le_bytes());
    v[8..12].copy_from_slice(&E01_SPC.to_le_bytes());
    v[12..16].copy_from_slice(&E01_BPS.to_le_bytes());
    v[16..24].copy_from_slice(&sector_count.to_le_bytes());
    v[36] = 0x03; // media flags: image + physical
    v[52] = 0x01; // compression level: good
    v[56..60].copy_from_slice(&64u32.to_le_bytes()); // error granularity
    // set-identifier GUID (16 nonzero bytes)
    for (i, b) in v[64..80].iter_mut().enumerate() {
        *b = 0xA0 + i as u8;
    }
    let sum = ewf::adler32(&v[..1048]);
    v[1048..1052].copy_from_slice(&sum.to_le_bytes());
    v
}

/// `table`/`table2` payload: 24-byte header + entries + 4-byte footer.
fn e01_table(entries: &[u32]) -> Vec<u8> {
    let mut t = vec![0u8; 24 + entries.len() * 4 + 4];
    t[0..4].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    // base offset @8 stays 0 (pre-EnCase-6 style absolute entries)
    for (i, e) in entries.iter().enumerate() {
        t[24 + i * 4..28 + i * 4].copy_from_slice(&e.to_le_bytes());
    }
    let h = ewf::adler32(&t[..20]);
    t[20..24].copy_from_slice(&h.to_le_bytes());
    let f = ewf::adler32(&t[24..24 + entries.len() * 4]);
    let n = t.len();
    t[n - 4..].copy_from_slice(&f.to_le_bytes());
    t
}

/// `hash` section: MD5 @0..16, 16 unknown bytes, checksum @32.
fn e01_hash(md5: &[u8; 16]) -> Vec<u8> {
    let mut h = vec![0u8; 36];
    h[..16].copy_from_slice(md5);
    let sum = ewf::adler32(&h[..32]);
    h[32..36].copy_from_slice(&sum.to_le_bytes());
    h
}

/// `digest` section: MD5 @0, SHA-1 @16, padding, checksum @76.
fn e01_digest(md5: &[u8; 16], sha1: &[u8; 20]) -> Vec<u8> {
    let mut d = vec![0u8; 80];
    d[..16].copy_from_slice(md5);
    d[16..36].copy_from_slice(sha1);
    let sum = ewf::adler32(&d[..76]);
    d[76..80].copy_from_slice(&sum.to_le_bytes());
    d
}

/// `error2` section: 520-byte header + 8-byte entries + footer.
fn e01_error2(ranges: &[(u32, u32)]) -> Vec<u8> {
    let mut e = vec![0u8; 520 + ranges.len() * 8 + 4];
    e[0..4].copy_from_slice(&(ranges.len() as u32).to_le_bytes());
    let h = ewf::adler32(&e[..516]);
    e[516..520].copy_from_slice(&h.to_le_bytes());
    for (i, &(start, count)) in ranges.iter().enumerate() {
        e[520 + i * 8..524 + i * 8].copy_from_slice(&start.to_le_bytes());
        e[524 + i * 8..528 + i * 8].copy_from_slice(&count.to_le_bytes());
    }
    let n = e.len();
    let f = ewf::adler32(&e[520..n - 4]);
    e[n - 4..].copy_from_slice(&f.to_le_bytes());
    e
}

/// Deterministic pseudo-content so compressed chunks exercise real deflate.
fn e01_media(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| ((i * 31 + (i / 7) * 13 + 5) & 0xff) as u8)
        .collect()
}

/// Knobs for `build_e01`.
#[derive(Default)]
struct E01Opts {
    header_text: Option<String>,
    /// Chunk index whose zlib stream is corrupted (byte flip mid-stream).
    corrupt_zlib_chunk: Option<usize>,
    /// Emit `table2` but no `table`.
    drop_table: bool,
    /// Truncate the emitted `table` to the first N entries.
    table_entries: Option<usize>,
    /// Volume `chunk_count` override (defaults to actual chunk count).
    declare_chunk_count: Option<u32>,
    /// Terminal section name ("done" or "next").
    terminal: Option<&'static str>,
    error2: Vec<(u32, u32)>,
    md5: Option<[u8; 16]>,
    sha1: Option<[u8; 20]>,
    /// Split chunks across two `sectors`+`table`/`table2` groups.
    two_table_groups: bool,
    /// Chunk index whose table entry points past EOF.
    bad_entry_index: Option<usize>,
    /// Drop the `volume` section entirely.
    drop_volume: bool,
}

/// Build a complete single-segment E01 holding `media`, compressed per
/// `flags[i]` (true = zlib, false = raw + Adler-32 trailer).
fn build_e01(media: &[u8], flags: &[bool], opts: E01Opts) -> Vec<u8> {
    let n_chunks = flags.len();
    assert_eq!(media.len().div_ceil(E01_CS), n_chunks);
    let mut w = E01::new();

    if let Some(text) = &opts.header_text {
        let z = miniz_oxide::deflate::compress_to_vec_zlib(text.as_bytes(), 6);
        w.section("header", &z);
    }
    if !opts.drop_volume {
        let chunk_count = opts.declare_chunk_count.unwrap_or(n_chunks as u32);
        let sectors = (media.len() as u64).div_ceil(E01_BPS as u64);
        w.section("volume", &e01_volume(chunk_count, sectors));
    }

    // Pack chunk payloads; remember each chunk's offset within its
    // `sectors` section data so table entries can be absolute.
    let groups: Vec<(usize, usize)> = if opts.two_table_groups && n_chunks > 1 {
        vec![(0, n_chunks / 2), (n_chunks / 2, n_chunks)]
    } else {
        vec![(0, n_chunks)]
    };
    let mut entries: Vec<u32> = Vec::with_capacity(n_chunks);
    for (first, last) in groups {
        let mut payloads = Vec::new();
        let mut rel_offsets = Vec::new();
        for i in first..last {
            let data = &media[i * E01_CS..media.len().min((i + 1) * E01_CS)];
            rel_offsets.push(payloads.len());
            if flags[i] {
                let mut z = miniz_oxide::deflate::compress_to_vec_zlib(data, 6);
                if opts.corrupt_zlib_chunk == Some(i) {
                    let mid = z.len() / 2;
                    z[mid] ^= 0xFF;
                }
                payloads.extend_from_slice(&z);
            } else {
                payloads.extend_from_slice(data);
                payloads.extend_from_slice(&ewf::adler32(data).to_le_bytes());
            }
        }
        let desc = w.section("sectors", &payloads);
        for (k, rel) in rel_offsets.iter().enumerate() {
            let i = first + k;
            let mut e = (desc + 76 + rel) as u32;
            if opts.bad_entry_index == Some(i) {
                e = 0x7fff_ff00; // beyond EOF → missing chunk
            }
            if flags[i] {
                e |= 0x8000_0000;
            }
            entries.push(e);
        }
        // `table_entries` truncates only the last group's table.
        let emit: &[u32] = match (opts.table_entries, last == n_chunks) {
            (Some(n), true) => &entries[first..entries.len().min(first + n)],
            _ => &entries[first..last],
        };
        let t = e01_table(emit);
        if !opts.drop_table {
            w.section("table", &t);
        }
        w.section("table2", &t);
    }

    if !opts.error2.is_empty() {
        w.section("error2", &e01_error2(&opts.error2));
    }
    if let Some(md5) = &opts.md5 {
        w.section("hash", &e01_hash(md5));
        let sha1 = opts.sha1.unwrap_or([0u8; 20]);
        w.section("digest", &e01_digest(md5, &sha1));
    }
    w.section(opts.terminal.unwrap_or("done"), &[]);
    w.finish()
}

#[test]
fn ewf_roundtrip_compressed_chunks() {
    // 2 full chunks + 3 whole sectors (media is sector-granular, like a
    // real acquisition — the logical size is a multiple of 512).
    let media = e01_media(2 * E01_CS + 3 * 512);
    let flags = [true, true, true];
    let img = build_e01(
        &media,
        &flags,
        E01Opts {
            header_text: Some("1\nmain\na\te\tSUTRAM-EXAMINER\n".to_string()),
            ..Default::default()
        },
    );
    let e = ewf::EwfSource::open(vec![vec_src(img)]).unwrap();
    assert_eq!(e.len(), media.len() as u64);
    // whole-image round trip
    assert_eq!(e.read_slice(0, media.len()).unwrap(), media);
    // read across a chunk boundary
    let off = E01_CS - 50;
    assert_eq!(e.read_slice(off as u64, 150).unwrap(), media[off..off + 150]);
    // tail & EOF clamping
    assert_eq!(
        e.read_slice(media.len() as u64 - 10, 100).unwrap(),
        media[media.len() - 10..]
    );
    assert!(e.read_slice(media.len() as u64, 8).unwrap().is_empty());
    // metadata
    let info = e.info();
    assert_eq!(info.chunk_size, E01_CS as u64);
    assert_eq!(info.bytes_per_sector, E01_BPS);
    assert_eq!(info.sectors_per_chunk, E01_SPC);
    assert_eq!(info.chunk_count, 3);
    assert_eq!(info.media_type, 0x01);
    assert_eq!(info.compression_level, 1);
    assert_eq!(info.error_granularity, 64);
    assert!(info.set_identifier.is_some());
    assert!(!info.multi_segment);
    assert!(info
        .acquisition_header
        .as_deref()
        .unwrap()
        .contains("SUTRAM-EXAMINER"));
}

#[test]
fn ewf_mixed_compressed_and_raw_chunks() {
    let media = e01_media(3 * E01_CS);
    let flags = [true, false, true]; // middle chunk stored raw
    let img = build_e01(&media, &flags, E01Opts::default());
    let e = ewf::EwfSource::open(vec![vec_src(img)]).unwrap();
    assert_eq!(e.read_slice(0, media.len()).unwrap(), media);
    // raw chunk content specifically
    assert_eq!(
        e.read_slice(E01_CS as u64, E01_CS).unwrap(),
        media[E01_CS..2 * E01_CS]
    );
    assert!(e.warnings().is_empty(), "unexpected warnings: {:?}", e.warnings());
}

#[test]
fn ewf_stored_hashes_exposed() {
    let media = e01_media(E01_CS);
    let md5 = [0x5Au8; 16];
    let sha1 = [0x11u8; 20];
    let img = build_e01(
        &media,
        &[true],
        E01Opts {
            md5: Some(md5),
            sha1: Some(sha1),
            ..Default::default()
        },
    );
    let e = ewf::EwfSource::open(vec![vec_src(img)]).unwrap();
    let h = e.acquisition_hash().unwrap();
    assert_eq!(h.md5, Some(md5));
    assert_eq!(h.sha1, Some(sha1));
    assert_eq!(h.md5_hex().as_deref(), Some("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"));
    assert!(h.sha1_hex().unwrap().starts_with("1111"));
}

#[test]
fn ewf_error2_ranges_read_zero() {
    let media = e01_media(2 * E01_CS);
    // sectors 10..12 → bytes [10*512, 12*512) inside chunk 0
    let img = build_e01(
        &media,
        &[true, true],
        E01Opts {
            error2: vec![(10, 2)],
            ..Default::default()
        },
    );
    let e = ewf::EwfSource::open(vec![vec_src(img)]).unwrap();
    assert_eq!(e.error_ranges(), &[(10 * 512, 12 * 512)]);
    let mut expected = media.clone();
    expected[10 * 512..12 * 512].fill(0);
    assert_eq!(e.read_slice(0, media.len()).unwrap(), expected);
}

#[test]
fn ewf_next_section_requires_further_segments() {
    // A `next` terminator says the image continues in .E02; opening
    // without it is a clear InvalidInput error, never a silent zero tail.
    let media = e01_media(E01_CS);
    let img = build_e01(
        &media,
        &[true],
        E01Opts {
            terminal: Some("next"),
            ..Default::default()
        },
    );
    let res = ewf::EwfSource::open(vec![vec_src(img)]);
    match res {
        Err(Error::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
            assert!(e.to_string().contains("next"));
        }
        Err(e) => panic!("expected InvalidInput io error, got {e:?}"),
        Ok(_) => panic!("expected an error, got an opened image"),
    }
}

#[test]
fn ewf_table2_mirror_fallback() {
    let media = e01_media(2 * E01_CS);
    let img = build_e01(
        &media,
        &[true, true],
        E01Opts {
            drop_table: true,
            ..Default::default()
        },
    );
    let e = ewf::EwfSource::open(vec![vec_src(img)]).unwrap();
    assert_eq!(e.read_slice(0, media.len()).unwrap(), media);
    assert!(e.warnings().iter().any(|w| w.contains("table2")));
}

#[test]
fn ewf_short_table_zero_fills_tail() {
    // Volume declares 3 chunks but the table only lists 2 — documented
    // leniency: the tail chunk reads as zeros and a warning is recorded.
    let media = e01_media(3 * E01_CS);
    let img = build_e01(
        &media,
        &[true, true, true],
        E01Opts {
            table_entries: Some(2),
            ..Default::default()
        },
    );
    let e = ewf::EwfSource::open(vec![vec_src(img)]).unwrap();
    assert_eq!(e.len(), media.len() as u64);
    assert!(e.warnings().iter().any(|w| w.contains("tail chunks")));
    let out = e.read_slice(0, media.len()).unwrap();
    assert_eq!(&out[..2 * E01_CS], &media[..2 * E01_CS]);
    assert!(out[2 * E01_CS..].iter().all(|&b| b == 0));
}

#[test]
fn ewf_extra_table_entries_ignored() {
    // Table lists 3 entries but volume declares 2 chunks: extras ignored,
    // image size clamps to the declared capacity.
    let media = e01_media(3 * E01_CS);
    let img = build_e01(
        &media,
        &[true, true, true],
        E01Opts {
            declare_chunk_count: Some(2),
            ..Default::default()
        },
    );
    let e = ewf::EwfSource::open(vec![vec_src(img)]).unwrap();
    assert_eq!(e.len(), 2 * E01_CS as u64);
    assert!(e.warnings().iter().any(|w| w.contains("extras ignored") || w.contains("clamped")));
    assert_eq!(e.read_slice(0, e.len() as usize).unwrap(), media[..2 * E01_CS]);
}

#[test]
fn ewf_corrupt_zlib_chunk_io_errors() {
    let media = e01_media(3 * E01_CS);
    let img = build_e01(
        &media,
        &[true, true, true],
        E01Opts {
            corrupt_zlib_chunk: Some(1),
            ..Default::default()
        },
    );
    let e = ewf::EwfSource::open(vec![vec_src(img)]).unwrap();
    // good chunks still read
    assert_eq!(e.read_slice(0, E01_CS).unwrap(), media[..E01_CS]);
    // the corrupt chunk reports InvalidData rather than fabricating zeros
    let mut buf = vec![0u8; E01_CS];
    let err = e.read_at(E01_CS as u64, &mut buf).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    // and a read spanning it also fails after delivering nothing
    assert!(e.read_slice(E01_CS as u64, E01_CS).is_err());
}

#[test]
fn ewf_out_of_range_entry_zero_fills() {
    let media = e01_media(2 * E01_CS);
    let img = build_e01(
        &media,
        &[true, true],
        E01Opts {
            bad_entry_index: Some(1),
            ..Default::default()
        },
    );
    let e = ewf::EwfSource::open(vec![vec_src(img)]).unwrap();
    assert!(e.warnings().iter().any(|w| w.contains("outside the segment")));
    let out = e.read_slice(0, media.len()).unwrap();
    assert_eq!(&out[..E01_CS], &media[..E01_CS]);
    assert!(out[E01_CS..].iter().all(|&b| b == 0));
}

#[test]
fn ewf_two_table_groups_accumulate() {
    // EnCase splits chunk maps into repeated sectors+table+table2 groups
    // (≤16375 entries each); entries append across groups.
    let media = e01_media(4 * E01_CS);
    let img = build_e01(
        &media,
        &[true, false, true, true],
        E01Opts {
            two_table_groups: true,
            ..Default::default()
        },
    );
    let e = ewf::EwfSource::open(vec![vec_src(img)]).unwrap();
    assert_eq!(e.read_slice(0, media.len()).unwrap(), media);
}

#[test]
fn ewf_truncated_trailer_still_reads() {
    // Segment cut inside the terminal `done` descriptor: the chunk table
    // survived, so all media reads fine; a warning records the damage.
    let media = e01_media(2 * E01_CS);
    let mut img = build_e01(&media, &[true, true], E01Opts::default());
    let cut = img.len() - 40; // inside the last descriptor
    img.truncate(cut);
    let e = ewf::EwfSource::open(vec![vec_src(img)]).unwrap();
    assert_eq!(e.read_slice(0, media.len()).unwrap(), media);
    assert!(!e.warnings().is_empty());
}

#[test]
fn ewf_truncated_past_table_degrades_to_zeros() {
    // Catastrophic truncation: the trailing `table`/`table2` sections are
    // gone. Open still succeeds (lenient) and every chunk reads as zeros
    // with warnings — never a panic, never fabricated non-zero data.
    let media = e01_media(2 * E01_CS);
    let mut img = build_e01(&media, &[true, true], E01Opts::default());
    let cut = img.len() - 400; // through the table sections
    img.truncate(cut);
    let e = ewf::EwfSource::open(vec![vec_src(img)]).unwrap();
    assert!(!e.warnings().is_empty());
    let out = e.read_slice(0, media.len()).unwrap();
    assert!(out.iter().all(|&b| b == 0));
}

#[test]
fn ewf_no_volume_is_corrupt() {
    let media = e01_media(E01_CS);
    let img = build_e01(
        &media,
        &[true],
        E01Opts {
            drop_volume: true,
            ..Default::default()
        },
    );
    let res = ewf::EwfSource::open(vec![vec_src(img)]);
    assert!(matches!(res, Err(Error::Corrupt { .. })));
}

#[test]
fn ewf_segment_number_two_unsupported() {
    let media = e01_media(E01_CS);
    let mut img = build_e01(&media, &[true], E01Opts::default());
    img[9..11].copy_from_slice(&2u16.to_le_bytes()); // segment 2
    let res = ewf::EwfSource::open(vec![vec_src(img)]);
    assert!(matches!(res, Err(Error::Unsupported { .. })));
}

// ---------------------------------------------------------------------------
// Multi-segment EWF corpus & tests
// ---------------------------------------------------------------------------

/// Build one segment file of a multi-segment EWF image holding `chunks`
/// (each exactly E01_CS bytes except possibly the last). Every segment
/// repeats the full-image `volume` geometry; `terminal` is `"next"` for
/// all but the last segment and `"done"` for the last. Chunks alternate
/// zlib-raw-zlib to exercise both paths per segment.
fn build_e01_segment(
    chunks: &[&[u8]],
    seg_no: u16,
    total_chunks: u32,
    total_sectors: u64,
    terminal: &str,
) -> Vec<u8> {
    let mut w = E01::new_seg(seg_no);
    w.section("volume", &e01_volume(total_chunks, total_sectors));

    let mut payloads = Vec::new();
    let mut rel_offsets = Vec::new();
    let mut compressed = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        rel_offsets.push(payloads.len());
        if i % 2 == 0 {
            let z = miniz_oxide::deflate::compress_to_vec_zlib(chunk, 6);
            payloads.extend_from_slice(&z);
            compressed.push(true);
        } else {
            payloads.extend_from_slice(chunk);
            payloads.extend_from_slice(&ewf::adler32(chunk).to_le_bytes());
            compressed.push(false);
        }
    }
    let desc = w.section("sectors", &payloads);
    let entries: Vec<u32> = rel_offsets
        .iter()
        .enumerate()
        .map(|(k, &rel)| {
            let mut e = (desc + 76 + rel) as u32;
            if compressed[k] {
                e |= 0x8000_0000;
            }
            e
        })
        .collect();
    let t = e01_table(&entries);
    w.section("table", &t);
    w.section("table2", &t);
    w.section(terminal, &[]);
    w.finish()
}

#[test]
fn ewf_multi_segment_roundtrip() {
    // 4 chunks: 2 in .E01 (terminated by `next`), 2 in .E02 (`done`).
    let media = e01_media(4 * E01_CS);
    let chunks: Vec<&[u8]> = media.chunks(E01_CS).collect();
    let sectors = (media.len() as u64).div_ceil(E01_BPS as u64);
    let s1 = build_e01_segment(&chunks[..2], 1, 4, sectors, "next");
    let s2 = build_e01_segment(&chunks[2..], 2, 4, sectors, "done");
    let e = ewf::EwfSource::open(vec![vec_src(s1), vec_src(s2)]).unwrap();
    assert_eq!(e.len(), media.len() as u64);
    assert!(e.info().multi_segment);
    assert_eq!(e.info().segment_count, 2);
    // whole-image round trip across the segment seam
    assert_eq!(e.read_slice(0, media.len()).unwrap(), media);
    // a read spanning the chunk 1|2 boundary is a cross-segment read
    let seam = 2 * E01_CS;
    let off = seam - 50;
    assert_eq!(
        e.read_slice(off as u64, 150).unwrap(),
        media[off..off + 150]
    );
    // reads confined to the second segment also work
    assert_eq!(
        e.read_slice(3 * E01_CS as u64, 512).unwrap(),
        media[3 * E01_CS..3 * E01_CS + 512]
    );
    assert!(
        e.warnings().is_empty(),
        "unexpected warnings: {:?}",
        e.warnings()
    );
}

#[test]
fn ewf_missing_continuation_segment_is_clear_error() {
    // .E01 ends with `next` but .E02 was not supplied → clear error.
    let media = e01_media(2 * E01_CS);
    let chunks: Vec<&[u8]> = media.chunks(E01_CS).collect();
    let sectors = (media.len() as u64).div_ceil(E01_BPS as u64);
    let s1 = build_e01_segment(&chunks[..1], 1, 2, sectors, "next");
    let res = ewf::EwfSource::open(vec![vec_src(s1)]);
    match res {
        Err(Error::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
            let m = e.to_string();
            assert!(m.contains("next") && m.contains("E02"), "{m}");
        }
        Err(e) => panic!("expected InvalidInput io error, got {e:?}"),
        Ok(_) => panic!("expected InvalidInput io error, got an opened image"),
    }
}

#[test]
fn ewf_multi_segment_three_way_and_bad_signature() {
    // 3 segments; a corrupt middle segment reports its position.
    let media = e01_media(3 * E01_CS);
    let chunks: Vec<&[u8]> = media.chunks(E01_CS).collect();
    let sectors = (media.len() as u64).div_ceil(E01_BPS as u64);
    let s1 = build_e01_segment(&chunks[..1], 1, 3, sectors, "next");
    let s2 = build_e01_segment(&chunks[1..2], 2, 3, sectors, "next");
    let s3 = build_e01_segment(&chunks[2..], 3, 3, sectors, "done");
    let e = ewf::EwfSource::open(vec![vec_src(s1.clone()), vec_src(s2), vec_src(s3)]).unwrap();
    assert_eq!(e.read_slice(0, media.len()).unwrap(), media);
    assert_eq!(e.info().segment_count, 3);

    let bad = vec_src(vec![0u8; 512]);
    let res = ewf::EwfSource::open(vec![vec_src(s1), bad]);
    match res {
        Err(Error::Corrupt { msg, .. }) => assert!(msg.contains("segment 2"), "{msg}"),
        Err(e) => panic!("expected Corrupt naming segment 2, got {e:?}"),
        Ok(_) => panic!("expected Corrupt naming segment 2, got an opened image"),
    }
}

#[test]
fn ewf_open_segments_from_paths() {
    // Real-file path API: write two segments to a temp dir, open by path.
    let media = e01_media(2 * E01_CS);
    let chunks: Vec<&[u8]> = media.chunks(E01_CS).collect();
    let sectors = (media.len() as u64).div_ceil(E01_BPS as u64);
    let s1 = build_e01_segment(&chunks[..1], 1, 2, sectors, "next");
    let s2 = build_e01_segment(&chunks[1..], 2, 2, sectors, "done");

    let dir = std::env::temp_dir()
        .join(format!("sutram-ewf-segments-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p1 = dir.join("case.E01");
    let p2 = dir.join("case.E02");
    std::fs::write(&p1, &s1).unwrap();
    std::fs::write(&p2, &s2).unwrap();

    let e = ewf::EwfSource::open_segments(&[p1.clone(), p2.clone()]).unwrap();
    assert_eq!(e.len(), media.len() as u64);
    assert_eq!(e.read_slice(0, media.len()).unwrap(), media);

    // A missing continuation path → io error naming the segment & path.
    let p3 = dir.join("case.E03");
    let res = ewf::EwfSource::open_segments(&[p1.clone(), p2.clone(), p3]);
    match res {
        Err(Error::Io(e)) => {
            let m = e.to_string();
            assert!(m.contains("segment 3") && m.contains("case.E03"), "{m}");
        }
        Err(e) => panic!("expected Io error for missing segment, got {e:?}"),
        Ok(_) => panic!("expected Io error for missing segment, got an opened image"),
    }
    std::fs::remove_dir_all(&dir).ok();
}

// ---------------------------------------------------------------------------
// VHD / VHDX synthetic-image corpus
// ---------------------------------------------------------------------------

/// Build a VHD footer (512 bytes, big-endian fields, valid checksum).
fn vhd_footer(disk_type: u32, current_size: u64, data_offset: u64) -> Vec<u8> {
    let mut f = vec![0u8; 512];
    f[..8].copy_from_slice(b"conectix");
    f[8..12].copy_from_slice(&2u32.to_be_bytes()); // features
    f[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes()); // version
    f[16..24].copy_from_slice(&data_offset.to_be_bytes());
    f[28..32].copy_from_slice(&0x7769_6E32u32.to_be_bytes()); // "win2"
    f[40..48].copy_from_slice(&current_size.to_be_bytes()); // original size
    f[48..56].copy_from_slice(&current_size.to_be_bytes()); // current size
    f[56..58].copy_from_slice(&4u16.to_be_bytes()); // cylinders
    f[58] = 16; // heads
    f[59] = 63; // sectors/track
    f[60..64].copy_from_slice(&disk_type.to_be_bytes());
    let sum: u64 = f
        .iter()
        .enumerate()
        .filter(|(i, _)| !(64..68).contains(i))
        .map(|(_, &b)| b as u64)
        .sum();
    f[64..68].copy_from_slice(&(!(sum as u32)).to_be_bytes());
    f
}

#[test]
fn vhd_fixed_roundtrip() {
    let media: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    let mut img = media.clone();
    img.extend_from_slice(&vhd_footer(2, media.len() as u64, u64::MAX));
    assert!(vhd::VhdSource::is_vhd(&img.as_slice()));
    assert!(!vhd::VhdSource::is_vhdx(&img.as_slice()));
    let v = vhd::VhdSource::open(vec_src(img)).unwrap();
    assert_eq!(v.info().format, vhd::VhdFormat::Vhd);
    assert_eq!(v.info().disk_type, 2);
    assert_eq!(v.len(), media.len() as u64);
    assert_eq!(v.read_slice(0, media.len()).unwrap(), media);
    assert!(v.read_slice(media.len() as u64, 10).unwrap().is_empty());
}

#[test]
fn vhd_fixed_trailing_garbage() {
    // Footer not at EOF: appended garbage must not hide it.
    let media: Vec<u8> = (0..1500u32).map(|i| (i % 97) as u8).collect();
    let mut img = media.clone();
    img.extend_from_slice(&vhd_footer(2, media.len() as u64, u64::MAX));
    img.extend_from_slice(&[0xAB; 600]); // trailing garbage
    let v = vhd::VhdSource::open(vec_src(img)).unwrap();
    assert_eq!(v.len(), media.len() as u64);
    assert_eq!(v.read_slice(0, media.len()).unwrap(), media);
    assert!(v.warnings().iter().any(|w| w.contains("trailing garbage")));
}

/// Build a dynamic VHD. `blocks[i]` is `Some(data)` for allocated blocks
/// or `None` for an unallocated BAT entry; `absent_sectors` lists
/// (block, sector-in-block) bitmap bits to clear on allocated blocks.
fn build_vhd_dynamic(
    block_size: usize,
    blocks: &[Option<Vec<u8>>],
    absent_sectors: &[(usize, usize)],
) -> Vec<u8> {
    let vsize = (block_size * blocks.len()) as u64;
    let mut img = Vec::new();
    // footer copy at 0
    img.extend_from_slice(&vhd_footer(3, vsize, 512));
    // dynamic header at 512
    // Blocks = [bitmap][data], written right after the dynamic header;
    // the BAT follows them (its offset is declared, so order is free).
    let spb = block_size / 512;
    let bm_bytes = spb.div_ceil(8).div_ceil(512) * 512;
    let n_alloc = blocks.iter().filter(|b| b.is_some()).count();
    let bat_off = (1536 + n_alloc * (bm_bytes + block_size)) as u64;

    let mut dh = vec![0u8; 1024];
    dh[..8].copy_from_slice(b"cxsparse");
    dh[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    dh[16..24].copy_from_slice(&bat_off.to_be_bytes());
    dh[24..28].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    dh[28..32].copy_from_slice(&(blocks.len() as u32).to_be_bytes());
    dh[32..36].copy_from_slice(&(block_size as u32).to_be_bytes());
    let sum: u64 = dh
        .iter()
        .enumerate()
        .filter(|(i, _)| !(36..40).contains(i))
        .map(|(_, &b)| b as u64)
        .sum();
    dh[36..40].copy_from_slice(&(!(sum as u32)).to_be_bytes());
    img.extend_from_slice(&dh);
    debug_assert_eq!(img.len(), 1536);

    // Blocks first, recording each one's sector offset for the BAT.
    let mut sectors = vec![0xFFFF_FFFFu32; blocks.len()];
    for (i, b) in blocks.iter().enumerate() {
        let Some(data) = b else { continue };
        assert_eq!(data.len(), block_size);
        debug_assert_eq!(img.len() % 512, 0);
        sectors[i] = (img.len() / 512) as u32;
        let mut bitmap = vec![0xFFu8; bm_bytes];
        for &(b_i, s) in absent_sectors {
            if b_i == i {
                bitmap[s / 8] &= !(0x80 >> (s % 8));
            }
        }
        img.extend_from_slice(&bitmap);
        img.extend_from_slice(data);
    }
    debug_assert_eq!(img.len(), bat_off as usize);
    for &s in &sectors {
        img.extend_from_slice(&s.to_be_bytes());
    }
    // real footer at EOF
    img.extend_from_slice(&vhd_footer(3, vsize, 512));
    img
}

#[test]
fn vhd_dynamic_roundtrip_and_unallocated() {
    let bs = 4096usize; // small but legal power-of-two block size
    let b0: Vec<u8> = (0..bs).map(|i| (i % 64) as u8).collect();
    let b2: Vec<u8> = (0..bs).map(|i| 0xC0 | (i % 16) as u8).collect();
    let img = build_vhd_dynamic(bs, &[Some(b0.clone()), None, Some(b2.clone())], &[]);
    let v = vhd::VhdSource::open(vec_src(img)).unwrap();
    assert_eq!(v.info().format, vhd::VhdFormat::Vhd);
    assert_eq!(v.info().disk_type, 3);
    assert_eq!(v.info().block_size, Some(bs as u32));
    assert_eq!(v.len(), 3 * bs as u64);
    assert_eq!(v.read_slice(0, bs).unwrap(), b0);
    assert!(v.read_slice(bs as u64, bs).unwrap().iter().all(|&b| b == 0));
    assert_eq!(v.read_slice(2 * bs as u64, bs).unwrap(), b2);
    // cross-block read
    let mut expected = b0[bs - 100..].to_vec();
    expected.extend_from_slice(&vec![0u8; bs]);
    expected.extend_from_slice(&b2[..100]);
    assert_eq!(
        v.read_slice((bs - 100) as u64, bs + 200).unwrap(),
        expected
    );
}

#[test]
fn vhd_dynamic_sector_bitmap_honoured() {
    // Block 0 present but its sector bitmap marks sector 2 absent →
    // that sector reads as zeros while neighbours keep stored data.
    let bs = 4096usize;
    let b0: Vec<u8> = vec![0x55; bs];
    let img = build_vhd_dynamic(bs, &[Some(b0)], &[(0, 2)]);
    let v = vhd::VhdSource::open(vec_src(img)).unwrap();
    let out = v.read_slice(0, bs).unwrap();
    assert!(out[..1024].iter().all(|&b| b == 0x55));
    assert!(out[1024..1536].iter().all(|&b| b == 0));
    assert!(out[1536..].iter().all(|&b| b == 0x55));
}

#[test]
fn vhd_differencing_unsupported() {
    let mut img = vec![0u8; 4096];
    img.extend_from_slice(&vhd_footer(4, 8192, 512));
    let res = vhd::VhdSource::open(vec_src(img));
    match res {
        Err(Error::Unsupported { msg }) => assert!(msg.contains("differencing")),
        Err(e) => panic!("expected Unsupported, got {e:?}"),
        Ok(_) => panic!("expected Unsupported, got an opened image"),
    }
}

#[test]
fn vhd_truncated_bat_zero_fills() {
    // Dynamic VHD whose file ends mid-BAT: opens leniently (the footer
    // copy at offset 0 is found by the tail scan), tail blocks read as
    // zeros with a warning.
    let bs = 4096usize;
    let b0: Vec<u8> = (0..bs).map(|i| (i % 32) as u8).collect();
    let mut img = build_vhd_dynamic(bs, &[Some(b0.clone()), Some(vec![0xEE; bs])], &[]);
    // Blocks occupy 1536..1536+2*(512+bs); the BAT starts after them.
    let bat_off = 1536 + 2 * (512 + bs);
    img.truncate(bat_off + 4); // keep only the first BAT entry
    let v = vhd::VhdSource::open(vec_src(img)).unwrap();
    assert!(v.warnings().iter().any(|w| w.contains("truncated")));
    assert_eq!(v.read_slice(0, bs).unwrap(), b0);
    assert!(v.read_slice(bs as u64, bs).unwrap().iter().all(|&b| b == 0));
}

#[test]
fn vhd_no_footer_is_corrupt() {
    let res = vhd::VhdSource::open(vec_src(vec![0u8; 8192]));
    assert!(matches!(res, Err(Error::Corrupt { .. })));
    let res = vhd::VhdSource::open(vec_src(vec![0u8; 100]));
    assert!(matches!(res, Err(Error::Truncated { .. })));
}

// ---- VHDX corpus -----------------------------------------------------------

/// Write a checksum-valid VHDX header at `off` in `img` (already sized).
fn vhdx_header(img: &mut [u8], off: usize, seq: u64) {
    img[off..off + 4].copy_from_slice(b"head");
    img[off + 8..off + 16].copy_from_slice(&seq.to_le_bytes());
    img[off + 34..off + 36].copy_from_slice(&1u16.to_le_bytes()); // version
    let sum = vhd::crc32c_zeroed(&img[off..off + 4096], 4);
    img[off + 4..off + 8].copy_from_slice(&sum.to_le_bytes());
}

/// Write a checksum-valid region table at `off`.
fn vhdx_region_table(img: &mut [u8], off: usize, entries: &[([u8; 16], u64, u64)]) {
    img[off..off + 4].copy_from_slice(b"regi");
    img[off + 8..off + 12].copy_from_slice(&(entries.len() as u32).to_le_bytes());
    for (i, (guid, file_off, len)) in entries.iter().enumerate() {
        let e = off + 16 + i * 32;
        img[e..e + 16].copy_from_slice(guid);
        img[e + 16..e + 24].copy_from_slice(&file_off.to_le_bytes());
        img[e + 24..e + 32].copy_from_slice(&len.to_le_bytes());
    }
    let sum = vhd::crc32c_zeroed(&img[off..off + 65536], 4);
    img[off + 4..off + 8].copy_from_slice(&sum.to_le_bytes());
}

const VHDX_GUID_BAT_T: [u8; 16] = [
    0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08,
];
const VHDX_GUID_META_T: [u8; 16] = [
    0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E,
];
const VHDX_ITEM_FILE_PARAMS_T: [u8; 16] = [
    0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B,
];
const VHDX_ITEM_VSIZE_T: [u8; 16] = [
    0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8,
];
const VHDX_ITEM_LSS_T: [u8; 16] = [
    0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F,
];
const VHDX_ITEM_PARENT_T: [u8; 16] = [
    0x2D, 0x5F, 0xD3, 0xA8, 0x0B, 0xB3, 0x4D, 0x45, 0xAB, 0xF7, 0xD3, 0xD8, 0x48, 0x34, 0xAB, 0x0C,
];

/// Minimal VHDX: BAT region at 1 MiB, metadata at 2 MiB, payload blocks
/// at 3 MiB+. `blocks[i]` = BAT payload state+offset written by caller.
/// block_size = 1 MiB, lss = 512 → chunk_ratio = 4096.
fn build_vhdx(
    vsize: u64,
    block_size: u32,
    bat_entries: &[(usize, u64)], // (bat_index, entry) pairs
    has_parent: bool,
) -> Vec<u8> {
    let mut img = vec![0u8; 5 << 20];
    img[..8].copy_from_slice(b"vhdxfile");
    vhdx_header(&mut img, 64 << 10, 1);
    vhdx_header(&mut img, 128 << 10, 1);
    vhdx_region_table(
        &mut img,
        192 << 10,
        &[(VHDX_GUID_BAT_T, 1 << 20, 1 << 20), (VHDX_GUID_META_T, 2 << 20, 1 << 20)],
    );
    vhdx_region_table(
        &mut img,
        256 << 10,
        &[(VHDX_GUID_BAT_T, 1 << 20, 1 << 20), (VHDX_GUID_META_T, 2 << 20, 1 << 20)],
    );
    // metadata region at 2 MiB
    let m = 2 << 20;
    img[m..m + 8].copy_from_slice(b"metadata");
    let items = if has_parent { 4u16 } else { 3u16 };
    img[m + 10..m + 12].copy_from_slice(&items.to_le_bytes());
    // item table at m+32; item data at m + 64KiB +
    let mut item_off = (64usize) << 10;
    let mut put_item = |img: &mut Vec<u8>, i: usize, id: &[u8; 16], data: &[u8]| {
        let e = m + 32 + i * 32;
        img[e..e + 16].copy_from_slice(id);
        img[e + 16..e + 20].copy_from_slice(&(item_off as u32).to_le_bytes());
        img[e + 20..e + 24].copy_from_slice(&(data.len() as u32).to_le_bytes());
        img[m + item_off..m + item_off + data.len()].copy_from_slice(data);
        item_off += data.len().max(64); // keep items separated
    };
    let mut fp = [0u8; 8];
    fp[..4].copy_from_slice(&block_size.to_le_bytes());
    if has_parent {
        fp[4..8].copy_from_slice(&2u32.to_le_bytes()); // HasParent
    }
    put_item(&mut img, 0, &VHDX_ITEM_FILE_PARAMS_T, &fp);
    put_item(&mut img, 1, &VHDX_ITEM_VSIZE_T, &vsize.to_le_bytes());
    put_item(&mut img, 2, &VHDX_ITEM_LSS_T, &512u32.to_le_bytes());
    if has_parent {
        put_item(&mut img, 3, &VHDX_ITEM_PARENT_T, &[0u8; 24]);
    }
    // BAT entries
    let b = 1 << 20;
    for &(idx, entry) in bat_entries {
        img[b + idx * 8..b + idx * 8 + 8].copy_from_slice(&entry.to_le_bytes());
    }
    img
}

/// BAT payload entry: state | file offset in MiB.
fn vhdx_bat_entry(state: u64, off_mb: u64) -> u64 {
    state | (off_mb << 20)
}

#[test]
fn vhdx_roundtrip() {
    // vsize 3 MiB, block_size 1 MiB → 3 payload blocks, chunk_ratio 4096.
    // bat[0] → block0 at 3 MiB (present), bat[1] not present, bat[2] → 4 MiB.
    let bs = 1usize << 20;
    let b0: Vec<u8> = (0..bs).map(|i| (i % 211) as u8).collect();
    let b2: Vec<u8> = (0..bs).map(|i| 0x80 ^ (i % 99) as u8).collect();
    let mut img = build_vhdx(
        3 * bs as u64,
        bs as u32,
        &[
            (0, vhdx_bat_entry(6, 3)),
            (2, vhdx_bat_entry(6, 4)),
        ],
        false,
    );
    img[3 * bs..4 * bs].copy_from_slice(&b0);
    img[4 * bs..].copy_from_slice(&b2);
    let v = vhd::VhdSource::open(vec_src(img)).unwrap();
    assert_eq!(v.info().format, vhd::VhdFormat::Vhdx);
    assert_eq!(v.info().virtual_size, 3 * bs as u64);
    assert_eq!(v.info().block_size, Some(bs as u32));
    assert_eq!(v.info().logical_sector_size, 512);
    assert_eq!(v.len(), 3 * bs as u64);
    assert_eq!(v.read_slice(0, bs).unwrap(), b0);
    assert!(v.read_slice(bs as u64, bs).unwrap().iter().all(|&b| b == 0));
    assert_eq!(v.read_slice(2 * bs as u64, bs).unwrap(), b2);
    // cross-block read spanning a hole
    let mut expected = b0[bs - 64..].to_vec();
    expected.extend_from_slice(&vec![0u8; bs]);
    expected.extend_from_slice(&b2[..64]);
    assert_eq!(v.read_slice((bs - 64) as u64, bs + 128).unwrap(), expected);
    // past EOF
    assert!(v.read_slice(3 * bs as u64, 16).unwrap().is_empty());
}

#[test]
fn vhdx_zero_and_undefined_states() {
    let bs = 1usize << 20;
    let img = build_vhdx(
        2 * bs as u64,
        bs as u32,
        &[(0, vhdx_bat_entry(2, 9)), (1, vhdx_bat_entry(1, 0))],
        false,
    );
    let v = vhd::VhdSource::open(vec_src(img)).unwrap();
    let out = v.read_slice(0, 2 * bs).unwrap();
    assert!(out.iter().all(|&b| b == 0));
}

#[test]
fn vhdx_differencing_unsupported() {
    let bs = 1usize << 20;
    let img = build_vhdx(bs as u64, bs as u32, &[(0, vhdx_bat_entry(6, 3))], true);
    let res = vhd::VhdSource::open(vec_src(img));
    match res {
        Err(Error::Unsupported { msg }) => assert!(msg.contains("differencing")),
        Err(e) => panic!("expected Unsupported, got {e:?}"),
        Ok(_) => panic!("expected Unsupported, got an opened image"),
    }
}

#[test]
fn vhdx_corrupt_headers_and_tables() {
    let bs = 1usize << 20;
    let good = build_vhdx(bs as u64, bs as u32, &[(0, vhdx_bat_entry(6, 3))], false);

    // Corrupt both headers → Corrupt.
    let mut img = good.clone();
    img[64 << 10] ^= 0xFF;
    img[128 << 10] ^= 0xFF;
    assert!(matches!(
        vhd::VhdSource::open(vec_src(img)),
        Err(Error::Corrupt { .. })
    ));

    // Corrupt only header 1 → header 2 wins, still opens.
    let mut img = good.clone();
    img[(64 << 10) + 20] ^= 0xFF;
    let v = vhd::VhdSource::open(vec_src(img)).unwrap();
    assert_eq!(v.len(), bs as u64);
    assert!(v.warnings().iter().any(|w| w.contains("CRC")));

    // Corrupt both region tables → Corrupt.
    let mut img = good.clone();
    img[(192 << 10) + 4] ^= 0xFF; // break checksum
    img[(256 << 10) + 4] ^= 0xFF;
    assert!(matches!(
        vhd::VhdSource::open(vec_src(img)),
        Err(Error::Corrupt { .. })
    ));

    // Truncated image → Truncated.
    let img = good[..100 << 10].to_vec();
    assert!(matches!(
        vhd::VhdSource::open(vec_src(img)),
        Err(Error::Truncated { .. })
    ));
}

#[test]
fn vhdx_reserved_bat_state_io_errors() {
    let bs = 1usize << 20;
    let img = build_vhdx(bs as u64, bs as u32, &[(0, vhdx_bat_entry(4, 3))], false);
    let v = vhd::VhdSource::open(vec_src(img)).unwrap();
    let mut buf = vec![0u8; 512];
    let e = v.read_at(0, &mut buf).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
}

// ---------------------------------------------------------------------------
// QCOW2 synthetic-image corpus
// ---------------------------------------------------------------------------

const QCOW2_CBITS: u32 = 12; // 4 KiB clusters
const QCOW2_CS: usize = 1 << QCOW2_CBITS;

/// Build a QCOW2 image: header + L1 + L2 tables + cluster payloads.
/// `clusters[i]` describes guest cluster i:
///   Raw(data)   — stored uncompressed at a fresh host cluster;
///   Comp(data)  — stored as raw deflate;
///   Unalloc     — L2 entry 0;
///   ZeroFlag    — L2 entry with the ZERO bit set.
enum QCluster {
    Raw(Vec<u8>),
    Comp(Vec<u8>),
    Unalloc,
    ZeroFlag,
}
use QCluster::*;

fn build_qcow2(clusters: &[QCluster], version: u32) -> Vec<u8> {
    let cs = QCOW2_CS as u64;
    let l2e = cs / 8; // entries per L2 table
    let total = clusters.len() as u64;
    let needed_l1 = total.div_ceil(l2e).max(1) as usize;
    // layout: header @0, l1 @ 512, l2 tables @ 4096+, payloads after
    let l1_off = 512u64;
    let l2_base = 4096u64;
    let mut img = vec![0u8; l2_base as usize + needed_l1 * QCOW2_CS];
    img[..4].copy_from_slice(&0x5146_49FBu32.to_be_bytes());
    img[4..8].copy_from_slice(&version.to_be_bytes());
    img[20..24].copy_from_slice(&QCOW2_CBITS.to_be_bytes());
    img[24..32].copy_from_slice(&(total * cs).to_be_bytes());
    img[36..40].copy_from_slice(&(needed_l1 as u32).to_be_bytes());
    img[40..48].copy_from_slice(&l1_off.to_be_bytes());
    if version == 3 {
        img[96..100].copy_from_slice(&4u32.to_be_bytes()); // refcount_order
        img[100..104].copy_from_slice(&(HEADER_LEN as u32).to_be_bytes());
    }

    let csize_shift = 62 - (QCOW2_CBITS - 8);
    let csize_mask = (1u64 << (QCOW2_CBITS - 8)) - 1;
    // L1 entry i → L2 table i at l2_base + i*cs, marked COPIED.
    for i in 0..needed_l1 {
        let e = ((l2_base + i as u64 * cs) & 0x00FF_FFFF_FFFF_FE00) | (1 << 63);
        img[l1_off as usize + i * 8..l1_off as usize + i * 8 + 8]
            .copy_from_slice(&e.to_be_bytes());
    }
    for (i, c) in clusters.iter().enumerate() {
        let l1i = i as u64 / l2e;
        let l2i = i as u64 % l2e;
        let l2e_off = (l2_base + l1i * cs) as usize + l2i as usize * 8;
        match c {
            Raw(d) => {
                assert!(d.len() <= QCOW2_CS);
                img.resize(img.len().div_ceil(QCOW2_CS) * QCOW2_CS, 0);
                let off = img.len() as u64;
                img.extend_from_slice(d);
                img.resize(off as usize + QCOW2_CS, 0);
                let e = (off & 0x00FF_FFFF_FFFF_FE00) | (1 << 63);
                img[l2e_off..l2e_off + 8].copy_from_slice(&e.to_be_bytes());
            }
            Comp(d) => {
                let z = miniz_oxide::deflate::compress_to_vec(d, 6); // raw deflate
                let off = img.len() as u64;
                img.extend_from_slice(&z);
                let nb_sec = (off % 512 + z.len() as u64).div_ceil(512);
                let e = (1u64 << 62)
                    | (((nb_sec - 1) & csize_mask) << csize_shift)
                    | (off & ((1 << csize_shift) - 1));
                img[l2e_off..l2e_off + 8].copy_from_slice(&e.to_be_bytes());
            }
            Unalloc => {} // entry stays 0
            ZeroFlag => {
                img[l2e_off..l2e_off + 8].copy_from_slice(&1u64.to_be_bytes());
            }
        }
    }
    img
}

const HEADER_LEN: usize = 104;

fn qcow_media(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 17 + i / 11 * 5 + 3) & 0xff) as u8).collect()
}

#[test]
fn qcow2_roundtrip_mixed_clusters() {
    let d0 = qcow_media(QCOW2_CS);
    let d1 = qcow_media(QCOW2_CS / 2); // compressed, partial cluster
    let img = build_qcow2(
        &[Raw(d0.clone()), Comp(d1.clone()), Unalloc, ZeroFlag],
        3,
    );
    assert!(qcow2::Qcow2Source::is_qcow2(&img.as_slice()));
    let q = qcow2::Qcow2Source::open(vec_src(img)).unwrap();
    assert_eq!(q.info().version, 3);
    assert_eq!(q.info().cluster_size, QCOW2_CS as u64);
    assert_eq!(q.len(), 4 * QCOW2_CS as u64);
    let mut expected = d0.clone();
    expected.extend_from_slice(&d1);
    expected.resize(4 * QCOW2_CS, 0);
    assert_eq!(q.read_slice(0, 4 * QCOW2_CS).unwrap(), expected);
    // cross-cluster read
    let off = QCOW2_CS - 10;
    let mut exp2 = d0[off..].to_vec();
    exp2.extend_from_slice(&d1[..20]);
    assert_eq!(q.read_slice(off as u64, 30).unwrap(), exp2);
    assert!(q.warnings().is_empty(), "{:?}", q.warnings());
}

#[test]
fn qcow2_version2_and_hostoff() {
    // v2 header + an L2 entry pointing at an absolute file offset (the
    // host region is appended after the image is laid out).
    let d0 = qcow_media(QCOW2_CS);
    let mut img = build_qcow2(&[Raw(d0.clone()), Unalloc], 2);
    let tail_off = img.len() as u64;
    img.extend_from_slice(&vec![0x77u8; QCOW2_CS]);
    // Point cluster 1's L2 entry at the appended data (COPIED + offset).
    let e = (tail_off & 0x00FF_FFFF_FFFF_FE00) | (1 << 63);
    img[4096 + 8..4096 + 16].copy_from_slice(&e.to_be_bytes());
    let q = qcow2::Qcow2Source::open(vec_src(img)).unwrap();
    assert_eq!(q.info().version, 2);
    assert_eq!(q.read_slice(0, QCOW2_CS).unwrap(), d0);
    assert!(q
        .read_slice(QCOW2_CS as u64, QCOW2_CS)
        .unwrap()
        .iter()
        .all(|&b| b == 0x77));
}

#[test]
fn qcow2_encrypted_and_backing_unsupported() {
    let d0 = qcow_media(QCOW2_CS);
    let mut img = build_qcow2(&[Raw(d0.clone())], 3);
    // crypt_method = 1 (AES)
    img[32..36].copy_from_slice(&1u32.to_be_bytes());
    match qcow2::Qcow2Source::open(vec_src(img)) {
        Err(Error::Unsupported { msg }) => assert!(msg.contains("crypt_method")),
        Err(e) => panic!("expected Unsupported, got {e:?}"),
        Ok(_) => panic!("expected Unsupported, got an opened image"),
    }
    // backing file set
    let mut img = build_qcow2(&[Raw(d0.clone())], 3);
    img[8..16].copy_from_slice(&4096u64.to_be_bytes());
    img[16..20].copy_from_slice(&4u32.to_be_bytes());
    match qcow2::Qcow2Source::open(vec_src(img)) {
        Err(Error::Unsupported { msg }) => assert!(msg.contains("backing")),
        Err(e) => panic!("expected Unsupported, got {e:?}"),
        Ok(_) => panic!("expected Unsupported, got an opened image"),
    }
    // old qcow v1
    let mut img = build_qcow2(&[Raw(d0)], 3);
    img[4..8].copy_from_slice(&1u32.to_be_bytes());
    match qcow2::Qcow2Source::open(vec_src(img)) {
        Err(Error::Unsupported { msg }) => assert!(msg.contains("version")),
        Err(e) => panic!("expected Unsupported, got {e:?}"),
        Ok(_) => panic!("expected Unsupported, got an opened image"),
    }
}

#[test]
fn qcow2_corrupt_deflate_io_error() {
    let d0 = qcow_media(QCOW2_CS);
    let mut img = build_qcow2(&[Comp(d0.clone()), Raw(d0.clone())], 3);
    // find the compressed stream: it's appended right after the L2 table
    // region; corrupt the middle of it. The compressed payload begins at
    // the first byte after l2_base + cs (l1 covers it) — locate via the
    // L2 entry.
    let cs = QCOW2_CS as u64;
    let l2e = le::u64_be(&img, 4096).unwrap(); // entry 0 in L2 table 0
    let csize_shift = 62 - (QCOW2_CBITS - 8);
    let comp_off = (l2e & ((1u64 << csize_shift) - 1)) as usize;
    img[comp_off + 4] ^= 0xFF;
    let q = qcow2::Qcow2Source::open(vec_src(img)).unwrap();
    let mut buf = vec![0u8; QCOW2_CS];
    let e = q.read_at(0, &mut buf).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    // the raw cluster still reads fine
    assert_eq!(q.read_slice(cs, QCOW2_CS).unwrap(), d0);
}

#[test]
fn qcow2_truncated_l2_and_bad_offsets_zero_fill() {
    let d0 = qcow_media(QCOW2_CS);
    let mut img = build_qcow2(&[Raw(d0.clone()), Raw(d0.clone())], 3);
    // point cluster 1's L2 entry past EOF
    img[4096 + 8..4096 + 16].copy_from_slice(&((0x00FF_FFFFu64 << 9) | (1 << 63)).to_be_bytes());
    let q = qcow2::Qcow2Source::open(vec_src(img)).unwrap();
    assert_eq!(q.read_slice(0, QCOW2_CS).unwrap(), d0);
    assert!(q
        .read_slice(QCOW2_CS as u64, QCOW2_CS)
        .unwrap()
        .iter()
        .all(|&b| b == 0));
}

#[test]
fn qcow2_bad_magic_and_geometry() {
    let res = qcow2::Qcow2Source::open(vec_src(vec![0u8; 4096]));
    assert!(matches!(res, Err(Error::Corrupt { .. })));
    let res = qcow2::Qcow2Source::open(vec_src(vec![0u8; 10]));
    assert!(matches!(res, Err(Error::Truncated { .. })));
    // absurd cluster_bits
    let d0 = qcow_media(QCOW2_CS);
    let mut img = build_qcow2(&[Raw(d0)], 3);
    img[20..24].copy_from_slice(&63u32.to_be_bytes());
    assert!(matches!(
        qcow2::Qcow2Source::open(vec_src(img)),
        Err(Error::Corrupt { .. })
    ));
}

// ---------------------------------------------------------------------------
// Split-raw concatenation tests (real temp files — the API is path-based)
// ---------------------------------------------------------------------------

fn split_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("sutram-split-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn split_raw_numeric_segments_concatenate() {
    let dir = split_dir("num");
    // Write out of order to prove ordering is by suffix, not dir order.
    std::fs::write(dir.join("disk.002"), b"world!").unwrap();
    std::fs::write(dir.join("disk.001"), b"hello ").unwrap();
    std::fs::write(dir.join("disk.003"), b"!!").unwrap();
    // lookalikes that must NOT join the set
    std::fs::write(dir.join("disk.extra.004"), b"nope").unwrap();
    std::fs::write(dir.join("disk.001.txt"), b"nope").unwrap();
    std::fs::write(dir.join("other.001"), b"nope").unwrap();

    assert!(detect_split(dir.join("disk.001")));
    // open_split accepts any member, not just the first
    let c = ConcatSource::open_split(dir.join("disk.002")).unwrap();
    assert_eq!(c.segment_count(), 3);
    assert_eq!(c.len(), 14);
    assert_eq!(c.read_slice(0, 14).unwrap(), b"hello world!!!");
    // cross-segment read
    assert_eq!(c.read_slice(4, 8).unwrap(), b"o world!");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn split_raw_alpha_and_underscore_segments() {
    let dir = split_dir("alpha");
    std::fs::write(dir.join("img_ab"), b"AB").unwrap();
    std::fs::write(dir.join("img_aa"), b"aa").unwrap();
    std::fs::write(dir.join("img_ac"), b"AC").unwrap();
    assert!(detect_split(dir.join("img_aa")));
    let c = ConcatSource::open_split(dir.join("img_aa")).unwrap();
    assert_eq!(c.read_slice(0, 6).unwrap(), b"aaABAC");

    // underscore + digits
    let dir2 = split_dir("und");
    std::fs::write(dir2.join("raw_02"), b"22").unwrap();
    std::fs::write(dir2.join("raw_01"), b"11").unwrap();
    assert!(detect_split(dir2.join("raw_01")));
    let c = ConcatSource::open_split(dir2.join("raw_01")).unwrap();
    assert_eq!(c.read_slice(0, 4).unwrap(), b"1122");
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&dir2).ok();
}

#[test]
fn split_raw_detection_edges() {
    let dir = split_dir("edges");
    // a lone segment is a valid name but detect_split wants ≥2 members
    std::fs::write(dir.join("solo.001"), b"x").unwrap();
    assert!(!detect_split(dir.join("solo.001")));
    // open_split still opens it (a one-part concat is harmless)
    let c = ConcatSource::open_split(dir.join("solo.001")).unwrap();
    assert_eq!(c.read_slice(0, 1).unwrap(), b"x");

    // no recognised suffix → InvalidInput, detect → false
    std::fs::write(dir.join("plain.raw"), b"y").unwrap();
    std::fs::write(dir.join("plain2.raw"), b"y").unwrap();
    assert!(!detect_split(dir.join("plain.raw")));
    match ConcatSource::open_split(dir.join("plain.raw")) {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput),
        Ok(_) => panic!("plain.raw must not open as a split image"),
    }

    // recognised name but file absent → NotFound
    match ConcatSource::open_split(dir.join("gone.001")) {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        Ok(_) => panic!("gone.001 must not open"),
    }
    assert!(!detect_split(dir.join("gone.001")));

    // EWF names must not be mistaken for split segments
    std::fs::write(dir.join("case.E01"), b"e").unwrap();
    std::fs::write(dir.join("case.E02"), b"e").unwrap();
    assert!(!detect_split(dir.join("case.E01")));
    std::fs::remove_dir_all(&dir).ok();
}
