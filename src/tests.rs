//! Unit tests for the individual decoders. Full synthetic-image corpora and
//! round-trip tests live in `tests/` (integration tests).

use std::sync::Arc;

use sutram_io::ByteSource;

use crate::fbe::{find_crypt_footer, CRYPT_FOOTER_OFFSET, CRYPT_FTR_MAGIC};
use crate::names::{classify_name, has_slot_suffix, split_slot_suffix, PartitionRole};
use crate::sparse::{is_android_sparse, open_sparse};
use crate::vbmeta::{self, DmVerityState, VbmetaDescriptor};

fn src(v: Vec<u8>) -> Arc<dyn ByteSource> {
    Arc::new(v)
}

fn w16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn w32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn w32be(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_be_bytes());
}
fn w64be(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_be_bytes());
}

// --- names ---------------------------------------------------------------

#[test]
fn slot_suffix_split() {
    assert_eq!(split_slot_suffix("boot_a"), ("boot", Some('a')));
    assert_eq!(split_slot_suffix("system_b"), ("system", Some('b')));
    assert_eq!(split_slot_suffix("vendor_boot"), ("vendor_boot", None));
    assert_eq!(split_slot_suffix("init_boot"), ("init_boot", None));
    assert_eq!(split_slot_suffix("a"), ("a", None));
    assert_eq!(split_slot_suffix("_a"), ("_a", None)); // len < 3 guard
    assert!(has_slot_suffix("userdata_b"));
    assert!(!has_slot_suffix("persist"));
}

#[test]
fn name_classification() {
    assert_eq!(classify_name("boot_a"), PartitionRole::Boot);
    assert_eq!(classify_name("system_ext"), PartitionRole::System);
    assert_eq!(classify_name("vendor"), PartitionRole::Vendor);
    assert_eq!(classify_name("vendor_dlkm"), PartitionRole::Dlkm);
    assert_eq!(classify_name("userdata"), PartitionRole::Userdata);
    assert_eq!(classify_name("super"), PartitionRole::Super);
    assert_eq!(classify_name("metadata"), PartitionRole::Metadata);
    assert_eq!(classify_name("persist"), PartitionRole::Persist);
    assert_eq!(classify_name("vbmeta_b"), PartitionRole::Vbmeta);
    assert_eq!(classify_name("modemst1"), PartitionRole::Modem);
    assert_eq!(classify_name("xbl_config"), PartitionRole::Bootloader);
    assert_eq!(classify_name("odm_stuff"), PartitionRole::Other);
}

// --- sparse --------------------------------------------------------------

fn sparse_image(chunks: &[(u16, u32, &[u8])]) -> Vec<u8> {
    // chunks: (type, blocks, payload-after-12-byte-header)
    let mut img = Vec::new();
    let mut hdr = [0u8; 28];
    w32(&mut hdr, 0, 0xED26_FF3A);
    w16(&mut hdr, 4, 1);
    w16(&mut hdr, 6, 0);
    w16(&mut hdr, 8, 28);
    w16(&mut hdr, 10, 12);
    w32(&mut hdr, 12, 4096);
    w32(&mut hdr, 16, chunks.iter().map(|c| c.1).sum::<u32>());
    w32(&mut hdr, 20, chunks.len() as u32);
    img.extend_from_slice(&hdr);
    for (ty, blocks, payload) in chunks {
        let mut ch = [0u8; 12];
        w16(&mut ch, 0, *ty);
        w32(&mut ch, 4, *blocks);
        w32(&mut ch, 8, 12 + payload.len() as u32);
        img.extend_from_slice(&ch);
        img.extend_from_slice(payload);
    }
    img
}

#[test]
fn sparse_detect_and_decode() {
    let data = vec![0xAB; 4096];
    let fill = 0xDEADBEEFu32.to_le_bytes();
    let img = sparse_image(&[
        (0xCAC1, 1, &data), // RAW 1 block
        (0xCAC2, 2, &fill), // FILL 2 blocks
        (0xCAC3, 1, &[]),   // DONT_CARE 1 block
    ]);
    assert!(is_android_sparse(&img.as_slice()));
    let sf = open_sparse(src(img)).unwrap();
    assert_eq!(sf.len(), 4 * 4096);
    assert_eq!(sf.read_slice(0, 4).unwrap(), &[0xAB; 4]);
    assert_eq!(sf.read_slice(4096, 4).unwrap(), &fill);
    assert_eq!(sf.read_slice(3 * 4096, 4).unwrap(), &[0; 4]);
}

#[test]
fn sparse_truncated_data_extent() {
    // RAW chunk declares 2 blocks but the file ends after one. Lenient
    // contract (sutram-io): the missing tail zero-fills rather than erroring
    // or leaking the following chunk's bytes.
    let data = vec![0xAB; 4096];
    let mut img = sparse_image(&[(0xCAC1, 2, &data)]);
    img.truncate(28 + 12 + 4096);
    let sf = open_sparse(src(img)).unwrap();
    assert_eq!(sf.read_slice(0, 4).unwrap(), &[0xAB; 4]);
    assert_eq!(sf.read_slice(4096, 4).unwrap(), &[0; 4]);
}

#[test]
fn sparse_bad_magic() {
    let img = vec![0u8; 64];
    assert!(!is_android_sparse(&img.as_slice()));
    assert!(open_sparse(src(img)).is_err());
}

// --- LP metadata ---------------------------------------------------------

#[test]
fn lp_geometry_rejects_garbage() {
    let img = vec![0u8; 8192 * 2];
    assert!(crate::lp::read_geometry(&img.as_slice()).is_err());
}

#[test]
fn lp_geometry_parses() {
    let mut img = vec![0u8; 64 * 1024];
    let mut geo = [0u8; 52];
    w32(&mut geo, 0, crate::lp::LP_GEOMETRY_MAGIC);
    w32(&mut geo, 4, 52);
    w32(&mut geo, 40, 65536); // metadata_max_size
    w32(&mut geo, 44, 2); // slot_count
    w32(&mut geo, 48, 4096); // logical_block_size
    let mut tmp = geo;
    tmp[8..40].fill(0);
    let sum = crate::sha256::sha256(&tmp);
    geo[8..40].copy_from_slice(&sum);
    img[0x1000..0x1000 + 52].copy_from_slice(&geo);

    let g = crate::lp::read_geometry(&img.as_slice()).unwrap();
    assert!(g.checksum_ok);
    assert_eq!(g.metadata_max_size, 65536);
    assert_eq!(g.metadata_slot_count, 2);
    assert_eq!(g.offset, 0x1000);
    // primary slot at 0x3000, backups at 0x3000+2*65536
    assert_eq!(
        crate::lp::total_metadata_size(&g),
        0x1000 + (0x1000 + 65536 * 2) * 2
    );
}

// --- vbmeta ---------------------------------------------------------------

fn vbmeta_image(flags: u32, rollback: u64, descriptors: &[u8]) -> Vec<u8> {
    let aux_size = descriptors.len().next_multiple_of(64) as u64;
    let mut aux = vec![0u8; aux_size as usize];
    aux[..descriptors.len()].copy_from_slice(descriptors);
    let mut hdr = [0u8; 256];
    hdr[0..4].copy_from_slice(b"AVB0");
    w32be(&mut hdr, 4, 1);
    w32be(&mut hdr, 8, 0);
    w64be(&mut hdr, 12, 0); // auth block size
    w64be(&mut hdr, 20, aux_size);
    w32be(&mut hdr, 28, 0); // algorithm_type: none
    w64be(&mut hdr, 96, 0); // descriptors_offset
    w64be(&mut hdr, 104, descriptors.len() as u64);
    w64be(&mut hdr, 112, rollback);
    w32be(&mut hdr, 120, flags);
    w32be(&mut hdr, 124, 0);
    hdr[128..128 + 13].copy_from_slice(b"avbtool 1.2.3");
    let mut img = hdr.to_vec();
    img.extend_from_slice(&aux);
    img
}

fn hashtree_descriptor(name: &str) -> Vec<u8> {
    let fixed = 104usize;
    let name_b = name.as_bytes();
    let payload = fixed + name_b.len();
    let padded = payload.next_multiple_of(8);
    let mut d = Vec::with_capacity(16 + padded);
    d.extend_from_slice(&1u64.to_be_bytes()); // tag HASHTREE
    d.extend_from_slice(&(padded as u64).to_be_bytes());
    let mut f = vec![0u8; padded];
    w32be(&mut f, 0, 1); // dm_verity_version
    f[4..12].copy_from_slice(&0x100000u64.to_be_bytes()); // image_size
    f[12..20].copy_from_slice(&0x80000u64.to_be_bytes()); // tree_offset
    f[20..28].copy_from_slice(&0x20000u64.to_be_bytes()); // tree_size
    w32be(&mut f, 28, 4096); // data_block_size
    w32be(&mut f, 32, 4096); // hash_block_size
    f[56..56 + 6].copy_from_slice(b"sha256");
    w32be(&mut f, 88, name_b.len() as u32);
    w32be(&mut f, 92, 32); // salt_len
    w32be(&mut f, 96, 32); // root_digest_len
    f[fixed..fixed + name_b.len()].copy_from_slice(name_b);
    d.extend_from_slice(&f);
    d
}

#[test]
fn vbmeta_header_and_hashtree() {
    let desc = hashtree_descriptor("system");
    let img = vbmeta_image(0, 7, &desc);
    let info = vbmeta::parse(&img.as_slice()).unwrap();
    assert_eq!(info.libavb_version, (1, 0));
    assert_eq!(info.rollback_index, 7);
    assert_eq!(info.dm_verity, DmVerityState::Enabled);
    assert_eq!(info.release_string, "avbtool 1.2.3");
    match &info.descriptors[0] {
        VbmetaDescriptor::Hashtree {
            partition_name,
            hash_algorithm,
            tree_size,
            ..
        } => {
            assert_eq!(partition_name, "system");
            assert_eq!(hash_algorithm, "sha256");
            assert_eq!(*tree_size, 0x20000);
        }
        other => panic!("unexpected descriptor {other:?}"),
    }
}

#[test]
fn vbmeta_disabled_flags() {
    let img = vbmeta_image(0b11, 0, &[]);
    let info = vbmeta::parse(&img.as_slice()).unwrap();
    assert_eq!(info.dm_verity, DmVerityState::VerificationDisabled);
    let img2 = vbmeta_image(0b01, 0, &[]);
    assert_eq!(
        vbmeta::parse(&img2.as_slice()).unwrap().dm_verity,
        DmVerityState::HashtreeDisabled
    );
}

#[test]
fn vbmeta_footer_path() {
    // boot-ish image: 0x4000 data, vbmeta blob, footer at end-64.
    let vb = vbmeta_image(0, 3, &[]);
    let mut img = vec![0u8; 0x4000];
    let voff = img.len() as u64;
    img.extend_from_slice(&vb);
    let mut footer = [0u8; 64];
    footer[0..4].copy_from_slice(b"AVBf");
    w32be(&mut footer, 4, 1);
    w64be(&mut footer, 12, voff); // original_image_size
    w64be(&mut footer, 20, voff); // vbmeta_offset
    w64be(&mut footer, 28, vb.len() as u64);
    img.extend_from_slice(&footer);

    let info = vbmeta::find_vbmeta(&img.as_slice()).unwrap();
    assert_eq!(info.rollback_index, 3);
    let f = info.footer.unwrap();
    assert_eq!(f.vbmeta_offset, voff);
    assert_eq!(f.footer_offset, img.len() as u64 - 64);
}

// --- crypto footer --------------------------------------------------------

#[test]
fn crypt_footer_detected() {
    let mut img = vec![0u8; 0x10000];
    let off = img.len() - CRYPT_FOOTER_OFFSET as usize;
    let mut ftr = [0u8; 128];
    w32(&mut ftr, 0, CRYPT_FTR_MAGIC);
    w16(&mut ftr, 4, 1);
    w16(&mut ftr, 6, 3);
    w32(&mut ftr, 8, 128);
    w32(&mut ftr, 12, 0);
    w32(&mut ftr, 16, 16);
    w32(&mut ftr, 20, 1); // crypt_type = default
    let cipher = b"aes-cbc-essiv:sha256";
    ftr[36..36 + cipher.len()].copy_from_slice(cipher);
    img[off..off + 128].copy_from_slice(&ftr);
    let f = find_crypt_footer(&img.as_slice()).unwrap();
    assert_eq!(f.offset, off as u64);
    assert_eq!(f.crypt_type, 1);
    assert_eq!(f.crypto_type_name, "aes-cbc-essiv:sha256");

    // no magic → None
    let clean = vec![0u8; 0x10000];
    assert!(find_crypt_footer(&clean.as_slice()).is_none());
}
