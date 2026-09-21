//! Unit tests for the individual decoders. Full synthetic-image corpora and
//! round-trip tests live in `tests/` (integration tests).

use std::sync::Arc;

use sutram_io::ByteSource;

use crate::fbe::{find_crypt_footer, CRYPT_FOOTER_OFFSET, CRYPT_FTR_MAGIC};
use crate::names::{classify_name, has_slot_suffix, split_slot_suffix, PartitionRole};
use crate::sparse::{inspect_sparse, is_android_sparse, open_sparse};
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
    assert!(has_slot_suffix("Boot_A")); // case-insensitive slot letter
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
    // Vendor case variants still classify (lower-then-split).
    assert_eq!(classify_name("Boot_A"), PartitionRole::Boot);
    assert_eq!(classify_name("SUPER"), PartitionRole::Super);
    assert_eq!(classify_name("UserData"), PartitionRole::Userdata);
    assert_eq!(classify_name("vbmeta_system"), PartitionRole::Vbmeta);
    assert_eq!(classify_name("preloader_a"), PartitionRole::Bootloader);
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

#[test]
fn sparse_header_field_validation() {
    // blk_sz = 0 → Corrupt (division-free decode, but nonsense geometry).
    let mut img = sparse_image(&[(0xCAC3, 1, &[])]);
    img[12..16].copy_from_slice(&0u32.to_le_bytes());
    assert!(open_sparse(src(img)).is_err());

    // chunk_hdr_sz < 12 → Corrupt.
    let mut img = sparse_image(&[(0xCAC3, 1, &[])]);
    img[10..12].copy_from_slice(&8u16.to_le_bytes());
    assert!(open_sparse(src(img)).is_err());

    // file_hdr_sz < 28 → Corrupt.
    let mut img = sparse_image(&[(0xCAC3, 1, &[])]);
    img[8..10].copy_from_slice(&16u16.to_le_bytes());
    assert!(open_sparse(src(img)).is_err());

    // Absurd blk_sz (> 16 MiB) → Corrupt.
    let mut img = sparse_image(&[(0xCAC3, 1, &[])]);
    img[12..16].copy_from_slice(&(1u32 << 25).to_le_bytes());
    assert!(open_sparse(src(img)).is_err());
}

#[test]
fn sparse_chunk_payload_mismatch_warns() {
    // RAW chunk declares 2 output blocks but total_sz covers only the
    // header — the extent maps whatever follows. Must be flagged.
    let mut img = Vec::new();
    let mut hdr = [0u8; 28];
    w32(&mut hdr, 0, 0xED26_FF3A);
    w16(&mut hdr, 8, 28);
    w16(&mut hdr, 10, 12);
    w32(&mut hdr, 12, 4096);
    w32(&mut hdr, 16, 2);
    w32(&mut hdr, 20, 1);
    img.extend_from_slice(&hdr);
    let mut ch = [0u8; 12];
    w16(&mut ch, 0, 0xCAC1);
    w32(&mut ch, 4, 2); // 2 blocks out
    w32(&mut ch, 8, 12); // but no payload
    img.extend_from_slice(&ch);
    img.extend_from_slice(&vec![0xAA; 8192]); // bytes exist, not declared

    let (sf, _h, warnings) = inspect_sparse(src(img)).unwrap();
    assert_eq!(sf.len(), 8192);
    assert!(warnings.iter().any(|w| w.contains("non-payload")));
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
    // avbtool layout: 104 bytes of fields + reserved[60], then
    // partition_name/salt/root_digest at offset 164.
    let fixed = 164usize;
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

/// PROPERTY descriptor — AvbPropertyDescriptor: key_num_bytes u64 @0,
/// value_num_bytes u64 @8, then key+NUL then value+NUL at offset 16.
fn property_descriptor(key: &str, value: &[u8]) -> Vec<u8> {
    let payload = 16 + key.len() + 1 + value.len() + 1;
    let padded = payload.next_multiple_of(8);
    let mut d = Vec::with_capacity(16 + padded);
    d.extend_from_slice(&0u64.to_be_bytes()); // tag PROPERTY
    d.extend_from_slice(&(padded as u64).to_be_bytes());
    let mut f = vec![0u8; padded];
    w64be(&mut f, 0, key.len() as u64);
    w64be(&mut f, 8, value.len() as u64);
    f[16..16 + key.len()].copy_from_slice(key.as_bytes());
    let voff = 16 + key.len() + 1;
    f[voff..voff + value.len()].copy_from_slice(value);
    d.extend_from_slice(&f);
    d
}

/// HASH descriptor — AvbHashDescriptor: fixed 116 bytes (56 fields +
/// reserved[60]), then name/salt/digest at offset 116.
fn hash_descriptor(name: &str) -> Vec<u8> {
    let fixed = 116usize;
    let name_b = name.as_bytes();
    let payload = fixed + name_b.len();
    let padded = payload.next_multiple_of(8);
    let mut d = Vec::with_capacity(16 + padded);
    d.extend_from_slice(&2u64.to_be_bytes()); // tag HASH
    d.extend_from_slice(&(padded as u64).to_be_bytes());
    let mut f = vec![0u8; padded];
    w64be(&mut f, 0, 0x3000); // image_size
    f[8..8 + 6].copy_from_slice(b"sha256");
    w32be(&mut f, 40, name_b.len() as u32);
    w32be(&mut f, 44, 4); // salt_len
    w32be(&mut f, 48, 32); // digest_len
    f[fixed..fixed + name_b.len()].copy_from_slice(name_b);
    d.extend_from_slice(&f);
    d
}

#[test]
fn vbmeta_property_descriptor() {
    // Regression: property lengths are u64 and data starts at offset 16 —
    // an earlier build read u32s at 0/4 and silently produced empty keys.
    let desc = property_descriptor("com.android.build.system.fingerprint", b"google/blueline");
    let img = vbmeta_image(0, 0, &desc);
    let info = vbmeta::parse(&img.as_slice()).unwrap();
    match &info.descriptors[0] {
        VbmetaDescriptor::Property { key, value } => {
            assert_eq!(key, "com.android.build.system.fingerprint");
            assert_eq!(value, b"google/blueline");
        }
        other => panic!("unexpected descriptor {other:?}"),
    }
}

#[test]
fn vbmeta_hash_descriptor_name() {
    // Regression: variable data follows the reserved[60] tail — the name
    // must not be read out of the reserved padding.
    let desc = hash_descriptor("vendor");
    let img = vbmeta_image(0, 0, &desc);
    let info = vbmeta::parse(&img.as_slice()).unwrap();
    match &info.descriptors[0] {
        VbmetaDescriptor::Hash {
            partition_name,
            hash_algorithm,
            image_size,
            ..
        } => {
            assert_eq!(partition_name, "vendor");
            assert_eq!(hash_algorithm, "sha256");
            assert_eq!(*image_size, 0x3000);
        }
        other => panic!("unexpected descriptor {other:?}"),
    }
}

#[test]
fn vbmeta_desc_overrun_warns_not_panics() {
    // descriptors region declared larger than the aux block.
    let desc = hashtree_descriptor("system");
    let mut img = vbmeta_image(0, 0, &desc);
    // Patch descriptors_size to exceed aux_size.
    img[104..112].copy_from_slice(&(1u64 << 20).to_be_bytes());
    let info = vbmeta::parse(&img.as_slice()).unwrap();
    assert!(info.descriptors.is_empty());
    assert!(info.warnings.iter().any(|w| w.contains("past auxiliary")));
}

#[test]
fn vbmeta_short_descriptor_header_stops_cleanly() {
    // Trailing garbage shorter than a descriptor header must not panic and
    // (non-zero) must warn.
    let img = vbmeta_image(0, 0, &[0xAA; 8]);
    // aux region is 64 bytes; the last 8 hold junk that isn't a descriptor.
    let info = vbmeta::parse(&img.as_slice()).unwrap();
    assert!(info.descriptors.is_empty());
    assert!(info.warnings.iter().any(|w| w.contains("trailing")));
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

#[test]
fn vbmeta_pubkey_size_field_not_offset() {
    // public_key_size lives at header+64; +72 is public_key_offset.
    // A blob with a key at aux-offset 0 (offset field = 0) must still
    // report has_public_key from the size field.
    let mut img = vbmeta_image(0, 0, &[]);
    w64be(&mut img, 64, 2048); // public_key_size
                               // public_key_offset @72 stays 0.
    let info = vbmeta::parse(&img.as_slice()).unwrap();
    assert!(info.has_public_key);
    // Size 0 with a nonzero offset → no key.
    let mut img = vbmeta_image(0, 0, &[]);
    w64be(&mut img, 72, 4096); // public_key_offset only
    let info = vbmeta::parse(&img.as_slice()).unwrap();
    assert!(!info.has_public_key);
}
