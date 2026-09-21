//! Mutated-image tests: LP table-descriptor corruption, extent target
//! edge cases, GPT/layout degradation paths and hostile inputs.

mod common;

use std::io;
use std::sync::Arc;

use common::*;
use sutram_io::ByteSource;
use sutram_part::*;

fn arc(v: Vec<u8>) -> Arc<dyn ByteSource> {
    Arc::new(v)
}

/// ByteSource that fails reads whose range intersects `fail_at`.
struct FailAt {
    inner: Vec<u8>,
    fail_at: u64,
}

impl ByteSource for FailAt {
    fn len(&self) -> u64 {
        self.inner.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset == self.fail_at {
            return Err(io::Error::other("injected read failure"));
        }
        self.inner.as_slice().read_at(offset, buf)
    }
}

// ---------------------------------------------------------------------------
// liblp table / header error arms (each corruption lands in every slot copy
// so no fallback can rescue the parse — except where noted).
// ---------------------------------------------------------------------------

/// Byte offset of slot `slot`'s primary metadata blob in the builder layout.
const SLOT0: usize = 0x3000;
const SLOT1: usize = 0x3000 + LP_MAX_SIZE as usize;
const BACK0: usize = 0x3000 + LP_MAX_SIZE as usize * LP_SLOT_COUNT as usize;
const BACK1: usize = BACK0 + LP_MAX_SIZE as usize;

fn sample() -> Vec<u8> {
    super_img(
        &[
            SuperPart {
                name: "system_a",
                group: "system",
                attrs: 0,
                data: vec![0xAAu8; 4096],
            },
            SuperPart {
                name: "vendor_a",
                group: "vendor",
                attrs: 0,
                data: vec![0xBBu8; 2048],
            },
        ],
        None,
    )
}

/// Patch a field inside *all four* metadata copies at blob-relative `off`.
fn patch_all_slots(img: &mut [u8], off: usize, f: impl Fn(&mut [u8])) {
    for base in [SLOT0, SLOT1, BACK0, BACK1] {
        f(&mut img[base + off..]);
    }
}

#[test]
fn lp_table_descriptor_error_arms() {
    // partitions: implausible entry count.
    let mut img = sample();
    patch_all_slots(&mut img, 84, |b| w32(b, 0, 999_999));
    assert!(read_metadata(&arc(img)).is_err());
    // partitions: entry_size below the floor.
    let mut img = sample();
    patch_all_slots(&mut img, 88, |b| w32(b, 0, 8));
    assert!(read_metadata(&arc(img)).is_err());
    // partitions: table offset runs past tables_size.
    let mut img = sample();
    patch_all_slots(&mut img, 80, |b| w32(b, 0, 0xFFFFF0));
    assert!(read_metadata(&arc(img)).is_err());
    // Same three arms on the other descriptor slots.
    for (desc, name) in [(92usize, "extents"), (104, "groups"), (116, "bdev")] {
        let mut img = sample();
        patch_all_slots(&mut img, desc + 4, |b| w32(b, 0, 999_999));
        assert!(read_metadata(&arc(img)).is_err(), "{name} count");
        let mut img = sample();
        patch_all_slots(&mut img, desc + 8, |b| w32(b, 0, 2));
        assert!(read_metadata(&arc(img)).is_err(), "{name} esz");
        let mut img = sample();
        patch_all_slots(&mut img, desc, |b| w32(b, 0, 0xFFFFF0));
        assert!(read_metadata(&arc(img)).is_err(), "{name} off");
    }
    // A descriptor error in the primary copy only → the backup wins and the
    // parse still succeeds (with the backup warning).
    let mut img = sample();
    w32(&mut img[SLOT0 + 84..], 0, 999_999);
    let md = read_metadata(&arc(img)).unwrap();
    assert!(md.from_backup);
    assert!(md
        .warnings
        .iter()
        .any(|w| w.contains("backup copy")));
}

#[test]
fn lp_header_error_arms() {
    // No LP magic in any slot copy.
    let mut img = sample();
    patch_all_slots(&mut img, 0, |b| w32(b, 0, 0xDEAD_BEEF));
    assert!(read_metadata(&arc(img)).is_err());
    // Implausible header_size.
    let mut img = sample();
    patch_all_slots(&mut img, 8, |b| w32(b, 0, 64));
    assert!(read_metadata(&arc(img)).is_err());
    // header+tables past metadata_max_size.
    let mut img = sample();
    patch_all_slots(&mut img, 44, |b| w32(b, 0, 0xFFFFF0));
    assert!(read_metadata(&arc(img)).is_err());
    // tables_size == 0.
    let mut img = sample();
    patch_all_slots(&mut img, 44, |b| w32(b, 0, 0));
    assert!(read_metadata(&arc(img)).is_err());
    // minor version above the known max → warning, still parses.
    let mut img = sample();
    patch_all_slots(&mut img, 6, |b| w16(b, 0, 99));
    let md = read_metadata(&arc(img)).unwrap();
    assert!(md.warnings.iter().any(|w| w.contains("minor version")));
    // v1.0-sized header (128 B) → flags field out of range, parsed as 0.
    let mut img = sample();
    patch_all_slots(&mut img, 8, |b| w32(b, 0, 128));
    let md = read_metadata(&arc(img)).unwrap();
    assert_eq!(md.header.flags, 0);
    // Broken primary header → backup copy, reported.
    let mut img = sample();
    w32(&mut img[SLOT0..], 0, 0xDEAD_BEEF);
    let md = read_metadata(&arc(img)).unwrap();
    assert!(md.from_backup);
}

#[test]
fn lp_read_io_arms() {
    let img = sample();
    // Primary geometry read fails with Io → the error propagates (the
    // backup copy only rescues *parse* failures, not read failures).
    let src = FailAt {
        inner: img.clone(),
        fail_at: 0x1000,
    };
    assert!(read_geometry(&src).is_err());
    // Backup geometry read fails after a bad primary → error.
    let mut bad = img.clone();
    bad[0x1000..0x1000 + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let src = FailAt {
        inner: bad,
        fail_at: 0x2000,
    };
    assert!(read_geometry(&src).is_err());
    // Metadata-slot read failure → all slots fail.
    let src = FailAt {
        inner: img,
        fail_at: SLOT0 as u64,
    };
    // slot0 primary fails, its backup parses → mount still ok.
    let md = read_metadata(&src).unwrap();
    assert!(md.from_backup);
}

#[test]
fn lp_extent_target_arms() {
    let img = sample();
    // Extent table of slot 0 primary: first partition's extent at
    // tables+parts(104). Patch target_source → unknown block device index.
    let ext0 = SLOT0 + 256 + 104;
    let mut t = img.clone();
    w32(&mut t[ext0 + 20..], 0, 5); // target_source = 5 (no such bdev)
    let (parts, warns) = logical_partitions_verbose(arc(t)).unwrap();
    assert!(warns.iter().any(|w| w.contains("unknown block device")));
    assert_eq!(parts[0].meta.get("external_extents").map(String::as_str), Some("true"));

    // Unknown extent target_type → hole + warning.
    let mut t = img.clone();
    w32(&mut t[ext0 + 8..], 0, 7);
    let (_parts, warns) = logical_partitions_verbose(arc(t)).unwrap();
    assert!(warns.iter().any(|w| w.contains("target_type")), "{warns:?}");

    // Extent end past the declared block-device size → warning.
    // bdev row sits at tables + parts(2*52=104) + ext(2*24=48) +
    // groups(2*48=96) = +248; its size field is at +16.
    let bdev0 = SLOT0 + 256 + 248;
    let mut t = img.clone();
    w64(&mut t[bdev0 + 16..], 0, 512); // device only 512 B
    let (_parts, warns) = logical_partitions_verbose(arc(t)).unwrap();
    assert!(warns.iter().any(|w| w.contains("block device size")), "{warns:?}");

    // Second block device + extent targeting it → named-device warning.
    let mut t = img.clone();
    w32(&mut t[SLOT0 + 116 + 4..], 0, 2); // bdev num = 2
    let cur = u32::from_le_bytes(t[SLOT0 + 44..SLOT0 + 48].try_into().unwrap());
    w64(&mut t[SLOT0 + 44..], 0, (cur + 64) as u64);
    let bdev1 = bdev0 + 64;
    w64(&mut t[bdev1..], 0, LP_FIRST_SECTOR);
    w64(&mut t[bdev1 + 16..], 0, 1 << 20);
    t[bdev1 + 24..bdev1 + 24 + 7].copy_from_slice(b"lun_two");
    w32(&mut t[ext0 + 20..], 0, 1); // target_source = 1 → the second LUN
    let (parts, warns) = logical_partitions_verbose(arc(t)).unwrap();
    assert!(warns.iter().any(|w| w.contains("lun_two")), "{warns:?}");
    assert_eq!(parts[0].meta.get("external_extents").map(String::as_str), Some("true"));

    // Slot-suffixed partition attribute → `_a` appended to the name.
    let mut t = img.clone();
    w32(&mut t[SLOT0 + 256 + 36..], 0, 2); // partition 0 attrs |= SLOT_SUFFIXED
    let (parts, _) = logical_partitions_verbose(arc(t)).unwrap();
    assert!(parts.iter().any(|p| p.name.ends_with("_a")), "{:?}", parts.iter().map(|p| &p.name).collect::<Vec<_>>());

    // The simple wrapper drops the warnings.
    assert!(!logical_partitions(arc(img)).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Layout-layer degradation arms
// ---------------------------------------------------------------------------

#[test]
fn analyze_sparse_header_error() {
    // Sparse magic with a zeroed rest → header validation fails → Err.
    let mut img = vec![0u8; 4096];
    img[0..4].copy_from_slice(&0xED26_FF3Au32.to_le_bytes());
    assert!(analyze(arc(img)).is_err());
}

#[test]
fn analyze_gpt_partition_past_end_skipped() {
    let mut img = gpt_img(&[GptPart {
        name: "boot",
        type_guid: test_guid(1),
        data: vec![0u8; 4096],
    }]);
    // Rewrite the entry's LBAs to a valid-ordered range that maps past
    // the image end → OffsetView fails → "skipped" warning.
    w64(&mut img, 2 * 512 + 32, 0x100000);
    w64(&mut img, 2 * 512 + 40, 0x100010);
    let layout = analyze(arc(img)).unwrap();
    assert!(layout
        .warnings
        .iter()
        .any(|w| w.contains("skipped")), "{:?}", layout.warnings);
}

#[test]
fn analyze_vbmeta_partition_parse_error() {
    let img = gpt_img(&[GptPart {
        name: "vbmeta",
        type_guid: test_guid(2),
        data: vec![0xCCu8; 4096], // garbage, not AVB0
    }]);
    let layout = analyze(arc(img)).unwrap();
    assert!(layout.vbmeta.is_none());
    assert!(layout
        .warnings
        .iter()
        .any(|w| w.contains("vbmeta partition")), "{:?}", layout.warnings);
}

#[test]
fn analyze_boot_embedded_vbmeta_and_dm_verity() {
    // boot partition with a vbmeta blob at its tail (AVBf footer path) whose
    // flags disable verification → "verified boot weakened" warning.
    let vb = vbmeta_blob(3, 7, &kernel_cmdline_desc("androidboot.x=1"));
    let boot = boot_img_with_vbmeta(&vb);
    let img = gpt_img(&[
        GptPart {
            name: "boot_a",
            type_guid: test_guid(3),
            data: boot,
        },
        GptPart {
            name: "userdata",
            type_guid: test_guid(4),
            data: vec![0u8; 4096],
        },
    ]);
    let layout = analyze(arc(img)).unwrap();
    assert!(layout.vbmeta.is_some());
    assert!(layout
        .warnings
        .iter()
        .any(|w| w.contains("dm-verity")), "{:?}", layout.warnings);
}

#[test]
fn analyze_super_partition_with_broken_lp() {
    // A `super` GPT partition that holds garbage → LP expansion warning.
    let img = gpt_img(&[GptPart {
        name: "super",
        type_guid: test_guid(5),
        data: vec![0x33u8; 0x30000],
    }]);
    let layout = analyze(arc(img)).unwrap();
    assert!(layout
        .warnings
        .iter()
        .any(|w| w.contains("no readable LP metadata")), "{:?}", layout.warnings);
}

#[test]
fn analyze_super_partition_expansion_warnings() {
    // `super` partition holding a real super image whose geometry checksum
    // is damaged → LP warnings surface prefixed with the parent name.
    let inner = super_img(
        &[SuperPart {
            name: "system_a",
            group: "system",
            attrs: 0,
            data: vec![0xAAu8; 1024],
        }],
        None,
    );
    let mut inner = inner;
    inner[0x1008] ^= 0xFF; // break primary geometry checksum
    inner[0x2008] ^= 0xFF; // and the backup's
    let img = gpt_img(&[GptPart {
        name: "super",
        type_guid: test_guid(6),
        data: inner,
    }]);
    let layout = analyze(arc(img)).unwrap();
    assert!(layout
        .warnings
        .iter()
        .any(|w| w.contains("super: LP") || w.contains("LP geometry")), "{:?}", layout.warnings);
    assert!(layout
        .partitions
        .iter()
        .any(|p| p.meta.contains_key("nested_in")));
    assert!(layout
        .partitions
        .iter()
        .any(|p| p.meta.contains_key("parent_offset")));
}

#[test]
fn analyze_raw_with_magic_hint() {
    // A raw blob with a recognisable signature → detected_magic meta.
    let mut img = vec![0u8; 8192];
    img[..4].copy_from_slice(b"PK\x03\x04");
    let layout = analyze(arc(img)).unwrap();
    assert!(matches!(layout.container, ContainerKind::Raw));
    assert_eq!(
        layout.partitions[0].meta.get("detected_magic").map(String::as_str),
        Some("ZIP archive")
    );
}

#[test]
fn analyze_partition_table_io_error() {
    // Sector-0 read fails → partitions() errors → Raw with a warning.
    let src = FailAt {
        inner: vec![0u8; 8192],
        fail_at: 0,
    };
    let layout = analyze(Arc::new(src)).unwrap();
    assert!(matches!(layout.container, ContainerKind::Raw));
    assert!(layout
        .warnings
        .iter()
        .any(|w| w.contains("partition table unreadable")));
}

#[test]
fn analyze_container_depth_cap() {
    // Six nested sparse images → deeper than MAX_CONTAINER_DEPTH.
    let mut img = as_sparse(&[0u8; 4096], 4096);
    for _ in 0..6 {
        img = as_sparse(&img, 4096);
    }
    assert!(analyze(arc(img)).is_err());
}

#[test]
fn crypt_footer_and_metadata_flags() {
    // userdata partition with a crypt_ftr + a metadata partition → both
    // crypto findings reported.
    let mut userdata = vec![0u8; 0x8000];
    with_crypt_footer(&mut userdata, 1, "aes-256-xts");
    let img = gpt_img(&[
        GptPart {
            name: "userdata",
            type_guid: test_guid(7),
            data: userdata,
        },
        GptPart {
            name: "metadata",
            type_guid: test_guid(8),
            data: vec![0u8; 4096],
        },
    ]);
    let layout = analyze(arc(img)).unwrap();
    assert_eq!(layout.crypto.len(), 2);
    assert!(layout.crypto.iter().any(|c| matches!(c.kind, CryptoKind::CryptFooter)));
    assert!(layout.crypto.iter().any(|c| matches!(c.kind, CryptoKind::MetadataPartition)));
}
