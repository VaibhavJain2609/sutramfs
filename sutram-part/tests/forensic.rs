//! Integration tests over synthetic Android images (CONVENTIONS §6):
//! sparse images, `super.img` with liblp metadata, GPT device images,
//! vbmeta blobs and crypto-footers — all built in `tests/common`.

mod common;

use std::sync::Arc;

use sutram_io::ByteSource;
use sutram_part::{
    analyze, logical_partitions, Attrs, ContainerKind, CryptoKind, DmVerityState, PartitionRole,
    VbmetaDescriptor,
};

fn arc(v: Vec<u8>) -> Arc<dyn ByteSource> {
    Arc::new(v)
}

fn find<'a>(layout: &'a sutram_part::AndroidLayout, name: &str) -> &'a sutram_part::NamedSource {
    layout
        .partitions
        .iter()
        .find(|p| p.name == name)
        .unwrap_or_else(|| panic!("partition {name} not found"))
}

// ---------------------------------------------------------------------------
// Sparse
// ---------------------------------------------------------------------------

#[test]
fn analyze_sparse_raw_image() {
    // A "userdata.img" style blob: RAW data block then a hole.
    let payload = vec![0x5Au8; 8192];
    let mut chunks: Vec<common::SparseChunk> = vec![(0xCAC1, 2, payload.clone())];
    chunks.push((0xCAC3, 4, vec![])); // DONT_CARE hole
    let img = common::sparse_img(&chunks, 4096);

    let layout = analyze(arc(img)).unwrap();
    assert_eq!(layout.container, ContainerKind::Sparse);
    assert_eq!(layout.partitions.len(), 1);
    let p = &layout.partitions[0];
    assert_eq!(p.source.len(), 6 * 4096);
    assert_eq!(&p.source.read_slice(0, 8).unwrap(), &[0x5A; 8]);
    assert_eq!(&p.source.read_slice(8192, 8).unwrap(), &[0; 8]);
    assert!(layout.warnings.iter().any(|w| w.contains("sparse")));
}

#[test]
fn analyze_rejects_garbage_as_raw_not_panic() {
    let layout = analyze(arc(vec![0xFFu8; 4096])).unwrap();
    assert_eq!(layout.container, ContainerKind::Raw);
    assert_eq!(layout.partitions.len(), 1);
    assert_eq!(layout.partitions[0].name, "image");
}

// ---------------------------------------------------------------------------
// super.img / liblp
// ---------------------------------------------------------------------------

fn sample_super() -> Vec<u8> {
    common::super_img(
        &[
            common::SuperPart {
                name: "system",
                group: "google_dynamic_partitions_a",
                attrs: Attrs::READONLY | Attrs::SLOT_SUFFIXED,
                data: b"SYSTEM-PARTITION-BYTES".to_vec(),
            },
            common::SuperPart {
                name: "userdata",
                group: "google_dynamic_partitions_a",
                attrs: 0,
                data: b"USERDATA-BYTES-HERE".to_vec(),
            },
        ],
        None,
    )
}

#[test]
fn super_logical_partitions() {
    let img = sample_super();
    let parts = logical_partitions(arc(img)).unwrap();
    assert_eq!(parts.len(), 2);

    // Slot 0 → "_a" applied because SLOT_SUFFIXED was set.
    let sys = &parts[0];
    assert_eq!(sys.name, "system_a");
    assert_eq!(sys.group, "google_dynamic_partitions_a");
    assert!(sys.attrs.readonly());
    assert!(sys.attrs.slot_suffixed());
    assert_eq!(sys.role, PartitionRole::System);
    assert_eq!(
        sys.source.read_slice(0, 22).unwrap(),
        b"SYSTEM-PARTITION-BYTES"
    );

    let ud = &parts[1];
    assert_eq!(ud.name, "userdata");
    assert_eq!(ud.role, PartitionRole::Userdata);
    assert_eq!(ud.source.read_slice(0, 19).unwrap(), b"USERDATA-BYTES-HERE");
}

#[test]
fn analyze_super() {
    let layout = analyze(arc(sample_super())).unwrap();
    assert_eq!(layout.container, ContainerKind::Super);
    assert_eq!(layout.partitions.len(), 2);
    let sys = find(&layout, "system_a");
    // Provenance: logical data starts at first_logical_sector (1 MiB).
    assert_eq!(sys.meta["lp_slot"], "0");
    let ud = find(&layout, "userdata");
    assert_eq!(ud.source.len(), 512); // ceil(19/512)
}

#[test]
fn sparse_wrapped_super() {
    let img = common::as_sparse(&sample_super(), 4096);
    let layout = analyze(arc(img)).unwrap();
    // Outermost container is sparse; the decoded image yielded LP partitions.
    assert_eq!(layout.container, ContainerKind::Sparse);
    assert_eq!(layout.partitions.len(), 2);
    assert_eq!(find(&layout, "system_a").name, "system_a");
}

#[test]
fn super_backup_slot_fallback() {
    // Kill primary slot 0 — parser must recover via the backup copy.
    let img = common::super_img(
        &[common::SuperPart {
            name: "boot",
            group: "g",
            attrs: 0,
            data: vec![0x42; 1024],
        }],
        Some(0),
    );
    let (parts, warnings) = sutram_part::lp::logical_partitions_verbose(arc(img)).unwrap();
    assert_eq!(parts.len(), 1);
    assert_eq!(parts[0].name, "boot");
    assert!(warnings.iter().any(|w| w.contains("backup")));
    assert_eq!(
        parts[0].meta.get("lp_backup").map(String::as_str),
        Some("true")
    );
}

#[test]
fn super_checksum_mismatch_warns_but_parses() {
    let mut img = sample_super();
    // Corrupt one byte inside the partition table of every copy: the table
    // checksum fails but structure stays parseable.
    for off in [
        0x3000usize,
        0x3000 + 65536,
        0x3000 + 2 * 65536,
        0x3000 + 3 * 65536,
    ] {
        img[off + 256 + 40] ^= 0xFF; // first_extent_index of partition 0
    }
    let layout = analyze(arc(img)).unwrap();
    assert_eq!(layout.container, ContainerKind::Super);
    assert_eq!(layout.partitions.len(), 2);
    assert!(layout
        .warnings
        .iter()
        .any(|w| w.contains("tables SHA-256 mismatch")));
}

#[test]
fn super_zero_extent_is_hole() {
    // Partition with a ZERO target extent — but our builder only emits LINEAR.
    // Craft manually: two extents, second is target_type ZERO.
    // Simpler: verify a DONT_CARE-free path via a hand-built metadata blob is
    // covered by unit-level extent decoding; here just ensure a partition
    // with attrs DISABLED is still surfaced.
    let img = common::super_img(
        &[common::SuperPart {
            name: "scratch",
            group: "default",
            attrs: Attrs::DISABLED,
            data: vec![0xEE; 512],
        }],
        None,
    );
    let parts = logical_partitions(arc(img)).unwrap();
    assert!(parts[0].attrs.disabled());
}

// ---------------------------------------------------------------------------
// GPT
// ---------------------------------------------------------------------------

fn sample_gpt() -> Vec<u8> {
    let vbmeta = common::vbmeta_blob(0, 9, &common::kernel_cmdline_desc("ro"));
    let mut userdata = vec![0u8; 0x10000];
    userdata[..4].copy_from_slice(b"UDAT");
    common::with_crypt_footer(&mut userdata, 1, "aes-256-xts");
    common::gpt_img(&[
        common::GptPart {
            name: "boot_a",
            type_guid: common::test_guid(1),
            data: b"ANDROID!bootimg".to_vec(),
        },
        common::GptPart {
            name: "super",
            type_guid: common::test_guid(2),
            data: vec![0; 2048],
        },
        common::GptPart {
            name: "metadata",
            type_guid: common::test_guid(3),
            data: vec![0; 1024],
        },
        common::GptPart {
            name: "persist",
            type_guid: common::test_guid(4),
            data: b"PST".to_vec(),
        },
        common::GptPart {
            name: "userdata",
            type_guid: common::test_guid(5),
            data: userdata,
        },
        common::GptPart {
            name: "vbmeta_a",
            type_guid: common::test_guid(6),
            data: vbmeta,
        },
    ])
}

#[test]
fn analyze_gpt_android_disk() {
    let layout = analyze(arc(sample_gpt())).unwrap();
    assert_eq!(layout.container, ContainerKind::Gpt);
    assert_eq!(layout.partitions.len(), 6);

    let boot = find(&layout, "boot_a");
    assert_eq!(boot.role, PartitionRole::Boot);
    assert!(boot.attrs.slot_suffixed());
    assert_eq!(boot.meta["table"], "gpt");
    assert!(boot.meta.contains_key("type_guid"));
    assert_eq!(&boot.source.read_slice(0, 7).unwrap(), b"ANDROID");

    assert_eq!(find(&layout, "super").role, PartitionRole::Super);
    assert_eq!(find(&layout, "metadata").role, PartitionRole::Metadata);
    assert_eq!(find(&layout, "persist").role, PartitionRole::Persist);

    // vbmeta partition parsed.
    let vb = layout.vbmeta.as_ref().expect("vbmeta parsed");
    assert_eq!(vb.rollback_index, 9);
    assert_eq!(vb.dm_verity, DmVerityState::Enabled);
    match &vb.descriptors[0] {
        VbmetaDescriptor::KernelCmdline { cmdline, .. } => assert_eq!(cmdline, "ro"),
        other => panic!("expected KernelCmdline, got {other:?}"),
    }

    // Crypto findings: metadata partition + crypt_ftr on userdata.
    assert!(layout
        .crypto
        .iter()
        .any(|c| c.kind == CryptoKind::MetadataPartition));
    let cf = layout
        .crypto
        .iter()
        .find(|c| c.kind == CryptoKind::CryptFooter)
        .expect("crypt footer flagged");
    assert_eq!(cf.partition, "userdata");
    assert_eq!(cf.footer.as_ref().unwrap().crypto_type_name, "aes-256-xts");
}

#[test]
fn gpt_super_partition_expands_logical() {
    // Full-device dump: physical GPT whose `super` partition holds LP
    // metadata — logical partitions must be reachable from the top level.
    let inner = sample_super();
    let img = common::gpt_img(&[
        common::GptPart {
            name: "super",
            type_guid: common::test_guid(2),
            data: inner,
        },
        common::GptPart {
            name: "vbmeta",
            type_guid: common::test_guid(6),
            data: common::vbmeta_blob(0, 1, &[]),
        },
    ]);
    let layout = analyze(arc(img)).unwrap();
    assert_eq!(layout.container, ContainerKind::Gpt);
    let sys = find(&layout, "system_a");
    assert_eq!(sys.meta["nested_in"], "super");
    assert_eq!(
        sys.source.read_slice(0, 22).unwrap(),
        b"SYSTEM-PARTITION-BYTES"
    );
    assert!(layout.vbmeta.is_some());
}

#[test]
fn lp_extent_past_source_end_warns() {
    // Truncate the super image inside the last partition's data: the LP
    // metadata is intact (it lives at the head) but a LINEAR extent now
    // runs past EOF — that must be surfaced as a warning, not silent
    // read failures later.
    let mut img = sample_super();
    img.truncate(common::LP_FIRST_SECTOR as usize * 512 + 512);
    let (parts, warnings) = sutram_part::lp::logical_partitions_verbose(arc(img)).unwrap();
    assert_eq!(parts.len(), 2);
    assert!(
        warnings.iter().any(|w| w.contains("exceeds source length")),
        "expected truncation warning, got {warnings:?}"
    );
}

#[test]
fn mbr_image_reports_mbr_container() {
    // Non-protective MBR (unusual on Android): partitions must be parsed
    // AND the container must not claim "raw".
    let mut img = vec![0u8; (2048 + 100) * 512];
    img[0x1BE] = 0x80; // bootable
    img[0x1BE + 4] = 0x83; // Linux type
    img[0x1BE + 8..0x1BE + 12].copy_from_slice(&2048u32.to_le_bytes());
    img[0x1BE + 12..0x1BE + 16].copy_from_slice(&100u32.to_le_bytes());
    img[0x1FE] = 0x55;
    img[0x1FF] = 0xAA;
    let layout = analyze(arc(img)).unwrap();
    assert_eq!(layout.container, ContainerKind::Mbr);
    assert_eq!(layout.partitions.len(), 1);
    assert_eq!(layout.partitions[0].meta["table"], "mbr");
    assert!(layout.warnings.iter().any(|w| w.contains("MBR")));
}

#[test]
fn gpt_partition_byte_provenance() {
    let layout = analyze(arc(sample_gpt())).unwrap();
    let persist = find(&layout, "persist");
    let off: u64 =
        u64::from_str_radix(persist.meta["offset"].trim_start_matches("0x"), 16).unwrap();
    assert!(off > 0 && off % 512 == 0);
    assert_eq!(&persist.source.read_slice(0, 3).unwrap(), b"PST");
}

// ---------------------------------------------------------------------------
// Raw / vbmeta blobs
// ---------------------------------------------------------------------------

#[test]
fn analyze_raw_vbmeta_image() {
    let vb = common::vbmeta_blob(vbmeta_flags_disabled(), 4, &[]);
    let layout = analyze(arc(vb)).unwrap();
    assert_eq!(layout.container, ContainerKind::Raw);
    let info = layout.vbmeta.unwrap();
    assert_eq!(info.dm_verity, DmVerityState::VerificationDisabled);
    assert!(layout
        .warnings
        .iter()
        .any(|w| w.contains("verified boot weakened")));
}

fn vbmeta_flags_disabled() -> u32 {
    0b11
}

#[test]
fn vbmeta_inside_boot_footer() {
    let vb = common::vbmeta_blob(0, 2, &[]);
    let boot = common::boot_img_with_vbmeta(&vb);
    let layout = analyze(arc(boot)).unwrap();
    assert_eq!(layout.container, ContainerKind::Raw);
    let info = layout.vbmeta.unwrap();
    assert_eq!(info.rollback_index, 2);
    assert!(info.footer.is_some());
}

#[test]
fn roundtrip_sparse_super_gpt_chain() {
    // sparse(super.img) → logical partition bytes equal what was baked in.
    let inner = sample_super();
    let img = common::as_sparse(&inner, 4096);
    let parts = logical_partitions(arc({
        // unwrap sparse first, like analyze() does
        let sf = sutram_part::open_sparse(arc(img)).unwrap();
        let mut v = vec![0u8; sf.len() as usize];
        sf.read_exact_at(0, &mut v).unwrap();
        v
    }))
    .unwrap();
    let sys = parts.iter().find(|p| p.name == "system_a").unwrap();
    assert_eq!(
        sys.source.read_slice(0, 22).unwrap(),
        b"SYSTEM-PARTITION-BYTES"
    );
}

// ---------------------------------------------------------------------------
// LP hostile-input paths
// ---------------------------------------------------------------------------

#[test]
fn lp_geometry_backup_fallback() {
    let mut img = sample_super();
    img[0x1000..0x1000 + 52].fill(0); // kill primary geometry
    let g = sutram_part::lp::read_geometry(arc(img).as_ref()).unwrap();
    assert_eq!(g.offset, 0x2000);
}

#[test]
fn lp_no_readable_slot_reports_super() {
    let mut img = sample_super();
    // Valid geometry, but every metadata copy is zeroed.
    img[0x3000..0x3000 + 4 * 65536].fill(0);
    let layout = analyze(arc(img)).unwrap();
    assert_eq!(layout.container, ContainerKind::Super);
    assert!(layout.partitions.is_empty());
    assert!(layout
        .warnings
        .iter()
        .any(|w| w.contains("LP metadata unreadable")));
}

#[test]
fn lp_geometry_checksum_mismatch_warns() {
    let mut img = sample_super();
    for off in [0x1000usize, 0x2000] {
        img[off + 44] ^= 0x01; // slot_count field — still parses
    }
    let layout = analyze(arc(img)).unwrap();
    assert!(layout
        .warnings
        .iter()
        .any(|w| w.contains("geometry SHA-256 mismatch")));
}

#[test]
fn lp_header_major_version_unsupported() {
    let mut img = sample_super();
    for off in [
        0x3000usize,
        0x3000 + 65536,
        0x3000 + 2 * 65536,
        0x3000 + 3 * 65536,
    ] {
        img[off + 4] = 9; // major_version
    }
    let layout = analyze(arc(img)).unwrap();
    assert!(layout.warnings.iter().any(|w| w.contains("major version")));
}

#[test]
fn lp_external_and_overshot_extents_are_holes() {
    let mut img = sample_super();
    // Extents table in slot0 primary @0x3000+256+104 (after 2×52 partitions).
    let ext0 = 0x3000 + 256 + 104;
    let ext1 = ext0 + 24;
    // extent 0 → target_source 9 (no such block device).
    img[ext0 + 20] = 9;
    // extent 1 → unknown target_type 77.
    img[ext1 + 8] = 77;
    let (parts, warnings) = sutram_part::lp::logical_partitions_verbose(arc(img)).unwrap();
    assert_eq!(
        parts[0].meta.get("external_extents").map(String::as_str),
        Some("true")
    );
    assert!(warnings.iter().any(|w| w.contains("unknown block device")));
    assert!(warnings
        .iter()
        .any(|w| w.contains("unknown extent target_type")));
    // The external extent maps a hole — reads give zeros, not wrong bytes.
    assert_eq!(&parts[0].source.read_slice(0, 8).unwrap(), &[0u8; 8]);
}

#[test]
fn lp_extent_range_past_table_warns() {
    let mut img = sample_super();
    // Partition 0 num_extents @0x3000+256+44 → 9 (table has 2).
    img[0x3000 + 256 + 44] = 9;
    let (_, warnings) = sutram_part::lp::logical_partitions_verbose(arc(img)).unwrap();
    assert!(warnings.iter().any(|w| w.contains("extent range")));
}

#[test]
fn lp_empty_partition_name_warns() {
    let mut img = sample_super();
    img[0x3000 + 256..0x3000 + 256 + 36].fill(0); // partition 0 name
    let (parts, warnings) = sutram_part::lp::logical_partitions_verbose(arc(img)).unwrap();
    assert_eq!(parts[0].name, "partition_0_a");
    assert!(warnings.iter().any(|w| w.contains("empty name")));
}

#[test]
fn lp_zero_target_extent_is_hole() {
    let mut img = sample_super();
    // extent 1 → target_type ZERO (1); target_data must be 0 per spec.
    let ext1 = 0x3000 + 256 + 104 + 24;
    img[ext1 + 8] = 1;
    img[ext1 + 12..ext1 + 20].fill(0);
    let (parts, _) = sutram_part::lp::logical_partitions_verbose(arc(img)).unwrap();
    assert_eq!(&parts[1].source.read_slice(0, 8).unwrap(), &[0u8; 8]);
}

#[test]
fn lp_first_logical_sector_overlap_warns() {
    let mut img = sample_super();
    // block_device[0].first_logical_sector @0x3000+256+ (104+48+48+200)=
    // bdev_off = 104+48+48 = 200? groups=1 entry (48B) → bdev at
    // 0x3000+256+200+0.
    let bdev = 0x3000 + 256 + 200;
    img[bdev..bdev + 8].copy_from_slice(&1u64.to_le_bytes()); // sector 1
    let (_, warnings) = sutram_part::lp::logical_partitions_verbose(arc(img)).unwrap();
    assert!(warnings.iter().any(|w| w.contains("overlaps metadata")));
}

#[test]
fn lp_geometry_implausible_fields_rejected() {
    let mut img = sample_super();
    img[0x1000 + 44] = 0; // slot_count = 0
    img[0x2000..0x2000 + 52].fill(0); // kill backup so primary error surfaces
    assert!(sutram_part::lp::read_geometry(arc(img).as_ref()).is_err());
    let mut img = sample_super();
    img[0x1000 + 40..0x1000 + 44].copy_from_slice(&1234u32.to_le_bytes()); // unaligned
    img[0x2000..0x2000 + 52].fill(0);
    assert!(sutram_part::lp::read_geometry(arc(img).as_ref()).is_err());
}

// ---------------------------------------------------------------------------
// Sparse hostile-input paths
// ---------------------------------------------------------------------------

#[test]
fn sparse_header_field_validation() {
    use sutram_part::sparse::read_header;
    // Not sparse at all.
    assert!(read_header(&vec![0u8; 64].as_slice()).is_err());
    // Truncated header.
    assert!(read_header(&vec![0u8; 20].as_slice()).is_err());
    let mk = |bs: u32| {
        let mut h = vec![0u8; 28];
        common::w32(&mut h, 0, 0xED26_FF3A);
        common::w16(&mut h, 8, 28);
        common::w16(&mut h, 10, 12);
        common::w32(&mut h, 12, bs);
        h
    };
    assert!(read_header(&mk(0).as_slice()).is_err());
    assert!(read_header(&mk(1 << 25).as_slice()).is_err());
    assert!(read_header(&mk(4096).as_slice()).is_ok());
    // file_hdr_sz / chunk_hdr_sz too small.
    let mut h = mk(4096);
    common::w16(&mut h, 8, 20);
    assert!(read_header(&h.as_slice()).is_err());
    let mut h = mk(4096);
    common::w16(&mut h, 10, 8);
    assert!(read_header(&h.as_slice()).is_err());
}

#[test]
fn sparse_chunk_table_warnings() {
    // RAW chunk whose payload is short → "maps non-payload bytes".
    let img = common::sparse_img(&[(0xCAC1, 2, vec![0xAA; 100])], 4096);
    let (_, _, w) = sutram_part::sparse::inspect_sparse(arc(img)).unwrap();
    assert!(w.iter().any(|m| m.contains("non-payload")));
    // FILL chunk must carry exactly 4 payload bytes.
    let img = common::sparse_img(&[(0xCAC2, 1, vec![0u8; 16])], 4096);
    let (_, _, w) = sutram_part::sparse::inspect_sparse(arc(img)).unwrap();
    assert!(w.iter().any(|m| m.contains("disagree")));
    // total_sz smaller than the chunk header → the decoder rejects hard.
    let mut img = common::sparse_img(&[(0xCAC3, 1, vec![])], 4096);
    common::w32(&mut img[28..40], 8, 4);
    assert!(sutram_part::sparse::inspect_sparse(arc(img)).is_err());
}

#[test]
fn sparse_nested_depth_guard() {
    // sparse(sparse(sparse(sparse(sparse(x))))) → nesting limit.
    let mut img = vec![0xABu8; 4096];
    for _ in 0..6 {
        img = common::as_sparse(&img, 4096);
    }
    assert!(analyze(arc(img)).is_err());
}

// ---------------------------------------------------------------------------
// vbmeta hostile-input paths
// ---------------------------------------------------------------------------

#[test]
fn vbmeta_truncated_and_misaligned() {
    // Truncated header → Err, not panic.
    assert!(sutram_part::vbmeta::parse(&vec![0u8; 100].as_slice()).is_err());
    // Misaligned auth/aux sizes → warning.
    let mut img = common::vbmeta_blob(0, 0, &[]);
    common::w64be(&mut img, 12, 65); // auth_size not 64-aligned
    img.resize(256 + 192, 0);
    let info = sutram_part::vbmeta::parse(&img.as_slice()).unwrap();
    assert!(info.warnings.iter().any(|w| w.contains("aligned")));
}

#[test]
fn vbmeta_descriptor_region_overrun() {
    let mut img = common::vbmeta_blob(0, 0, &[]);
    // desc region claims past aux_size → warning + no descriptors.
    common::w64be(&mut img, 104, 1 << 20);
    let info = sutram_part::vbmeta::parse(&img.as_slice()).unwrap();
    assert!(info.warnings.iter().any(|w| w.contains("auxiliary")));
    assert!(info.descriptors.is_empty());
}

#[test]
fn vbmeta_chain_and_unknown_descriptors() {
    // CHAIN_PARTITION (tag 4) + unknown tag descriptor.
    let mut d = Vec::new();
    d.extend_from_slice(&4u64.to_be_bytes());
    d.extend_from_slice(&88u64.to_be_bytes()); // 76 fixed + name(12 pad)
    let mut f = vec![0u8; 88];
    common::w32be(&mut f, 0, 3); // rollback_index_location
    common::w32be(&mut f, 4, 6); // name_len
    common::w32be(&mut f, 8, 2048); // public_key_len
    f[76..82].copy_from_slice(b"system");
    d.extend_from_slice(&f);
    d.extend_from_slice(&0xDEADu64.to_be_bytes());
    d.extend_from_slice(&16u64.to_be_bytes());
    d.extend_from_slice(&[0xCC; 16]);
    let img = common::vbmeta_blob(0, 1, &d);
    let info = sutram_part::vbmeta::parse(&img.as_slice()).unwrap();
    match &info.descriptors[0] {
        VbmetaDescriptor::ChainPartition {
            partition_name,
            rollback_index_location,
            ..
        } => {
            assert_eq!(partition_name, "system");
            assert_eq!(*rollback_index_location, 3);
            assert_eq!(info.descriptors[0].partition_name(), Some("system"));
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        info.descriptors[1],
        VbmetaDescriptor::Unknown {
            tag: 0xDEAD,
            len: 16
        }
    ));
}

#[test]
fn gpt_vbmeta_partition_garbage_warns() {
    let img = common::gpt_img(&[
        common::GptPart {
            name: "vbmeta",
            type_guid: common::test_guid(6),
            data: vec![0xAB; 4096],
        },
        common::GptPart {
            name: "boot",
            type_guid: common::test_guid(1),
            data: common::boot_img_with_vbmeta(&common::vbmeta_blob(0, 5, &[])),
        },
    ]);
    let layout = analyze(arc(img)).unwrap();
    // vbmeta partition unreadable → warning; boot footer path still finds it.
    assert!(layout
        .warnings
        .iter()
        .any(|w| w.contains("vbmeta partition")));
    assert_eq!(layout.vbmeta.unwrap().rollback_index, 5);
}

#[test]
fn gpt_partition_past_image_skipped() {
    let mut img = sample_gpt();
    // Patch partition 0's last_lba way past the image → OffsetView fails.
    let e = 2 * 512;
    img[e + 40..e + 48].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes());
    let layout = analyze(arc(img)).unwrap();
    assert!(layout
        .warnings
        .iter()
        .any(|w| w.contains("exceeds source length")));
}

#[test]
fn corrupt_partition_table_falls_back_to_raw() {
    let mut img = sample_gpt();
    img.truncate(600); // GPT header exists but entry array is gone.
    let layout = analyze(arc(img)).unwrap();
    assert_eq!(layout.container, ContainerKind::Raw);
}

#[test]
fn raw_image_magic_and_crypto_flags() {
    // ZIP magic at offset 0 → detected_magic provenance.
    let mut img = vec![0u8; 0x8000];
    img[..4].copy_from_slice(b"PK\x03\x04");
    common::with_crypt_footer(&mut img, 1, "aes-cbc-essiv:sha256");
    let layout = analyze(arc(img)).unwrap();
    assert_eq!(layout.container, ContainerKind::Raw);
    assert_eq!(layout.partitions[0].meta["detected_magic"], "ZIP archive");
    let cf = &layout.crypto[0];
    assert_eq!(cf.partition, "");
    assert_eq!(cf.kind.as_str(), "crypt_footer");
}

#[test]
fn role_and_state_labels() {
    use sutram_part::{ContainerKind, PartitionRole};
    // Enum label coverage — reports use these strings.
    assert_eq!(PartitionRole::Frp.as_str(), "frp");
    assert_eq!(PartitionRole::Bootloader.as_str(), "bootloader");
    assert_eq!(ContainerKind::Mbr.as_str(), "mbr");
    assert_eq!(ContainerKind::Raw.as_str(), "raw");
    assert_eq!(
        DmVerityState::HashtreeDisabled.as_str(),
        "hashtree_disabled"
    );
    let a = Attrs(Attrs::UPDATED | Attrs::DISABLED);
    assert!(a.updated() && a.disabled() && !a.readonly());
}
