//! Integration tests over the synthetic NTFS corpus.

mod common;

use std::io::Read;
use std::sync::Arc;
use std::sync::OnceLock;

use sutram_fs::{
    DetectConfidence, FsEntry, FsEntryStatus, FsParser, MountOptions, RecoveryState,
};
use sutram_io::ByteSource;
use sutram_magic::{MagicType, Severity};
use sutram_ntfs::NtfsParser;

fn image() -> Arc<dyn ByteSource> {
    static IMG: OnceLock<Arc<dyn ByteSource>> = OnceLock::new();
    IMG.get_or_init(|| Arc::new(common::build_ntfs())).clone()
}

fn mount() -> Box<dyn sutram_fs::FileSystem> {
    NtfsParser.mount(image()).unwrap()
}

fn all_entries() -> Vec<FsEntry> {
    // The corpus intentionally contains one torn record (72) — lenient mode
    // reports it as an Err item; drop those for the per-entry assertions.
    mount().walk().filter_map(|i| i.ok()).collect()
}

fn find<'a>(entries: &'a [FsEntry], name: &str) -> &'a FsEntry {
    entries.iter().find(|e| e.name == name).unwrap_or_else(|| {
        panic!(
            "entry {name} not found; got {:?}",
            entries.iter().map(|e| &e.path).collect::<Vec<_>>()
        )
    })
}

#[test]
fn detects_ntfs() {
    assert_eq!(NtfsParser.detect(image().as_ref()), DetectConfidence::Certain);
    // Garbage and foreign signatures are rejected.
    let zeros = vec![0u8; 4096];
    assert_eq!(NtfsParser.detect(&zeros.as_slice()), DetectConfidence::None);
    let mut fat = vec![0u8; 512];
    fat[3..11].copy_from_slice(b"MSWIN4.1");
    fat[510] = 0x55;
    fat[511] = 0xAA;
    assert_eq!(NtfsParser.detect(&fat.as_slice()), DetectConfidence::None);
}

#[test]
fn info_reports_ntfs() {
    let info = mount().info();
    assert_eq!(info.fs_type, "NTFS");
    assert_eq!(info.label.as_deref(), Some("TESTVOL"));
    assert_eq!(info.uuid.as_deref(), Some("A1B2C3D4E5F60718"));
    assert_eq!(info.block_size, 4096);
    assert_eq!(info.total_blocks, 2048);
    assert_eq!(info.meta["ntfs_version"], "3.1");
    assert_eq!(info.meta["mft_lcn"], "4");
    assert_eq!(info.meta["logfile_present"], "true");
    assert_eq!(info.meta["usn_journal_present"], "true");
    assert!(info.free_blocks.unwrap() > 0);
}

#[test]
fn live_tree_walks() {
    let entries = all_entries();
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    for p in [
        "/",
        "/$MFT",
        "/$LogFile",
        "/HELLO.TXT",
        "/BIG.BIN",
        "/SUBDIR",
        "/SUBDIR/INNER.TXT",
        "/$Extend/$UsnJrnl",
    ] {
        assert!(paths.contains(&p), "missing {p}");
    }
    // $UsnJrnl ADS streams are exposed as their own entries.
    assert!(paths.contains(&"/$Extend/$UsnJrnl:$J"));
    assert!(paths.contains(&"/$Extend/$UsnJrnl:$Max"));
}

#[test]
fn resident_file_reads_back() {
    let entries = all_entries();
    let e = find(&entries, "HELLO.TXT");
    assert_eq!(e.path, "/HELLO.TXT");
    // Resident data: provenance points inside the MFT record.
    assert_eq!(e.disk_offset, common::rec_off(16) as u64);
    assert_eq!(e.allocated_ranges.len(), 1);
    let (off, len) = e.allocated_ranges[0];
    assert_eq!(len, 16);
    assert!(off > common::rec_off(16) as u64 && off < common::rec_off(17) as u64);
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"hello ntfs world");
}

#[test]
fn nonresident_file_reads_back() {
    let entries = all_entries();
    let e = find(&entries, "BIG.BIN");
    assert_eq!(e.size, 6000);
    assert_eq!(
        e.allocated_ranges,
        vec![(common::clus_off(40) as u64, 4 * 4096)]
    );
    // file slack: 4 clusters allocated for 6000 bytes
    assert_eq!(e.meta["slack_len"], (4 * 4096 - 6000).to_string());
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 6000);
    assert!(buf.starts_with(b"BIG-BIN-HEAD-"));
}

#[test]
fn dual_si_fn_timestamps() {
    let entries = all_entries();
    let e = find(&entries, "HELLO.TXT");
    // SI set drives the structured timestamps.
    let m = e.timestamps.modified.as_ref().unwrap();
    assert_eq!(m.value, Some(1_705_314_620_000_000_000));
    assert_eq!(m.raw_encoding, "ntfs-filetime");
    assert!(e.timestamps.created.is_some());
    assert!(e.timestamps.changed.is_some()); // MFT-changed maps to `changed`
    // Both sets are in meta: si_* and fn_*.
    for k in [
        "si_created",
        "si_modified",
        "si_mft_changed",
        "si_accessed",
        "fn_created",
        "fn_modified",
        "fn_mft_changed",
        "fn_accessed",
    ] {
        assert!(e.meta.contains_key(k), "missing meta {k}");
    }
    assert_eq!(e.meta["si_modified"], "1705314620000000000");
    assert_eq!(e.meta["fn_created"], "1705314620000000000");
}

#[test]
fn timestomp_suspect_flagged() {
    let entries = all_entries();
    let e = find(&entries, "TIMESTOMP.TXT");
    // SI times are all older than FN times → si_* < fn_*.
    assert_eq!(e.meta["si_created"], "1000000000000000000");
    assert_eq!(e.meta["fn_created"], "1705314620000000000");
    let suspect = &e.meta["timestomp_suspect"];
    assert!(suspect.contains("si_created<fn_created"), "{suspect}");
    // A normal file carries no flag.
    assert!(!find(&entries, "HELLO.TXT").meta.contains_key("timestomp_suspect"));
}

#[test]
fn ads_streams_enumerated() {
    let entries = all_entries();
    let e = find(&entries, "ADS.TXT:secret");
    assert_eq!(e.path, "/ADS.TXT:secret");
    assert_eq!(e.meta["ads"], "true");
    assert_eq!(e.meta["stream_name"], "secret");
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"hidden-stream-data");
}

#[test]
fn hardlink_emits_both_paths() {
    let entries = all_entries();
    let a = find(&entries, "LINK1.TXT");
    let b = find(&entries, "LINK2.TXT");
    assert_eq!(a.path, "/LINK1.TXT");
    assert_eq!(b.path, "/SUBDIR/LINK2.TXT");
    assert_eq!(b.meta["hardlink"], "true");
    assert_eq!(a.meta["link_count"], "2");
    // Same record → same entry_id.
    assert_eq!(a.entry_id, b.entry_id);
}

#[test]
fn sparse_file_reads_holes() {
    let entries = all_entries();
    let e = find(&entries, "SPARSE.BIN");
    assert_eq!(e.meta["sparse"], "true");
    // allocated_ranges lists only real extents (2+2 clusters).
    assert_eq!(
        e.allocated_ranges,
        vec![
            (common::clus_off(44) as u64, 2 * 4096),
            (common::clus_off(46) as u64, 2 * 4096),
        ]
    );
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 6 * 4096);
    assert!(buf.starts_with(b"SPARSE-HEAD____"));
    assert!(buf[2 * 4096..4 * 4096].iter().all(|&b| b == 0)); // the hole
    assert_eq!(&buf[4 * 4096..4 * 4096 + 15], b"SPARSE-TAIL____");
}

#[test]
fn compressed_file_decompresses() {
    let entries = all_entries();
    let e = find(&entries, "COMPRESS.BIN");
    assert_eq!(e.meta["compressed"], "lznt1");
    assert_eq!(e.meta["compression_unit_clusters"], "16");
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"COMPRESS");
}

#[test]
fn attr_list_merges_extents() {
    let entries = all_entries();
    let e = find(&entries, "ATTRLIST.BIN");
    assert_eq!(e.meta["extension_records"], "32");
    // runs from base record (vcn0@70) + extension record (vcn2@72)
    assert_eq!(
        e.allocated_ranges,
        vec![
            (common::clus_off(70) as u64, 2 * 4096),
            (common::clus_off(72) as u64, 2 * 4096),
        ]
    );
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.starts_with(b"ATTRLIST-PART-ONE-"));
    assert_eq!(&buf[2 * 4096..2 * 4096 + 18], b"ATTRLIST-PART-TWO-");
}

#[test]
fn deleted_intact_recovers() {
    let entries = all_entries();
    // MFT record 20 — flag cleared, extents freed in $BITMAP but surviving.
    let e = entries
        .iter()
        .find(|e| e.name == "DELETED1.TXT" && e.meta.contains_key("mft_record"))
        .unwrap();
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    ));
    assert_eq!(e.meta["deleted_marker"], "mft_inactive");
    // the $MFT bitmap still marks the slot → anomaly is recorded
    assert_eq!(e.meta["mft_bitmap_inuse"], "true");
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.starts_with(b"DELETED-ONE-HEAD"));
    assert_eq!(buf.len(), 5000);
}

#[test]
fn deleted_partial_overwrite() {
    let entries = all_entries();
    let e = find(&entries, "PARTIAL.BIN");
    match e.status {
        FsEntryStatus::Deleted {
            recovery:
                RecoveryState::PartiallyOverwritten {
                    recovered_bytes,
                    total_bytes,
                },
        } => assert_eq!((recovered_bytes, total_bytes), (8192, 14000)),
        other => panic!("expected partial overwrite, got {other:?}"),
    }
    // surviving extent = clusters 54–55 only
    assert_eq!(
        e.allocated_ranges,
        vec![(common::clus_off(54) as u64, 2 * 4096)]
    );
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert!(buf.starts_with(b"PARTIAL-TAIL-SURVIVES-1"));
}

#[test]
fn deleted_unrecoverable() {
    let entries = all_entries();
    let e = find(&entries, "GONE.TXT");
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unrecoverable
        }
    ));
}

#[test]
fn mft_slack_fragment_carved() {
    let entries = all_entries();
    let e = find(&entries, "GHOSTF.DAT");
    assert_eq!(e.meta["mft_slack"], "true");
    assert!(e.is_deleted());
    // Resident data inside the fragment is intact.
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"ghost-bytes");
}

#[test]
fn baad_record_emitted() {
    let entries = all_entries();
    let e = entries
        .iter()
        .find(|e| e.meta.get("baad").map(|s| s.as_str()) == Some("true"))
        .expect("BAAD record should be emitted");
    assert!(e.is_deleted());
    assert_eq!(e.meta["mft_record"], "71");
}

#[test]
fn indx_slack_and_dangling_residue() {
    let entries = all_entries();
    // slack entry: SLACKED.TXT never had a live MFT record in this image
    let slack = entries
        .iter()
        .find(|e| e.meta.get("source").map(|s| s.as_str()) == Some("indx_slack"))
        .expect("INDX slack entry should be emitted");
    assert_eq!(slack.name, "SLACKED.TXT");
    assert_eq!(slack.path, "/SLACKED.TXT");
    assert_eq!(slack.meta["target_record"], "90");
    assert!(matches!(
        slack.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Unknown
        }
    ));
    // dangling: the live index entry still names DELETED1.TXT → record 20 free
    let dang = entries
        .iter()
        .find(|e| {
            e.meta.get("source").map(|s| s.as_str()) == Some("indx_dangling")
                && e.name == "DELETED1.TXT"
        })
        .expect("INDX dangling entry should be emitted");
    assert_eq!(dang.name, "DELETED1.TXT");
    assert_eq!(dang.meta["target_record"], "20");
}

#[test]
fn orphan_detected() {
    let entries = all_entries();
    let e = find(&entries, "ORPHAN.TXT");
    assert!(e.path.starts_with("/$ORPHANED/"));
    assert_eq!(e.meta["orphan"], "true");
}

#[test]
fn ea_names_reported() {
    let entries = all_entries();
    let e = find(&entries, "EA.TXT");
    assert_eq!(e.meta["ea_names"], "MYEA");
    assert_eq!(e.meta["ea_present"], "true");
}

#[test]
fn magic_verdicts() {
    let entries = all_entries();
    let e = find(&entries, "EVIL.DOC");
    let v = e.magic.as_ref().unwrap();
    assert!(v.mismatch);
    assert_eq!(v.severity, Severity::High);
    assert_eq!(v.detected, Some(MagicType::Pe));

    let e = find(&entries, "RESUME.DOCX");
    let v = e.magic.as_ref().unwrap();
    assert!(!v.mismatch, "{:?}", v.reasons);
}

#[test]
fn provenance_disk_offsets() {
    let entries = all_entries();
    let e = find(&entries, "BIG.BIN");
    assert_eq!(e.disk_offset, common::rec_off(17) as u64);
    assert_eq!(e.meta["mft_record"], "17");
    assert_eq!(e.meta["mft_offset"], format!("{:#x}", common::rec_off(17)));
}

#[test]
fn deleted_entries_view() {
    // Err items pass through deleted_entries() — the torn record 72 is
    // expected; drop it here (asserted separately in the lenient-walk test).
    let deleted: Vec<_> = mount()
        .deleted_entries()
        .filter_map(|i| i.ok())
        .collect();
    let names: Vec<&str> = deleted.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"DELETED1.TXT"));
    assert!(names.contains(&"PARTIAL.BIN"));
    assert!(names.contains(&"GONE.TXT"));
    assert!(!names.contains(&"HELLO.TXT"));
}

#[test]
fn unallocated_ranges_from_bitmap() {
    let ranges = mount().unallocated_ranges();
    assert!(!ranges.is_empty());
    // cluster 50 (deleted file's extent, free in bitmap) is unallocated
    let free = common::clus_off(50) as u64;
    assert!(ranges.iter().any(|(o, l)| *o <= free && free < o + l));
    // cluster 40 (BIG.BIN) is allocated
    let used = common::clus_off(40) as u64;
    assert!(!ranges.iter().any(|(o, l)| *o <= used && used < o + l));
}

#[test]
fn lenient_walk_reports_corrupt_record() {
    let items: Vec<_> = mount().walk().collect();
    // record 72 has a deliberately torn fixup → Err item, walk continues
    let errs: Vec<_> = items.iter().filter(|i| i.is_err()).collect();
    assert_eq!(errs.len(), 1, "expected exactly one corrupt-record error");
    let oks = items.iter().filter(|i| i.is_ok()).count();
    assert!(oks > 20);
}

#[test]
fn strict_mode_aborts() {
    let fs = NtfsParser
        .mount_with(image(), &MountOptions::strict())
        .unwrap();
    let mut seen_err = false;
    let mut ok_after_err = false;
    for item in fs.walk() {
        if seen_err && item.is_ok() {
            ok_after_err = true;
        }
        if item.is_err() {
            seen_err = true;
        }
    }
    assert!(seen_err);
    assert!(!ok_after_err, "strict walk must not emit after first error");
}

#[test]
fn truncated_image_no_panic() {
    let img = common::build_ntfs();
    // Cut the image inside the data region; mount may still succeed.
    let truncated = img[..common::clus_off(45)].to_vec();
    let src: Arc<dyn ByteSource> = Arc::new(truncated);
    if let Ok(fs) = NtfsParser.mount(src) {
        let items: Vec<_> = fs.walk().collect();
        assert!(items.iter().any(|i| i.is_ok()));
    }
}

#[test]
fn extension_record_not_emitted_standalone() {
    let entries = all_entries();
    // record 32 is ATTRLIST.BIN's extension — never appears on its own.
    assert!(!entries
        .iter()
        .any(|e| e.meta.get("mft_record").map(|r| r == "32").unwrap_or(false)
            && e.name != "ATTRLIST.BIN"));
}

#[test]
fn dos_alias_and_dos_flags() {
    let entries = all_entries();
    let e = find(&entries, "DOSFLAGS.TXT");
    assert_eq!(e.meta["dos_name"], "DOSFLA~1.TXT");
    assert_eq!(e.meta["readonly"], "true");
    assert_eq!(e.meta["hidden"], "true");
    assert_eq!(e.meta["system"], "true");
}

#[test]
fn symlink_reparse_target() {
    let entries = all_entries();
    let e = find(&entries, "SYMLINK.LNK");
    assert_eq!(e.kind, sutram_fs::EntryKind::Symlink);
    // PrintName field of the reparse buffer, not the substitute name.
    assert_eq!(e.meta["symlink_target"], "target\\real.txt");
    assert_eq!(e.meta["reparse_tag"], "0xa000000c");
}

#[test]
fn object_id_and_fn_only_timestamps() {
    let entries = all_entries();
    let e = find(&entries, "OBJID.BIN");
    assert_eq!(e.meta["object_id"], "04030201-0605-0807-090a-0b0c0d0e0f10");
    // No $SI: FN is the only timestamp set and still fills Timestamps.
    let m = e.timestamps.modified.as_ref().unwrap();
    assert_eq!(m.value, Some(1_705_314_620_000_000_000));
    assert!(e.meta.contains_key("fn_created"));
    assert!(!e.meta.contains_key("si_created"));
}

#[test]
fn compressed_raw_and_sparse_units() {
    let entries = all_entries();
    let e = find(&entries, "RAWCMP.BIN");
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 32 * common::CSZ);
    // Unit 0 was stored raw (incompressible) — verbatim bytes come back.
    assert!(buf.starts_with(b"RAWCMP-UNIT0-STORED-RAW"));
    // Unit 1 is a wholly sparse compression unit — zeros.
    assert!(buf[16 * common::CSZ..].iter().all(|&b| b == 0));
}

#[test]
fn sparse_stream_leading_vcn_gap() {
    let entries = all_entries();
    let e = find(&entries, "GAPDATA.BIN");
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf.len(), 8 * common::CSZ);
    // VCNs 0..4 are an unmapped gap → zeros; the extent at VCN 4 is real.
    assert!(buf[..4 * common::CSZ].iter().all(|&b| b == 0));
    assert_eq!(&buf[4 * common::CSZ..4 * common::CSZ + 20], b"GAPDATA-REAL-EXTENT-");
}

#[test]
fn deleted_extent_still_marked_in_bitmap() {
    let entries = all_entries();
    let e = find(&entries, "BITDEL.TXT");
    // runlist covers 1 of 2 needed clusters; survivor is marked allocated.
    assert_eq!(
        e.meta["recovery_note_1"],
        "runlist covers 1 of 2 expected clusters"
    );
    assert_eq!(
        e.meta["recovery_note_2"],
        "1 surviving cluster(s) still marked allocated in $BITMAP"
    );
    match e.status {
        FsEntryStatus::Deleted {
            recovery:
                RecoveryState::PartiallyOverwritten {
                    recovered_bytes,
                    total_bytes,
                },
        } => assert_eq!((recovered_bytes, total_bytes), (4096, 8000)),
        other => panic!("expected partial recovery, got {other:?}"),
    }
}

#[test]
fn deleted_dir_assessed_via_index_allocation() {
    let entries = all_entries();
    let e = find(&entries, "DELDIR");
    // Cluster 63 is free and unclaimed — the index stream survives intact.
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    ));
}

#[test]
fn orphan_extension_record_emitted() {
    let entries = all_entries();
    // record 42 is an extension record whose base (45) is an empty slot.
    let e = entries
        .iter()
        .find(|e| e.meta.get("mft_record").map(|r| r == "42").unwrap_or(false))
        .expect("orphan extension record should be emitted");
    assert_eq!(e.meta["orphan"], "true");
    assert_eq!(e.name, "EXTORPHAN.DAT");
    assert!(e.path.starts_with("/$ORPHANED/"));
}

#[test]
fn corrupt_attribute_recorded_as_note() {
    let entries = all_entries();
    let e = find(&entries, "BADATTR.BIN");
    assert!(e.meta["note"].starts_with("attribute parse:"), "{}", e.meta["note"]);
}

#[test]
fn deleted_ads_stream_assessed() {
    let entries = all_entries();
    let e = find(&entries, "DELADS.TXT:hidden");
    assert_eq!(e.path, "/DELADS.TXT:hidden");
    assert_eq!(e.meta["ads"], "true");
    // Resident stream data lives in the surviving record → intact.
    assert!(matches!(
        e.status,
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact
        }
    ));
}

#[test]
fn indx_root_slack_residue() {
    let entries = all_entries();
    // Slack of the resident $INDEX_ROOT inside SUBDIR's record.
    let slack = entries
        .iter()
        .find(|e| {
            e.meta.get("source").map(|s| s.as_str()) == Some("indx_slack")
                && e.name == "ROOTSLACK.TXT"
        })
        .expect("index-root slack residue should be emitted");
    assert_eq!(slack.path, "/SUBDIR/ROOTSLACK.TXT");
    assert_eq!(slack.meta["target_record"], "91");
}

#[test]
fn read_file_rejects_directories() {
    let entries = all_entries();
    let e = find(&entries, "SUBDIR");
    let err = mount().read_file(e).err().expect("not a file");
    assert!(matches!(err, sutram_fs::FsError::InvalidInput { .. }));
}

#[test]
fn source_accessor_returns_image() {
    let fs = mount();
    assert_eq!(fs.source().len(), image().len());
    assert_eq!(NtfsParser.name(), "ntfs");
}

#[test]
fn mount_rejects_bad_boot_sectors() {
    // Valid image, then successively break each checked field.
    for (off, val, why) in [
        (3usize, 0u8, "OEM"),
        (510, 0u8, "signature"),
        (11, 0u8, "bytes/sector"),
        (13, 0u8, "sectors/cluster"),
        (40, 0u8, "total sectors"),
        (64, 0u8, "clusters-per-record"),
    ] {
        let mut img = common::build_ntfs();
        match off {
            11 => common::w16(&mut img, 11, 300), // not a power of two
            40 => common::w64(&mut img, 40, 0),
            _ => img[off] = val,
        }
        let src: Arc<dyn ByteSource> = Arc::new(img);
        assert!(
            NtfsParser.mount(src).is_err(),
            "mount should reject corrupt {why}"
        );
    }
    // Truncated boot sector.
    let tiny: Arc<dyn ByteSource> = Arc::new(vec![0u8; 100]);
    assert!(NtfsParser.mount(tiny).is_err());
    // Garbage index-record-size byte (0x00 → decode fails; 0x7F → implausible).
    for bad in [0x00u8, 0x7F] {
        let mut img = common::build_ntfs();
        img[68] = bad;
        let src: Arc<dyn ByteSource> = Arc::new(img);
        assert!(NtfsParser.mount(src).is_err(), "index record byte {bad:#x}");
    }
    // $MFT LCN out of range.
    let mut img = common::build_ntfs();
    common::w64(&mut img, 48, 999_999);
    let src: Arc<dyn ByteSource> = Arc::new(img);
    assert!(NtfsParser.mount(src).is_err());
}

#[test]
fn detect_low_confidence_without_signature() {
    // NTFS OEM string but no 0x55AA → Low, not None.
    let mut img = common::build_ntfs();
    img[510] = 0;
    img[511] = 0;
    assert_eq!(
        NtfsParser.detect(&img.as_slice()),
        DetectConfidence::Low
    );
}

#[test]
fn attr_list_rejects_foreign_and_stale_records() {
    // Record 45's $ATTRIBUTE_LIST references record 46 (a base record —
    // not an extension of 45) and record 47 (stale sequence in the file
    // reference). Neither may be merged: doing so would graft another
    // file's extents onto BADLIST.BIN.
    let entries = all_entries();
    let e = find(&entries, "BADLIST.BIN");
    assert!(!e.is_deleted());
    // The decoy (cluster 84) and stale (cluster 85) extents must not appear.
    for (off, _) in &e.allocated_ranges {
        assert_ne!(*off, common::clus_off(84) as u64);
        assert_ne!(*off, common::clus_off(85) as u64);
    }
    // Resident data reads back only its own bytes.
    let mut buf = Vec::new();
    mount().read_file(e).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"badlist-data");
    // The rejection is surfaced as an attribute-parse note.
    let note = e.meta.get("note").expect("attr-list rejection note");
    assert!(note.contains("extension record 50"), "note: {note}");
    // The decoy is a live file in its own right.
    let d = find(&entries, "DECOY.DAT");
    let mut buf = Vec::new();
    mount().read_file(d).unwrap().read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"decoy-bytes");
}

#[test]
fn deleted_sparse_file_credits_holes() {
    // DELSPRSE.BIN: 2 surviving clusters + 3 sparse + 2 surviving — the
    // sparse hole is recoverable as zeros, so the file is Intact, not
    // PartiallyOverwritten.
    let entries = all_entries();
    let e = find(&entries, "DELSPRSE.BIN");
    match e.status {
        FsEntryStatus::Deleted {
            recovery: RecoveryState::Intact,
        } => {}
        ref s => panic!("expected Deleted{{Intact}}, got {s:?}"),
    }
    assert_eq!(e.meta["sparse"], "true");
    // The two surviving real extents are listed for provenance.
    assert_eq!(e.allocated_ranges.len(), 2);
    assert_eq!(
        e.allocated_ranges[0].0,
        common::clus_off(86) as u64
    );
    assert_eq!(
        e.allocated_ranges[1].0,
        common::clus_off(88) as u64
    );
}
