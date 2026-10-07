//! Unit tests for the safe core (`core`, `json`) — every value is
//! constructed in memory; no fixture files, no FFI. The FFI boundary
//! itself is exercised in `tests/ffi.rs`.

use std::collections::HashMap;
use std::time::Duration;

use sutram_fs::{
    DetectConfidence, EntryKind, FsEntry, FsEntryStatus, FsInfo, FsTimestamp, RecoveryState,
    Timestamps,
};
use sutram_magic::{MagicType, MagicVerdict, Severity};

use crate::core;
use crate::json;

fn base_entry() -> FsEntry {
    FsEntry {
        path: "/A.TXT".into(),
        name: "A.TXT".into(),
        entry_id: 7,
        kind: EntryKind::File,
        size: 4,
        disk_offset: 0x400,
        allocated_ranges: vec![(0x800, 4)],
        timestamps: Timestamps::default(),
        status: FsEntryStatus::Live,
        meta: HashMap::new(),
        magic: None,
    }
}

#[test]
fn parsers_registry_is_complete_and_ordered() {
    let names: Vec<_> = core::parsers().iter().map(|p| p.name()).collect();
    assert_eq!(
        names,
        ["ntfs", "exfat", "fat", "ext4", "btrfs", "f2fs", "xfs", "hfs", "apfs"]
    );
}

#[test]
fn detect_all_on_garbage() {
    let garbage = vec![0xABu8; 8192];
    let cands = core::detect_all(&garbage);
    assert_eq!(cands.len(), 9);
    // Sorted by confidence descending; garbage scores None everywhere.
    assert!(cands.windows(2).all(|w| w[0].1 >= w[1].1));
    assert_eq!(cands[0].1, DetectConfidence::None);
}

#[test]
fn esc_covers_every_escape() {
    let mut s = String::new();
    json::esc(&mut s, "q\"b\\n\nr\tt\ru\0x\u{1f}");
    assert_eq!(s, "\"q\\\"b\\\\n\\nr\\tt\\ru\\u0000x\\u001f\"");
}

#[test]
fn entry_json_kinds() {
    for (kind, want) in [
        (EntryKind::File, "\"file\""),
        (EntryKind::Directory, "\"directory\""),
        (EntryKind::Symlink, "\"symlink\""),
        (EntryKind::Other, "\"other\""),
    ] {
        let e = FsEntry {
            kind,
            ..base_entry()
        };
        assert!(json::entry_json(&e).contains(&format!("\"kind\":{want}")));
    }
}

#[test]
fn entry_json_recovery_states() {
    for (recovery, want) in [
        (RecoveryState::Intact, "\"recovery\":\"intact\""),
        (
            RecoveryState::PartiallyOverwritten {
                recovered_bytes: 10,
                total_bytes: 40,
            },
            "\"recovery\":\"partial\",\"recovered_bytes\":10,\"total_bytes\":40",
        ),
        (
            RecoveryState::Unrecoverable,
            "\"recovery\":\"unrecoverable\"",
        ),
        (RecoveryState::Unknown, "\"recovery\":\"unknown\""),
    ] {
        let e = FsEntry {
            status: FsEntryStatus::Deleted { recovery },
            ..base_entry()
        };
        let s = json::entry_json(&e);
        assert!(s.contains(want), "{want} not in {s}");
        assert!(s.contains("\"deleted\":{"), "{s}");
    }
}

#[test]
fn entry_json_ranges_meta_and_ts() {
    let mut e = base_entry();
    // Multiple ranges → exercises the comma separator.
    e.allocated_ranges = vec![(1, 2), (3, 4), (5, 6)];
    e.meta.insert("zeta".into(), "1".into());
    e.meta.insert("alpha".into(), "2".into());
    e.timestamps.modified = Some(FsTimestamp {
        value: Some(1_700_000_000_000_000_000),
        raw_value: 0xBEEF,
        raw_encoding: "test-enc",
        granularity: Duration::from_nanos(100),
    });
    // A slot populated but with an unset value → value_ns:null.
    e.timestamps.deleted = Some(FsTimestamp {
        value: None,
        raw_value: 0,
        raw_encoding: "test-enc",
        granularity: Duration::from_secs(1),
    });
    let s = json::entry_json(&e);
    assert!(s.contains("[[1,2],[3,4],[5,6]]"), "{s}");
    // meta keys sorted deterministically.
    let ai = s.find("\"alpha\":").unwrap();
    let zi = s.find("\"zeta\":").unwrap();
    assert!(ai < zi, "{s}");
    assert!(s.contains("\"value_ns\":1700000000000000000"), "{s}");
    assert!(s.contains("\"raw_value\":48879"), "{s}");
    assert!(s.contains("\"raw_encoding\":\"test-enc\""), "{s}");
    assert!(s.contains("\"granularity_ns\":100"), "{s}");
    assert!(s.contains("\"deleted\":{\"value_ns\":null"), "{s}");
    // Unset slots serialize as null.
    assert!(s.contains("\"accessed\":null"), "{s}");
}

#[test]
fn entry_json_magic_verdict() {
    let mut e = base_entry();
    e.magic = Some(MagicVerdict {
        declared: Some(MagicType::Pdf),
        detected: Some(MagicType::Pe),
        mismatch: true,
        severity: Severity::High,
        reasons: vec!["r1".into(), "r2".into()],
    });
    let s = json::entry_json(&e);
    assert!(s.contains("\"declared\":\"Pdf\""), "{s}");
    assert!(s.contains("\"detected\":\"Pe\""), "{s}");
    assert!(s.contains("\"mismatch\":true"), "{s}");
    assert!(s.contains("\"severity\":\"High\""), "{s}");
    assert!(s.contains("\"reasons\":[\"r1\",\"r2\"]"), "{s}");

    // declared: None / detected: None → null fields.
    e.magic = Some(MagicVerdict {
        declared: None,
        detected: None,
        mismatch: false,
        severity: Severity::Info,
        reasons: vec![],
    });
    let s = json::entry_json(&e);
    assert!(s.contains("\"declared\":null"), "{s}");
    assert!(s.contains("\"detected\":null"), "{s}");
    assert!(s.contains("\"mismatch\":false"), "{s}");
}

#[test]
fn info_json_full_and_empty() {
    let info = FsInfo {
        fs_type: "FAT32".into(),
        label: Some("VOL".into()),
        uuid: Some("CAFE".into()),
        block_size: 512,
        total_blocks: 100,
        free_blocks: Some(50),
        total_nodes: Some(9),
        meta: HashMap::from([("k".to_string(), "v".to_string())]),
    };
    let s = json::info_json(&info, "fat");
    assert!(s.contains("\"parser\":\"fat\""), "{s}");
    assert!(s.contains("\"label\":\"VOL\""), "{s}");
    assert!(s.contains("\"uuid\":\"CAFE\""), "{s}");
    assert!(s.contains("\"free_blocks\":50"), "{s}");
    assert!(s.contains("\"total_nodes\":9"), "{s}");
    assert!(s.contains("\"k\":\"v\""), "{s}");

    let s = json::info_json(&FsInfo::default(), "x");
    assert!(s.contains("\"label\":null"), "{s}");
    assert!(s.contains("\"uuid\":null"), "{s}");
    assert!(s.contains("\"free_blocks\":null"), "{s}");
    assert!(s.contains("\"total_nodes\":null"), "{s}");
    assert!(s.contains("\"meta\":{}"), "{s}");
}

#[test]
fn detect_json_shapes() {
    use DetectConfidence as D;
    // Best below Medium → null filesystem/confidence, all names present.
    let s = json::detect_json(&[("ntfs", D::Low), ("fat", D::None)]);
    assert_eq!(
        s,
        "{\"filesystem\":null,\"confidence\":null,\"candidates\":[[\"ntfs\",\"low\"],[\"fat\",\"none\"]]}"
    );
    // Medium-or-better best → named; every confidence name covered.
    let s = json::detect_json(&[
        ("fat", D::Certain),
        ("ntfs", D::High),
        ("ext4", D::Medium),
        ("xfs", D::Low),
        ("hfs", D::None),
    ]);
    assert!(s.contains("\"filesystem\":\"fat\""), "{s}");
    assert!(s.contains("\"confidence\":\"certain\""), "{s}");
    for c in ["high", "medium", "low", "none"] {
        assert!(s.contains(&format!("\"{c}\"")), "{c} missing in {s}");
    }
    // Empty candidate list → nulls, empty array.
    assert_eq!(
        json::detect_json(&[]),
        "{\"filesystem\":null,\"confidence\":null,\"candidates\":[]}"
    );
}

#[test]
fn error_json_escapes() {
    assert_eq!(json::error_json("plain"), "{\"error\":\"plain\"}");
    assert_eq!(
        json::error_json("bad \"quoted\" msg"),
        "{\"error\":\"bad \\\"quoted\\\" msg\"}"
    );
}
