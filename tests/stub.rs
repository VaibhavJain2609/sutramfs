//! Stub-`FileSystem` tests: report/diff branches no synthetic FAT image can
//! produce — every `RecoveryState`, suspicious-meta keys, orphan meta flags,
//! walk errors, the `max_entries`/`hash_max_bytes` caps, read failures,
//! symlink/other kinds, fabricated magic verdicts, and empty-section
//! renderers.

mod common;

use std::collections::HashMap;
use std::time::Duration;

use common::{stub_entry, StubData, StubFs, StubItem};
use sutram_fs::{
    EntryKind, FsEntryStatus, FsTimestamp, MagicType, MagicVerdict, RecoveryState, Severity,
};
use sutram_report::{diff, generate, DiffOptions, ReportOptions};

fn opts() -> ReportOptions {
    ReportOptions {
        title: "stub report".into(),
        ..Default::default()
    }
}

fn deleted(recovery: RecoveryState) -> FsEntryStatus {
    FsEntryStatus::Deleted { recovery }
}

// ---------------------------------------------------------------------------
// Report: census + deleted-recovery classification
// ---------------------------------------------------------------------------

#[test]
fn every_recovery_state_classified() {
    let mut fs = StubFs::new();
    let mut intact = stub_entry(1, "/del_intact.bin", EntryKind::File, 10);
    intact.status = deleted(RecoveryState::Intact);
    let mut part = stub_entry(2, "/del_partial.bin", EntryKind::File, 10);
    part.status = deleted(RecoveryState::PartiallyOverwritten {
        recovered_bytes: 4,
        total_bytes: 10,
    });
    let mut lost = stub_entry(3, "/del_lost.bin", EntryKind::File, 10);
    lost.status = deleted(RecoveryState::Unrecoverable);
    let mut unk = stub_entry(4, "/del_unknown.bin", EntryKind::File, 10);
    unk.status = deleted(RecoveryState::Unknown);
    for e in [intact, part, lost, unk] {
        fs.push(e);
    }

    let r = generate(&fs, &opts());
    assert_eq!(r.census.deleted, 4);
    assert_eq!(r.census.recovery_intact, 1);
    assert_eq!(r.census.recovery_partial, 1);
    assert_eq!(r.census.recovery_unrecoverable, 1);
    assert_eq!(r.census.recovery_unknown, 1);
    assert_eq!(r.census.deleted_bytes, 40);

    let d = &r.deleted;
    assert_eq!(d.intact, 1);
    assert_eq!(d.partial, 1);
    assert_eq!(d.lost, 2, "unrecoverable + unknown are both 'lost'");
    assert_eq!(d.recovered_bytes, 10 + 4);
    assert_eq!(d.total_bytes, 10 + 10 + 10 + 10);

    let labels: Vec<_> = d.rows.iter().map(|r| r.recovery.as_str()).collect();
    assert_eq!(
        labels,
        [
            "intact",
            "partially_overwritten",
            "unrecoverable",
            "unknown"
        ]
    );
    // Per-file detail carries the same recovery labels.
    let unk_detail = r
        .files
        .iter()
        .find(|f| f.path == "/del_unknown.bin")
        .unwrap();
    assert_eq!(unk_detail.status, "deleted");
    assert_eq!(unk_detail.recovery, "unknown");
}

#[test]
fn kind_census_and_details_toggle() {
    let mut fs = StubFs::new();
    fs.push(stub_entry(1, "/a.txt", EntryKind::File, 1));
    fs.push(stub_entry(2, "/dir", EntryKind::Directory, 0));
    fs.push(stub_entry(3, "/link", EntryKind::Symlink, 5));
    fs.push(stub_entry(4, "/weird", EntryKind::Other, 0));

    let r = generate(&fs, &opts());
    assert_eq!(r.census.total_entries, 4);
    assert_eq!(r.census.files, 1);
    assert_eq!(r.census.directories, 1);
    assert_eq!(r.census.symlinks, 1);
    assert_eq!(r.census.other, 1);
    // Directories are excluded from file detail; symlinks/other are not.
    let kinds: Vec<_> = r.files.iter().map(|f| f.kind.as_str()).collect();
    assert!(kinds.contains(&"file") && kinds.contains(&"symlink") && kinds.contains(&"other"));
    assert!(!kinds.contains(&"directory"));
    // Non-file kinds are never hashed.
    let link = r.files.iter().find(|f| f.path == "/link").unwrap();
    assert!(link.sha256.is_none() && link.hashed_bytes == 0);

    let r2 = generate(
        &fs,
        &ReportOptions {
            include_file_details: false,
            ..opts()
        },
    );
    assert!(r2.files.is_empty());
}

// ---------------------------------------------------------------------------
// Report: anomalies
// ---------------------------------------------------------------------------

#[test]
fn suspicious_meta_and_orphan_flags() {
    let mut fs = StubFs::new();
    let mut e = stub_entry(1, "/odd.bin", EntryKind::File, 4);
    e.meta = HashMap::from([
        ("beyond_eod".into(), "true".into()),
        ("lfn_checksum_ok".into(), "false".into()),
        ("lfn_partial".into(), "true".into()),
        ("carved_dirent".into(), "yes".into()),
        ("inode_cleared".into(), "true".into()),
        ("inode_reused".into(), "5->7".into()),
        ("inode_unallocated".into(), "true".into()),
        // Non-trigger values must NOT flag.
        ("beyond_eod_dup".into(), "x".into()), // unknown key — harmless
    ]);
    fs.push(e);
    let mut o1 = stub_entry(2, "/flag_orphan.bin", EntryKind::File, 4);
    o1.meta = HashMap::from([("orphan".into(), "true".into())]);
    fs.push(o1);
    let mut o2 = stub_entry(3, "/list_orphan.bin", EntryKind::File, 4);
    o2.meta = HashMap::from([("orphan_list".into(), "inode 88".into())]);
    fs.push(o2);
    fs.push(stub_entry(4, "/$LOST/chain_3", EntryKind::File, 4));

    let r = generate(&fs, &opts());
    let meta_anoms: Vec<_> = r
        .anomalies
        .iter()
        .filter(|a| a.kind == "suspicious-meta")
        .collect();
    for key in [
        "beyond_eod",
        "lfn_checksum_ok",
        "lfn_partial",
        "carved_dirent",
        "inode_cleared",
        "inode_reused",
        "inode_unallocated",
    ] {
        assert!(
            meta_anoms.iter().any(|a| a.detail.starts_with(key)),
            "missing suspicious-meta anomaly for {key}: {:?}",
            r.anomalies
        );
    }
    assert_eq!(meta_anoms.len(), 7);

    let orphans: Vec<_> = r.anomalies.iter().filter(|a| a.kind == "orphan").collect();
    assert_eq!(orphans.len(), 3, "{:?}", orphans);
    assert!(orphans.iter().any(|a| a.detail.contains("orphan list")));
    assert!(orphans.iter().any(|a| a.path == "/$LOST/chain_3"));
}

#[test]
fn walk_errors_and_max_entries_cap() {
    let mut fs = StubFs::new();
    fs.push(stub_entry(1, "/a", EntryKind::File, 0));
    fs.items.push(StubItem::Error("bogus dirent".into()));
    fs.push(stub_entry(2, "/b", EntryKind::File, 0));
    fs.push(stub_entry(3, "/c", EntryKind::File, 0));

    let r = generate(&fs, &opts());
    assert_eq!(r.census.walk_errors, 1);
    assert_eq!(r.census.total_entries, 3);
    assert!(r
        .anomalies
        .iter()
        .any(|a| a.kind == "walk-error" && a.detail.contains("bogus dirent")));

    let capped = generate(
        &fs,
        &ReportOptions {
            max_entries: 2,
            ..opts()
        },
    );
    assert_eq!(capped.census.total_entries, 2, "walk must stop at the cap");
    assert!(capped.anomalies.iter().any(|a| a
        .detail
        .contains("walk truncated at 2 entries")));
}

// ---------------------------------------------------------------------------
// Report: hashing caps and read failures
// ---------------------------------------------------------------------------

#[test]
fn hash_cap_partial_and_failures() {
    let mut fs = StubFs::new();
    let capped = stub_entry(1, "/big.bin", EntryKind::File, 100);
    fs.push(capped);
    fs.data
        .insert(1, StubData::Bytes(vec![7u8; 100]));
    let denied = stub_entry(2, "/denied.bin", EntryKind::File, 8);
    fs.push(denied);
    fs.fail_ids.insert(2);
    let flaky = stub_entry(3, "/flaky.bin", EntryKind::File, 64);
    fs.push(flaky);
    fs.data.insert(3, StubData::Flaky { good: 5 });

    let r = generate(
        &fs,
        &ReportOptions {
            hash_max_bytes: 10,
            ..opts()
        },
    );
    let big = r.files.iter().find(|f| f.path == "/big.bin").unwrap();
    assert_eq!(big.hashed_bytes, 10, "cap must stop the feed");
    assert!(big.sha256.is_some());
    assert_eq!(big.size, 100);

    let denied = r.files.iter().find(|f| f.path == "/denied.bin").unwrap();
    assert!(denied.sha256.is_none() && denied.hashed_bytes == 0);

    // Mid-stream error: no digest, but hashed_bytes records what was read.
    let flaky = r.files.iter().find(|f| f.path == "/flaky.bin").unwrap();
    assert!(flaky.sha256.is_none());
    assert_eq!(flaky.hashed_bytes, 5);
}

#[test]
fn timestamps_and_meta_in_detail() {
    let mut fs = StubFs::new();
    let mut e = stub_entry(1, "/ts.bin", EntryKind::File, 4);
    e.timestamps.modified = Some(FsTimestamp {
        value: Some(1_700_000_000_000_000_000),
        raw_value: 0,
        raw_encoding: "unix-ns",
        granularity: Duration::from_nanos(1),
    });
    e.timestamps.accessed = Some(FsTimestamp {
        value: Some(-5), // pre-epoch → exercises Json::Int negatives
        raw_value: 0,
        raw_encoding: "unix-ns",
        granularity: Duration::from_nanos(1),
    });
    e.meta = HashMap::from([("zeta".into(), "1".into()), ("alpha".into(), "2".into())]);
    e.allocated_ranges = vec![(0x400, 4), (0x800, 2)];
    fs.push(e);

    let r = generate(&fs, &opts());
    let f = &r.files[0];
    assert_eq!(f.modified_ns, Some(1_700_000_000_000_000_000));
    assert_eq!(f.accessed_ns, Some(-5));
    assert_eq!(f.created_ns, None);
    // Meta sorted by key.
    assert_eq!(
        f.meta,
        vec![
            ("alpha".to_string(), "2".to_string()),
            ("zeta".to_string(), "1".to_string())
        ]
    );
    let j = r.to_json();
    assert!(j.contains("\"accessed_ns\":-5"), "{j}");
    assert!(j.contains("\"stub_key\":\"stub_val\""), "volume meta: {j}");
    assert!(j.contains("[1024,4]"), "extents: {j}");
}

// ---------------------------------------------------------------------------
// Report: magic-mismatch sorting
// ---------------------------------------------------------------------------

fn verdict(sev: Severity) -> MagicVerdict {
    MagicVerdict {
        declared: Some(MagicType::Pdf),
        detected: Some(MagicType::Pe),
        mismatch: true,
        severity: sev,
        reasons: vec!["content disagrees with extension".into()],
    }
}

#[test]
fn magic_mismatch_sorted_worst_first_then_path() {
    let mut fs = StubFs::new();
    let mut z = stub_entry(1, "/z.pdf", EntryKind::File, 10);
    z.magic = Some(verdict(Severity::Suspicious));
    let mut a = stub_entry(2, "/a.pdf", EntryKind::File, 10);
    a.magic = Some(verdict(Severity::Suspicious));
    let mut hi = stub_entry(3, "/m.pdf", EntryKind::File, 10);
    hi.magic = Some(verdict(Severity::High));
    let mut del = stub_entry(4, "/d.pdf", EntryKind::File, 10);
    del.status = deleted(RecoveryState::Intact);
    del.magic = Some(verdict(Severity::Info));
    // A non-mismatch verdict must not appear.
    let mut ok = stub_entry(5, "/ok.pdf", EntryKind::File, 10);
    ok.magic = Some(MagicVerdict {
        declared: Some(MagicType::Pdf),
        detected: Some(MagicType::Pdf),
        mismatch: false,
        severity: Severity::Info,
        reasons: vec![],
    });
    for e in [z, a, hi, del, ok] {
        fs.push(e);
    }

    let r = generate(&fs, &opts());
    let paths: Vec<_> = r.magic_mismatches.iter().map(|m| m.path.as_str()).collect();
    assert_eq!(
        paths,
        ["/m.pdf", "/a.pdf", "/z.pdf", "/d.pdf"],
        "worst severity first; ties by path"
    );
    let del_row = r
        .magic_mismatches
        .iter()
        .find(|m| m.path == "/d.pdf")
        .unwrap();
    assert!(del_row.deleted);
    assert_eq!(del_row.declared.as_deref(), Some("PDF"));
    assert_eq!(del_row.detected.as_deref(), Some("PE/COFF Windows executable"));
    assert!(!del_row.reasons.is_empty());
}

// ---------------------------------------------------------------------------
// Report: renderers on stub data (empty + populated sections)
// ---------------------------------------------------------------------------

#[test]
fn renderers_empty_sections() {
    let fs = StubFs::new();
    let r = generate(&fs, &opts());
    assert_eq!(r.volume.fs_type, "stub");
    assert_eq!(r.volume.image_size, 4096);
    assert_eq!(r.volume.label.as_deref(), Some("STUBVOL"));
    assert_eq!(r.volume.free_blocks, Some(4));
    assert_eq!(r.volume.total_nodes, Some(16));

    let m = r.to_markdown();
    assert!(m.contains("None."), "{m}");
    assert!(m.contains("| fs_type | stub |"), "{m}");
    assert!(m.contains("| uuid | deadbeef |"), "{m}");

    let h = r.to_html();
    assert!(h.contains("<p>None.</p>"), "{h}");
    assert!(h.contains("<th>fs_type</th><td>stub</td>"), "{h}");

    let j = r.to_json_pretty();
    assert!(j.contains("\n  \"volume\": {"), "{j}");
    assert!(j.contains("\"magic_mismatches\": []"), "{j}");
}

#[test]
fn renderers_populated_sections() {
    let mut fs = StubFs::new();
    let mut e = stub_entry(1, "/x.bin", EntryKind::File, 4);
    e.magic = Some(verdict(Severity::Suspicious));
    e.status = deleted(RecoveryState::Unrecoverable);
    e.meta = HashMap::from([("orphan".into(), "true".into())]);
    fs.push(e);
    fs.data.insert(1, StubData::Bytes(b"data".to_vec()));
    fs.items.push(StubItem::Error("walk hiccup".into()));

    let r = generate(
        &fs,
        &ReportOptions {
            examiner_notes: "note <here>".into(),
            image_desc: "stub image".into(),
            ..opts()
        },
    );
    let m = r.to_markdown();
    for needle in [
        "| Path | Size | Recovery |",
        "| Severity | Path | Declared |",
        "`orphan`",
        "`walk-error`",
        "unrecoverable",
        "note <here>",
        "stub image",
    ] {
        assert!(m.contains(needle), "markdown missing {needle}: {m}");
    }
    let h = r.to_html();
    for needle in [
        "Deleted recovery",
        "sev-suspicious",
        "class=\"orphan\"",
        "class=\"walk-error\"",
        "note &lt;here&gt;",
        "Image: stub image",
    ] {
        assert!(h.contains(needle), "html missing {needle}: {h}");
    }
    // examiner_notes passthrough verbatim in JSON.
    let j = r.to_json();
    assert!(j.contains("\"examiner_notes\":\"note <here>\""), "{j}");
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

#[test]
fn diff_kind_and_timestamp_changes() {
    let mut a = StubFs::new();
    a.push(stub_entry(1, "/node", EntryKind::File, 4));
    a.data.insert(1, StubData::Bytes(b"abcd".to_vec()));
    let mut ts_a = stub_entry(2, "/ts", EntryKind::File, 4);
    ts_a.timestamps.modified = Some(FsTimestamp {
        value: Some(111),
        raw_value: 0,
        raw_encoding: "unix-ns",
        granularity: Duration::from_nanos(1),
    });
    a.push(ts_a);

    let mut b = StubFs::new();
    b.push(stub_entry(1, "/node", EntryKind::Directory, 0)); // kind flip
    let mut ts_b = stub_entry(2, "/ts", EntryKind::File, 4);
    ts_b.timestamps.modified = Some(FsTimestamp {
        value: Some(222),
        raw_value: 0,
        raw_encoding: "unix-ns",
        granularity: Duration::from_nanos(1),
    });
    ts_b.timestamps.created = Some(FsTimestamp {
        value: Some(9),
        raw_value: 0,
        raw_encoding: "unix-ns",
        granularity: Duration::from_nanos(1),
    });
    b.push(ts_b);
    b.data.insert(2, StubData::Bytes(b"abcd".to_vec()));

    let d = diff(&a, &b, &DiffOptions::default());
    let node = d.modified.iter().find(|m| m.path == "/node").unwrap();
    assert!(node.changes.iter().any(|c| c.contains("kind: file -> directory")));
    assert!(node.changes.iter().any(|c| c.starts_with("size: 4 -> 0")));
    let ts = d.modified.iter().find(|m| m.path == "/ts").unwrap();
    assert!(ts.changes.iter().any(|c| c.starts_with("modified: Some(111)")));
    assert!(ts.changes.iter().any(|c| c.starts_with("created: None")));
}

#[test]
fn diff_recovery_transition_labels() {
    let mut a = StubFs::new();
    let mut e = stub_entry(1, "/victim.bin", EntryKind::File, 10);
    e.status = deleted(RecoveryState::Intact);
    a.push(e);
    let mut b = StubFs::new();
    let mut e2 = stub_entry(1, "/victim.bin", EntryKind::File, 10);
    e2.status = deleted(RecoveryState::PartiallyOverwritten {
        recovered_bytes: 2,
        total_bytes: 10,
    });
    b.push(e2);

    let d = diff(&a, &b, &DiffOptions::default());
    assert_eq!(d.deleted_changes.len(), 1);
    assert_eq!(d.deleted_changes[0].from, "deleted(intact)");
    assert_eq!(d.deleted_changes[0].to, "deleted(partially_overwritten)");
    assert!(d.to_text().contains("deleted(intact) -> deleted(partially_overwritten)"));
}

#[test]
fn diff_truncation_errors_and_pretty() {
    let mut a = StubFs::new();
    a.items.push(StubItem::Error("a-side corrupt".into()));
    for i in 0..3u64 {
        a.push(stub_entry(i, &format!("/a{i}"), EntryKind::File, 0));
    }
    let mut b = StubFs::new();
    b.items.push(StubItem::Error("b-side corrupt".into()));

    let d = diff(
        &a,
        &b,
        &DiffOptions {
            max_entries: 2,
            ..Default::default()
        },
    );
    assert!(d.truncated);
    assert_eq!(d.errors_a, 1);
    assert_eq!(d.errors_b, 1);
    // Cap stopped A's walk after 2 entries → /a2 never read; the two
    // collected paths show as removed (absent from empty B).
    assert_eq!(d.removed.len(), 2, "{:?}", d.removed);
    assert!(d.removed.contains(&"/a0".to_string()));
    let t = d.to_text();
    assert!(t.contains("TRUNCATED"));
    assert!(t.contains("walk errors: A=1 B=1"));
    let jp = d.to_json_pretty();
    assert!(jp.contains("\n  \"added\": ["), "{jp}");
    assert!(jp.contains("\"errors_a\": 1"), "{jp}");
}

#[test]
fn diff_unhashable_sides_and_no_hash_option() {
    // Same path/size/ts both sides; one side unreadable, one clean with
    // different bytes → hash pair is (None, Some) → skipped, no change.
    let mut a = StubFs::new();
    a.push(stub_entry(1, "/f.bin", EntryKind::File, 4));
    a.data.insert(1, StubData::Bytes(b"aaaa".to_vec()));
    let mut b = StubFs::new();
    b.push(stub_entry(1, "/f.bin", EntryKind::File, 4));
    b.fail_ids.insert(1);

    let d = diff(&a, &b, &DiffOptions::default());
    assert!(d.is_clean(), "unhashable side must not fabricate a change: {d:?}");

    // hash_content=false: a same-size overwrite is invisible.
    let mut b2 = StubFs::new();
    b2.push(stub_entry(1, "/f.bin", EntryKind::File, 4));
    b2.data.insert(1, StubData::Bytes(b"bbbb".to_vec()));
    let d2 = diff(
        &a,
        &b2,
        &DiffOptions {
            hash_content: false,
            ..Default::default()
        },
    );
    assert!(d2.is_clean());
    // …and with hashing on the overwrite is caught.
    let d3 = diff(&a, &b2, &DiffOptions::default());
    let m = d3.modified.iter().find(|m| m.path == "/f.bin").unwrap();
    assert!(m.changes.iter().any(|c| c.contains("content hash")));
}

#[test]
fn diff_duplicate_paths_first_wins() {
    let mut a = StubFs::new();
    a.push(stub_entry(1, "/dup", EntryKind::File, 1));
    a.push(stub_entry(2, "/dup", EntryKind::File, 99)); // hostile duplicate
    a.data.insert(1, StubData::Bytes(b"x".to_vec()));
    a.data.insert(2, StubData::Bytes(b"yy".to_vec()));
    let mut b = StubFs::new();
    b.push(stub_entry(3, "/dup", EntryKind::File, 1));
    b.data.insert(3, StubData::Bytes(b"x".to_vec()));

    let d = diff(&a, &b, &DiffOptions::default());
    assert!(d.is_clean(), "first duplicate wins: {d:?}");
}
