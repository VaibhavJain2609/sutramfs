//! Integration tests: mount the synthetic FAT12 corpus and verify every
//! report section — census, deleted recovery, magic mismatches, anomalies,
//! per-file detail — plus all three renderers.

mod common;

use std::sync::Arc;

use sutram_fs::{FileSystem, FsParser};
use sutram_report::{generate, ReportOptions};

fn mount(img: Vec<u8>) -> Box<dyn FileSystem> {
    sutram_fat::FatParser
        .mount(Arc::new(img))
        .expect("synthetic FAT12 must mount")
}

fn report() -> sutram_report::Report {
    let fs = mount(common::image_a());
    let opts = ReportOptions {
        title: "Case 2024-001 — test image".into(),
        image_desc: "synthetic FAT12 (tests/common::image_a)".into(),
        examiner_notes: "Corpus built in-memory; all offsets reproducible.".into(),
        ..Default::default()
    };
    generate(fs.as_ref(), &opts)
}

#[test]
fn volume_summary_populated() {
    let r = report();
    assert!(r.volume.fs_type.starts_with("FAT"), "{}", r.volume.fs_type);
    assert!(r.volume.block_size > 0);
    assert_eq!(r.volume.image_size, 1 << 20);
    assert!(r.tool.starts_with("sutram-report"));
}

#[test]
fn census_counts() {
    let r = report();
    let c = &r.census;
    // live: HELLO.TXT, SUBDIR, INNER.TXT, EVIL.DOC (+ maybe a root entry)
    assert!(c.live >= 4, "live={}", c.live);
    assert!(c.files >= 3);
    assert!(c.directories >= 1);
    assert!(c.deleted >= 1, "deleted={}", c.deleted);
    assert_eq!(c.walk_errors, 0, "clean image must not emit errors");
    assert!(c.live_bytes >= 12 + 4 + 60);
}

#[test]
fn deleted_recovery_table() {
    let r = report();
    let row = r
        .deleted
        .rows
        .iter()
        .find(|d| d.path == "/_DELETED.TXT")
        .expect("deleted row for _DELETED.TXT");
    assert_eq!(row.recovery, "intact", "chain survives → intact");
    assert_eq!(row.recovered_bytes, 12);
    assert_eq!(row.total_bytes, 12);
    assert!(row.disk_offset > 0, "provenance offset required");
    assert!(r.deleted.intact >= 1);
    assert!(r.deleted.recovered_bytes >= 12);
}

#[test]
fn magic_mismatch_high_severity_first() {
    let r = report();
    assert!(
        !r.magic_mismatches.is_empty(),
        "EVIL.DOC masquerade must be flagged"
    );
    let top = &r.magic_mismatches[0];
    assert_eq!(top.path, "/EVIL.DOC");
    assert_eq!(sutram_report::report::severity_label(top.severity), "high");
    assert_eq!(top.detected.as_deref(), Some("PE/COFF Windows executable"));
    assert!(!top.reasons.is_empty(), "verdict reasons must be preserved");
}

#[test]
fn orphan_anomaly_reported() {
    let r = report();
    let orphans: Vec<_> = r
        .anomalies
        .iter()
        .filter(|a| a.kind == "orphan")
        .collect();
    assert!(
        !orphans.is_empty(),
        "allocated-unreferenced cluster 8 must surface as orphan: {:?}",
        r.anomalies
    );
    assert!(orphans[0].path.contains("$ORPHANED"));
}

#[test]
fn file_detail_hashes_and_provenance() {
    let r = report();
    let hello = r
        .files
        .iter()
        .find(|f| f.path == "/HELLO.TXT")
        .expect("file detail for HELLO.TXT");
    // sha256("hello world!") — verified against coreutils.
    assert_eq!(
        hello.sha256.as_deref(),
        Some("7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9")
    );
    assert_eq!(hello.hashed_bytes, 12);
    assert_eq!(hello.disk_offset as usize, common::ROOT_OFF + 32);
    assert_eq!(
        hello.allocated_ranges.first().map(|r| r.0 as usize),
        Some(common::clus_off(2))
    );
    // Deleted file detail still hashes its recoverable bytes.
    let del = r.files.iter().find(|f| f.path == "/_DELETED.TXT").unwrap();
    assert_eq!(del.status, "deleted");
    assert_eq!(del.recovery, "intact");
}

#[test]
fn json_output_shape() {
    let r = report();
    let j = r.to_json();
    assert!(j.starts_with('{') && j.ends_with('}'));
    for needle in [
        "\"fs_type\":\"FAT",
        "\"census\":{",
        "\"recovery\":\"intact\"",
        "\"severity\":\"high\"",
        "\"sha256\":\"7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9\"",
        "\"orphan\"",
        "\"examiner_notes\":\"Corpus built in-memory",
    ] {
        assert!(j.contains(needle), "missing {needle} in {j}");
    }
}

#[test]
fn markdown_sections() {
    let r = report();
    let m = r.to_markdown();
    for needle in [
        "# Case 2024-001",
        "## Volume",
        "## Entry census",
        "## Deleted recovery",
        "## Extension/content mismatches",
        "## Anomalies",
        "## File details",
        "## Examiner notes",
        "/EVIL.DOC",
        "/_DELETED.TXT",
        "7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9",
    ] {
        assert!(m.contains(needle), "missing {needle}");
    }
}

#[test]
fn html_self_contained_and_escaped() {
    let r = report();
    let h = r.to_html();
    assert!(h.starts_with("<!DOCTYPE html>"));
    assert!(h.contains("<style>"));
    assert!(!h.contains("<script"), "no JS allowed");
    assert!(h.contains("sev-high"), "severity styling");
    assert!(h.contains("/EVIL.DOC"));
    // A hostile value must be escaped — exercise through notes.
    let fs = mount(common::image_a());
    let opts = ReportOptions {
        examiner_notes: "x<script>alert(1)</script>&\"'".into(),
        ..Default::default()
    };
    let h2 = generate(fs.as_ref(), &opts).to_html();
    assert!(h2.contains("&lt;script&gt;"));
    assert!(!h2.contains("<script>alert"));
    assert!(h2.contains("&quot;"));
}

#[test]
fn no_hash_option() {
    let fs = mount(common::image_a());
    let opts = ReportOptions {
        hash_files: false,
        ..Default::default()
    };
    let r = generate(fs.as_ref(), &opts);
    assert!(r.files.iter().all(|f| f.sha256.is_none()));
    // Report still carries size+timestamps+provenance per the fallback plan.
    let hello = r.files.iter().find(|f| f.path == "/HELLO.TXT").unwrap();
    assert_eq!(hello.size, 12);
    assert!(!hello.allocated_ranges.is_empty());
}
