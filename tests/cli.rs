//! Integration tests for the `sutramfs` binary.
//!
//! Drives the compiled binary (`CARGO_BIN_EXE_sutramfs`) against the
//! synthetic FAT12 / MBR images from `common` and asserts on exit codes
//! and stdout/stderr — the CLI is thin, so end-to-end is the honest test.

mod common;

use std::process::{Command, Output};

fn sutramfs() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sutramfs"))
}

fn run(args: &[&str]) -> Output {
    sutramfs()
        .args(args)
        .output()
        .expect("spawn sutramfs")
}

fn ok(out: Output) -> String {
    assert!(
        out.status.success(),
        "expected success, got {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("stdout utf8")
}

fn fail(out: Output) -> String {
    assert!(
        !out.status.success(),
        "expected failure, got success\nstdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8(out.stderr).expect("stderr utf8")
}

// ---- detect -----------------------------------------------------------

#[test]
fn detect_lists_all_parsers_sorted() {
    let img = common::temp_image(&common::fat12(), "detect");
    let out = run(&["detect", img.path().to_str().unwrap()]);
    let s = ok(out);
    assert!(s.contains("parser"));
    // FAT must be the top hit on a FAT12 volume.
    let first = s.lines().nth(1).unwrap();
    assert!(first.starts_with("fat"), "top row was: {first}");
    for name in ["ntfs", "exfat", "fat", "ext4", "btrfs", "f2fs", "xfs", "hfs", "apfs"] {
        assert!(s.lines().any(|l| l.starts_with(name)), "missing {name}");
    }
}

#[test]
fn detect_empty_image_still_exits_zero() {
    let img = common::temp_image(&[], "empty");
    let s = ok(run(&["detect", img.path().to_str().unwrap()]));
    assert!(s.contains("fat"));
}

#[test]
fn detect_ff_image_no_panic() {
    let img = common::temp_image(&vec![0xFFu8; 4096], "ff");
    let s = ok(run(&["detect", img.path().to_str().unwrap()]));
    assert!(s.contains("None") || s.contains("Low"));
}

#[test]
fn detect_random_image_no_panic() {
    // Deterministic "random" bytes — xorshift so the test is stable.
    let mut v = vec![0u8; 8192];
    let mut x = 0x9E3779B97F4A7C15u64;
    for b in &mut v {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
    let img = common::temp_image(&v, "rand");
    ok(run(&["detect", img.path().to_str().unwrap()]));
}

// ---- usage / arg errors ------------------------------------------------

#[test]
fn no_args_prints_usage_exit_2() {
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("detect"), "usage text: {err}");
}

#[test]
fn unknown_command_exit_2() {
    let out = run(&["frobnicate"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn unknown_flag_fails() {
    let img = common::temp_image(&common::fat12(), "badflag");
    let err = fail(run(&["ls", "--bogus", img.path().to_str().unwrap()]));
    assert!(err.contains("unknown flag"), "stderr: {err}");
}

#[test]
fn missing_image_fails() {
    let err = fail(run(&["ls"]));
    assert!(err.contains("missing <image>"), "stderr: {err}");
}

#[test]
fn nonexistent_image_fails() {
    let err = fail(run(&["detect", "/nonexistent/definitely-not-here.img"]));
    assert!(err.contains("open"), "stderr: {err}");
}

#[test]
fn bad_partition_index_fails() {
    let img = common::temp_image(&common::fat12(), "badpart");
    let err = fail(run(&["ls", img.path().to_str().unwrap(), "-p", "9"]));
    assert!(err.contains("partition") || err.contains("no partition"), "stderr: {err}");
}

#[test]
fn bad_fs_type_fails() {
    let img = common::temp_image(&common::fat12(), "badtype");
    let err = fail(run(&["ls", img.path().to_str().unwrap(), "-t", "nosuchfs"]));
    assert!(err.contains("unknown fs type"), "stderr: {err}");
}

#[test]
fn unrecognized_image_needs_t_flag() {
    let img = common::temp_image(&vec![0xABu8; 4096], "unrec");
    let err = fail(run(&["info", img.path().to_str().unwrap()]));
    assert!(err.contains("no parser recognised"), "stderr: {err}");
}

// ---- parts -------------------------------------------------------------

#[test]
fn parts_bare_fs_reports_none() {
    let img = common::temp_image(&common::fat12(), "partsbare");
    let s = ok(run(&["parts", img.path().to_str().unwrap()]));
    assert!(s.contains("no partition table"), "stdout: {s}");
}

#[test]
fn parts_lists_mbr_entry() {
    let disk = common::mbr_disk(&common::fat12(), 1);
    let img = common::temp_image(&disk, "parts");
    let s = ok(run(&["parts", img.path().to_str().unwrap()]));
    assert!(s.contains("Mbr"), "stdout: {s}");
    assert!(s.contains("0x01"), "stdout: {s}");
}

// ---- info / ls / cat ---------------------------------------------------

#[test]
fn info_shows_fat12_fields() {
    let img = common::temp_image(&common::fat12(), "info");
    let s = ok(run(&["info", img.path().to_str().unwrap()]));
    assert!(s.contains("type:"), "stdout: {s}");
    assert!(s.to_lowercase().contains("fat12"), "stdout: {s}");
    assert!(s.contains("block_size:"), "stdout: {s}");
}

#[test]
fn info_forced_type_flag() {
    let img = common::temp_image(&common::fat12(), "infot");
    let s = ok(run(&["info", img.path().to_str().unwrap(), "-t", "fat"]));
    assert!(s.to_lowercase().contains("fat"), "stdout: {s}");
}

#[test]
fn info_strict_flag() {
    let img = common::temp_image(&common::fat12(), "infostrict");
    ok(run(&["info", img.path().to_str().unwrap(), "--strict"]));
}

#[test]
fn ls_tree_lists_root_entries() {
    let img = common::temp_image(&common::fat12(), "lstree");
    let s = ok(run(&["ls", img.path().to_str().unwrap()]));
    assert!(s.contains("HELLO.TXT"), "stdout: {s}");
    assert!(s.contains("SUBDIR"), "stdout: {s}");
    assert!(s.contains("INNER.TXT"), "stdout: {s}");
    assert!(s.contains("entries"), "stdout: {s}");
}

#[test]
fn ls_deleted_only_filters_live() {
    let img = common::temp_image(&common::fat12(), "lsdel");
    let s = ok(run(&["ls", img.path().to_str().unwrap(), "-d"]));
    assert!(!s.contains("HELLO.TXT"), "stdout: {s}");
    assert!(s.contains("ELETED"), "stdout: {s}");
}

#[test]
fn ls_json_emits_jsonl() {
    let img = common::temp_image(&common::fat12(), "lsjson");
    let s = ok(run(&["ls", img.path().to_str().unwrap(), "-o", "json"]));
    let mut saw_hello = false;
    for line in s.lines().filter(|l| !l.trim().is_empty()) {
        assert!(line.starts_with('{'), "not a JSON object: {line}");
        assert!(line.contains("\"name\""), "no name field: {line}");
        if line.contains("HELLO.TXT") {
            saw_hello = true;
        }
    }
    assert!(saw_hello, "no HELLO.TXT in: {s}");
}

#[test]
fn ls_csv_and_bodyfile_formats() {
    let img = common::temp_image(&common::fat12(), "lsfmt");
    let csv = ok(run(&["ls", img.path().to_str().unwrap(), "-o", "csv"]));
    assert!(csv.contains("HELLO.TXT"), "csv: {csv}");
    let bf = ok(run(&["ls", img.path().to_str().unwrap(), "-o", "bodyfile"]));
    assert!(bf.contains('|'), "bodyfile: {bf}");
}

#[test]
fn cat_recovers_file_contents() {
    let img = common::temp_image(&common::fat12(), "cat");
    let out = run(&["cat", img.path().to_str().unwrap(), "HELLO.TXT"]);
    let s = ok(out);
    assert!(s.contains("hello world!"), "stdout: {s}");
}

#[test]
fn cat_by_full_path() {
    let img = common::temp_image(&common::fat12(), "catpath");
    let s = ok(run(&["cat", img.path().to_str().unwrap(), "/SUBDIR/INNER.TXT"]));
    assert!(s.contains("inner"), "stdout: {s}");
}

#[test]
fn cat_missing_path_fails() {
    let img = common::temp_image(&common::fat12(), "catmiss");
    let err = fail(run(&["cat", img.path().to_str().unwrap(), "NOPE.BIN"]));
    assert!(err.contains("no entry"), "stderr: {err}");
}

#[test]
fn cat_deleted_file_recovers() {
    let img = common::temp_image(&common::fat12(), "catdel");
    // Deleted entries render with a `_` first byte (TSK convention).
    let s = ok(run(&[
        "cat",
        img.path().to_str().unwrap(),
        "_ELETED.TXT",
        "--recover",
    ]));
    assert!(s.contains("0123456789"), "stdout: {s}");
}

// ---- carve --------------------------------------------------------------

#[test]
fn carve_runs_and_reports_hits() {
    let img = common::temp_image(&common::fat12(), "carve");
    let out = run(&["carve", img.path().to_str().unwrap()]);
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    ok(out);
    assert!(err.contains("carve hits"), "stderr: {err}");
}

#[test]
fn carve_offset_len_align_flags() {
    let img = common::temp_image(&common::fat12(), "carveflags");
    ok(run(&[
        "carve",
        img.path().to_str().unwrap(),
        "--offset", "512",
        "--len", "1024",
        "--align", "512",
    ]));
}

#[test]
fn carve_bad_offset_fails() {
    let img = common::temp_image(&common::fat12(), "carveoff");
    fail(run(&["carve", img.path().to_str().unwrap(), "--offset", "xyz"]));
}

#[test]
fn carve_unallocated_flag() {
    let img = common::temp_image(&common::fat12(), "carveun");
    ok(run(&["carve", img.path().to_str().unwrap(), "--unallocated"]));
}

// ---- partition-scoped mount ---------------------------------------------

#[test]
fn partition_scoped_ls_and_detect() {
    let disk = common::mbr_disk(&common::fat12(), 1);
    let img = common::temp_image(&disk, "part");
    let s = ok(run(&["ls", img.path().to_str().unwrap(), "-p", "0"]));
    assert!(s.contains("HELLO.TXT"), "stdout: {s}");
    let d = ok(run(&["detect", img.path().to_str().unwrap(), "-p", "0"]));
    assert!(d.lines().nth(1).unwrap().starts_with("fat"), "detect: {d}");
}

// ---- android -------------------------------------------------------------

#[test]
fn android_command_runs_on_bare_image() {
    let img = common::temp_image(&common::fat12(), "android");
    // analyze() may fail on a non-Android image — that's fine; assert the
    // command exits cleanly in either direction without a panic.
    let out = run(&["android", img.path().to_str().unwrap()]);
    assert!(out.status.code() == Some(0) || out.status.code() == Some(1));
}
