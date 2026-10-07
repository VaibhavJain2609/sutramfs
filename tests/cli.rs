//! Integration tests for the `sutramfs` binary.
//!
//! Drives the compiled binary (`CARGO_BIN_EXE_sutramfs`) against the
//! synthetic FAT12 / MBR images from `common` and asserts on exit codes
//! and stdout/stderr — the CLI is thin, so end-to-end is the honest test.
//! Per-format coverage lives in `smoke.rs`; this file concentrates on
//! argument parsing, output formats, and error paths.

mod common;

use std::process::{Command, Output};

fn sutramfs() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sutramfs"))
}

fn run(args: &[&str]) -> Output {
    sutramfs().args(args).output().expect("spawn sutramfs")
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

// ---- detect ------------------------------------------------------------

#[test]
fn detect_lists_all_parsers_sorted() {
    let img = common::temp_image(&common::fat12(), "detect");
    let s = ok(run(&["detect", img.path().to_str().unwrap()]));
    assert!(s.contains("parser"));
    // FAT must be the top hit on a FAT12 volume.
    let first = s.lines().nth(1).unwrap();
    assert!(first.starts_with("fat"), "top row was: {first}");
    assert!(first.contains("Certain"), "top row was: {first}");
    for name in [
        "ntfs", "exfat", "fat", "ext4", "btrfs", "f2fs", "xfs", "hfs", "apfs",
    ] {
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

// ---- usage / arg errors --------------------------------------------------

#[test]
fn no_args_prints_usage_exit_2() {
    let out = run(&[]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("detect"), "usage text: {err}");
}

#[test]
fn help_flags_print_usage() {
    for f in ["-h", "--help"] {
        let out = run(&[f]);
        assert_eq!(out.status.code(), Some(2), "flag {f}");
        assert!(String::from_utf8_lossy(&out.stderr).contains("detect"));
    }
}

#[test]
fn unknown_command_exit_2() {
    let out = run(&["frobnicate"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown command"));
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
    assert!(
        err.contains("partition") || err.contains("no partition"),
        "stderr: {err}"
    );
}

#[test]
fn partition_flag_needs_value() {
    let img = common::temp_image(&common::fat12(), "pval");
    let err = fail(run(&["ls", img.path().to_str().unwrap(), "-p"]));
    assert!(err.contains("-p"), "stderr: {err}");
}

#[test]
fn bad_fs_type_fails() {
    let img = common::temp_image(&common::fat12(), "badtype");
    let err = fail(run(&["ls", img.path().to_str().unwrap(), "-t", "nosuchfs"]));
    assert!(err.contains("unknown fs type"), "stderr: {err}");
}

#[test]
fn type_flag_needs_value() {
    let img = common::temp_image(&common::fat12(), "tval");
    let err = fail(run(&["ls", img.path().to_str().unwrap(), "-t"]));
    assert!(err.contains("-t"), "stderr: {err}");
}

#[test]
fn unrecognized_image_needs_t_flag() {
    let img = common::temp_image(&vec![0xABu8; 4096], "unrec");
    let err = fail(run(&["info", img.path().to_str().unwrap()]));
    assert!(err.contains("no parser recognised"), "stderr: {err}");
}

#[test]
fn ls_bad_output_format_fails() {
    let img = common::temp_image(&common::fat12(), "badfmt");
    let err = fail(run(&["ls", img.path().to_str().unwrap(), "-o", "yaml"]));
    assert!(err.contains("unknown output format"), "stderr: {err}");
}

#[test]
fn ls_output_flag_needs_value() {
    let img = common::temp_image(&common::fat12(), "oval");
    let err = fail(run(&["ls", img.path().to_str().unwrap(), "-o"]));
    assert!(err.contains("-o"), "stderr: {err}");
}

// ---- parts ---------------------------------------------------------------

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

// ---- info / ls / cat ------------------------------------------------------

#[test]
fn info_shows_fat12_fields() {
    let img = common::temp_image(&common::fat12(), "info");
    let s = ok(run(&["info", img.path().to_str().unwrap()]));
    assert!(s.contains("type:"), "stdout: {s}");
    assert!(s.to_lowercase().contains("fat"), "stdout: {s}");
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
fn ls_walk_alias_works() {
    let img = common::temp_image(&common::fat12(), "walkalias");
    let s = ok(run(&["walk", img.path().to_str().unwrap()]));
    assert!(s.contains("HELLO.TXT"), "stdout: {s}");
}

#[test]
fn ls_deleted_only_filters_live() {
    let img = common::temp_image(&common::fat12(), "lsdel");
    let s = ok(run(&["ls", img.path().to_str().unwrap(), "-d"]));
    assert!(!s.contains("HELLO.TXT"), "stdout: {s}");
    assert!(s.contains("ELETED"), "stdout: {s}");
}

#[test]
fn ls_marks_masquerade_file() {
    // FAKE.TXT holds MZ/PE bytes — must be flagged in both tree and json.
    let img = common::temp_image(&common::fat12(), "masq");
    let s = ok(run(&["ls", img.path().to_str().unwrap()]));
    let fake = s.lines().find(|l| l.contains("FAKE.TXT"));
    assert!(
        fake.is_some_and(|l| l.contains("MAGIC-MISMATCH")),
        "tree row: {s}"
    );
    let j = ok(run(&["ls", img.path().to_str().unwrap(), "-o", "json"]));
    let fj = j.lines().find(|l| l.contains("FAKE.TXT"));
    assert!(
        fj.is_some_and(|l| l.contains("\"mismatch\":true")),
        "json row: {j}"
    );
}

#[test]
fn ls_json_emits_valid_jsonl() {
    let img = common::temp_image(&common::fat12(), "lsjson");
    let s = ok(run(&["ls", img.path().to_str().unwrap(), "-o", "json"]));
    let mut saw_hello = false;
    for line in s.lines().filter(|l| !l.trim().is_empty()) {
        assert!(line.starts_with('{') && line.ends_with('}'), "not a JSON object: {line}");
        for key in [
            "\"path\"", "\"name\"", "\"entry_id\"", "\"kind\"", "\"size\"",
            "\"disk_offset\"", "\"allocated_ranges\"", "\"status\"",
            "\"timestamps\"", "\"meta\"", "\"magic\"",
        ] {
            assert!(line.contains(key), "missing {key}: {line}");
        }
        if line.contains("HELLO.TXT") {
            saw_hello = true;
        }
    }
    assert!(saw_hello, "no HELLO.TXT in: {s}");
}

#[test]
fn ls_jsonl_alias_emits_jsonl() {
    let img = common::temp_image(&common::fat12(), "jsonl");
    let s = ok(run(&["ls", img.path().to_str().unwrap(), "-o", "jsonl"]));
    // `meta` is a HashMap — key order varies per process, so assert
    // structural validity rather than byte-equality with `-o json`.
    for line in s.lines().filter(|l| !l.trim().is_empty()) {
        assert!(line.starts_with('{') && line.ends_with('}'), "non-JSONL: {line}");
    }
    assert!(s.contains("HELLO.TXT"));
}

#[test]
fn ls_csv_has_header_and_rows() {
    let img = common::temp_image(&common::fat12(), "lscsv");
    let s = ok(run(&["ls", img.path().to_str().unwrap(), "-o", "csv"]));
    let mut lines = s.lines();
    assert_eq!(
        lines.next().unwrap(),
        "entry_id,kind,size,status,mtime,disk_offset,path"
    );
    assert!(lines.any(|l| l.contains("HELLO.TXT")), "csv: {s}");
}

#[test]
fn ls_bodyfile_is_mactime_parseable() {
    let img = common::temp_image(&common::fat12(), "lsbf");
    let s = ok(run(&["ls", img.path().to_str().unwrap(), "-o", "bodyfile"]));
    let mut rows = 0;
    for line in s.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split('|').collect();
        assert_eq!(f.len(), 10, "bodyfile field count: {line}");
        assert!(f[0].starts_with('/'), "name field: {line}");
        // inode + size + MACB fields must be integers.
        for (i, fld) in f.iter().enumerate() {
            if matches!(i, 1 | 5 | 6 | 7 | 8 | 9) {
                assert!(fld.parse::<i64>().is_ok(), "field {i} in: {line}");
            }
        }
        rows += 1;
    }
    assert!(rows > 0);
}

#[test]
fn ls_mactime_alias_emits_bodyfile() {
    let img = common::temp_image(&common::fat12(), "mact");
    let s = ok(run(&["ls", img.path().to_str().unwrap(), "-o", "mactime"]));
    assert!(
        s.lines().all(|l| l.split('|').count() == 10),
        "mactime rows: {s}"
    );
}

#[test]
fn ls_deleted_json_rows_are_deleted() {
    let img = common::temp_image(&common::fat12(), "lsdj");
    let s = ok(run(&[
        "ls",
        img.path().to_str().unwrap(),
        "-d",
        "-o",
        "json",
    ]));
    for line in s.lines().filter(|l| !l.trim().is_empty()) {
        assert!(
            line.contains("\"status\":\"deleted"),
            "expected deleted: {line}"
        );
    }
}

#[test]
fn cat_recovers_file_contents() {
    let img = common::temp_image(&common::fat12(), "cat");
    let s = ok(run(&["cat", img.path().to_str().unwrap(), "HELLO.TXT"]));
    assert!(s.contains("hello world!"), "stdout: {s}");
}

#[test]
fn cat_by_full_path() {
    let img = common::temp_image(&common::fat12(), "catpath");
    let s = ok(run(&["cat", img.path().to_str().unwrap(), "/SUBDIR/INNER.TXT"]));
    assert!(s.contains("inner"), "stdout: {s}");
}

#[test]
fn cat_extract_alias_works() {
    let img = common::temp_image(&common::fat12(), "extract");
    let s = ok(run(&["extract", img.path().to_str().unwrap(), "/HELLO.TXT"]));
    assert!(s.contains("hello world!"), "stdout: {s}");
}

#[test]
fn cat_missing_path_fails() {
    let img = common::temp_image(&common::fat12(), "catmiss");
    let err = fail(run(&["cat", img.path().to_str().unwrap(), "NOPE.BIN"]));
    assert!(err.contains("no entry"), "stderr: {err}");
}

#[test]
fn cat_missing_path_arg_fails() {
    let img = common::temp_image(&common::fat12(), "catnoarg");
    let err = fail(run(&["cat", img.path().to_str().unwrap()]));
    assert!(err.contains("usage"), "stderr: {err}");
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

// ---- carve -----------------------------------------------------------------

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
        "--offset",
        "512",
        "--len",
        "1024",
        "--align",
        "512",
    ]));
}

#[test]
fn carve_bad_offset_fails() {
    let img = common::temp_image(&common::fat12(), "carveoff");
    fail(run(&[
        "carve",
        img.path().to_str().unwrap(),
        "--offset",
        "xyz",
    ]));
}

#[test]
fn carve_bad_len_fails() {
    let img = common::temp_image(&common::fat12(), "carvelen");
    fail(run(&["carve", img.path().to_str().unwrap(), "--len", "abc"]));
}

#[test]
fn carve_bad_align_fails() {
    let img = common::temp_image(&common::fat12(), "carvealign");
    fail(run(&["carve", img.path().to_str().unwrap(), "--align", "zz"]));
}

#[test]
fn carve_offset_beyond_image_fails() {
    let img = common::temp_image(&common::fat12(), "carveoob");
    let err = fail(run(&[
        "carve",
        img.path().to_str().unwrap(),
        "--offset",
        "999999999",
    ]));
    assert!(err.contains("offset"), "stderr: {err}");
}

#[test]
fn carve_len_clamps_to_image_end() {
    // --len huge must not panic or fail; it clamps to the image end.
    let img = common::temp_image(&common::fat12(), "carveclamp");
    ok(run(&[
        "carve",
        img.path().to_str().unwrap(),
        "--offset",
        "512",
        "--len",
        "18446744073709551615",
    ]));
}

#[test]
fn carve_unallocated_flag() {
    let img = common::temp_image(&common::fat12(), "carveun");
    ok(run(&["carve", img.path().to_str().unwrap(), "--unallocated"]));
}

// ---- partition-scoped mount --------------------------------------------------

#[test]
fn partition_scoped_ls_and_detect() {
    let disk = common::mbr_disk(&common::fat12(), 1);
    let img = common::temp_image(&disk, "part");
    let s = ok(run(&["ls", img.path().to_str().unwrap(), "-p", "0"]));
    assert!(s.contains("HELLO.TXT"), "stdout: {s}");
    let d = ok(run(&["detect", img.path().to_str().unwrap(), "-p", "0"]));
    assert!(d.lines().nth(1).unwrap().starts_with("fat"), "detect: {d}");
}

#[test]
fn partition_scoped_info_and_cat() {
    let disk = common::mbr_disk(&common::fat12(), 1);
    let img = common::temp_image(&disk, "partinfo");
    let s = ok(run(&["info", img.path().to_str().unwrap(), "-p", "0"]));
    assert!(s.to_lowercase().contains("fat"), "stdout: {s}");
    let c = ok(run(&["cat", img.path().to_str().unwrap(), "/HELLO.TXT", "-p", "0"]));
    assert!(c.contains("hello world!"), "stdout: {c}");
}

// ---- android -----------------------------------------------------------------

#[test]
fn android_command_runs_on_bare_image() {
    let img = common::temp_image(&common::fat12(), "android");
    // analyze() may fail on a non-Android image — that's fine; assert the
    // command exits cleanly in either direction without a panic.
    let out = run(&["android", img.path().to_str().unwrap()]);
    assert!(out.status.code() == Some(0) || out.status.code() == Some(1));
}
