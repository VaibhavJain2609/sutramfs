//! Per-format end-to-end smoke tests for the `sutramfs` binary.
//!
//! Every parser's own synthetic test corpus — the `tests/common` builders
//! mandated by CONVENTIONS §6 — is reused here verbatim via `#[path]` (the
//! builders are pure byte assembly; no crate-private APIs). This exercises
//! the real CLI binary (`detect`, `info`, `ls`, `cat`, `carve`, `parts`,
//! `android`) against one realistic image per supported filesystem.

mod common;

#[allow(dead_code)]
#[path = "../../sutram-fat/tests/common/mod.rs"]
mod fat_img;
#[allow(dead_code)]
#[path = "../../sutram-exfat/tests/common/mod.rs"]
mod exfat_img;
#[allow(dead_code)]
#[path = "../../sutram-ext4/tests/common/mod.rs"]
mod ext4_img;
#[allow(dead_code)]
#[path = "../../sutram-btrfs/tests/common/mod.rs"]
mod btrfs_img;
#[allow(dead_code)]
#[path = "../../sutram-f2fs/tests/common/mod.rs"]
mod f2fs_img;
#[allow(dead_code)]
#[path = "../../sutram-xfs/tests/common/mod.rs"]
mod xfs_img;
#[allow(dead_code)]
#[path = "../../sutram-hfs/tests/common/mod.rs"]
mod hfs_img;
#[allow(dead_code)]
#[path = "../../sutram-ntfs/tests/common/mod.rs"]
mod ntfs_img;
#[allow(dead_code)]
#[path = "../../sutram-apfs/tests/common/mod.rs"]
mod apfs_img;
#[allow(dead_code)]
#[path = "../../sutram-part/tests/common/mod.rs"]
mod part_img;

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

/// Minimal XFS v5 volume: root dir (shortform) with one file `hello.txt`
/// whose single extent lives at fsblock 24.
fn xfs_image() -> Vec<u8> {
    use xfs_img::*;
    let mut i = Img::new();
    let root_sf = sf_dir(ROOTINO, &[("hello.txt", 65, 1)]);
    i.write_inode(
        ROOTINO,
        &InodeSpec {
            mode: 0o40755,
            format: 1, // local/inline
            size: root_sf.len() as u64,
            nlink: 2,
            inline_data: root_sf,
            ..Default::default()
        },
    );
    let data = b"hello xfs world\n";
    i.write_data(24, data);
    i.write_inode(
        65,
        &InodeSpec {
            format: 2, // extents
            size: data.len() as u64,
            nblocks: 1,
            extents: vec![ExtentSpec {
                fileoff: 0,
                fsb: 24,
                len: 1,
                unwritten: false,
            }],
            ..Default::default()
        },
    );
    // inobt chunk for inos 64..=127: 64 (root) and 65 allocated.
    let mut free = u64::MAX;
    free &= !0b11;
    i.inobt.push(ChunkRec {
        startino: 64,
        freecount: free.count_ones(),
        free,
    });
    // Blocks in use: 0-3 AG metadata, 4-7 inode chunk, 16-23 log, 24 data.
    i.free = vec![(8, 8), (25, AGBLOCKS - 25)];
    i.icount = 64;
    i.ifree = free.count_ones() as u64;
    i.finish()
}

/// Full pipeline for one image: detect finds `parser`, `info` reports
/// `fs_marker` (uppercase substring match on the `type:` line), `ls` lists
/// `file`, `cat` returns `content`, `carve` exits cleanly.
fn smoke(tag: &str, img: &[u8], parser: &str, fs_marker: &str, file: &str, content: &str) {
    let img = common::temp_image(img, tag);
    let p = img.path().to_str().unwrap().to_string();

    // detect — the right parser must surface at Medium or better.
    let d = ok(run(&["detect", &p]));
    let row = d
        .lines()
        .find(|l| l.starts_with(parser))
        .unwrap_or_else(|| panic!("no '{parser}' row in detect output:\n{d}"));
    assert!(
        row.contains("Certain") || row.contains("High") || row.contains("Medium"),
        "{tag}: weak detect row: {row}"
    );

    // info — auto-detected mount must report the right family.
    let i = ok(run(&["info", &p]));
    let ty = i
        .lines()
        .find(|l| l.starts_with("type:"))
        .unwrap_or_else(|| panic!("{tag}: no type line:\n{i}"));
    assert!(
        ty.to_uppercase().contains(&fs_marker.to_uppercase()),
        "{tag}: fs_type mismatch: {ty}"
    );

    // ls — the known live file must appear.
    let l = ok(run(&["ls", &p]));
    assert!(l.contains(file), "{tag}: '{file}' not in ls:\n{l}");

    // ls -o json — every line a JSON object with the core keys.
    let j = ok(run(&["ls", &p, "-o", "json"]));
    assert!(
        j.lines()
            .filter(|l| !l.trim().is_empty())
            .all(|l| l.starts_with('{') && l.ends_with('}') && l.contains("\"path\"")),
        "{tag}: non-JSONL line in:\n{j}"
    );

    // cat — recover the known file's content (raw bytes: payloads may be
    // binary, e.g. the APFS PNG).
    let c = run(&["cat", &p, file]);
    assert!(
        c.status.success(),
        "{tag}: cat failed: {}",
        String::from_utf8_lossy(&c.stderr)
    );
    assert!(
        c.stdout
            .windows(content.len())
            .any(|w| w == content.as_bytes()),
        "{tag}: cat {file} did not contain expected content"
    );

    // carve — bounded scan, exits cleanly.
    let cv = run(&["carve", &p, "--len", "8192"]);
    assert!(
        cv.status.success(),
        "{tag}: carve failed: {}",
        String::from_utf8_lossy(&cv.stderr)
    );

    // forced -t must reach the same parser.
    let f = ok(run(&["info", &p, "-t", parser]));
    assert!(f.contains("type:"), "{tag}: -t {parser} info:\n{f}");
}

// ---- per-format smoke ---------------------------------------------------

#[test]
fn smoke_fat32() {
    smoke(
        "fat32",
        &fat_img::build_fat32(),
        "fat",
        "FAT",
        "/HELLO.TXT",
        "hello world!",
    );
}

#[test]
fn smoke_exfat() {
    smoke(
        "exfat",
        &exfat_img::build_exfat(),
        "exfat",
        "EXFAT",
        "/HELLO.TXT",
        "hello, fragmented world",
    );
}

#[test]
fn smoke_ext4() {
    smoke(
        "ext4",
        &ext4_img::build_ext4(),
        "ext4",
        "EXT4",
        "/hello.txt",
        "hello ext4!",
    );
}

#[test]
fn smoke_btrfs() {
    smoke(
        "btrfs",
        &btrfs_img::build_image(),
        "btrfs",
        "BTRFS",
        "/hello.txt",
        "hello world!",
    );
}

#[test]
fn smoke_f2fs() {
    let img = f2fs_img::image();
    smoke(
        "f2fs",
        img.as_slice(),
        "f2fs",
        "F2FS",
        "/hello.txt",
        "Hello F2FS forensic world!",
    );
}

#[test]
fn smoke_xfs() {
    smoke(
        "xfs",
        &xfs_image(),
        "xfs",
        "XFS",
        "/hello.txt",
        "hello xfs world",
    );
}

#[test]
fn smoke_hfs() {
    smoke(
        "hfs",
        &hfs_img::build_hfsplus(),
        "hfs",
        "HFS",
        "/hello.txt",
        "hello world!",
    );
}

#[test]
fn smoke_ntfs() {
    smoke(
        "ntfs",
        &ntfs_img::build_ntfs(),
        "ntfs",
        "NTFS",
        "/HELLO.TXT",
        "hello ntfs world",
    );
}

#[test]
fn smoke_apfs() {
    let img = apfs_img::build_image(false);
    smoke("apfs", &img, "apfs", "APFS", "/photo.png", "IHDRtest");
}

// ---- partition tables -----------------------------------------------------

#[test]
fn parts_lists_gpt_entries() {
    let disk = part_img::gpt_img(&[
        part_img::GptPart {
            name: "boot_a",
            type_guid: part_img::test_guid(1),
            data: common::fat12(),
        },
        part_img::GptPart {
            name: "userdata",
            type_guid: part_img::test_guid(2),
            data: vec![0xAB; 4096],
        },
    ]);
    let img = common::temp_image(&disk, "gpt");
    let s = ok(run(&["parts", img.path().to_str().unwrap()]));
    assert!(s.contains("Gpt"), "parts: {s}");
    assert!(s.contains("boot_a"), "parts: {s}");
    assert!(s.contains("userdata"), "parts: {s}");

    // -p 0 must scope into the FAT12 volume.
    let l = ok(run(&["ls", img.path().to_str().unwrap(), "-p", "0"]));
    assert!(l.contains("HELLO.TXT"), "ls -p0: {l}");
    let d = ok(run(&["detect", img.path().to_str().unwrap(), "-p", "0"]));
    assert!(d.lines().nth(1).unwrap().starts_with("fat"), "detect: {d}");
}

// ---- android ----------------------------------------------------------------

#[test]
fn android_super_image_layout() {
    let disk = part_img::super_img(
        &[part_img::SuperPart {
            name: "system_a",
            group: "sutram_dynamic_a",
            attrs: 0,
            data: vec![0xEE; 4096],
        }],
        None,
    );
    let img = common::temp_image(&disk, "super");
    let out = run(&["android", img.path().to_str().unwrap()]);
    let s = String::from_utf8_lossy(&out.stdout).to_string();
    let e = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "android failed: {e}\nstdout: {s}"
    );
    assert!(s.contains("system_a"), "android output: {s}");
}
