//! Integration tests for the `sutramfs` binary: builds a synthetic FAT12
//! image and exercises every subcommand end-to-end.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sutramfs"))
}

fn dent(img: &mut [u8], off: usize, name: &[u8], ext: &[u8], attr: u8, clus: u16, size: u32) {
    let mut n = [b' '; 8];
    n[..name.len().min(8)].copy_from_slice(&name[..name.len().min(8)]);
    img[off..off + 8].copy_from_slice(&n);
    let mut e = [b' '; 3];
    e[..ext.len().min(3)].copy_from_slice(&ext[..ext.len().min(3)]);
    img[off + 8..off + 11].copy_from_slice(&e);
    img[off + 11] = attr;
    img[off + 26..off + 28].copy_from_slice(&clus.to_le_bytes());
    img[off + 28..off + 32].copy_from_slice(&size.to_le_bytes());
}

/// Minimal FAT12 image: 1 reserved + 2 FATs + root dir + data area.
/// Contains: live HELLO.TXT (cluster 2), deleted _ELETED.TXT (cluster 3),
/// TESTDIR (cluster 4) containing FAKE.TXT (cluster 5, MZ content).
fn fat12_image() -> Vec<u8> {
    let mut img = vec![0u8; 1 << 20]; // 1 MiB
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[3..11].copy_from_slice(b"SUTRAMFS");
    img[11..13].copy_from_slice(&512u16.to_le_bytes()); // bps
    img[13] = 1; // spc
    img[14..16].copy_from_slice(&1u16.to_le_bytes()); // reserved
    img[16] = 2; // nfats
    img[17..19].copy_from_slice(&224u16.to_le_bytes()); // root ents
    img[19..21].copy_from_slice(&2048u16.to_le_bytes()); // total sectors
    img[21] = 0xF8;
    img[22..24].copy_from_slice(&8u16.to_le_bytes()); // fat sz
    img[24..26].copy_from_slice(&32u16.to_le_bytes());
    img[26..28].copy_from_slice(&64u16.to_le_bytes());
    img[510] = 0x55;
    img[511] = 0xAA;
    for base in [512usize, 512 + 8 * 512] {
        img[base] = 0xF8;
        img[base + 1] = 0xFF;
        img[base + 2] = 0xFF;
    }
    let rd = 0x2200usize;
    dent(&mut img, rd, b"HELLO", b"TXT", 0x20, 2, 20);
    dent(&mut img, rd + 32, &[0xE5, b'D', b'E', b'L', b'E', b'T', b'E', b'D'], b"TXT", 0x20, 3, 12);
    dent(&mut img, rd + 64, b"TESTDIR", b"", 0x10, 4, 0);
    // data area: cluster n -> rd + 224*32 + (n-2)*512
    let cdata = rd + 224 * 32;
    img[cdata..cdata + 20].copy_from_slice(b"hello forensic world");
    img[cdata + 512..cdata + 512 + 12].copy_from_slice(b"deleted data");
    let d = cdata + 2 * 512; // cluster 4
    dent(&mut img, d, b".", b"", 0x10, 4, 0);
    dent(&mut img, d + 32, b"..", b"", 0x10, 0, 0);
    dent(&mut img, d + 64, b"FAKE", b"TXT", 0x20, 5, 64);
    let f = cdata + 3 * 512; // cluster 5
    img[f] = b'M';
    img[f + 1] = b'Z';
    img[f + 0x3C..f + 0x40].copy_from_slice(&0x40u32.to_le_bytes()); // e_lfanew
    img[f + 0x40..f + 0x44].copy_from_slice(b"PE\0\0"); // PE sig -> real PE
    img
}

fn write_img() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "sutram-cli-test-{}-{}.img",
        std::process::id(),
        std::thread::current().name().unwrap_or("t")
    ));
    std::fs::File::create(&p)
        .unwrap()
        .write_all(&fat12_image())
        .unwrap();
    p
}

fn stdout(c: &mut Command) -> String {
    let out = c.output().unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn detect_reports_fat_certain() {
    let img = write_img();
    let s = stdout(bin().args(["detect", img.to_str().unwrap()]));
    assert!(s.contains("fat"), "detect output: {s}");
    let fat_line = s.lines().find(|l| l.starts_with("fat")).unwrap();
    assert!(fat_line.contains("Certain"), "{fat_line}");
}

#[test]
fn ls_lists_live_and_deleted() {
    let img = write_img();
    let s = stdout(bin().args(["ls", img.to_str().unwrap()]));
    assert!(s.contains("/HELLO.TXT"));
    assert!(s.contains("[DELETED]"));
    assert!(s.contains("/TESTDIR/FAKE.TXT"));
}

#[test]
fn ls_deleted_flag_and_json() {
    let img = write_img();
    let s = stdout(bin().args(["ls", img.to_str().unwrap(), "-d", "-o", "json"]));
    for line in s.lines().filter(|l| !l.trim().is_empty()) {
        assert!(line.starts_with('{'), "non-json line: {line}");
        assert!(line.contains("\"status\":\"deleted"), "expected deleted: {line}");
    }
}

#[test]
fn cat_recovers_file_content() {
    let img = write_img();
    let s = stdout(bin().args(["cat", img.to_str().unwrap(), "/HELLO.TXT"]));
    assert!(s.contains("hello forensic world"));
}

#[test]
fn parts_handles_bare_fs() {
    let img = write_img();
    let s = stdout(bin().args(["parts", img.to_str().unwrap()]));
    assert!(s.contains("no partition table") || s.contains('#'));
}

#[test]
fn info_shows_volume() {
    let img = write_img();
    let s = stdout(bin().args(["info", img.to_str().unwrap()]));
    assert!(s.contains("FAT"), "info output: {s}");
    assert!(s.contains("block_size:"));
}

#[test]
fn unknown_command_errors() {
    let out = bin().arg("bogus").output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn missing_image_errors() {
    let out = bin().args(["ls", "/nonexistent/dd.img"]).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn carve_runs() {
    let img = write_img();
    // whole-image carve; exits cleanly regardless of hits
    let _ = stdout(bin().args(["carve", img.to_str().unwrap(), "--len", "65536"]));
}
