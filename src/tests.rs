//! Unit tests for the exFAT decoders (checksums, timestamps, names).

use crate::boot::BootSector;
use crate::dirent;
use crate::ExFatParser;
use std::sync::Arc;
use std::time::Duration;
use sutram_fs::{DetectConfidence, FsParser};
use sutram_io::ByteSource;

/// Build a minimal in-memory 3-entry set (primary+stream+name) and return
/// the raw bytes, with the stored SetChecksum filled in.
fn build_set(name: &str, valid_len: u64, fc: u32, data_len: u64, no_fat: bool) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let nname = units.len().div_ceil(15).max(1);
    let mut set = vec![0u8; 32 * (1 + 1 + nname)];
    // primary
    set[0] = 0x85;
    set[1] = (1 + nname) as u8;
    set[4] = 0x20; // archive
    // stream ext
    let s = 32;
    set[s] = 0xC0;
    set[s + 1] = if no_fat { 0x02 } else { 0x00 };
    set[s + 3] = units.len() as u8;
    set[s + 4..s + 6].copy_from_slice(&0x1234u16.to_le_bytes());
    set[s + 8..s + 16].copy_from_slice(&valid_len.to_le_bytes());
    set[s + 20..s + 24].copy_from_slice(&fc.to_le_bytes());
    set[s + 24..s + 32].copy_from_slice(&data_len.to_le_bytes());
    // name entries
    for i in 0..nname {
        let o = 64 + i * 32;
        set[o] = 0xC1;
        for (j, u) in units[i * 15..units.len().min((i + 1) * 15)]
            .iter()
            .enumerate()
        {
            set[o + 2 + j * 2..o + 4 + j * 2].copy_from_slice(&u.to_le_bytes());
        }
    }
    let sum = dirent::set_checksum(&set, false);
    set[2..4].copy_from_slice(&sum.to_le_bytes());
    set
}

#[test]
fn set_checksum_roundtrip() {
    let set = build_set("HELLO.TXT", 12, 5, 12, false);
    let (fs, used) = dirent::parse_file_set(&set, 0).unwrap();
    assert_eq!(used, 3);
    assert_eq!(fs.name.as_deref(), Some("HELLO.TXT"));
    assert_eq!(fs.checksum_ok, Some(true));
    assert!(!fs.deleted);
    assert_eq!(fs.valid_len, 12);
    assert_eq!(fs.first_cluster, 5);
    assert!(!fs.no_fat_chain);
}

#[test]
fn deleted_set_checksums_with_restored_inuse() {
    let mut set = build_set("GONE.BIN", 300, 9, 300, true);
    // Deletion: clear the in-use bit of every entry-type byte.
    for e in set.chunks_exact_mut(32) {
        e[0] &= 0x7F;
    }
    let (fs, _) = dirent::parse_file_set(&set, 0).unwrap();
    assert!(fs.deleted);
    assert_eq!(fs.checksum_ok, Some(true)); // verifies with bits restored
    assert_eq!(fs.name.as_deref(), Some("GONE.BIN")); // name survives
    assert!(fs.no_fat_chain);
}

#[test]
fn truncated_set_reports_unverifiable() {
    let set = build_set("A Very Long File Name That Spans.TXT", 1, 5, 1, true);
    // Cut the last name entry off.
    let short = &set[..set.len() - 32];
    let (fs, _) = dirent::parse_file_set(short, 0).unwrap();
    assert_eq!(fs.checksum_ok, None);
    assert!(fs.secondaries_seen < fs.secondary_count as usize);
}

#[test]
fn long_name_assembles_across_entries() {
    let name = "A Very Long File Name.TXT"; // 25 chars → 2 name entries
    let set = build_set(name, 700, 8, 700, true);
    let (fs, used) = dirent::parse_file_set(&set, 0).unwrap();
    assert_eq!(used, 4);
    assert_eq!(fs.name.as_deref(), Some(name));
}

#[test]
fn name_bytes_sanitised() {
    // A hostile dirent: control char inside the UTF-16 name.
    let mut set = build_set("EVIL.TXT", 1, 5, 1, true);
    let noff = 64;
    // overwrite first name unit with U+0007 (control)
    set[noff + 2..noff + 4].copy_from_slice(&0x0007u16.to_le_bytes());
    // recompute checksum so the set stays valid
    set[2] = 0;
    set[3] = 0;
    let sum = dirent::set_checksum(&set, false);
    set[2..4].copy_from_slice(&sum.to_le_bytes());
    let (fs, _) = dirent::parse_file_set(&set, 0).unwrap();
    assert_eq!(fs.name.as_deref(), Some("_VIL.TXT"));
}

#[test]
fn exfat_timestamp_with_tz() {
    // 2024-01-15 10:30:20 local, +02:00 → 08:30:20Z; cs = 50 → +0.5 s.
    let date: u32 = (((2024 - 1980) << 9) | (1 << 5) | 15) as u32;
    let time: u32 = ((10 << 11) | (30 << 5) | 10) as u32;
    let raw = (date << 16) | time;
    let ts = dirent::exfat_ts(raw, 50, 0x88, true);
    assert_eq!(ts.granularity, Duration::from_millis(10));
    assert_eq!(ts.raw_encoding, "exfat-datetime");
    // 2024-01-15T10:30:20 = 1705314620 s; minus 2 h, plus 0.5 s.
    assert_eq!(ts.value, Some((1_705_314_620 - 7200) * 1_000_000_000 + 500_000_000));
}

#[test]
fn exfat_timestamp_no_tz_and_unset() {
    let date: u32 = (((2024 - 1980) << 9) | (1 << 5) | 15) as u32;
    let time: u32 = ((10 << 11) | (30 << 5) | 10) as u32;
    let raw = (date << 16) | time;
    // tz valid bit clear → naive decode, 2 s granularity for access ts.
    let ts = dirent::exfat_ts(raw, 0, 0x00, false);
    assert_eq!(ts.granularity, Duration::from_secs(2));
    assert_eq!(ts.value, Some(1_705_314_620_000_000_000));
    // zero timestamp → value None (never fabricated)
    let ts = dirent::exfat_ts(0, 0, 0x80, true);
    assert_eq!(ts.value, None);
}

#[test]
fn tz_offset_decode() {
    assert_eq!(dirent::tz_minutes(0x80), Some(0)); // UTC
    assert_eq!(dirent::tz_minutes(0x88), Some(120)); // UTC+2
    assert_eq!(dirent::tz_minutes(0xF4), Some(-180)); // UTC-3 (negative 7-bit)
    assert_eq!(dirent::tz_minutes(0x40), None); // valid bit clear
}

#[test]
fn detect_confidence() {
    let zeros: Arc<dyn ByteSource> = Arc::new(vec![0u8; 4096]);
    assert_eq!(ExFatParser.detect(zeros.as_ref()), DetectConfidence::None);
    // FAT signature must not be taken for exFAT.
    let mut fat = vec![0u8; 4096];
    fat[0] = 0xEB;
    fat[3..11].copy_from_slice(b"MSWIN4.1");
    fat[510] = 0x55;
    fat[511] = 0xAA;
    assert_eq!(
        ExFatParser.detect(&fat.as_slice()),
        DetectConfidence::None
    );
    // "EXFAT   " but MustBeZero violated → weak at best.
    let mut fake = vec![0u8; 4096];
    fake[3..11].copy_from_slice(b"EXFAT   ");
    fake[0x20] = 0xFF;
    assert!(ExFatParser.detect(&fake.as_slice()) <= DetectConfidence::Medium);
}

#[test]
fn boot_sector_rejects_garbage() {
    let src: Vec<u8> = vec![0u8; 512];
    assert!(BootSector::parse(&src.as_slice()).is_err());
}
