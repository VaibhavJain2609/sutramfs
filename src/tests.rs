//! Unit tests for the on-disk decoders: DOS datetime, CP437 names, octal
//! and base-256 fields, pax records/timestamps, cpio field decoders.

use super::*;

#[test]
fn dos_datetime_roundtrip() {
    // 2024-01-15 12:30:00 → date 0x582F, time 0x63C0.
    let ts = zip::dos_timestamp(0x582F, 0x63C0);
    assert_eq!(ts.value, Some(1_705_321_800_000_000_000));
    assert_eq!(ts.raw_encoding, "dos-datetime");
    assert_eq!(ts.granularity, std::time::Duration::from_secs(2));
    // date==0 → unset, not fabricated.
    assert_eq!(zip::dos_timestamp(0, 0).value, None);
    // Invalid month 13 → None.
    assert_eq!(zip::dos_timestamp(0x5820 | (13 << 5), 0).value, None);
}

#[test]
fn cp437_upper_maps() {
    assert_eq!(zip::decode_name(&[0x82], false), "é"); // 0x82 = é in CP437
    assert_eq!(zip::decode_name(b"plain.txt", false), "plain.txt");
}

#[test]
fn member_path_sanitises() {
    let (p, dir) = zip::member_path(b"a/b/c.txt", false);
    assert_eq!((p.as_str(), dir), ("a/b/c.txt", false));
    let (p, dir) = zip::member_path(b"d/", false);
    assert_eq!((p.as_str(), dir), ("d", true));
    let (p, _) = zip::member_path(b"../evil/../../x", false);
    assert_eq!(p, "__/evil/__/__/x");
    let (p, _) = zip::member_path(b"./a/./b", false);
    assert_eq!(p, "a/b");
}

#[test]
fn tar_octal_and_base256() {
    assert_eq!(tar::parse_octal(b"0000644\0"), Some(0o644));
    assert_eq!(tar::parse_octal(b"  644 \0"), Some(0o644));
    assert_eq!(tar::parse_octal(b"\0\0\0\0"), None);
    assert_eq!(tar::parse_octal(b"9999999\0"), None);
    // base-256: top bit set, big-endian mantissa.
    let mut f = [0u8; 12];
    f[0] = 0x80;
    f[11] = 0xFF;
    f[10] = 0x01;
    assert_eq!(tar::parse_size(&f), Some(0x1FF));
}

#[test]
fn tar_pax_records() {
    // Record length includes the decimal digits themselves:
    // "path=some/name.txt\n" (19) + "22 " (3) = 22; "mtime=1234.5\n" (13)
    // + "16 " (3) = 16.
    let data = b"22 path=some/name.txt\n16 mtime=1234.5\n";
    let recs = tar::parse_pax(data);
    assert_eq!(
        recs,
        vec![
            ("path".to_string(), "some/name.txt".to_string()),
            ("mtime".to_string(), "1234.5".to_string())
        ]
    );
    // Truncated record → parse stops, keeps what it had.
    let partial = b"22 path=some/name.txt\n99 mtime=...";
    let recs = tar::parse_pax(partial);
    assert_eq!(recs.len(), 1);
}

#[test]
fn tar_pax_timestamp_fraction() {
    let (_, ns, enc) = tar::pax_ts("1700000000.5").unwrap();
    assert_eq!(ns, 1_700_000_000_500_000_000);
    assert_eq!(enc, "pax-unix-sec");
    assert!(tar::pax_ts("notanumber").is_none());
    assert!(tar::pax_ts("").is_none());
}

#[test]
fn tar_checksum_verifies() {
    // Build a minimal valid header: name + zeroed octal fields + checksum.
    let mut h = [0u8; 512];
    h[0..5].copy_from_slice(b"f.txt");
    for f in [100usize, 108, 116, 124, 136] {
        let width = if f == 124 || f == 136 { 11 } else { 7 };
        let s = format!("{:0width$o}", 0u64, width = width);
        h[f..f + width].copy_from_slice(s.as_bytes());
    }
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u64 = h
        .iter()
        .enumerate()
        .map(|(i, &b)| if (148..156).contains(&i) { b' ' as u64 } else { b as u64 })
        .sum();
    let s = format!("{:06o}\0 ", sum);
    h[148..156].copy_from_slice(s.as_bytes());
    assert!(tar::checksum_ok(&h));
    h[300] = 0xFF;
    assert!(!tar::checksum_ok(&h));
}

#[test]
fn cpio_field_decoders() {
    assert_eq!(cpio::hex_field(b"00001000"), Some(0x1000));
    assert_eq!(cpio::hex_field(b"zzzzzzzz"), None);
    assert_eq!(cpio::oct_field(b"000644"), Some(0o644));
    // PDP-endian 32-bit: hi word first, each word in archive byte order.
    // 0x12345678 → bytes (LE archive): 78 56 34 12? No — per the NetBSD
    // man: 0x12345678 stored as 34 12 78 56 (hi word 0x1234 LE first).
    assert_eq!(cpio::r32bin(&[0x34, 0x12, 0x78, 0x56], true), 0x12345678);
    // BE archive: hi word BE first → 12 34 56 78.
    assert_eq!(cpio::r32bin(&[0x12, 0x34, 0x56, 0x78], false), 0x12345678);
}
