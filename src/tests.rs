use crate::boot::BootSector;
use crate::dirent::{self, DirEntry, LfnPart};
use crate::FatParser;
use sutram_fs::{DetectConfidence, FsParser};
use std::sync::Arc;
use std::time::Duration;
use sutram_io::ByteSource;

fn entry(name: &[u8; 11], deleted: bool) -> DirEntry {
    DirEntry {
        deleted,
        raw_name: *name,
        attr: 0x20,
        first_cluster: 3,
        size: 10,
        crt_tenth: 0,
        crt_time: 0,
        crt_date: 0,
        acc_date: 0,
        wrt_time: 0,
        wdate: 0,
    }
}

#[test]
fn name83_basics() {
    let e = entry(b"HELLO   TXT", false);
    assert_eq!(dirent::name83(&e), "HELLO.TXT");
    let e = entry(b"NOEXT      ", false);
    assert_eq!(dirent::name83(&e), "NOEXT");
    // deleted: 0xE5 lead byte shown as '_'
    let mut e = entry(b"DELETED TXT", true);
    e.raw_name[0] = 0xE5;
    assert_eq!(dirent::name83(&e), "_ELETED.TXT");
    // 0x05 escapes a literal 0xE5 lead byte (rendered lossily — never panic)
    let mut e = entry(b"\x05APAN   TXT", false);
    e.raw_name[0] = 0x05;
    assert!(dirent::name83(&e).ends_with("APAN.TXT"));
}

#[test]
fn name83_control_bytes_sanitised() {
    let e = entry(b"A\x01B     TXT", false);
    assert_eq!(dirent::name83(&e), "A_B.TXT");
}

#[test]
fn lfn_assembly() {
    let units: Vec<u16> = "Long File Name.txt".encode_utf16().collect();
    let mk = |seq: u8, us: &[u16]| {
        let mut u = [0xFFFFu16; 13];
        for (i, x) in us.iter().enumerate() {
            u[i] = *x;
        }
        if us.len() < 13 {
            u[us.len()] = 0;
        }
        LfnPart {
            seq,
            deleted: false,
            checksum: 0,
            units: u,
        }
    };
    // stored order: part 2 (0x42) physically first, then part 1
    let parts = vec![mk(2, &units[13..]), mk(1, &units[..13])];
    assert_eq!(
        dirent::assemble_lfn(&parts).as_deref(),
        Some("Long File Name.txt")
    );
    assert_eq!(dirent::assemble_lfn(&[]), None);
}

#[test]
fn dos_timestamps() {
    let mut e = entry(b"A       TXT", false);
    // 2024-01-15 10:30:20, create tenth=50 (0.5 s), access 2024-01-16
    e.wdate = ((2024 - 1980) << 9) | (1 << 5) | 15;
    e.wrt_time = (10 << 11) | (30 << 5) | 10;
    e.crt_date = e.wdate;
    e.crt_time = e.wrt_time;
    e.crt_tenth = 50;
    e.acc_date = ((2024 - 1980) << 9) | (1 << 5) | 16;
    let ts = dirent::timestamps(&e);
    let m = ts.modified.unwrap();
    assert_eq!(m.granularity, Duration::from_secs(2));
    // 2024-01-15T10:30:20Z == 1705314620 s
    assert_eq!(m.value, Some(1_705_314_620_000_000_000));
    let c = ts.created.unwrap();
    assert_eq!(c.granularity, Duration::from_millis(10));
    assert_eq!(c.value, Some(1_705_314_620_500_000_000));
    let a = ts.accessed.unwrap();
    assert_eq!(a.granularity, Duration::from_secs(86_400));
    // date-only → midnight 2024-01-16
    assert_eq!(a.value, Some(1_705_363_200_000_000_000));
}

#[test]
fn detect_confidence() {
    // Garbage → None
    let zeros: Arc<dyn ByteSource> = Arc::new(vec![0u8; 512]);
    assert_eq!(FatParser.detect(zeros.as_ref()), DetectConfidence::None);
    // NTFS signature → explicitly not FAT
    let mut ntfs = vec![0u8; 512];
    ntfs[3..11].copy_from_slice(b"NTFS    ");
    ntfs[510] = 0x55;
    ntfs[511] = 0xAA;
    assert_eq!(
        FatParser.detect(&ntfs.as_slice()),
        DetectConfidence::None
    );
}

#[test]
fn boot_sector_rejects_garbage() {
    let src: Vec<u8> = vec![0u8; 512];
    assert!(BootSector::parse(&src.as_slice()).is_err());
}

/// A minimally-valid FAT32-style boot sector; callers then break one field.
fn valid_boot() -> Vec<u8> {
    let mut b = vec![0u8; 512];
    b[0] = 0xEB;
    b[3..11].copy_from_slice(b"SUTRAM32");
    b[11..13].copy_from_slice(&512u16.to_le_bytes());
    b[13] = 1;
    b[14..16].copy_from_slice(&32u16.to_le_bytes());
    b[16] = 2;
    b[21] = 0xF8;
    b[32..36].copy_from_slice(&200_000u32.to_le_bytes());
    b[36..40].copy_from_slice(&512u32.to_le_bytes());
    b[44..48].copy_from_slice(&2u32.to_le_bytes());
    b[510] = 0x55;
    b[511] = 0xAA;
    b
}

#[test]
fn boot_sector_validation_errors() {
    // Each corrupt field must be a hard FsError, never a panic.
    let bad_sig = valid_boot();
    let mut bad_sig2 = bad_sig.clone();
    bad_sig2[511] = 0x00;
    assert!(BootSector::parse(&bad_sig2.as_slice()).is_err());

    let mut b = valid_boot();
    b[11..13].copy_from_slice(&100u16.to_le_bytes()); // bad bytes/sector
    assert!(BootSector::parse(&b.as_slice()).is_err());

    let mut b = valid_boot();
    b[13] = 0; // sectors/cluster = 0
    assert!(BootSector::parse(&b.as_slice()).is_err());
    let mut b = valid_boot();
    b[13] = 3; // not a power of two
    assert!(BootSector::parse(&b.as_slice()).is_err());

    let mut b = valid_boot();
    b[14..16].copy_from_slice(&0u16.to_le_bytes()); // reserved = 0
    assert!(BootSector::parse(&b.as_slice()).is_err());

    let mut b = valid_boot();
    b[16] = 0; // zero FATs
    assert!(BootSector::parse(&b.as_slice()).is_err());

    let mut b = valid_boot();
    b[32..36].copy_from_slice(&0u32.to_le_bytes()); // zero total sectors
    assert!(BootSector::parse(&b.as_slice()).is_err());

    let mut b = valid_boot();
    b[36..40].copy_from_slice(&0u32.to_le_bytes()); // zero FAT size
    assert!(BootSector::parse(&b.as_slice()).is_err());

    let mut b = valid_boot();
    b[32..36].copy_from_slice(&500u32.to_le_bytes()); // impossible geometry
    assert!(BootSector::parse(&b.as_slice()).is_err());

    let mut b = valid_boot();
    b[44..48].copy_from_slice(&0u32.to_le_bytes()); // FAT32 root cluster < 2
    assert!(BootSector::parse(&b.as_slice()).is_err());

    // Truncated source (< 512 B) is an error, not a panic.
    let short = vec![0u8; 100];
    assert!(BootSector::parse(&short.as_slice()).is_err());
}

#[test]
fn boot_sector_tot16_tot32_and_label_paths() {
    // tot16 nonzero wins over tot32.
    let mut b = valid_boot();
    b[19..21].copy_from_slice(&60_000u16.to_le_bytes());
    let bs = BootSector::parse(&b.as_slice()).unwrap();
    assert_eq!(bs.total_sectors, 60_000);
    // ext-BPB signature present → volume id + label decoded.
    let mut b = valid_boot();
    b[66] = 0x29;
    b[67..71].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    b[71..82].copy_from_slice(b"MYVOL      ");
    let bs = BootSector::parse(&b.as_slice()).unwrap();
    assert_eq!(bs.volume_id, Some(0xDEAD_BEEF));
    assert_eq!(bs.volume_label.as_deref(), Some("MYVOL"));
    // absent signature → None fields
    let bs = BootSector::parse(&valid_boot().as_slice()).unwrap();
    assert!(bs.volume_id.is_none());
}
