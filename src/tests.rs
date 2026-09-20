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
