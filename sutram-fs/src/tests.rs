use crate::*;
use std::sync::Arc;

#[test]
fn confidence_ordering() {
    assert!(DetectConfidence::Certain > DetectConfidence::High);
    assert!(DetectConfidence::Medium > DetectConfidence::Low);
    assert!(DetectConfidence::Low > DetectConfidence::None);
}

#[test]
fn error_display_carries_offset() {
    let e = FsError::corrupt(0x200, "bad magic");
    assert!(e.to_string().contains("0x200"));
    let e = FsError::truncated(0x10, 512, 100);
    assert!(e.to_string().contains("0x10"));
}

#[test]
fn error_variants_display_and_convert() {
    assert!(FsError::unsupported("crypto").to_string().contains("crypto"));
    assert!(FsError::NotFound { path: "/x".into() }
        .to_string()
        .contains("/x"));
    assert!(FsError::InvalidInput { msg: "align".into() }
        .to_string()
        .contains("align"));
    let io = FsError::Io(std::io::Error::other("disk"));
    assert!(io.to_string().contains("i/o error"));
    assert!(std::error::Error::source(&io).is_some());
    assert!(std::error::Error::source(&FsError::NotFound { path: "x".into() }).is_none());
    // sutram_io::Error → FsError mappings
    let t: FsError = sutram_io::Error::Truncated {
        offset: 8,
        requested: 16,
        available: 4,
    }
    .into();
    assert!(matches!(
        t,
        FsError::Truncated {
            offset: 8,
            needed: 16,
            available: 4
        }
    ));
    let u: FsError = sutram_io::Error::unsupported("ewf").into();
    assert!(matches!(u, FsError::Unsupported { .. }));
    let i: FsError = sutram_io::Error::Io(std::io::Error::other("io")).into();
    assert!(matches!(i, FsError::Io(_)));
}

#[test]
fn io_error_conversion() {
    let io_err = std::io::Error::other("x");
    let e: FsError = io_err.into();
    assert!(matches!(e, FsError::Io(_)));
    let sutram_err = sutram_io::Error::corrupt(0x40, "boom");
    let e: FsError = sutram_err.into();
    assert!(matches!(e, FsError::Corrupt { offset: 0x40, .. }));
}

#[test]
fn unix_nanos_known_dates() {
    // 1970-01-01T00:00:00Z == 0
    assert_eq!(util::unix_nanos(1970, 1, 1, 0, 0, 0, 0), Some(0));
    // 2000-01-01 == 946684800 s
    assert_eq!(
        util::unix_nanos(2000, 1, 1, 0, 0, 0, 0),
        Some(946_684_800_000_000_000)
    );
    // invalid month → None, never panic
    assert_eq!(util::unix_nanos(2000, 13, 1, 0, 0, 0, 0), None);
    assert_eq!(util::unix_nanos(2000, 1, 1, 25, 0, 0, 0), None);
    // impossible calendar dates → None (not a silent roll into next month)
    assert_eq!(util::unix_nanos(2001, 2, 29, 0, 0, 0, 0), None); // common year
    assert!(util::unix_nanos(2000, 2, 29, 0, 0, 0, 0).is_some()); // leap year
    assert_eq!(util::unix_nanos(1900, 2, 29, 0, 0, 0, 0), None); // %100 non-leap
    assert!(util::unix_nanos(2000, 4, 30, 0, 0, 0, 0).is_some());
    assert_eq!(util::unix_nanos(2000, 4, 31, 0, 0, 0, 0), None);
    // pre-epoch times work (FAT can't store them, but NTFS-era reuse can)
    assert!(util::unix_nanos(1969, 12, 31, 23, 59, 59, 0) == Some(-1_000_000_000));
}

#[test]
fn recovery_state_display() {
    assert_eq!(RecoveryState::Intact.to_string(), "intact");
    assert_eq!(RecoveryState::Unrecoverable.to_string(), "unrecoverable");
    assert_eq!(RecoveryState::Unknown.to_string(), "unknown");
    let p = RecoveryState::PartiallyOverwritten {
        recovered_bytes: 10,
        total_bytes: 100,
    };
    assert!(p.to_string().contains("10/100"));
}

#[test]
fn mount_options_presets() {
    let d = MountOptions::default();
    assert!(!d.strict && d.check_magic && d.include_orphans);
    let s = MountOptions::strict();
    assert!(s.strict && s.check_magic && s.include_orphans);
}

#[test]
fn paths_and_sanitise() {
    assert_eq!(util::join_path("/", "a"), "/a");
    assert_eq!(util::join_path("/a/b", "c"), "/a/b/c");
    assert_eq!(util::sanitize_name("a/b\\c\0d"), "a_b_c_d");
    assert_eq!(util::orphan_path(0x2a), "/$ORPHANED/0x2a");
}

// A trivial in-memory filesystem proves the trait surface is object-safe
// and that default methods (deleted_entries, carve_region) work.
struct TinyFs {
    src: Arc<dyn ByteSource>,
}

struct TinyParser;
impl FsParser for TinyParser {
    fn name(&self) -> &'static str {
        "tiny"
    }
    fn detect(&self, src: &dyn ByteSource) -> DetectConfidence {
        if src.len() >= 4 && src.read_slice(0, 4).unwrap_or_default() == b"TINY" {
            DetectConfidence::Certain
        } else {
            DetectConfidence::None
        }
    }
    fn mount_with(
        &self,
        src: Arc<dyn ByteSource>,
        _o: &MountOptions,
    ) -> Result<Box<dyn FileSystem>> {
        Ok(Box::new(TinyFs { src }))
    }
}

impl FileSystem for TinyFs {
    fn info(&self) -> FsInfo {
        FsInfo {
            fs_type: "tiny".into(),
            ..Default::default()
        }
    }
    fn source(&self) -> Arc<dyn ByteSource> {
        self.src.clone()
    }
    fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
        let mut meta = std::collections::HashMap::new();
        meta.insert("k".into(), "v".into());
        let live = FsEntry {
            path: "/a.png".into(),
            name: "a.png".into(),
            entry_id: 1,
            kind: EntryKind::File,
            size: 4,
            disk_offset: 0,
            allocated_ranges: vec![(0, 4)],
            timestamps: Timestamps::default(),
            status: FsEntryStatus::Live,
            meta,
            magic: None,
        };
        let mut gone = live.clone();
        gone.path = "/gone".into();
        gone.name = "gone".into();
        gone.status = FsEntryStatus::Deleted {
            recovery: RecoveryState::PartiallyOverwritten {
                recovered_bytes: 2,
                total_bytes: 4,
            },
        };
        Box::new(vec![Ok(live), Ok(gone)].into_iter())
    }
    fn read_file(&self, entry: &FsEntry) -> Result<Box<dyn std::io::Read + Send>> {
        let data = self
            .src
            .read_slice(entry.allocated_ranges[0].0, entry.size as usize)
            .map_err(FsError::Io)?;
        Ok(Box::new(std::io::Cursor::new(data)))
    }
}

#[test]
fn trait_surface_object_safe_and_works() {
    let mut img = vec![0u8; 64];
    img[..4].copy_from_slice(b"TINY");
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let parser = TinyParser;
    assert_eq!(parser.detect(src.as_ref()), DetectConfidence::Certain);
    let fs = parser.mount(src).unwrap();
    let entries: Vec<_> = fs.walk().collect::<Result<Vec<_>>>().unwrap();
    assert_eq!(entries.len(), 2);
    let deleted: Vec<_> = fs.deleted_entries().collect::<Result<Vec<_>>>().unwrap();
    assert_eq!(deleted.len(), 1);
    assert!(deleted[0].is_deleted());
    // default carve_region: a PNG header at offset 8 is found
    let img2 = {
        let mut v = vec![0u8; 8192];
        v[..4].copy_from_slice(b"TINY");
        v[8..16].copy_from_slice(b"\x89PNG\x0D\x0A\x1A\x0A");
        v
    };
    let fs2 = TinyParser
        .mount(Arc::new(img2) as Arc<dyn ByteSource>)
        .unwrap();
    let hits: Vec<_> = fs2
        .carve_region(0, 8192, 8)
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert!(hits.iter().any(|h| h.kind == MagicType::Png && h.offset == 8));
    // align == 0 is a caller error, not a panic
    assert!(matches!(
        fs2.carve_region(0, 64, 0),
        Err(FsError::InvalidInput { .. })
    ));
    // region outside the source yields no hits, no panic
    assert_eq!(fs2.carve_region(9000, 4096, 8).unwrap().count(), 0);
    let fs3 = &fs2;
    // read_file_at skips into the file's data
    let live = entries[0].clone();
    let mut buf = [0u8; 2];
    let n = fs3.read_file_at(&live, 2, &mut buf).unwrap();
    assert_eq!(n, 2);
    assert_eq!(&buf, b"NY");
    // past EOF → 0 bytes
    let n = fs3.read_file_at(&live, 4096, &mut buf).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn default_trait_methods_are_empty() {
    // journal_entries / unallocated_ranges default to "nothing to report".
    let src: Arc<dyn ByteSource> = Arc::new(vec![0u8; 16]);
    let fs = TinyParser.mount(src).unwrap();
    assert_eq!(fs.journal_entries().count(), 0);
    assert!(fs.unallocated_ranges().is_empty());
}

// A filesystem whose walk is one corruption record: `deleted_entries` must
// surface walk errors, not swallow them.
struct FailFs;

impl FileSystem for FailFs {
    fn info(&self) -> FsInfo {
        FsInfo::default()
    }
    fn source(&self) -> Arc<dyn ByteSource> {
        Arc::new(Vec::new())
    }
    fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
        Box::new(vec![Err(FsError::corrupt(0x40, "bad dirent"))].into_iter())
    }
    fn read_file(&self, _e: &FsEntry) -> Result<Box<dyn std::io::Read + Send>> {
        Err(FsError::NotFound { path: "n/a".into() })
    }
}

#[test]
fn deleted_entries_passes_error_items_through() {
    let items: Vec<_> = FailFs.deleted_entries().collect();
    assert_eq!(items.len(), 1);
    assert!(matches!(
        &items[0],
        Err(FsError::Corrupt { offset: 0x40, .. })
    ));
}

// A source that fails every read exercises CarveIter's `Err` item path.
struct BadSrc;

impl ByteSource for BadSrc {
    fn len(&self) -> u64 {
        8192
    }
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("device gone"))
    }
}

#[test]
fn carve_region_yields_io_error_items() {
    let fs = TinyFs {
        src: Arc::new(BadSrc) as Arc<dyn ByteSource>,
    };
    let items: Vec<_> = fs.carve_region(0, 64, 8).unwrap().collect();
    assert_eq!(items.len(), 8); // one Err per probe offset, no panic
    assert!(items.iter().all(|i| matches!(i, Err(FsError::Io(_)))));
}

// ---------------------------------------------------------------------------
// bounded carving
// ---------------------------------------------------------------------------

/// Assemble a real 45-byte PNG: signature + IHDR + IEND.
fn test_png() -> Vec<u8> {
    let mut p = b"\x89PNG\x0D\x0A\x1A\x0A".to_vec();
    // IHDR: len 13, type, 13 data bytes, crc
    p.extend_from_slice(&13u32.to_be_bytes());
    p.extend_from_slice(b"IHDR");
    p.extend_from_slice(&[0u8; 13]);
    p.extend_from_slice(&[0u8; 4]);
    // IEND: len 0, type, crc
    p.extend_from_slice(&0u32.to_be_bytes());
    p.extend_from_slice(b"IEND");
    p.extend_from_slice(&[0u8; 4]);
    p
}

#[test]
fn carve_bounds_png_extent_exactly() {
    let png = test_png();
    let mut img = vec![0u8; 8192];
    img[512..512 + png.len()].copy_from_slice(&png);
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = TinyFs { src };
    let hits: Vec<_> = fs
        .carve_region(0, 8192, 512)
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(hits.len(), 1);
    let h = &hits[0];
    assert_eq!(h.kind, MagicType::Png);
    assert_eq!(h.offset, 512);
    assert!(h.exact);
    // signature + IHDR(25) + IEND(12)
    assert_eq!(h.len as usize, png.len());
}

#[test]
fn carve_bounds_jpeg_by_footer() {
    let mut img = vec![0u8; 8192];
    // JPEG: SOI + APP0-ish data + EOI at 1024..1026
    img[1024] = 0xFF;
    img[1025] = 0xD8;
    img[1026] = 0xFF;
    img[1027] = 0xE0;
    img[2000] = 0xAA;
    img[3000] = 0xFF;
    img[3001] = 0xD9;
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = TinyFs { src };
    let hits: Vec<_> = fs
        .carve_region(0, 8192, 512)
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    let jpg = hits.iter().find(|h| h.kind == MagicType::Jpeg).unwrap();
    assert_eq!(jpg.offset, 1024);
    assert_eq!(jpg.len, 3002 - 1024);
    assert!(jpg.exact);
}

#[test]
fn carve_to_next_signature_when_unbounded() {
    // Two objects with ToNextHit bounds (e.g. zlib streams) carved
    // back-to-back: the second's header ends the first's extent.
    let mut img = vec![0u8; 8192];
    img[512..514].copy_from_slice(b"\x78\x9C");
    img[1024..1026].copy_from_slice(b"\x78\x01");
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = TinyFs { src };
    let hits: Vec<_> = fs
        .carve_region(0, 8192, 512)
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].kind, MagicType::Zlib);
    assert_eq!(hits[0].offset, 512);
    assert_eq!(hits[0].len, 512); // next hit at 1024 bounds it
    assert!(!hits[0].exact);
    assert_eq!(hits[1].offset, 1024);
}

#[test]
fn carve_zip_eocd_extents() {
    let mut img = vec![0u8; 8192];
    // fake zip: LFH + data + EOCD record (22 bytes, comment_len 0)
    img[512..516].copy_from_slice(b"PK\x03\x04");
    let eocd = 1024usize;
    img[eocd..eocd + 4].copy_from_slice(b"PK\x05\x06");
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = TinyFs { src };
    let hits: Vec<_> = fs
        .carve_region(0, 8192, 512)
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    // one Zip hit at 512, extent through EOCD end; the EOCD record's own
    // signature is inside the carved span and must not double-report.
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].kind, MagicType::Zip);
    assert_eq!(hits[0].offset, 512);
    assert_eq!(hits[0].len as usize, eocd + 22 - 512);
    assert!(hits[0].exact);
}

#[test]
fn carve_exact_flag_distinguishes_capped() {
    // A PDF header with no %%EOF inside the region → capped, not exact.
    let mut img = vec![0u8; 4096];
    img[512..517].copy_from_slice(b"%PDF-");
    let src: Arc<dyn ByteSource> = Arc::new(img);
    let fs = TinyFs { src };
    let hits: Vec<_> = fs
        .carve_region(0, 4096, 512)
        .unwrap()
        .collect::<Result<Vec<_>>>()
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].kind, MagicType::Pdf);
    assert!(!hits[0].exact);
}

#[test]
fn unix_nanos_rejects_invalid_and_absurd_fields() {
    assert_eq!(util::unix_nanos(2000, 0, 1, 0, 0, 0, 0), None); // month 0
    assert_eq!(util::unix_nanos(2000, -3, 1, 0, 0, 0, 0), None); // month < 0
    assert_eq!(util::unix_nanos(2000, 1, 0, 0, 0, 0, 0), None); // day 0
    assert_eq!(util::unix_nanos(2000, 1, 32, 0, 0, 0, 0), None); // day 32
    assert_eq!(util::unix_nanos(2000, 1, 1, 0, -1, 0, 0), None); // min < 0
    assert_eq!(util::unix_nanos(2000, 1, 1, 0, 60, 0, 0), None); // min 60
    assert_eq!(util::unix_nanos(2000, 1, 1, 0, 0, -1, 0), None); // sec < 0
    assert_eq!(util::unix_nanos(2000, 1, 1, 0, 0, 60, 0), None); // sec 60
    assert_eq!(util::unix_nanos(2000, 1, 1, 0, 0, 0, -1), None); // nanos < 0
    assert_eq!(util::unix_nanos(2000, 1, 1, 0, 0, 0, 1_000_000_000), None);
    // Absurd years return None instead of overflowing (hostile fields).
    assert_eq!(util::unix_nanos(i64::MAX / 2, 1, 1, 0, 0, 0, 0), None);
    assert_eq!(util::unix_nanos(i64::MIN / 2, 1, 1, 0, 0, 0, 0), None);
    assert_eq!(util::unix_nanos(i64::MIN, 1, 1, 0, 0, 0, 0), None);
    // End-of-day stays in the same day; century leap-year rules.
    assert_eq!(
        util::unix_nanos(1970, 1, 1, 23, 59, 59, 999_999_999),
        Some(86_399_999_999_999)
    );
    assert_eq!(util::unix_nanos(2100, 2, 29, 0, 0, 0, 0), None); // %100 non-leap
    // (the %400 leap rule is exercised by year 2000 in unix_nanos_known_dates)
    // Dates outside ~1678..2262 overflow i64 nanoseconds → None, not a panic.
    assert_eq!(util::unix_nanos(2400, 1, 1, 0, 0, 0, 0), None);
    assert_eq!(util::unix_nanos(1600, 1, 1, 0, 0, 0, 0), None);
}

#[test]
fn util_edge_cases() {
    assert_eq!(util::join_path("", "x"), "/x");
    assert_eq!(util::sanitize_name(""), "");
    assert_eq!(util::sanitize_name("a\nb\tc\u{7f}"), "a_b_c_");
    assert_eq!(util::sanitize_name("plain"), "plain");
    assert_eq!(util::orphan_path(0), "/$ORPHANED/0x0");
    assert_eq!(util::orphan_path(u64::MAX), "/$ORPHANED/0xffffffffffffffff");
}

#[test]
fn fstimestamp_value_is_optional_never_fabricated() {
    use std::time::Duration;
    let unset = FsTimestamp {
        value: None,
        raw_value: 0,
        raw_encoding: "fat-dos-datetime",
        granularity: Duration::from_secs(2),
    };
    assert!(unset.value.is_none());
    assert_eq!(unset.granularity, Duration::from_secs(2));
    let set = FsTimestamp {
        value: util::unix_nanos(2020, 1, 1, 0, 0, 0, 0),
        raw_value: 0x9C21,
        raw_encoding: "fat-dos-datetime",
        granularity: Duration::from_secs(2),
    };
    assert_eq!(set.value, Some(1_577_836_800_000_000_000)); // 2020-01-01 UTC
}
