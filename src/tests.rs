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
