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
fn io_error_conversion() {
    let io_err = std::io::Error::new(std::io::ErrorKind::Other, "x");
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
}
