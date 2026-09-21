//! The parser registry — all nine SUTRAM-FS parsers behind `dyn FsParser`.

use sutram_fs::{DetectConfidence, FsParser};

/// Every parser this daemon can serve, in no meaningful order.
///
/// `Detect` iterates the whole registry; `Mount` looks names up here or
/// picks the highest-confidence parser for the image.
pub fn registry() -> Vec<Box<dyn FsParser>> {
    vec![
        Box::new(sutram_fat::FatParser),
        Box::new(sutram_exfat::ExFatParser),
        Box::new(sutram_ntfs::NtfsParser),
        Box::new(sutram_ext4::Ext4Parser),
        Box::new(sutram_xfs::XfsParser),
        Box::new(sutram_btrfs::BtrfsParser),
        Box::new(sutram_apfs::ApfsParser),
        Box::new(sutram_hfs::HfsParser),
        Box::new(sutram_f2fs::F2fsParser),
    ]
}

/// Run `detect` on every registered parser, strongest confidence first.
pub fn detect_all(
    parsers: &[Box<dyn FsParser>],
    src: &dyn sutram_io::ByteSource,
) -> Vec<(&'static str, DetectConfidence)> {
    let mut v: Vec<_> = parsers
        .iter()
        .map(|p| (p.name(), p.detect(src)))
        .collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    v
}

/// Highest-confidence parser for `src`, if any returned above `None`.
pub fn best_parser<'a>(
    parsers: &'a [Box<dyn FsParser>],
    src: &dyn sutram_io::ByteSource,
) -> Option<(&'a dyn FsParser, DetectConfidence)> {
    parsers
        .iter()
        .map(|p| (p.as_ref(), p.detect(src)))
        .filter(|(_, c)| *c > DetectConfidence::None)
        .max_by_key(|(_, c)| *c)
}

/// Look a parser up by its short name (`"fat"`, `"ntfs"`, …).
pub fn by_name<'a>(
    parsers: &'a [Box<dyn FsParser>],
    name: &str,
) -> Option<&'a dyn FsParser> {
    parsers
        .iter()
        .find(|p| p.name() == name)
        .map(|p| p.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_nine_unique_parsers() {
        let r = registry();
        assert_eq!(r.len(), 9);
        let mut names: Vec<_> = r.iter().map(|p| p.name()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 9, "duplicate parser names");
        assert!(names.contains(&"fat"));
    }

    #[test]
    fn by_name_lookup() {
        let r = registry();
        assert_eq!(by_name(&r, "fat").unwrap().name(), "fat");
        assert!(by_name(&r, "zfs").is_none());
    }

    #[test]
    fn detect_garbage_yields_no_mountable() {
        let r = registry();
        let img: Vec<u8> = vec![0xAB; 8192];
        let dets = detect_all(&r, &img);
        assert!(dets.iter().all(|(_, c)| *c < DetectConfidence::Certain));
        assert!(best_parser(&r, &img).is_none());
    }
}
