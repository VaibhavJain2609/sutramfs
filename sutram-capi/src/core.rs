//! Safe core logic shared by the C FFI and the Python bindings: parser
//! registry, image open/detect, entry enumeration and file reads. No
//! `unsafe`, no FFI types — everything here is ordinary Rust so it can be
//! unit-tested directly and so the unsafe surface stays confined to
//! `ffi.rs`.

use std::io::Read;
use std::sync::Arc;

use sutram_fs::{DetectConfidence, FileSystem, FsEntry, FsParser, MountOptions};
use sutram_io::{ByteSource, FileSource};

/// Every parser in the family, in the same order as `sutram-cli`.
pub fn parsers() -> Vec<Box<dyn FsParser>> {
    vec![
        Box::new(sutram_ntfs::NtfsParser),
        Box::new(sutram_exfat::ExFatParser),
        Box::new(sutram_fat::FatParser),
        Box::new(sutram_ext4::Ext4Parser),
        Box::new(sutram_btrfs::BtrfsParser),
        Box::new(sutram_f2fs::F2fsParser),
        Box::new(sutram_xfs::XfsParser),
        Box::new(sutram_hfs::HfsParser),
        Box::new(sutram_apfs::ApfsParser),
    ]
}

/// A mounted filesystem — the handle handed across the FFI boundary.
pub struct Mounted {
    pub fs: Box<dyn FileSystem>,
    /// Short parser name (`"fat"`, `"ntfs"`, …) that mounted the image.
    pub parser_name: &'static str,
}

/// `(name, confidence)` for every parser, strongest first.
pub fn detect_all(src: &dyn ByteSource) -> Vec<(&'static str, DetectConfidence)> {
    let mut v: Vec<(&'static str, DetectConfidence)> = parsers()
        .iter()
        .map(|p| (p.name(), p.detect(src)))
        .collect();
    v.sort_by_key(|&(_, c)| std::cmp::Reverse(c));
    v
}

/// Open an image file, optionally scope it to a partition, and mount it.
///
/// `fs_name: None` → best detect() at Medium or better; `Some(name)` →
/// force a parser by its short name. `partition: None` → whole image.
pub fn open(
    path: &str,
    fs_name: Option<&str>,
    partition: Option<usize>,
) -> Result<Mounted, String> {
    let file = FileSource::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut src: Arc<dyn ByteSource> = sutram_io::into_arc(file);
    if let Some(i) = partition {
        let parts =
            sutram_io::open_partitions(src).map_err(|e| format!("partition table: {e}"))?;
        let p = parts
            .into_iter()
            .nth(i)
            .ok_or_else(|| format!("no partition #{i}"))?;
        src = sutram_io::into_arc(p.source);
    }
    let parser = match fs_name {
        Some(name) => parsers()
            .into_iter()
            .find(|p| p.name() == name)
            .ok_or_else(|| format!("unknown fs type '{name}'"))?,
        None => {
            let mut best: Option<(Box<dyn FsParser>, DetectConfidence)> = None;
            for p in parsers() {
                let c = p.detect(src.as_ref());
                if c > best
                    .as_ref()
                    .map(|(_, bc)| *bc)
                    .unwrap_or(DetectConfidence::None)
                {
                    best = Some((p, c));
                }
            }
            match best {
                Some((p, c)) if c >= DetectConfidence::Medium => p,
                _ => return Err("no parser recognised the image".into()),
            }
        }
    };
    let name = parser.name();
    let fs = parser
        .mount_with(src, &MountOptions::default())
        .map_err(|e| format!("mount: {e}"))?;
    Ok(Mounted {
        fs,
        parser_name: name,
    })
}

/// Run `f` over every walked entry; lenient-mode walk errors are passed
/// to `f` as `Err(String)` so the caller can emit them inline. Returns
/// the number of `f` invocations.
pub fn for_each_entry(
    m: &Mounted,
    mut f: impl FnMut(std::result::Result<&FsEntry, String>),
) -> u64 {
    let mut n = 0u64;
    for item in m.fs.walk() {
        n += 1;
        match item {
            Ok(e) => f(Ok(&e)),
            Err(e) => f(Err(e.to_string())),
        }
    }
    n
}

/// Find an entry by path (leading `/` optional) and read up to
/// `max_bytes` of its content.
pub fn read_file_by_path(m: &Mounted, path: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
    let want = path.trim_start_matches('/');
    let mut found: Option<FsEntry> = None;
    for e in m.fs.walk().flatten() {
        if e.path.trim_start_matches('/') == want {
            found = Some(e);
            break;
        }
    }
    let entry = found.ok_or_else(|| format!("no such entry: {path}"))?;
    let mut rdr = m
        .fs
        .read_file(&entry)
        .map_err(|e| format!("read_file: {e}"))?;
    let mut out = Vec::new();
    rdr.by_ref()
        .take(max_bytes)
        .read_to_end(&mut out)
        .map_err(|e| format!("read: {e}"))?;
    Ok(out)
}
