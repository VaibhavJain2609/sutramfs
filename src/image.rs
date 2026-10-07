//! Format-sniffing image open — the single entry point for disk images.
//!
//! [`open_image`] reads the first (and, for VHD, last) bytes of `path`
//! and returns the right [`ByteSource`] for the container found:
//!
//! * **EWF/E01** (`EVF` signature) — [`ewf::EwfSource`] over the `.E01`
//!   and every contiguous `.E02`, `.E03`, … sibling in the directory.
//!   EWF2 (`*.Ex01`) and logical `.L01` images surface as
//!   [`Error::Unsupported`].
//! * **VHDX** (`vhdxfile`) / **VHD** (`conectix` footer cookie) —
//!   [`vhd::VhdSource`]; differencing chains are [`Error::Unsupported`].
//! * **QCOW2** (`QFI\xFB` magic) — [`qcow2::Qcow2Source`]; backing-file
//!   and encrypted images are [`Error::Unsupported`].
//! * **Split raw** — `disk.001`/`disk.002`, `disk_aa`/`disk_ab` sibling
//!   sets are concatenated via [`ConcatSource::open_split`].
//! * Anything else is opened as **raw** (`dd`, `*.img`, `*.raw`, device
//!   files) — the historic [`FileSource`] behaviour.
//!
//! AFF4-L logical containers (`*.aff4`) are deliberately *not* routed
//! here: they hold evidence files, not a disk-image byte stream — see
//! the `sutram-aff4` crate.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::ewf::EwfSource;
use crate::qcow2::Qcow2Source;
use crate::vhd::VhdSource;
use crate::views::{detect_split, ConcatSource};
use crate::{into_arc, ByteSource, Error, FileSource, Result};

/// Open a disk image at `path` as a [`ByteSource`], sniffing the
/// container format from its signature bytes.
///
/// A `path` that is an `.E02`+ continuation segment is still accepted:
/// sibling discovery always starts the acquisition at the `.E01` found
/// in the same directory. A raw file with no recognised signature is
/// returned as a plain [`FileSource`], preserving historical `dd`/`img`
/// behaviour.
pub fn open_image(path: impl AsRef<Path>) -> Result<Arc<dyn ByteSource>> {
    let path = path.as_ref();
    let src = FileSource::open(path)?;

    if EwfSource::is_ewf(&src) {
        let segs = ewf_segment_paths(path)?;
        return Ok(into_arc(EwfSource::open_segments(&segs)?));
    }

    let arc: Arc<dyn ByteSource> = Arc::new(src);
    if VhdSource::is_vhdx(arc.as_ref()) || VhdSource::is_vhd(arc.as_ref()) {
        return Ok(Arc::new(VhdSource::open(arc)?));
    }
    if Qcow2Source::is_qcow2(arc.as_ref()) {
        return Ok(Arc::new(Qcow2Source::open(arc)?));
    }
    if detect_split(path) {
        return Ok(Arc::new(ConcatSource::open_split(path)?));
    }
    Ok(arc)
}

/// Segment number encoded by an EWF extension (`E01`–`E99`, then
/// `EAA`–`EZZ`); case-insensitive. `E00` and non-EWF extensions → `None`.
fn ewf_segment_number(ext: &str) -> Option<u64> {
    let b = ext.as_bytes();
    if b.len() != 3 || !b[0].eq_ignore_ascii_case(&b'E') {
        return None;
    }
    let c1 = b[1].to_ascii_uppercase();
    let c2 = b[2].to_ascii_uppercase();
    if c1.is_ascii_digit() && c2.is_ascii_digit() {
        return Some(((c1 - b'0') * 10 + (c2 - b'0')) as u64);
    }
    if c1.is_ascii_uppercase() && c2.is_ascii_uppercase() {
        return Some(100 + (c1 - b'A') as u64 * 26 + (c2 - b'A') as u64);
    }
    None
}

/// Every EWF segment sharing `path`'s stem (`*.E01`, `*.E02`, …), in
/// acquisition order. Scanning the directory — not only the given path —
/// means a caller can hand in any segment and still get the run from
/// `.E01`. The contiguous run starting at segment 1 is what we return:
/// a gap truncates the set and [`EwfSource::open`] then reports the
/// image's own `next`-section incompleteness with a clearer error.
fn ewf_segment_paths(path: &Path) -> Result<Vec<PathBuf>> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return Ok(vec![path.to_path_buf()]);
    };
    let mut found: Vec<(u64, PathBuf)> = Vec::new();
    for entry in fs::read_dir(dir).map_err(Error::Io)? {
        let entry = entry.map_err(Error::Io)?;
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let Some(stem2) = p.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if !stem2.eq_ignore_ascii_case(stem) {
            continue;
        }
        let Some(ext) = p.extension().and_then(|s| s.to_str()) else {
            continue;
        };
        if let Some(n) = ewf_segment_number(ext) {
            found.push((n, p));
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut segs = Vec::with_capacity(found.len());
    let mut expect = 1u64;
    for (n, p) in found {
        if n < expect {
            // Duplicate segment number (e.g. `img.E01` + `img.e01` on a
            // case-sensitive volume) — first in sorted order wins.
            continue;
        }
        if n != expect {
            break;
        }
        segs.push(p);
        expect += 1;
    }
    if segs.is_empty() {
        // Signature says EWF but the directory scan found no E01 — fall
        // back to the caller's path so EwfSource reports its own error.
        segs.push(path.to_path_buf());
    }
    Ok(segs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_number_decodes_encase_naming() {
        assert_eq!(ewf_segment_number("E01"), Some(1));
        assert_eq!(ewf_segment_number("e01"), Some(1));
        assert_eq!(ewf_segment_number("E99"), Some(99));
        assert_eq!(ewf_segment_number("EAA"), Some(100));
        assert_eq!(ewf_segment_number("EAZ"), Some(125));
        assert_eq!(ewf_segment_number("EBA"), Some(126));
        assert_eq!(ewf_segment_number("E00"), Some(0));
        assert_eq!(ewf_segment_number("E0A"), None);
        assert_eq!(ewf_segment_number("E1"), None);
        assert_eq!(ewf_segment_number("FOO"), None);
        assert_eq!(ewf_segment_number("001"), None);
    }

    #[test]
    fn segment_paths_follow_contiguous_run() {
        let dir = std::env::temp_dir().join(format!("sutram-ewf-{:x}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        for name in ["img.E01", "img.E02", "img.e03", "img.E05", "other.E01"] {
            fs::write(dir.join(name), b"x").unwrap();
        }
        let segs = ewf_segment_paths(&dir.join("img.E01")).unwrap();
        let names: Vec<_> = segs
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap().to_string())
            .collect();
        // .e03 is segment 3; the E05 stops at the missing 4. `other`
        // stem excluded.
        assert_eq!(names, ["img.E01", "img.E02", "img.e03"]);
        fs::remove_dir_all(&dir).unwrap();
    }
}
