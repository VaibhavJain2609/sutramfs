//! Windows recycle-bin `$I*` metadata file parser.
//!
//! Every file sent to the recycle bin on Vista+ leaves a `$Ixxxxxx.ext`
//! sidecar recording where it came from. Two on-disk layouts exist:
//!
//! - **Version 1** (Vista / 7 / 2008): fixed 544-byte record —
//!   `version:u64=1`, `file_size:u64`, `deletion FILETIME:u64`, then a
//!   520-byte fixed ANSI path buffer.
//! - **Version 2** (Windows 10+, Server 2016+): variable — `version:u64=2`,
//!   `file_size:u64`, `deletion FILETIME:u64`, `name_len:u32` (UTF-16
//!   chars *including* the terminating NUL), then the UTF-16LE path.
//!
//! The matching `$Rxxxxxx.ext` holds the file content itself.

use crate::common::{
    ansi_str, filetime, read_to_end_bounded, utf16_str, ArtifactTimestamp, Cursor, Error, Result,
    DEFAULT_MAX_INPUT,
};
use std::io::Read;

/// Fixed length of the version-1 record.
pub const V1_RECORD_LEN: usize = 544;
/// Fixed size of the version-1 path field.
pub const V1_PATH_LEN: usize = 520;
/// Minimum size of a version-2 record (header through `name_len`).
pub const V2_HEADER_LEN: usize = 28;

/// A parsed `$I*` recycle-bin metadata record.
#[derive(Debug, Clone)]
pub struct RecycledItem {
    /// On-disk header version: 1 (Vista/7) or 2 (Win10+).
    pub version: u64,
    /// Original absolute path of the deleted file (ANSI for v1,
    /// UTF-16 for v2). May be empty if the field was wiped.
    pub original_path: String,
    /// Size in bytes of the file when it was deleted.
    pub size: u64,
    /// Deletion timestamp (FILETIME).
    pub deleted_at: ArtifactTimestamp,
    /// Absolute offset of the path field within the input.
    pub path_offset: usize,
    /// Non-fatal problems (e.g. trailing garbage, length mismatch).
    pub warnings: Vec<String>,
}

impl RecycledItem {
    /// Parse a `$I*` file from a byte slice.
    ///
    /// Strict about the version dword (unknown versions are
    /// [`Error::Unsupported`]); lenient about the path field.
    pub fn parse(data: &[u8]) -> Result<RecycledItem> {
        if data.len() < 24 {
            return Err(Error::Truncated {
                offset: 0,
                needed: 24,
                available: data.len() as u64,
            });
        }
        let mut c = Cursor::new(data);
        let version = c.u64()?;
        let size = c.u64()?;
        let deleted_at = filetime(c.u64()?);
        match version {
            1 => Self::parse_v1(data, size, deleted_at),
            2 => Self::parse_v2(data, size, deleted_at),
            v => Err(Error::Unsupported {
                msg: format!("$I version {v}"),
            }),
        }
    }

    /// Parse from any `Read`, bounded at `DEFAULT_MAX_INPUT` bytes.
    pub fn from_reader(r: impl Read) -> Result<RecycledItem> {
        Self::parse(&read_to_end_bounded(r, DEFAULT_MAX_INPUT)?)
    }

    fn parse_v1(
        data: &[u8],
        size: u64,
        deleted_at: ArtifactTimestamp,
    ) -> Result<RecycledItem> {
        let mut warnings = Vec::new();
        if data.len() < V1_RECORD_LEN {
            // Tolerate a short file: parse whatever path bytes exist.
            if data.len() <= 24 {
                return Err(Error::Truncated {
                    offset: 24,
                    needed: V1_PATH_LEN as u64,
                    available: 0,
                });
            }
            warnings.push(format!(
                "v1 record {} bytes < {V1_RECORD_LEN}",
                data.len()
            ));
        }
        let path_end = data.len().min(V1_RECORD_LEN);
        let original_path = ansi_str(&data[24..path_end]);
        if data.len() > V1_RECORD_LEN {
            warnings.push(format!(
                "{} trailing bytes after v1 record",
                data.len() - V1_RECORD_LEN
            ));
        }
        Ok(RecycledItem {
            version: 1,
            original_path,
            size,
            deleted_at,
            path_offset: 24,
            warnings,
        })
    }

    fn parse_v2(
        data: &[u8],
        size: u64,
        deleted_at: ArtifactTimestamp,
    ) -> Result<RecycledItem> {
        let mut warnings = Vec::new();
        if data.len() < V2_HEADER_LEN {
            return Err(Error::Truncated {
                offset: 24,
                needed: 4,
                available: data.len() as u64 - 24,
            });
        }
        let name_chars = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as usize;
        // name_len counts UTF-16 code units including the NUL.
        let want = name_chars.saturating_mul(2);
        let have = data.len() - V2_HEADER_LEN;
        let take = want.min(have) - (want.min(have) % 2);
        if want > have {
            warnings.push(format!(
                "name field {want} bytes truncated to {have}"
            ));
        }
        let original_path = utf16_str(&data[V2_HEADER_LEN..V2_HEADER_LEN + take]);
        if have > want {
            warnings.push(format!("{} trailing bytes after name", have - want));
        }
        Ok(RecycledItem {
            version: 2,
            original_path,
            size,
            deleted_at,
            path_offset: V2_HEADER_LEN,
            warnings,
        })
    }
}

/// Quick plausibility check: plausible version dword (1 or 2) and a
/// minimum length. Reads only the header — safe for triage.
pub fn detect(data: &[u8]) -> bool {
    if data.len() < 24 {
        return false;
    }
    let v = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0; 8]));
    match v {
        1 => true,
        2 => data.len() >= V2_HEADER_LEN,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w32(b: &mut Vec<u8>, v: u32) {
        b.extend_from_slice(&v.to_le_bytes());
    }
    fn w64(b: &mut Vec<u8>, v: u64) {
        b.extend_from_slice(&v.to_le_bytes());
    }

    const TS: u64 = 133_000_000_000_000_000; // some FILETIME

    fn v2() -> Vec<u8> {
        let mut b = Vec::new();
        w64(&mut b, 2);
        w64(&mut b, 0xBADC0DE);
        w64(&mut b, TS);
        let name = "C:\\Users\\bob\\secret.docx";
        w32(&mut b, (name.chars().count() + 1) as u32); // incl NUL
        for u in name.encode_utf16().chain(std::iter::once(0)) {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b
    }

    fn v1() -> Vec<u8> {
        let mut b = Vec::new();
        w64(&mut b, 1);
        w64(&mut b, 4096);
        w64(&mut b, TS);
        let mut p = b"C:\\tmp\\old.txt\0".to_vec();
        p.resize(V1_PATH_LEN, 0);
        b.extend_from_slice(&p);
        b
    }

    #[test]
    fn parses_v2() {
        let f = RecycledItem::parse(&v2()).expect("v2");
        assert_eq!(f.version, 2);
        assert_eq!(f.original_path, "C:\\Users\\bob\\secret.docx");
        assert_eq!(f.size, 0xBADC0DE);
        assert!(f.deleted_at.value.is_some());
        assert_eq!(f.path_offset, 28);
        assert!(f.warnings.is_empty());
        assert!(detect(&v2()));
    }

    #[test]
    fn parses_v1() {
        let f = RecycledItem::parse(&v1()).expect("v1");
        assert_eq!(f.version, 1);
        assert_eq!(f.original_path, "C:\\tmp\\old.txt");
        assert_eq!(f.size, 4096);
        assert!(detect(&v1()));
    }

    #[test]
    fn rejects_unknown_version() {
        let mut b = v2();
        b[0..8].copy_from_slice(&9u64.to_le_bytes());
        assert!(matches!(
            RecycledItem::parse(&b),
            Err(Error::Unsupported { .. })
        ));
        assert!(!detect(&b));
    }

    #[test]
    fn truncated_v2_name_warns() {
        let mut b = v2();
        b.truncate(34); // name cut short
        let f = RecycledItem::parse(&b).expect("parse");
        assert!(!f.warnings.is_empty());
        assert!(f.original_path.starts_with("C:\\"));
    }

    #[test]
    fn truncated_and_garbage_never_panic() {
        let full = v2();
        for cut in 0..full.len() {
            let _ = RecycledItem::parse(&full[..cut]);
        }
        let mut m = full.clone();
        for i in 0..m.len() {
            m[i] = 0xFF;
            let _ = RecycledItem::parse(&m);
            m[i] = full[i];
        }
    }

    #[test]
    fn v1_short_record_warns() {
        let mut b = v1();
        b.truncate(100);
        let f = RecycledItem::parse(&b).expect("parse");
        assert!(!f.warnings.is_empty());
        assert_eq!(f.original_path, "C:\\tmp\\old.txt");
    }
}
