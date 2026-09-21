//! Windows Prefetch (`*.pf`) parser — `SCCA` format versions 17, 23,
//! 26, 30 and 31.
//!
//! Header (all versions, little-endian):
//!
//! | Offset | Field                                    |
//! |--------|------------------------------------------|
//! | 0x00   | `u32` format version (17/23/26/30/31)    |
//! | 0x04   | `"SCCA"` signature                        |
//! | 0x0C   | `u32` claimed file size                   |
//! | 0x10   | `char[30]` UTF-16LE executable name       |
//! | 0x4C   | `u32` prefetch hash (of the exe's path)   |
//!
//! The version-specific *file information* section starts at 0x54 and
//! carries the run-count and last-run FILETIME array:
//!
//! | Version | OS           | run times        | run count |
//! |---------|--------------|------------------|-----------|
//! | 17      | XP/2003      | 1 × @0x78        | @0x90     |
//! | 23      | Vista/7      | 1 × @0x80        | @0x98     |
//! | 26      | 8/8.1        | 8 × @0x80        | @0xD0     |
//! | 30      | 10           | 8 × @0x80        | @0xD0 / @0xC8 (variant) |
//! | 31      | 11           | 8 × @0x80        | @0xD0     |
//!
//! Windows 10+ normally wraps the whole file in a `MAM\x04` XPRESS-
//! Huffman container. Those are detected and reported
//! `compressed: true`; the body decode returns
//! [`Error::Unsupported`] — this crate ships no decompressor.

use crate::common::{
    filetime, read_to_end_bounded, utf16_str, ArtifactTimestamp, Error, Result, DEFAULT_MAX_INPUT,
};
use std::io::Read;

/// Uncompressed signature (at offset 4).
pub const SCCA_SIG: &[u8; 4] = b"SCCA";
/// Compressed container signature (at offset 0).
pub const MAM_SIG: &[u8; 4] = b"MAM\x04";
/// Size of the fixed file header (through the prefetch hash + spare).
pub const HEADER_LEN: usize = 0x54;
/// Executable-name field: offset and byte length (30 UTF-16 units).
pub const NAME_OFF: usize = 0x10;
/// Name field length in bytes.
pub const NAME_LEN: usize = 60;
/// Prefetch-hash field offset.
pub const HASH_OFF: usize = 0x4C;
/// Number of run-time slots in versions ≥ 26.
pub const RUN_TIME_SLOTS: usize = 8;

/// Quick triage check: `MAM\x04` compressed container or a plausible
/// `version + "SCCA"` header.
pub fn detect(data: &[u8]) -> bool {
    if data.len() >= 4 && &data[..4] == MAM_SIG {
        return true;
    }
    if data.len() < 8 || &data[4..8] != SCCA_SIG {
        return false;
    }
    matches!(
        u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        17 | 23 | 26 | 30 | 31
    )
}

/// A parsed prefetch file.
#[derive(Debug, Clone)]
pub struct Prefetch {
    /// Format version (17/23/26/30/31), or `None` for a compressed file
    /// whose inner header was not decoded.
    pub version: Option<u32>,
    /// True for `MAM\x04` XPRESS-compressed input (Win10 1607+). Body
    /// fields are `None`; call [`Prefetch::body`] for the explicit
    /// `Unsupported` error.
    pub compressed: bool,
    /// Declared decompressed size (compressed inputs only).
    pub uncompressed_size: Option<u32>,
    /// Executable file name from the header (UTF-16LE, ≤ 29 chars).
    pub executable_name: Option<String>,
    /// Prefetch hash of the executable's path (matches the `-XXXXXXXX`
    /// in the `.pf` filename).
    pub prefetch_hash: Option<u32>,
    /// File size claimed by the header.
    pub claimed_size: Option<u32>,
    /// Times the program was run.
    pub run_count: Option<u32>,
    /// Last-run FILETIMEs, newest first. One entry on v17/v23; up to
    /// eight on v26+ (empty/zero slots are included with `value: None`).
    pub last_run_times: Vec<ArtifactTimestamp>,
    /// Absolute offset of the file-information section.
    pub file_info_offset: usize,
    /// Non-fatal anomalies (size mismatch, unknown variant, …).
    pub warnings: Vec<String>,
}

impl Prefetch {
    /// Parse a prefetch file from a byte slice.
    ///
    /// Compressed (`MAM`) input succeeds with `compressed: true` and no
    /// body fields — use [`Prefetch::body`] to get the explicit error.
    pub fn parse(data: &[u8]) -> Result<Prefetch> {
        if data.len() >= 4 && &data[..4] == MAM_SIG {
            let size = if data.len() >= 8 {
                Some(u32::from_le_bytes([data[4], data[5], data[6], data[7]]))
            } else {
                None
            };
            return Ok(Prefetch {
                version: None,
                compressed: true,
                uncompressed_size: size,
                executable_name: None,
                prefetch_hash: None,
                claimed_size: None,
                run_count: None,
                last_run_times: Vec::new(),
                file_info_offset: 0,
                warnings: vec!["MAM/XPRESS-compressed prefetch; body not decoded".into()],
            });
        }
        if data.len() < HEADER_LEN {
            return Err(Error::Truncated {
                offset: 0,
                needed: HEADER_LEN as u64,
                available: data.len() as u64,
            });
        }
        if &data[4..8] != SCCA_SIG {
            return Err(Error::Corrupt {
                offset: 4,
                msg: "bad SCCA signature".into(),
            });
        }
        let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if !matches!(version, 17 | 23 | 26 | 30 | 31) {
            return Err(Error::Unsupported {
                msg: format!("prefetch version {version}"),
            });
        }
        let claimed_size = u32::from_le_bytes([data[0x0C], data[0x0D], data[0x0E], data[0x0F]]);
        let executable_name = utf16_str(&data[NAME_OFF..NAME_OFF + NAME_LEN]);
        let prefetch_hash =
            u32::from_le_bytes([data[HASH_OFF], data[HASH_OFF + 1], data[HASH_OFF + 2], data[HASH_OFF + 3]]);

        let mut warnings = Vec::new();
        if claimed_size != 0 && claimed_size as usize != data.len() {
            warnings.push(format!(
                "header size {claimed_size} != actual {}",
                data.len()
            ));
        }

        // Version-dependent field layout (see module table).
        let (times_off, n_times, run_count_off) = match version {
            17 => (0x78usize, 1usize, 0x90usize),
            23 => (0x80, 1, 0x98),
            26 => (0x80, RUN_TIME_SLOTS, 0xD0),
            30 | 31 => {
                // Two file-information layouts are documented for v30
                // (220- and 212-byte). The metrics-array offset at file
                // info +0 disambiguates: 0x130 → run count @0xD0,
                // 0x128 → @0xC8.
                let metrics = u32::from_le_bytes([
                    data[HEADER_LEN],
                    data[HEADER_LEN + 1],
                    data[HEADER_LEN + 2],
                    data[HEADER_LEN + 3],
                ]);
                let rc = match metrics {
                    0x128 => {
                        warnings.push("v30 variant-2 layout (metrics @0x128)".into());
                        0xC8
                    }
                    0x130 => 0xD0,
                    _ => 0xD0,
                };
                (0x80, RUN_TIME_SLOTS, rc)
            }
            _ => unreachable!(),
        };

        let mut last_run_times = Vec::new();
        for i in 0..n_times {
            let o = times_off + i * 8;
            match data.get(o..o + 8) {
                Some(b) => last_run_times
                    .push(filetime(u64::from_le_bytes(b.try_into().unwrap_or([0; 8])))),
                None => {
                    warnings.push(format!("run time slot {i} truncated"));
                    break;
                }
            }
        }
        let run_count = match data.get(run_count_off..run_count_off + 4) {
            Some(b) => Some(u32::from_le_bytes(b.try_into().unwrap_or([0; 4]))),
            None => {
                warnings.push(format!("run count @{run_count_off:#x} truncated"));
                None
            }
        };

        Ok(Prefetch {
            version: Some(version),
            compressed: false,
            uncompressed_size: None,
            executable_name: Some(executable_name),
            prefetch_hash: Some(prefetch_hash),
            claimed_size: Some(claimed_size),
            run_count,
            last_run_times,
            file_info_offset: HEADER_LEN,
            warnings,
        })
    }

    /// Parse from any `Read`, bounded at `DEFAULT_MAX_INPUT` bytes.
    pub fn from_reader(r: impl Read) -> Result<Prefetch> {
        Self::parse(&read_to_end_bounded(r, DEFAULT_MAX_INPUT)?)
    }

    /// Explicitly request the decoded body of a compressed file —
    /// always [`Error::Unsupported`]; exists so callers get a typed
    /// error instead of silently-empty fields.
    pub fn body(&self) -> Result<()> {
        if self.compressed {
            Err(Error::Unsupported {
                msg: "XPRESS-Huffman decompression not implemented".into(),
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w32(b: &mut Vec<u8>, off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn w64(b: &mut Vec<u8>, off: usize, v: u64) {
        b[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Minimal header + file-info region sized for the version.
    fn make(version: u32, size: usize) -> Vec<u8> {
        let mut b = vec![0u8; size];
        w32(&mut b, 0, version);
        b[4..8].copy_from_slice(SCCA_SIG);
        w32(&mut b, 0x0C, size as u32);
        let name = "EVIL.EXE";
        for (i, u) in name.encode_utf16().enumerate() {
            b[NAME_OFF + 2 * i] = u as u8;
            b[NAME_OFF + 2 * i + 1] = (u >> 8) as u8;
        }
        w32(&mut b, HASH_OFF, 0xCAFEBABE);
        b
    }

    #[test]
    fn parses_v17() {
        let mut b = make(17, 0xA0);
        w64(&mut b, 0x78, 133_000_000_000_000_000);
        w32(&mut b, 0x90, 7);
        let p = Prefetch::parse(&b).expect("parse");
        assert_eq!(p.version, Some(17));
        assert_eq!(p.executable_name.as_deref(), Some("EVIL.EXE"));
        assert_eq!(p.prefetch_hash, Some(0xCAFEBABE));
        assert_eq!(p.run_count, Some(7));
        assert_eq!(p.last_run_times.len(), 1);
        assert!(p.last_run_times[0].value.is_some());
        assert!(detect(&b));
    }

    #[test]
    fn parses_v23() {
        let mut b = make(23, 0x100);
        w64(&mut b, 0x80, 133_111_111_111_111_111);
        w32(&mut b, 0x98, 3);
        let p = Prefetch::parse(&b).expect("parse");
        assert_eq!(p.run_count, Some(3));
        assert_eq!(p.last_run_times.len(), 1);
    }

    #[test]
    fn parses_v30_eight_times() {
        let mut b = make(30, 0x200);
        w32(&mut b, HEADER_LEN, 0x130); // metrics offset → variant 1
        for i in 0..8 {
            w64(&mut b, 0x80 + i * 8, 133_000_000_000_000_000 + i as u64);
        }
        w32(&mut b, 0xD0, 55);
        let p = Prefetch::parse(&b).expect("parse");
        assert_eq!(p.run_count, Some(55));
        assert_eq!(p.last_run_times.len(), 8);
        assert_eq!(p.last_run_times[7].raw_value, 133_000_000_000_000_007);
    }

    #[test]
    fn v30_variant2_run_count() {
        let mut b = make(30, 0x200);
        w32(&mut b, HEADER_LEN, 0x128); // variant 2
        w32(&mut b, 0xC8, 99);
        let p = Prefetch::parse(&b).expect("parse");
        assert_eq!(p.run_count, Some(99));
        assert!(p.warnings.iter().any(|w| w.contains("variant-2")));
    }

    #[test]
    fn mam_compressed_detected() {
        let mut b = b"MAM\x04".to_vec();
        b.extend_from_slice(&12345u32.to_le_bytes());
        b.extend_from_slice(&[0xAB; 32]);
        let p = Prefetch::parse(&b).expect("parse");
        assert!(p.compressed);
        assert_eq!(p.uncompressed_size, Some(12345));
        assert!(p.executable_name.is_none());
        assert!(matches!(p.body(), Err(Error::Unsupported { .. })));
        assert!(detect(&b));
    }

    #[test]
    fn rejects_garbage_and_unknown_version() {
        assert!(matches!(
            Prefetch::parse(b"no"),
            Err(Error::Truncated { .. })
        ));
        let mut b = make(99, 0x100);
        assert!(matches!(
            Prefetch::parse(&b),
            Err(Error::Unsupported { .. })
        ));
        w32(&mut b, 0, 23);
        b[4] = b'X';
        assert!(matches!(
            Prefetch::parse(&b),
            Err(Error::Corrupt { .. })
        ));
    }

    #[test]
    fn truncated_never_panics() {
        let full = make(26, 0x200);
        for cut in 0..full.len() {
            let _ = Prefetch::parse(&full[..cut]);
        }
        for i in 0..full.len() {
            let mut m = full.clone();
            m[i] ^= 0xA5;
            let _ = Prefetch::parse(&m);
        }
    }
}
