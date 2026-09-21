//! Shared machinery for all artifact parsers: error taxonomy, timestamps,
//! and a bounds-checked little-endian byte reader.
//!
//! [`ArtifactTimestamp`] mirrors `sutram_fs::FsTimestamp` field-for-field
//! (this crate is dependency-free by design, so it cannot reuse the type).

use std::fmt;
use std::io::{self, Read};
use std::time::Duration;

/// Default cap for [`read_to_end_bounded`]: 256 MiB. Artifact files are
/// small; the cap exists so a hostile/corrupt source cannot exhaust memory.
pub const DEFAULT_MAX_INPUT: u64 = 256 * 1024 * 1024;

/// Error taxonomy shared by every artifact parser (mirrors the sutram
/// `FsError` contract: `offset` is always an absolute byte offset into the
/// input buffer).
#[derive(Debug)]
pub enum Error {
    /// Malformed on-disk structure.
    Corrupt {
        /// Absolute byte offset of the offending structure.
        offset: u64,
        /// What was wrong.
        msg: String,
    },
    /// Input shorter than a structure requires.
    Truncated {
        /// Absolute byte offset where the read began.
        offset: u64,
        /// Bytes required.
        needed: u64,
        /// Bytes actually present.
        available: u64,
    },
    /// Recognised but unsupported variant (version, compression, …).
    Unsupported {
        /// Why it cannot be handled.
        msg: String,
    },
    /// Underlying source read failure (only from `from_reader`).
    Io(io::Error),
    /// Bad caller argument.
    InvalidInput {
        /// What was wrong.
        msg: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Corrupt { offset, msg } => write!(f, "corrupt at {offset:#x}: {msg}"),
            Error::Truncated {
                offset,
                needed,
                available,
            } => write!(
                f,
                "truncated at {offset:#x}: need {needed} bytes, have {available}"
            ),
            Error::Unsupported { msg } => write!(f, "unsupported: {msg}"),
            Error::Io(e) => write!(f, "io: {e}"),
            Error::InvalidInput { msg } => write!(f, "invalid input: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Read a whole artifact from a byte source, bounded by `max` bytes.
///
/// Returns [`Error::InvalidInput`] when the source exceeds `max` —
/// untrusted streams must not be able to force unbounded allocation.
pub fn read_to_end_bounded(mut r: impl Read, max: u64) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = r.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if buf.len() as u64 + n as u64 > max {
            return Err(Error::InvalidInput {
                msg: format!("input exceeds {max}-byte cap"),
            });
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

/// One timestamp as stored in an artifact, with its provenance.
///
/// Field-for-field mirror of `sutram_fs::FsTimestamp`: `value` is
/// nanoseconds since the Unix epoch (UTC), `None` when the on-disk field
/// is unset/zero or unrepresentable — parsers must not fabricate times.
#[derive(Debug, Clone)]
pub struct ArtifactTimestamp {
    /// Nanoseconds since the Unix epoch (UTC).
    pub value: Option<i64>,
    /// Raw on-disk value before decoding, for byte-level citation.
    pub raw_value: u64,
    /// Machine-readable encoding name, e.g. `"ntfs-filetime"`.
    pub raw_encoding: &'static str,
    /// Resolution of the on-disk field.
    pub granularity: Duration,
}

/// Seconds between 1601-01-01 and 1970-01-01.
const FILETIME_EPOCH_DELTA_S: i64 = 11_644_473_600;

/// Decode a Windows FILETIME (100-ns ticks since 1601-01-01 UTC).
/// A raw value of 0 means "unset" and yields `value: None`.
/// Split into seconds + remainder to avoid `i64` overflow: a live
/// FILETIME is ~1.3e17 ticks, and ticks×100 overflows.
pub fn filetime(raw: u64) -> ArtifactTimestamp {
    let value = if raw == 0 {
        None
    } else {
        let secs = (raw / 10_000_000) as i64;
        let rem_ns = ((raw % 10_000_000) as i64) * 100;
        secs.checked_sub(FILETIME_EPOCH_DELTA_S)
            .and_then(|s| s.checked_mul(1_000_000_000))
            .map(|ns| ns + rem_ns)
    };
    ArtifactTimestamp {
        value,
        raw_value: raw,
        raw_encoding: "ntfs-filetime",
        granularity: Duration::from_nanos(100),
    }
}

/// Decode a 32-bit Unix time in seconds.
pub fn unix_secs(raw: u32, encoding: &'static str) -> ArtifactTimestamp {
    ArtifactTimestamp {
        value: Some(raw as i64).and_then(|s| s.checked_mul(1_000_000_000)),
        raw_value: raw as u64,
        raw_encoding: encoding,
        granularity: Duration::from_secs(1),
    }
}

/// Decode a Mac absolute-time double (seconds since 2001-01-01 UTC),
/// as stored in bplist `date` objects.
pub fn mac_absolute_time(raw: f64) -> ArtifactTimestamp {
    const MAC_EPOCH_DELTA_S: f64 = 978_307_200.0;
    let unix_s = raw + MAC_EPOCH_DELTA_S;
    let value = if unix_s.is_finite() && unix_s.abs() < 4e18 / 1e9 {
        Some((unix_s * 1e9) as i64)
    } else {
        None
    };
    ArtifactTimestamp {
        value,
        raw_value: raw.to_bits(),
        raw_encoding: "mac-absolute-time",
        granularity: Duration::from_nanos(1),
    }
}

/// Nano-seconds since Unix epoch for a civil datetime (UTC), `None` for
/// out-of-range fields. (`days_from_civil` after Hinnant.)
#[allow(clippy::too_many_arguments)]
pub fn unix_nanos(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    min: i64,
    sec: i64,
    nanos: i64,
) -> Option<i64> {
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&min)
        || !(0..60).contains(&sec)
        || !(0..1_000_000_000).contains(&nanos)
    {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let dim = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ][(month - 1) as usize];
    if day > dim {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days.checked_mul(86_400)?
        .checked_add(hour.checked_mul(3600)? + min * 60 + sec)?
        .checked_mul(1_000_000_000)?
        .checked_add(nanos)
}

/// Bounds-checked little-endian cursor over a `&[u8]`. Every read either
/// succeeds or returns `Truncated` — unchecked indexing is impossible.
pub struct Cursor<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    pub fn at(buf: &'a [u8], pos: usize) -> Self {
        Cursor { buf, pos }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn trunc(&self, needed: usize) -> Error {
        Error::Truncated {
            offset: self.pos as u64,
            needed: needed as u64,
            available: self.remaining() as u64,
        }
    }

    pub fn u8(&mut self) -> Result<u8> {
        if self.remaining() < 1 {
            return Err(self.trunc(1));
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.arr()?))
    }

    pub fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.arr()?))
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.arr()?))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.arr()?))
    }

    pub fn be_u32(&mut self) -> Result<u32> {
        if self.remaining() < 4 {
            return Err(self.trunc(4));
        }
        let v = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap_or([0; 4]));
        self.pos += 4;
        Ok(v)
    }

    pub fn be_u64(&mut self) -> Result<u64> {
        if self.remaining() < 8 {
            return Err(self.trunc(8));
        }
        let v = u64::from_be_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap_or([0; 8]));
        self.pos += 8;
        Ok(v)
    }

    fn arr<const N: usize>(&mut self) -> Result<[u8; N]> {
        if self.remaining() < N {
            return Err(self.trunc(N));
        }
        let mut a = [0u8; N];
        a.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(a)
    }

    /// Borrow `n` bytes at the cursor, advancing past them.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(self.trunc(n));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.bytes(n).map(|_| ())
    }
}

/// Slice `len` bytes at absolute `off` without moving a cursor.
pub fn slice_at(buf: &[u8], off: usize, len: usize) -> Result<&[u8]> {
    let end = off.checked_add(len).ok_or_else(|| Error::Corrupt {
        offset: off as u64,
        msg: "offset overflow".into(),
    })?;
    if end > buf.len() {
        return Err(Error::Truncated {
            offset: off as u64,
            needed: len as u64,
            available: buf.len().saturating_sub(off) as u64,
        });
    }
    Ok(&buf[off..end])
}

/// Decode UTF-16LE units, tolerating lone surrogates (lossy).
pub fn utf16_lossy(units: &[u16]) -> String {
    String::from_utf16_lossy(units)
}

/// Read a NUL-terminated-or-exact UTF-16LE string from raw bytes.
/// Trailing NULs are stripped; odd trailing bytes are ignored.
pub fn utf16_str(raw: &[u8]) -> String {
    let n = raw.len() / 2;
    let mut units = Vec::with_capacity(n);
    for i in 0..n {
        units.push(u16::from_le_bytes([raw[2 * i], raw[2 * i + 1]]));
    }
    while units.last() == Some(&0) {
        units.pop();
    }
    utf16_lossy(&units)
}

/// Read a NUL-terminated-or-exact byte string (ASCII/ANSI/UTF-8-ish).
/// Non-UTF8 bytes become U+FFFD via `String::from_utf8_lossy`.
pub fn ansi_str(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// Format 16 bytes as a GUID string using the Windows "GUID packet"
/// (mixed-endian) representation: first three fields little-endian,
/// last two verbatim — matching how LNK droid IDs and registry GUIDs
/// are displayed by Windows tools.
pub fn guid_string(b: &[u8]) -> String {
    if b.len() != 16 {
        return String::new();
    }
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// If a GUID is version-1 (time-based), decode the embedded MAC address
/// (last 6 bytes) and the 60-bit timestamp. Returns `(mac, filetime_raw)`.
pub fn guid_v1_mac_time(b: &[u8]) -> Option<(String, u64)> {
    if b.len() != 16 {
        return None;
    }
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    if (d3 >> 12) != 1 {
        return None;
    }
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64;
    let d2 = u16::from_le_bytes([b[4], b[5]]) as u64;
    let ts = ((d3 as u64 & 0x0fff) << 48) | (d2 << 32) | d1;
    let mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[10], b[11], b[12], b[13], b[14], b[15]
    );
    Some((mac, ts))
}
