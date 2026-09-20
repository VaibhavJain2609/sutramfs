//! Explicit little-endian decode helpers.
//!
//! On-disk filesystem structures are little-endian (with rare, explicitly
//! documented exceptions such as GPT GUID byte order or UFS). Parsers must
//! **never** read multi-byte integers via `transmute`, pointer casts, or
//! host-endian APIs — always use these helpers (or `from_le_bytes` on a
//! copied array). All helpers return `Option`/`None` instead of panicking on
//! short buffers so untrusted input cannot crash a parser.
//!
//! ```text
//! if let Some(v) = le::u32(buf, 0x1c) { ... } else { return Err(corrupt) }
//! ```

/// Return `buf[off..off+n]` or `None` when out of range.
#[inline]
pub fn get(buf: &[u8], off: usize, n: usize) -> Option<&[u8]> {
    buf.get(off..off.checked_add(n)?)
}

/// `u8` at `off`.
#[inline]
pub fn u8(buf: &[u8], off: usize) -> Option<u8> {
    buf.get(off).copied()
}

/// Little-endian `u16` at `off`.
#[inline]
pub fn u16(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(get(buf, off, 2)?.try_into().ok()?))
}

/// Big-endian `u16` at `off` (for the rare BE field, e.g. inside GPT GUIDs —
/// note GUIDs themselves are stored little-endian; prefer [`uuid_le`]).
#[inline]
pub fn u16_be(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes(get(buf, off, 2)?.try_into().ok()?))
}

/// Little-endian `u32` at `off`.
#[inline]
pub fn u32(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(get(buf, off, 4)?.try_into().ok()?))
}

/// Big-endian `u32` at `off`.
#[inline]
pub fn u32_be(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes(get(buf, off, 4)?.try_into().ok()?))
}

/// Little-endian `u64` at `off`.
#[inline]
pub fn u64(buf: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(get(buf, off, 8)?.try_into().ok()?))
}

/// Big-endian `u64` at `off`.
#[inline]
pub fn u64_be(buf: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_be_bytes(get(buf, off, 8)?.try_into().ok()?))
}

/// Decode a 16-byte GUID stored in Microsoft's mixed-endian on-disk form
/// (first three fields little-endian, last two as-is), as used by GPT.
/// Returns the RFC-4122 textual form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
pub fn uuid_le(buf: &[u8], off: usize) -> Option<String> {
    let raw = get(buf, off, 16)?;
    let d1 = u32::from_le_bytes(raw[0..4].try_into().ok()?);
    let d2 = u16::from_le_bytes(raw[4..6].try_into().ok()?);
    let d3 = u16::from_le_bytes(raw[6..8].try_into().ok()?);
    Some(format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15]
    ))
}

/// Decode a NUL- or space-terminated ASCII field (e.g. FAT volume label).
pub fn ascii(buf: &[u8], off: usize, n: usize) -> Option<String> {
    let raw = get(buf, off, n)?;
    let end = raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(raw.len());
    Some(String::from_utf8_lossy(&raw[..end]).trim_end().to_string())
}
