//! Small shared utilities for parser crates.
//!
//! Endianness: parsers must decode on-disk integers with
//! [`sutram_io::le`] (or `from_le_bytes` on copied arrays) — never
//! transmute or host-order reads. Filesystems are overwhelmingly
//! little-endian; big-endian fields (GPT GUIDs, LUKS version) get explicit
//! `be` helpers.

/// Join a path component onto a parent path with `/` separators.
///
/// ```
/// use sutram_fs::util::join_path;
/// assert_eq!(join_path("/", "a"), "/a");
/// assert_eq!(join_path("/a", "b"), "/a/b");
/// ```
pub fn join_path(parent: &str, name: &str) -> String {
    if parent == "/" || parent.is_empty() {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// Make an on-disk name safe to embed in a `path`: replaces `/`, `\`,
/// NUL and control characters with `_`. Never fails, never panics —
/// untrusted dirents carry arbitrary bytes.
pub fn sanitize_name(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c == '/' || c == '\\' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect()
}

/// Pseudo-path for an orphaned/lost entry with no surviving name.
/// Convention: `$ORPHANED/<identifier>`.
pub fn orphan_path(id: u64) -> String {
    format!("/$ORPHANED/{id:#x}")
}

/// Nano-seconds since Unix epoch for a civil datetime (UTC).
/// Returns `None` for out-of-range/invalid fields — callers map that to
/// `FsTimestamp { value: None, .. }`.
///
/// `days_from_civil` algorithm after Hinnant; valid for years in
/// roughly ±292 million.
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
    // Impossible calendar dates (Feb 30, Apr 31, Feb 29 on a common year)
    // must yield None — silently rolling into the next month would
    // misreport the evidence.
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
    days
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3600)? + min * 60 + sec)?
        .checked_mul(1_000_000_000)?
        .checked_add(nanos)
}
