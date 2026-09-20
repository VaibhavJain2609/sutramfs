//! Small shared helpers.

/// Truncate `s` to at most `max` chars (on a char boundary), appending an
/// ellipsis marker when truncated. Used to bound error/report strings that
/// embed untrusted upstream text.
pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Unix epoch seconds now — the timestamp base for cache TTL accounting
/// (wall-clock, so it survives restarts and matches the sqlite schema).
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Normalise a hash for VT lookup: trim + lowercase + validate hex of a
/// plausible length (MD5 32 / SHA-1 40 / SHA-256 64). Returns the
/// normalised string or `None`.
pub fn normalize_hash(hash: &str) -> Option<String> {
    let h = hash.trim().to_ascii_lowercase();
    let ok_len = matches!(h.len(), 32 | 40 | 64);
    if ok_len && !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(h)
    } else {
        None
    }
}
