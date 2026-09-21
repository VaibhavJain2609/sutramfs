//! Minimal hand-rolled JSON writers — no serde dependency. `FsEntry` and
//! `FsInfo` are foreign types so derives are unavailable anyway; writing
//! them by hand keeps exact control over field names (shared with the
//! Python dict shape) and guarantees the output is valid JSON
//! (all strings pass through [`esc`]).

use std::fmt::Write;

use sutram_fs::{DetectConfidence, FsEntry, FsInfo, FsTimestamp};

/// Append a JSON-escaped, quoted string.
pub fn esc(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn kv(out: &mut String, key: &str, first: &mut bool) {
    if !*first {
        out.push(',');
    }
    *first = false;
    esc(out, key);
    out.push(':');
}

/// Serialize one entry as a single-line JSON object.
pub fn entry_json(e: &FsEntry) -> String {
    let mut s = String::with_capacity(256);
    let mut first = true;
    s.push('{');
    kv(&mut s, "path", &mut first);
    esc(&mut s, &e.path);
    kv(&mut s, "name", &mut first);
    esc(&mut s, &e.name);
    kv(&mut s, "entry_id", &mut first);
    let _ = write!(s, "{}", e.entry_id);
    kv(&mut s, "kind", &mut first);
    esc(
        &mut s,
        match e.kind {
            sutram_fs::EntryKind::File => "file",
            sutram_fs::EntryKind::Directory => "directory",
            sutram_fs::EntryKind::Symlink => "symlink",
            sutram_fs::EntryKind::Other => "other",
        },
    );
    kv(&mut s, "size", &mut first);
    let _ = write!(s, "{}", e.size);
    kv(&mut s, "disk_offset", &mut first);
    let _ = write!(s, "{}", e.disk_offset);

    kv(&mut s, "allocated_ranges", &mut first);
    s.push('[');
    for (i, (off, len)) in e.allocated_ranges.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "[{off},{len}]");
    }
    s.push(']');

    kv(&mut s, "status", &mut first);
    match e.status {
        sutram_fs::FsEntryStatus::Live => esc(&mut s, "live"),
        sutram_fs::FsEntryStatus::Deleted { recovery } => {
            s.push_str("{\"deleted\":{\"recovery\":");
            esc(
                &mut s,
                match recovery {
                    sutram_fs::RecoveryState::Intact => "intact",
                    sutram_fs::RecoveryState::PartiallyOverwritten { .. } => "partial",
                    sutram_fs::RecoveryState::Unrecoverable => "unrecoverable",
                    sutram_fs::RecoveryState::Unknown => "unknown",
                },
            );
            if let sutram_fs::RecoveryState::PartiallyOverwritten {
                recovered_bytes,
                total_bytes,
            } = recovery
            {
                let _ = write!(
                    s,
                    ",\"recovered_bytes\":{recovered_bytes},\"total_bytes\":{total_bytes}"
                );
            }
            s.push_str("}}");
        }
    }

    kv(&mut s, "timestamps", &mut first);
    timestamps_json(&mut s, e);

    kv(&mut s, "meta", &mut first);
    s.push('{');
    let mut mfirst = true;
    // Sorted for deterministic output across runs.
    let mut keys: Vec<&String> = e.meta.keys().collect();
    keys.sort();
    for k in keys {
        kv(&mut s, k, &mut mfirst);
        esc(&mut s, &e.meta[k]);
    }
    s.push('}');

    kv(&mut s, "magic", &mut first);
    match &e.magic {
        None => s.push_str("null"),
        Some(m) => {
            s.push('{');
            let mut f = true;
            kv(&mut s, "declared", &mut f);
            match &m.declared {
                Some(d) => esc(&mut s, &format!("{d:?}")),
                None => s.push_str("null"),
            }
            kv(&mut s, "detected", &mut f);
            match &m.detected {
                Some(d) => esc(&mut s, &format!("{d:?}")),
                None => s.push_str("null"),
            }
            kv(&mut s, "mismatch", &mut f);
            s.push_str(if m.mismatch { "true" } else { "false" });
            kv(&mut s, "severity", &mut f);
            esc(&mut s, &format!("{:?}", m.severity));
            kv(&mut s, "reasons", &mut f);
            s.push('[');
            for (i, r) in m.reasons.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                esc(&mut s, r);
            }
            s.push(']');
            s.push('}');
        }
    }

    s.push('}');
    s
}

fn timestamps_json(s: &mut String, e: &FsEntry) {
    s.push('{');
    let mut first = true;
    let t = &e.timestamps;
    for (name, ts) in [
        ("modified", &t.modified),
        ("accessed", &t.accessed),
        ("created", &t.created),
        ("changed", &t.changed),
        ("deleted", &t.deleted),
    ] {
        kv(s, name, &mut first);
        ts_json(s, ts);
    }
    s.push('}');
}

fn ts_json(s: &mut String, ts: &Option<FsTimestamp>) {
    match ts {
        None => s.push_str("null"),
        Some(t) => {
            s.push('{');
            let mut f = true;
            kv(s, "value_ns", &mut f);
            match t.value {
                Some(v) => {
                    let _ = write!(s, "{v}");
                }
                None => s.push_str("null"),
            }
            kv(s, "raw_value", &mut f);
            let _ = write!(s, "{}", t.raw_value);
            kv(s, "raw_encoding", &mut f);
            esc(s, t.raw_encoding);
            kv(s, "granularity_ns", &mut f);
            let _ = write!(s, "{}", t.granularity.as_nanos());
            s.push('}');
        }
    }
}

/// Serialize `FsInfo` as JSON.
pub fn info_json(i: &FsInfo, parser_name: &str) -> String {
    let mut s = String::with_capacity(192);
    let mut first = true;
    s.push('{');
    kv(&mut s, "parser", &mut first);
    esc(&mut s, parser_name);
    kv(&mut s, "fs_type", &mut first);
    esc(&mut s, &i.fs_type);
    kv(&mut s, "label", &mut first);
    match &i.label {
        Some(l) => esc(&mut s, l),
        None => s.push_str("null"),
    }
    kv(&mut s, "uuid", &mut first);
    match &i.uuid {
        Some(u) => esc(&mut s, u),
        None => s.push_str("null"),
    }
    kv(&mut s, "block_size", &mut first);
    let _ = write!(s, "{}", i.block_size);
    kv(&mut s, "total_blocks", &mut first);
    let _ = write!(s, "{}", i.total_blocks);
    kv(&mut s, "free_blocks", &mut first);
    match i.free_blocks {
        Some(v) => {
            let _ = write!(s, "{v}");
        }
        None => s.push_str("null"),
    }
    kv(&mut s, "total_nodes", &mut first);
    match i.total_nodes {
        Some(v) => {
            let _ = write!(s, "{v}");
        }
        None => s.push_str("null"),
    }
    kv(&mut s, "meta", &mut first);
    s.push('{');
    let mut mf = true;
    let mut keys: Vec<&String> = i.meta.keys().collect();
    keys.sort();
    for k in keys {
        kv(&mut s, k, &mut mf);
        esc(&mut s, &i.meta[k]);
    }
    s.push('}');
    s.push('}');
    s
}

/// Serialize detect results:
/// `{"filesystem":<best|null>,"confidence":<best|null>,"candidates":[[name,conf],…]}`.
pub fn detect_json(candidates: &[(&'static str, DetectConfidence)]) -> String {
    let mut s = String::with_capacity(128);
    s.push('{');
    let best = candidates.first();
    s.push_str("\"filesystem\":");
    match best {
        Some((n, c)) if *c >= DetectConfidence::Medium => esc(&mut s, n),
        _ => s.push_str("null"),
    }
    s.push_str(",\"confidence\":");
    match best {
        Some((_, c)) if *c >= DetectConfidence::Medium => {
            esc(&mut s, confidence_name(*c))
        }
        _ => s.push_str("null"),
    }
    s.push_str(",\"candidates\":[");
    for (i, (n, c)) in candidates.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push('[');
        esc(&mut s, n);
        s.push(',');
        esc(&mut s, confidence_name(*c));
        s.push(']');
    }
    s.push_str("]}");
    s
}

fn confidence_name(c: DetectConfidence) -> &'static str {
    match c {
        DetectConfidence::None => "none",
        DetectConfidence::Low => "low",
        DetectConfidence::Medium => "medium",
        DetectConfidence::High => "high",
        DetectConfidence::Certain => "certain",
    }
}

/// One-line `{"error":"…"}` object for lenient-mode walk errors.
pub fn error_json(msg: &str) -> String {
    let mut s = String::with_capacity(msg.len() + 16);
    s.push_str("{\"error\":");
    esc(&mut s, msg);
    s.push('}');
    s
}
