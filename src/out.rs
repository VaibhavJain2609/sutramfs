//! Entry output formatters: tree, JSONL, CSV, mactime bodyfile.

use std::io::Write;
use sutram_fs::{EntryKind, FsEntry, FsEntryStatus, FsTimestamp};

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn kind_str(k: EntryKind) -> &'static str {
    match k {
        EntryKind::File => "file",
        EntryKind::Directory => "dir",
        EntryKind::Symlink => "symlink",
        EntryKind::Other => "other",
    }
}

fn status_str(e: &FsEntry) -> String {
    match e.status {
        FsEntryStatus::Live => "live".into(),
        FsEntryStatus::Deleted { recovery } => format!("deleted:{recovery}"),
    }
}

fn ts_json(t: &FsTimestamp) -> String {
    format!(
        "{{\"value\":{},\"raw\":{},\"encoding\":\"{}\",\"granularity_ns\":{}}}",
        t.value.map(|v| v.to_string()).unwrap_or("null".into()),
        t.raw_value,
        t.raw_encoding,
        t.granularity.as_nanos()
    )
}

fn json(e: &FsEntry) -> String {
    let mut ts = String::from("{");
    for (name, t) in [
        ("modified", &e.timestamps.modified),
        ("accessed", &e.timestamps.accessed),
        ("created", &e.timestamps.created),
        ("changed", &e.timestamps.changed),
        ("deleted", &e.timestamps.deleted),
    ] {
        ts.push_str(&format!(
            "\"{name}\":{},",
            t.as_ref().map(|t| ts_json(t)).unwrap_or("null".into())
        ));
    }
    ts.pop();
    ts.push('}');

    let magic = e
        .magic
        .as_ref()
        .map(|m| {
            format!(
                "{{\"declared\":{},\"detected\":{},\"mismatch\":{},\"severity\":\"{:?}\",\"reasons\":[{}]}}",
                m.declared.map(|k| format!("\"{k:?}\"")).unwrap_or("null".into()),
                m.detected.map(|k| format!("\"{k:?}\"")).unwrap_or("null".into()),
                m.mismatch,
                m.severity,
                m.reasons.iter().map(|r| format!("\"{}\"", esc(r))).collect::<Vec<_>>().join(",")
            )
        })
        .unwrap_or("null".into());

    let meta = e
        .meta
        .iter()
        .map(|(k, v)| format!("\"{}\":\"{}\"", esc(k), esc(v)))
        .collect::<Vec<_>>()
        .join(",");

    let ranges = e
        .allocated_ranges
        .iter()
        .map(|(o, l)| format!("[{o},{l}]"))
        .collect::<Vec<_>>()
        .join(",");

    format!(
        "{{\"path\":\"{}\",\"name\":\"{}\",\"entry_id\":{},\"kind\":\"{}\",\"size\":{},\"disk_offset\":{},\"allocated_ranges\":[{}],\"status\":\"{}\",\"timestamps\":{},\"meta\":{{{}}},\"magic\":{}}}",
        esc(&e.path),
        esc(&e.name),
        e.entry_id,
        kind_str(e.kind),
        e.size,
        e.disk_offset,
        ranges,
        esc(&status_str(e)),
        ts,
        meta,
        magic
    )
}

fn tree(e: &FsEntry) -> String {
    let deleted = if e.is_deleted() { " [DELETED]" } else { "" };
    let magic_note = match &e.magic {
        Some(m) if m.mismatch => format!(" [MAGIC-MISMATCH {:?}]", m.severity),
        _ => String::new(),
    };
    let ts = e
        .timestamps
        .modified
        .as_ref()
        .and_then(|t| t.value)
        .map(|ns| {
            let secs = ns / 1_000_000_000;
            format!(" {}", secs) // epoch seconds — compact; JSONL carries full detail
        })
        .unwrap_or_default();
    format!(
        "{:<10} {:>10} {:>8} {}{}{}{}",
        kind_str(e.kind),
        e.size,
        e.entry_id,
        e.path,
        deleted,
        magic_note,
        ts
    )
}

fn csv(e: &FsEntry) -> String {
    let mtime = e
        .timestamps
        .modified
        .as_ref()
        .and_then(|t| t.value)
        .map(|v| (v / 1_000_000_000).to_string())
        .unwrap_or_default();
    let path = if e.path.contains(',') || e.path.contains('"') {
        format!("\"{}\"", e.path.replace('"', "\"\""))
    } else {
        e.path.clone()
    };
    format!(
        "{},{},{},{},{},{},{}",
        e.entry_id,
        kind_str(e.kind),
        e.size,
        status_str(e),
        mtime,
        e.disk_offset,
        path
    )
}

/// mactime bodyfile: name|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
fn bodyfile(e: &FsEntry) -> String {
    let sec = |t: &Option<FsTimestamp>| {
        t.as_ref()
            .and_then(|t| t.value)
            .map(|v| (v / 1_000_000_000).to_string())
            .unwrap_or_else(|| "0".into())
    };
    let mode = e
        .meta
        .get("mode")
        .cloned()
        .unwrap_or_else(|| kind_str(e.kind).into());
    let uid = e.meta.get("uid").cloned().unwrap_or_else(|| "0".into());
    let gid = e.meta.get("gid").cloned().unwrap_or_else(|| "0".into());
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        e.path,
        e.entry_id,
        mode,
        uid,
        gid,
        e.size,
        sec(&e.timestamps.accessed),
        sec(&e.timestamps.modified),
        sec(&e.timestamps.changed),
        sec(&e.timestamps.created)
    )
}

pub fn emit(w: &mut impl Write, e: &FsEntry, format: &str) -> std::io::Result<()> {
    let line = match format {
        "json" | "jsonl" => json(e),
        "csv" => csv(e),
        "bodyfile" | "mactime" => bodyfile(e),
        _ => tree(e),
    };
    writeln!(w, "{line}")
}
