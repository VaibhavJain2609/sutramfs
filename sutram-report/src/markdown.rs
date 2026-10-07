//! `Report` → Markdown. Tables, fenced nothing, GitHub-renderable.
//! Cells are sanitised (`|` escaped, newlines folded) so on-disk names
//! can't break the layout.

use std::fmt::Write as _;

use crate::report::{severity_label, Report};

/// Make a string safe for a Markdown table cell.
fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace(['\n', '\r'], " ")
}

fn opt(v: &Option<String>) -> String {
    v.clone().unwrap_or_else(|| "—".into())
}

fn ns(v: Option<i64>) -> String {
    v.map(|n| n.to_string())
        .unwrap_or_else(|| "—".into())
}

/// Render the full report.
pub fn render(r: &Report) -> String {
    let mut o = String::with_capacity(16 * 1024);
    let _ = writeln!(o, "# {}", cell(&r.title));
    let _ = writeln!(o);
    let _ = writeln!(o, "- **Tool:** {}", r.tool);
    let _ = writeln!(o, "- **Generated (unix s):** {}", r.generated_unix_secs);
    if !r.image_desc.is_empty() {
        let _ = writeln!(o, "- **Image:** {}", cell(&r.image_desc));
    }
    let _ = writeln!(o);

    // ---- Volume --------------------------------------------------------
    let v = &r.volume;
    let _ = writeln!(o, "## Volume");
    let _ = writeln!(o);
    let _ = writeln!(o, "| Field | Value |");
    let _ = writeln!(o, "|---|---|");
    let _ = writeln!(o, "| fs_type | {} |", cell(&v.fs_type));
    let _ = writeln!(o, "| label | {} |", cell(&opt(&v.label)));
    let _ = writeln!(o, "| uuid | {} |", cell(&opt(&v.uuid)));
    let _ = writeln!(o, "| block_size | {} |", v.block_size);
    let _ = writeln!(o, "| total_blocks | {} |", v.total_blocks);
    let _ = writeln!(
        o,
        "| free_blocks | {} |",
        v.free_blocks.map(|n| n.to_string()).unwrap_or("—".into())
    );
    let _ = writeln!(o, "| image_size | {} |", v.image_size);
    for (k, val) in &v.meta {
        let _ = writeln!(o, "| {} | {} |", cell(k), cell(val));
    }
    let _ = writeln!(o);

    // ---- Census ----------------------------------------------------------
    let c = &r.census;
    let _ = writeln!(o, "## Entry census");
    let _ = writeln!(o);
    let _ = writeln!(o, "| Metric | Count |");
    let _ = writeln!(o, "|---|---|");
    let _ = writeln!(o, "| total entries | {} |", c.total_entries);
    let _ = writeln!(o, "| live | {} |", c.live);
    let _ = writeln!(o, "| deleted | {} |", c.deleted);
    let _ = writeln!(o, "| files | {} |", c.files);
    let _ = writeln!(o, "| directories | {} |", c.directories);
    let _ = writeln!(o, "| symlinks | {} |", c.symlinks);
    let _ = writeln!(o, "| other | {} |", c.other);
    let _ = writeln!(o, "| recovery: intact | {} |", c.recovery_intact);
    let _ = writeln!(o, "| recovery: partial | {} |", c.recovery_partial);
    let _ = writeln!(
        o,
        "| recovery: unrecoverable | {} |",
        c.recovery_unrecoverable
    );
    let _ = writeln!(o, "| recovery: unknown | {} |", c.recovery_unknown);
    let _ = writeln!(o, "| live bytes | {} |", c.live_bytes);
    let _ = writeln!(o, "| deleted bytes | {} |", c.deleted_bytes);
    let _ = writeln!(o, "| walk errors | {} |", c.walk_errors);
    let _ = writeln!(o);

    // ---- Deleted recovery --------------------------------------------------
    let d = &r.deleted;
    let _ = writeln!(o, "## Deleted recovery");
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "**{}** deleted entries — intact **{}**, partial **{}**, lost **{}**; \
         **{}**/**{}** bytes recoverable.",
        d.rows.len(),
        d.intact,
        d.partial,
        d.lost,
        d.recovered_bytes,
        d.total_bytes
    );
    let _ = writeln!(o);
    if !d.rows.is_empty() {
        let _ = writeln!(
            o,
            "| Path | Size | Recovery | Recovered B | Total B | Dirent @ |"
        );
        let _ = writeln!(o, "|---|---|---|---|---|---|");
        for row in &d.rows {
            let _ = writeln!(
                o,
                "| {} | {} | {} | {} | {} | {:#x} |",
                cell(&row.path),
                row.size,
                row.recovery,
                row.recovered_bytes,
                row.total_bytes,
                row.disk_offset
            );
        }
        let _ = writeln!(o);
    }

    // ---- Magic mismatches ---------------------------------------------------
    let _ = writeln!(o, "## Extension/content mismatches");
    let _ = writeln!(o);
    if r.magic_mismatches.is_empty() {
        let _ = writeln!(o, "None.");
    } else {
        let _ = writeln!(
            o,
            "| Severity | Path | Declared | Detected | Size | Deleted | Reasons |"
        );
        let _ = writeln!(o, "|---|---|---|---|---|---|---|");
        for m in &r.magic_mismatches {
            let _ = writeln!(
                o,
                "| {} | {} | {} | {} | {} | {} | {} |",
                severity_label(m.severity),
                cell(&m.path),
                cell(&opt(&m.declared)),
                cell(&opt(&m.detected)),
                m.size,
                if m.deleted { "yes" } else { "no" },
                cell(&m.reasons.join("; "))
            );
        }
    }
    let _ = writeln!(o);

    // ---- Anomalies ------------------------------------------------------------
    let _ = writeln!(o, "## Anomalies");
    let _ = writeln!(o);
    if r.anomalies.is_empty() {
        let _ = writeln!(o, "None.");
    } else {
        for a in &r.anomalies {
            let _ = writeln!(o, "- `{}` **{}** — {}", a.kind, cell(&a.path), cell(&a.detail));
        }
    }
    let _ = writeln!(o);

    // ---- File details -----------------------------------------------------------
    let _ = writeln!(o, "## File details");
    let _ = writeln!(o);
    if r.files.is_empty() {
        let _ = writeln!(o, "None.");
    } else {
        let _ = writeln!(
            o,
            "| Path | Status | Size | SHA-256 | Modified (ns) | Dirent @ | Extents |"
        );
        let _ = writeln!(o, "|---|---|---|---|---|---|---|");
        for f in &r.files {
            let extents = f
                .allocated_ranges
                .iter()
                .map(|&(off, len)| format!("{off:#x}+{len}"))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                o,
                "| {} | {}{} | {} | {} | {} | {:#x} | {} |",
                cell(&f.path),
                f.status,
                if f.recovery.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", f.recovery)
                },
                f.size,
                f.sha256.as_deref().unwrap_or("—"),
                ns(f.modified_ns),
                f.disk_offset,
                cell(&extents),
            );
        }
    }
    let _ = writeln!(o);

    // ---- Notes -------------------------------------------------------------------
    if !r.examiner_notes.is_empty() {
        let _ = writeln!(o, "## Examiner notes");
        let _ = writeln!(o);
        let _ = writeln!(o, "{}", r.examiner_notes);
    }
    o
}
