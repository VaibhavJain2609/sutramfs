//! `Report` → self-contained HTML: inline CSS, zero JS, zero external
//! references — safe to attach to a case file or open off a write-blocked
//! share. **Every** interpolated value passes [`esc`] — on-disk names are
//! hostile input.

use std::fmt::Write as _;

use crate::report::{severity_label, Report};

/// HTML-escape `&<>"'`.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn opt(v: &Option<String>) -> String {
    v.as_deref().map(esc).unwrap_or_else(|| "—".into())
}

fn ns(v: Option<i64>) -> String {
    v.map(|n| n.to_string()).unwrap_or_else(|| "—".into())
}

const CSS: &str = "\
body{font-family:system-ui,-apple-system,sans-serif;margin:2em;color:#1a1a1a;max-width:1100px}\
h1{font-size:1.5em;border-bottom:2px solid #333;padding-bottom:.3em}\
h2{font-size:1.15em;margin-top:1.6em;color:#222}\
table{border-collapse:collapse;width:100%;font-size:.9em}\
th,td{border:1px solid #ccc;padding:.3em .6em;text-align:left;vertical-align:top}\
th{background:#f0f0f0}\
tr:nth-child(even){background:#fafafa}\
.sev-high{background:#fdd;color:#900;font-weight:700}\
.sev-suspicious{background:#ffe9c2}\
.mono{font-family:ui-monospace,monospace;font-size:.85em;word-break:break-all}\
.summary{color:#444}\
ul.anomalies{list-style:none;padding:0}\
ul.anomalies li{margin:.25em 0;padding:.3em .6em;background:#f6f6f6;border-left:3px solid #999}\
ul.anomalies li.orphan{border-color:#07c}\
ul.anomalies li.suspicious-meta{border-color:#c80}\
ul.anomalies li.walk-error{border-color:#c00}";

/// Render the full report as a standalone HTML document.
pub fn render(r: &Report) -> String {
    let mut o = String::with_capacity(32 * 1024);
    let _ = writeln!(
        o,
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\
         \n<title>{}</title>\n<style>{CSS}</style>\n</head>\n<body>",
        esc(&r.title)
    );
    let _ = writeln!(o, "<h1>{}</h1>", esc(&r.title));
    let _ = writeln!(
        o,
        "<p class=\"summary\">Tool: <b>{}</b> &middot; generated (unix s): {}</p>",
        esc(&r.tool),
        r.generated_unix_secs
    );
    if !r.image_desc.is_empty() {
        let _ = writeln!(o, "<p class=\"summary\">Image: {}</p>", esc(&r.image_desc));
    }

    // ---- Volume ---------------------------------------------------------
    let v = &r.volume;
    let _ = writeln!(o, "<h2>Volume</h2>\n<table>");
    for (k, val) in [
        ("fs_type", esc(&v.fs_type)),
        ("label", opt(&v.label)),
        ("uuid", opt(&v.uuid)),
        ("block_size", v.block_size.to_string()),
        ("total_blocks", v.total_blocks.to_string()),
        (
            "free_blocks",
            v.free_blocks.map(|n| n.to_string()).unwrap_or("—".into()),
        ),
        ("image_size", v.image_size.to_string()),
    ] {
        let _ = writeln!(o, "<tr><th>{k}</th><td>{val}</td></tr>");
    }
    for (k, val) in &v.meta {
        let _ = writeln!(o, "<tr><th>{}</th><td>{}</td></tr>", esc(k), esc(val));
    }
    let _ = writeln!(o, "</table>");

    // ---- Census -----------------------------------------------------------
    let c = &r.census;
    let _ = writeln!(o, "<h2>Entry census</h2>\n<table>");
    let _ = writeln!(o, "<tr><th>Metric</th><th>Count</th></tr>");
    for (k, val) in [
        ("total entries", c.total_entries),
        ("live", c.live),
        ("deleted", c.deleted),
        ("files", c.files),
        ("directories", c.directories),
        ("symlinks", c.symlinks),
        ("other", c.other),
        ("recovery: intact", c.recovery_intact),
        ("recovery: partial", c.recovery_partial),
        ("recovery: unrecoverable", c.recovery_unrecoverable),
        ("recovery: unknown", c.recovery_unknown),
        ("walk errors", c.walk_errors),
    ] {
        let _ = writeln!(o, "<tr><td>{k}</td><td>{val}</td></tr>");
    }
    let _ = writeln!(o, "<tr><td>live bytes</td><td>{}</td></tr>", c.live_bytes);
    let _ = writeln!(
        o,
        "<tr><td>deleted bytes</td><td>{}</td></tr>",
        c.deleted_bytes
    );
    let _ = writeln!(o, "</table>");

    // ---- Deleted recovery ---------------------------------------------------
    let d = &r.deleted;
    let _ = writeln!(
        o,
        "<h2>Deleted recovery</h2>\n<p class=\"summary\">{} deleted entries — \
         intact {}, partial {}, lost {}; {}/{} bytes recoverable.</p>",
        d.rows.len(),
        d.intact,
        d.partial,
        d.lost,
        d.recovered_bytes,
        d.total_bytes
    );
    if !d.rows.is_empty() {
        let _ = writeln!(
            o,
            "<table>\n<tr><th>Path</th><th>Size</th><th>Recovery</th>\
             <th>Recovered B</th><th>Total B</th><th>Dirent @</th></tr>"
        );
        for row in &d.rows {
            let _ = writeln!(
                o,
                "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td><td>{}</td>\
                 <td>{}</td><td>{:#x}</td></tr>",
                esc(&row.path),
                row.size,
                row.recovery,
                row.recovered_bytes,
                row.total_bytes,
                row.disk_offset
            );
        }
        let _ = writeln!(o, "</table>");
    }

    // ---- Magic mismatches ------------------------------------------------------
    let _ = writeln!(o, "<h2>Extension/content mismatches</h2>");
    if r.magic_mismatches.is_empty() {
        let _ = writeln!(o, "<p>None.</p>");
    } else {
        let _ = writeln!(
            o,
            "<table>\n<tr><th>Severity</th><th>Path</th><th>Declared</th>\
             <th>Detected</th><th>Size</th><th>Deleted</th><th>Reasons</th></tr>"
        );
        for m in &r.magic_mismatches {
            let sev = severity_label(m.severity);
            let _ = writeln!(
                o,
                "<tr><td class=\"sev-{sev}\">{sev}</td><td class=\"mono\">{}</td>\
                 <td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&m.path),
                opt(&m.declared),
                opt(&m.detected),
                m.size,
                if m.deleted { "yes" } else { "no" },
                esc(&m.reasons.join("; "))
            );
        }
        let _ = writeln!(o, "</table>");
    }

    // ---- Anomalies ------------------------------------------------------------------
    let _ = writeln!(o, "<h2>Anomalies</h2>");
    if r.anomalies.is_empty() {
        let _ = writeln!(o, "<p>None.</p>");
    } else {
        let _ = writeln!(o, "<ul class=\"anomalies\">");
        for a in &r.anomalies {
            let _ = writeln!(
                o,
                "<li class=\"{}\"><code>{}</code> <b>{}</b> — {}</li>",
                esc(&a.kind),
                esc(&a.kind),
                esc(&a.path),
                esc(&a.detail)
            );
        }
        let _ = writeln!(o, "</ul>");
    }

    // ---- File details -------------------------------------------------------------------
    let _ = writeln!(o, "<h2>File details</h2>");
    if r.files.is_empty() {
        let _ = writeln!(o, "<p>None.</p>");
    } else {
        let _ = writeln!(
            o,
            "<table>\n<tr><th>Path</th><th>Status</th><th>Size</th><th>SHA-256</th>\
             <th>Modified (ns)</th><th>Dirent @</th><th>Extents</th></tr>"
        );
        for f in &r.files {
            let extents = f
                .allocated_ranges
                .iter()
                .map(|&(off, len)| format!("{off:#x}+{len}"))
                .collect::<Vec<_>>()
                .join(", ");
            let status = if f.recovery.is_empty() {
                esc(&f.status)
            } else {
                format!("{} ({})", esc(&f.status), esc(&f.recovery))
            };
            let _ = writeln!(
                o,
                "<tr><td class=\"mono\">{}</td><td>{}</td><td>{}</td>\
                 <td class=\"mono\">{}</td><td>{}</td><td>{:#x}</td>\
                 <td class=\"mono\">{}</td></tr>",
                esc(&f.path),
                status,
                f.size,
                f.sha256.as_deref().map(esc).unwrap_or("—".into()),
                ns(f.modified_ns),
                f.disk_offset,
                esc(&extents),
            );
        }
        let _ = writeln!(o, "</table>");
    }

    // ---- Notes ------------------------------------------------------------------------------
    if !r.examiner_notes.is_empty() {
        let _ = writeln!(o, "<h2>Examiner notes</h2>\n<p>{}</p>", esc(&r.examiner_notes));
    }
    let _ = writeln!(o, "</body>\n</html>");
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_covers_all_specials() {
        assert_eq!(
            esc("<a href=\"x\">&'</a>"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;"
        );
    }
}
