//! Hand-rolled JSON — zero dependencies, compact deterministic output.
//!
//! `Json` preserves object key order (reports read top-down: summary →
//! census → deleted → mismatches → anomalies → files). All strings pass
//! through [`escape`], so hostile on-disk names can't break the document.

/// JSON value with insertion-ordered object keys.
#[derive(Debug, Clone)]
pub enum Json {
    /// `null`.
    Null,
    /// `true`/`false`.
    Bool(bool),
    /// Integer or unsigned number (no floats anywhere in reports).
    Num(u64),
    /// Signed number (unix nanos can be negative pre-1970).
    Int(i64),
    /// String — escaped on emit.
    Str(String),
    /// Array.
    Arr(Vec<Json>),
    /// Object — key order preserved.
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// `Json::Str` from anything stringly.
    pub fn s(v: impl Into<String>) -> Json {
        Json::Str(v.into())
    }

    /// `Option<T>` → `Json` or `Null`.
    pub fn opt<T>(v: Option<T>, f: impl FnOnce(T) -> Json) -> Json {
        v.map(f).unwrap_or(Json::Null)
    }

    /// Serialize compactly.
    pub fn to_string(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    /// Serialize with 2-space indentation.
    pub fn to_string_pretty(&self) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, 0);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => out.push_str(&n.to_string()),
            Json::Int(n) => out.push_str(&n.to_string()),
            Json::Str(s) => {
                out.push('"');
                out.push_str(&escape(s));
                out.push('"');
            }
            Json::Arr(items) => {
                out.push('[');
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    it.write(out);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push('"');
                    out.push_str(&escape(k));
                    out.push_str("\":");
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    fn write_pretty(&self, out: &mut String, depth: usize) {
        let pad = |out: &mut String, d: usize| {
            for _ in 0..d {
                out.push_str("  ");
            }
        };
        match self {
            Json::Arr(items) if !items.is_empty() => {
                out.push_str("[\n");
                for (i, it) in items.iter().enumerate() {
                    pad(out, depth + 1);
                    it.write_pretty(out, depth + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                pad(out, depth);
                out.push(']');
            }
            Json::Obj(fields) if !fields.is_empty() => {
                out.push_str("{\n");
                for (i, (k, v)) in fields.iter().enumerate() {
                    pad(out, depth + 1);
                    out.push('"');
                    out.push_str(&escape(k));
                    out.push_str("\": ");
                    v.write_pretty(out, depth + 1);
                    if i + 1 < fields.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                pad(out, depth);
                out.push('}');
            }
            _ => self.write(out),
        }
    }
}

/// Escape a string for JSON per RFC 8259 (control chars, `"`, `\`; DEL and
/// other non-ASCII pass through — JSON is UTF-8).
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping() {
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
        assert_eq!(escape("\x01\x1f"), "\\u0001\\u001f");
        assert_eq!(escape("héllo"), "héllo");
    }

    #[test]
    fn object_order_preserved() {
        let j = Json::Obj(vec![
            ("b".into(), Json::Num(1)),
            ("a".into(), Json::Arr(vec![Json::Bool(true)])),
        ]);
        assert_eq!(j.to_string(), "{\"b\":1,\"a\":[true]}");
    }

    #[test]
    fn pretty_prints() {
        let j = Json::Obj(vec![("k".into(), Json::Arr(vec![Json::Num(1), Json::Num(2)]))]);
        let p = j.to_string_pretty();
        assert!(p.contains("\n  \"k\": [\n    1,\n    2\n  ]\n"));
    }
}
