//! A purpose-built, **lenient** extractor for AFF4 `information.turtle`
//! manifests.
//!
//! This is *not* an RDF/Turtle parser — full RDF (blank nodes, collections,
//! datatype coercion, prefix resolution) is out of scope for this crate.
//! What an AFF4-L examiner actually needs from the manifest is small:
//!
//! * the subject IRIs that describe members (the evidence-file ARNs), and
//! * the `aff4:hash` objects attached to each subject — hash URNs of the
//!   form `<aff4:sha256=deadbeef…>` (algorithm spelling and hex encoding
//!   tolerated liberally), or literal objects with a `^^<algo>` datatype.
//!
//! The extractor is **total**: it never fails. Malformed input degrades to
//! partial results plus human-readable `notes` so the caller can report an
//! honest degraded state rather than guessing.

use std::collections::HashSet;

/// Hash algorithms recognised in AFF4 hash URNs.
///
/// Only [`HashAlgorithm::Sha256`] is verified today (see
/// [`crate::Aff4Container::verify`]); the rest are parsed and reported
/// honestly as unverifiable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// `md5` — 32 hex chars.
    Md5,
    /// `sha1` — 40 hex chars.
    Sha1,
    /// `sha256` — 64 hex chars; the AFF4-L default.
    Sha256,
    /// `sha512` — 128 hex chars.
    Sha512,
    /// Anything else seen in a hash URN (kept verbatim).
    Other(String),
}

impl HashAlgorithm {
    /// Whether [`crate::Aff4Container::verify`] can recompute this digest.
    pub fn supported(&self) -> bool {
        matches!(self, HashAlgorithm::Sha256)
    }

    /// Canonical lowercase algorithm name.
    pub fn name(&self) -> &str {
        match self {
            HashAlgorithm::Md5 => "md5",
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha512 => "sha512",
            HashAlgorithm::Other(s) => s.as_str(),
        }
    }

    /// Expected lowercase-hex digest length, when the algorithm is known.
    fn hex_len(&self) -> Option<usize> {
        match self {
            HashAlgorithm::Md5 => Some(32),
            HashAlgorithm::Sha1 => Some(40),
            HashAlgorithm::Sha256 => Some(64),
            HashAlgorithm::Sha512 => Some(128),
            HashAlgorithm::Other(_) => None,
        }
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// One hash value recorded for a subject in the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredHash {
    /// Parsed algorithm.
    pub algorithm: HashAlgorithm,
    /// The digest value, lowercase hex when it decoded cleanly.
    pub value: String,
    /// The verbatim manifest token (`aff4:sha256=…`, `"…"^^aff4:sha1`, …).
    pub urn: String,
    /// `true` when the captured value does not look like a well-formed hex
    /// digest for the algorithm (truncated line, base64 encoding, …).
    /// Such hashes are reported as [`crate::NotVerifiable::MalformedHash`]
    /// rather than allowed to masquerade as a [`crate::Verification::Mismatch`].
    pub malformed: bool,
}

/// A manifest subject (evidence-file ARN or other resource) together with
/// every hash the manifest recorded for it.
#[derive(Debug, Clone)]
pub struct ManifestSubject {
    /// Subject IRI text, verbatim (still percent-encoded).
    pub subject: String,
    /// Hashes extracted for this subject (deduplicated).
    pub hashes: Vec<StoredHash>,
}

/// Outcome of [`extract_manifest`].
#[derive(Debug, Default)]
pub(crate) struct ManifestParse {
    /// Subjects that carried at least recognisable structure.
    pub subjects: Vec<ManifestSubject>,
    /// Statements seen (terminated by `.`, plus a trailing unterminated one).
    pub statements: usize,
    /// Lenient-parse observations worth surfacing (`"unterminated IRI"`, …).
    pub notes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tokeniser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    /// `<iri>` — contents only.
    Iri(String),
    /// `"lit"` / `'lit'` / `"""lit"""` — contents only.
    Lit(String),
    /// Bare word: prefixed name, `a`, number, `^^…`, `[`, `]`, …
    Word(String),
    /// `;` — next word is a new predicate for the same subject.
    Semi,
    /// `,` — next object for the current predicate.
    Comma,
}

fn is_word_break(c: u8) -> bool {
    c.is_ascii_whitespace()
        || matches!(
            c,
            b';' | b',' | b'<' | b'>' | b'"' | b'\'' | b'(' | b')' | b'[' | b']' | b'#'
        )
}

/// Scan `text` into per-statement token vectors. Never fails; oddities land
/// in `notes`.
fn tokenize(text: &str) -> (Vec<Vec<Tok>>, Vec<String>) {
    let b = text.as_bytes();
    let mut stmts: Vec<Vec<Tok>> = Vec::new();
    let mut cur: Vec<Tok> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut i = 0usize;

    while i < b.len() {
        let c = b[i];
        match c {
            // Comment — runs to end of line (outside IRI/literal, which are
            // consumed atomically by their own arms).
            b'#' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            _ if c.is_ascii_whitespace() => i += 1,
            b'<' => {
                let start = i + 1;
                i += 1;
                let mut closed = false;
                while i < b.len() {
                    if b[i] == b'>' {
                        closed = true;
                        break;
                    }
                    if b[i] == b'\n' || b[i] == b'<' {
                        break; // unterminated / nested — resync
                    }
                    i += 1;
                }
                if closed {
                    cur.push(Tok::Iri(text[start..i].to_string()));
                    i += 1;
                } else {
                    notes.push("unterminated or malformed IRI".into());
                }
            }
            q @ (b'"' | b'\'') => {
                let triple = b.get(i + 1) == Some(&q) && b.get(i + 2) == Some(&q);
                let start = i + if triple { 3 } else { 1 };
                let mut j = start;
                let mut closed = false;
                while j < b.len() {
                    if b[j] == b'\\' {
                        j += 2; // skip escape pair
                        continue;
                    }
                    if triple {
                        if b[j] == q && b.get(j + 1) == Some(&q) && b.get(j + 2) == Some(&q) {
                            cur.push(Tok::Lit(text[start..j].to_string()));
                            j += 3;
                            closed = true;
                            break;
                        }
                    } else if b[j] == q {
                        cur.push(Tok::Lit(text[start..j].to_string()));
                        j += 1;
                        closed = true;
                        break;
                    }
                    j += 1;
                }
                if !closed {
                    notes.push("unterminated string literal".into());
                    cur.push(Tok::Lit(text[start.min(b.len())..].to_string()));
                    j = b.len();
                }
                i = j;
            }
            b';' => {
                cur.push(Tok::Semi);
                i += 1;
            }
            b',' => {
                cur.push(Tok::Comma);
                i += 1;
            }
            _ => {
                // Bare word — or a stray delimiter we don't model. Interior
                // `.` is a word char (decimals, `version.txt`); a `.`
                // followed by whitespace/EOF/comment is the statement
                // terminator, since Turtle names cannot end in one.
                let start = i;
                loop {
                    while i < b.len() && !is_word_break(b[i]) && b[i] != b'.' {
                        i += 1;
                    }
                    if i < b.len()
                        && b[i] == b'.'
                        && i + 1 < b.len()
                        && !is_word_break(b[i + 1])
                        && b[i + 1] != b'.'
                    {
                        i += 1; // interior dot — keep scanning the word
                        continue;
                    }
                    break;
                }
                if start < i {
                    cur.push(Tok::Word(text[start..i].to_string()));
                }
                if i < b.len() && b[i] == b'.' {
                    // Terminating dot (possibly glued to the word).
                    stmts.push(std::mem::take(&mut cur));
                    i += 1;
                } else if i == start {
                    // Lone stray delimiter (`>`, `(`, `)`, `[`, `]`) — keep
                    // it as a word token so the statement processor can see
                    // the structure, and always advance.
                    cur.push(Tok::Word(text[i..i + 1].to_string()));
                    i += 1;
                }
            }
        }
    }
    if !cur.is_empty() {
        notes.push("trailing statement without `.` terminator".into());
        stmts.push(cur);
    }
    (stmts, notes)
}

// ---------------------------------------------------------------------------
// Hash URN / literal parsing
// ---------------------------------------------------------------------------

fn algo_of(text: &str) -> Option<HashAlgorithm> {
    let t: String = text
        .to_lowercase()
        .chars()
        .filter(|c| *c != '-' && *c != '_')
        .collect();
    if t.contains("sha512") {
        Some(HashAlgorithm::Sha512)
    } else if t.contains("sha256") {
        Some(HashAlgorithm::Sha256)
    } else if t.contains("sha1") {
        Some(HashAlgorithm::Sha1)
    } else if t.contains("md5") {
        Some(HashAlgorithm::Md5)
    } else {
        None
    }
}

/// Tail of `text` after the last `=` or `:` that is all hex, or the whole
/// text when it is itself hex. Minimum 8 hex chars to keep noise out.
fn hex_tail(text: &str) -> Option<String> {
    let candidate = |s: &str| -> Option<String> {
        let s = s.trim();
        if s.len() >= 8 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            Some(s.to_lowercase())
        } else {
            None
        }
    };
    for sep in ['=', ':'] {
        if let Some(pos) = text.rfind(sep) {
            if let Some(h) = candidate(&text[pos + 1..]) {
                return Some(h);
            }
        }
    }
    candidate(text)
}

/// Build a [`StoredHash`] from an object token (`aff4:sha256=hex`,
/// `urn:sha1:hex`, `deadbeef…`) with an optional datatype hint
/// (`aff4:sha256` from `^^aff4:sha256`).
fn parse_hash(value: &str, hint: Option<&str>) -> Option<StoredHash> {
    let algo = hint
        .and_then(algo_of)
        .or_else(|| algo_of(value))
        .unwrap_or_else(|| HashAlgorithm::Other("unknown".into()));
    if matches!(algo, HashAlgorithm::Other(_)) && hint.is_none() {
        return None; // no recognisable algorithm anywhere — not a hash
    }
    let hex = match hex_tail(value) {
        Some(h) => h,
        None => {
            return Some(StoredHash {
                algorithm: algo,
                value: value.trim().to_string(),
                urn: value.to_string(),
                malformed: true,
            });
        }
    };
    let malformed = algo.hex_len().map(|want| hex.len() != want).unwrap_or(false);
    Some(StoredHash {
        algorithm: algo,
        value: hex,
        urn: value.to_string(),
        malformed,
    })
}

/// `true` when a predicate token names a hash property (`aff4:hash`,
/// `<http://aff4.org/Schema#hash>`, …).
fn is_hash_predicate(text: &str) -> bool {
    text.trim_end().to_lowercase().ends_with("hash")
}

// ---------------------------------------------------------------------------
// Statement processing
// ---------------------------------------------------------------------------

fn process(tokens: &[Tok], parse: &mut ManifestParse) {
    let subject = match tokens.first() {
        Some(Tok::Iri(s)) | Some(Tok::Word(s)) => s.clone(),
        _ => return, // literal-first or empty statement — nothing to anchor
    };
    let mut hashes: Vec<StoredHash> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut expect_pred = true;
    let mut pred_is_hash = false;
    let mut pending_datatype = false;
    let mut last_obj: Option<String> = None;
    // A hash-predicate object that failed to parse; reported only if no
    // `^^datatype` handler manages to salvage it.
    let mut failed_hash_obj: Option<String> = None;

    let mut record = |h: StoredHash,
                      hashes: &mut Vec<StoredHash>,
                      failed: &mut Option<String>| {
        if seen.insert((h.algorithm.name().to_string(), h.value.clone())) {
            hashes.push(h);
        }
        *failed = None;
    };

    for t in &tokens[1..] {
        match t {
            Tok::Semi => {
                expect_pred = true;
                pred_is_hash = false;
                pending_datatype = false;
                last_obj = None;
                if let Some(s) = failed_hash_obj.take() {
                    parse.notes.push(format!("hash predicate object not recognised: {s:?}"));
                }
            }
            Tok::Comma => {
                // Another object for the same predicate.
                pending_datatype = false;
                last_obj = None;
            }
            Tok::Word(w) if w.starts_with("^^") && !expect_pred => {
                // Datatype marker: `^^aff4:sha256` inline, or bare `^^` with
                // the datatype as the next token.
                if w.len() > 2 {
                    if pred_is_hash {
                        if let Some(lit) = &last_obj {
                            if let Some(h) = parse_hash(lit, Some(&w[2..])) {
                                record(h, &mut hashes, &mut failed_hash_obj);
                            }
                        }
                    }
                } else {
                    pending_datatype = true;
                }
            }
            Tok::Iri(s) | Tok::Word(s) | Tok::Lit(s) => {
                if pending_datatype {
                    if pred_is_hash {
                        if let Some(lit) = &last_obj {
                            if let Some(h) = parse_hash(lit, Some(s)) {
                                record(h, &mut hashes, &mut failed_hash_obj);
                            }
                        }
                    }
                    pending_datatype = false;
                    continue;
                }
                if expect_pred {
                    pred_is_hash = is_hash_predicate(s);
                    expect_pred = false;
                    continue;
                }
                // Object position. Record when the predicate is a hash
                // property — and, leniently, whenever the token itself
                // parses as a hash URN (covers encodings where the hash URN
                // appears under a generic predicate).
                match parse_hash(s, None) {
                    Some(h) => record(h, &mut hashes, &mut failed_hash_obj),
                    None => {
                        if pred_is_hash {
                            failed_hash_obj = Some(s.clone());
                        }
                    }
                }
                last_obj = Some(s.clone());
            }
        }
    }
    if let Some(s) = failed_hash_obj.take() {
        parse.notes.push(format!("hash predicate object not recognised: {s:?}"));
    }
    parse.subjects.push(ManifestSubject { subject, hashes });
}

/// Extract subjects and their hashes from `information.turtle` text.
/// Never fails — partial results plus `notes` on malformed input.
pub(crate) fn extract_manifest(text: &str) -> ManifestParse {
    let (stmts, notes) = tokenize(text);
    let mut parse = ManifestParse {
        subjects: Vec::new(),
        statements: stmts.len(),
        notes,
    };
    for s in &stmts {
        process(s, &mut parse);
    }
    parse
}

// ---------------------------------------------------------------------------
// Subject → member matching helpers
// ---------------------------------------------------------------------------

/// Percent-decode an IRI (`%41` → `A`); invalid escapes pass through.
/// Output is lossy UTF-8.
pub(crate) fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    let hex = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `true` when manifest `subject` plausibly refers to zip member `name`:
/// exact match after percent-decoding, or the subject ends with
/// `/`-joined (or `:`-joined) member name — `aff4://<uuid>/<member>`
/// being the canonical AFF4 form.
pub(crate) fn subject_matches(subject: &str, member_name: &str) -> bool {
    let dec = pct_decode(subject);
    let dec = dec.trim_end_matches('/');
    if dec == member_name {
        return true;
    }
    dec.ends_with(&format!("/{member_name}"))
        || dec.ends_with(&format!(":{member_name}"))
        || dec.ends_with(&format!("#{member_name}"))
}
