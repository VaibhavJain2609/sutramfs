//! Binary-safe keyword search over entry contents.
//!
//! [`search`] streams every `EntryKind::File` through
//! [`FileSystem::read_file`] in bounded chunks and yields
//! [`SearchHit`]s — each carrying the file-relative offset and ±
//! [`SearchOptions::context`] bytes of context (default 32 B each side).
//!
//! Pattern kinds ([`Pattern`]):
//!
//! * `literal` — exact byte sequence;
//! * `case_insensitive` — ASCII case-folded literal;
//! * `hex` — hex byte string with optional `??` wildcard bytes
//!   (`"de ad ?? ef"`), for binary needles and UTF-16 text
//!   (`"6f 00 6f 00"` = "oo" as UTF-16LE).
//!
//! Directories and symlinks are skipped (no byte stream). Deleted files
//! *are* searched by default — their recoverable extents are often the
//! evidence — controlled by [`SearchOptions::include_deleted`].
//! Per-entry reads are capped (`max_bytes_per_entry`, default 64 MiB)
//! and hit counts are bounded (`max_hits_per_entry`, `max_hits_total`),
//! so a hostile image cannot exhaust memory.
//!
//! Walk errors and per-file read failures surface as `Err` items in the
//! stream — the search continues (lenient contract), matching how the
//! parsers report corruption.
//!
//! Matching is a straightforward substring scan — no regex, no DFA.
//! With bounded reads and small pattern counts that is the honest
//! trade-off; bring a real grep engine if you need one.

use std::collections::VecDeque;
use std::io::Read;

use sutram_fs::{EntryKind, FileSystem, FsEntry, FsError, Result};

/// Read chunk size for the search stream.
const CHUNK: usize = 256 << 10;

/// One needle to search for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// Exact bytes.
    Literal(Vec<u8>),
    /// ASCII-case-insensitive bytes (stored lowercased).
    CaseInsensitive(Vec<u8>),
    /// Hex pattern; `None` = wildcard byte (`??`).
    Hex(Vec<Option<u8>>),
}

impl Pattern {
    /// Literal pattern from a string.
    pub fn literal(s: impl AsRef<str>) -> Pattern {
        Pattern::Literal(s.as_ref().as_bytes().to_vec())
    }

    /// Literal pattern from raw bytes.
    pub fn literal_bytes(b: impl AsRef<[u8]>) -> Pattern {
        Pattern::Literal(b.as_ref().to_vec())
    }

    /// ASCII case-insensitive literal (`"JPEG"` matches "jpeg", "Jpeg").
    pub fn case_insensitive(s: impl AsRef<str>) -> Pattern {
        Pattern::CaseInsensitive(s.as_ref().as_bytes().to_ascii_lowercase())
    }

    /// Hex pattern: `"de ad be ef"`, `"deadbeef"`, wildcards `??`
    /// (`"MZ ?? ?? ?? pe"`). Whitespace between bytes is ignored.
    /// An odd number of nibbles or a non-hex character is an error.
    pub fn hex(s: impl AsRef<str>) -> std::result::Result<Pattern, String> {
        let s = s.as_ref();
        let hexits: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        if hexits.len() % 2 != 0 {
            return Err(format!("hex pattern '{s}' has an odd nibble count"));
        }
        let mut bytes = Vec::with_capacity(hexits.len() / 2);
        let chars: Vec<char> = hexits.chars().collect();
        for pair in chars.chunks(2) {
            if pair == ['?', '?'] {
                bytes.push(None);
                continue;
            }
            let byte: String = pair.iter().collect();
            let v = u8::from_str_radix(&byte, 16)
                .map_err(|_| format!("hex pattern '{s}': invalid byte '{byte}'"))?;
            bytes.push(Some(v));
        }
        if bytes.is_empty() {
            return Err("hex pattern is empty".to_string());
        }
        Ok(Pattern::Hex(bytes))
    }
}

/// Compiled matcher for one [`Pattern`].
struct Needle {
    /// `None` entries are wildcards (hex patterns only).
    bytes: Vec<Option<u8>>,
    /// ASCII-fold matching (literal-CI).
    ci: bool,
    /// Display label for hits/reports.
    label: String,
}

impl Needle {
    fn len(&self) -> usize {
        self.bytes.len()
    }

    /// `true` when `hay[0..len]` matches the needle.
    fn matches_at(&self, hay: &[u8]) -> bool {
        for (i, want) in self.bytes.iter().enumerate() {
            let Some(&w) = want.as_ref() else { continue };
            let mut h = hay[i];
            if self.ci {
                h = h.to_ascii_lowercase();
            }
            if h != w {
                return false;
            }
        }
        true
    }
}

fn compile(p: &Pattern) -> Needle {
    match p {
        Pattern::Literal(b) => Needle {
            bytes: b.iter().map(|&x| Some(x)).collect(),
            ci: false,
            label: format!("{:?}", String::from_utf8_lossy(b)),
        },
        Pattern::CaseInsensitive(b) => Needle {
            bytes: b.iter().map(|&x| Some(x)).collect(),
            ci: true,
            label: format!("ci:{:?}", String::from_utf8_lossy(b)),
        },
        Pattern::Hex(b) => {
            let label = b
                .iter()
                .map(|x| x.map(|v| format!("{v:02x}")).unwrap_or_else(|| "??".into()))
                .collect::<Vec<_>>()
                .join(" ");
            Needle {
                bytes: b.clone(),
                ci: false,
                label: format!("hex:{label}"),
            }
        }
    }
}

/// Knobs for [`search`].
#[derive(Debug, Clone)]
pub struct SearchOptions {
    /// Maximum bytes read per entry. Default 64 MiB — keyword search is
    /// for triage; hash/everything-else paths exist for full reads.
    pub max_bytes_per_entry: u64,
    /// Context bytes around each hit, each side. Default 32.
    pub context: usize,
    /// Search deleted entries' recoverable extents. Default `true`.
    pub include_deleted: bool,
    /// Cap on hits per entry. Default 1024.
    pub max_hits_per_entry: usize,
    /// Cap on hits across the whole search. Default 100_000.
    pub max_hits_total: usize,
}

impl Default for SearchOptions {
    fn default() -> Self {
        SearchOptions {
            max_bytes_per_entry: 64 << 20,
            context: 32,
            include_deleted: true,
            max_hits_per_entry: 1024,
            max_hits_total: 100_000,
        }
    }
}

/// One match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    /// Path of the entry the hit was found in.
    pub entry_path: String,
    /// File-relative byte offset of the match start.
    pub offset: u64,
    /// Which pattern matched (`literal`, `ci:`, `hex:` prefixed).
    pub pattern: String,
    /// ±`context` bytes around the match (bounded — up to
    /// `2 * context + match_len` bytes; shorter at file/chunk edges).
    pub context: Vec<u8>,
    /// File-relative offset where `context` begins.
    pub context_offset: u64,
    /// The entry's stable identifier.
    pub entry_id: u64,
}

/// Streaming search iterator — yields `Ok(SearchHit)` per match,
/// `Err(FsError)` for walk/read failures (search continues).
pub struct SearchHits<'a> {
    fs: &'a dyn FileSystem,
    walk: Box<dyn Iterator<Item = Result<FsEntry>> + Send + 'a>,
    needles: Vec<Needle>,
    opts: SearchOptions,
    /// Deferred hits ready to yield.
    pending: VecDeque<SearchHit>,
    /// Current entry being scanned.
    cur: Option<FsEntry>,
    reader: Option<Box<dyn Read + Send>>,
    /// Bytes retained from the previous chunk (start offset = `buf_base`).
    carry: Vec<u8>,
    /// File offset of `carry[0]`.
    buf_base: u64,
    /// File offset scanned up to (match starts already reported below it).
    scanned_upto: u64,
    /// Bytes read so far for `cur`.
    read_so_far: u64,
    /// Hits emitted for `cur`.
    hits_this_entry: usize,
    hits_total: usize,
    /// Reader reached EOF for `cur`.
    eof: bool,
    /// Walk exhausted / global cap hit.
    done: bool,
}

impl<'a> SearchHits<'a> {
    fn new(fs: &'a dyn FileSystem, patterns: &[Pattern], opts: SearchOptions) -> Self {
        SearchHits {
            fs,
            walk: fs.walk(),
            needles: patterns.iter().map(compile).collect(),
            opts,
            pending: VecDeque::new(),
            cur: None,
            reader: None,
            carry: Vec::new(),
            buf_base: 0,
            scanned_upto: 0,
            read_so_far: 0,
            hits_this_entry: 0,
            hits_total: 0,
            eof: false,
            done: false,
        }
    }

    /// Advance the walk to the next searchable file.
    /// Returns `Ok(true)` when a reader is open, `Ok(false)` when the
    /// walk ended, `Err` records pass straight through to the caller.
    fn next_entry(&mut self) -> Option<Result<()>> {
        for item in self.walk.by_ref() {
            let entry = match item {
                Ok(e) => e,
                Err(e) => return Some(Err(e)),
            };
            // Only files carry a byte stream; dirs/symlinks skipped.
            if entry.kind != EntryKind::File {
                continue;
            }
            if entry.is_deleted() && !self.opts.include_deleted {
                continue;
            }
            match self.fs.read_file(&entry) {
                Ok(r) => {
                    self.cur = Some(entry);
                    self.reader = Some(r);
                    self.carry.clear();
                    self.buf_base = 0;
                    self.scanned_upto = 0;
                    self.read_so_far = 0;
                    self.hits_this_entry = 0;
                    self.eof = false;
                    return Some(Ok(()));
                }
                Err(e) => return Some(Err(e)),
            }
        }
        None
    }

    /// Read the next chunk of the current file into `carry`, then scan
    /// the newly-safe region. Returns `false` at EOF (after a final scan).
    fn pump(&mut self) -> Result<bool> {
        let cap = self.opts.max_bytes_per_entry;
        let want = (cap - self.read_so_far).min(CHUNK as u64) as usize;
        let mut chunk = vec![0u8; want];
        let n = match self.reader.as_mut() {
            Some(r) => r.read(&mut chunk).map_err(FsError::Io)?,
            None => return Ok(false),
        };
        if want == 0 || n == 0 {
            self.eof = true;
        }
        chunk.truncate(n);
        self.read_so_far = self.read_so_far.saturating_add(n as u64);

        // hay = carry ++ chunk; absolute base = buf_base.
        let mut hay = std::mem::take(&mut self.carry);
        hay.extend_from_slice(&chunk);
        let hay_end = self.buf_base + hay.len() as u64;

        // On a non-final chunk, keep `defer` bytes unsearched so a match
        // can't be missed across the boundary and every emitted hit has
        // its full trailing context.
        let overlap = self
            .needles
            .iter()
            .map(|n| n.len().saturating_sub(1))
            .max()
            .unwrap_or(0) as u64;
        let defer = overlap + self.opts.context as u64;
        let scan_end = if self.eof {
            hay_end
        } else {
            hay_end.saturating_sub(defer)
        };

        self.scan(&hay, scan_end);

        // Retain the unsearched tail as next chunk's carry. `scan_end`
        // can sit below `buf_base` when the buffer is smaller than
        // `defer` — then nothing was scanned and everything carries.
        let keep_from = if self.eof {
            hay.len()
        } else {
            scan_end.saturating_sub(self.buf_base) as usize
        };
        self.carry = hay[keep_from.min(hay.len())..].to_vec();
        self.buf_base = hay_end - self.carry.len() as u64;
        // `scan` may have advanced `scanned_upto` past a match end beyond
        // scan_end — never rewind it or the overlap region double-reports.
        self.scanned_upto = self.scanned_upto.max(self.buf_base);
        Ok(!self.eof)
    }

    /// Find matches with start offsets in `[scanned_upto, scan_end)` and
    /// queue their hits.
    fn scan(&mut self, hay: &[u8], scan_end: u64) {
        let Some(entry) = &self.cur else { return };
        let hay_end = self.buf_base + hay.len() as u64;
        let mut pos = self.scanned_upto.max(self.buf_base);
        while pos < scan_end {
            if self.hits_this_entry >= self.opts.max_hits_per_entry
                || self.hits_total >= self.opts.max_hits_total
            {
                return;
            }
            let rel = (pos - self.buf_base) as usize;
            let mut matched = false;
            for needle in &self.needles {
                let end = rel + needle.len();
                if end > hay.len() {
                    continue; // can't fully match within buffered data
                }
                if needle.matches_at(&hay[rel..end]) {
                    // context window clipped to buffered bytes
                    let ctx_lo = pos.saturating_sub(self.opts.context as u64).max(self.buf_base);
                    let ctx_hi = (pos + needle.len() as u64)
                        .saturating_add(self.opts.context as u64)
                        .min(hay_end);
                    let hit = SearchHit {
                        entry_path: entry.path.clone(),
                        offset: pos,
                        pattern: needle.label.clone(),
                        context: hay[(ctx_lo - self.buf_base) as usize
                            ..(ctx_hi - self.buf_base) as usize]
                            .to_vec(),
                        context_offset: ctx_lo,
                        entry_id: entry.entry_id,
                    };
                    self.pending.push_back(hit);
                    self.hits_this_entry += 1;
                    self.hits_total += 1;
                    pos += needle.len() as u64; // no overlapping matches
                    matched = true;
                    break;
                }
            }
            if !matched {
                pos += 1;
            }
        }
        self.scanned_upto = pos.max(self.scanned_upto);
    }
}

impl Iterator for SearchHits<'_> {
    type Item = Result<SearchHit>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(hit) = self.pending.pop_front() {
                return Some(Ok(hit));
            }
            if self.done {
                return None;
            }
            if self.reader.is_some() {
                match self.pump() {
                    Ok(true) => continue,
                    Ok(false) => {
                        self.reader = None;
                        self.cur = None;
                        continue;
                    }
                    Err(e) => {
                        self.reader = None;
                        self.cur = None;
                        return Some(Err(e));
                    }
                }
            }
            match self.next_entry() {
                Some(Ok(())) => continue,
                Some(Err(e)) => return Some(Err(e)),
                None => {
                    self.done = true;
                    return None;
                }
            }
        }
    }
}

/// Search every file of `fs` for `patterns`, streaming hits.
///
/// ```
/// use sutram_analyze::grep::{search, Pattern, SearchOptions};
/// # fn demo(fs: &dyn sutram_fs::FileSystem) {
/// let hits = search(fs, &[Pattern::literal("password"), Pattern::hex("de ad ?? ef").unwrap()],
///     &SearchOptions::default());
/// for h in hits {
///     match h {
///         Ok(hit) => println!("{} @ {:#x} [{}]", hit.entry_path, hit.offset, hit.pattern),
///         Err(e)  => eprintln!("search error: {e}"),
///     }
/// }
/// # }
/// ```
pub fn search<'a>(
    fs: &'a dyn FileSystem,
    patterns: &[Pattern],
    opts: &SearchOptions,
) -> SearchHits<'a> {
    SearchHits::new(fs, patterns, opts.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::sync::Arc;

    use sutram_fs::{FsEntryStatus, FsInfo, RecoveryState, Timestamps};
    use sutram_io::ByteSource;

    struct MemFs {
        entries: Vec<FsEntry>,
        data: HashMap<u64, Vec<u8>>,
        src: Arc<Vec<u8>>,
    }

    impl FileSystem for MemFs {
        fn info(&self) -> FsInfo {
            FsInfo {
                fs_type: "mem".into(),
                ..Default::default()
            }
        }
        fn source(&self) -> Arc<dyn ByteSource> {
            self.src.clone()
        }
        fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
            Box::new(self.entries.clone().into_iter().map(Ok))
        }
        fn read_file(&self, entry: &FsEntry) -> Result<Box<dyn Read + Send>> {
            match self.data.get(&entry.entry_id) {
                Some(d) => Ok(Box::new(Cursor::new(d.clone()))),
                None => Err(FsError::NotFound {
                    path: entry.path.clone(),
                }),
            }
        }
    }

    fn file_entry(id: u64, path: &str, deleted: bool) -> FsEntry {
        FsEntry {
            path: path.into(),
            name: path.rsplit('/').next().unwrap_or(path).into(),
            entry_id: id,
            kind: EntryKind::File,
            size: 0,
            disk_offset: 0,
            allocated_ranges: vec![],
            timestamps: Timestamps::default(),
            status: if deleted {
                FsEntryStatus::Deleted {
                    recovery: RecoveryState::Intact,
                }
            } else {
                FsEntryStatus::Live
            },
            meta: HashMap::new(),
            magic: None,
        }
    }

    fn fs_with(files: &[(&str, &[u8], bool)]) -> MemFs {
        let mut fs = MemFs {
            entries: vec![],
            data: HashMap::new(),
            src: Arc::new(Vec::new()),
        };
        for (i, (path, data, deleted)) in files.iter().enumerate() {
            let mut e = file_entry(i as u64 + 1, path, *deleted);
            e.size = data.len() as _;
            fs.data.insert(e.entry_id, data.to_vec());
            fs.entries.push(e);
        }
        fs
    }

    #[test]
    fn pattern_parse() {
        assert_eq!(
            Pattern::hex("de ad be ef").unwrap(),
            Pattern::Hex(vec![Some(0xde), Some(0xad), Some(0xbe), Some(0xef)])
        );
        assert_eq!(
            Pattern::hex("de ?? ef").unwrap(),
            Pattern::Hex(vec![Some(0xde), None, Some(0xef)])
        );
        assert!(Pattern::hex("abc").is_err()); // odd nibbles
        assert!(Pattern::hex("zz").is_err());
        assert!(Pattern::hex("").is_err());
    }

    #[test]
    fn literal_hits_with_context() {
        let mut content = vec![0u8; 100];
        content[50..58].copy_from_slice(b"password");
        let fs = fs_with(&[("/a.txt", &content, false)]);
        let hits: Vec<_> = search(
            &fs,
            &[Pattern::literal("password")],
            &SearchOptions::default(),
        )
        .collect::<Result<Vec<_>>>()
        .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 50);
        assert_eq!(hits[0].entry_path, "/a.txt");
        assert_eq!(hits[0].pattern, "\"password\"");
        // ±32 context → 32 before + 8 needle + 32 after = 72 bytes
        assert_eq!(hits[0].context.len(), 72);
        assert_eq!(hits[0].context_offset, 18);
        assert_eq!(&hits[0].context[32..40], b"password");
    }

    #[test]
    fn case_insensitive_and_hex() {
        // "..Jpeg.." + raw bytes DE AD BE EF DE AD
        let mut content = b"..Jpeg..".to_vec();
        content.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0xde, 0xad]);
        let fs = fs_with(&[("/b.bin", &content, false)]);
        let hits: Vec<_> = search(
            &fs,
            &[
                Pattern::case_insensitive("jpeg"),
                Pattern::hex("de ad").unwrap(),
            ],
            &SearchOptions::default(),
        )
        .collect::<Result<Vec<_>>>()
        .unwrap();
        assert_eq!(hits.len(), 3);
        assert_eq!(hits[0].offset, 2); // "Jpeg"
        assert_eq!(hits[1].offset, 8); // de ad
        assert_eq!(hits[2].offset, 12); // second de ad
        assert_eq!(hits[1].pattern, "hex:de ad");
        assert!(hits[0].pattern.starts_with("ci:"));
    }

    #[test]
    fn hex_wildcard() {
        let fs = fs_with(&[("/c.bin", b"\xde\x00\xad\xbe\xef", false)]);
        let hits: Vec<_> = search(
            &fs,
            &[Pattern::hex("de ?? ad").unwrap()],
            &SearchOptions::default(),
        )
        .collect::<Result<Vec<_>>>()
        .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 0);
    }

    #[test]
    fn match_across_chunk_boundary() {
        // Put the needle straddling the CHUNK boundary by exceeding it.
        // Cheap version: shrink CHUNK via a big file + small cap isn't
        // possible (cap is per entry). Instead verify the carry logic on
        // a file bigger than CHUNK would take 256KiB of content — fine.
        let mut content = vec![0u8; CHUNK + 10];
        let needle = b"BOUNDARY!";
        content[CHUNK - 4..CHUNK - 4 + needle.len()].copy_from_slice(needle);
        let fs = fs_with(&[("/big.bin", &content, false)]);
        let hits: Vec<_> = search(
            &fs,
            &[Pattern::literal("BOUNDARY!")],
            &SearchOptions::default(),
        )
        .collect::<Result<Vec<_>>>()
        .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, (CHUNK - 4) as u64);
    }

    #[test]
    fn skips_dirs_and_honours_deleted_flag() {
        let mut dir = file_entry(9, "/dir", false);
        dir.kind = EntryKind::Directory;
        let mut fs = fs_with(&[("/del.bin", b"needle here", true)]);
        fs.entries.insert(0, dir);
        let hits: Vec<_> = search(
            &fs,
            &[Pattern::literal("needle")],
            &SearchOptions::default(),
        )
        .collect::<Result<Vec<_>>>()
        .unwrap();
        assert_eq!(hits.len(), 1); // deleted file searched by default

        let hits: Vec<_> = search(
            &fs,
            &[Pattern::literal("needle")],
            &SearchOptions {
                include_deleted: false,
                ..Default::default()
            },
        )
        .collect::<Result<Vec<_>>>()
        .unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn caps_bound_output() {
        let content = b"aa aa aa aa aa".repeat(100);
        let fs = fs_with(&[("/rep.bin", &content, false)]);
        let hits: Vec<_> = search(
            &fs,
            &[Pattern::literal("aa")],
            &SearchOptions {
                max_hits_per_entry: 5,
                ..Default::default()
            },
        )
        .collect::<Result<Vec<_>>>()
        .unwrap();
        assert_eq!(hits.len(), 5);
    }

    #[test]
    fn read_cap_limits_scan() {
        let mut content = vec![0u8; 4096];
        content[4000..4006].copy_from_slice(b"needle");
        let fs = fs_with(&[("/cap.bin", &content, false)]);
        let hits: Vec<_> = search(
            &fs,
            &[Pattern::literal("needle")],
            &SearchOptions {
                max_bytes_per_entry: 2048,
                ..Default::default()
            },
        )
        .collect::<Result<Vec<_>>>()
        .unwrap();
        assert!(hits.is_empty()); // needle beyond the cap
    }

    #[test]
    fn utf16le_via_hex() {
        // "pass" as UTF-16LE
        let utf16: Vec<u8> = "pass".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut content = vec![0u8; 64];
        content[10..10 + utf16.len()].copy_from_slice(&utf16);
        let fs = fs_with(&[("/u.txt", &content, false)]);
        let hits: Vec<_> = search(
            &fs,
            &[Pattern::hex("70 00 61 00 73 00 73 00").unwrap()],
            &SearchOptions::default(),
        )
        .collect::<Result<Vec<_>>>()
        .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].offset, 10);
    }
}
