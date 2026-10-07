//! MACB timeline construction from a `walk()` stream.
//!
//! Every [`sutram_fs::FsEntry`] carries up to five forensic timestamps — modified
//! (**M**), accessed (**A**), metadata-changed (**C**), created/birth
//! (**B**) and deletion time (**D**, e.g. ext4 `dtime`). [`Timeline`]
//! explodes each populated slot into one [`TimelineEvent`], sorts by
//! nanoseconds-since-epoch, and renders the result as:
//!
//! * **CSV** — `date,time,MACB,path` rows (mactime-style dotted MACB
//!   column, `d` appended for deletion events);
//! * **JSONL** — one JSON object per event (ISO time + raw nanos +
//!   provenance fields);
//! * **TSK bodyfile** — the `md5|name|inode|mode|uid|gid|size|atime|
//!   mtime|ctime|crtime` pipe format `mactime` consumes. The bodyfile
//!   has no deletion-time column; `d` events are omitted there (use CSV
//!   or JSONL to see them).
//!
//! `Timeline::build` is bounded: [`TimelineOptions::max_events`] caps the
//! collected events (walk errors are counted, never fatal — corrupt
//! records in a lenient walk do not abort the timeline).

use std::fmt::Write as _;

use sutram_fs::{EntryKind, FileSystem, FsEntryStatus, FsTimestamp};

/// One timestamped observation of one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEvent {
    /// Nanoseconds since the Unix epoch (UTC). May be negative.
    pub ts_nanos: i64,
    /// Entry path (`/`-joined).
    pub path: String,
    /// MACB letter: `m`, `a`, `c`, `b` — or `d` for a recorded deletion
    /// time.
    pub macb_letter: char,
    /// Which [`sutram_fs::Timestamps`] field produced this event
    /// (`"modified"`, `"accessed"`, `"changed"`, `"created"`,
    /// `"deleted"`).
    pub source_field: &'static str,
    /// The entry's stable identifier (inode / MFT entry / dir slot).
    pub entry_id: u64,
    /// Live or deleted-with-recoverability.
    pub status: FsEntryStatus,
    /// Node kind (needed for the bodyfile mode column).
    pub kind: EntryKind,
    /// Entry logical size (needed for bodyfile rendering).
    pub size: u64,
}

impl TimelineEvent {
    /// mactime-style dotted MACB column (`m...`, `.a..`, `..c.`,
    /// `...b`, `....d`).
    pub fn macb_column(&self) -> String {
        let mut s = ['.'; 5];
        match self.macb_letter {
            'm' => s[0] = 'm',
            'a' => s[1] = 'a',
            'c' => s[2] = 'c',
            'b' => s[3] = 'b',
            _ => s[4] = 'd',
        }
        s.iter().collect()
    }

    /// `YYYY-MM-DD` (UTC) for the event time.
    pub fn date(&self) -> String {
        let (y, mo, d, _, _, _) = civil_from_nanos(self.ts_nanos);
        format!("{y:04}-{mo:02}-{d:02}")
    }

    /// `HH:MM:SS` (UTC) for the event time.
    pub fn time(&self) -> String {
        let (_, _, _, h, mi, s) = civil_from_nanos(self.ts_nanos);
        format!("{h:02}:{mi:02}:{s:02}")
    }

    /// ISO-8601 `YYYY-MM-DDTHH:MM:SSZ`.
    pub fn iso8601(&self) -> String {
        format!("{}T{}Z", self.date(), self.time())
    }
}

/// Knobs for [`Timeline::build_with`].
#[derive(Debug, Clone)]
pub struct TimelineOptions {
    /// Maximum events collected. Default 1_000_000 — a hard bound so a
    /// pathological image cannot exhaust memory. Excess sets
    /// [`Timeline::truncated`].
    pub max_events: usize,
    /// Include directory timestamps. Default `true` (mactime includes
    /// directories; dir mtimes are where activity hides).
    pub include_dirs: bool,
    /// Emit `d` events for recorded deletion timestamps (formats that
    /// store one). Default `true`.
    pub include_deleted_time: bool,
}

impl Default for TimelineOptions {
    fn default() -> Self {
        TimelineOptions {
            max_events: 1_000_000,
            include_dirs: true,
            include_deleted_time: true,
        }
    }
}

/// A sorted MACB timeline.
#[derive(Debug, Default)]
pub struct Timeline {
    events: Vec<TimelineEvent>,
    /// `true` when `max_events` cut the walk short.
    pub truncated: bool,
    /// Number of `Err` items the lenient walk yielded.
    pub errors: usize,
}

impl Timeline {
    /// Build with default options.
    pub fn build(fs: &dyn FileSystem) -> Timeline {
        Self::build_with(fs, &TimelineOptions::default())
    }

    /// Walk `fs`, explode every populated timestamp into an event, sort
    /// by time. Walk `Err` items are counted in `errors` — they are
    /// records of corruption, not reasons to abort (lenient contract).
    pub fn build_with(fs: &dyn FileSystem, opts: &TimelineOptions) -> Timeline {
        let mut tl = Timeline::default();
        'walk: for item in fs.walk() {
            let entry = match item {
                Ok(e) => e,
                Err(_) => {
                    tl.errors += 1;
                    continue;
                }
            };
            if entry.kind == EntryKind::Directory && !opts.include_dirs {
                continue;
            }
            let mut emit = |ts: &FsTimestamp, letter: char, field: &'static str| {
                if let Some(ns) = ts.value {
                    if tl.events.len() >= opts.max_events {
                        tl.truncated = true;
                        return false;
                    }
                    tl.events.push(TimelineEvent {
                        ts_nanos: ns,
                        path: entry.path.clone(),
                        macb_letter: letter,
                        source_field: field,
                        entry_id: entry.entry_id,
                        status: entry.status,
                        kind: entry.kind,
                        size: entry.size,
                    });
                }
                true
            };
            let t = &entry.timestamps;
            if let Some(ts) = &t.modified {
                if !emit(ts, 'm', "modified") {
                    break 'walk;
                }
            }
            if let Some(ts) = &t.accessed {
                if !emit(ts, 'a', "accessed") {
                    break 'walk;
                }
            }
            if let Some(ts) = &t.changed {
                if !emit(ts, 'c', "changed") {
                    break 'walk;
                }
            }
            if let Some(ts) = &t.created {
                if !emit(ts, 'b', "created") {
                    break 'walk;
                }
            }
            if opts.include_deleted_time {
                if let Some(ts) = &t.deleted {
                    if !emit(ts, 'd', "deleted") {
                        break 'walk;
                    }
                }
            }
        }
        tl.events.sort_by(|a, b| {
            a.ts_nanos
                .cmp(&b.ts_nanos)
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| a.macb_letter.cmp(&b.macb_letter))
        });
        tl
    }

    /// The sorted events.
    pub fn events(&self) -> &[TimelineEvent] {
        &self.events
    }

    /// Number of events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// `true` when no events were collected.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Render as `date,time,MACB,path` CSV (one row per event).
    pub fn to_csv(&self) -> String {
        let mut out = String::with_capacity(self.events.len() * 64);
        out.push_str("date,time,MACB,path\n");
        for e in &self.events {
            out.push_str(&e.date());
            out.push(',');
            out.push_str(&e.time());
            out.push(',');
            out.push_str(&e.macb_column());
            out.push(',');
            csv_field(&mut out, &e.path);
            out.push('\n');
        }
        out
    }

    /// Render as JSON lines — one object per event.
    pub fn to_jsonl(&self) -> String {
        let mut out = String::with_capacity(self.events.len() * 128);
        for e in &self.events {
            let status = match e.status {
                FsEntryStatus::Live => "live",
                FsEntryStatus::Deleted { .. } => "deleted",
            };
            let _ = write!(
                out,
                "{{\"ts_nanos\":{},\"time\":\"{}\",\"macb\":\"{}\",\"field\":\"{}\",\"path\":\"{}\",\"entry_id\":{},\"status\":\"{}\",\"size\":{}}}",
                e.ts_nanos,
                e.iso8601(),
                e.macb_letter,
                e.source_field,
                json_escape(&e.path),
                e.entry_id,
                status,
                e.size,
            );
            out.push('\n');
        }
        out
    }

    /// Render as a TSK bodyfile (`md5|name|inode|mode|uid|gid|size|atime|
    /// mtime|ctime|crtime`), one line per *entry* (not per event —
    /// bodyfile aggregates the four MACB times on one line).
    ///
    /// `MD5` is `0` (hashing is a separate concern, see [`crate::hash`]),
    /// uid/gid are `0` (not all formats store them). Deletion time has no
    /// column — emit CSV/JSONL for `d` events.
    pub fn to_bodyfile(&self) -> String {
        // Re-aggregate events by entry: the four MACB slots land on one
        // line, seconds granularity.
        let mut lines: Vec<(i64, String)> = Vec::new();
        let mut i = 0;
        let mut sorted: Vec<&TimelineEvent> = self.events.iter().collect();
        sorted.sort_by(|a, b| a.path.cmp(&b.path).then(a.entry_id.cmp(&b.entry_id)));
        while i < sorted.len() {
            let first = sorted[i];
            let (mut atime, mut mtime, mut ctime, mut crtime) = (0i64, 0i64, 0i64, 0i64);
            let mut j = i;
            while j < sorted.len()
                && sorted[j].entry_id == first.entry_id
                && sorted[j].path == first.path
            {
                let sec = sorted[j].ts_nanos.div_euclid(1_000_000_000);
                match sorted[j].macb_letter {
                    'm' => mtime = sec,
                    'a' => atime = sec,
                    'c' => ctime = sec,
                    'b' => crtime = sec,
                    _ => {} // 'd' — no bodyfile column
                }
                j += 1;
            }
            let deleted = matches!(first.status, FsEntryStatus::Deleted { .. });
            let name = if deleted {
                format!("{} (deleted)", first.path)
            } else {
                first.path.clone()
            };
            lines.push((
                first.ts_nanos,
                format!(
                    "0|{}|{}|{}|0|0|{}|{}|{}|{}|{}",
                    name,
                    first.entry_id,
                    mode_string(first),
                    first.size,
                    atime,
                    mtime,
                    ctime,
                    crtime,
                ),
            ));
            i = j;
        }
        // Bodyfile consumers expect chronological order.
        lines.sort_by_key(|(ts, _)| *ts);
        let mut out = String::with_capacity(lines.len() * 80);
        for (_, l) in lines {
            out.push_str(&l);
            out.push('\n');
        }
        out
    }
}

/// TSK `mode_as_string` column — real permission bits are format-specific
/// metadata (`meta["mode"]`), not part of `FsEntry`, so the column carries
/// the node kind with all-access placeholders.
fn mode_string(e: &TimelineEvent) -> &'static str {
    match e.kind {
        EntryKind::Directory => "d/drwxrwxrwx",
        EntryKind::Symlink => "l/lrwxrwxrwx",
        _ => "-/rwxrwxrwx",
    }
}

fn csv_field(out: &mut String, s: &str) {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        out.push('"');
        for c in s.chars() {
            if c == '"' {
                out.push('"');
            }
            out.push(c);
        }
        out.push('"');
    } else {
        out.push_str(s);
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// `(year, month, day, hour, min, sec)` for nanoseconds-since-epoch —
/// the inverse of `sutram_fs::util::unix_nanos` (Hinnant's
/// `civil_from_days`). Handles pre-epoch times via `div_euclid`.
fn civil_from_nanos(nanos: i64) -> (i64, u32, u32, u32, u32, u32) {
    let secs = nanos.div_euclid(1_000_000_000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    );
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Read;
    use std::sync::Arc;
    use std::time::Duration;

    use sutram_fs::{
        EntryKind, FsEntry, FsError, FsInfo, RecoveryState, Result, Timestamps,
    };
    use sutram_io::ByteSource;

    struct MemFs {
        entries: Vec<FsEntry>,
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
        fn read_file(&self, _entry: &FsEntry) -> Result<Box<dyn Read + Send>> {
            Err(FsError::InvalidInput { msg: "no data".into() })
        }
    }

    fn ts(ns: i64) -> FsTimestamp {
        FsTimestamp {
            value: Some(ns),
            raw_value: ns as u64,
            raw_encoding: "test",
            granularity: Duration::from_secs(1),
        }
    }

    fn entry(id: u64, path: &str, kind: EntryKind, deleted: bool) -> FsEntry {
        FsEntry {
            path: path.into(),
            name: path.rsplit('/').next().unwrap_or(path).into(),
            entry_id: id,
            kind,
            size: 100,
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

    const SEC: i64 = 1_000_000_000;
    const DAY: i64 = 86_400 * SEC;

    #[test]
    fn civil_roundtrip() {
        // 2024-01-15T10:30:20Z
        let ns = sutram_fs::util::unix_nanos(2024, 1, 15, 10, 30, 20, 0).unwrap();
        assert_eq!(civil_from_nanos(ns), (2024, 1, 15, 10, 30, 20));
        // epoch
        assert_eq!(civil_from_nanos(0), (1970, 1, 1, 0, 0, 0));
        // pre-epoch: 1969-12-31T23:59:59Z
        assert_eq!(civil_from_nanos(-SEC), (1969, 12, 31, 23, 59, 59));
        // leap day
        let ns = sutram_fs::util::unix_nanos(2000, 2, 29, 12, 0, 0, 0).unwrap();
        assert_eq!(civil_from_nanos(ns), (2000, 2, 29, 12, 0, 0));
    }

    #[test]
    fn build_sorts_and_expands() {
        let mut a = entry(1, "/a.txt", EntryKind::File, false);
        a.timestamps.modified = Some(ts(10 * DAY));
        a.timestamps.accessed = Some(ts(2 * DAY));
        let mut b = entry(2, "/b.txt", EntryKind::File, true);
        b.timestamps.created = Some(ts(5 * DAY));
        b.timestamps.deleted = Some(ts(7 * DAY));
        let fs = MemFs {
            entries: vec![a, b],
            src: Arc::new(Vec::new()),
        };
        let tl = Timeline::build(&fs);
        assert_eq!(tl.len(), 4);
        let letters: Vec<char> = tl.events().iter().map(|e| e.macb_letter).collect();
        assert_eq!(letters, ['a', 'b', 'd', 'm']);
        assert!(tl.events()[0].ts_nanos < tl.events()[3].ts_nanos);
        assert!(!tl.truncated);
        assert_eq!(tl.errors, 0);
        // the 'd' event cites its source field and status
        let d = &tl.events()[2];
        assert_eq!(d.source_field, "deleted");
        assert!(matches!(d.status, FsEntryStatus::Deleted { .. }));
    }

    #[test]
    fn build_honours_caps_and_dir_filter() {
        let mut dir = entry(1, "/d", EntryKind::Directory, false);
        dir.timestamps.modified = Some(ts(DAY));
        let mut f = entry(2, "/f", EntryKind::File, false);
        f.timestamps.modified = Some(ts(2 * DAY));
        f.timestamps.accessed = Some(ts(3 * DAY));
        let fs = MemFs {
            entries: vec![dir, f],
            src: Arc::new(Vec::new()),
        };
        let tl = Timeline::build_with(
            &fs,
            &TimelineOptions {
                include_dirs: false,
                ..Default::default()
            },
        );
        assert_eq!(tl.len(), 2);
        let tl = Timeline::build_with(
            &fs,
            &TimelineOptions {
                max_events: 1,
                ..Default::default()
            },
        );
        assert_eq!(tl.len(), 1);
        assert!(tl.truncated);
    }

    #[test]
    fn all_macb_letters_render() {
        let mut e = entry(1, "/full.txt", EntryKind::File, false);
        e.timestamps.modified = Some(ts(DAY));
        e.timestamps.accessed = Some(ts(2 * DAY));
        e.timestamps.changed = Some(ts(3 * DAY));
        e.timestamps.created = Some(ts(4 * DAY));
        e.timestamps.deleted = Some(ts(5 * DAY));
        let fs = MemFs {
            entries: vec![e],
            src: Arc::new(Vec::new()),
        };
        let tl = Timeline::build(&fs);
        assert_eq!(tl.len(), 5);
        let csv = tl.to_csv();
        for col in ["m....", ".a...", "..c..", "...b.", "....d"] {
            assert!(csv.contains(&format!(",{col},/full.txt")), "{col} in {csv}");
        }
        // exclude_deleted_time drops the 'd' event only
        let tl = Timeline::build_with(
            &fs,
            &TimelineOptions {
                include_deleted_time: false,
                ..Default::default()
            },
        );
        assert_eq!(tl.len(), 4);
        assert!(!tl.to_csv().contains("....d"));
    }

    #[test]
    fn truncation_breaks_mid_entry() {
        // A cap that lands inside one entry's timestamp expansion exits
        // the walk early at each `emit` site.
        let mut e = entry(1, "/f", EntryKind::File, false);
        e.timestamps.modified = Some(ts(DAY));
        e.timestamps.accessed = Some(ts(2 * DAY));
        e.timestamps.changed = Some(ts(3 * DAY));
        e.timestamps.created = Some(ts(4 * DAY));
        e.timestamps.deleted = Some(ts(5 * DAY));
        for cap in 0..5usize {
            let fs = MemFs {
                entries: vec![e.clone()],
                src: Arc::new(Vec::new()),
            };
            let tl = Timeline::build_with(
                &fs,
                &TimelineOptions {
                    max_events: cap,
                    ..Default::default()
                },
            );
            assert_eq!(tl.len(), cap, "cap {cap}");
            assert!(tl.truncated, "cap {cap}");
        }
    }

    #[test]
    fn empty_timeline() {
        let fs = MemFs {
            entries: vec![],
            src: Arc::new(Vec::new()),
        };
        assert_eq!(fs.info().fs_type, "mem");
        let _ = fs.source();
        let tl = Timeline::build(&fs);
        assert!(tl.is_empty());
        assert_eq!(tl.len(), 0);
        assert_eq!(tl.to_csv(), "date,time,MACB,path\n");
        assert!(tl.to_jsonl().is_empty());
        assert!(tl.to_bodyfile().is_empty());
    }

    #[test]
    fn csv_and_jsonl_escape_special_chars() {
        let mut e = entry(1, "/quo\"te\\back\u{1}end", EntryKind::File, false);
        e.timestamps.modified = Some(ts(0));
        let fs = MemFs {
            entries: vec![e],
            src: Arc::new(Vec::new()),
        };
        let tl = Timeline::build(&fs);
        let csv = tl.to_csv();
        // quote doubled, whole field quoted
        assert!(
            csv.contains("\"/quo\"\"te\\back\u{1}end\""),
            "{csv}"
        );
        let j = tl.to_jsonl();
        assert!(
            j.contains("/quo\\\"te\\\\back\\u0001end"),
            "{j}"
        );
    }

    #[test]
    fn bodyfile_symlink_mode_and_deleted_marker() {
        let mut l = entry(1, "/link", EntryKind::Symlink, false);
        l.timestamps.changed = Some(ts(DAY));
        l.timestamps.created = Some(ts(2 * DAY));
        let mut d = entry(2, "/gone.bin", EntryKind::File, true);
        d.timestamps.deleted = Some(ts(3 * DAY));
        let mut dir = entry(3, "/dir", EntryKind::Directory, false);
        dir.timestamps.modified = Some(ts(4 * DAY));
        let fs = MemFs {
            entries: vec![l, d, dir],
            src: Arc::new(Vec::new()),
        };
        let bf = Timeline::build(&fs).to_bodyfile();
        // symlink → l/lrwxrwxrwx mode; ctime/crtime columns populated
        assert!(
            bf.contains("0|/link|1|l/lrwxrwxrwx|0|0|100|0|0|86400|172800"),
            "{bf}"
        );
        // 'd'-only event still emits a line (zeroed time columns) with
        // the (deleted) suffix
        assert!(bf.contains("|/gone.bin (deleted)|2|"), "{bf}");
        // directory → d/drwxrwxrwx mode
        assert!(bf.contains("0|/dir|3|d/drwxrwxrwx|"), "{bf}");
    }

    #[test]
    fn csv_output() {
        let mut e = entry(1, "/hello.txt", EntryKind::File, false);
        // 2024-01-15T10:30:20Z
        let ns = sutram_fs::util::unix_nanos(2024, 1, 15, 10, 30, 20, 0).unwrap();
        e.timestamps.modified = Some(ts(ns));
        e.timestamps.created = Some(ts(ns + SEC));
        let fs = MemFs {
            entries: vec![e],
            src: Arc::new(Vec::new()),
        };
        let csv = Timeline::build(&fs).to_csv();
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "date,time,MACB,path");
        assert_eq!(lines[1], "2024-01-15,10:30:20,m....,/hello.txt");
        assert_eq!(lines[2], "2024-01-15,10:30:21,...b.,/hello.txt");
    }

    #[test]
    fn csv_escapes_commas() {
        let mut e = entry(1, "/weird,name.txt", EntryKind::File, false);
        e.timestamps.modified = Some(ts(0));
        let fs = MemFs {
            entries: vec![e],
            src: Arc::new(Vec::new()),
        };
        let csv = Timeline::build(&fs).to_csv();
        assert!(csv.contains("m....,\"/weird,name.txt\""), "{csv}");
    }

    #[test]
    fn jsonl_output() {
        let mut e = entry(7, "/x.bin", EntryKind::File, true);
        e.timestamps.deleted = Some(ts(0));
        let fs = MemFs {
            entries: vec![e],
            src: Arc::new(Vec::new()),
        };
        let j = Timeline::build(&fs).to_jsonl();
        assert!(j.contains("\"macb\":\"d\""), "{j}");
        assert!(j.contains("\"field\":\"deleted\""), "{j}");
        assert!(j.contains("\"status\":\"deleted\""), "{j}");
        assert!(j.contains("\"path\":\"/x.bin\""), "{j}");
        assert!(j.contains("\"time\":\"1970-01-01T00:00:00Z\""), "{j}");
    }

    #[test]
    fn bodyfile_aggregates_per_entry() {
        let mut e = entry(42, "/f.bin", EntryKind::File, false);
        e.size = 777;
        e.timestamps.modified = Some(ts(2 * DAY + 5 * SEC));
        e.timestamps.accessed = Some(ts(3 * DAY));
        let fs = MemFs {
            entries: vec![e],
            src: Arc::new(Vec::new()),
        };
        let bf = Timeline::build(&fs).to_bodyfile();
        // one line: 0|path|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
        let expect = format!(
            "0|/f.bin|42|-/rwxrwxrwx|0|0|777|{}|{}|0|0",
            3 * DAY / SEC,
            2 * DAY / SEC + 5
        );
        assert_eq!(bf.trim(), expect);
    }

    #[test]
    fn walk_errors_are_counted_not_fatal() {
        // MemFs variant that injects an error record mid-stream.
        struct ErrFs {
            inner: MemFs,
        }
        impl FileSystem for ErrFs {
            fn info(&self) -> FsInfo {
                self.inner.info()
            }
            fn source(&self) -> Arc<dyn ByteSource> {
                self.inner.source()
            }
            fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
                let e = self.inner.entries[0].clone();
                Box::new(
                    vec![
                        Ok(e),
                        Err(FsError::corrupt(0x100, "bogus dirent")),
                    ]
                    .into_iter(),
                )
            }
            fn read_file(&self, entry: &FsEntry) -> Result<Box<dyn Read + Send>> {
                self.inner.read_file(entry)
            }
        }
        let mut e = entry(1, "/a", EntryKind::File, false);
        e.timestamps.modified = Some(ts(0));
        let fs = ErrFs {
            inner: MemFs {
                entries: vec![e.clone()],
                src: Arc::new(Vec::new()),
            },
        };
        let _ = fs.info();
        let _ = fs.source();
        assert!(fs.read_file(&e).is_err());
        let tl = Timeline::build(&fs);
        assert_eq!(tl.errors, 1);
        assert_eq!(tl.len(), 1);
    }
}
