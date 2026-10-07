//! Directory-tree reconstruction from carved remnants, and matching of
//! live (carved-back) files against it.
//!
//! Data model: every recovered `FILE` record and `INDX` entry contributes
//! `(child record number, name, parent record number, size, is_dir)`. Parent
//! record numbers chain upward to the MFT root (record 5), so walking them
//! rebuilds original absolute paths even when the $MFT itself is destroyed.
//! Chains that die before reaching the root get a `LOST#<recno>` prefix —
//! honest, greppable, and resolvable later if the missing record shows up.
//!
//! Matching: a live file `F` maps to an old directory entry when
//! `(lowercase basename, exact size)` collides uniquely or by first
//! unconsumed candidate; collisions are emitted with `ambiguous`.

use std::collections::HashMap;

use crate::remnants::Remnant;

/// Root record number — NTFS reserves 5 for `.` (the volume root dir).
pub const ROOT_REC: u64 = 5;
/// Sanity bound on record numbers seen in remnant data.
const RECN_MAX: u64 = 10_000_000;

/// What we know about one MFT record number in the dead filesystem.
#[derive(Debug, Clone)]
pub struct RemnantNode {
    pub name: String,
    pub parent: u64,
    pub is_dir: bool,
    pub size: u64,
    /// Came from a FILE record body (strong) vs. an INDX mention.
    pub from_record: bool,
}

/// A directory-membership fact: `parent` contained `recno` under `name`.
#[derive(Debug, Clone)]
pub struct OldMember {
    pub recno: u64,
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
}

/// Reconstructed old-filesystem tree.
#[derive(Debug, Default)]
pub struct RemnantTree {
    /// recno → node identity (from FILE records and INDX entries).
    pub nodes: HashMap<u64, RemnantNode>,
    /// parent recno → children seen in index blocks / FILE records.
    pub members: HashMap<u64, Vec<OldMember>>,
}

/// `NAME~1.EXT`-style DOS short-name heuristic (kept out of display).
fn looks_sfn(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name);
    stem.contains('~') && name.chars().all(|c| !c.is_lowercase())
}

fn sane(recno: u64, name: &str) -> bool {
    recno < RECN_MAX
        && !name.is_empty()
        && name != "."
        && name != ".."
        && name.chars().all(|c| !c.is_control())
}

/// Live-filesystem identity map: recno → (name, parent recno). Remnant
/// entries whose (child recno, name, parent) all match a live record are
/// echoes of the *current* volume's own index blocks — swept as "remnants"
/// simply because live index allocations are INDX blocks too — and must be
/// dropped or they graft current names onto old parent chains.
pub type LiveNames = HashMap<u64, (String, u64)>;

/// `true` when a remnant membership fact is identical to a live record's
/// own (name, parent) — i.e. it describes the live filesystem, not the
/// dead one.
fn live_echo(live: &LiveNames, recno: u64, name: &str, parent: u64) -> bool {
    live.get(&recno)
        .is_some_and(|(n, p)| *p == parent && n.eq_ignore_ascii_case(name))
}

impl RemnantTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one scan hit into the tree. `live` (when provided) filters
    /// current-filesystem echoes — pass `NtfsFs::live_names()`.
    pub fn feed(&mut self, r: &Remnant, live: Option<&LiveNames>) {
        match r {
            Remnant::File(f) => {
                // A record only anchors in the tree when it knows its own
                // number (0x2C field); unnumbered log copies still donate
                // their parent-link knowledge via `names`.
                let recno = f.record_no as u64;
                let best = f
                    .names
                    .iter()
                    .find(|n| n.namespace != 2)
                    .or_else(|| f.names.first());
                if let Some(b) = best {
                    let echo = live.is_some_and(|l| live_echo(l, recno, &b.name, b.parent_rec));
                    if !echo && sane(b.parent_rec, &b.name) {
                        self.members
                            .entry(b.parent_rec)
                            .or_default()
                            .push(OldMember {
                                recno,
                                name: b.name.clone(),
                                size: b.real_size,
                                is_dir: f.is_dir,
                            });
                        if recno != 0 && recno < RECN_MAX {
                            match self.nodes.get_mut(&recno) {
                                // Record bodies are authoritative: upgrade an
                                // INDX-mention identity wholesale.
                                Some(e) if !e.from_record => {
                                    e.name = b.name.clone();
                                    e.parent = b.parent_rec;
                                    e.is_dir = f.is_dir;
                                    e.size = b.real_size;
                                    e.from_record = true;
                                }
                                // Prefer the richer name if we first learned
                                // it as an SFN.
                                Some(e) if looks_sfn(&e.name) && !looks_sfn(&b.name) => {
                                    e.name = b.name.clone();
                                }
                                Some(_) => {}
                                None => {
                                    self.nodes.insert(
                                        recno,
                                        RemnantNode {
                                            name: b.name.clone(),
                                            parent: b.parent_rec,
                                            is_dir: f.is_dir,
                                            size: b.real_size,
                                            from_record: true,
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }
            Remnant::Index(x) => {
                for e in &x.entries {
                    if !sane(e.child_rec, &e.name) || !sane(e.parent_rec, "x") {
                        continue;
                    }
                    if live.is_some_and(|l| live_echo(l, e.child_rec, &e.name, e.parent_rec)) {
                        continue;
                    }
                    let is_dir = e.flags & 0x1000_0000 != 0;
                    // node identity for the child. INDX mentions never
                    // overwrite a FILE-record identity — the record body is
                    // era-authoritative; a stale index entry may describe a
                    // different generation of the same record number.
                    match self.nodes.get_mut(&e.child_rec) {
                        Some(n) if n.from_record => {
                            if looks_sfn(&n.name) && !looks_sfn(&e.name) {
                                n.name = e.name.clone();
                            }
                        }
                        Some(n) if looks_sfn(&n.name) && !looks_sfn(&e.name) => {
                            *n = RemnantNode {
                                name: e.name.clone(),
                                parent: e.parent_rec,
                                is_dir,
                                size: e.real_size,
                                from_record: false,
                            };
                        }
                        Some(_) => {}
                        None => {
                            self.nodes.insert(
                                e.child_rec,
                                RemnantNode {
                                    name: e.name.clone(),
                                    parent: e.parent_rec,
                                    is_dir,
                                    size: e.real_size,
                                    from_record: false,
                                },
                            );
                        }
                    }
                    self.members
                        .entry(e.parent_rec)
                        .or_default()
                        .push(OldMember {
                            recno: e.child_rec,
                            name: e.name.clone(),
                            size: e.real_size,
                            is_dir,
                        });
                }
            }
        }
    }

    /// Deduplicate members (same parent+child listed twice — e.g. the SFN
    /// and LFN index flavours) keeping the best display name.
    pub fn normalize(&mut self) {
        for kids in self.members.values_mut() {
            let mut seen: HashMap<u64, usize> = HashMap::new();
            let mut out: Vec<OldMember> = Vec::with_capacity(kids.len());
            for k in kids.drain(..) {
                match seen.get(&k.recno) {
                    Some(&i) => {
                        if looks_sfn(&out[i].name) && !looks_sfn(&k.name) {
                            out[i] = k;
                        }
                    }
                    None => {
                        seen.insert(k.recno, out.len());
                        out.push(k);
                    }
                }
            }
            *kids = out;
        }
    }

    /// Absolute path of a record number in the dead filesystem. Cycles and
    /// unknown ancestors resolve to `LOST#<recno>`; an ancestor whose own
    /// record body says it is a *file* resolves to `FILE#<recno>` — record
    /// numbers were reused across eras, so child claims under a file are
    /// stale grafts, not real directories.
    pub fn path_of(&self, recno: u64) -> String {
        let mut parts = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut cur = recno;
        let mut first = true;
        while cur != ROOT_REC {
            if !seen.insert(cur) {
                parts.push(format!("CYCLE#{cur}"));
                break;
            }
            match self.nodes.get(&cur) {
                Some(n) => {
                    if !first && !n.is_dir {
                        parts.push(format!("FILE#{cur}"));
                        break;
                    }
                    first = false;
                    parts.push(n.name.clone());
                    if n.parent == cur {
                        parts.push(format!("SELF#{cur}"));
                        break;
                    }
                    cur = n.parent;
                }
                None => {
                    parts.push(format!("LOST#{cur}"));
                    break;
                }
            }
        }
        parts.reverse();
        format!("/{}", parts.join("/"))
    }

    /// Every directory-membership fact as a full old-path entry.
    pub fn entries(&self) -> Vec<RestoredEntry> {
        let mut out = Vec::new();
        for (parent, kids) in &self.members {
            // A parent whose only identity says "file" can't be a real dir —
            // keep the membership fact (the child existed) but mark the
            // path FILE# so the bogus chain is visible rather than silently
            // presenting a file's name as a directory.
            let ppath = match self.nodes.get(parent) {
                Some(n) if !n.is_dir => format!("/FILE#{parent}"),
                _ => self.path_of(*parent),
            };
            for k in kids {
                let path = if ppath == "/" {
                    format!("/{}", k.name)
                } else {
                    format!("{}/{}", ppath, k.name)
                };
                out.push(RestoredEntry {
                    path,
                    recno: k.recno,
                    size: k.size,
                    is_dir: k.is_dir,
                });
            }
        }
        out
    }
}

/// One reconstructed old-path fact.
#[derive(Debug, Clone)]
pub struct RestoredEntry {
    pub path: String,
    pub recno: u64,
    pub size: u64,
    pub is_dir: bool,
}

/// A proposed restoration: live carved file → its old path.
#[derive(Debug, Clone)]
pub struct RestorePlan {
    pub live_path: String,
    pub live_entry_id: u64,
    pub restored_path: String,
    pub size: u64,
    pub old_recno: u64,
    /// More than one live file could have filled this slot.
    pub ambiguous: bool,
}

/// Live-file descriptor for matching (from `FileSystem::walk`).
pub struct LiveFile {
    pub entry_id: u64,
    pub path: String,
    pub name: String,
    pub size: u64,
}

/// Match live files to old tree entries on `(basename lowercase, size)`.
/// Each live file fills at most one old slot; each old slot takes one file.
pub fn match_live(entries: &[RestoredEntry], live: &[LiveFile]) -> Vec<RestorePlan> {
    let mut by_key: HashMap<(String, u64), Vec<usize>> = HashMap::new();
    for (i, l) in live.iter().enumerate() {
        by_key
            .entry((l.name.to_lowercase(), l.size))
            .or_default()
            .push(i);
    }
    let mut used = vec![false; live.len()];
    let mut plan = Vec::new();
    for e in entries {
        if e.is_dir || e.size == 0 {
            continue;
        }
        let name = e.path.rsplit('/').next().unwrap_or("").to_lowercase();
        if let Some(cands) = by_key.get(&(name.clone(), e.size)) {
            let mut free = cands.iter().copied().filter(|&i| !used[i]);
            if let Some(i) = free.next() {
                let ambiguous = free.next().is_some();
                used[i] = true;
                plan.push(RestorePlan {
                    live_path: live[i].path.clone(),
                    live_entry_id: live[i].entry_id,
                    restored_path: e.path.clone(),
                    size: e.size,
                    old_recno: e.recno,
                    ambiguous,
                });
            }
        }
    }
    plan
}

// ---------------- JSONL re-ingestion ----------------
//
// Reads lines produced by `remnants::to_jsonl` back into `Remnant` values.
// Hand-rolled mini JSON parser — enough for our flat schema (objects,
// arrays, strings with escapes, numbers, bools).

pub fn parse_remnant_line(line: &str) -> Option<Remnant> {
    let v = mini::Parser::new(line.trim()).value()?;
    let kind = v.get("kind").as_str()?;
    match kind {
        "FILE" => Some(remnant_file(&v)),
        "INDX" => Some(remnant_index(&v)),
        _ => None,
    }
}

fn remnant_file(v: &mini::J) -> Remnant {
    let mut rec = crate::remnants::RemnantRecord {
        offset: v.get("off").num_u64(),
        record_no: v.get("rec_no").num_u64() as u32,
        signature: *b"FILE",
        sequence: v.get("seq").num_u64() as u16,
        in_use: v.get("in_use").as_bool(),
        is_dir: v.get("is_dir").as_bool(),
        base_ref: v.get("base").num_u64(),
        names: Vec::new(),
        data: Vec::new(),
    };
    if let Some(arr) = v.get("names").as_arr() {
        for n in arr {
            rec.names.push(crate::remnants::RemnantName {
                parent_ref: n.get("parent").num_u64(),
                parent_rec: n.get("parent").num_u64(),
                name: n.get("name").as_str_owned(),
                real_size: n.get("real").num_u64(),
                flags: n.get("flags").num_u64() as u32,
                namespace: n.get("ns").num_u64() as u8,
            });
        }
    }
    if let Some(arr) = v.get("datas").as_arr() {
        for d in arr {
            let resident = d.get("resident").as_bool();
            let mut runs = Vec::new();
            if let Some(rr) = d.get("runs").as_arr() {
                for pair in rr {
                    if let Some(p) = pair.as_arr() {
                        if p.len() == 2 {
                            runs.push((p[0].num_u64(), p[1].num_u64()));
                        }
                    }
                }
            }
            rec.data.push(crate::remnants::RemnantData {
                name: {
                    let s = d.get("name").as_str_owned();
                    if s.is_empty() { None } else { Some(s) }
                },
                real_size: d.get("real").num_u64(),
                resident,
                resident_len: d.get("res_len").num_u64() as usize,
                runs,
            });
        }
    }
    Remnant::File(rec)
}

fn remnant_index(v: &mini::J) -> Remnant {
    let mut idx = crate::remnants::RemnantIndex {
        offset: v.get("off").num_u64(),
        vcn: v.get("vcn").num_u64(),
        entries: Vec::new(),
    };
    if let Some(arr) = v.get("entries").as_arr() {
        for e in arr {
            let child = e.get("child").num_u64();
            let cseq = e.get("cseq").num_u64();
            idx.entries.push(crate::remnants::RemnantIndexEntry {
                child_ref: child | (cseq << 48),
                child_rec: child,
                parent_ref: e.get("parent").num_u64(),
                parent_rec: e.get("parent").num_u64(),
                name: e.get("name").as_str_owned(),
                real_size: e.get("size").num_u64(),
                flags: if e.get("is_dir").as_bool() {
                    0x1000_0000
                } else {
                    0
                },
                namespace: 1,
                has_subnode: e.get("sub").num_u64() != 0,
            });
        }
    }
    Remnant::Index(idx)
}

/// Minimal JSON value parser (our own flat schema — strings, numbers,
/// bools, arrays, objects). No floats needed; numbers parse as u64/f64.
mod mini {
    #[derive(Debug)]
    pub enum J {
        Obj(Vec<(String, J)>),
        Arr(Vec<J>),
        Str(String),
        Num(f64),
        Bool(bool),
        Null,
    }

    const NULL_J: J = J::Null;

    impl J {
        pub fn get(&self, key: &str) -> &J {
            if let J::Obj(kv) = self {
                for (k, v) in kv {
                    if k == key {
                        return v;
                    }
                }
            }
            &NULL_J
        }
        pub fn as_arr(&self) -> Option<&Vec<J>> {
            if let J::Arr(v) = self {
                Some(v)
            } else {
                None
            }
        }
        pub fn as_str(&self) -> Option<&str> {
            if let J::Str(s) = self {
                Some(s)
            } else {
                None
            }
        }
        pub fn as_str_owned(&self) -> String {
            self.as_str().unwrap_or("").to_string()
        }
        pub fn as_bool(&self) -> bool {
            matches!(self, J::Bool(true))
        }
        pub fn num_u64(&self) -> u64 {
            match self {
                J::Num(n) => *n as u64,
                _ => 0,
            }
        }
    }

    pub struct Parser<'a> {
        b: &'a [u8],
        i: usize,
    }

    impl<'a> Parser<'a> {
        pub fn new(s: &'a str) -> Self {
            Self {
                b: s.as_bytes(),
                i: 0,
            }
        }
        fn ws(&mut self) {
            while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
                self.i += 1;
            }
        }
        fn peek(&self) -> Option<u8> {
            self.b.get(self.i).copied()
        }
        pub fn value(&mut self) -> Option<J> {
            self.ws();
            match self.peek()? {
                b'{' => self.object(),
                b'[' => self.array(),
                b'"' => self.string().map(J::Str),
                b't' => self.lit("true", J::Bool(true)),
                b'f' => self.lit("false", J::Bool(false)),
                b'n' => self.lit("null", J::Null),
                _ => self.number(),
            }
        }
        fn lit(&mut self, s: &str, v: J) -> Option<J> {
            if self.b[self.i..].starts_with(s.as_bytes()) {
                self.i += s.len();
                Some(v)
            } else {
                None
            }
        }
        fn number(&mut self) -> Option<J> {
            let start = self.i;
            while self.i < self.b.len()
                && matches!(self.b[self.i], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
            {
                self.i += 1;
            }
            std::str::from_utf8(&self.b[start..self.i])
                .ok()?
                .parse()
                .ok()
                .map(J::Num)
        }
        fn string(&mut self) -> Option<String> {
            if self.peek()? != b'"' {
                return None;
            }
            self.i += 1;
            let mut s = String::new();
            while let Some(c) = self.peek() {
                self.i += 1;
                match c {
                    b'"' => return Some(s),
                    b'\\' => {
                        let e = self.peek()?;
                        self.i += 1;
                        match e {
                            b'"' => s.push('"'),
                            b'\\' => s.push('\\'),
                            b'/' => s.push('/'),
                            b'n' => s.push('\n'),
                            b't' => s.push('\t'),
                            b'r' => s.push('\r'),
                            b'b' => s.push('\u{8}'),
                            b'f' => s.push('\u{c}'),
                            b'u' => {
                                let h = std::str::from_utf8(self.b.get(self.i..self.i + 4)?).ok()?;
                                let cp = u32::from_str_radix(h, 16).ok()?;
                                s.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                                self.i += 4;
                            }
                            _ => return None,
                        }
                    }
                    _ => {
                        // raw UTF-8 byte — collect continuation bytes
                        let mut buf = [0u8; 4];
                        buf[0] = c;
                        let n = if c >= 0xF0 {
                            4
                        } else if c >= 0xE0 {
                            3
                        } else if c >= 0xC0 {
                            2
                        } else {
                            1
                        };
                        for k in 1..n {
                            buf[k] = *self.b.get(self.i)?;
                            self.i += 1;
                        }
                        s.push_str(std::str::from_utf8(&buf[..n]).unwrap_or("\u{fffd}"));
                    }
                }
            }
            None
        }
        fn object(&mut self) -> Option<J> {
            self.i += 1; // {
            let mut kv = Vec::new();
            self.ws();
            if self.peek() == Some(b'}') {
                self.i += 1;
                return Some(J::Obj(kv));
            }
            loop {
                self.ws();
                let k = self.string()?;
                self.ws();
                if self.peek()? != b':' {
                    return None;
                }
                self.i += 1;
                let v = self.value()?;
                kv.push((k, v));
                self.ws();
                match self.peek()? {
                    b',' => self.i += 1,
                    b'}' => {
                        self.i += 1;
                        return Some(J::Obj(kv));
                    }
                    _ => return None,
                }
            }
        }
        fn array(&mut self) -> Option<J> {
            self.i += 1; // [
            let mut items = Vec::new();
            self.ws();
            if self.peek() == Some(b']') {
                self.i += 1;
                return Some(J::Arr(items));
            }
            loop {
                let v = self.value()?;
                items.push(v);
                self.ws();
                match self.peek()? {
                    b',' => self.i += 1,
                    b']' => {
                        self.i += 1;
                        return Some(J::Arr(items));
                    }
                    _ => return None,
                }
            }
        }
    }
}
