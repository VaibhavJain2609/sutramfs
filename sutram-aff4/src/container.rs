//! [`Aff4Container`] — a read-only AFF4-L evidence container.
//!
//! An AFF4-L container is a ZIP archive of *stored* (uncompressed) members
//! carrying evidence files plus an `information.turtle` RDF manifest that
//! records, per member subject IRI, the hash URNs the acquirer computed
//! (`<aff4://uuid/member> aff4:hash <aff4:sha256=…>`), a
//! `container.description` member naming the container ARN, and a
//! `version.txt` member naming the spec version.
//!
//! The ZIP layer is [`sutram_archive::ZipParser`] (via the `sutram-fs`
//! `FileSystem` contract): members are indexed from its walk stream with
//! their absolute zip-record offsets for provenance, and content is read
//! through `read_file` so stored members come back byte-for-byte.

use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use sutram_archive::ZipParser;
use sutram_fs::{DetectConfidence, EntryKind, FsEntry, FsError, FsParser, Result};
use sutram_io::{into_arc, ByteSource, FileSource};

use crate::manifest::{
    extract_manifest, subject_matches, HashAlgorithm, ManifestSubject, StoredHash,
};
use crate::sha256::sha256_reader_hex;

/// Bytes of tail scanned by [`Aff4Container::detect`] for AFF4 member
/// names in the central directory. Larger than the ZIP EOCD window so a
/// moderately large CD still exposes `information.turtle`.
const DETECT_WINDOW: u64 = 256 * 1024;

/// Upper bound on manifest bytes read per `information.turtle` member —
/// a manifest is metadata; anything bigger is almost certainly hostile
/// or misnamed and is parsed truncated (the extractor tolerates it).
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

/// What a zip member is *for* in an AFF4-L container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberRole {
    /// An evidence file (or other payload) — the reason the container exists.
    Evidence,
    /// `information.turtle` (or an `information.<n>.turtle` segment) —
    /// the RDF manifest.
    Manifest,
    /// `container.description` — holds the container ARN.
    ContainerDescription,
    /// `version.txt` — holds the AFF4 spec version.
    VersionTxt,
}

/// Why [`Aff4Container::verify`] could not produce a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotVerifiable {
    /// The container has no usable `information.turtle`, or it failed to
    /// parse far enough to record this member's hashes.
    NoManifest,
    /// The manifest records no hash for this member.
    NoStoredHash,
    /// Hashes were recorded but none use an algorithm this crate can
    /// recompute (only `sha256` today). Carries the algorithm list.
    UnsupportedAlgorithm(String),
    /// A hash was recorded but its value is not well-formed hex for the
    /// algorithm — a manifest defect, *not* evidence of tampering.
    MalformedHash(String),
    /// The member is not a regular file (directory, symlink, …).
    NotARegularMember,
}

/// Outcome of [`Aff4Container::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// Every recorded hash of a supported algorithm recomputed correctly.
    Verified {
        /// Algorithm that verified (SHA-256).
        algorithm: HashAlgorithm,
        /// The recomputed lowercase hex digest.
        digest: String,
    },
    /// A recorded hash disagrees with the member's bytes — the member was
    /// modified after acquisition (or the manifest/zip is corrupt).
    Mismatch {
        /// Algorithm that was checked.
        algorithm: HashAlgorithm,
        /// Hash as recorded in the manifest.
        expected: String,
        /// Hash recomputed from member bytes.
        computed: String,
    },
    /// Verification was impossible — see the reason. Absence of a
    /// verdict is a statement about the *container*, not the member.
    NotAvailable(NotVerifiable),
}

impl Verification {
    /// `true` only when a recorded hash recomputed correctly.
    pub fn is_verified(&self) -> bool {
        matches!(self, Verification::Verified { .. })
    }
}

/// State of the `information.turtle` manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestStatus {
    /// At least one manifest member parsed.
    Parsed {
        /// Turtle statements scanned.
        statements: usize,
        /// Distinct subjects that carried ≥1 hash.
        hashed_subjects: usize,
    },
    /// No `information.turtle` member exists — degraded mode: members
    /// still list/extract, but nothing can be hash-verified.
    Absent,
    /// A manifest member existed but could not be read or yielded no
    /// usable statements. `recovered_subjects` counts what was salvaged.
    Malformed {
        /// What went wrong.
        note: String,
        /// Subjects with hashes recovered despite the defect.
        recovered_subjects: usize,
    },
}

impl ManifestStatus {
    /// `true` when a manifest was found and parsed.
    pub fn is_parsed(&self) -> bool {
        matches!(self, ManifestStatus::Parsed { .. })
    }
}

/// One zip member of the container, indexed at open time.
///
/// `member_offset` is the absolute byte offset of the zip record that
/// produced this entry (central-directory record for live members, local
/// file header for hidden/unreferenced ones) — the provenance citation.
#[derive(Debug, Clone)]
pub struct Aff4Member {
    /// Zip member name, verbatim (`dir/evidence.bin`).
    pub name: String,
    /// Manifest subject IRI describing this member (percent-decoded form
    /// as recorded), when the manifest named it.
    pub arn: Option<String>,
    /// Logical size in bytes.
    pub size: u64,
    /// Absolute offset of the zip record (provenance).
    pub member_offset: u64,
    /// Absolute `(offset, len)` extents of the member's stored bytes.
    pub data_ranges: Vec<(u64, u64)>,
    /// Entry kind from the zip layer (`File`, `Directory`, …).
    pub kind: EntryKind,
    /// AFF4 role of this member.
    pub role: MemberRole,
    /// Hashes the manifest recorded for this member (may be empty).
    pub stored_hashes: Vec<StoredHash>,
    /// The underlying forensic entry (status, timestamps, magic verdict,
    /// zip anomaly meta) — kept for `extract`/`verify` and exposed via
    /// [`Aff4Member::entry`].
    entry: FsEntry,
}

impl Aff4Member {
    /// The underlying `sutram-fs` entry — carries `disk_offset`,
    /// `allocated_ranges`, MACB timestamps, `meta["anomaly"]`,
    /// `meta["hidden_entry"]` and the magic verdict.
    pub fn entry(&self) -> &FsEntry {
        &self.entry
    }

    /// `true` when this member is an evidence file (not a manifest,
    /// description, version marker, or directory).
    pub fn is_evidence(&self) -> bool {
        self.role == MemberRole::Evidence && self.kind == EntryKind::File
    }
}

/// A parsed AFF4-L container. Degraded by design: a zip that lacks or
/// corrupts its manifest still opens — `manifest_status()` reports the
/// state and `verify()` returns [`Verification::NotAvailable`].
pub struct Aff4Container {
    fs: Box<dyn sutram_fs::FileSystem>,
    members: Vec<Aff4Member>,
    manifest: ManifestStatus,
    /// Manifest subjects (with hashes) that matched no member — the
    /// manifest claims files the container does not hold.
    unmatched_subjects: Vec<ManifestSubject>,
    /// Scratch for the open pipeline (`read_manifest` fills, `link_manifest`
    /// consumes). Always empty after `open` returns.
    manifest_subjects: Vec<ManifestSubject>,
    /// Container ARN from `container.description`, when present/readable.
    container_arn: Option<String>,
    /// Spec version string from `version.txt`, when present/readable.
    aff4_version: Option<String>,
    /// Non-fatal problems seen while opening (walk errors, unreadable
    /// manifests, …). Empty on a clean container.
    warnings: Vec<String>,
}

impl Aff4Container {
    /// Open an AFF4-L container over any [`ByteSource`].
    ///
    /// `src` may be a `Vec<u8>`, `&[u8]`, `File`, `FileSource` or an
    /// `Arc<dyn ByteSource>`. Fails only when the source is not a usable
    /// ZIP archive; a missing/broken manifest is *not* an error.
    pub fn open<S: ByteSource + 'static>(src: S) -> Result<Self> {
        Self::open_arc(into_arc(src))
    }

    /// Open over a shared source (avoids the double-`Arc` of [`Self::open`]).
    pub fn open_arc(src: Arc<dyn ByteSource>) -> Result<Self> {
        let fs = ZipParser.mount(src)?;
        Self::from_mounted(fs)
    }

    /// Open a container file by path.
    pub fn open_path(path: impl AsRef<Path>) -> Result<Self> {
        let fs = FileSource::open(path).map_err(FsError::Io)?;
        Self::open(fs)
    }

    /// Cheap probe: `Certain`-ish when the tail window shows AFF4 marker
    /// member names inside an otherwise valid ZIP.
    ///
    /// Bounded — reads at most [`DETECT_WINDOW`] tail bytes. A plain ZIP
    /// (no markers) reports `Low`; non-ZIP reports `None`.
    pub fn detect(src: &dyn ByteSource) -> DetectConfidence {
        if ZipParser.detect(src) < DetectConfidence::Medium {
            return DetectConfidence::None;
        }
        let len = src.len();
        let start = len.saturating_sub(DETECT_WINDOW);
        let Ok(win) = src.read_slice(start, (len - start) as usize) else {
            return DetectConfidence::Low;
        };
        if find_sub(&win, b"information.turtle").is_some()
            || find_sub(&win, b"container.description").is_some()
        {
            DetectConfidence::High
        } else {
            // A real AFF4-L names its manifest in the central directory —
            // nothing found, but it is at least a mountable zip.
            DetectConfidence::Low
        }
    }

    /// Build from an already-mounted ZIP filesystem.
    fn from_mounted(fs: Box<dyn sutram_fs::FileSystem>) -> Result<Self> {
        let mut warnings = Vec::new();
        let mut members: Vec<Aff4Member> = Vec::new();
        for item in fs.walk() {
            match item {
                Ok(e) => {
                    // Real zip members carry their member index as
                    // entry_id; the synthetic root/implied directories use
                    // u64::MAX. The path check is belt-and-braces.
                    if e.entry_id == u64::MAX || e.path == "/" {
                        continue;
                    }
                    members.push(member_from_entry(e));
                }
                Err(e) => warnings.push(format!("zip walk: {e}")),
            }
        }

        let mut c = Aff4Container {
            fs,
            members,
            manifest: ManifestStatus::Absent,
            unmatched_subjects: Vec::new(),
            manifest_subjects: Vec::new(),
            container_arn: None,
            aff4_version: None,
            warnings,
        };
        c.read_container_metadata();
        c.read_manifest();
        c.link_manifest();
        Ok(c)
    }

    /// Pull `container.description` / `version.txt` contents.
    fn read_container_metadata(&mut self) {
        for m in &self.members {
            match m.role {
                MemberRole::ContainerDescription => {
                    self.container_arn = self.read_member_text(m, 4096).and_then(|t| {
                        t.lines()
                            .map(str::trim)
                            .find(|l| !l.is_empty())
                            .map(str::to_string)
                    });
                }
                MemberRole::VersionTxt => {
                    self.aff4_version = self
                        .read_member_text(m, 256)
                        .map(|t| t.trim().to_string());
                }
                _ => {}
            }
        }
    }

    /// Parse every `information[.*].turtle` member into the subject/hash
    /// table. All manifest members contribute; a partially unreadable one
    /// degrades to `Malformed` while the rest still apply.
    fn read_manifest(&mut self) {
        let manifest_idx: Vec<usize> = self
            .members
            .iter()
            .enumerate()
            .filter(|(_, m)| m.role == MemberRole::Manifest)
            .map(|(i, _)| i)
            .collect();
        if manifest_idx.is_empty() {
            self.manifest = ManifestStatus::Absent;
            self.manifest_subjects = Vec::new();
            return;
        }

        let mut subjects: Vec<ManifestSubject> = Vec::new();
        let mut statements = 0usize;
        let mut notes: Vec<String> = Vec::new();
        for idx in &manifest_idx {
            let m = &self.members[*idx];
            match self.read_member_text(m, MAX_MANIFEST_BYTES) {
                Some(text) => {
                    let parsed = extract_manifest(&text);
                    statements += parsed.statements;
                    notes.extend(parsed.notes);
                    subjects.extend(parsed.subjects);
                }
                None => {
                    notes.push(format!("manifest member {:?} unreadable", m.name));
                }
            }
        }
        let hashed = subjects.iter().filter(|s| !s.hashes.is_empty()).count();
        if statements == 0 {
            self.manifest = ManifestStatus::Malformed {
                note: notes
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "no parseable turtle statements".into()),
                recovered_subjects: hashed,
            };
        } else {
            if !notes.is_empty() {
                self.warnings
                    .push(format!("manifest parse notes: {}", notes.join("; ")));
            }
            self.manifest = ManifestStatus::Parsed {
                statements,
                hashed_subjects: hashed,
            };
        }
        self.manifest_subjects = subjects;
    }

    /// Attach extracted manifest hashes to the members they name.
    fn link_manifest(&mut self) {
        let subjects = std::mem::take(&mut self.manifest_subjects);
        for sub in subjects {
            let mut hit = false;
            for m in &mut self.members {
                if subject_matches(&sub.subject, &m.name) {
                    m.arn = Some(sub.subject.clone());
                    m.stored_hashes = sub.hashes.clone();
                    hit = true;
                    break;
                }
            }
            if !hit && !sub.hashes.is_empty() {
                // Manifest claims a file the container does not hold —
                // worth surfacing to the examiner.
                self.unmatched_subjects.push(sub);
            }
        }
    }

    /// Read a member as text, size-capped. `None` on any read failure.
    fn read_member_text(&self, m: &Aff4Member, cap: u64) -> Option<String> {
        let r = self.fs.read_file(&m.entry).ok()?;
        let mut buf = Vec::new();
        r.take(cap).read_to_end(&mut buf).ok()?;
        Some(String::from_utf8_lossy(&buf).into_owned())
    }

    // -- public surface ----------------------------------------------------

    /// All zip members, in central-directory order.
    pub fn members(&self) -> &[Aff4Member] {
        &self.members
    }

    /// Evidence-file members only (manifest/description/version excluded).
    pub fn evidence_members(&self) -> impl Iterator<Item = &Aff4Member> {
        self.members.iter().filter(|m| m.is_evidence())
    }

    /// Find a member by verbatim zip name (a leading `/` is tolerated).
    pub fn member(&self, name: &str) -> Option<&Aff4Member> {
        let name = name.trim_start_matches('/');
        self.members.iter().find(|m| m.name == name)
    }

    /// Container ARN from `container.description`, if present.
    pub fn container_arn(&self) -> Option<&str> {
        self.container_arn.as_deref()
    }

    /// AFF4 spec version string from `version.txt`, if present.
    pub fn aff4_version(&self) -> Option<&str> {
        self.aff4_version.as_deref()
    }

    /// Manifest state — see [`ManifestStatus`].
    pub fn manifest_status(&self) -> &ManifestStatus {
        &self.manifest
    }

    /// Manifest subjects carrying hashes that matched **no** member —
    /// the manifest claims files absent from the container.
    pub fn unmatched_subjects(&self) -> &[ManifestSubject] {
        &self.unmatched_subjects
    }

    /// Non-fatal problems observed while opening.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// A streaming reader over the member's bytes (stored data verbatim
    /// for conformant AFF4-L members; decompressed if a non-conformant
    /// writer used deflate).
    pub fn open_member(&self, m: &Aff4Member) -> Result<Box<dyn Read + Send>> {
        self.fs.read_file(&m.entry)
    }

    /// The member's whole contents as bytes. Buffers the member —
    /// evidence files can be large; prefer [`Self::open_member`] when you
    /// only need a prefix or a streaming pass.
    pub fn extract(&self, m: &Aff4Member) -> Result<Vec<u8>> {
        let mut r = self.open_member(m)?;
        let mut v = Vec::with_capacity(m.size.min(16 * 1024 * 1024) as usize);
        r.read_to_end(&mut v).map_err(FsError::Io)?;
        Ok(v)
    }

    /// Recompute the member's digest and compare against the manifest.
    ///
    /// Semantics:
    /// * `Verified` — every recorded hash of a supported algorithm
    ///   (SHA-256 today) recomputed correctly.
    /// * `Mismatch` — a recorded supported hash disagrees.
    /// * `NotAvailable` — no usable hash exists; the reason distinguishes
    ///   missing manifest, missing hash, malformed hash value, and
    ///   algorithms this crate cannot compute (`sha1`/`sha512`/`md5`).
    pub fn verify(&self, m: &Aff4Member) -> Result<Verification> {
        if m.kind != EntryKind::File {
            return Ok(Verification::NotAvailable(NotVerifiable::NotARegularMember));
        }
        if m.stored_hashes.is_empty() {
            let reason = match self.manifest {
                ManifestStatus::Parsed { .. } => NotVerifiable::NoStoredHash,
                _ => NotVerifiable::NoManifest,
            };
            return Ok(Verification::NotAvailable(reason));
        }
        if m.stored_hashes.iter().any(|h| h.malformed) {
            let bad = m
                .stored_hashes
                .iter()
                .find(|h| h.malformed)
                .map(|h| h.urn.clone())
                .unwrap_or_default();
            return Ok(Verification::NotAvailable(NotVerifiable::MalformedHash(bad)));
        }
        let supported: Vec<&StoredHash> = m
            .stored_hashes
            .iter()
            .filter(|h| h.algorithm.supported())
            .collect();
        if supported.is_empty() {
            let algos = m
                .stored_hashes
                .iter()
                .map(|h| h.algorithm.name().to_string())
                .collect::<Vec<_>>()
                .join(",");
            return Ok(Verification::NotAvailable(
                NotVerifiable::UnsupportedAlgorithm(algos),
            ));
        }
        // Single streaming pass; every supported hash shares the digest.
        let digest = sha256_reader_hex(self.open_member(m)?).map_err(FsError::Io)?;
        for h in &supported {
            if !h.value.eq_ignore_ascii_case(&digest) {
                return Ok(Verification::Mismatch {
                    algorithm: h.algorithm.clone(),
                    expected: h.value.clone(),
                    computed: digest,
                });
            }
        }
        Ok(Verification::Verified {
            algorithm: supported[0].algorithm.clone(),
            digest,
        })
    }

    /// Verify every member. Results are aligned with [`Self::members`];
    /// per-member read failures surface as `Err` items, not aborts.
    pub fn verify_all(&self) -> Vec<Result<Verification>> {
        self.members.iter().map(|m| self.verify(m)).collect()
    }
}

/// Substring scan (used by `detect` — avoids a regex dep).
fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Map a zip-layer [`FsEntry`] to an [`Aff4Member`].
fn member_from_entry(e: FsEntry) -> Aff4Member {
    // The verbatim zip member name: `meta["raw_name"]` when sanitisation
    // changed it, else the path with its leading `/` stripped.
    let name = e
        .meta
        .get("raw_name")
        .cloned()
        .unwrap_or_else(|| e.path.trim_start_matches('/').to_string());
    let base = name.rsplit('/').next().unwrap_or(&name);
    let role = if base == "container.description" {
        MemberRole::ContainerDescription
    } else if base == "version.txt" {
        MemberRole::VersionTxt
    } else if base == "information.turtle"
        || (base.starts_with("information.") && base.ends_with(".turtle"))
    {
        MemberRole::Manifest
    } else {
        MemberRole::Evidence
    };
    Aff4Member {
        name,
        arn: None,
        size: e.size,
        member_offset: e.disk_offset,
        data_ranges: e.allocated_ranges.clone(),
        kind: e.kind,
        role,
        stored_hashes: Vec::new(),
        entry: e,
    }
}
