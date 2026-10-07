//! Core record types: [`FsEntry`], [`FsTimestamp`], [`FsInfo`], carving and
//! recovery types.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use sutram_magic::MagicVerdict;

/// How strongly `detect` believes a source holds this filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DetectConfidence {
    /// Definitely not this filesystem.
    None,
    /// Weak hints only (e.g. signature ambiguous).
    Low,
    /// Boot/superblock validates structurally.
    Medium,
    /// Strong signature match (magic + version + geometry sanity).
    High,
    /// All checks pass; safe to mount without prompting.
    Certain,
}

/// What kind of node an [`FsEntry`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    /// Regular file.
    File,
    /// Directory.
    Directory,
    /// Symbolic link — target in `meta["symlink_target"]` when stored.
    Symlink,
    /// Something else (device node, socket, orphan record, …); see `meta`.
    Other,
}

/// How much of a deleted entry's data survives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryState {
    /// Metadata *and* all data extents appear intact.
    Intact,
    /// Some data survives. `recovered_bytes`/`total_bytes` quantify it;
    /// `FsEntry::allocated_ranges` lists exactly which extents remain.
    PartiallyOverwritten {
        /// Bytes still recoverable.
        recovered_bytes: u64,
        /// Original file size.
        total_bytes: u64,
    },
    /// Metadata survives but no data extent is recoverable.
    Unrecoverable,
    /// Could not determine (parser lacks information to decide).
    Unknown,
}

/// Live or deleted — every entry carries its forensic state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FsEntryStatus {
    /// Reachable from the live directory tree.
    Live,
    /// Marked deleted / unreachable, with a recoverability assessment.
    Deleted {
        /// How much data survives.
        recovery: RecoveryState,
    },
}

/// One timestamp as stored on disk, with its provenance.
#[derive(Debug, Clone)]
pub struct FsTimestamp {
    /// Nanoseconds since the Unix epoch (UTC). `None` when the field is
    /// unset/zero or unrepresentable — parsers must not fabricate times.
    pub value: Option<i64>,
    /// Raw on-disk value (the packed integer before decoding), for
    /// byte-level citation.
    pub raw_value: u64,
    /// Machine-readable encoding name, e.g. `"fat-dos-datetime"`,
    /// `"ntfs-filetime"`, `"unix-sec"`, `"apfs-nano"`.
    pub raw_encoding: &'static str,
    /// Resolution of the on-disk field (FAT write time = 2 s, FAT create
    /// time = 10 ms, FAT access date = 1 day, NTFS = 100 ns, …).
    pub granularity: Duration,
}

/// MACB-style timestamp set. Every slot a format stores must be populated
/// (with `value: None` if unset); slots the format does not store are
/// `None` themselves.
#[derive(Debug, Clone, Default)]
pub struct Timestamps {
    /// Content modified (**M**).
    pub modified: Option<FsTimestamp>,
    /// Last accessed (**A**).
    pub accessed: Option<FsTimestamp>,
    /// Created / birth (**B**).
    pub created: Option<FsTimestamp>,
    /// Metadata changed (**C** — e.g. ext `ctime`, NTFS MFT change).
    pub changed: Option<FsTimestamp>,
    /// Deletion time where the format records one (ext4 `dtime`).
    pub deleted: Option<FsTimestamp>,
}

/// One filesystem node (file, directory, deleted artefact, orphan).
///
/// Provenance contract:
/// * `disk_offset` — byte offset of the metadata record that produced this
///   entry (dir-entry, inode, MFT record, …).
/// * `allocated_ranges` — the data extents, as absolute `(offset, len)`
///   byte ranges; for deleted entries, the *still-recoverable* extents.
#[derive(Debug, Clone)]
pub struct FsEntry {
    /// Full path from the filesystem root (`/``-joined, components
    /// sanitised). Orphans live under `$ORPHANED/` or `$LOST/` per
    /// CONVENTIONS.md.
    pub path: String,
    /// Basename (`/` for root).
    pub name: String,
    /// Format-specific stable identifier (inode number, MFT entry, dir-slot
    /// index, first cluster) — used by `read_file` and for dedup.
    pub entry_id: u64,
    /// Node kind.
    pub kind: EntryKind,
    /// Logical size in bytes.
    pub size: u64,
    /// Absolute byte offset of the on-disk metadata record.
    pub disk_offset: u64,
    /// Data extents as absolute `(byte_offset, byte_len)` ranges on the
    /// mounted source. For deleted entries: only extents that still hold
    /// recoverable data.
    pub allocated_ranges: Vec<(u64, u64)>,
    /// MACB+ timestamps.
    pub timestamps: Timestamps,
    /// Live / deleted with recoverability.
    pub status: FsEntryStatus,
    /// Format-specific extras: attributes, owner, LFN checksums, slack
    /// size (`slack_bytes`/`slack_offset`/`slack_len`), orphan flag, …
    /// Keys are `snake_case`; document new keys in CONVENTIONS.md.
    pub meta: HashMap<String, String>,
    /// Extension↔content verdict from `sutram-magic`, when the parser read
    /// the file's header (usually for `File` kind only).
    pub magic: Option<MagicVerdict>,
}

impl FsEntry {
    /// `true` when the entry is a deleted artefact.
    pub fn is_deleted(&self) -> bool {
        matches!(self.status, FsEntryStatus::Deleted { .. })
    }
}

/// Mounted-filesystem summary from [`crate::FileSystem::info`].
#[derive(Debug, Clone, Default)]
pub struct FsInfo {
    /// Parser name, e.g. `"FAT32"`, `"NTFS"`, `"ext4"`.
    pub fs_type: String,
    /// Volume label if the format has one.
    pub label: Option<String>,
    /// Volume UUID/serial (hex or text) if the format has one.
    pub uuid: Option<String>,
    /// Allocation unit in bytes (cluster/block).
    pub block_size: u64,
    /// Total allocation units.
    pub total_blocks: u64,
    /// Free allocation units, when computable cheaply.
    pub free_blocks: Option<u64>,
    /// Total metadata slots (inodes/MFT entries/root slots), when known.
    pub total_nodes: Option<u64>,
    /// Format-specific extras (FAT count, journal state, feature flags…).
    pub meta: HashMap<String, String>,
}

/// A carved hit inside an unallocated region — produced by
/// [`crate::FileSystem::carve_region`].
#[derive(Debug, Clone)]
pub struct CarveHit {
    /// Absolute byte offset of the hit.
    pub offset: u64,
    /// Byte length of the carved extent — the object's real size when
    /// `exact` is set (footer/declared-size/structure-bounded), else the
    /// cap used (to-next-signature or per-type maximum).
    pub len: u64,
    /// What signature matched.
    pub kind: sutram_magic::MagicType,
    /// `true` when `len` is the object's actual extent (footer found,
    /// size field honoured, chunk chain walked); `false` when it was
    /// capped — the carve may be truncated.
    pub exact: bool,
    /// The leading bytes that produced the verdict (evidence excerpt;
    /// bounded — never the whole object).
    pub header: Vec<u8>,
}

/// Recovery bookkeeping for a deleted entry — returned by dedicated
/// recovery APIs and embedded in reports.
#[derive(Debug, Clone)]
pub struct RecoveryReport {
    /// The entry assessed.
    pub entry_id: u64,
    /// Computed recoverability.
    pub state: RecoveryState,
    /// Extents still containing original data.
    pub surviving_ranges: Vec<(u64, u64)>,
    /// Extents overwritten or lost.
    pub lost_ranges: Vec<(u64, u64)>,
    /// Human-readable notes (why it was judged partial/intact/lost).
    pub notes: Vec<String>,
}

impl fmt::Display for RecoveryState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecoveryState::Intact => write!(f, "intact"),
            RecoveryState::PartiallyOverwritten {
                recovered_bytes,
                total_bytes,
            } => write!(
                f,
                "partially overwritten ({recovered_bytes}/{total_bytes} bytes recoverable)"
            ),
            RecoveryState::Unrecoverable => write!(f, "unrecoverable"),
            RecoveryState::Unknown => write!(f, "unknown"),
        }
    }
}
