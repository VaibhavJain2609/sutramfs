//! NTFS journal forensics: `$UsnJrnl` change records and `$LogFile`.
//!
//! `$UsnJrnl:$J` (MFT record 12) holds a sparse stream of USN change
//! records — the filesystem's own audit log of which file changed, when,
//! and why. `USN_RECORD_V2` is little-endian:
//!
//! ```text
//! 0x00 u32 record_len     0x04 u16 major_ver  0x06 u16 minor_ver
//! 0x08 u64 file_ref       0x10 u64 parent_ref 0x18 i64 usn
//! 0x20 u64 filetime       0x28 u32 reason     0x2C u32 source_info
//! 0x30 u32 security_id    0x34 u32 file_attrs 0x38 u16 name_len
//! 0x3A u16 name_off       0x3C .. utf16 name
//! ```
//!
//! (v3 records carry 128-bit file references; the low 64 bits are kept.)
//!
//! `$LogFile` (record 2) is a 4 KiB-paged LFS log: `RSTR` restart pages
//! hold the restart area (checkpoint anchor), `RCRD` pages hold log
//! record headers, `CHKD` pages hold checkpoints and `BAAD` marks torn
//! writes — itself forensic evidence of the last in-flight operation.
//!
//! Both streams are **parsed, never replayed**: a USN record is evidence
//! a file changed, not a view of its data; a log record is a transaction
//! witness, not applied state.

use std::collections::VecDeque;

use sutram_fs::{FsError, Result};
use sutram_io::le;

/// Bound on `$UsnJrnl:$J` / `$LogFile` bytes materialised for scanning
/// (64 MiB — the crate's established stream cap). Larger journals stream
/// truncated with a `*_scan_truncated` meta note.
pub(crate) const MAX_JOURNAL_BYTES: u64 = 64 << 20;

/// NTFS log page size (LFS default).
const LOG_PAGE: usize = 0x1000;
/// Stream offset where log records begin inside an RCRD page.
const RCRD_DATA_OFF: usize = 0x40;
/// Offset of RESTART_AREA inside an RSTR page.
const RSTR_AREA_OFF: usize = 0x30;
/// Offset of the checkpoint record inside a CHKD page.
const CHKD_REC_OFF: usize = 0x30;
/// Fixed LOG_RECORD header span (through `mft_cluster_offset`).
const LOGREC_HDR: usize = 0x48;
/// USN records are 8-aligned and at least 64 bytes.
const USN_MIN: usize = 0x40;
/// Hostile-input bound on one USN record.
const USN_MAX: usize = 0x1_0000;
/// Bound on candidate-record probes per RCRD page.
const MAX_PAGE_PROBES: usize = 512;
/// Bound on client-data bytes retained per log record (u16 field, but a
/// hostile page could claim 64 KiB — still cheap, and `client_data_len`
/// is already validated against the page extent).
const MAX_CLIENT_DATA: usize = 0x1_0000;

// USN reason flags.
const REASONS: &[(u32, &str)] = &[
    (0x0000_0001, "data_overwrite"),
    (0x0000_0002, "data_extend"),
    (0x0000_0004, "data_truncation"),
    (0x0000_0010, "named_data_overwrite"),
    (0x0000_0020, "named_data_extend"),
    (0x0000_0040, "named_data_truncation"),
    (0x0000_0100, "file_create"),
    (0x0000_0200, "file_delete"),
    (0x0000_0400, "ea_change"),
    (0x0000_0800, "security_change"),
    (0x0000_1000, "rename_old_name"),
    (0x0000_2000, "rename_new_name"),
    (0x0000_4000, "indexable_change"),
    (0x0000_8000, "basic_info_change"),
    (0x0001_0000, "hard_link_change"),
    (0x0002_0000, "compression_change"),
    (0x0004_0000, "encryption_change"),
    (0x0008_0000, "object_id_change"),
    (0x0010_0000, "reparse_point_change"),
    (0x0020_0000, "stream_change"),
    (0x8000_0000, "close"),
];

/// Human-readable names of a USN record's reason flags (for meta).
pub fn reason_names(reason: u32) -> Vec<&'static str> {
    REASONS
        .iter()
        .filter(|(bit, _)| reason & bit != 0)
        .map(|(_, n)| *n)
        .collect()
}

/// One parsed USN change record — evidence that `file_ref` changed.
#[derive(Debug, Clone)]
pub struct UsnRecord {
    /// `record_len` as stored (hostile values are already validated).
    pub record_len: u32,
    pub major_version: u16,
    pub minor_version: u16,
    /// File reference (record number + sequence) of the changed file.
    pub file_ref: u64,
    /// File reference of the parent directory.
    pub parent_ref: u64,
    /// Update Sequence Number — the journal's own ordering.
    pub usn: i64,
    /// Event time as an NTFS FILETIME.
    pub filetime: u64,
    /// `USN_REASON_*` bits.
    pub reason: u32,
    /// `USN_SOURCE_*` flags.
    pub source_info: u32,
    pub security_id: u32,
    pub file_attributes: u32,
    /// UTF-16 filename carried by the record.
    pub name: String,
    /// Offset inside the `$J` stream.
    pub stream_offset: u64,
    /// Absolute disk offset when the stream's runs cover the record.
    pub disk_offset: Option<u64>,
}

/// Decode one USN record at `off` inside `buf`. Returns `None` when the
/// fixed header does not fit; the caller decides malformed vs padding.
fn parse_usn(buf: &[u8], off: usize, disk: Option<u64>) -> Result<UsnRecord> {
    let record_len = le::u32(buf, off).unwrap_or(0) as usize;
    if !(USN_MIN..=USN_MAX).contains(&record_len) {
        return Err(FsError::corrupt(
            disk.unwrap_or(0),
            format!("USN record at stream {off:#x}: hostile record_len {record_len}"),
        ));
    }
    let end = off + record_len;
    if end > buf.len() {
        return Err(FsError::truncated(
            disk.unwrap_or(0),
            (off + record_len) as u64,
            buf.len() as u64,
        ));
    }
    let r = &buf[off..end];
    let major = le::u16(r, 0x04).unwrap_or(0);
    let minor = le::u16(r, 0x06).unwrap_or(0);
    let (file_ref, parent_ref, usn, filetime, reason, source, secid, fattrs, noff) =
        match major {
            2 => (
                le::u64(r, 0x08).unwrap_or(0),
                le::u64(r, 0x10).unwrap_or(0),
                le::u64(r, 0x18).unwrap_or(0) as i64,
                le::u64(r, 0x20).unwrap_or(0),
                le::u32(r, 0x28).unwrap_or(0),
                le::u32(r, 0x2C).unwrap_or(0),
                le::u32(r, 0x30).unwrap_or(0),
                le::u32(r, 0x34).unwrap_or(0),
                0x3Cusize,
            ),
            // v3/v4: 128-bit refs — keep the low 64 bits + shift the tail.
            3 | 4 => (
                le::u64(r, 0x08).unwrap_or(0),
                le::u64(r, 0x18).unwrap_or(0),
                le::u64(r, 0x28).unwrap_or(0) as i64,
                le::u64(r, 0x30).unwrap_or(0),
                le::u32(r, 0x38).unwrap_or(0),
                le::u32(r, 0x3C).unwrap_or(0),
                le::u32(r, 0x40).unwrap_or(0),
                le::u32(r, 0x44).unwrap_or(0),
                0x4Cusize,
            ),
            other => {
                return Err(FsError::corrupt(
                    disk.unwrap_or(0),
                    format!("USN record at stream {off:#x}: unsupported major version {other}"),
                ))
            }
        };
    let name_len = le::u16(r, if major == 2 { 0x38 } else { 0x48 }).unwrap_or(0) as usize;
    let name_off = le::u16(r, if major == 2 { 0x3A } else { 0x4A }).unwrap_or(0) as usize;
    let name_off = if name_off == 0 { noff } else { name_off };
    let name_bytes = le::get(r, name_off, name_len).ok_or_else(|| FsError::Corrupt {
        offset: disk.unwrap_or(0),
        msg: format!("USN record at stream {off:#x}: filename escapes record"),
    })?;
    let name = String::from_utf16_lossy(
        &name_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<u16>>(),
    );
    Ok(UsnRecord {
        record_len: record_len as u32,
        major_version: major,
        minor_version: minor,
        file_ref,
        parent_ref,
        usn,
        filetime,
        reason,
        source_info: source,
        security_id: secid,
        file_attributes: fattrs,
        name,
        stream_offset: off as u64,
        disk_offset: disk,
    })
}

/// Iterator over USN records inside a materialised `$J` byte buffer.
/// Zero-filled regions (sparse holes, tail padding) are skipped;
/// malformed candidates yield `Err` and scanning resynchronises at the
/// next 8-byte boundary. In strict mode the first error ends the stream.
pub(crate) struct UsnIter {
    buf: Vec<u8>,
    /// `(logical_offset, disk_offset, len)` allocated regions of `$J`.
    regions: Vec<(u64, u64, u64)>,
    pos: usize,
    finished: bool,
    strict: bool,
}

impl UsnIter {
    pub(crate) fn new(buf: Vec<u8>, regions: Vec<(u64, u64, u64)>, strict: bool) -> Self {
        UsnIter {
            buf,
            regions,
            pos: 0,
            finished: false,
            strict,
        }
    }

    /// Disk offset of a `$J` stream offset, via allocated regions.
    fn disk_of(&self, logical: u64) -> Option<u64> {
        for &(lo, disk, len) in &self.regions {
            if logical >= lo && logical < lo.saturating_add(len) {
                return Some(disk + (logical - lo));
            }
        }
        None
    }
}

impl Iterator for UsnIter {
    type Item = Result<UsnRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        while self.pos + 8 <= self.buf.len() {
            let off = self.pos;
            let len = le::u32(&self.buf, off).unwrap_or(0) as usize;
            if len == 0 {
                self.pos += 8; // padding / sparse hole — skip
                continue;
            }
            match parse_usn(&self.buf, off, self.disk_of(off as u64)) {
                Ok(rec) => {
                    self.pos += rec.record_len.max(8) as usize;
                    return Some(Ok(rec));
                }
                Err(e) => {
                    self.pos += 8; // resynchronise at the next boundary
                    if self.strict {
                        self.finished = true;
                    }
                    return Some(Err(e));
                }
            }
        }
        self.finished = true;
        None
    }
}

/// Parsed LFS restart area (the checkpoint anchor of `$LogFile`).
#[derive(Debug, Clone)]
pub struct RestartArea {
    /// Highest LSN the checkpoint covers.
    pub current_lsn: u64,
    pub log_clients: u16,
    pub client_free_lsn_idx: u16,
    pub client_inuse_lsn_idx: u16,
    /// `seq_nr_bits` — the sequence-number bit count for LSN rotation.
    pub seq_nr_bits: u32,
    pub restart_area_len: u16,
    /// Logical `$LogFile` size recorded by the LFS.
    pub file_size: u64,
    pub last_lsn_data_len: u32,
    /// `record_page_len` — the log's record page unit.
    pub record_page_len: u16,
    /// Absolute disk offset of the restart page.
    pub disk_offset: u64,
}

/// Parsed LOG_RECORD header inside an RCRD page plus its bounded client
/// data (redo/undo buffers are *interpreted* by [`LogRecord::interpret`],
/// never applied).
#[derive(Debug, Clone)]
pub struct LogRecord {
    /// This record's log sequence number.
    pub this_lsn: u64,
    pub client_prev_lsn: u64,
    pub client_undo_next_lsn: u64,
    pub client_data_len: u16,
    pub record_type: u32,
    pub transaction_id: u32,
    pub flags: u16,
    pub redo_op: u16,
    pub undo_op: u16,
    /// Byte offset of the redo payload within `client_data`.
    pub redo_offset: u16,
    pub redo_len: u16,
    /// Byte offset of the undo payload within `client_data`.
    pub undo_offset: u16,
    pub undo_len: u16,
    /// Offset of the attribute the record targets inside the file record.
    pub target_attribute: u16,
    /// Number of LCNs listed after the fixed header (targets of a
    /// multi-cluster write).
    pub lcns_to_follow: u16,
    /// Offset of this record within its page (LFS bookkeeping).
    pub record_offset: u16,
    /// Offset of the affected attribute-list entry, when the record
    /// concerns an attribute list.
    pub attr_list_offset: u16,
    /// VCN within `$MFT`'s data holding the target file-record segment —
    /// the record number's cluster-granular anchor.
    pub mft_cluster_index: u64,
    /// The client-data area (redo/undo payloads), bounded by
    /// [`MAX_CLIENT_DATA`].
    pub client_data: Vec<u8>,
    /// Absolute disk offset of the record header.
    pub disk_offset: Option<u64>,
    /// Computed record extent (header + lcn list + client data, aligned).
    pub extent: usize,
}

/// The redo operation a `$LogFile` record performs (the `redo_op` /
/// `undo_op` code table — ntfsdoc "Log Record Operation Codes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogOp {
    Noop,
    /// A compensation record — undoes a named earlier operation.
    CompensationLogRecord,
    /// Initialise a file-record segment (a new/reused MFT slot).
    InitializeFileRecordSegment,
    /// Free a file-record segment (the MFT slot is being deallocated).
    DeallocateFileRecordSegment,
    /// Write the trailer of a file-record segment.
    WriteEndOfFileRecordSegment,
    /// Insert an attribute into a file record.
    CreateAttribute,
    /// Remove an attribute from a file record.
    DeleteAttribute,
    /// Rewrite a resident attribute's content (a.k.a.
    /// `SetResidentAttributeContent`).
    UpdateResidentValue,
    /// Rewrite non-resident clusters' content.
    UpdateNonresidentValue,
    /// Replace a non-resident attribute's runlist (mapping pairs).
    UpdateMappingPairs,
    /// Drop dirty clusters from a runlist tail.
    DeleteDirtyClusters,
    /// Record new allocated/real sizes for an attribute.
    SetNewAttributeSizes,
    /// Insert an index entry into the resident index root ($I30 creates).
    AddIndexEntryRoot,
    /// Remove an index entry from the index root ($I30 deletes).
    DeleteIndexEntryRoot,
    /// Insert an index entry into an index-allocation block.
    AddIndexEntryAllocation,
    /// Remove an index entry from an index-allocation block.
    DeleteIndexEntryAllocation,
    /// Rewrite the VCN stored in an index-root entry (a directory index
    /// tree reshuffle).
    SetIndexEntryVcnRoot,
    /// Same, inside an index-allocation block.
    SetIndexEntryVcnAllocation,
    /// Update a $FILE_NAME attribute in the index root.
    UpdateFileNameRoot,
    /// Update a $FILE_NAME attribute in an index-allocation block.
    UpdateFileNameAllocation,
    /// Set bits in a non-resident $BITMAP (allocation log).
    SetBitsInNonresidentBitmap,
    /// Clear bits in a non-resident $BITMAP (freeing clusters).
    ClearBitsInNonresidentBitmap,
    /// Sector relocation (bad-cluster remapping).
    HotFix,
    /// End of a top-level action — the transaction committed.
    EndTopLevelAction,
    PrepareTransaction,
    CommitTransaction,
    ForgetTransaction,
    /// Open a non-resident attribute (attribute-table maintenance).
    OpenNonresidentAttribute,
    OpenAttributeTableDump,
    AttributeNameDump,
    DirtyPageTableDump,
    TransactionTableDump,
    UpdateRecordDataRoot,
    UpdateRecordDataAllocation,
    /// A code outside the documented table.
    Unknown(u16),
}

impl LogOp {
    /// Decode a raw `redo_op`/`undo_op` code.
    pub fn from_code(code: u16) -> LogOp {
        use LogOp::*;
        match code {
            0x00 => Noop,
            0x01 => CompensationLogRecord,
            0x02 => InitializeFileRecordSegment,
            0x03 => DeallocateFileRecordSegment,
            0x04 => WriteEndOfFileRecordSegment,
            0x05 => CreateAttribute,
            0x06 => DeleteAttribute,
            0x07 => UpdateResidentValue,
            0x08 => UpdateNonresidentValue,
            0x09 => UpdateMappingPairs,
            0x0A => DeleteDirtyClusters,
            0x0B => SetNewAttributeSizes,
            0x0C => AddIndexEntryRoot,
            0x0D => DeleteIndexEntryRoot,
            0x0E => AddIndexEntryAllocation,
            0x0F => DeleteIndexEntryAllocation,
            0x10 => SetIndexEntryVcnRoot,
            0x11 => SetIndexEntryVcnAllocation,
            0x12 => UpdateFileNameRoot,
            0x13 => UpdateFileNameAllocation,
            0x14 => SetBitsInNonresidentBitmap,
            0x15 => ClearBitsInNonresidentBitmap,
            0x16 => HotFix,
            0x17 => EndTopLevelAction,
            0x18 => PrepareTransaction,
            0x19 => CommitTransaction,
            0x1A => ForgetTransaction,
            0x1B => OpenNonresidentAttribute,
            0x1C => OpenAttributeTableDump,
            0x1D => AttributeNameDump,
            0x1E => DirtyPageTableDump,
            0x1F => TransactionTableDump,
            0x20 => UpdateRecordDataRoot,
            0x21 => UpdateRecordDataAllocation,
            c => Unknown(c),
        }
    }

    /// Stable snake_case name for `meta` values.
    pub fn name(self) -> &'static str {
        use LogOp::*;
        match self {
            Noop => "noop",
            CompensationLogRecord => "compensation_log_record",
            InitializeFileRecordSegment => "initialize_file_record_segment",
            DeallocateFileRecordSegment => "deallocate_file_record_segment",
            WriteEndOfFileRecordSegment => "write_end_of_file_record_segment",
            CreateAttribute => "create_attribute",
            DeleteAttribute => "delete_attribute",
            UpdateResidentValue => "update_resident_value",
            UpdateNonresidentValue => "update_nonresident_value",
            UpdateMappingPairs => "update_mapping_pairs",
            DeleteDirtyClusters => "delete_dirty_clusters",
            SetNewAttributeSizes => "set_new_attribute_sizes",
            AddIndexEntryRoot => "add_index_entry_root",
            DeleteIndexEntryRoot => "delete_index_entry_root",
            AddIndexEntryAllocation => "add_index_entry_allocation",
            DeleteIndexEntryAllocation => "delete_index_entry_allocation",
            SetIndexEntryVcnRoot => "set_index_entry_vcn_root",
            SetIndexEntryVcnAllocation => "set_index_entry_vcn_allocation",
            UpdateFileNameRoot => "update_file_name_root",
            UpdateFileNameAllocation => "update_file_name_allocation",
            SetBitsInNonresidentBitmap => "set_bits_in_nonresident_bitmap",
            ClearBitsInNonresidentBitmap => "clear_bits_in_nonresident_bitmap",
            HotFix => "hot_fix",
            EndTopLevelAction => "end_top_level_action",
            PrepareTransaction => "prepare_transaction",
            CommitTransaction => "commit_transaction",
            ForgetTransaction => "forget_transaction",
            OpenNonresidentAttribute => "open_nonresident_attribute",
            OpenAttributeTableDump => "open_attribute_table_dump",
            AttributeNameDump => "attribute_name_dump",
            DirtyPageTableDump => "dirty_page_table_dump",
            TransactionTableDump => "transaction_table_dump",
            UpdateRecordDataRoot => "update_record_data_root",
            UpdateRecordDataAllocation => "update_record_data_allocation",
            Unknown(_) => "unknown",
        }
    }

    /// `true` for the index-entry insert/remove family — the payload is a
    /// `$I30` INDEX_ENTRY carrying a whole $FILE_NAME.
    fn is_index_entry_op(self) -> bool {
        matches!(
            self,
            LogOp::AddIndexEntryRoot
                | LogOp::DeleteIndexEntryRoot
                | LogOp::AddIndexEntryAllocation
                | LogOp::DeleteIndexEntryAllocation
        )
    }
}

/// What a `$LogFile` record's payload says — targets recovered by
/// interpreting redo/undo buffers (still read-only: evidence, not replay).
#[derive(Debug, Clone)]
pub struct LogInterpret {
    /// Decoded redo/undo operation classes.
    pub redo_op: LogOp,
    pub undo_op: LogOp,
    /// Human-readable detail ("mft 20 attr 0x30 delete", "i30 'X.TXT'").
    pub detail: String,
    /// MFT record number the operation targets. Exact when a FILE header
    /// or index entry survives in the payload; otherwise the first record
    /// of `mft_cluster_index`'s cluster (a lower bound — flagged by
    /// `record_is_bound`).
    pub mft_record: Option<u64>,
    /// `true` when `mft_record` is the cluster-floor estimate, not exact.
    pub record_is_bound: bool,
    /// Filename recovered from the payload ($I30 index entry, $FILE_NAME
    /// update, or a created/deleted named attribute).
    pub file_name: Option<String>,
    /// Parent file reference from an embedded $FILE_NAME / index entry.
    pub parent_ref: Option<u64>,
    /// File reference the index entry pointed at (the indexed child).
    pub child_ref: Option<u64>,
    /// Attribute type code touched (`$FILE_NAME` = 0x30, …).
    pub attr_type: Option<u32>,
    /// Named attribute's decoded name, when the payload carries one.
    pub attr_name: Option<String>,
}

/// Read a length-prefixed UTF-16LE name at `buf[off]` (`name_len` u8
/// count, then that many u16s) — the tail of a $FILE_NAME body or an
/// attribute header's name field.
fn utf16_name(buf: &[u8], count_off: usize, chars_off: usize) -> Option<String> {
    let n = *buf.get(count_off)? as usize;
    let bytes = le::get(buf, chars_off, n.checked_mul(2)?)?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// Parse a $FILE_NAME body: `(parent_ref, name)`.
fn parse_file_name(b: &[u8]) -> Option<(u64, String)> {
    if b.len() < 0x42 {
        return None;
    }
    let parent = le::u64(b, 0x00).unwrap_or(0);
    let name = utf16_name(b, 0x40, 0x42)?;
    Some((parent, name))
}

/// Parse an INDEX_ENTRY (`file_ref, entry_len, stream_len, flags, stream`)
/// — the payload of AddIndexEntry*/DeleteIndexEntry* records. Returns
/// `(child_ref, parent_ref, name)` when the stream is a $FILE_NAME.
fn parse_index_entry(b: &[u8]) -> Option<(u64, u64, String)> {
    if b.len() < 0x10 + 0x42 {
        return None;
    }
    let child = le::u64(b, 0x00).unwrap_or(0);
    let entry_len = le::u16(b, 0x08).unwrap_or(0) as usize;
    let stream_len = le::u16(b, 0x0A).unwrap_or(0) as usize;
    if entry_len < 0x10 || stream_len < 0x42 {
        return None;
    }
    let (parent, name) = parse_file_name(b.get(0x10..)?)?;
    Some((child, parent, name))
}

/// Attribute type code + optional name from an attribute-record payload
/// (the redo/undo buffer of CreateAttribute/DeleteAttribute).
fn parse_attr_header(b: &[u8]) -> Option<(u32, Option<String>)> {
    if b.len() < 0x10 {
        return None;
    }
    let ty = le::u32(b, 0x00).unwrap_or(0);
    // Plausibility: known attribute type codes are ≤ 0x100 and nonzero;
    // 0xFFFFFFFF is the record terminator, never an attribute here.
    if ty == 0 || ty == 0xFFFF_FFFF || ty > 0x100 {
        return None;
    }
    let name_len = *b.get(0x09)? as usize;
    let name = if name_len > 0 {
        let off = le::u16(b, 0x0A).unwrap_or(0) as usize;
        utf16_name(b, 0x09, off)
    } else {
        None
    };
    Some((ty, name))
}

impl LogRecord {
    /// The redo payload slice (`redo_offset`/`redo_len` are relative to
    /// the client-data area per ntfsdoc), when the record carries one.
    pub fn redo(&self) -> Option<&[u8]> {
        let s = self.redo_offset as usize;
        self.client_data
            .get(s..s.saturating_add(self.redo_len as usize))
            .filter(|b| !b.is_empty())
    }

    /// The undo payload slice, when present.
    pub fn undo(&self) -> Option<&[u8]> {
        let s = self.undo_offset as usize;
        self.client_data
            .get(s..s.saturating_add(self.undo_len as usize))
            .filter(|b| !b.is_empty())
    }

    /// The payload that carries the forensic content for `op`: adds,
    /// creates and writes leave the new state in redo; deletes leave the
    /// removed state in undo.
    fn op_payload(&self, op: LogOp) -> Option<&[u8]> {
        let (first, second) = match op {
            LogOp::DeleteIndexEntryRoot
            | LogOp::DeleteIndexEntryAllocation
            | LogOp::DeleteAttribute
            | LogOp::CompensationLogRecord => (self.undo(), self.redo()),
            _ => (self.redo(), self.undo()),
        };
        first.or(second)
    }

    /// Interpret the record's payloads: decode the operation classes and
    /// pull out whichever targets survive — the MFT record number, the
    /// filename an index/$FILE_NAME op touched, the attribute type. Needs
    /// the volume's `cluster_size` and `file_record_size` to translate
    /// `mft_cluster_index` into a record number.
    pub fn interpret(&self, cluster_size: u64, record_size: u64) -> LogInterpret {
        let redo_op = LogOp::from_code(self.redo_op);
        let undo_op = LogOp::from_code(self.undo_op);
        let mut it = LogInterpret {
            redo_op,
            undo_op,
            detail: String::new(),
            mft_record: None,
            record_is_bound: false,
            file_name: None,
            parent_ref: None,
            child_ref: None,
            attr_type: None,
            attr_name: None,
        };
        // Cluster-floor anchor: the record lives somewhere in this MFT
        // cluster — a lower bound, refined below when the payload names it.
        if self.mft_cluster_index != 0 && cluster_size != 0 && record_size != 0 {
            it.mft_record = Some(self.mft_cluster_index * (cluster_size / record_size));
            it.record_is_bound = true;
        }
        let payload = self.op_payload(redo_op);
        match redo_op {
            op if op.is_index_entry_op() => {
                if let Some(p) = payload {
                    if let Some((child, parent, name)) = parse_index_entry(p) {
                        it.child_ref = Some(child);
                        it.parent_ref = Some(parent);
                        it.file_name = Some(name.clone());
                        it.attr_type = Some(0x30); // $I30 indexes $FILE_NAME
                        it.detail = format!(
                            "$I30 {}: '{}' ref={:#x} parent={:#x}",
                            op.name(),
                            name,
                            child,
                            parent
                        );
                    } else {
                        it.detail = format!(
                            "$I30 {}: {} payload bytes (unparsed)",
                            op.name(),
                            p.len()
                        );
                    }
                }
            }
            LogOp::UpdateFileNameRoot | LogOp::UpdateFileNameAllocation => {
                if let Some(p) = payload {
                    if let Some((parent, name)) = parse_file_name(p) {
                        it.parent_ref = Some(parent);
                        it.file_name = Some(name.clone());
                        it.attr_type = Some(0x30);
                        it.detail = format!(
                            "$FILE_NAME update: '{}' parent={:#x}",
                            name, parent
                        );
                    }
                }
            }
            LogOp::CreateAttribute | LogOp::DeleteAttribute => {
                if let Some(p) = payload {
                    if let Some((ty, name)) = parse_attr_header(p) {
                        it.attr_type = Some(ty);
                        it.attr_name = name.clone();
                        it.detail = format!(
                            "{} attr {ty:#x}{} (attr_off {:#x})",
                            op_verb(redo_op),
                            name.map(|n| format!(" '{n}'")).unwrap_or_default(),
                            self.target_attribute,
                        );
                    }
                }
            }
            LogOp::InitializeFileRecordSegment => {
                // The redo payload is the new FILE record header; NTFS ≥3
                // stores the record number at +0x2C.
                if let Some(p) = payload {
                    if p.len() >= 0x30 && &p[0..4] == b"FILE" {
                        it.mft_record = Some(le::u32(p, 0x2C).unwrap_or(0) as u64);
                        it.record_is_bound = false;
                    }
                }
                it.detail = "initialise file record segment".to_string();
            }
            LogOp::DeallocateFileRecordSegment => {
                it.detail = "deallocate file record segment".to_string();
            }
            LogOp::UpdateResidentValue => {
                it.detail = format!(
                    "resident attribute content: {} bytes at attr_off {:#x}",
                    self.redo_len, self.target_attribute,
                );
            }
            LogOp::UpdateMappingPairs => {
                it.detail = format!("runlist rewrite: {} bytes", self.redo_len);
            }
            LogOp::SetNewAttributeSizes => {
                if let Some(p) = payload {
                    if p.len() >= 0x10 {
                        it.detail = format!(
                            "new sizes: alloc={} real={}",
                            le::u64(p, 0).unwrap_or(0),
                            le::u64(p, 8).unwrap_or(0),
                        );
                    }
                }
            }
            LogOp::SetBitsInNonresidentBitmap | LogOp::ClearBitsInNonresidentBitmap => {
                // bit_ops payloads: (bit index u32? , count) — report span.
                if let Some(p) = payload {
                    if p.len() >= 0x08 {
                        it.detail = format!(
                            "bitmap bits {}..+{}",
                            le::u32(p, 0).unwrap_or(0),
                            le::u32(p, 4).unwrap_or(0),
                        );
                    }
                }
            }
            _ => {}
        }
        if it.detail.is_empty() {
            it.detail = format!(
                "{} (undo {})",
                redo_op.name(),
                undo_op.name()
            );
        }
        it
    }
}

/// Verb for attribute ops in detail strings.
fn op_verb(op: LogOp) -> &'static str {
    match op {
        LogOp::CreateAttribute => "create",
        LogOp::DeleteAttribute => "delete",
        _ => "modify",
    }
}

/// One `$LogFile` artefact.
#[derive(Debug, Clone)]
pub enum LogEvent {
    /// A restart page's decoded restart area.
    Restart(RestartArea),
    /// A LOG_RECORD header inside an RCRD page.
    Record(LogRecord),
    /// A checkpoint page (`CHKD`) — raw anchor LSN.
    Checkpoint { lsn: u64, disk_offset: u64 },
    /// A torn write (`BAAD` page) — evidence of an in-flight operation.
    Torn { disk_offset: u64 },
}

/// One journal artefact across both streams: a `$UsnJrnl` change record
/// or a `$LogFile` structure.
#[derive(Debug, Clone)]
pub enum JournalEvent {
    /// A parsed USN change record (`$UsnJrnl:$J`).
    Usn(UsnRecord),
    /// A decoded restart area (`RSTR` page).
    Restart(RestartArea),
    /// A log-record header (`RCRD` page).
    LogRecord(LogRecord),
    /// A checkpoint page (`CHKD`).
    Checkpoint { lsn: u64, disk_offset: u64 },
    /// A torn write page (`BAAD`) — the last in-flight log page.
    TornPage { disk_offset: u64 },
}

/// Semantic operation class of a journal event — `JournalEvent::op()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalOp {
    /// A `$UsnJrnl` change record (its `reason` bits say what changed).
    UsnChange,
    /// A `$LogFile` restart area (`RSTR` page).
    LogRestart,
    /// A `$LogFile` client record — the carried op is its redo operation.
    Log(LogOp),
    /// A `$LogFile` checkpoint page (`CHKD`).
    LogCheckpoint,
    /// A torn log page (`BAAD`).
    TornPage,
}

impl JournalEvent {
    /// The semantic operation this event records. For `$LogFile` client
    /// records this is the decoded `redo_op`; USN records classify as
    /// `UsnChange` (their reason bits are the detail).
    pub fn op(&self) -> JournalOp {
        match self {
            JournalEvent::Usn(_) => JournalOp::UsnChange,
            JournalEvent::Restart(_) => JournalOp::LogRestart,
            JournalEvent::LogRecord(lr) => JournalOp::Log(LogOp::from_code(lr.redo_op)),
            JournalEvent::Checkpoint { .. } => JournalOp::LogCheckpoint,
            JournalEvent::TornPage { .. } => JournalOp::TornPage,
        }
    }
}

impl From<LogEvent> for JournalEvent {
    fn from(e: LogEvent) -> Self {
        match e {
            LogEvent::Restart(r) => JournalEvent::Restart(r),
            LogEvent::Record(r) => JournalEvent::LogRecord(r),
            LogEvent::Checkpoint { lsn, disk_offset } => JournalEvent::Checkpoint { lsn, disk_offset },
            LogEvent::Torn { disk_offset } => JournalEvent::TornPage { disk_offset },
        }
    }
}

/// Decode the restart area inside a fixup-applied RSTR page.
fn parse_restart(page: &[u8], disk_off: u64) -> Option<RestartArea> {
    let a = le::get(page, RSTR_AREA_OFF, 0x36)?;
    Some(RestartArea {
        current_lsn: le::u64(a, 0x00).unwrap_or(0),
        log_clients: le::u16(a, 0x08).unwrap_or(0),
        client_free_lsn_idx: le::u16(a, 0x0A).unwrap_or(0),
        client_inuse_lsn_idx: le::u16(a, 0x0C).unwrap_or(0),
        seq_nr_bits: le::u32(a, 0x1A).unwrap_or(0),
        restart_area_len: le::u16(a, 0x1E).unwrap_or(0),
        file_size: le::u64(a, 0x24).unwrap_or(0),
        last_lsn_data_len: le::u32(a, 0x2C).unwrap_or(0),
        record_page_len: le::u16(a, 0x30).unwrap_or(0),
        disk_offset: disk_off,
    })
}

/// Decode one LOG_RECORD header at `pos` in a fixup-applied RCRD page.
/// Returns `(record, extent)` or `None` when implausible.
fn parse_logrec(page: &[u8], pos: usize) -> Option<(LogRecord, usize)> {
    let h = le::get(page, pos, LOGREC_HDR)?;
    let this_lsn = le::u64(h, 0x00).unwrap_or(0);
    if this_lsn == 0 {
        return None;
    }
    let client_data_len = le::u16(h, 0x18).unwrap_or(0);
    // Header layout (ntfsdoc "Log Record"): 0x28 redo_op, 0x2A undo_op,
    // 0x2C redo_off, 0x2E redo_len, 0x30 undo_off, 0x32 undo_len,
    // 0x34 target_attr, 0x36 lcns_to_follow, 0x38 record_offset,
    // 0x3A attr_list_offset, 0x40 mft_cluster_index, then the LCN list
    // and the client data (redo/undo buffers).
    let lcns = le::u16(h, 0x36).unwrap_or(0) as usize;
    if lcns > 64 {
        return None; // an LCN list that long is not a record
    }
    let extent = LOGREC_HDR
        .saturating_add(lcns * 8)
        .saturating_add(client_data_len as usize)
        .max(LOGREC_HDR)
        .div_ceil(8)
        * 8;
    if pos + extent > page.len() {
        return None;
    }
    // Client data follows the LCN list, capped at the page-bounded extent.
    let data_start = pos + LOGREC_HDR + lcns * 8;
    let data_end = (data_start + client_data_len as usize)
        .min(data_start + MAX_CLIENT_DATA)
        .min(pos + extent);
    let client_data = page
        .get(data_start..data_end)
        .map(|b| b.to_vec())
        .unwrap_or_default();
    Some((
        LogRecord {
            this_lsn,
            client_prev_lsn: le::u64(h, 0x08).unwrap_or(0),
            client_undo_next_lsn: le::u64(h, 0x10).unwrap_or(0),
            client_data_len,
            record_type: le::u32(h, 0x1C).unwrap_or(0),
            transaction_id: le::u32(h, 0x20).unwrap_or(0),
            flags: le::u16(h, 0x24).unwrap_or(0),
            redo_op: le::u16(h, 0x28).unwrap_or(0),
            undo_op: le::u16(h, 0x2A).unwrap_or(0),
            redo_offset: le::u16(h, 0x2C).unwrap_or(0),
            redo_len: le::u16(h, 0x2E).unwrap_or(0),
            undo_offset: le::u16(h, 0x30).unwrap_or(0),
            undo_len: le::u16(h, 0x32).unwrap_or(0),
            target_attribute: le::u16(h, 0x34).unwrap_or(0),
            lcns_to_follow: lcns as u16,
            record_offset: le::u16(h, 0x38).unwrap_or(0),
            attr_list_offset: le::u16(h, 0x3A).unwrap_or(0),
            mft_cluster_index: le::u64(h, 0x40).unwrap_or(0),
            client_data,
            disk_offset: None,
            extent,
        },
        extent,
    ))
}

/// Iterator over `$LogFile` pages inside a materialised byte buffer:
/// RSTR restart areas, RCRD log-record headers, CHKD checkpoints and
/// BAAD torn pages. Non-LFS pages are skipped; fixup failures are `Err`.
pub(crate) struct LogIter {
    buf: Vec<u8>,
    regions: Vec<(u64, u64, u64)>,
    sector_size: usize,
    pending: VecDeque<Result<LogEvent>>,
    pos: usize,
    finished: bool,
    strict: bool,
}

impl LogIter {
    pub(crate) fn new(
        buf: Vec<u8>,
        regions: Vec<(u64, u64, u64)>,
        sector_size: usize,
        strict: bool,
    ) -> Self {
        LogIter {
            buf,
            regions,
            sector_size,
            pending: VecDeque::new(),
            pos: 0,
            finished: false,
            strict,
        }
    }

    fn disk_of(&self, logical: u64) -> Option<u64> {
        for &(lo, disk, len) in &self.regions {
            if logical >= lo && logical < lo.saturating_add(len) {
                return Some(disk + (logical - lo));
            }
        }
        None
    }

    /// Parse one log page at `pos`, queueing its events.
    fn page(&mut self, pos: usize) -> Result<()> {
        let raw = &self.buf[pos..pos + LOG_PAGE];
        let magic = &raw[0..4];
        if !matches!(magic, b"RSTR" | b"RCRD" | b"CHKD" | b"BAAD") {
            return Ok(());
        }
        let disk_off = self.disk_of(pos as u64).unwrap_or(0);
        if magic == b"BAAD" {
            self.pending.push_back(Ok(LogEvent::Torn { disk_offset: disk_off }));
            return Ok(());
        }
        let mut page = raw.to_vec();
        let usa_off = le::u16(&page, 4).unwrap_or(0) as usize;
        let usa_count = le::u16(&page, 6).unwrap_or(0) as usize;
        crate::record::apply_fixup(&mut page, disk_off, usa_off, usa_count, self.sector_size)?;
        match magic {
            b"RSTR" => {
                if let Some(ra) = parse_restart(&page, disk_off) {
                    self.pending.push_back(Ok(LogEvent::Restart(ra)));
                }
            }
            b"CHKD" => {
                let lsn = le::u64(&page, CHKD_REC_OFF).unwrap_or(0);
                self.pending.push_back(Ok(LogEvent::Checkpoint {
                    lsn,
                    disk_offset: disk_off,
                }));
            }
            b"RCRD" => {
                let mut p = RCRD_DATA_OFF;
                let mut probes = 0;
                while p + LOGREC_HDR <= page.len() && probes < MAX_PAGE_PROBES {
                    probes += 1;
                    match parse_logrec(&page, p) {
                        Some((mut rec, extent)) => {
                            rec.disk_offset = self.disk_of((pos + p) as u64);
                            self.pending.push_back(Ok(LogEvent::Record(rec)));
                            p += extent.max(8);
                        }
                        None => p += 8,
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl Iterator for LogIter {
    type Item = Result<LogEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.pending.pop_front() {
            return Some(item);
        }
        if self.finished {
            return None;
        }
        while self.pos + LOG_PAGE <= self.buf.len() {
            let pos = self.pos;
            self.pos += LOG_PAGE;
            match self.page(pos) {
                Ok(()) => {
                    if let Some(item) = self.pending.pop_front() {
                        return Some(item);
                    }
                }
                Err(e) => {
                    if self.strict {
                        self.finished = true;
                    }
                    return Some(Err(e));
                }
            }
        }
        self.finished = true;
        self.pending.pop_front()
    }
}
