//! NTFS attribute decoding: resident/non-resident headers, runlist
//! (data-run) decoding, and the payload structures that matter
//! forensically — `$STANDARD_INFORMATION`, `$FILE_NAME`, `$ATTRIBUTE_LIST`,
//! `$EA`, `$OBJECT_ID`, `$VOLUME_*` and `$REPARSE_POINT`.
//!
//! Timestamps are NTFS FILETIMEs: unsigned 100-ns ticks since
//! 1601-01-01 UTC. Both timestamp *sets* (SI and FN) are decoded
//! separately — their divergence is the raw material of timestomp
//! detection.

use std::time::Duration;

use sutram_fs::{FsError, FsTimestamp, Result};
use sutram_io::le;

// Attribute type codes.
pub(crate) const T_STANDARD_INFORMATION: u32 = 0x10;
pub(crate) const T_ATTRIBUTE_LIST: u32 = 0x20;
pub(crate) const T_FILE_NAME: u32 = 0x30;
pub(crate) const T_OBJECT_ID: u32 = 0x40;
pub(crate) const T_VOLUME_NAME: u32 = 0x60;
pub(crate) const T_VOLUME_INFORMATION: u32 = 0x70;
pub(crate) const T_DATA: u32 = 0x80;
pub(crate) const T_INDEX_ROOT: u32 = 0x90;
pub(crate) const T_INDEX_ALLOCATION: u32 = 0xA0;
pub(crate) const T_BITMAP: u32 = 0xB0;
pub(crate) const T_REPARSE_POINT: u32 = 0xC0;
pub(crate) const T_EA_INFORMATION: u32 = 0xD0;
pub(crate) const T_EA: u32 = 0xE0;
pub(crate) const T_END: u32 = 0xFFFF_FFFF;

/// Attribute flag: compressed (0x0001) / encrypted (0x4000) / sparse (0x8000).
pub(crate) const ATTR_FLAG_COMPRESSED: u16 = 0x0001;
pub(crate) const ATTR_FLAG_ENCRYPTED: u16 = 0x4000;
pub(crate) const ATTR_FLAG_SPARSE: u16 = 0x8000;

/// FILETIME ticks between 1601-01-01 and 1970-01-01.
pub(crate) const FILETIME_EPOCH_DIFF: i64 = 116_444_736_000_000_000;

/// FILETIME → `FsTimestamp` (`"ntfs-filetime"`, 100 ns granularity).
/// A zero FILETIME is "unset" → `value: None`, never fabricated.
pub(crate) fn filetime_ts(raw: u64) -> FsTimestamp {
    let value = if raw == 0 {
        None
    } else {
        // try_from: FILETIMEs ≥ 2^63 are implausible — casting would wrap
        // negative and fabricate a pre-epoch instant. Decode as unset.
        i64::try_from(raw)
            .ok()
            .and_then(|t| t.checked_sub(FILETIME_EPOCH_DIFF))
            .and_then(|t| t.checked_mul(100))
    };
    FsTimestamp {
        value,
        raw_value: raw,
        raw_encoding: "ntfs-filetime",
        granularity: Duration::from_nanos(100),
    }
}

/// Decode a file reference: low 48 bits = record number, high 16 = sequence.
pub(crate) fn file_ref_rec(reference: u64) -> u64 {
    reference & 0x0000_FFFF_FFFF_FFFF
}

/// One runlist extent. `lcn == None` marks a sparse run (no disk backing —
/// reads as zeros).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DataRun {
    /// First virtual cluster covered (absolute VCN, resolved).
    pub vcn: u64,
    /// Cluster count of the run.
    pub len: u64,
    /// Absolute logical cluster number, or `None` for a sparse hole.
    pub lcn: Option<u64>,
}

/// A parsed attribute header + the parts needed downstream.
#[derive(Debug)]
pub(crate) struct Attr {
    /// Type code (0x10 … 0xE0).
    pub type_code: u32,
    /// Absolute byte offset of this attribute's header (provenance).
    pub offset: u64,
    /// Attribute name (UTF-16, may be empty → `None`). `$DATA` names are
    /// ADS names; `$INDEX_ALLOCATION` names are the index name (`$I30`).
    pub name: Option<String>,
    /// `true` for non-resident.
    pub non_resident: bool,
    /// Header flags: compressed/encrypted/sparse.
    pub flags: u16,
    /// Resident: absolute offset + length of the content bytes.
    pub resident: Option<(u64, u32)>,
    /// Non-resident: first VCN this attribute portion covers.
    pub first_vcn: u64,
    /// Non-resident: decoded data runs.
    pub runs: Vec<DataRun>,
    /// Non-resident: logical (real) size in bytes.
    pub real_size: u64,
    /// Non-resident: allocated size in bytes.
    pub alloc_size: u64,
    /// Non-resident: initialized size in bytes.
    pub init_size: u64,
    /// Non-resident: compression unit as log2 of clusters (0 = none).
    pub comp_unit_shift: u8,
}

impl Attr {
    /// `true` when the header or stream is flagged compressed.
    pub fn compressed(&self) -> bool {
        self.flags & ATTR_FLAG_COMPRESSED != 0 || self.comp_unit_shift != 0
    }
    /// `true` when flagged sparse.
    pub fn sparse(&self) -> bool {
        self.flags & ATTR_FLAG_SPARSE != 0 || self.runs.iter().any(|r| r.lcn.is_none())
    }
    /// `true` when flagged encrypted.
    pub fn encrypted(&self) -> bool {
        self.flags & ATTR_FLAG_ENCRYPTED != 0
    }
}

/// Decode an NTFS runlist into absolute-VCN [`DataRun`]s.
///
/// Each run: a header byte (low nibble = size of the *length* field,
/// high nibble = size of the *offset* field), then the unsigned length,
/// then the signed LCN delta relative to the previous run's LCN
/// (absolute for the first run). Offset-field size 0 = sparse run.
/// Terminated by a zero header byte. Loop- and bounds-guarded.
pub(crate) fn decode_runlist(buf: &[u8], base_vcn: u64, limit_off: u64) -> Result<Vec<DataRun>> {
    let mut runs = Vec::new();
    let mut pos = 0usize;
    let mut vcn = base_vcn;
    let mut lcn: i64 = 0;
    // A run needs ≥1 header byte; cap iterations at buffer length.
    while pos < buf.len() {
        let hdr = buf[pos];
        pos += 1;
        if hdr == 0 {
            break;
        }
        let len_sz = (hdr & 0x0F) as usize;
        let off_sz = (hdr >> 4) as usize;
        if len_sz == 0 || len_sz > 8 || off_sz > 8 {
            return Err(FsError::corrupt(
                limit_off + pos as u64 - 1,
                format!("bad runlist field sizes len={len_sz} off={off_sz}"),
            ));
        }
        if pos + len_sz + off_sz > buf.len() {
            return Err(FsError::corrupt(
                limit_off + pos as u64,
                "runlist truncated mid-run",
            ));
        }
        let mut len: u64 = 0;
        for i in 0..len_sz {
            len |= (buf[pos + i] as u64) << (8 * i);
        }
        pos += len_sz;
        // Signed LCN delta (two's complement, little-endian).
        let lcn_field: Option<i64> = if off_sz == 0 {
            None
        } else {
            let mut v: i64 = 0;
            for i in 0..off_sz {
                v |= (buf[pos + i] as i64) << (8 * i);
            }
            // Sign-extend only for fields narrower than i64: at off_sz == 8
            // the loaded bytes already *are* the full signed value, and a
            // `<< 64` would overflow (debug panic / masked shift in release).
            if off_sz < 8 && buf[pos + off_sz - 1] & 0x80 != 0 {
                v |= -1i64 << (8 * off_sz);
            }
            pos += off_sz;
            Some(v)
        };
        if len == 0 {
            return Err(FsError::corrupt(limit_off + pos as u64, "zero-length data run"));
        }
        match lcn_field {
            Some(delta) => {
                lcn = lcn.wrapping_add(delta);
                if lcn < 0 {
                    return Err(FsError::corrupt(
                        limit_off + pos as u64,
                        format!("negative LCN {lcn} in runlist"),
                    ));
                }
                runs.push(DataRun {
                    vcn,
                    len,
                    lcn: Some(lcn as u64),
                });
            }
            None => runs.push(DataRun { vcn, len, lcn: None }),
        }
        vcn = vcn.checked_add(len).ok_or_else(|| {
            FsError::corrupt(limit_off + pos as u64, "runlist VCN overflow")
        })?;
    }
    Ok(runs)
}

/// Decode a UTF-16LE name field (bounded).
fn utf16(buf: &[u8]) -> String {
    let units: Vec<u16> = buf
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Parse one attribute header starting at `data[off]` (already
/// fixup-applied record bytes). `rec_off` is the record's absolute offset
/// for provenance/error reporting. Returns `(attr, header_len)`.
pub(crate) fn parse_attr(data: &[u8], off: usize, rec_off: u64) -> Result<Option<(Attr, usize)>> {
    let type_code = le::u32(data, off).unwrap_or(T_END);
    if type_code == T_END {
        return Ok(None);
    }
    let len = le::u32(data, off + 4).unwrap_or(0) as usize;
    // `len > data.len() - off` avoids a 32-bit usize wrap on `off + len`.
    if len < 0x18 || len > data.len().saturating_sub(off) {
        return Err(FsError::corrupt(
            rec_off + off as u64,
            format!("bad attribute length {len:#x} (type {type_code:#x})"),
        ));
    }
    let non_resident = le::u8(data, off + 8).unwrap_or(0) != 0;
    let name_len = le::u8(data, off + 9).unwrap_or(0) as usize;
    let name_off = le::u16(data, off + 10).unwrap_or(0) as usize;
    let flags = le::u16(data, off + 12).unwrap_or(0);
    let name = if name_len > 0 {
        // The name lives inside the attribute header: bound it by this
        // attribute's own length so a corrupt name_off cannot alias the
        // following attribute's bytes.
        if name_off + name_len * 2 > len {
            return Err(FsError::corrupt(
                rec_off + off as u64,
                "attribute name out of bounds",
            ));
        }
        match le::get(data, off + name_off, name_len * 2) {
            Some(nb) => Some(utf16(nb)),
            None => {
                return Err(FsError::corrupt(
                    rec_off + off as u64,
                    "attribute name out of bounds",
                ))
            }
        }
    } else {
        None
    };

    let mut attr = Attr {
        type_code,
        offset: rec_off + off as u64,
        name,
        non_resident,
        flags,
        resident: None,
        first_vcn: 0,
        runs: Vec::new(),
        real_size: 0,
        alloc_size: 0,
        init_size: 0,
        comp_unit_shift: 0,
    };

    if !non_resident {
        let content_len = le::u32(data, off + 16).unwrap_or(0);
        let content_off = le::u16(data, off + 20).unwrap_or(0) as usize;
        let end = (off + content_off)
            .checked_add(content_len as usize)
            .ok_or_else(|| FsError::corrupt(rec_off + off as u64, "resident content overflow"))?;
        // Resident content lives *inside* the attribute: it must fit both
        // the record and this attribute's own `len`, else a corrupt
        // content_len would alias the following attributes' bytes.
        let content_end = content_off as u64 + content_len as u64;
        if end > data.len() || content_end > len as u64 {
            return Err(FsError::corrupt(
                rec_off + off as u64,
                format!("resident content out of bounds (type {type_code:#x})"),
            ));
        }
        attr.resident = Some((rec_off + (off + content_off) as u64, content_len));
        attr.real_size = content_len as u64;
        attr.alloc_size = content_len as u64;
        attr.init_size = content_len as u64;
    } else {
        if len < 0x40 {
            return Err(FsError::corrupt(
                rec_off + off as u64,
                "short non-resident attribute header",
            ));
        }
        attr.first_vcn = le::u64(data, off + 16).unwrap_or(0);
        let last_vcn = le::u64(data, off + 24).unwrap_or(0);
        let runs_off = le::u16(data, off + 32).unwrap_or(0) as usize;
        attr.comp_unit_shift = le::u8(data, off + 34).unwrap_or(0);
        attr.alloc_size = le::u64(data, off + 40).unwrap_or(0);
        attr.real_size = le::u64(data, off + 48).unwrap_or(0);
        attr.init_size = le::u64(data, off + 56).unwrap_or(0);
        if runs_off >= len || off + runs_off >= data.len() {
            return Err(FsError::corrupt(
                rec_off + off as u64,
                "runlist offset out of bounds",
            ));
        }
        // The runlist can extend to the end of the attribute; a stray
        // nonzero tail is ignored by decode_runlist only until it
        // misparses — bound it at the attribute end.
        let rl = &data[off + runs_off..off + len];
        attr.runs = decode_runlist(rl, attr.first_vcn, rec_off + (off + runs_off) as u64)?;
        // Sanity: runs should roughly cover the declared last VCN. Not a
        // hard failure — damaged headers still yield partial runs.
        let _ = last_vcn;
    }
    Ok(Some((attr, len)))
}

// ---------------------------------------------------------------------------
// Payload decoders (resident contents)
// ---------------------------------------------------------------------------

/// The four FILETIMEs + flags of `$STANDARD_INFORMATION`.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StandardInformation {
    pub created: u64,
    pub modified: u64,
    pub mft_changed: u64,
    pub accessed: u64,
    /// DOS-style attribute flags.
    pub file_attributes: u32,
}

/// Decode a resident $STANDARD_INFORMATION body.
pub(crate) fn parse_si(body: &[u8]) -> Option<StandardInformation> {
    if body.len() < 0x30 {
        return None;
    }
    Some(StandardInformation {
        created: le::u64(body, 0)?,
        modified: le::u64(body, 8)?,
        mft_changed: le::u64(body, 16)?,
        accessed: le::u64(body, 24)?,
        file_attributes: le::u32(body, 32)?,
    })
}

/// A decoded `$FILE_NAME` attribute body.
#[derive(Debug, Clone)]
pub(crate) struct FileName {
    /// Parent directory file reference (record + sequence).
    pub parent_ref: u64,
    pub created: u64,
    pub modified: u64,
    pub mft_changed: u64,
    pub accessed: u64,
    pub real_size: u64,
    /// Namespace: 0 POSIX, 1 WIN32, 2 DOS, 3 WIN32&DOS.
    pub namespace: u8,
    pub name: String,
}

/// Decode a resident $FILE_NAME body.
pub(crate) fn parse_fn(body: &[u8]) -> Option<FileName> {
    if body.len() < 0x42 {
        return None;
    }
    let name_len = le::u8(body, 0x40)? as usize;
    let namespace = le::u8(body, 0x41)?;
    let name_bytes = le::get(body, 0x42, name_len * 2)?;
    Some(FileName {
        parent_ref: le::u64(body, 0)?,
        created: le::u64(body, 8)?,
        modified: le::u64(body, 16)?,
        mft_changed: le::u64(body, 24)?,
        accessed: le::u64(body, 32)?,
        real_size: le::u64(body, 48)?,
        namespace,
        name: utf16(name_bytes),
    })
}

/// One `$ATTRIBUTE_LIST` entry pointing at where an attribute instance lives.
#[derive(Debug, Clone)]
pub(crate) struct AttrListEntry {
    /// File reference of the record holding this instance.
    pub record_ref: u64,
}

/// Decode a resident $ATTRIBUTE_LIST body.
pub(crate) fn parse_attr_list(body: &[u8], base_off: u64) -> Result<Vec<AttrListEntry>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let cap = body.len() / 0x1A + 1;
    while pos + 0x1A <= body.len() && out.len() < cap {
        let type_code = le::u32(body, pos).unwrap_or(T_END);
        if type_code == T_END || type_code == 0 {
            break;
        }
        let elen = le::u16(body, pos + 4).unwrap_or(0) as usize;
        if elen < 0x1A || pos + elen > body.len() {
            return Err(FsError::corrupt(
                base_off + pos as u64,
                format!("bad attribute-list entry length {elen:#x}"),
            ));
        }
        out.push(AttrListEntry {
            record_ref: le::u64(body, pos + 16).unwrap_or(0),
        });
        pos += elen;
    }
    Ok(out)
}

/// Decode a resident $EA body → list of `(name, value_len)` (values are
/// not surfaced — only names/sizes are forensic metadata).
pub(crate) fn parse_ea(body: &[u8]) -> Vec<(String, u16)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let cap = body.len() / 8 + 1;
    while pos + 8 <= body.len() && out.len() < cap {
        let next = le::u32(body, pos).unwrap_or(0) as usize;
        let name_len = le::u8(body, pos + 5).unwrap_or(0) as usize;
        let value_len = le::u16(body, pos + 6).unwrap_or(0);
        let name = le::get(body, pos + 8, name_len)
            .map(|b| String::from_utf8_lossy(b).to_string())
            .unwrap_or_default();
        out.push((name, value_len));
        if next == 0 {
            break;
        }
        pos += next;
    }
    out
}

/// Decode a resident $OBJECT_ID body → object GUID string.
pub(crate) fn parse_object_id(body: &[u8]) -> Option<String> {
    le::uuid_le(body, 0)
}

/// Decode a resident $VOLUME_NAME body → UTF-16 label.
pub(crate) fn parse_volume_name(body: &[u8]) -> Option<String> {
    if body.len() < 2 {
        return None;
    }
    Some(utf16(body))
}

/// Decode a resident $VOLUME_INFORMATION body → (major, minor).
pub(crate) fn parse_volume_information(body: &[u8]) -> Option<(u8, u8)> {
    Some((le::u8(body, 8)?, le::u8(body, 9)?))
}

/// Decode a resident $REPARSE_POINT body → (tag, optional symlink target).
pub(crate) fn parse_reparse(body: &[u8]) -> Option<(u32, Option<String>)> {
    if body.len() < 8 {
        return None;
    }
    let tag = le::u32(body, 0)?;
    // IO_REPARSE_TAG_SYMLINK = 0xA000000C: the display target is the
    // PrintName field — PrintNameOffset@0x0C / PrintNameLength@0x0E,
    // relative to PathBuffer@0x14 (0x10 is the SYMLINK Flags field).
    let target = if tag == 0xA000_000C && body.len() >= 0x14 {
        let print_off = le::u16(body, 0x0C).unwrap_or(0) as usize;
        let print_len = le::u16(body, 0x0E).unwrap_or(0) as usize;
        le::get(body, 0x14 + print_off, print_len).map(utf16)
    } else {
        None
    };
    Some((tag, target))
}
