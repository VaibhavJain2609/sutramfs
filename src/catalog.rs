//! Catalog-file record decoding: keyed `(parentID, name)` leaf records —
//! folder, file and thread — plus HFS+ (1904-epoch) timestamp conversion.
//!
//! All fields are big-endian. Structure offsets follow `hfsplus_cat_*`
//! in TN1150 / `linux/fs/hfsplus/hfsplus_raw.h`.

use std::time::Duration;

use sutram_fs::util;
use sutram_fs::{FsTimestamp, Timestamps};
use sutram_io::le;

use crate::vh::ForkData;

/// Catalog record types (`recordType`, i16 BE at data offset 0).
pub(crate) const REC_FOLDER: i16 = 0x0001;
pub(crate) const REC_FILE: i16 = 0x0002;
pub(crate) const REC_FOLDER_THREAD: i16 = 0x0003;
pub(crate) const REC_FILE_THREAD: i16 = 0x0004;

/// Special CNIDs (TN1150).
pub(crate) const CNID_ROOT: u32 = 2;
pub(crate) const CNID_EXTENTS: u32 = 3;
pub(crate) const CNID_CATALOG: u32 = 4;
pub(crate) const CNID_ALLOC: u32 = 6;
pub(crate) const CNID_STARTUP: u32 = 7;
pub(crate) const CNID_ATTRS: u32 = 8;
/// `kHFSMetadataFolderID` — the `"\0\0\0\0HFS+ Private Data"` directory that
/// holds file-hardlink inode files (`iNode<N>`).
pub(crate) const CNID_METADATA_DIR: u32 = 18;
/// `kHFSDirMetadataFolderID` — `.HFS+ Private Directory Data\r` for
/// directory hard links (`dir_<N>`).
pub(crate) const CNID_DIR_METADATA_DIR: u32 = 19;

/// Finder info signatures used by HFS+ special files.
pub(crate) const FINDER_HARDLINK_TYPE: u32 = 0x686C6E6B; // 'hlnk'
pub(crate) const FINDER_HFSPLUS_CREATOR: u32 = 0x6866732B; // 'hfs+'
pub(crate) const FINDER_SYMLINK_TYPE: u32 = 0x736C6E6B; // 'slnk'
pub(crate) const FINDER_SYMLINK_CREATOR: u32 = 0x72686170; // 'rhap'

/// File/folder flags (low u16 of the record).
pub(crate) const FLAG_LOCKED: u16 = 0x0001;
pub(crate) const FLAG_THREAD_EXISTS: u16 = 0x0002;
pub(crate) const FLAG_XATTR: u16 = 0x0004;
pub(crate) const FLAG_ACL: u16 = 0x0008;

/// `UF_COMPRESSED` — BSD `userFlags` bit marking a decmpfs-compressed file.
pub(crate) const UF_COMPRESSED: u8 = 0x20;

/// Seconds between the HFS+ epoch (1904-01-01 UTC) and the Unix epoch.
pub(crate) const HFS_EPOCH_DELTA: i64 = 2_082_844_800;

/// A decoded catalog key: `(parentID, name)`.
#[derive(Debug, Clone)]
pub(crate) struct CatKey {
    pub parent: u32,
    /// Decoded UTF-16 name (lossy, unsanitised; empty for threads).
    pub name: String,
    /// Byte length of `key_len + key` within the record.
    pub total_len: usize,
}

/// The record-data half of a catalog leaf record.
#[derive(Debug)]
pub(crate) enum CatRecord {
    Folder(FolderRec),
    File(FileRec),
    /// Thread record: `(parentID of the node it describes, its name)`.
    Thread {
        parent: u32,
        name: String,
    },
    /// Anything else (unknown record type).
    Other(i16),
}

#[derive(Debug)]
pub(crate) struct FolderRec {
    pub flags: u16,
    pub valence: u32,
    pub cnid: u32,
    /// `[create, content_mod, attr_mod, access, backup]` raw u32s.
    pub dates: [u32; 5],
    pub owner: u32,
    pub group: u32,
    pub user_flags: u8,
    pub mode: u16,
    /// Finder `userInfo` 16 bytes (DInfo).
    pub finder_info: [u8; 16],
    pub text_encoding: u32,
}

#[derive(Debug)]
pub(crate) struct FileRec {
    pub flags: u16,
    pub cnid: u32,
    pub dates: [u32; 5],
    pub owner: u32,
    pub group: u32,
    pub user_flags: u8,
    pub mode: u16,
    /// `special` (device number for dev nodes, inode link ref for hardlinks).
    pub special: u32,
    /// FInfo fields.
    pub fd_type: u32,
    pub fd_creator: u32,
    pub fd_flags: u16,
    /// FXInfo 16 bytes.
    pub ext_info: [u8; 16],
    pub text_encoding: u32,
    pub data_fork: ForkData,
    pub rsrc_fork: ForkData,
}

impl FileRec {
    /// File-type hard link (`hlnk`/`hfs+`)? `special` then holds the iNode
    /// reference — the real extents live in `iNode<special>` under CNID 18.
    pub(crate) fn is_hardlink(&self) -> bool {
        self.fd_type == FINDER_HARDLINK_TYPE
            && (self.fd_creator == FINDER_HFSPLUS_CREATOR || self.fd_creator == 0)
    }
    /// POSIX symlink (`slnk`/`rhap`); the data fork holds the target path.
    pub(crate) fn is_symlink(&self) -> bool {
        self.fd_type == FINDER_SYMLINK_TYPE && self.fd_creator == FINDER_SYMLINK_CREATOR
    }
}

/// Decode `length`-prefixed UTF-16 (BE) at `buf[off..]`; returns the string
/// and the consumed byte count (2 + 2*len), or `None`.
pub(crate) fn unistr(buf: &[u8], off: usize, max_units: usize) -> Option<(String, usize)> {
    let n = le::u16_be(buf, off)? as usize;
    if n > max_units {
        return None;
    }
    let mut units = Vec::with_capacity(n);
    for i in 0..n {
        units.push(le::u16_be(buf, off + 2 + i * 2)?);
    }
    Some((String::from_utf16_lossy(&units), 2 + n * 2))
}

/// Parse a catalog record's key. Returns `None` when the key is malformed
/// (the record is residue or corrupt — not a hard error).
pub(crate) fn parse_key(rec: &[u8]) -> Option<CatKey> {
    let key_len = le::u16_be(rec, 0)? as usize;
    // HFS+ catalog keys: 2-byte parent + UniStr255 → 6..=516 bytes.
    if key_len < 6 || key_len > 516 || rec.len() < 2 + key_len {
        return None;
    }
    let parent = le::u32_be(rec, 2)?;
    // `name_len` includes the 2-byte length prefix → key = 4 + (2 + 2n).
    let (name, name_len) = unistr(rec, 6, 255)?;
    if 4 + name_len != key_len {
        return None; // key_len must match the encoded name exactly
    }
    Some(CatKey {
        parent,
        name,
        total_len: 2 + key_len,
    })
}

/// Parse the record-data half of a catalog record.
pub(crate) fn parse_record(data: &[u8]) -> Option<CatRecord> {
    let ty = le::u16_be(data, 0)? as i16;
    match ty {
        REC_FOLDER => {
            if data.len() < 88 {
                return None;
            }
            let mut finder_info = [0u8; 16];
            finder_info.copy_from_slice(data.get(48..64)?);
            Some(CatRecord::Folder(FolderRec {
                flags: le::u16_be(data, 2)?,
                valence: le::u32_be(data, 4)?,
                cnid: le::u32_be(data, 8)?,
                dates: [
                    le::u32_be(data, 12)?,
                    le::u32_be(data, 16)?,
                    le::u32_be(data, 20)?,
                    le::u32_be(data, 24)?,
                    le::u32_be(data, 28)?,
                ],
                owner: le::u32_be(data, 32)?,
                group: le::u32_be(data, 36)?,
                user_flags: data.get(41).copied()?,
                mode: le::u16_be(data, 42)?,
                finder_info,
                text_encoding: le::u32_be(data, 80)?,
            }))
        }
        REC_FILE => {
            if data.len() < 248 {
                return None;
            }
            let mut ext_info = [0u8; 16];
            ext_info.copy_from_slice(data.get(64..80)?);
            Some(CatRecord::File(FileRec {
                flags: le::u16_be(data, 2)?,
                cnid: le::u32_be(data, 8)?,
                dates: [
                    le::u32_be(data, 12)?,
                    le::u32_be(data, 16)?,
                    le::u32_be(data, 20)?,
                    le::u32_be(data, 24)?,
                    le::u32_be(data, 28)?,
                ],
                owner: le::u32_be(data, 32)?,
                group: le::u32_be(data, 36)?,
                user_flags: data.get(41).copied()?,
                mode: le::u16_be(data, 42)?,
                special: le::u32_be(data, 44)?,
                fd_type: le::u32_be(data, 48)?,
                fd_creator: le::u32_be(data, 52)?,
                fd_flags: le::u16_be(data, 56)?,
                ext_info,
                text_encoding: le::u32_be(data, 80)?,
                data_fork: ForkData::parse(data, 88)?,
                rsrc_fork: ForkData::parse(data, 168)?,
            }))
        }
        REC_FOLDER_THREAD | REC_FILE_THREAD => {
            // type i16 @0, reserved s16 @2, parentID u32 @4, name @8.
            let parent = le::u32_be(data, 4)?;
            let (name, _) = unistr(data, 8, 255)?;
            Some(CatRecord::Thread { parent, name })
        }
        other => Some(CatRecord::Other(other)),
    }
}

/// HFS+ timestamp → [`FsTimestamp`]. Raw is u32 seconds since
/// 1904-01-01T00:00:00. The spec stores **local time** (the writing host's
/// clock); we convert as if UTC and preserve `raw_value` — the encoding
/// name records that caveat (`"hfs+-u32-1904-local"`).
pub(crate) fn hfs_ts(raw: u32) -> FsTimestamp {
    let value = if raw == 0 {
        None
    } else {
        (raw as i64)
            .checked_sub(HFS_EPOCH_DELTA)
            .and_then(|s| s.checked_mul(1_000_000_000))
    };
    FsTimestamp {
        value,
        raw_value: raw as u64,
        raw_encoding: "hfs+-u32-1904-local",
        granularity: Duration::from_secs(1),
    }
}

/// MACB set from a record's `[create, content_mod, attr_mod, access, backup]`.
/// `backup` has no MACB slot — callers put it in `meta["backup_date"]`.
pub(crate) fn timestamps(dates: &[u32; 5]) -> Timestamps {
    Timestamps {
        modified: Some(hfs_ts(dates[1])),
        accessed: Some(hfs_ts(dates[3])),
        created: Some(hfs_ts(dates[0])),
        changed: Some(hfs_ts(dates[2])), // attributeModDate ≈ ctime
        deleted: None,
    }
}

/// A catalog record reference — the mount-time index entry.
#[derive(Debug, Clone)]
pub(crate) struct RecRef {
    /// B-tree node index holding the record.
    pub node: u32,
    /// Record offset within the node buffer.
    pub rec_off: u16,
    /// Absolute disk offset of the record's first byte (provenance).
    pub disk_off: u64,
    /// Parsed key.
    pub parent: u32,
    /// Sanitised name from the key.
    pub name: String,
    /// Raw record type (`REC_*`); negative values kept as i16.
    pub rectype: i16,
    /// CNID from the record body (0 for threads/unknown).
    pub cnid: u32,
}

/// Plausibility-check a would-be catalog record starting at `buf[pos]`:
/// used when carving **free space** and dead nodes for deleted residue.
/// Returns `(record_len, CatKey)` when `pos` looks like a real record —
/// conservative by construction (exact key-length consistency required).
pub(crate) fn sniff_record(buf: &[u8], pos: usize) -> Option<(usize, CatKey)> {
    let key_len = le::u16_be(buf, pos)? as usize;
    if !(6..=516).contains(&key_len) || key_len % 2 != 0 {
        return None;
    }
    let end = pos.checked_add(2 + key_len)?;
    let key = parse_key(buf.get(pos..end)?)?;
    if key.parent == 0 {
        return None;
    }
    let data = buf.get(end..)?;
    let ty = le::u16_be(data, 0)? as i16;
    let rec_len = match ty {
        REC_FILE => {
            if data.len() < 248 {
                return None;
            }
            2 + key_len + 248
        }
        REC_FOLDER => {
            if data.len() < 88 {
                return None;
            }
            2 + key_len + 88
        }
        REC_FOLDER_THREAD | REC_FILE_THREAD => {
            // Variable length; at minimum reserved+parentID+empty unistr.
            if data.len() < 10 {
                return None;
            }
            let (_, name_len) = unistr(data, 8, 255)?;
            2 + key_len + 8 + name_len
        }
        _ => return None,
    };
    Some((rec_len, key))
}

/// Sanitise an on-disk name for path use (control chars, `/` → `_`).
pub(crate) fn clean_name(raw: &str) -> String {
    util::sanitize_name(raw)
}
