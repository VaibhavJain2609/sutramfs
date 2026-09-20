//! File-system-tree records (`jkey`/`jrec`) — the leaf payload of the
//! volume's file-system B-tree (`OBJECT_TYPE_FSTREE`).
//!
//! Every key begins with `j_key_t.obj_id_and_type`: the low 60 bits are the
//! file-system object identifier (inode/CNID) and the high 4 bits the record
//! type. The rest of the key, and the value layout, depend on the type.

use std::collections::HashMap;

use sutram_fs::{FsError, Result};
use sutram_io::le;

/// `obj_id_and_type` split: low 60 bits oid, high 4 bits type.
pub(crate) const OBJ_ID_MASK: u64 = 0x0fff_ffff_ffff_ffff;
pub(crate) const OBJ_TYPE_SHIFT: u32 = 60;

/// `j_key_t` record types (the four high bits of `obj_id_and_type`).
pub(crate) mod jtype {
    pub const SNAP_METADATA: u64 = 0x1;
    pub const EXTENT: u64 = 0x2;
    pub const INODE: u64 = 0x3;
    pub const XATTR: u64 = 0x4;
    pub const SIBLING_LINK: u64 = 0x5;
    pub const CRYPTO_STATE: u64 = 0x7;
    pub const FILE_EXTENT: u64 = 0x8;
    pub const DIR_REC: u64 = 0x9;
    pub const DIR_STATS: u64 = 0xa;
    pub const SNAP_NAME: u64 = 0xb;
    pub const SIBLING_MAP: u64 = 0xc;
}

/// Reserved file-system object identifier: the volume root directory.
pub(crate) const ROOT_DIR_INODE: u64 = 2;

/// Directory-entry file-type bits (`j_drec_val_t.flags & DREC_TYPE_MASK`).
pub(crate) const DREC_TYPE_MASK: u16 = 0x000f;

/// `j_xattr_val_t.flags`.
pub(crate) const XATTR_DATA_STREAM: u16 = 0x0001;
pub(crate) const XATTR_DATA_EMBEDDED: u16 = 0x0002;

/// `j_file_extent_val_t.len_and_flags` split: low 56 bits length, top byte flags.
pub(crate) const EXTENT_LEN_MASK: u64 = 0x00ff_ffff_ffff_ffff;

/// `j_drec_hashed_key_t.name_len_and_hash` split.
pub(crate) const DREC_LEN_MASK: u32 = 0x0000_03ff; // low 10 bits
pub(crate) const DREC_HASH_SHIFT: u32 = 10;

/// Extended-field types (`x_field_t.x_type`) this parser interprets.
pub(crate) mod xtype {
    pub const DREC_SIBLING_ID: u8 = 1;
    pub const INO_SNAP_XID: u8 = 1;
    pub const INO_DOCUMENT_ID: u8 = 3;
    pub const INO_NAME: u8 = 4;
    pub const INO_PREV_FSIZE: u8 = 5;
    pub const INO_FINDER_INFO: u8 = 7;
    pub const INO_DSTREAM: u8 = 8;
    pub const INO_SPARSE_BYTES: u8 = 13;
    pub const INO_RDEV: u8 = 14;
}

/// `internal_flags` of `j_inode_val_t` (selection).
pub(crate) mod inode_flags {
    pub const APFS_PRIVATE: u64 = 0x1;
    pub const IS_SPARSE: u64 = 0x200;
}

/// `S_IFMT` file-type bits of the inode `mode` field.
pub(crate) const S_IFMT: u16 = 0o170000;
pub(crate) const S_IFDIR: u16 = 0o040000;
pub(crate) const S_IFREG: u16 = 0o100000;
pub(crate) const S_IFLNK: u16 = 0o120000;

/// Decode `j_key_t`.
pub(crate) fn split_key(key: &[u8]) -> Option<(u64, u64)> {
    let raw = le::u64(key, 0)?;
    Some((raw & OBJ_ID_MASK, raw >> OBJ_TYPE_SHIFT))
}

/// `j_dstream_t` — a file's data-stream descriptor (40 bytes), found in the
/// `INO_EXT_TYPE_DSTREAM` extended field. Carries the logical size.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Dstream {
    pub size: u64,
    pub alloced_size: u64,
    pub default_crypto_id: u64,
    pub total_bytes_written: u64,
    pub total_bytes_read: u64,
}

impl Dstream {
    fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 40 {
            return None;
        }
        Some(Dstream {
            size: le::u64(buf, 0)?,
            alloced_size: le::u64(buf, 8)?,
            default_crypto_id: le::u64(buf, 16)?,
            total_bytes_written: le::u64(buf, 24)?,
            total_bytes_read: le::u64(buf, 32)?,
        })
    }
}

/// One decoded extended field: `(x_type, x_flags, data)`.
///
/// `xf_blob_t` layout: `u16 xf_num_exts`, `u16 xf_used_data`, then
/// `x_field_t[num]` ({u8 type, u8 flags, u16 size}), then the values in
/// declared order, each starting at the next 8-byte-aligned offset relative
/// to the start of the value area.
pub(crate) fn parse_xfields(buf: &[u8]) -> Vec<(u8, u8, &[u8])> {
    let mut out = Vec::new();
    if buf.len() < 4 {
        return out;
    }
    let num = le::u16(buf, 0).unwrap_or(0) as usize;
    // Plausibility bound: each descriptor is 4 bytes.
    let desc_area = 4usize;
    let val_area = match desc_area.checked_add(num.checked_mul(4).unwrap_or(usize::MAX)) {
        Some(v) if v <= buf.len() => v,
        _ => return out,
    };
    let mut rel = 0usize;
    for i in 0..num {
        let d = desc_area + i * 4;
        let xt = buf[d];
        let xf = buf[d + 1];
        let xs = le::u16(buf, d + 2).unwrap_or(0) as usize;
        let abs = val_area + rel;
        if abs + xs > buf.len() {
            break;
        }
        out.push((xt, xf, &buf[abs..abs + xs]));
        rel += xs;
        rel = (rel + 7) & !7;
    }
    out
}

/// Decoded `j_inode_val_t` (fixed part is 92 bytes; xfields follow).
#[derive(Debug, Clone, Default)]
pub(crate) struct InodeVal {
    pub parent_id: u64,
    pub private_id: u64,
    pub create_time: i64,
    pub mod_time: i64,
    pub change_time: i64,
    pub access_time: i64,
    pub internal_flags: u64,
    /// nchildren for directories / nlink for files.
    pub nchildren_or_nlink: u32,
    pub default_protection_class: u32,
    pub write_generation_counter: u32,
    pub bsd_flags: u32,
    pub owner: u32,
    pub group: u32,
    pub mode: u16,
    /// `INO_EXT_TYPE_NAME` — primary-link name for hardlinked inodes.
    pub xf_name: Option<String>,
    /// `INO_EXT_TYPE_DSTREAM` — the data stream (size, crypto id).
    pub dstream: Option<Dstream>,
    /// `INO_EXT_TYPE_SPARSE_BYTES`.
    pub sparse_bytes: Option<u64>,
    /// `INO_EXT_TYPE_DOCUMENT_ID`.
    pub document_id: Option<u32>,
    /// `INO_EXT_TYPE_RDEV` — raw device id bytes.
    pub rdev: Option<u64>,
    /// `INO_EXT_TYPE_PREV_FSIZE`.
    pub prev_fsize: Option<u64>,
    /// `INO_EXT_TYPE_SNAP_XID`.
    pub snap_xid: Option<u64>,
    /// `INO_EXT_TYPE_FINDER_INFO` seen.
    pub has_finder_info: bool,
}

impl InodeVal {
    pub(crate) fn decode(val: &[u8]) -> Result<Self> {
        if val.len() < 92 {
            return Err(FsError::corrupt(0, "inode value < 92 bytes"));
        }
        let mut v = InodeVal {
            parent_id: le::u64(val, 0).unwrap_or(0),
            private_id: le::u64(val, 8).unwrap_or(0),
            create_time: le::u64(val, 16).unwrap_or(0) as i64,
            mod_time: le::u64(val, 24).unwrap_or(0) as i64,
            change_time: le::u64(val, 32).unwrap_or(0) as i64,
            access_time: le::u64(val, 40).unwrap_or(0) as i64,
            internal_flags: le::u64(val, 48).unwrap_or(0),
            nchildren_or_nlink: le::u32(val, 56).unwrap_or(0),
            default_protection_class: le::u32(val, 60).unwrap_or(0),
            write_generation_counter: le::u32(val, 64).unwrap_or(0),
            bsd_flags: le::u32(val, 68).unwrap_or(0),
            owner: le::u32(val, 72).unwrap_or(0),
            group: le::u32(val, 76).unwrap_or(0),
            mode: le::u16(val, 80).unwrap_or(0),
            ..Default::default()
        };
        for (xt, _xf, data) in parse_xfields(&val[92..]) {
            match xt {
                xtype::INO_NAME => {
                    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                    v.xf_name =
                        Some(String::from_utf8_lossy(&data[..end]).into_owned());
                }
                xtype::INO_DSTREAM => v.dstream = Dstream::decode(data),
                xtype::INO_SPARSE_BYTES => {
                    v.sparse_bytes = le::u64(data, 0)
                }
                xtype::INO_DOCUMENT_ID => {
                    v.document_id = le::u32(data, 0)
                }
                xtype::INO_RDEV => v.rdev = le::u64(data, 0),
                xtype::INO_PREV_FSIZE => v.prev_fsize = le::u64(data, 0),
                xtype::INO_SNAP_XID => v.snap_xid = le::u64(data, 0),
                xtype::INO_FINDER_INFO => v.has_finder_info = true,
                _ => {}
            }
        }
        Ok(v)
    }
}

/// A decoded fs-tree leaf record.
#[derive(Debug)]
pub(crate) enum JRecord {
    /// `APFS_TYPE_INODE`.
    Inode { oid: u64, val: InodeVal },
    /// `APFS_TYPE_DIR_REC` (key carries parent oid + name).
    Drec {
        parent_oid: u64,
        name: String,
        name_hash: Option<u32>,
        file_id: u64,
        date_added: i64,
        flags: u16,
        /// `DREC_EXT_TYPE_SIBLING_ID` xfield when present (hardlink).
        sibling_id: Option<u64>,
    },
    /// `APFS_TYPE_FILE_EXTENT` — keyed by the inode's *private_id*.
    FileExtent {
        private_id: u64,
        logical_addr: u64,
        len: u64,
        flags: u8,
        phys_block: u64,
        crypto_id: u64,
    },
    /// `APFS_TYPE_XATTR`.
    Xattr {
        oid: u64,
        name: String,
        flags: u16,
        data_len: u16,
        /// Embedded data (XATTR_DATA_EMBEDDED).
        embedded: Option<Vec<u8>>,
        /// `j_xattr_dstream_t.xattr_obj_id` for stream xattrs.
        stream_oid: Option<u64>,
    },
    /// `APFS_TYPE_SIBLING_LINK` — extra hardlink name.
    SiblingLink {
        oid: u64,
        sibling_id: u64,
        parent_id: u64,
        name: String,
    },
    /// `APFS_TYPE_SIBLING_MAP` — sibling_id → file_id.
    SiblingMap { sibling_id: u64, file_id: u64 },
    /// `APFS_TYPE_DIR_STATS`.
    DirStats {
        oid: u64,
        num_children: u64,
        total_size: u64,
    },
    /// `APFS_TYPE_SNAP_NAME` — name → snap xid.
    SnapName { name: String, snap_xid: u64 },
    /// `APFS_TYPE_SNAP_METADATA` (snapshot-metadata tree).
    SnapMetadata {
        snap_xid: u64,
        extentref_tree_oid: u64,
        sblock_oid: u64,
        create_time: i64,
        change_time: i64,
        flags: u32,
        name: String,
    },
    /// `APFS_TYPE_CRYPTO_STATE` — encryption state record present.
    CryptoState { oid: u64 },
    /// `APFS_TYPE_EXTENT` — physical extent record (allocated block span).
    PhysExtent { oid: u64, len: u64 },
    /// Anything else — preserved for reporting, not interpreted.
    Other { oid: u64, jtype: u64 },
}

/// Decode one leaf `(key, value)` pair into a [`JRecord`].
///
/// `hashed_drec` selects the `j_drec_hashed_key_t` vs `j_drec_key_t` layout;
/// `auto` sniffs when the caller doesn't know (we try the layout whose
/// declared name length exactly consumes the key).
pub(crate) fn decode_record(key: &[u8], val: &[u8], hashed_drec: Option<bool>) -> Result<JRecord> {
    let (oid, jt) =
        split_key(key).ok_or_else(|| FsError::corrupt(0, "fs record key < 8 bytes"))?;
    match jt {
        jtype::INODE => Ok(JRecord::Inode {
            oid,
            val: InodeVal::decode(val)?,
        }),
        jtype::DIR_REC => decode_drec(key, val, oid, hashed_drec),
        jtype::FILE_EXTENT => {
            let logical_addr = le::u64(key, 8).unwrap_or(0);
            let len_and_flags = le::u64(val, 0).unwrap_or(0);
            Ok(JRecord::FileExtent {
                private_id: oid,
                logical_addr,
                len: len_and_flags & EXTENT_LEN_MASK,
                flags: (len_and_flags >> 56) as u8,
                phys_block: le::u64(val, 8).unwrap_or(0),
                crypto_id: le::u64(val, 16).unwrap_or(0),
            })
        }
        jtype::XATTR => decode_xattr(key, val, oid),
        jtype::SIBLING_LINK => {
            let sibling_id = le::u64(key, 8).unwrap_or(0);
            let parent_id = le::u64(val, 0).unwrap_or(0);
            let name_len = le::u16(val, 8).unwrap_or(0) as usize;
            let name = read_named(&val[10..], name_len);
            Ok(JRecord::SiblingLink {
                oid,
                sibling_id,
                parent_id,
                name,
            })
        }
        jtype::SIBLING_MAP => Ok(JRecord::SiblingMap {
            sibling_id: oid,
            file_id: le::u64(val, 0).unwrap_or(0),
        }),
        jtype::DIR_STATS => Ok(JRecord::DirStats {
            oid,
            num_children: le::u64(val, 0).unwrap_or(0),
            total_size: le::u64(val, 8).unwrap_or(0),
        }),
        jtype::SNAP_NAME => {
            let name_len = le::u16(key, 8).unwrap_or(0) as usize;
            Ok(JRecord::SnapName {
                name: read_named(&key[10..], name_len),
                snap_xid: le::u64(val, 0).unwrap_or(0),
            })
        }
        jtype::SNAP_METADATA => {
            let name_len = le::u16(val, 48).unwrap_or(0) as usize;
            Ok(JRecord::SnapMetadata {
                snap_xid: oid,
                extentref_tree_oid: le::u64(val, 0).unwrap_or(0),
                sblock_oid: le::u64(val, 8).unwrap_or(0),
                create_time: le::u64(val, 16).unwrap_or(0) as i64,
                change_time: le::u64(val, 24).unwrap_or(0) as i64,
                flags: le::u32(val, 44).unwrap_or(0),
                name: read_named(val.get(50..).unwrap_or(&[]), name_len),
            })
        }
        jtype::CRYPTO_STATE => Ok(JRecord::CryptoState { oid }),
        jtype::EXTENT => {
            let len_and_kind = le::u64(val, 0).unwrap_or(0);
            Ok(JRecord::PhysExtent {
                oid,
                len: len_and_kind & OBJ_ID_MASK,
            })
        }
        _ => Ok(JRecord::Other { oid, jtype: jt }),
    }
}

/// Directory-record decode. `hashed_drec`: `Some(true)` forces the hashed
/// layout, `Some(false)` plain, `None` sniffs.
fn decode_drec(
    key: &[u8],
    val: &[u8],
    parent_oid: u64,
    hashed_drec: Option<bool>,
) -> Result<JRecord> {
    let sniff = |hashed: bool| -> Option<(String, Option<u32>)> {
        if hashed {
            let nh = le::u32(key, 8)?;
            let nlen = (nh & DREC_LEN_MASK) as usize;
            if nlen == 0 || 12 + nlen > key.len() {
                return None;
            }
            Some((
                read_named(&key[12..], nlen),
                Some(nh >> DREC_HASH_SHIFT),
            ))
        } else {
            let nlen = le::u16(key, 8)? as usize;
            if nlen == 0 || 10 + nlen > key.len() {
                return None;
            }
            Some((read_named(&key[10..], nlen), None))
        }
    };
    // Exact-length key fits are trusted; otherwise fall back to the flag.
    let hashed_ok = sniff(true).filter(|_| le::u32(key, 8).map(|nh| (nh & DREC_LEN_MASK) as usize + 12 == key.len()).unwrap_or(false));
    let plain_ok = sniff(false).filter(|_| le::u16(key, 8).map(|n| n as usize + 10 == key.len()).unwrap_or(false));
    let (name, hash) = match hashed_drec {
        Some(true) => sniff(true)
            .or(hashed_ok)
            .or(plain_ok)
            .ok_or_else(|| FsError::corrupt(0, "drec key: bad hashed name length"))?,
        Some(false) => sniff(false)
            .or(plain_ok)
            .or(hashed_ok)
            .ok_or_else(|| FsError::corrupt(0, "drec key: bad name length"))?,
        None => hashed_ok.or(plain_ok).ok_or_else(|| {
            FsError::corrupt(0, "drec key: undecodable name field")
        })?,
    };
    let mut sibling_id = None;
    for (xt, _xf, data) in parse_xfields(val.get(18..).unwrap_or(&[])) {
        if xt == xtype::DREC_SIBLING_ID {
            sibling_id = le::u64(data, 0);
        }
    }
    Ok(JRecord::Drec {
        parent_oid,
        name,
        name_hash: hash,
        file_id: le::u64(val, 0).unwrap_or(0),
        date_added: le::u64(val, 8).unwrap_or(0) as i64,
        flags: le::u16(val, 16).unwrap_or(0),
        sibling_id,
    })
}

/// Xattr record decode.
fn decode_xattr(key: &[u8], val: &[u8], oid: u64) -> Result<JRecord> {
    let name_len = le::u16(key, 8).unwrap_or(0) as usize;
    let name = read_named(key.get(10..).unwrap_or(&[]), name_len);
    let flags = le::u16(val, 0).unwrap_or(0);
    let data_len = le::u16(val, 2).unwrap_or(0);
    let data = val.get(4..4 + data_len as usize).unwrap_or(&[]);
    let mut embedded = None;
    let mut stream_oid = None;
    if flags & XATTR_DATA_STREAM != 0 {
        // j_xattr_dstream_t: 8-byte dstream oid + j_dstream_t.
        stream_oid = le::u64(val, 4);
    } else if flags & XATTR_DATA_EMBEDDED != 0 || !data.is_empty() {
        embedded = Some(data.to_vec());
    }
    Ok(JRecord::Xattr {
        oid,
        name,
        flags,
        data_len,
        embedded,
        stream_oid,
    })
}

/// Read a NUL-terminated UTF-8 name of declared length `n` (the on-disk
/// length includes the terminator). Tolerant: trims at the first NUL and
/// lossy-decodes.
fn read_named(buf: &[u8], n: usize) -> String {
    let raw = buf.get(..n.min(buf.len())).unwrap_or(&[]);
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// A decoded directory record with provenance.
#[derive(Debug)]
pub(crate) struct DrecRec {
    pub off: u64,
    pub parent_oid: u64,
    pub name: String,
    pub name_hash: Option<u32>,
    pub file_id: u64,
    pub date_added: i64,
    pub flags: u16,
    pub sibling_id: Option<u64>,
}

/// A decoded file extent with provenance.
#[derive(Debug, Clone)]
pub(crate) struct ExtentRec {
    pub off: u64,
    pub logical_addr: u64,
    pub len: u64,
    pub flags: u8,
    pub phys_block: u64,
    pub crypto_id: u64,
}

/// A decoded xattr record.
#[derive(Debug)]
pub(crate) struct XattrRec {
    pub off: u64,
    pub name: String,
    pub flags: u16,
    pub data_len: u16,
    pub embedded: Option<Vec<u8>>,
    pub stream_oid: Option<u64>,
}

/// A sibling-link (extra hardlink name) record.
#[derive(Debug)]
pub(crate) struct SiblingLinkRec {
    pub off: u64,
    pub oid: u64,
    pub sibling_id: u64,
    pub parent_id: u64,
    pub name: String,
}

/// A snapshot-metadata record.
#[derive(Debug)]
pub(crate) struct SnapMetaRec {
    pub off: u64,
    pub snap_xid: u64,
    pub extentref_tree_oid: u64,
    pub sblock_oid: u64,
    pub create_time: i64,
    pub change_time: i64,
    pub flags: u32,
    pub name: String,
}

/// All live-tree records sorted into per-type indexes.
#[derive(Default)]
pub(crate) struct SplitRecords {
    /// oid → (key disk offset, inode value).
    pub inodes: HashMap<u64, (u64, InodeVal)>,
    /// Directory records (parent_oid, name → file_id).
    pub drecs: Vec<DrecRec>,
    /// private_id → extents (unsorted; sorted on use).
    pub extents: HashMap<u64, Vec<ExtentRec>>,
    /// oid → xattr records.
    pub xattrs: HashMap<u64, Vec<XattrRec>>,
    /// Extra hardlink names.
    pub sibling_links: Vec<SiblingLinkRec>,
    /// sibling_id → file_id.
    pub sibling_map: HashMap<u64, u64>,
    /// oid → (num_children, total_size).
    pub dir_stats: HashMap<u64, (u64, u64)>,
    /// (key offset, name, snap_xid) from fs-tree SNAP_NAME records.
    pub snap_names: Vec<(u64, String, u64)>,
    /// Oids with a crypto-state record (encrypted streams).
    pub crypto_oids: std::collections::HashSet<u64>,
    /// Physical extent records (extent tree material): `(oid, len)`.
    pub phys_extents: Vec<(u64, u64)>,
    /// Unhandled record types: jtype → (count, first oid).
    pub other_count: HashMap<u64, (u64, u64)>,
}
