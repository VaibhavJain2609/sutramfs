//! Attributes-file records (HFS+ extended attributes) and AppleFSCompression
//! (`com.apple.decmpfs`) handling.
//!
//! Attr keys are `(fileID, startBlock, name)`; record types:
//! `0x10` inline data, `0x20` fork data (attr data in its own extents),
//! `0x30` extents record (continuation extents for a large attr).
//!
//! The `com.apple.decmpfs` xattr marks a compressed file: 16-byte header
//! (LE magic `"cmpf"` = 0x636d7066, LE `compression_type`, LE
//! `uncompressed_size`), then either an inline payload (odd types) or a
//! resource-fork block table (even types). zlib types (3 inline, 4 resource
//! fork) are decompressed via `miniz_oxide`; LZVN/LZFSE/LZBITMAP are
//! reported `Unsupported`.

use sutram_fs::{FsError, Result};
use sutram_io::le;

use crate::vh::{Extent, ForkData};

/// Record types in the attributes file.
pub(crate) const ATTR_INLINE: u32 = 0x10;
pub(crate) const ATTR_FORK_DATA: u32 = 0x20;
pub(crate) const ATTR_EXTENTS: u32 = 0x30;

/// The name marking a decmpfs-compressed file.
pub(crate) const DECMPFS_XATTR: &str = "com.apple.decmpfs";
/// `DECMPFS_MAGIC` — LE u32 0x636d7066 (bytes `fpmc`).
pub(crate) const DECMPFS_MAGIC: u32 = 0x636D7066;
/// decmpfs header length (payload follows).
pub(crate) const DECMPFS_HDR_LEN: usize = 16;
/// Max bytes a zlib block inflates to inside a resource-fork block table.
const CHUNK_SIZE: u64 = 64 * 1024;

/// Decoded attributes-file key.
#[derive(Debug, Clone)]
pub(crate) struct AttrKey {
    pub cnid: u32,
    /// Logical start block this record continues from (0 for the first).
    pub start_block: u32,
    pub name: String,
    /// `key_len + 2` — bytes consumed by the key in the record.
    pub total_len: usize,
}

/// Parse an attributes-file record key.
pub(crate) fn parse_key(rec: &[u8]) -> Option<AttrKey> {
    let key_len = le::u16_be(rec, 0)? as usize;
    if key_len < 14 || rec.len() < 2 + key_len {
        return None;
    }
    let cnid = le::u32_be(rec, 4)?;
    let start_block = le::u32_be(rec, 8)?;
    let nlen = le::u16_be(rec, 12)? as usize;
    if nlen > 127 {
        return None;
    }
    let mut units = Vec::with_capacity(nlen);
    for i in 0..nlen {
        units.push(le::u16_be(rec, 14 + i * 2)?);
    }
    // key_len covers pad..end of name = 12 + 2*nlen.
    if key_len != 12 + nlen * 2 {
        return None;
    }
    Some(AttrKey {
        cnid,
        start_block,
        name: String::from_utf16_lossy(&units),
        total_len: 2 + key_len,
    })
}

/// Decoded attribute record data.
#[derive(Debug)]
pub(crate) enum AttrData {
    /// `0x10`: attr bytes live in the record itself. `data_off`/`len` are
    /// offsets *within the record slice* (add to the record's disk offset
    /// for absolute provenance).
    Inline {
        /// Offset of the attribute bytes inside the record.
        data_off: usize,
        /// Attribute byte length (`u16` on disk).
        len: u16,
    },
    /// `0x20`: attr bytes live in a dedicated fork's extents.
    ForkData(ForkData),
    /// `0x30`: continuation extent for a large attribute.
    Extents(Extent),
    Other(u32),
}

/// Parse an attribute record's data half.
pub(crate) fn parse_record(data: &[u8]) -> Option<AttrData> {
    let ty = le::u32_be(data, 0)?;
    Some(match ty {
        ATTR_INLINE => {
            // recordType @0, reserved1 @4, reserved2[6] @8, length u16 @14,
            // bytes @16.
            if data.len() < 16 {
                return None;
            }
            let len = le::u16_be(data, 14)?;
            AttrData::Inline { data_off: 16, len }
        }
        ATTR_FORK_DATA => {
            if data.len() < 88 {
                return None;
            }
            AttrData::ForkData(ForkData::parse(data, 8)?)
        }
        ATTR_EXTENTS => {
            if data.len() < 16 {
                return None;
            }
            AttrData::Extents(Extent {
                start: le::u32_be(data, 8)?,
                count: le::u32_be(data, 12)?,
            })
        }
        other => AttrData::Other(other),
    })
}

/// A parsed `com.apple.decmpfs` xattr header.
#[derive(Debug, Clone)]
pub(crate) struct DecmpfsHeader {
    /// `compression_type` (codec + location selector).
    pub compression_type: u32,
    /// Declared uncompressed size.
    pub uncompressed_size: u64,
    /// Inline payload after the 16-byte header (may be empty).
    pub inline: Vec<u8>,
}

/// Parse the decmpfs xattr value. `xattr` is the raw attribute bytes.
/// Returns `Err(Corrupt)` for short/bad-magic values.
pub(crate) fn parse_decmpfs(xattr: &[u8]) -> Result<DecmpfsHeader> {
    if xattr.len() < DECMPFS_HDR_LEN {
        return Err(FsError::truncated(
            0,
            DECMPFS_HDR_LEN as u64,
            xattr.len() as u64,
        ));
    }
    let magic = le::u32(xattr, 0).unwrap_or(0);
    if magic != DECMPFS_MAGIC {
        return Err(FsError::corrupt(
            0,
            format!("decmpfs magic {magic:#010x} != {DECMPFS_MAGIC:#010x}"),
        ));
    }
    Ok(DecmpfsHeader {
        compression_type: le::u32(xattr, 4).unwrap_or(0),
        uncompressed_size: le::u64(xattr, 8).unwrap_or(0),
        inline: xattr[DECMPFS_HDR_LEN..].to_vec(),
    })
}

/// Human-readable codec/location name for a `compression_type`.
pub(crate) fn decmpfs_type_name(t: u32) -> &'static str {
    match t {
        1 | 9 => "uncompressed-inline",
        3 => "zlib-inline",
        4 => "zlib-resource-fork",
        5 => "dedup-store",
        7 => "lzvn-inline",
        8 => "lzvn-resource-fork",
        10 => "uncompressed-resource-fork",
        11 => "lzfse-inline",
        12 => "lzfse-resource-fork",
        13 => "lzbitmap-inline",
        14 => "lzbitmap-resource-fork",
        _ => "unknown",
    }
}

/// Storage-location parity rule: **even** `compression_type`s keep their
/// payload in the file's resource fork (block table), **odd** types inline
/// it after the xattr header. Used for provenance (`allocated_ranges`) even
/// when the codec itself is unsupported.
pub(crate) fn decmpfs_is_rsrc(t: u32) -> bool {
    t != 0 && t % 2 == 0
}

/// Inflate a zlib/DEFLATE stream, capped at `cap` output bytes.
fn inflate(data: &[u8], cap: u64) -> Result<Vec<u8>> {
    miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(data, cap as usize)
        .map_err(|e| FsError::corrupt(0, format!("decmpfs zlib inflate failed: {e:?}")))
}

/// Decompress a decmpfs payload.
///
/// `hdr` comes from [`parse_decmpfs`]; `rsrc` is the resource fork's bytes
/// when the type needs it. Returns `Err(Unsupported)` for LZVN/LZFSE/etc.
pub(crate) fn decompress(hdr: &DecmpfsHeader, rsrc: Option<&[u8]>) -> Result<Vec<u8>> {
    let cap = hdr.uncompressed_size.max(CHUNK_SIZE);
    match hdr.compression_type {
        // Uncompressed data stored verbatim after the header.
        1 | 9 => Ok(hdr.inline.clone()),
        // zlib inline; a leading 0xFF means the rest is stored verbatim.
        3 => match hdr.inline.first() {
            Some(0xFF) => Ok(hdr.inline[1..].to_vec()),
            _ => inflate(&hdr.inline, cap),
        },
        // zlib in the resource fork: CmpfRsrcHead + block table.
        4 => {
            let rsrc = rsrc.ok_or_else(|| FsError::Corrupt {
                offset: 0,
                msg: "decmpfs type 4 requires the resource fork".into(),
            })?;
            decompress_rsrc_table(rsrc, hdr.uncompressed_size)
        }
        // Uncompressed chunked resource fork.
        10 => {
            let rsrc = rsrc.ok_or_else(|| FsError::Corrupt {
                offset: 0,
                msg: "decmpfs type 10 requires the resource fork".into(),
            })?;
            decompress_rsrc_table_raw(rsrc, hdr.uncompressed_size)
        }
        other => Err(FsError::unsupported(format!(
            "decmpfs compression_type {other} ({})",
            decmpfs_type_name(other)
        ))),
    }
}

/// Parse the zlib resource-fork block table (decmpfs type 4):
/// `CmpfRsrcHead` (BE u32 headerSize, totalSize, dataSize, flags), then at
/// `headerSize`: BE u32 dataSize, LE u32 numBlocks, `numBlocks` × LE
/// `(offset, size)` — offsets relative to `headerSize`.
fn decompress_rsrc_table(rsrc: &[u8], uncompressed_size: u64) -> Result<Vec<u8>> {
    let header_size = le::u32_be(rsrc, 0).unwrap_or(0) as usize;
    if header_size < 16 || header_size + 8 > rsrc.len() {
        return Err(FsError::corrupt(
            0,
            format!("decmpfs rsrc header_size {header_size} out of range"),
        ));
    }
    let num_blocks = le::u32(rsrc, header_size + 4).unwrap_or(0) as usize;
    let table = header_size + 8;
    if num_blocks > 1_000_000 || table + num_blocks * 8 > rsrc.len() {
        return Err(FsError::corrupt(
            header_size as u64,
            format!("decmpfs rsrc block count {num_blocks} out of range"),
        ));
    }
    let mut out = Vec::with_capacity(uncompressed_size.min(1 << 26) as usize);
    for i in 0..num_blocks {
        let off = le::u32(rsrc, table + i * 8).unwrap_or(0) as usize;
        let size = le::u32(rsrc, table + i * 8 + 4).unwrap_or(0) as usize;
        let abs = header_size + off;
        let chunk = rsrc
            .get(abs..abs.saturating_add(size))
            .ok_or_else(|| FsError::truncated(abs as u64, size as u64, rsrc.len() as u64))?;
        // A block whose first byte is 0xFF stores its tail verbatim.
        if chunk.first() == Some(&0xFF) {
            out.extend_from_slice(&chunk[1..]);
        } else {
            out.extend_from_slice(&inflate(chunk, CHUNK_SIZE)?);
        }
        if out.len() as u64 >= uncompressed_size {
            break;
        }
    }
    out.truncate(uncompressed_size as usize);
    Ok(out)
}

/// Type 10: chunked but uncompressed resource fork — same table, raw bytes.
fn decompress_rsrc_table_raw(rsrc: &[u8], uncompressed_size: u64) -> Result<Vec<u8>> {
    let header_size = le::u32_be(rsrc, 0).unwrap_or(0) as usize;
    if header_size < 16 || header_size + 8 > rsrc.len() {
        return Err(FsError::corrupt(
            0,
            format!("decmpfs rsrc header_size {header_size} out of range"),
        ));
    }
    let num_blocks = le::u32(rsrc, header_size + 4).unwrap_or(0) as usize;
    let table = header_size + 8;
    if num_blocks > 1_000_000 || table + num_blocks * 8 > rsrc.len() {
        return Err(FsError::corrupt(
            header_size as u64,
            format!("decmpfs rsrc block count {num_blocks} out of range"),
        ));
    }
    let mut out = Vec::with_capacity(uncompressed_size.min(1 << 26) as usize);
    for i in 0..num_blocks {
        let off = le::u32(rsrc, table + i * 8).unwrap_or(0) as usize;
        // Block-run entries are little-endian, same table as type 4.
        let size = le::u32(rsrc, table + i * 8 + 4).unwrap_or(0) as usize;
        let abs = header_size + off;
        let chunk = rsrc
            .get(abs..abs.saturating_add(size))
            .ok_or_else(|| FsError::truncated(abs as u64, size as u64, rsrc.len() as u64))?;
        out.extend_from_slice(chunk);
        if out.len() as u64 >= uncompressed_size {
            break;
        }
    }
    out.truncate(uncompressed_size as usize);
    Ok(out)
}
