//! Extended-attribute decoding.
//!
//! `di_aformat == LOCAL` stores a shortform attribute list in the attr
//! fork:
//!
//! ```text
//! {totsize u16, count u8, pad u8}
//! per entry: {namelen u8, valuelen u8, flags u8, name[], value[]}
//! ```
//!
//! `EXTENTS`/`BTREE` attrs live in fsblock leaves ('XFS_ATTR_LEAF_MAGIC'
//! 0xfbee v2 / 'XFS_ATTR3_LEAF_MAGIC' 0x3bee v5, a u16 at offset 8 in the
//! da blkinfo). Leaf entries are `{hashval u32, nameidx u16, flags u8,
//! pad u8}`; at `nameidx` sits either a local `{valuelen u16, namelen u8,
//! name+val}` or a remote `{valueblk u32, valuelen u32, namelen u8, name}`
//! name block. Remote values live in 'XARM' blocks (v5 header, 56 bytes).
//!
//! Flag bits: bit0 local value, bit1 root/"trusted.", bit2
//! secure/"security.", else "user." namespace.

use sutram_fs::{FsError, Result};
use sutram_io::le::{u16_be, u32_be};
use sutram_io::ByteSource;

use crate::crc;
use crate::extent::{collect_extents, Extent};
use crate::inode::Inode;
use crate::sb::Superblock;

const ATTR_LEAF_MAGIC_V2: u16 = 0xFBEE;
const ATTR_LEAF_MAGIC_V3: u16 = 0x3BEE;
/// 'XARM' remote value block magic (v5).
const ATTR_RMT_MAGIC: u32 = 0x5841_524D;
/// Remote value block header length (v5).
const RMT_HDR_LEN: usize = 56;
/// Cap on leaf entries per block and bytes captured per value.
const MAX_ATTRS: usize = 1 << 12;
const MAX_VALUE_CAPTURE: usize = 256;

const FLAG_LOCAL: u8 = 1 << 0;
const FLAG_ROOT: u8 = 1 << 1;
const FLAG_SECURE: u8 = 1 << 2;

/// A decoded extended attribute.
#[derive(Debug, Clone)]
pub(crate) struct Xattr {
    /// Full namespaced name ("user.foo", "trusted.bar", ...).
    pub name: String,
    /// Raw flags byte.
    pub flags: u8,
    /// Declared value length.
    pub value_len: u32,
    /// Value bytes when stored locally or fetched from remote blocks
    /// (truncated at MAX_VALUE_CAPTURE).
    pub value: Option<Vec<u8>>,
    /// True when the value lives in remote 'XARM' blocks.
    pub remote: bool,
    /// Remote value's logical block within the attr fork.
    pub valueblk: u32,
}

/// Namespace prefix implied by the flags byte.
fn prefix(flags: u8) -> &'static str {
    if flags & FLAG_ROOT != 0 {
        "trusted."
    } else if flags & FLAG_SECURE != 0 {
        "security."
    } else {
        "user."
    }
}

/// Parse a shortform attribute list from the attr fork bytes.
pub(crate) fn parse_local(buf: &[u8]) -> Vec<Xattr> {
    let mut out = Vec::new();
    if buf.len() < 4 {
        return out;
    }
    // xfs_attr_sf_hdr = {totsize u16, count u8} — 3 bytes, no pad.
    let count = buf[2] as usize;
    let mut pos = 3;
    for _ in 0..count.min(MAX_ATTRS) {
        if pos + 3 > buf.len() {
            break;
        }
        let namelen = buf[pos] as usize;
        let valuelen = buf[pos + 1] as usize;
        let flags = buf[pos + 2];
        let start = pos + 3;
        if start + namelen + valuelen > buf.len() {
            break;
        }
        let name = String::from_utf8_lossy(&buf[start..start + namelen]).into_owned();
        let value = buf[start + namelen..start + namelen + valuelen].to_vec();
        out.push(Xattr {
            name: format!("{}{name}", prefix(flags)),
            flags,
            value_len: valuelen as u32,
            value: Some(value),
            remote: false,
            valueblk: 0,
        });
        pos = start + namelen + valuelen;
    }
    out
}

/// Collect attributes for an inode — handles LOCAL, EXTENTS and BTREE
/// attr-fork formats.
pub(crate) fn collect(
    src: &dyn ByteSource,
    sb: &Superblock,
    inode: &Inode,
) -> Result<Vec<Xattr>> {
    let afork = match inode.afork() {
        Some(a) if !a.is_empty() => a,
        _ => return Ok(Vec::new()),
    };
    match inode.aformat {
        crate::inode::FMT_LOCAL => Ok(parse_local(afork)),
        crate::inode::FMT_EXTENTS | crate::inode::FMT_BTREE => {
            let extents = collect_extents(src, sb, afork, inode.aformat, inode.anextents as u64)?;
            collect_leaf(src, sb, &extents)
        }
        _ => Ok(Vec::new()),
    }
}

/// Walk every extent of an extent/btree attr fork and parse leaf blocks.
fn collect_leaf(
    src: &dyn ByteSource,
    sb: &Superblock,
    extents: &[Extent],
) -> Result<Vec<Xattr>> {
    let mut out = Vec::new();
    let bs = sb.blocksize as usize;
    for e in extents {
        for b in 0..e.len {
            if out.len() >= MAX_ATTRS {
                return Ok(out);
            }
            let off = sb.fsb_off(e.fsb + b as u64);
            let blk = src.read_slice(off, bs).map_err(FsError::Io)?;
            if blk.len() < 32 {
                continue;
            }
            let magic = u16_be(&blk, 8).unwrap_or(0);
            let v3 = match magic {
                ATTR_LEAF_MAGIC_V3 => true,
                ATTR_LEAF_MAGIC_V2 => false,
                _ => continue, // may be a remote value block or node
            };
            if v3 && sb.has_crc() {
                let stored = u32::from_le_bytes([blk[12], blk[13], blk[14], blk[15]]);
                if crc::verify(&blk, 12, stored) == Some(false) {
                    return Err(FsError::corrupt(off, "attr leaf CRC mismatch"));
                }
            }
            // Header: v3 = 80 B, v2 = 32 B; entries follow.
            let (hdr_len, count_off) = if v3 { (80usize, 56usize) } else { (32, 12) };
            let count = u16_be(&blk, count_off).unwrap_or(0) as usize;
            for i in 0..count.min(MAX_ATTRS) {
                let eoff = hdr_len + i * 8;
                if eoff + 8 > blk.len() {
                    break;
                }
                let nameidx = u16_be(&blk, eoff + 4).unwrap_or(0) as usize;
                let flags = blk[eoff + 6];
                if let Some(mut x) = parse_nameblk(&blk, nameidx, flags) {
                    // Fetch bounded remote values ('XARM' blocks) eagerly.
                    if x.remote
                        && x.value_len as usize <= MAX_VALUE_CAPTURE * 16
                        && x.value_len > 0
                    {
                        if let Ok(v) =
                            remote_read(src, sb, extents, x.valueblk, x.value_len)
                        {
                            let mut v = v;
                            v.truncate(MAX_VALUE_CAPTURE);
                            x.value = Some(v);
                        }
                    }
                    out.push(x);
                }
            }
        }
    }
    Ok(out)
}

/// Decode the name block at `nameidx` inside an attr leaf.
fn parse_nameblk(blk: &[u8], nameidx: usize, flags: u8) -> Option<Xattr> {
    if nameidx + 3 > blk.len() {
        return None;
    }
    if flags & FLAG_LOCAL != 0 {
        let valuelen = u16_be(blk, nameidx)? as usize;
        let namelen = *blk.get(nameidx + 2)? as usize;
        let start = nameidx + 3;
        if start + namelen + valuelen > blk.len() {
            return None;
        }
        let name = String::from_utf8_lossy(&blk[start..start + namelen]).into_owned();
        let mut value = blk[start + namelen..start + namelen + valuelen].to_vec();
        value.truncate(MAX_VALUE_CAPTURE);
        Some(Xattr {
            name: format!("{}{name}", prefix(flags)),
            flags,
            value_len: valuelen as u32,
            value: Some(value),
            remote: false,
            valueblk: 0,
        })
    } else {
        // Remote: {valueblk u32, valuelen u32, namelen u8, name[]}.
        let valueblk = u32_be(blk, nameidx)?;
        let valuelen = u32_be(blk, nameidx + 4)?;
        let namelen = *blk.get(nameidx + 8)? as usize;
        let start = nameidx + 9;
        if start + namelen > blk.len() {
            return None;
        }
        let name = String::from_utf8_lossy(&blk[start..start + namelen]).into_owned();
        Some(Xattr {
            name: format!("{}{name}", prefix(flags)),
            flags,
            value_len: valuelen,
            value: None,
            remote: true,
            valueblk,
        })
    }
}

/// Read a remote attribute value: `valueblk` is a logical block in the
/// attr fork; each referenced block carries an 'XARM' header on v5.
pub(crate) fn remote_read(
    src: &dyn ByteSource,
    sb: &Superblock,
    extents: &[Extent],
    valueblk: u32,
    valuelen: u32,
) -> Result<Vec<u8>> {
    let bs = sb.blocksize as usize;
    // v5 remote blocks carry a 56-byte 'XARM' header; v4 blocks are raw.
    let per_block = if sb.is_v5() { bs - RMT_HDR_LEN } else { bs };
    let nblocks = (valuelen as usize).div_ceil(per_block);
    let mut out = Vec::with_capacity(valuelen.min(1 << 20) as usize);
    for i in 0..nblocks.max(1) {
        let logical = valueblk as u64 + i as u64;
        let fsb = extents
            .iter()
            .find(|e| logical >= e.fileoff && logical < e.fileoff + e.len as u64)
            .map(|e| e.fsb + (logical - e.fileoff));
        let fsb = match fsb {
            Some(f) => f,
            None => return Err(FsError::corrupt(0, "remote attr extent gap")),
        };
        let off = sb.fsb_off(fsb);
        let blk = src.read_slice(off, bs).map_err(FsError::Io)?;
        if sb.is_v5() {
            if blk.len() < RMT_HDR_LEN || u32_be(&blk, 0) != Some(ATTR_RMT_MAGIC) {
                return Err(FsError::corrupt(off, "bad XARM remote attr header"));
            }
            let take = (bs - RMT_HDR_LEN).min(valuelen as usize - out.len().min(valuelen as usize));
            out.extend_from_slice(&blk[RMT_HDR_LEN..RMT_HDR_LEN + take]);
        } else {
            let take = bs.min(valuelen as usize - out.len().min(valuelen as usize));
            out.extend_from_slice(&blk[..take.min(blk.len())]);
        }
        if out.len() >= valuelen as usize {
            break;
        }
    }
    out.truncate(valuelen as usize);
    Ok(out)
}
