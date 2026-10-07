//! Generic APFS B-tree node decoding (`btree_node_phys_t`).
//!
//! A node block is laid out as:
//!
//! ```text
//!   0  obj_phys_t            32 B object header (type BTREE / BTREE_NODE)
//!  32  node header           24 B (flags, level, nkeys, 4× nloc_t)
//!  56  btn_data[]            table of contents, then keys growing forward;
//!                           values grow *backward* from the end of the
//!                           node's storage (end of block; for the root
//!                           node the last 40 B hold `btree_info_t`).
//! ```
//!
//! Table-of-contents entries are `kvloc_t` (8 B: key nloc + value nloc) or
//! `kvoff_t` (4 B: offsets only) when `BTNODE_FIXED_KV_SIZE` is set — lengths
//! then come from the root's `btree_info_fixed_t` (or the caller's known
//! sizes). Key offsets count forward from the start of the key area (which
//! begins right after the table of contents). Value offsets count backward
//! from the end of the value area to the *start* of the value.
//!
//! Internal-node values are always 8-byte child references: a physical block
//! number for `BTREE_PHYSICAL` trees, an ephemeral oid for `BTREE_EPHEMERAL`
//! trees (resolved via the checkpoint map), and a virtual oid otherwise
//! (resolved via the tree's object map).

use sutram_fs::{FsError, Result};
use sutram_io::le;

use crate::object::{otype, ObjHdr};

/// `btn_flags` bits.
pub(crate) const BTNODE_ROOT: u16 = 0x0001;
pub(crate) const BTNODE_LEAF: u16 = 0x0002;
pub(crate) const BTNODE_FIXED_KV_SIZE: u16 = 0x0004;

/// `bt_flags` (btree_info_t) bits that select the child-pointer namespace.
pub(crate) const BTREE_EPHEMERAL: u32 = 0x0000_0008;
pub(crate) const BTREE_PHYSICAL: u32 = 0x0000_0010;

/// `nloc_t`/`kvloc_t` sentinel for "no value" (ghost entry).
pub(crate) const BTOFF_INVALID: u16 = 0xffff;

/// Absolute offset of `btn_data` inside a node block.
const BTN_DATA: usize = 56;

/// `btree_info_t` size, stored at the end of the root node's block.
const BTREE_INFO_SIZE: usize = 40;

/// Hard cap on tree depth and node fan-in — untrusted images contain cycles.
pub(crate) const MAX_TREE_DEPTH: usize = 64;

/// A decoded B-tree node borrowing its block.
pub(crate) struct BtreeNode<'a> {
    pub(crate) block: &'a [u8],
    /// Object header (already checksum-verified by the caller path).
    pub(crate) hdr: ObjHdr,
    /// Absolute byte offset of this node block on the source.
    pub(crate) disk_offset: u64,
    /// `btn_level` — 0 for leaves.
    pub(crate) level: u16,
    pub(crate) nkeys: u32,
    /// Start of the table of contents inside `block`.
    toc_base: usize,
    /// Start of the key area (end of the table of contents).
    keys_start: usize,
    /// End of the value area (values grow backward from here).
    vals_end: usize,
    fixed_kv: bool,
    is_root: bool,
    is_leaf: bool,
}

/// Decoded `btree_info_t` from the end of a root node.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BtreeInfo {
    pub flags: u32,
    pub node_size: u32,
    pub key_size: u32,
    pub val_size: u32,
    pub key_count: u64,
    pub node_count: u64,
}

impl<'a> BtreeNode<'a> {
    /// Parse a node block. `block` is exactly one block read at `off`.
    /// The object checksum must already have been verified by the caller
    /// (object reads go through `crate::fs` helpers that enforce it).
    pub(crate) fn parse(block: &'a [u8], off: u64) -> Result<Self> {
        if block.len() < BTN_DATA {
            return Err(FsError::corrupt(off, "btree node smaller than header"));
        }
        let hdr = ObjHdr::parse(block, off, false)?;
        let t = hdr.type_code();
        if t != otype::BTREE && t != otype::BTREE_NODE {
            return Err(FsError::corrupt(
                off + 24,
                format!("o_type {:#x} is not a btree node", hdr.otype),
            ));
        }
        let flags = le::u16(block, 32).unwrap_or(0);
        let level = le::u16(block, 34).unwrap_or(0);
        let nkeys = le::u32(block, 36).unwrap_or(0);
        let toc_off = le::u16(block, 40).unwrap_or(0) as usize;
        let toc_len = le::u16(block, 42).unwrap_or(0) as usize;

        let is_root = flags & BTNODE_ROOT != 0;
        let is_leaf = flags & BTNODE_LEAF != 0;
        let fixed_kv = flags & BTNODE_FIXED_KV_SIZE != 0;

        let toc_base = BTN_DATA + toc_off;
        let keys_start = toc_base
            .checked_add(toc_len)
            .ok_or_else(|| FsError::corrupt(off + 40, "btree table space overflows"))?;
        let vals_end = if is_root {
            block
                .len()
                .checked_sub(BTREE_INFO_SIZE)
                .ok_or_else(|| FsError::corrupt(off, "btree root smaller than footer"))?
        } else {
            block.len()
        };
        if keys_start > vals_end || toc_base > block.len() {
            return Err(FsError::corrupt(
                off + 40,
                "btree table of contents collides with value area",
            ));
        }
        // The table must be able to hold nkeys entries (4 or 8 bytes each).
        let entry_size = if fixed_kv { 4usize } else { 8 };
        let needed = (nkeys as usize)
            .checked_mul(entry_size)
            .ok_or_else(|| FsError::corrupt(off + 36, "btree nkeys overflow"))?;
        if needed > toc_len {
            return Err(FsError::corrupt(
                off + 36,
                format!("btree nkeys {nkeys} exceeds table space {toc_len}"),
            ));
        }
        Ok(BtreeNode {
            block,
            hdr,
            disk_offset: off,
            level,
            nkeys,
            toc_base,
            keys_start,
            vals_end,
            fixed_kv,
            is_root,
            is_leaf,
        })
    }

    pub(crate) fn is_root(&self) -> bool {
        self.is_root
    }
    pub(crate) fn is_leaf(&self) -> bool {
        self.is_leaf
    }

    /// `btree_info_t` from the end of the block (root nodes only).
    pub(crate) fn info(&self) -> Option<BtreeInfo> {
        if !self.is_root {
            return None;
        }
        let off = self.block.len().checked_sub(BTREE_INFO_SIZE)?;
        Some(BtreeInfo {
            flags: le::u32(self.block, off)?,
            node_size: le::u32(self.block, off + 4)?,
            key_size: le::u32(self.block, off + 8)?,
            val_size: le::u32(self.block, off + 12)?,
            key_count: le::u64(self.block, off + 24)?,
            node_count: le::u64(self.block, off + 32)?,
        })
    }

    /// Fixed key/value sizes for `BTNODE_FIXED_KV_SIZE` trees: the root
    /// footer carries them; non-root nodes use the caller's values.
    fn fixed_sizes(&self, fallback: (u16, u16)) -> (usize, usize) {
        match self.info() {
            Some(info) if info.key_size != 0 && info.val_size != 0 => {
                (info.key_size as usize, info.val_size as usize)
            }
            _ => (fallback.0 as usize, fallback.1 as usize),
        }
    }

    /// Raw table-of-contents fields for entry `i`. For `kvoff_t` nodes the
    /// lengths come from `fixed` (or the root footer when present).
    fn toc_entry(&self, i: u32, fixed: (u16, u16)) -> Result<(u16, u16, u16, u16)> {
        if i >= self.nkeys {
            return Err(FsError::corrupt(
                self.disk_offset,
                format!("btree index {i} >= nkeys {}", self.nkeys),
            ));
        }
        let entry_size = if self.fixed_kv { 4usize } else { 8 };
        let e = self.toc_base + i as usize * entry_size;
        if e + entry_size > self.block.len() {
            return Err(FsError::corrupt(
                self.disk_offset + e as u64,
                "btree ToC entry out of bounds",
            ));
        }
        if self.fixed_kv {
            let (fk, fv) = self.fixed_sizes(fixed);
            Ok((
                le::u16(self.block, e).unwrap_or(0),
                fk as u16,
                le::u16(self.block, e + 2).unwrap_or(0),
                fv as u16,
            ))
        } else {
            Ok((
                le::u16(self.block, e).unwrap_or(0),
                le::u16(self.block, e + 2).unwrap_or(0),
                le::u16(self.block, e + 4).unwrap_or(0),
                le::u16(self.block, e + 6).unwrap_or(0),
            ))
        }
    }

    /// Entry `i` of the table of contents → `(key_disk_off, key, value)`.
    ///
    /// `key_disk_off` is the absolute source offset of the key — the
    /// provenance anchor for records. `fixed` supplies `(klen, vlen)` used
    /// for `kvoff_t` nodes when this node has no footer (non-root nodes in a
    /// fixed-KV tree).
    pub(crate) fn entry_at(&self, i: u32, fixed: (u16, u16)) -> Result<(u64, &'a [u8], &'a [u8])> {
        let (koff, klen, voff, vlen) = self.toc_entry(i, fixed)?;
        let kstart = self
            .keys_start
            .checked_add(koff as usize)
            .ok_or_else(|| FsError::corrupt(self.disk_offset, "btree key offset overflow"))?;
        let kend = kstart
            .checked_add(klen as usize)
            .ok_or_else(|| FsError::corrupt(self.disk_offset, "btree key length overflow"))?;
        if kend > self.vals_end || kend > self.block.len() {
            return Err(FsError::corrupt(
                self.disk_offset + kstart as u64,
                "btree key extends past value area",
            ));
        }
        let key = &self.block[kstart..kend];

        let val: &[u8] = if voff == BTOFF_INVALID {
            &[] // ghost entry — key with no value
        } else {
            // v.off counts backward from vals_end to the *start* of the value.
            let vstart = self.vals_end.checked_sub(voff as usize).ok_or_else(|| {
                FsError::corrupt(self.disk_offset, "btree value offset underflow")
            })?;
            let vend = vstart
                .checked_add(vlen as usize)
                .ok_or_else(|| FsError::corrupt(self.disk_offset, "btree value length overflow"))?;
            if vstart < self.keys_start || vend > self.vals_end {
                return Err(FsError::corrupt(
                    self.disk_offset + vstart as u64,
                    "btree value outside value area",
                ));
            }
            &self.block[vstart..vend]
        };
        Ok((self.disk_offset + kstart as u64, key, val))
    }

    /// Iterate all entries: `(key_disk_off, key, value)`.
    pub(crate) fn entries(
        &self,
        fixed: (u16, u16),
    ) -> impl Iterator<Item = Result<(u64, &'a [u8], &'a [u8])>> + '_ {
        (0..self.nkeys).map(move |i| self.entry_at(i, fixed))
    }

    /// The 8-byte child reference of an internal-node entry.
    /// Returns `(key, child_ref)`.
    ///
    /// Internal-node values are *always* 8 bytes per the spec, even in
    /// `BTNODE_FIXED_KV_SIZE` trees whose footer `bt_val_size` describes the
    /// leaf value size — so the value length is forced to 8 here and
    /// `key_len` is the caller-supplied fixed key size for `kvoff_t` nodes.
    pub(crate) fn child_at(&self, i: u32, key_len: u16) -> Result<(&'a [u8], u64)> {
        let (koff, klen, voff, _) = self.toc_entry(i, (key_len, 8))?;
        let vlen = 8usize;
        let kstart = self
            .keys_start
            .checked_add(koff as usize)
            .ok_or_else(|| FsError::corrupt(self.disk_offset, "btree key offset overflow"))?;
        let kend = kstart
            .checked_add(klen as usize)
            .ok_or_else(|| FsError::corrupt(self.disk_offset, "btree key length overflow"))?;
        if kend > self.vals_end || kend > self.block.len() {
            return Err(FsError::corrupt(
                self.disk_offset + kstart as u64,
                "btree internal key past value area",
            ));
        }
        let key = &self.block[kstart..kend];
        if voff == BTOFF_INVALID {
            return Err(FsError::corrupt(
                self.disk_offset + kstart as u64,
                "btree internal entry is a ghost",
            ));
        }
        let vstart = self
            .vals_end
            .checked_sub(voff as usize)
            .ok_or_else(|| FsError::corrupt(self.disk_offset, "btree child offset underflow"))?;
        let vend = vstart.saturating_add(vlen);
        if vend > self.vals_end {
            return Err(FsError::corrupt(
                self.disk_offset + vstart as u64,
                "btree child pointer outside value area",
            ));
        }
        let v = le::u64(&self.block[vstart..vend], 0)
            .ok_or_else(|| FsError::corrupt(self.disk_offset, "btree child value < 8 bytes"))?;
        Ok((key, v))
    }
}
