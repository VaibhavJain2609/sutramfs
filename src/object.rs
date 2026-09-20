//! `obj_phys_t` — the 32-byte header that begins every APFS object.
//!
//! Layout (all little-endian):
//!
//! ```text
//!   0   u64  o_cksum    Fletcher-64 over block[8..]
//!   8   u64  o_oid      object identifier (physical objects: == paddr)
//!  16   u64  o_xid      transaction id of the last modification
//!  24   u32  o_type     high 16 bits flags / storage class, low 16 bits type
//!  28   u32  o_subtype  type-specific (btree nodes: the tree's object type)
//! ```

use sutram_fs::{FsError, Result};
use sutram_io::le;

use crate::checksum;

/// `o_type` low-16-bit object type codes — the subset this parser decodes
/// or validates against. (The full registry includes reaper/EFI/fusion/
/// spaceman-auxiliary types that v1 does not interpret.)
pub(crate) mod otype {
    pub const NX_SUPERBLOCK: u32 = 0x0001;
    pub const BTREE: u32 = 0x0002;
    pub const BTREE_NODE: u32 = 0x0003;
    pub const SPACEMAN: u32 = 0x0005;
    pub const OMAP: u32 = 0x000b;
    pub const CHECKPOINT_MAP: u32 = 0x000c;
    pub const FS: u32 = 0x000d;
    pub const FSTREE: u32 = 0x000e;
    pub const SNAPMETATREE: u32 = 0x0010;
}

/// `o_type` flag bits (high 16 bits).
pub(crate) mod oflags {
    /// Ephemeral object: located through the checkpoint map.
    pub const EPHEMERAL: u32 = 0x8000_0000;
    /// Physical object: `o_oid` equals its block address.
    pub const PHYSICAL: u32 = 0x4000_0000;
    /// Object contents are encrypted.
    pub const ENCRYPTED: u32 = 0x1000_0000;
    pub const TYPE_MASK: u32 = 0x0000_ffff;
    pub const STORAGETYPE_MASK: u32 = 0xc000_0000;
}

/// How an object is located.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Storage {
    /// Physical object — `o_oid` is its block address; referenced by paddr.
    Physical,
    /// Ephemeral object — referenced by oid, resolved via the checkpoint map.
    Ephemeral,
    /// Virtual object — referenced by oid, resolved via an object map.
    Virtual,
}

/// A decoded object header.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ObjHdr {
    /// `o_oid` — virtual/ephemeral oid (physical objects: == paddr).
    pub oid: u64,
    /// `o_xid` — transaction that last modified this object.
    pub xid: u64,
    /// Raw `o_type` (flags | type).
    pub otype: u32,
    /// `o_subtype` — for btree nodes, the tree's object type.
    pub osubtype: u32,
}

impl ObjHdr {
    /// Parse the header of `block` (which must be at least 32 bytes).
    ///
    /// `verify_cksum` controls whether the Fletcher-64 is checked; callers
    /// that parse opportunistically (checkpoint scans) pass `true` and treat
    /// a failure as "not a valid object". `off` is the absolute byte offset
    /// of the block on the source, for error provenance.
    pub(crate) fn parse(block: &[u8], off: u64, verify_cksum: bool) -> Result<Self> {
        if block.len() < 32 {
            return Err(FsError::truncated(off, 32, block.len() as u64));
        }
        if verify_cksum && !checksum::verify(block) {
            return Err(FsError::corrupt(
                off,
                "object Fletcher-64 checksum mismatch",
            ));
        }
        Ok(ObjHdr {
            oid: le::u64(block, 8).unwrap_or(0),
            xid: le::u64(block, 16).unwrap_or(0),
            otype: le::u32(block, 24).unwrap_or(0),
            osubtype: le::u32(block, 28).unwrap_or(0),
        })
    }

    /// `o_type & OBJECT_TYPE_MASK`.
    pub(crate) fn type_code(&self) -> u32 {
        self.otype & oflags::TYPE_MASK
    }

    /// Storage class per the spec's storagetype bits.
    pub(crate) fn storage(&self) -> Storage {
        match self.otype & oflags::STORAGETYPE_MASK {
            oflags::EPHEMERAL => Storage::Ephemeral,
            oflags::PHYSICAL => Storage::Physical,
            _ => Storage::Virtual,
        }
    }

    /// `OBJ_ENCRYPTED` set.
    pub(crate) fn encrypted(&self) -> bool {
        self.otype & oflags::ENCRYPTED != 0
    }

    /// Short type name for diagnostics.
    pub(crate) fn type_name(&self) -> &'static str {
        match self.type_code() {
            otype::NX_SUPERBLOCK => "nx_superblock",
            otype::BTREE => "btree",
            otype::BTREE_NODE => "btree_node",
            otype::SPACEMAN => "spaceman",
            otype::OMAP => "omap",
            otype::CHECKPOINT_MAP => "checkpoint_map",
            otype::FS => "apfs_superblock",
            otype::FSTREE => "fs_tree",
            otype::SNAPMETATREE => "snapmeta_tree",
            _ => "unknown",
        }
    }
}
