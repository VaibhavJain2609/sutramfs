//! The object map (`omap_phys_t` + its B-tree of `omap_key_t → omap_val_t`
//! records) — the oid → physical-block translation layer.
//!
//! Lookups are `(oid, xid)`-keyed: resolving oid `O` at transaction `X`
//! selects the entry with `ok_oid == O` and the largest `ok_xid <= X`
//! (per the spec's lookup rule). That versioned mapping is what lets this
//! parser resolve trees *as of a prior checkpoint* — the core of APFS
//! deleted-object recovery.

use std::collections::BTreeMap;

use sutram_fs::{FsError, Result};
use sutram_io::le;

use crate::object::{otype, ObjHdr};

/// `omap_val_t.ov_flags` bits we act on.
pub(crate) const OMAP_VAL_DELETED: u32 = 0x01;
/// The object the entry points at is encrypted (never decrypted — flagged).
pub(crate) const OMAP_VAL_ENCRYPTED: u32 = 0x04;

/// Fixed key/value sizes of an omap B-tree leaf.
pub(crate) const OMAP_KV_SIZE: (u16, u16) = (16, 16);

/// Decoded `omap_phys_t` (the object header + fixed fields; 88 bytes used).
#[derive(Debug, Clone, Copy)]
pub(crate) struct OmapPhys {
    pub hdr: ObjHdr,
    /// `om_snap_count` — number of omap snapshots recorded.
    pub snap_count: u32,
    /// `om_tree_type` — object type (incl. storage flags) of the tree root.
    pub tree_type: u32,
    /// `om_tree_oid` — for an ephemeral omap, the oid resolved via the
    /// checkpoint map; for a physical omap, the root node's block number.
    pub tree_oid: u64,
    /// `om_most_recent_snap` — xid of the most recent snapshot.
    pub most_recent_snap: u64,
}

impl OmapPhys {
    /// Parse the omap object at `block` (one block read at `off`).
    /// Caller has already verified the Fletcher-64.
    pub(crate) fn parse(block: &[u8], off: u64) -> Result<Self> {
        let hdr = ObjHdr::parse(block, off, false)?;
        if hdr.type_code() != otype::OMAP {
            return Err(FsError::corrupt(
                off + 24,
                format!("o_type {:#x} is not OMAP", hdr.otype),
            ));
        }
        Ok(OmapPhys {
            hdr,
            snap_count: le::u32(block, 36).unwrap_or(0),
            tree_type: le::u32(block, 40).unwrap_or(0),
            tree_oid: le::u64(block, 48).unwrap_or(0),
            most_recent_snap: le::u64(block, 64).unwrap_or(0),
        })
    }
}

/// One decoded `omap_key_t → omap_val_t` record.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OmapEntry {
    /// `ok_oid`.
    pub oid: u64,
    /// `ok_xid`.
    pub xid: u64,
    /// `ov_flags`.
    pub flags: u32,
    /// `ov_size` — object size in bytes.
    pub size: u32,
    /// `ov_paddr` — physical block number.
    pub paddr: u64,
}

impl OmapEntry {
    /// Decode a key/value pair from an omap leaf.
    pub(crate) fn decode(key: &[u8], val: &[u8]) -> Result<Self> {
        if key.len() < 16 || val.len() < 16 {
            return Err(FsError::corrupt(0, "omap record smaller than 16+16"));
        }
        Ok(OmapEntry {
            oid: le::u64(key, 0).unwrap_or(0),
            xid: le::u64(key, 8).unwrap_or(0),
            flags: le::u32(val, 0).unwrap_or(0),
            size: le::u32(val, 4).unwrap_or(0),
            paddr: le::u64(val, 8).unwrap_or(0),
        })
    }
}

/// All leaf records of an omap tree, indexed for `(oid, xid)` lookups.
/// Built once per omap per view — memory proportional to live object count.
#[derive(Debug, Default)]
pub(crate) struct OmapIndex {
    /// oid → entries ascending by xid.
    pub by_oid: BTreeMap<u64, Vec<OmapEntry>>,
    /// Total records seen (incl. superseded versions).
    pub record_count: usize,
}

impl OmapIndex {
    /// Add one leaf record.
    pub(crate) fn insert(&mut self, e: OmapEntry) {
        let v = self.by_oid.entry(e.oid).or_default();
        // Keep ascending-xid order for lookup.
        match v.binary_search_by_key(&e.xid, |x| x.xid) {
            Ok(pos) | Err(pos) => v.insert(pos, e),
        }
        self.record_count += 1;
    }

    /// Resolve `oid` at transaction bound `max_xid`: the entry with the
    /// largest `ok_xid <= max_xid` decides. If that entry is flagged
    /// `OMAP_VAL_DELETED` the object was absent at that transaction —
    /// falling back to an older mapping would resurrect a stale paddr
    /// whose block may have been reallocated.
    pub(crate) fn lookup(&self, oid: u64, max_xid: u64) -> Option<OmapEntry> {
        let v = self.by_oid.get(&oid)?;
        let e = v.iter().rev().find(|e| e.xid <= max_xid)?;
        if e.flags & OMAP_VAL_DELETED != 0 {
            return None;
        }
        Some(*e)
    }
}
