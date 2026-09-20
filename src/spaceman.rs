//! `spaceman_phys_t` — the container space manager.
//!
//! v1 parses only the fixed header: geometry and the main device's free
//! block count (used for `FsInfo::free_blocks`). The full free-space bitmap
//! (chunk-info blocks / CIBs) is deferred; `unallocated_ranges()` instead
//! reports the complement of blocks reachable from live metadata + file
//! extents — documented in the README.

use sutram_fs::{FsError, Result};
use sutram_io::le;

use crate::object::{otype, ObjHdr};

/// Parsed space-manager header fields.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Spaceman {
    pub block_size: u32,
    pub blocks_per_chunk: u32,
    pub chunks_per_cib: u32,
    pub cibs_per_cab: u32,
    /// `sm_dev[SD_MAIN]` fields.
    pub dev_block_count: u64,
    pub dev_chunk_count: u64,
    pub dev_free_count: u64,
    /// `sm_flags`.
    pub flags: u32,
}

impl Spaceman {
    /// Parse a spaceman object block read at `off` (checksum already
    /// verified by the caller).
    pub(crate) fn parse(block: &[u8], off: u64) -> Result<Self> {
        let hdr = ObjHdr::parse(block, off, false)?;
        if hdr.type_code() != otype::SPACEMAN {
            return Err(FsError::corrupt(
                off + 24,
                format!("o_type {:#x} is not SPACEMAN", hdr.otype),
            ));
        }
        Ok(Spaceman {
            block_size: le::u32(block, 32).unwrap_or(0),
            blocks_per_chunk: le::u32(block, 36).unwrap_or(0),
            chunks_per_cib: le::u32(block, 40).unwrap_or(0),
            cibs_per_cab: le::u32(block, 44).unwrap_or(0),
            dev_block_count: le::u64(block, 48).unwrap_or(0),
            dev_chunk_count: le::u64(block, 56).unwrap_or(0),
            dev_free_count: le::u64(block, 72).unwrap_or(0),
            flags: le::u32(block, 144).unwrap_or(0),
        })
    }
}
