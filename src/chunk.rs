//! Logical→physical address translation (`chunk.py` port, extended with
//! striped profiles: RAID0/RAID10 stripe math; DUP/RAID1* read the first
//! mirror; RAID5/6 parity layouts are recognised but flagged unsupported).

use std::collections::HashSet;

use sutram_fs::FsError;
use sutram_io::{le, ByteSource};

use crate::btree;
use crate::ondisk::*;

/// One logical chunk → physical stripe set.
#[derive(Debug, Clone)]
pub struct ChunkEntry {
    /// Logical start (the chunk item's key.offset).
    pub logical: u64,
    /// Chunk length.
    pub length: u64,
    /// `BTRFS_BLOCK_GROUP_*` type flags.
    pub ty: u64,
    /// Stripe length for striped profiles.
    pub stripe_len: u64,
    /// Physical offsets of each stripe (device-relative; single-device
    /// images carry one device at offset 0 of the source).
    pub stripe_offsets: Vec<u64>,
    /// Parity RAID (5/6) — translation not reconstructed.
    pub parity: bool,
}

/// The `ChunkMap`: sorted logical ranges → physical addresses.
#[derive(Debug, Default)]
pub struct ChunkMap {
    pub chunks: Vec<ChunkEntry>,
}

impl ChunkMap {
    /// Register a chunk; `physical` is the first stripe's offset.
    /// (Used by tests and single-stripe fast paths.)
    #[allow(dead_code)]
    pub fn add_chunk(&mut self, logical_start: u64, length: u64, physical_offset: u64) {
        self.add(ChunkEntry {
            logical: logical_start,
            length,
            ty: 0,
            stripe_len: 0,
            stripe_offsets: vec![physical_offset],
            parity: false,
        });
    }

    /// Register a fully-parsed chunk item.
    pub fn add(&mut self, c: ChunkEntry) {
        if c.length == 0 {
            return;
        }
        // Keep the first mapping for a logical range (later tree copies of
        // the same chunk agree; a conflicting one would be corrupt).
        if self
            .chunks
            .iter()
            .any(|e| e.logical == c.logical && e.length == c.length)
        {
            return;
        }
        self.chunks.push(c);
        self.chunks.sort_by_key(|e| e.logical);
    }

    /// Chunk covering a logical address.
    fn lookup(&self, logical: u64) -> Option<&ChunkEntry> {
        // Binary search on sorted starts, then verify range.
        let idx = match self
            .chunks
            .binary_search_by(|e| {
                if logical < e.logical {
                    std::cmp::Ordering::Greater
                } else if logical >= e.logical + e.length {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            }) {
            Ok(i) => i,
            Err(_) => return None,
        };
        Some(&self.chunks[idx])
    }

    /// Translate one logical address to an absolute physical offset.
    /// `None` when unmapped or the chunk is a parity-RAID profile.
    pub fn logical_to_physical(&self, logical: u64) -> Option<u64> {
        let c = self.lookup(logical)?;
        if c.parity || c.stripe_offsets.is_empty() {
            return None;
        }
        let off = logical - c.logical;
        let n = c.stripe_offsets.len() as u64;
        if n == 1 || c.stripe_len == 0 {
            return Some(c.stripe_offsets[0].saturating_add(off));
        }
        // RAID0/RAID10 striping: stripes of `stripe_len` bytes rotate over
        // the stripe set.
        let s = c.stripe_len;
        let band = off / s; // which stripe-width band
        let stripe_idx = (band % n) as usize;
        let within = off % s;
        let stripe_base = c.stripe_offsets[stripe_idx];
        Some(stripe_base.saturating_add(band / n * s).saturating_add(within))
    }

    /// Translate a logical byte range to physical `(offset, len)` pieces.
    /// Single-stripe chunks return one piece; striped chunks are split at
    /// stripe-band boundaries (never yields more than `len` pieces).
    pub fn translate_range(&self, logical: u64, len: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut pos = logical;
        let mut left = len;
        let mut guard = 0u64;
        while left > 0 && guard < 1 << 20 {
            guard += 1;
            let c = match self.lookup(pos) {
                Some(c) if !c.parity && !c.stripe_offsets.is_empty() => c,
                _ => {
                    // Unmapped/parity hole — report nothing for the gap;
                    // caller treats missing coverage as unreadable.
                    let skip = self
                        .lookup(pos)
                        .map(|c| c.logical + c.length - pos)
                        .unwrap_or(left);
                    pos = pos.saturating_add(skip);
                    left = left.saturating_sub(skip);
                    continue;
                }
            };
            // Max contiguous run inside this chunk & stripe band.
            let in_chunk = c.logical + c.length - pos;
            let off = pos - c.logical;
            let n = c.stripe_offsets.len() as u64;
            let run = if n == 1 || c.stripe_len == 0 {
                in_chunk.min(left)
            } else {
                let s = c.stripe_len;
                let band = off / s;
                let within = off % s;
                let band_left = s - within;
                // Stay within this stripe band so the mapping stays linear.
                let nr = band_left.min(in_chunk).min(left);
                let phys = c.stripe_offsets[(band % n) as usize]
                    .saturating_add(band / n * s)
                    .saturating_add(within);
                out.push((phys, nr));
                pos += nr;
                left -= nr;
                continue;
            };
            match self.logical_to_physical(pos) {
                Some(phys) => out.push((phys, run)),
                None => {}
            }
            pos += run;
            left -= run;
        }
        out
    }

    /// Total bytes mapped by chunks (device coverage for free-space math).
    pub fn covered_ranges(&self) -> Vec<(u64, u64)> {
        self.chunks
            .iter()
            .map(|c| (c.logical, c.length))
            .collect()
    }
}

/// Parse the superblock's `sys_chunk_array` (repeated KEY+CHUNK_ITEM
/// pairs). Port of `parse_sys_chunk_array`.
pub fn parse_sys_chunk_array(sys_chunk_array: &[u8]) -> ChunkMap {
    let mut map = ChunkMap::default();
    let mut pos = 0usize;
    while pos + KEY_SIZE + CHUNK_ITEM_FIXED_SIZE <= sys_chunk_array.len() {
        let key = match Key::parse(sys_chunk_array, pos) {
            Some(k) => k,
            None => break,
        };
        pos += KEY_SIZE;
        if key.ty != ty::CHUNK_ITEM {
            // sys_chunk_array may hold DEV_ITEM entries too — skip by their
            // fixed size.
            if key.ty == ty::DEV_ITEM {
                if pos + DEV_ITEM_SIZE > sys_chunk_array.len() {
                    break;
                }
                pos += DEV_ITEM_SIZE;
                continue;
            }
            break;
        }
        match Chunk::parse(sys_chunk_array, pos) {
            Some(chunk) => {
                map.add(chunk_entry(key.offset, &chunk));
                pos += chunk.total_size();
            }
            None => break,
        }
    }
    map
}

fn chunk_entry(logical: u64, chunk: &Chunk) -> ChunkEntry {
    ChunkEntry {
        logical,
        length: chunk.length,
        ty: chunk.ty,
        stripe_len: chunk.stripe_len,
        stripe_offsets: chunk.stripes.iter().map(|s| s.offset).collect(),
        parity: !block_group::translatable(chunk.ty),
    }
}

/// Walk the chunk tree (rooted at `chunk_root`) and merge all CHUNK_ITEMs
/// into the map. Port of `read_chunk_tree`; returns errors leniently.
pub fn read_chunk_tree(
    src: &dyn ByteSource,
    chunk_root: u64,
    map: &mut ChunkMap,
    nodesize: u32,
) -> Vec<FsError> {
    let mut errs = Vec::new();
    let mut visited = HashSet::new();
    let mut stack = vec![chunk_root];
    let mut guard = 0u64;
    while let Some(logical) = stack.pop() {
        if !visited.insert(logical) {
            continue;
        }
        if guard > btree::MAX_TREE_NODES {
            errs.push(FsError::corrupt(logical, "chunk tree node cap exceeded"));
            break;
        }
        guard += 1;
        let phys = match map.logical_to_physical(logical) {
            Some(p) => p,
            None => {
                errs.push(FsError::corrupt(
                    logical,
                    format!("chunk-tree node {logical:#x} not covered by chunk map"),
                ));
                continue;
            }
        };
        let block = match src.read_slice(phys, nodesize as usize) {
            Ok(b) => b,
            Err(e) => {
                errs.push(FsError::Io(e));
                continue;
            }
        };
        let header = match Header::parse(&block) {
            Some(h) => h,
            None => {
                errs.push(FsError::corrupt(phys, "short chunk-tree node"));
                continue;
            }
        };
        if header.level == 0 {
            let mut pos = HEADER_SIZE;
            for _ in 0..header.nritems {
                let item = match Item::parse(&block, pos) {
                    Some(i) => i,
                    None => break,
                };
                pos += ITEM_SIZE;
                if item.key.ty != ty::CHUNK_ITEM {
                    continue;
                }
                let ds = HEADER_SIZE + item.offset as usize;
                if let Some(chunk) = Chunk::parse(&block, ds) {
                    map.add(chunk_entry(item.key.offset, &chunk));
                }
            }
        } else {
            let mut pos = HEADER_SIZE;
            for _ in 0..header.nritems {
                match KeyPtr::parse(&block, pos) {
                    Some(ptr) => stack.push(ptr.blockptr),
                    None => break,
                }
                pos += KEY_PTR_SIZE;
            }
        }
    }
    errs
}

/// Collect DEV_ITEMs seen in the chunk tree (device capacity reporting).
pub fn dev_items(
    src: &dyn ByteSource,
    chunk_root: u64,
    map: &ChunkMap,
    nodesize: u32,
) -> Vec<DevItem> {
    let mut out = Vec::new();
    let mut visited = HashSet::new();
    let mut stack = vec![chunk_root];
    while let Some(logical) = stack.pop() {
        if !visited.insert(logical) {
            continue;
        }
        let phys = match map.logical_to_physical(logical) {
            Some(p) => p,
            None => continue,
        };
        let block = match src.read_slice(phys, nodesize as usize) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let header = match Header::parse(&block) {
            Some(h) => h,
            None => continue,
        };
        if header.level == 0 {
            let mut pos = HEADER_SIZE;
            for _ in 0..header.nritems {
                let item = match Item::parse(&block, pos) {
                    Some(i) => i,
                    None => break,
                };
                pos += ITEM_SIZE;
                if item.key.ty == ty::DEV_ITEM {
                    let ds = HEADER_SIZE + item.offset as usize;
                    if let Some(d) = le::get(&block, ds, item.size as usize)
                        .and_then(|d| DevItem::parse(d))
                    {
                        out.push(d);
                    }
                }
            }
        } else {
            let mut pos = HEADER_SIZE;
            for _ in 0..header.nritems {
                match KeyPtr::parse(&block, pos) {
                    Some(ptr) => stack.push(ptr.blockptr),
                    None => break,
                }
                pos += KEY_PTR_SIZE;
            }
        }
    }
    out
}
