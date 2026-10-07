//! B-tree traversal — port of `btree.py` with hardening for forensics:
//! checksum verification, generation consistency checks, per-item
//! provenance (logical + physical addresses), visited-set loop guards.
//!
//! Traversal is callback-based (`TreeWalk`) so callers never buffer a whole
//! tree of raw blocks; item *bodies* are yielded as bounded slices.

use std::collections::HashSet;

use sutram_fs::FsError;
use sutram_io::ByteSource;

use crate::chunk::ChunkMap;
use crate::ondisk::*;
use crate::superblock::CSUM_CRC32C;

/// Hard cap on tree nodes visited — stops corrupt/cyclic trees.
pub const MAX_TREE_NODES: u64 = 1_000_000;

/// One item found in a leaf, with full provenance.
#[derive(Debug)]
pub struct TreeItem<'a> {
    pub key: Key,
    /// Item body slice (into the leaf buffer).
    pub data: &'a [u8],
    /// Absolute offset of the item body inside `data`'s block buffer.
    pub body_off_in_block: usize,
    /// Logical address of the leaf holding the item.
    pub leaf_logical: u64,
    /// Physical address of the leaf (provenance — kept for callers that
    /// want block-level citation rather than item-level).
    #[allow(dead_code)]
    pub leaf_phys: u64,
    /// Generation of the leaf (kept for callers doing history analysis).
    #[allow(dead_code)]
    pub leaf_gen: u64,
    /// Absolute physical offset of the item body on the source.
    pub item_phys: u64,
    /// The leaf's header checksum verified (`None` = unverifiable).
    pub csum_ok: Option<bool>,
    /// The child's generation disagreed with the parent's keyptr
    /// (stale/COW-remnant or torn write).
    pub gen_mismatch: bool,
}

/// Context for tree traversal.
pub struct TreeWalk<'a> {
    pub src: &'a dyn ByteSource,
    pub map: &'a ChunkMap,
    pub nodesize: u32,
    /// Checksum type from the superblock (0 = CRC32C).
    pub csum_type: u16,
    /// Errors collected during traversal (lenient mode).
    pub errors: Vec<FsError>,
}

impl<'a> TreeWalk<'a> {
    pub fn new(
        src: &'a dyn ByteSource,
        map: &'a ChunkMap,
        nodesize: u32,
        csum_type: u16,
    ) -> Self {
        TreeWalk {
            src,
            map,
            nodesize,
            csum_type,
            errors: Vec::new(),
        }
    }

    /// Read a tree block by logical address → (block bytes, phys, header).
    pub fn read_block(&self, logical: u64) -> Result<(Vec<u8>, u64, Header), FsError> {
        let phys = self.map.logical_to_physical(logical).ok_or_else(|| {
            FsError::corrupt(logical, format!("logical address {logical:#x} not in chunk map"))
        })?;
        let block = self.src.read_slice(phys, self.nodesize as usize)?;
        if block.len() < HEADER_SIZE {
            return Err(FsError::truncated(
                phys,
                HEADER_SIZE as u64,
                block.len() as u64,
            ));
        }
        let mut header = Header::parse(&block)
            .ok_or_else(|| FsError::corrupt(phys, "could not parse node header"))?;
        if self.csum_type == CSUM_CRC32C {
            let stored = u32::from_le_bytes(header.csum[0..4].try_into().unwrap_or([0; 4]));
            header.csum_ok = Some(
                crc32fast::hash(&block[CSUM_SIZE..block.len().min(self.nodesize as usize)])
                    == stored,
            );
        }
        Ok((block, phys, header))
    }

    /// Visit every leaf item under `root_logical` (DFS, visited-guarded).
    /// The callback gets each [`TreeItem`]; errors are recorded in
    /// `self.errors` and traversal continues (lenient).
    pub fn for_each_item<F>(&mut self, root_logical: u64, cb: &mut F)
    where
        F: FnMut(&TreeItem),
    {
        let mut visited: HashSet<u64> = HashSet::new();
        // (logical addr, expected generation from parent, gen_mismatch)
        let mut stack: Vec<(u64, Option<u64>)> = vec![(root_logical, None)];
        let mut count = 0u64;
        while let Some((logical, expect_gen)) = stack.pop() {
            if count >= MAX_TREE_NODES {
                self.errors.push(FsError::corrupt(
                    logical,
                    "tree node cap exceeded (corrupt or cyclic tree)",
                ));
                return;
            }
            if !visited.insert(logical) {
                continue; // shared/COW-referenced block seen already
            }
            count += 1;
            let (block, phys, header) = match self.read_block(logical) {
                Ok(v) => v,
                Err(e) => {
                    self.errors.push(e);
                    continue;
                }
            };
            if header.csum_ok == Some(false) {
                // Bad node checksum: the block's contents are suspect but
                // still parsed leniently — every item is flagged csum_bad.
                self.errors.push(FsError::corrupt(
                    phys,
                    format!("node checksum mismatch (level {}, gen {})", header.level, header.generation),
                ));
            }
            let gen_mismatch = matches!(expect_gen, Some(g) if g != header.generation);
            if gen_mismatch {
                // Stale pointer: the parent expected generation g but the
                // block was written by a different transaction. Parse it
                // anyway (best effort) but flag every item it yields.
                self.errors.push(FsError::corrupt(
                    phys,
                    format!(
                        "generation mismatch: keyptr expects {}, block has {}",
                        expect_gen.unwrap_or(0),
                        header.generation
                    ),
                ));
            }
            if header.level == 0 {
                let mut pos = HEADER_SIZE;
                for _ in 0..header.nritems.min(
                    self.nodesize.saturating_sub(HEADER_SIZE as u32) / ITEM_SIZE as u32,
                ) {
                    let item = match Item::parse(&block, pos) {
                        Some(i) => i,
                        None => {
                            self.errors
                                .push(FsError::corrupt(phys + pos as u64, "bad item descriptor"));
                            break;
                        }
                    };
                    pos += ITEM_SIZE;
                    let body_off = HEADER_SIZE + item.offset as usize;
                    let body_end = body_off.saturating_add(item.size as usize);
                    if body_end > block.len() || body_off < HEADER_SIZE {
                        self.errors.push(FsError::corrupt(
                            phys + pos as u64,
                            "item body out of bounds",
                        ));
                        continue;
                    }
                    cb(&TreeItem {
                        key: item.key,
                        data: &block[body_off..body_end],
                        body_off_in_block: body_off,
                        leaf_logical: logical,
                        leaf_phys: phys,
                        leaf_gen: header.generation,
                        item_phys: phys + body_off as u64,
                        csum_ok: header.csum_ok,
                        gen_mismatch,
                    });
                }
            } else {
                let mut pos = HEADER_SIZE;
                for _ in 0..header.nritems.min(
                    self.nodesize.saturating_sub(HEADER_SIZE as u32) / KEY_PTR_SIZE as u32,
                ) {
                    match KeyPtr::parse(&block, pos) {
                        Some(ptr) => {
                            if ptr.blockptr != 0 {
                                stack.push((ptr.blockptr, Some(ptr.generation)));
                            }
                        }
                        None => {
                            self.errors
                                .push(FsError::corrupt(phys + pos as u64, "bad key pointer"));
                            break;
                        }
                    }
                    pos += KEY_PTR_SIZE;
                }
            }
        }
    }

}
