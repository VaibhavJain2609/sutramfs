//! Physical block mapping: ext4 extent trees and the ext2/3 legacy
//! direct/indirect block map fallback.
//!
//! Both decoders produce `Vec<BlockRun>` — `(logical block, physical
//! block, length in blocks)` runs — so recovery analysis can reason about
//! *which logical offsets* survive rather than just "how many bytes".

use std::collections::HashSet;

use sutram_fs::{FsError, Result};
use sutram_io::{le, ByteSource};

use crate::inode::Inode;

/// `eh_magic` for extent-tree nodes.
const EXTENT_MAGIC: u16 = 0xF30A;
/// `ee_len` values above this mark an *uninitialised* extent; the real
/// length is `ee_len - 0x8000`.
const EXTENT_UNINIT: u16 = 0x8000;
/// Hard caps against hostile/cyclic structures.
const MAX_EXTENT_DEPTH: u16 = 5;
const MAX_EXTENT_NODES: usize = 1 << 16;

/// A contiguous run of physical blocks covering `len` file blocks
/// starting at logical block `logical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlockRun {
    pub logical: u64,
    pub phys: u64,
    pub len: u64,
}

/// How an inode's data is laid out.
#[derive(Debug)]
pub(crate) enum BlockMap {
    /// Block-mapped (extents or legacy indirect).
    Runs(Vec<BlockRun>),
    /// `EXT4_INLINE_DATA_FL` regular file: the first `min(i_size, 60)`
    /// data bytes live in `i_block` itself (no length prefix — the
    /// 4-byte header applies to inline *directories*); any spillover is
    /// the `system.data` ibody xattr value.
    Inline {
        /// Bytes of inline data inside `i_block` (≤ 60).
        len: u32,
    },
    /// `EXT4_INLINE_DATA_FL` directory: `i_block[0..4]` is the parent
    /// inode number and `i_block[4..60]` holds `ext4_dir_entry` records.
    /// (Larger inline dirs spill into the `system.data` xattr, treated
    /// by the kernel as a separate dirent block — see README.)
    InlineDir,
    /// Nothing mapped (empty file, fast symlink, …).
    Empty,
}

/// Map an inode to its physical block runs.
pub(crate) fn map_inode(
    src: &dyn ByteSource,
    inode: &Inode,
    block_size: u64,
    blocks_count: u64,
) -> Result<BlockMap> {
    if inode.has_inline_data() {
        // Regular file: raw data starts at i_block[0]; no length prefix.
        // Directory: i_block[0..4] is the parent inode number, dirents
        // follow at i_block[4..60] (kernel ext4 inlinedata doc).
        return Ok(if inode.is_dir() {
            BlockMap::InlineDir
        } else {
            BlockMap::Inline {
                len: inode.size.min(60) as u32,
            }
        });
    }
    if inode.has_extents() {
        return Ok(BlockMap::Runs(walk_extents(
            src,
            &inode.block60,
            inode.disk_offset + 0x28,
            block_size,
        )?));
    }
    if inode.is_fast_symlink() || inode.blocks_512 == 0 {
        return Ok(BlockMap::Empty);
    }
    Ok(BlockMap::Runs(walk_indirect(
        src,
        &inode.block60,
        block_size,
        blocks_count,
    )?))
}

// ---------------------------------------------------------------------------
// Extent trees
// ---------------------------------------------------------------------------

/// Parse a 12-byte extent node header → `(entry_count, depth)`.
fn extent_header(buf: &[u8], off: u64) -> Result<(u16, u16)> {
    if le::u16(buf, 0) != Some(EXTENT_MAGIC) {
        return Err(FsError::corrupt(
            off,
            "bad extent magic (not 0xf30a)".to_string(),
        ));
    }
    let entries = le::u16(buf, 2).unwrap_or(0);
    let max = le::u16(buf, 4).unwrap_or(0);
    let depth = le::u16(buf, 6).unwrap_or(0);
    let cap = ((buf.len().saturating_sub(12)) / 12) as u16;
    if entries > cap || max > cap {
        return Err(FsError::corrupt(
            off + 2,
            format!("extent node claims {entries} entries (capacity {cap})"),
        ));
    }
    if depth > MAX_EXTENT_DEPTH {
        return Err(FsError::corrupt(
            off + 6,
            format!("extent depth {depth} > {MAX_EXTENT_DEPTH}"),
        ));
    }
    Ok((entries, depth))
}

/// Walk the extent tree rooted in `root` (the inode's 60-byte `i_block`
/// for depth-0/idx roots) collecting leaf extents as `BlockRun`s.
fn walk_extents(
    src: &dyn ByteSource,
    root: &[u8; 60],
    root_off: u64,
    block_size: u64,
) -> Result<Vec<BlockRun>> {
    let mut runs = Vec::new();
    // Stack of (node bytes, disk offset). Node bytes are either the in-inode
    // 60-byte root or whole filesystem blocks.
    let mut stack: Vec<(Vec<u8>, u64)> = vec![(root.to_vec(), root_off)];
    let mut visited: HashSet<u64> = HashSet::new();
    let mut nodes = 0usize;
    while let Some((node, node_off)) = stack.pop() {
        nodes += 1;
        if nodes > MAX_EXTENT_NODES {
            return Err(FsError::corrupt(
                node_off,
                format!("extent tree exceeds {MAX_EXTENT_NODES} nodes (cycle?)"),
            ));
        }
        let (entries, depth) = extent_header(&node, node_off)?;
        for i in 0..entries as usize {
            let e = 12 + i * 12;
            if depth == 0 {
                let logical = le::u32(&node, e).unwrap_or(0) as u64;
                let ee_len = le::u16(&node, e + 4).unwrap_or(0);
                let len = if ee_len > EXTENT_UNINIT {
                    (ee_len - EXTENT_UNINIT) as u64
                } else {
                    ee_len as u64
                };
                let phys = ((le::u16(&node, e + 6).unwrap_or(0) as u64) << 32)
                    | le::u32(&node, e + 8).unwrap_or(0) as u64;
                if len > 0 && phys > 0 {
                    push_run(&mut runs, logical, phys, len);
                }
            } else {
                // Interior index entry → child node block.
                let child = ((le::u16(&node, e + 8).unwrap_or(0) as u64) << 32)
                    | le::u32(&node, e + 4).unwrap_or(0) as u64;
                if !visited.insert(child) {
                    continue; // cycle — skip silently, sibling idx entries still parse
                }
                let buf = src
                    .read_slice(child * block_size, block_size as usize)
                    .map_err(FsError::Io)?;
                if (buf.len() as u64) < block_size {
                    return Err(FsError::truncated(
                        child * block_size,
                        block_size,
                        buf.len() as u64,
                    ));
                }
                stack.push((buf, child * block_size));
            }
        }
    }
    // Stack order scrambles leaf order; sort by logical offset.
    runs.sort_by_key(|r| r.logical);
    Ok(runs)
}

// ---------------------------------------------------------------------------
// Legacy direct/indirect block map (ext2/3)
// ---------------------------------------------------------------------------

/// Decode the 15 `i_block` slots of a non-extents inode:
/// 12 direct, then single/double/triple indirect block-number lists.
fn walk_indirect(
    src: &dyn ByteSource,
    block60: &[u8; 60],
    block_size: u64,
    blocks_count: u64,
) -> Result<Vec<BlockRun>> {
    let mut runs = Vec::new();
    let mut logical = 0u64;
    let ptrs = |i: usize| -> u32 { le::u32(block60, i * 4).unwrap_or(0) };
    // 12 direct pointers.
    for i in 0..12 {
        let b = ptrs(i) as u64;
        if b != 0 {
            push_run(&mut runs, logical, b, 1);
        }
        logical += 1;
    }
    // Indirect pointers at depth 1..3.
    let per_block = block_size / 4;
    let mut visited = HashSet::new();
    // Total data blocks cannot exceed the volume's block count.
    let cap = blocks_count.min(1 << 22);
    for level in 1..=3u8 {
        let root_ptr = ptrs(11 + level as usize) as u64;
        if root_ptr == 0 {
            // A NULL indirect pointer is a hole covering per_block^level
            // logical slots — skipping it without advancing would map
            // every later block at the wrong logical offset.
            logical += per_block.pow(level as u32);
            continue;
        }
        walk_indirect_level(
            src,
            root_ptr,
            level,
            per_block,
            block_size,
            &mut logical,
            &mut runs,
            &mut visited,
            cap,
        )?;
    }
    Ok(runs)
}

#[allow(clippy::too_many_arguments)]
fn walk_indirect_level(
    src: &dyn ByteSource,
    block: u64,
    level: u8,
    per_block: u64,
    block_size: u64,
    logical: &mut u64,
    runs: &mut Vec<BlockRun>,
    visited: &mut HashSet<u64>,
    cap: u64,
) -> Result<()> {
    if !visited.insert(block) {
        return Ok(()); // cycle — already expanded
    }
    if *logical > cap {
        return Ok(());
    }
    let off = block * block_size;
    let buf = src.read_slice(off, block_size as usize).map_err(FsError::Io)?;
    if (buf.len() as u64) < block_size {
        return Err(FsError::truncated(off, block_size, buf.len() as u64));
    }
    for i in 0..per_block {
        let b = le::u32(&buf, (i * 4) as usize).unwrap_or(0);
        if level == 1 {
            if b != 0 {
                push_run(runs, *logical, b as u64, 1);
            }
            *logical += 1;
        } else {
            // The slot count consumed by each subtree below this level.
            if b != 0 {
                walk_indirect_level(
                    src,
                    b as u64,
                    level - 1,
                    per_block,
                    block_size,
                    logical,
                    runs,
                    visited,
                    cap,
                )?;
            } else {
                *logical += per_block.pow(level as u32 - 1);
            }
        }
        if *logical > cap {
            return Ok(());
        }
    }
    Ok(())
}

/// Append `(logical, phys, len)` merging with the tail run when contiguous.
fn push_run(runs: &mut Vec<BlockRun>, logical: u64, phys: u64, len: u64) {
    if let Some(last) = runs.last_mut() {
        if last.phys + last.len == phys && last.logical + last.len == logical {
            last.len += len;
            return;
        }
    }
    runs.push(BlockRun { logical, phys, len });
}
