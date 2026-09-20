//! Generic HFS+ B-tree access: header record, node fetch through the
//! tree-file's extent map, leaf-chain traversal and free-space bounds.
//!
//! A B-tree is itself stored in a *file* (a fork's extents). Node `n` lives
//! at logical offset `n * node_size`; node bytes are a 14-byte descriptor,
//! records growing forward, and a u16 offset table growing backward from
//! `node_size`. The bytes between the last record's end and the offset
//! table are **free space** — where deleted records leave residue.
//!
//! Every walk is bounded: leaf chains are followed with a visited cap of
//! `total_nodes`, and node indices are validated against `total_nodes`.

use sutram_fs::{FsError, Result};
use sutram_io::le;
use sutram_io::ByteSource;

/// Node kinds (`kind` field of the node descriptor).
pub(crate) const NODE_HEADER: i8 = 1;
pub(crate) const NODE_LEAF: i8 = -1;

/// `BTHeaderRec` — parsed from record 0 of node 0.
#[derive(Debug, Clone)]
pub(crate) struct BtreeHeader {
    pub depth: u16,
    pub root: u32,
    pub leaf_count: u32,
    pub first_leaf: u32,
    pub last_leaf: u32,
    pub node_size: u16,
    pub max_key_len: u16,
    pub total_nodes: u32,
    pub free_nodes: u32,
    pub clump_size: u32,
    pub btree_type: u8,
    pub key_type: u8,
    pub attributes: u32,
}

/// A B-tree *file*: header + the extent list its nodes are read through.
#[derive(Debug, Clone)]
pub(crate) struct Btree {
    pub hdr: BtreeHeader,
    /// Byte extents of the tree file on disk (`(offset, len)`), clipped to
    /// the fork's logical size.
    pub ranges: Vec<(u64, u64)>,
    /// Absolute byte offset of this tree file's first byte, if contiguous.
    pub first_off: u64,
}

impl Btree {
    /// Build a `Btree` from a source + the byte ranges of the tree file.
    pub(crate) fn open(
        src: &dyn ByteSource,
        ranges: Vec<(u64, u64)>,
        file_off: u64,
    ) -> Result<Self> {
        let node0 = read_range_span(src, &ranges, 0, 512)
            .ok_or_else(|| FsError::corrupt(file_off, "B-tree header node unreadable"))?;
        if node0.len() < 512 {
            return Err(FsError::truncated(file_off, 512, node0.len() as u64));
        }
        let kind = node0.get(8).copied().unwrap_or(0) as i8;
        if kind != NODE_HEADER {
            return Err(FsError::corrupt(
                file_off + 8,
                format!("B-tree node 0 kind {kind}, want header (1)"),
            ));
        }
        // BTHeaderRec sits at offset 14 (after the node descriptor).
        let h = &node0[14..];
        let node_size = le::u16_be(h, 18).unwrap_or(0);
        if node_size < 512 || !node_size.is_power_of_two() {
            return Err(FsError::corrupt(
                file_off + 14 + 18,
                format!("bad B-tree node size {node_size}"),
            ));
        }
        let total_nodes = le::u32_be(h, 22).unwrap_or(0);
        if total_nodes == 0 {
            return Err(FsError::corrupt(
                file_off + 14 + 22,
                "B-tree reports zero nodes",
            ));
        }
        Ok(Btree {
            hdr: BtreeHeader {
                depth: le::u16_be(h, 0).unwrap_or(0),
                root: le::u32_be(h, 2).unwrap_or(0),
                leaf_count: le::u32_be(h, 6).unwrap_or(0),
                first_leaf: le::u32_be(h, 10).unwrap_or(0),
                last_leaf: le::u32_be(h, 14).unwrap_or(0),
                node_size,
                max_key_len: le::u16_be(h, 20).unwrap_or(0),
                total_nodes,
                free_nodes: le::u32_be(h, 26).unwrap_or(0),
                clump_size: le::u32_be(h, 32).unwrap_or(0),
                btree_type: h.get(36).copied().unwrap_or(0),
                key_type: h.get(37).copied().unwrap_or(0),
                attributes: le::u32_be(h, 38).unwrap_or(0),
            },
            ranges,
            first_off: file_off,
        })
    }

    /// Byte offset of node `n` (logical `n * node_size` mapped through the
    /// file's extents). `None` when `n` is out of range or unmapped.
    pub(crate) fn node_offset(&self, n: u32) -> Option<u64> {
        map_logical(&self.ranges, n as u64 * self.hdr.node_size as u64)
    }

    /// Read node `n`'s bytes.
    pub(crate) fn read_node(&self, src: &dyn ByteSource, n: u32) -> Result<Vec<u8>> {
        if n >= self.hdr.total_nodes {
            return Err(FsError::corrupt(
                self.first_off,
                format!("node {n} >= total_nodes {}", self.hdr.total_nodes),
            ));
        }
        let logical = n as u64 * self.hdr.node_size as u64;
        let buf = read_range_span(src, &self.ranges, logical, self.hdr.node_size as usize)
            .ok_or_else(|| FsError::corrupt(self.first_off, format!("node {n} outside extents")))?;
        if (buf.len() as u64) < self.hdr.node_size as u64 {
            let off = self.node_offset(n).unwrap_or(self.first_off);
            return Err(FsError::truncated(
                off,
                self.hdr.node_size as u64,
                buf.len() as u64,
            ));
        }
        Ok(buf)
    }

    /// Iterate the leaf chain starting at `first_leaf`, calling `f` with
    /// `(node_index, Node)`. Bounded by `total_nodes`; a broken/cyclic link
    /// ends the chain without error (residue scanners cover the rest).
    pub(crate) fn for_each_leaf<F>(&self, src: &dyn ByteSource, mut f: F) -> Result<()>
    where
        F: FnMut(u32, &Node) -> Result<()>,
    {
        let mut n = self.hdr.first_leaf;
        let mut seen = std::collections::HashSet::new();
        while n != 0 && seen.insert(n) && (n as u64) < self.hdr.total_nodes as u64 {
            let buf = self.read_node(src, n)?;
            let node = Node::parse(buf, n)?;
            if node.kind != NODE_LEAF || node.height != 1 {
                return Err(FsError::corrupt(
                    self.node_offset(n).unwrap_or(self.first_off),
                    format!(
                        "leaf-chain node {n} has kind {} height {}",
                        node.kind, node.height
                    ),
                ));
            }
            f(n, &node)?;
            n = node.next;
        }
        Ok(())
    }
}

/// A parsed node: descriptor fields + the record offset table.
#[derive(Debug)]
pub(crate) struct Node {
    pub buf: Vec<u8>,
    /// `fLink` — next node at this level (leaf chain forward link).
    pub next: u32,
    pub kind: i8,
    /// Tree height this node sits at (leaves are height 1).
    pub height: u8,
    pub num_recs: u16,
    /// `num_recs + 1` record-start offsets into `buf`.
    pub offsets: Vec<u16>,
}

impl Node {
    /// Decode the descriptor + offset table of one node buffer.
    /// `buf` must be exactly `node_size` bytes.
    pub(crate) fn parse(buf: Vec<u8>, index: u32) -> Result<Node> {
        if buf.len() < 16 {
            return Err(FsError::corrupt(0, "node buffer too short"));
        }
        let node_size = buf.len();
        let num_recs = le::u16_be(&buf, 10).unwrap_or(0) as usize;
        // Offset table: (num_recs + 1) u16s ending at node_size.
        let table_len = (num_recs + 1) * 2;
        if table_len > node_size {
            return Err(FsError::corrupt(
                0,
                format!("node {index}: {num_recs} records overflow offset table"),
            ));
        }
        let table_off = node_size - table_len;
        let mut offsets = Vec::with_capacity(num_recs + 1);
        let mut prev = 0usize;
        for i in 0..=num_recs {
            let o = le::u16_be(&buf, table_off + i * 2).unwrap_or(0) as usize;
            // Offsets must be monotonic and inside the node.
            if o < 14 && num_recs > 0 && i == 0 {
                return Err(FsError::corrupt(
                    0,
                    format!("node {index}: record 0 offset {o} overlaps descriptor"),
                ));
            }
            if o < prev || o > table_off {
                return Err(FsError::corrupt(
                    0,
                    format!("node {index}: non-monotonic record offset {o}"),
                ));
            }
            prev = o;
            offsets.push(o as u16);
        }
        let next = le::u32_be(&buf, 0).unwrap_or(0);
        let kind = buf.get(8).copied().unwrap_or(0) as i8;
        let height = buf.get(9).copied().unwrap_or(0);
        Ok(Node {
            buf,
            next,
            kind,
            height,
            num_recs: num_recs as u16,
            offsets,
        })
    }

    /// Record `i`'s bytes (key + data).
    pub(crate) fn record(&self, i: usize) -> Option<&[u8]> {
        if i >= self.num_recs as usize {
            return None;
        }
        let s = *self.offsets.get(i)? as usize;
        let e = *self.offsets.get(i + 1)? as usize;
        self.buf.get(s..e)
    }

    /// The record whose start offset within the node is `off` — used to
    /// re-fetch a record by a [`RecRef`](crate::catalog::RecRef).
    pub(crate) fn record_at(&self, off: usize) -> Option<&[u8]> {
        for i in 0..self.num_recs as usize {
            if self.offsets[i] as usize == off {
                return self.record(i);
            }
        }
        None
    }

    /// Free-space span: `(start, end)` inside `buf` between the end of the
    /// last record and the start of the offset table. Deleted records decay
    /// here — this is the leaf-residue carving ground.
    pub(crate) fn free_space(&self) -> Option<(usize, usize)> {
        if self.offsets.is_empty() {
            return None;
        }
        let end_of_recs = *self.offsets.last()? as usize;
        let table_off = self.buf.len() - self.offsets.len() * 2;
        if end_of_recs >= table_off {
            return None;
        }
        Some((end_of_recs, table_off))
    }
}

/// Map a logical file offset through an extent list to an absolute offset.
pub(crate) fn map_logical(ranges: &[(u64, u64)], logical: u64) -> Option<u64> {
    let mut acc = 0u64;
    for &(off, len) in ranges {
        if logical < acc + len {
            return Some(off + (logical - acc));
        }
        acc += len;
    }
    None
}

/// Read up to `len` bytes starting at logical offset `logical` through an
/// extent map. Returns `None` when `logical` is beyond the mapped region;
/// short reads at the extent-list end return what exists.
pub(crate) fn read_range_span(
    src: &dyn ByteSource,
    ranges: &[(u64, u64)],
    logical: u64,
    len: usize,
) -> Option<Vec<u8>> {
    // Find the extent containing `logical`.
    let mut acc = 0u64;
    let mut idx = ranges.len();
    for (i, &(_, l)) in ranges.iter().enumerate() {
        if logical < acc + l {
            idx = i;
            break;
        }
        acc += l;
    }
    if idx == ranges.len() {
        return None;
    }
    let mut out = Vec::with_capacity(len.min(1 << 20));
    let mut pos = logical;
    let mut i = idx;
    while out.len() < len && i < ranges.len() {
        let (off, l) = ranges[i];
        let mut ext_logical_start = 0u64;
        for &(_, l2) in &ranges[..i] {
            ext_logical_start += l2;
        }
        if pos < ext_logical_start || pos >= ext_logical_start + l {
            break;
        }
        let in_ext = pos - ext_logical_start;
        let want = (l - in_ext).min((len - out.len()) as u64) as usize;
        let chunk = src.read_slice(off + in_ext, want).ok()?;
        if chunk.is_empty() {
            break;
        }
        pos += chunk.len() as u64;
        out.extend_from_slice(&chunk);
        i += 1;
    }
    Some(out)
}
