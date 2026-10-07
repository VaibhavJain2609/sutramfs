//! F2FS node-block decoding.
//!
//! Every node block is one filesystem block ending in a 24-byte
//! `node_footer` (`nid`, `ino`, `flag`, `cp_ver`, `next_blkaddr`). The body
//! is one of three kinds:
//!
//! * **inode node** — `struct f2fs_inode`: mode/size/times/flags plus the
//!   `i_addr[]` direct block pointers and `i_nid[5]` node pointers
//!   (2 direct nodes, 2 indirect, 1 double-indirect). `nid == ino`.
//! * **direct node** — `u32 addr[1018]` data block pointers.
//! * **indirect node** — `u32 nid[1018]` pointers to lower node blocks.
//!
//! The inode's `i_addr` region shares space with optional *extra attributes*
//! (at its head — crtime, compression info) and *inline xattrs* (at its
//! tail). Inline file data / inline dentries live inside the same region.

use sutram_fs::{FsError, Result};
use sutram_io::le;

/// `i_inline` bits.
#[allow(dead_code)]
pub(crate) mod inline_flag {
    pub const INLINE_XATTR: u8 = 0x01;
    pub const INLINE_DATA: u8 = 0x02;
    pub const INLINE_DENTRY: u8 = 0x04;
    pub const DATA_EXIST: u8 = 0x08;
    pub const EXTRA_ATTR: u8 = 0x20;
    pub const PIN_FILE: u8 = 0x40;
    pub const COMPRESS_RELEASED: u8 = 0x80;
}

/// `i_flags` bits (a subset of the Linux FS_*_FL namespace).
#[allow(dead_code)]
pub(crate) mod inode_flag {
    pub const COMPR: u32 = 0x0000_0004;
    pub const SYNC: u32 = 0x0000_0008;
    pub const IMMUTABLE: u32 = 0x0000_0010;
    pub const APPEND: u32 = 0x0000_0020;
    pub const NODUMP: u32 = 0x0000_0040;
    pub const NOATIME: u32 = 0x0000_0080;
    pub const NOCOMP: u32 = 0x0000_0400;
    pub const ENCRYPT: u32 = 0x0000_0800;
    pub const INDEX: u32 = 0x0000_1000;
    pub const DIRSYNC: u32 = 0x0001_0000;
    pub const VERITY: u32 = 0x0010_0000;
    pub const PROJINHERIT: u32 = 0x2000_0000;
    pub const CASEFOLD: u32 = 0x4000_0000;
    pub const SNOCOW: u32 = 0x0080_0000;
}

/// On-disk `file_type` values (shared `FT_*` numbering).
#[allow(dead_code)]
pub(crate) mod file_type {
    pub const UNKNOWN: u8 = 0;
    pub const REG_FILE: u8 = 1;
    pub const DIR: u8 = 2;
    pub const CHRDEV: u8 = 3;
    pub const BLKDEV: u8 = 4;
    pub const FIFO: u8 = 5;
    pub const SOCK: u8 = 6;
    pub const SYMLINK: u8 = 7;
}

/// Special block-address sentinels in `i_addr`/`addr` arrays.
pub(crate) const NULL_ADDR: u32 = 0;
pub(crate) const NEW_ADDR: u32 = u32::MAX;
pub(crate) const COMPRESS_ADDR: u32 = u32::MAX - 1;

/// Xattr magic (`struct f2fs_xattr_header::h_magic`).
pub(crate) const XATTR_MAGIC: u32 = 0xF2F5_2011;
/// Xattr index for the fscrypt context (name "c").
pub(crate) const XATTR_INDEX_ENCRYPTION: u8 = 9;
/// Xattr index for fs-verity metadata (name "v").
pub(crate) const XATTR_INDEX_VERITY: u8 = 11;

/// The 24-byte node footer sits at the end of every node block.
pub(crate) const FOOTER_LEN: usize = 24;

/// Decoded node footer.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NodeFooter {
    /// This node's own id.
    pub nid: u32,
    /// Owning inode number.
    pub ino: u32,
    /// cold/fsync/dent/offset flag bits.
    pub flag: u32,
    /// Checkpoint version that wrote this node block.
    pub cp_ver: u64,
    /// fsync chain link (usually 0).
    pub next_blkaddr: u32,
}

impl NodeFooter {
    /// Parse the footer of a block-sized buffer.
    pub fn parse(b: &[u8]) -> Option<Self> {
        let off = b.len().checked_sub(FOOTER_LEN)?;
        Some(NodeFooter {
            nid: le::u32(b, off)?,
            ino: le::u32(b, off + 4)?,
            flag: le::u32(b, off + 8)?,
            cp_ver: le::u64(b, off + 12)?,
            next_blkaddr: le::u32(b, off + 20)?,
        })
    }
}

/// Decoded `struct f2fs_inode` (the inode-node body).
#[derive(Debug, Clone)]
pub(crate) struct Inode {
    /// This inode's node id (== footer.nid == inode number). Set by the
    /// caller after [`Inode::decode`].
    pub nid: u32,
    pub mode: u16,
    pub advise: u8,
    pub inline_flags: u8,
    pub uid: u32,
    pub gid: u32,
    pub links: u32,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub ctime: u64,
    pub mtime: u64,
    pub atime_nsec: u32,
    pub ctime_nsec: u32,
    pub mtime_nsec: u32,
    pub generation: u32,
    pub current_depth: u32,
    pub xattr_nid: u32,
    pub flags: u32,
    pub pino: u32,
    /// Last-checkpoint name ("SPOR" recovery aid) — raw bytes.
    pub name: Vec<u8>,
    pub dir_level: u8,
    /// Cached largest extent (fofs, blk, len).
    pub i_ext: (u32, u32, u32),
    /// Extra-attr region size in bytes (0 when EXTRA_ATTR unset).
    pub extra_isize: u32,
    /// Inline-xattr region size in u32 units.
    pub inline_xattr_size: u32,
    /// i_extra_isize present and covers crtime (offset ≥ 24).
    pub crtime: Option<(u64, u32)>,
    pub compr_blocks: u64,
    pub compress_algorithm: u8,
    pub log_cluster_size: u8,
    pub compress_flag: u16,
    /// The raw inode bytes (kept for inline-data/xattr/dentry extraction).
    pub raw: Vec<u8>,
    /// Byte offset of `i_nid[0]` inside `raw` — follows `i_addr[]`, so it
    /// depends on the block size (4052 for 4 KiB blocks).
    pub nid_off: usize,
    /// Physical block this node was read from (set by the caller).
    pub blk: u64,
}

impl Inode {
    /// Byte offset of `i_addr[0]` inside the node block.
    pub(crate) const I_ADDR_OFF: usize = 360;

    /// Decode an inode-node body (the 4072 bytes before the footer for
    /// 4 KiB blocks). `body` is the node block minus the 24-byte footer.
    pub fn decode(body: &[u8], blk: u64) -> Result<Inode> {
        if body.len() < Self::I_ADDR_OFF + 24 {
            return Err(FsError::corrupt(blk, "node block too small for inode"));
        }
        let mode = le::u16(body, 0).unwrap_or(0);
        let inline_flags = le::u8(body, 3).unwrap_or(0);
        let extra_isize = if inline_flags & inline_flag::EXTRA_ATTR != 0 {
            le::u16(body, Self::I_ADDR_OFF).unwrap_or(0) as u32
        } else {
            0
        };
        let inline_xattr_size = if inline_flags & inline_flag::INLINE_XATTR != 0 {
            le::u16(body, Self::I_ADDR_OFF + 2).unwrap_or(0) as u32
        } else {
            0
        };
        let crtime = if extra_isize >= 24 {
            Some((
                le::u64(body, Self::I_ADDR_OFF + 12).unwrap_or(0),
                le::u32(body, Self::I_ADDR_OFF + 20).unwrap_or(0),
            ))
        } else {
            None
        };
        let namelen = le::u32(body, 88).unwrap_or(0).min(255) as usize;
        let name = body.get(92..92 + namelen).unwrap_or(&[]).to_vec();
        Ok(Inode {
            nid: 0,
            mode,
            advise: le::u8(body, 2).unwrap_or(0),
            inline_flags,
            uid: le::u32(body, 4).unwrap_or(0),
            gid: le::u32(body, 8).unwrap_or(0),
            links: le::u32(body, 12).unwrap_or(0),
            size: le::u64(body, 16).unwrap_or(0),
            blocks: le::u64(body, 24).unwrap_or(0),
            atime: le::u64(body, 32).unwrap_or(0),
            ctime: le::u64(body, 40).unwrap_or(0),
            mtime: le::u64(body, 48).unwrap_or(0),
            atime_nsec: le::u32(body, 56).unwrap_or(0),
            ctime_nsec: le::u32(body, 60).unwrap_or(0),
            mtime_nsec: le::u32(body, 64).unwrap_or(0),
            generation: le::u32(body, 68).unwrap_or(0),
            current_depth: le::u32(body, 72).unwrap_or(0),
            xattr_nid: le::u32(body, 76).unwrap_or(0),
            flags: le::u32(body, 80).unwrap_or(0),
            pino: le::u32(body, 84).unwrap_or(0),
            name,
            dir_level: le::u8(body, 347).unwrap_or(0),
            i_ext: (
                le::u32(body, 348).unwrap_or(0),
                le::u32(body, 352).unwrap_or(0),
                le::u32(body, 356).unwrap_or(0),
            ),
            extra_isize,
            inline_xattr_size,
            crtime,
            compr_blocks: if extra_isize >= 36 {
                le::u64(body, Self::I_ADDR_OFF + 24).unwrap_or(0)
            } else {
                0
            },
            compress_algorithm: if extra_isize >= 36 {
                le::u8(body, Self::I_ADDR_OFF + 32).unwrap_or(0)
            } else {
                0
            },
            log_cluster_size: if extra_isize >= 36 {
                le::u8(body, Self::I_ADDR_OFF + 33).unwrap_or(0)
            } else {
                0
            },
            compress_flag: if extra_isize >= 36 {
                le::u16(body, Self::I_ADDR_OFF + 34).unwrap_or(0)
            } else {
                0
            },
            raw: body.to_vec(),
            // i_nid[0] sits just past i_addr[DEF_ADDRS_PER_INODE]:
            // I_ADDR_OFF + (blksize - I_ADDR_OFF - 20 - 24).
            nid_off: Self::I_ADDR_OFF + (body.len().saturating_sub(Self::I_ADDR_OFF + 20) / 4) * 4,
            blk,
        })
    }

    /// u32 index into `i_addr` where data block pointers start
    /// (extra attributes occupy the head of the array).
    pub fn addr_base(&self, def_addrs: usize) -> usize {
        (self.extra_isize as usize / 4).min(def_addrs)
    }

    /// Number of usable direct block pointers in `i_addr`
    /// (`ADDRS_PER_INODE`: minus extra attrs and inline xattrs).
    pub fn addrs_count(&self, def_addrs: usize) -> usize {
        def_addrs
            .saturating_sub(self.extra_isize as usize / 4)
            .saturating_sub(self.inline_xattr_size as usize)
    }

    /// Direct block pointer `k` (logical block `k`), or `None`.
    /// Returns the raw `u32` — callers filter NULL/NEW/COMPRESS sentinels.
    pub fn i_addr(&self, k: usize, def_addrs: usize) -> Option<u32> {
        if k >= self.addrs_count(def_addrs) {
            return None;
        }
        let idx = self.addr_base(def_addrs) + k;
        le::u32(&self.raw, Self::I_ADDR_OFF + idx * 4)
    }

    /// Node-id pointer `i_nid[i]` (0..5: dir1, dir2, ind1, ind2, dind).
    pub fn i_nid(&self, i: usize) -> Option<u32> {
        if i >= 5 {
            return None;
        }
        le::u32(&self.raw, self.nid_off + i * 4)
    }

    /// Byte range of the inline-data/inline-dentry region inside the node
    /// block: `i_addr[extra + 1 .. 923 - xattr]` per `inline_data_addr`.
    /// Returns `(start, len)` relative to the node-block start.
    pub fn inline_region(&self, blksize: usize) -> (usize, usize) {
        let def_addrs = (blksize - Self::I_ADDR_OFF - 20 - FOOTER_LEN) / 4;
        let start = Self::I_ADDR_OFF + (self.extra_isize as usize / 4) * 4 + 4;
        let end =
            Self::I_ADDR_OFF + (def_addrs.saturating_sub(self.inline_xattr_size as usize)) * 4;
        (start, end.saturating_sub(start))
    }

    /// Byte range of the inline-xattr region inside the node block, if any.
    pub fn inline_xattr_region(&self, blksize: usize) -> Option<(usize, usize)> {
        if self.inline_xattr_size == 0 {
            return None;
        }
        let def_addrs = (blksize - Self::I_ADDR_OFF - 20 - FOOTER_LEN) / 4;
        let start = Self::I_ADDR_OFF + (def_addrs - self.inline_xattr_size as usize) * 4;
        Some((start, self.inline_xattr_size as usize * 4))
    }

    /// `true` when the inode carries the fscrypt flag.
    pub fn is_encrypted(&self) -> bool {
        self.flags & inode_flag::ENCRYPT != 0
    }
}

/// What a parsed node block contains.
pub(crate) enum NodeView {
    Inode(Box<Inode>),
    /// Non-inode node: array of u32 pointers (data addrs or child nids).
    Indirect(Vec<u32>),
}

/// Parse a node block: footer first, then body.
pub(crate) fn parse_node(b: &[u8], blk: u64, blksize: usize) -> Result<(NodeFooter, NodeView)> {
    let footer = NodeFooter::parse(b)
        .ok_or_else(|| FsError::corrupt(blk * blksize as u64, "short node block"))?;
    let body_len = b.len() - FOOTER_LEN;
    if footer.nid == footer.ino && footer.nid != 0 {
        let mut inode = Inode::decode(&b[..body_len], blk)?;
        inode.nid = footer.nid;
        Ok((footer, NodeView::Inode(Box::new(inode))))
    } else {
        let mut ptrs = Vec::with_capacity(body_len / 4);
        for i in 0..body_len / 4 {
            ptrs.push(le::u32(b, i * 4).unwrap_or(0));
        }
        Ok((footer, NodeView::Indirect(ptrs)))
    }
}

/// Does `b` plausibly contain a node block? Used when scanning stale
/// segments — the footer is self-describing (`nid`, `ino`, `cp_ver`).
pub(crate) fn looks_like_node(b: &[u8], max_nid: u64, latest_cp_ver: u64) -> Option<NodeFooter> {
    let f = NodeFooter::parse(b)?;
    if f.nid == 0 || f.ino == 0 || f.nid as u64 > max_nid || f.ino as u64 > max_nid {
        return None;
    }
    // cp_ver must not exceed the latest checkpoint by much (allow slack for
    // roll-forward writes between checkpoints).
    if f.cp_ver > latest_cp_ver.saturating_add(1) {
        return None;
    }
    Some(f)
}

/// Parsed xattr info relevant to forensics.
#[derive(Debug, Clone, Default)]
pub(crate) struct Xattrs {
    /// fscrypt context present (index 9, name "c").
    pub encrypt_ctx: Option<Vec<u8>>,
    /// fs-verity descriptor present (index 11, name "v").
    pub verity: bool,
    /// Names/indices seen (name_index:name pairs) for meta notes.
    pub list: Vec<String>,
}

/// Parse a sequence of `f2fs_xattr_entry` records (header already consumed
/// for block xattrs; the inline region starts directly at the first entry).
pub(crate) fn parse_xattr_entries(b: &[u8]) -> Xattrs {
    let mut out = Xattrs::default();
    let mut pos = 0usize;
    let mut guard = 0usize;
    loop {
        guard += 1;
        if guard > 512 || pos + 4 > b.len() {
            break;
        }
        // IS_XATTR_LAST_ENTRY: next 4 bytes all zero.
        if b[pos..pos + 4].iter().all(|&x| x == 0) {
            break;
        }
        let name_index = b[pos];
        let name_len = b[pos + 1] as usize;
        let value_size = le::u16(b, pos + 2).unwrap_or(0) as usize;
        let entry_size = (4 + name_len + 3) & !3; // XATTR_ALIGN(4 + name_len)
        let name = b.get(pos + 4..pos + 4 + name_len).unwrap_or(&[]);
        let value = b.get(pos + entry_size..pos + entry_size + value_size);
        out.list
            .push(format!("{name_index}:{}", String::from_utf8_lossy(name)));
        if name_index == XATTR_INDEX_ENCRYPTION {
            if let Some(v) = value {
                out.encrypt_ctx = Some(v.to_vec());
            }
        }
        if name_index == XATTR_INDEX_VERITY {
            out.verity = true;
        }
        if entry_size + value_size > b.len() - pos {
            break;
        }
        pos += entry_size + value_size;
    }
    out
}

/// Parse a standalone xattr block (i_xattr_nid target): 24-byte header then
/// the entry list. Returns `None` if the magic doesn't match.
pub(crate) fn parse_xattr_block(b: &[u8]) -> Option<Xattrs> {
    if b.len() < 24 || le::u32(b, 0)? != XATTR_MAGIC {
        return None;
    }
    Some(parse_xattr_entries(&b[24..]))
}
