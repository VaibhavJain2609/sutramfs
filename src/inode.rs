//! Inode decoding: mode/kind, nanosecond + crtime timestamps, extended
//! attributes (in-inode body and `i_file_acl` block).
//!
//! Byte offsets below are the classic ext2 inode layout; ext4 inodes are
//! the same structure widened to `s_inode_size` (usually 256 bytes) with
//! `i_extra_isize` extension fields at 0x80+.

use std::time::Duration;

use sutram_fs::{FsTimestamp, Timestamps};
use sutram_io::le;

/// Minimum structurally-meaningful inode size (rev 0 inodes).
pub(crate) const MIN_INODE_SIZE: usize = 128;

// i_mode type bits (S_IFMT).
pub(crate) const S_IFMT: u16 = 0xF000;
pub(crate) const S_IFREG: u16 = 0x8000;
pub(crate) const S_IFDIR: u16 = 0x4000;
pub(crate) const S_IFLNK: u16 = 0xA000;

// i_flags bits.
/// Extent tree in `i_block` (absent → legacy direct/indirect map).
pub(crate) const EXT4_EXTENTS_FL: u32 = 0x0008_0000;
/// HTree-indexed directory.
pub(crate) const EXT4_INDEX_FL: u32 = 0x0000_1000;
/// fscrypt-encrypted file/dir.
pub(crate) const EXT4_ENCRYPT_FL: u32 = 0x0000_0800;
/// File data stored inside the inode (+ `system.data` xattr spillover).
pub(crate) const EXT4_INLINE_DATA_FL: u32 = 0x1000_0000;
/// Case-insensitive directory (casefold feature).
pub(crate) const EXT4_CASEFOLD_FL: u32 = 0x4000_0000;

/// `h_magic` of an xattr block / in-inode xattr region.
const XATTR_MAGIC: u32 = 0xEA02_0000;

/// A decoded inode. `raw` is retained (≤ `s_inode_size`, bounded) so xattr
/// tails and inline data can be decoded lazily without re-reading the disk.
#[derive(Debug, Clone)]
pub(crate) struct Inode {
    pub ino: u32,
    /// Absolute byte offset of the inode on the source (provenance).
    pub disk_offset: u64,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    /// Logical file size (`i_size_lo | i_size_high<<32` for regular files).
    pub size: u64,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    /// Deletion time — also the next-orphan link for orphan-list inodes.
    pub dtime: u32,
    pub links_count: u16,
    /// i_blocks in 512-byte units (with the `l_i_blocks_high` extension).
    pub blocks_512: u64,
    pub flags: u32,
    /// The raw 60-byte `i_block` array (extent root, block map, fast
    /// symlink target or inline-data payload depending on flags/mode).
    pub block60: [u8; 60],
    pub generation: u32,
    /// xattr block number (`i_file_acl_lo | l_i_file_acl_high<<32`).
    pub file_acl: u64,
    /// Extra fields beyond byte 128 (nsec timestamps + crtime live here).
    pub extra_isize: u16,
    pub atime_extra: u32,
    pub ctime_extra: u32,
    pub mtime_extra: u32,
    pub crtime: Option<(u32, u32)>,
    /// The full raw inode bytes.
    pub raw: Vec<u8>,
}

impl Inode {
    /// Decode `raw` (≥ 128 bytes, ≤ `s_inode_size`) as inode `ino`.
    ///
    /// Never fails on weird field values — implausible inodes are the
    /// caller's problem ([`Inode::is_plausible`]); only a short buffer is
    /// an error, which cannot happen when the caller honours
    /// `s_inode_size`.
    pub(crate) fn parse(raw: &[u8], ino: u32, disk_offset: u64) -> Option<Inode> {
        if raw.len() < MIN_INODE_SIZE {
            return None;
        }
        let mut block60 = [0u8; 60];
        block60.copy_from_slice(le::get(raw, 0x28, 60)?);
        let extra_isize = le::u16(raw, 0x80).unwrap_or(0);
        // Extension field `x` (ending at inode offset `end`) is present iff
        // `end - 0x80 <= extra_isize` and fits the buffer.
        let has_field = |end: usize| {
            end - 0x80 <= extra_isize as usize && end <= raw.len()
        };
        let ext_u32 = |off: usize| -> u32 {
            if has_field(off + 4) {
                le::u32(raw, off).unwrap_or(0)
            } else {
                0
            }
        };
        let is_reg = le::u16(raw, 0x00).unwrap_or(0) & S_IFMT == S_IFREG;
        let size_lo = le::u32(raw, 0x04).unwrap_or(0) as u64;
        let size_hi = le::u32(raw, 0x6C).unwrap_or(0) as u64;
        let size = if is_reg { size_lo | (size_hi << 32) } else { size_lo };
        let crtime = if has_field(0x94) {
            Some((le::u32(raw, 0x90).unwrap_or(0), le::u32(raw, 0x94).unwrap_or(0)))
        } else if has_field(0x90) {
            Some((le::u32(raw, 0x90).unwrap_or(0), 0))
        } else {
            None
        };
        Some(Inode {
            ino,
            disk_offset,
            mode: le::u16(raw, 0x00).unwrap_or(0),
            uid: le::u16(raw, 0x02).unwrap_or(0) as u32
                | ((le::u16(raw, 0x78).unwrap_or(0) as u32) << 16),
            gid: le::u16(raw, 0x18).unwrap_or(0) as u32
                | ((le::u16(raw, 0x7A).unwrap_or(0) as u32) << 16),
            size,
            atime: le::u32(raw, 0x08).unwrap_or(0),
            ctime: le::u32(raw, 0x0C).unwrap_or(0),
            mtime: le::u32(raw, 0x10).unwrap_or(0),
            dtime: le::u32(raw, 0x14).unwrap_or(0),
            links_count: le::u16(raw, 0x1A).unwrap_or(0),
            blocks_512: le::u32(raw, 0x1C).unwrap_or(0) as u64
                | ((le::u16(raw, 0x74).unwrap_or(0) as u64) << 32),
            flags: le::u32(raw, 0x20).unwrap_or(0),
            block60,
            generation: le::u32(raw, 0x64).unwrap_or(0),
            file_acl: le::u32(raw, 0x68).unwrap_or(0) as u64
                | ((le::u16(raw, 0x76).unwrap_or(0) as u64) << 32),
            extra_isize,
            atime_extra: ext_u32(0x8C),
            ctime_extra: ext_u32(0x84),
            mtime_extra: ext_u32(0x88),
            crtime,
            raw: raw.to_vec(),
        })
    }

    /// The inode looks like it once held a real file — used to separate
    /// genuinely deleted inodes from never-used table slots (all zeros).
    pub(crate) fn is_plausible(&self) -> bool {
        self.mode != 0 && self.mode & S_IFMT != 0
    }

    pub(crate) fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
    pub(crate) fn is_reg(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
    pub(crate) fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }
    pub(crate) fn has_extents(&self) -> bool {
        self.flags & EXT4_EXTENTS_FL != 0
    }
    pub(crate) fn has_inline_data(&self) -> bool {
        self.flags & EXT4_INLINE_DATA_FL != 0
    }
    /// Fast symlink: target stored in `i_block` (≤60 bytes, no blocks).
    pub(crate) fn is_fast_symlink(&self) -> bool {
        self.is_symlink() && self.blocks_512 == 0 && self.size <= 60
    }

    /// Decode MACB + birth + deletion timestamps.
    ///
    /// ext4 stores `u32` seconds plus an extension field carrying 30 bits
    /// of nanoseconds and 2 high epoch bits (`extra = nsec<<2 | sec>>32`).
    /// Without the extension fields (ext2/rev0 or small inodes) the
    /// granularity is whole seconds.
    pub(crate) fn timestamps(&self) -> Timestamps {
        Timestamps {
            modified: Some(ext4_ts(self.mtime, self.mtime_extra, "ext4-mtime")),
            accessed: Some(ext4_ts(self.atime, self.atime_extra, "ext4-atime")),
            changed: Some(ext4_ts(self.ctime, self.ctime_extra, "ext4-ctime")),
            created: self
                .crtime
                .map(|(s, x)| ext4_ts(s, x, "ext4-crtime")),
            deleted: if self.dtime != 0 {
                Some(FsTimestamp {
                    value: Some(self.dtime as i64 * 1_000_000_000),
                    raw_value: self.dtime as u64,
                    raw_encoding: "ext4-dtime-sec",
                    granularity: Duration::from_secs(1),
                })
            } else {
                Some(FsTimestamp {
                    value: None,
                    raw_value: 0,
                    raw_encoding: "ext4-dtime-sec",
                    granularity: Duration::from_secs(1),
                })
            },
        }
    }

    /// Extended attribute names (`user.*`, `security.*`, `system.*`,
    /// `trusted.*`) from the in-inode body region only — block xattrs are
    /// decoded separately via [`parse_xattr_block`].
    pub(crate) fn ibody_xattr_names(&self) -> Vec<String> {
        // The ibody xattr region follows the fixed+extended inode fields.
        let start = (MIN_INODE_SIZE + self.extra_isize as usize + 3) & !3;
        if start + 4 > self.raw.len() {
            return Vec::new();
        }
        if le::u32(&self.raw, start) != Some(XATTR_MAGIC) {
            return Vec::new();
        }
        parse_xattr_entries(&self.raw, start + 4, self.raw.len())
    }
}

/// Decode one timestamp pair `(sec, extra)`.
///
/// `extra` low 2 bits extend the epoch to 34 bits; upper 30 bits are
/// nanoseconds. `sec == 0 && extra == 0` → unset (`value: None`), never
/// fabricate the epoch.
pub(crate) fn ext4_ts(sec: u32, extra: u32, enc: &'static str) -> FsTimestamp {
    let secs = (sec as i64) | (((extra & 0x3) as i64) << 32);
    let nanos = (extra >> 2) as i64;
    let value = if sec == 0 && extra == 0 {
        None
    } else {
        secs.checked_mul(1_000_000_000)
            .and_then(|v| v.checked_add(nanos))
    };
    FsTimestamp {
        value,
        raw_value: (sec as u64) | ((extra as u64) << 32),
        raw_encoding: if extra != 0 { "ext4-sec+nsec" } else { enc },
        granularity: if extra != 0 {
            Duration::from_nanos(1)
        } else {
            Duration::from_secs(1)
        },
    }
}

/// Name-index → prefix, per ext4 `xattr` name-index table.
fn xattr_prefix(index: u8) -> &'static str {
    match index {
        1 => "user.",
        2 => "system.posix_acl_access",
        3 => "system.posix_acl_default",
        4 => "trusted.",
        6 => "security.",
        7 => "system.",
        8 => "system.richacl",
        _ => "",
    }
}

/// Decode an `ext4_xattr_entry` array starting at `off` in `buf`,
/// terminated by a zeroed entry (`e_name_len == 0`).
/// `entries_end` bounds the entry array; returns full `prefix.name` strings.
///
/// Entry layout: `u8 name_len, u8 name_index, u16 value_offs,
/// u32 value_inum, u32 value_size, u32 hash, char name[name_len]` —
/// a 16-byte header; each entry is padded to a 4-byte boundary.
fn parse_xattr_entries(buf: &[u8], mut off: usize, entries_end: usize) -> Vec<String> {
    let mut names = Vec::new();
    const MAX_XATTRS: usize = 128;
    while off + 16 <= entries_end && names.len() < MAX_XATTRS {
        let name_len = match le::u8(buf, off) {
            Some(0) | None => break,
            Some(n) => n as usize,
        };
        let index = le::u8(buf, off + 1).unwrap_or(0);
        let name_off = off + 16;
        if name_off + name_len > buf.len() {
            break;
        }
        let name = String::from_utf8_lossy(&buf[name_off..name_off + name_len]);
        names.push(format!("{}{}", xattr_prefix(index), name));
        off = (name_off + name_len + 3) & !3;
    }
    names
}

/// Decode the xattr names stored in a dedicated `i_file_acl` block.
/// `block` is the raw filesystem block; header is 32 bytes.
pub(crate) fn parse_xattr_block(block: &[u8]) -> Vec<String> {
    if block.len() < 32 || le::u32(block, 0) != Some(XATTR_MAGIC) {
        return Vec::new();
    }
    parse_xattr_entries(block, 32, block.len())
}
