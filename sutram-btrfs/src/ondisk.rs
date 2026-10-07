//! BTRFS on-disk structures and constants — the Rust port of the Python
//! parser's `structures.py` + `constants.py`.
//!
//! Decoders are *complete-format*: fields are decoded even when the current
//! forensic pipeline doesn't read them yet (kept for API completeness and
//! byte-level citation) — hence `dead_code` is allowed module-wide.
#![allow(dead_code)]
//!
//! Every decoder is bounds-checked (`Option`/`Result`, never a panic) and
//! little-endian via `sutram_io::le`. Offsets below are the exact byte
//! positions used by the Linux kernel's `ctree.h`/`disk-io` layouts.

use std::time::Duration;

use sutram_fs::{EntryKind, FsTimestamp};
use sutram_io::le;

// ---------------------------------------------------------------------------
// Constants (constants.py)
// ---------------------------------------------------------------------------

/// Primary superblock location, relative to the volume start.
pub const SUPERBLOCK_OFFSET: u64 = 0x10000;
/// Superblock mirror copies: 64 KiB, 64 MiB, 256 GiB.
pub const SUPERBLOCK_MIRRORS: [u64; 3] = [0x10000, 0x4000000, 0x4000000000];
/// Superblock is 4 KiB.
pub const SUPERBLOCK_SIZE: usize = 4096;
/// `_BHRfS_M` at superblock offset 0x40.
pub const BTRFS_MAGIC: &[u8; 8] = b"_BHRfS_M";
/// Offset of the magic inside the superblock.
pub const MAGIC_OFFSET: usize = 0x40;
/// Checksum field width.
pub const CSUM_SIZE: usize = 32;
/// Node header size.
pub const HEADER_SIZE: usize = 101;
/// `btrfs_key` = objectid(8) + type(1) + offset(8).
pub const KEY_SIZE: usize = 17;
/// Leaf item descriptor: key + offset(4) + size(4).
pub const ITEM_SIZE: usize = 25;
/// Internal-node key pointer: key + blockptr(8) + generation(8).
pub const KEY_PTR_SIZE: usize = 33;
/// Fixed part of a chunk item (before stripes).
pub const CHUNK_ITEM_FIXED_SIZE: usize = 48;
/// One stripe record inside a chunk item.
pub const STRIPE_SIZE: usize = 32;
/// `btrfs_inode_item` size.
pub const INODE_ITEM_SIZE: usize = 160;
/// Fixed part of a dir/xattr item.
pub const DIR_ITEM_FIXED_SIZE: usize = 30;
/// `btrfs_dev_item` size.
pub const DEV_ITEM_SIZE: usize = 98;
/// `btrfs_root_backup` size; four sit in the superblock tail.
pub const ROOT_BACKUP_SIZE: usize = 168;
/// Offset of the backup-roots array inside the superblock.
pub const SUPER_ROOTS_OFFSET: usize = 0xB2B;
/// `sys_chunk_array` inside the superblock.
pub const SYS_CHUNK_ARRAY_OFFSET: usize = 0x32B;
pub const SYS_CHUNK_ARRAY_SIZE: usize = 2048;
/// `btrfs_root_item` fixed size.
pub const ROOT_ITEM_SIZE: usize = 439;

/// Item types (`key.type`).
pub mod ty {
    pub const INODE_ITEM: u8 = 1;
    pub const INODE_REF: u8 = 12;
    pub const INODE_EXTREF: u8 = 13;
    pub const XATTR_ITEM: u8 = 24;
    pub const ORPHAN_ITEM: u8 = 48;
    pub const DIR_LOG_ITEM: u8 = 60;
    pub const DIR_LOG_INDEX: u8 = 72;
    pub const DIR_ITEM: u8 = 84;
    pub const DIR_INDEX: u8 = 96;
    pub const EXTENT_DATA: u8 = 108;
    pub const EXTENT_CSUM: u8 = 128;
    pub const ROOT_ITEM: u8 = 132;
    pub const ROOT_BACKREF: u8 = 144;
    pub const ROOT_REF: u8 = 156;
    pub const EXTENT_ITEM: u8 = 168;
    pub const METADATA_ITEM: u8 = 169;
    pub const TREE_BLOCK_REF: u8 = 176;
    pub const EXTENT_DATA_REF: u8 = 178;
    pub const EXTENT_REF_DEPRECATED: u8 = 180;
    pub const SHARED_BLOCK_REF: u8 = 182;
    pub const SHARED_DATA_REF: u8 = 184;
    pub const EXTENT_OWNER_REF: u8 = 188;
    pub const BLOCK_GROUP_ITEM: u8 = 192;
    pub const FREE_SPACE_INFO: u8 = 198;
    pub const FREE_SPACE_EXTENT: u8 = 199;
    pub const FREE_SPACE_BITMAP: u8 = 200;
    pub const DEV_EXTENT: u8 = 204;
    pub const DEV_ITEM: u8 = 216;
    pub const CHUNK_ITEM: u8 = 228;
    pub const QGROUP_STATUS: u8 = 240;
    pub const QGROUP_INFO: u8 = 242;
    pub const QGROUP_LIMIT: u8 = 244;
    pub const QGROUP_RELATION: u8 = 246;
}

/// Well-known object IDs (`key.objectid`).
pub mod objid {
    pub const ROOT_TREE: u64 = 1;
    pub const EXTENT_TREE: u64 = 2;
    pub const CHUNK_TREE: u64 = 3;
    pub const DEV_TREE: u64 = 4;
    pub const FS_TREE: u64 = 5;
    pub const ROOT_TREE_DIR: u64 = 6;
    pub const CSUM_TREE: u64 = 7;
    pub const QUOTA_TREE: u64 = 8;
    pub const UUID_TREE: u64 = 9;
    pub const FREE_SPACE_TREE: u64 = 10;
    /// `BTRFS_ORPHAN_OBJECTID` — (-48): parent objectid of ORPHAN_ITEMs.
    pub const ORPHAN: u64 = (-48i64) as u64; // 0xFFFF_FFFF_FFFF_FFD0
    /// First objectid usable for files/dirs/subvolumes.
    pub const FIRST_FREE: u64 = 256;
    pub const LAST_FREE: u64 = 0xFFFF_FFFF_FFFF_FF00;
    /// `BTRFS_FIRST_CHUNK_TREE_OBJECTID` — objectid of chunk items.
    pub const FIRST_CHUNK_TREE: u64 = 256;
}

/// Directory-entry file types (`BTRFS_FT_*`).
pub mod ft {
    use sutram_fs::EntryKind;

    pub const UNKNOWN: u8 = 0;
    pub const REG_FILE: u8 = 1;
    pub const DIR: u8 = 2;
    pub const CHRDEV: u8 = 3;
    pub const BLKDEV: u8 = 4;
    pub const FIFO: u8 = 5;
    pub const SOCK: u8 = 6;
    pub const SYMLINK: u8 = 7;
    pub const XATTR: u8 = 8;

    pub fn name(t: u8) -> &'static str {
        match t {
            REG_FILE => "file",
            DIR => "directory",
            CHRDEV => "chrdev",
            BLKDEV => "blkdev",
            FIFO => "fifo",
            SOCK => "socket",
            SYMLINK => "symlink",
            XATTR => "xattr",
            _ => "unknown",
        }
    }

    pub fn entry_kind(t: u8) -> Option<EntryKind> {
        match t {
            REG_FILE => Some(EntryKind::File),
            DIR => Some(EntryKind::Directory),
            SYMLINK => Some(EntryKind::Symlink),
            _ => None,
        }
    }
}

/// `btrfs_file_extent_item` compression values.
pub mod compression {
    pub const NONE: u8 = 0;
    pub const ZLIB: u8 = 1;
    pub const LZO: u8 = 2;
    pub const ZSTD: u8 = 3;

    pub fn name(c: u8) -> &'static str {
        match c {
            NONE => "none",
            ZLIB => "zlib",
            LZO => "lzo",
            ZSTD => "zstd",
            _ => "unknown",
        }
    }
}

/// `btrfs_file_extent_item` type values.
pub mod extent_ty {
    pub const INLINE: u8 = 0;
    pub const REGULAR: u8 = 1;
    pub const PREALLOC: u8 = 2;
}

/// Block-group / chunk `type` flag bits (`BTRFS_BLOCK_GROUP_*`).
pub mod block_group {
    pub const DATA: u64 = 1 << 0;
    pub const SYSTEM: u64 = 1 << 1;
    pub const METADATA: u64 = 1 << 2;
    pub const RAID0: u64 = 1 << 3;
    pub const RAID1: u64 = 1 << 4;
    pub const DUP: u64 = 1 << 5;
    pub const RAID10: u64 = 1 << 6;
    pub const RAID5: u64 = 1 << 7;
    pub const RAID6: u64 = 1 << 8;
    pub const RAID1C3: u64 = 1 << 9;
    pub const RAID1C4: u64 = 1 << 10;

    /// Profiles we can translate (parity RAID needs data/parity geometry we
    /// don't reconstruct).
    pub fn translatable(ty: u64) -> bool {
        ty & (RAID5 | RAID6) == 0
    }
}

/// `btrfs_extent_item` flag bits.
pub mod extent_flags {
    pub const DATA: u64 = 1 << 0;
    pub const TREE_BLOCK: u64 = 1 << 1;
}

/// `btrfs_root_item` flag bits.
pub mod root_flags {
    /// `BTRFS_SUBVOL_RDONLY` — set on read-only snapshots.
    pub const RDONLY: u64 = 1 << 0;
    /// `BTRFS_SUBVOL_DEAD` — subvolume is being deleted.
    pub const DEAD: u64 = 1 << 1;
}

/// Inode flag bits (`btrfs_inode_item.flags`, Python `BTRFS_INODE_FLAGS`).
pub mod inode_flags {
    pub const NODATASUM: u64 = 1 << 0;
    pub const NODATACOW: u64 = 1 << 1;
    pub const READONLY: u64 = 1 << 2;
    pub const NOCOMPRESS: u64 = 1 << 3;
    pub const PREALLOC: u64 = 1 << 4;
    pub const SYNC: u64 = 1 << 5;
    pub const IMMUTABLE: u64 = 1 << 6;
    pub const APPEND: u64 = 1 << 7;
    pub const NODUMP: u64 = 1 << 8;
    pub const NOATIME: u64 = 1 << 9;
    pub const DIRSYNC: u64 = 1 << 10;
    pub const COMPRESS: u64 = 1 << 11;
    pub const NODEDALLOC: u64 = 1 << 30;

    /// Decode to a comma-separated string, matching the Python parser.
    pub fn to_string(flags: u64) -> String {
        const NAMES: &[(u64, &str)] = &[
            (NODATASUM, "NODATASUM"),
            (NODATACOW, "NODATACOW"),
            (READONLY, "READONLY"),
            (NOCOMPRESS, "NOCOMPRESS"),
            (PREALLOC, "PREALLOC"),
            (SYNC, "SYNC"),
            (IMMUTABLE, "IMMUTABLE"),
            (APPEND, "APPEND"),
            (NODUMP, "NODUMP"),
            (NOATIME, "NOATIME"),
            (DIRSYNC, "DIRSYNC"),
            (COMPRESS, "COMPRESS"),
        ];
        NAMES
            .iter()
            .filter(|(bit, _)| flags & bit != 0)
            .map(|(_, n)| *n)
            .collect::<Vec<_>>()
            .join(",")
    }
}

// ---------------------------------------------------------------------------
// Structures (structures.py)
// ---------------------------------------------------------------------------

/// `btrfs_key` — every item in every tree is addressed by one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    pub objectid: u64,
    pub ty: u8,
    pub offset: u64,
}

impl Key {
    pub fn parse(buf: &[u8], pos: usize) -> Option<Key> {
        Some(Key {
            objectid: le::u64(buf, pos)?,
            ty: le::u8(buf, pos + 8)?,
            offset: le::u64(buf, pos + 9)?,
        })
    }
}

/// `btrfs_timespec` — sec(8) + nsec(4), nanosecond granularity.
#[derive(Debug, Clone, Copy, Default)]
pub struct Timespec {
    pub sec: u64,
    pub nsec: u32,
}

impl Timespec {
    pub fn parse(buf: &[u8], pos: usize) -> Option<Timespec> {
        Some(Timespec {
            sec: le::u64(buf, pos)?,
            nsec: le::u32(buf, pos + 8)?,
        })
    }

    /// Forensic timestamp. `sec == 0` (epoch) is a real stored value, not
    /// "unset" — BTRFS zeroes only truly-unset times, so we treat 0 as
    /// stored-but-epoch… which is indistinguishable; follow the forensic
    /// rule "never fabricate": emit `value: None` only when both fields are
    /// zero (BTRFS leaves otime zeroed when unknown).
    pub fn to_fs(self) -> FsTimestamp {
        let value = if self.sec == 0 && self.nsec == 0 {
            None
        } else {
            (self.sec as i64)
                .checked_mul(1_000_000_000)
                .and_then(|s| s.checked_add(self.nsec as i64))
        };
        FsTimestamp {
            value,
            // Pack both fields for byte-level citation.
            raw_value: (self.sec << 32) | self.nsec as u64,
            raw_encoding: "btrfs-timespec",
            granularity: Duration::from_nanos(1),
        }
    }
}

/// 101-byte node header at the start of every tree block.
#[derive(Debug, Clone)]
pub struct Header {
    pub csum: [u8; CSUM_SIZE],
    pub fsid: [u8; 16],
    /// Logical address this block claims to live at.
    pub bytenr: u64,
    pub flags: u64,
    pub chunk_tree_uuid: [u8; 16],
    /// Transaction that wrote this block.
    pub generation: u64,
    /// Objectid of the owning tree.
    pub owner: u64,
    pub nritems: u32,
    /// 0 = leaf, >0 = internal level.
    pub level: u8,
    /// CRC32C over `block[32..]` matched (only set when csum_type == 0).
    pub csum_ok: Option<bool>,
}

impl Header {
    pub fn parse(buf: &[u8]) -> Option<Header> {
        let mut csum = [0u8; CSUM_SIZE];
        let mut fsid = [0u8; 16];
        let mut chunk_tree_uuid = [0u8; 16];
        csum.copy_from_slice(le::get(buf, 0, CSUM_SIZE)?);
        fsid.copy_from_slice(le::get(buf, 0x20, 16)?);
        chunk_tree_uuid.copy_from_slice(le::get(buf, 0x40, 16)?);
        Some(Header {
            csum,
            fsid,
            bytenr: le::u64(buf, 0x30)?,
            flags: le::u64(buf, 0x38)?,
            chunk_tree_uuid,
            generation: le::u64(buf, 0x50)?,
            owner: le::u64(buf, 0x58)?,
            nritems: le::u32(buf, 0x60)?,
            level: le::u8(buf, 0x64)?,
            csum_ok: None,
        })
    }
}

/// 25-byte item descriptor in a leaf.
#[derive(Debug, Clone, Copy)]
pub struct Item {
    pub key: Key,
    /// Offset of the item body, relative to end of header (byte 101).
    pub offset: u32,
    /// Body length.
    pub size: u32,
}

impl Item {
    pub fn parse(buf: &[u8], pos: usize) -> Option<Item> {
        Some(Item {
            key: Key::parse(buf, pos)?,
            offset: le::u32(buf, pos + 17)?,
            size: le::u32(buf, pos + 21)?,
        })
    }
}

/// 33-byte key pointer in an internal node.
#[derive(Debug, Clone, Copy)]
pub struct KeyPtr {
    pub key: Key,
    /// Logical address of the child block.
    pub blockptr: u64,
    /// Expected generation of the child block.
    pub generation: u64,
}

impl KeyPtr {
    pub fn parse(buf: &[u8], pos: usize) -> Option<KeyPtr> {
        Some(KeyPtr {
            key: Key::parse(buf, pos)?,
            blockptr: le::u64(buf, pos + 17)?,
            generation: le::u64(buf, pos + 25)?,
        })
    }
}

/// `btrfs_inode_item` — 160 bytes of file/dir metadata.
#[derive(Debug, Clone)]
pub struct InodeItem {
    pub generation: u64,
    pub transid: u64,
    /// Logical file size.
    pub size: u64,
    /// Allocated bytes.
    pub nbytes: u64,
    pub block_group: u64,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub rdev: u64,
    pub flags: u64,
    pub sequence: u64,
    pub atime: Timespec,
    pub ctime: Timespec,
    pub mtime: Timespec,
    /// Birth time.
    pub otime: Timespec,
}

impl InodeItem {
    pub fn parse(buf: &[u8], pos: usize) -> Option<InodeItem> {
        le::get(buf, pos, INODE_ITEM_SIZE)?;
        Some(InodeItem {
            generation: le::u64(buf, pos)?,
            transid: le::u64(buf, pos + 8)?,
            size: le::u64(buf, pos + 16)?,
            nbytes: le::u64(buf, pos + 24)?,
            block_group: le::u64(buf, pos + 32)?,
            nlink: le::u32(buf, pos + 40)?,
            uid: le::u32(buf, pos + 44)?,
            gid: le::u32(buf, pos + 48)?,
            mode: le::u32(buf, pos + 52)?,
            rdev: le::u64(buf, pos + 56)?,
            flags: le::u64(buf, pos + 64)?,
            sequence: le::u64(buf, pos + 72)?,
            // pos+80 .. pos+112 reserved
            atime: Timespec::parse(buf, pos + 112)?,
            ctime: Timespec::parse(buf, pos + 124)?,
            mtime: Timespec::parse(buf, pos + 136)?,
            otime: Timespec::parse(buf, pos + 148)?,
        })
    }

    /// `EntryKind` from the mode's `S_IFMT` bits.
    pub fn kind(&self) -> EntryKind {
        const S_IFMT: u32 = 0o170000;
        match self.mode & S_IFMT {
            0o100000 => EntryKind::File,
            0o040000 => EntryKind::Directory,
            0o120000 => EntryKind::Symlink,
            _ => EntryKind::Other,
        }
    }

    pub fn is_dir(&self) -> bool {
        self.kind() == EntryKind::Directory
    }
}

/// `btrfs_file_extent_item` — maps a file range to disk.
#[derive(Debug, Clone)]
pub struct FileExtentItem {
    pub generation: u64,
    /// Uncompressed size of the whole extent.
    pub ram_bytes: u64,
    /// 0 none / 1 zlib / 2 lzo / 3 zstd.
    pub compression: u8,
    pub encryption: u8,
    /// 0 inline / 1 regular / 2 prealloc.
    pub ty: u8,
    /// Logical disk address (0 = hole/sparse).
    pub disk_bytenr: u64,
    /// On-disk (compressed) bytes.
    pub disk_num_bytes: u64,
    /// Offset into the uncompressed extent.
    pub offset: u64,
    /// Bytes of the file covered by this item.
    pub num_bytes: u64,
}

impl FileExtentItem {
    /// Parse from the item body; `body` starts at the fixed header.
    /// Mirrors `BtrfsFileExtentItem.unpack`: type ≥1 needs 53 bytes total.
    pub fn parse(data: &[u8]) -> Option<FileExtentItem> {
        le::get(data, 0, 21)?;
        let ty = le::u8(data, 20)?;
        let (disk_bytenr, disk_num_bytes, offset, num_bytes) =
            if (ty == extent_ty::REGULAR || ty == extent_ty::PREALLOC) && data.len() >= 53 {
                (
                    le::u64(data, 21)?,
                    le::u64(data, 29)?,
                    le::u64(data, 37)?,
                    le::u64(data, 45)?,
                )
            } else {
                (0, 0, 0, le::u64(data, 8)?)
            };
        Some(FileExtentItem {
            generation: le::u64(data, 0)?,
            ram_bytes: le::u64(data, 8)?,
            compression: le::u8(data, 16)?,
            encryption: le::u8(data, 17)?,
            ty,
            disk_bytenr,
            disk_num_bytes,
            offset,
            num_bytes,
        })
    }
}

/// `btrfs_dir_item` — directory entry / xattr (variable length).
#[derive(Debug)]
pub struct DirItem {
    /// Key of the referenced inode.
    pub location: Key,
    pub transid: u64,
    /// xattr value length (0 for dir entries).
    pub data_len: u16,
    pub name_len: u16,
    /// `BTRFS_FT_*` file type.
    pub ty: u8,
    /// Byte offset of the name within the item body.
    pub name_off: usize,
    /// Total bytes this item occupies in the leaf body.
    pub total: usize,
}

impl DirItem {
    /// Parse the fixed header; `name`/`data` slices are taken by callers as
    /// `data[item.name_off .. +name_len]` and the following `data_len` bytes.
    pub fn parse(data: &[u8], pos: usize) -> Option<DirItem> {
        let name_len = le::u16(data, pos + 27)?;
        let data_len = le::u16(data, pos + 25)?;
        let total = DIR_ITEM_FIXED_SIZE + name_len as usize + data_len as usize;
        le::get(data, pos, total)?;
        Some(DirItem {
            location: Key::parse(data, pos)?,
            transid: le::u64(data, pos + 17)?,
            data_len,
            name_len,
            ty: le::u8(data, pos + 29)?,
            name_off: pos + DIR_ITEM_FIXED_SIZE,
            total,
        })
    }

    pub fn name<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        le::get(data, self.name_off, self.name_len as usize)
    }

    pub fn value<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        le::get(
            data,
            self.name_off + self.name_len as usize,
            self.data_len as usize,
        )
    }
}

/// `btrfs_root_ref` / `btrfs_root_backref` body.
#[derive(Debug)]
pub struct RootRef {
    /// Directory id inside the parent tree.
    pub dirid: u64,
    pub sequence: u64,
    pub name_len: u16,
    pub name_off: usize,
    pub total: usize,
}

impl RootRef {
    pub fn parse(data: &[u8], pos: usize) -> Option<RootRef> {
        let name_len = le::u16(data, pos + 16)?;
        let total = 18 + name_len as usize;
        le::get(data, pos, total)?;
        Some(RootRef {
            dirid: le::u64(data, pos)?,
            sequence: le::u64(data, pos + 8)?,
            name_len,
            name_off: pos + 18,
            total,
        })
    }

    pub fn name<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        le::get(data, self.name_off, self.name_len as usize)
    }
}

/// One stripe of a `btrfs_chunk`.
#[derive(Debug, Clone)]
pub struct Stripe {
    pub devid: u64,
    /// Physical offset on that device.
    pub offset: u64,
    pub dev_uuid: [u8; 16],
}

/// `btrfs_chunk` — logical→physical mapping record.
#[derive(Debug, Clone)]
pub struct Chunk {
    /// Chunk length in bytes.
    pub length: u64,
    /// Owning root objectid.
    pub owner: u64,
    pub stripe_len: u64,
    /// `BTRFS_BLOCK_GROUP_*` flags.
    pub ty: u64,
    pub io_align: u32,
    pub io_width: u32,
    pub sector_size: u32,
    pub num_stripes: u16,
    pub sub_stripes: u16,
    pub stripes: Vec<Stripe>,
}

impl Chunk {
    pub fn parse(data: &[u8], pos: usize) -> Option<Chunk> {
        let num_stripes = le::u16(data, pos + 44)?;
        let total = CHUNK_ITEM_FIXED_SIZE + STRIPE_SIZE * num_stripes as usize;
        le::get(data, pos, total)?;
        let mut stripes = Vec::with_capacity(num_stripes as usize);
        for i in 0..num_stripes as usize {
            let sp = pos + CHUNK_ITEM_FIXED_SIZE + i * STRIPE_SIZE;
            let mut dev_uuid = [0u8; 16];
            dev_uuid.copy_from_slice(le::get(data, sp + 16, 16)?);
            stripes.push(Stripe {
                devid: le::u64(data, sp)?,
                offset: le::u64(data, sp + 8)?,
                dev_uuid,
            });
        }
        Some(Chunk {
            length: le::u64(data, pos)?,
            owner: le::u64(data, pos + 8)?,
            stripe_len: le::u64(data, pos + 16)?,
            ty: le::u64(data, pos + 24)?,
            io_align: le::u32(data, pos + 32)?,
            io_width: le::u32(data, pos + 36)?,
            sector_size: le::u32(data, pos + 40)?,
            num_stripes,
            sub_stripes: le::u16(data, pos + 46)?,
            stripes,
        })
    }

    pub fn total_size(&self) -> usize {
        CHUNK_ITEM_FIXED_SIZE + STRIPE_SIZE * self.num_stripes as usize
    }
}

/// `btrfs_root_item` — describes a tree (subvolume or system tree).
#[derive(Debug, Clone)]
pub struct RootItem {
    /// Embedded inode of the tree's root directory.
    pub inode: InodeItem,
    pub generation: u64,
    pub root_dirid: u64,
    /// Logical address of the tree's root block.
    pub bytenr: u64,
    pub byte_limit: u64,
    pub bytes_used: u64,
    pub last_snapshot: u64,
    /// `BTRFS_SUBVOL_*` flags.
    pub flags: u64,
    pub refs: u32,
    /// Tree depth of the referenced root.
    pub level: u8,
    pub generation_v2: u64,
    pub uuid: [u8; 16],
    /// Non-zero for snapshots: uuid of the source subvolume.
    pub parent_uuid: [u8; 16],
    pub ctransid: u64,
    pub otransid: u64,
    pub ctime: Timespec,
    pub otime: Timespec,
}

impl RootItem {
    /// Parse; requires the 239-byte prefix (`bytenr` at 176, `level` at
    /// 238). Later fields are optional — absent → defaults.
    pub fn parse(data: &[u8]) -> Option<RootItem> {
        le::get(data, 0, 239)?;
        let mut uuid = [0u8; 16];
        let mut parent_uuid = [0u8; 16];
        if let Some(b) = le::get(data, 247, 16) {
            uuid.copy_from_slice(b);
        }
        if let Some(b) = le::get(data, 263, 16) {
            parent_uuid.copy_from_slice(b);
        }
        Some(RootItem {
            inode: InodeItem::parse(data, 0)?,
            generation: le::u64(data, 160)?,
            root_dirid: le::u64(data, 168)?,
            bytenr: le::u64(data, 176)?,
            byte_limit: le::u64(data, 184).unwrap_or(0),
            bytes_used: le::u64(data, 192).unwrap_or(0),
            last_snapshot: le::u64(data, 200).unwrap_or(0),
            flags: le::u64(data, 208).unwrap_or(0),
            refs: le::u32(data, 216).unwrap_or(0),
            level: le::u8(data, 238).unwrap_or(0),
            generation_v2: le::u64(data, 239).unwrap_or(0),
            uuid,
            parent_uuid,
            ctransid: le::u64(data, 295).unwrap_or(0),
            otransid: le::u64(data, 303).unwrap_or(0),
            ctime: Timespec::parse(data, 327).unwrap_or_default(),
            otime: Timespec::parse(data, 339).unwrap_or_default(),
        })
    }

    /// Effective tree generation (`generation_v2` when present).
    pub fn tree_gen(&self) -> u64 {
        if self.generation_v2 != 0 {
            self.generation_v2
        } else {
            self.generation
        }
    }
}

/// `btrfs_extent_item` fixed part + decoded inline backrefs.
#[derive(Debug, Clone)]
pub struct ExtentItem {
    /// Reference count.
    pub refs: u64,
    /// Transaction that allocated the extent.
    pub generation: u64,
    /// `BTRFS_EXTENT_FLAG_*`.
    pub flags: u64,
}

impl ExtentItem {
    pub fn parse(data: &[u8]) -> Option<ExtentItem> {
        Some(ExtentItem {
            refs: le::u64(data, 0)?,
            generation: le::u64(data, 8)?,
            flags: le::u64(data, 16)?,
        })
    }
}

/// `btrfs_extent_data_ref` body (28 bytes) — inside EXTENT_DATA_REF items
/// and inline inside EXTENT_ITEMs.
#[derive(Debug, Clone, Copy)]
pub struct ExtentDataRef {
    /// Tree/root objectid holding the reference.
    pub root: u64,
    /// Inode referencing the extent.
    pub objectid: u64,
    /// File offset of the reference.
    pub offset: u64,
    pub count: u32,
}

impl ExtentDataRef {
    pub fn parse(data: &[u8], pos: usize) -> Option<ExtentDataRef> {
        le::get(data, pos, 28)?;
        Some(ExtentDataRef {
            root: le::u64(data, pos)?,
            objectid: le::u64(data, pos + 8)?,
            offset: le::u64(data, pos + 16)?,
            count: le::u32(data, pos + 24)?,
        })
    }
}

/// `btrfs_dev_item` — one filesystem member device (98 bytes).
#[derive(Debug, Clone)]
pub struct DevItem {
    pub devid: u64,
    /// Device capacity in bytes.
    pub total_bytes: u64,
    pub bytes_used: u64,
    pub sector_size: u32,
}

impl DevItem {
    pub fn parse(data: &[u8]) -> Option<DevItem> {
        le::get(data, 0, DEV_ITEM_SIZE)?;
        Some(DevItem {
            devid: le::u64(data, 0)?,
            total_bytes: le::u64(data, 8)?,
            bytes_used: le::u64(data, 16)?,
            // io_align@24, io_width@28, sector_size@32, type@36
            sector_size: le::u32(data, 32)?,
        })
    }
}

/// `btrfs_free_space_entry` — a free extent or bitmap inside the
/// free-space tree (objectid 10): `offset`(8) + `length`(8) [+ bitmap].
#[derive(Debug, Clone, Copy)]
pub struct FreeSpaceEntry {
    pub offset: u64,
    /// Byte length the entry covers.
    pub length: u64,
}

impl FreeSpaceEntry {
    pub fn parse(data: &[u8]) -> Option<FreeSpaceEntry> {
        Some(FreeSpaceEntry {
            offset: le::u64(data, 0)?,
            length: le::u64(data, 8)?,
        })
    }
}

/// `btrfs_root_backup` — one of the four previous-generation tree roots
/// stored in the superblock tail (`BTRFS_NUM_BACKUP_ROOTS`).
#[derive(Debug, Clone, Copy)]
pub struct RootBackup {
    pub tree_root: u64,
    pub tree_root_gen: u64,
    pub chunk_root: u64,
    pub chunk_root_gen: u64,
    pub extent_root: u64,
    pub extent_root_gen: u64,
    /// FS_TREE (objectid 5) root for this generation.
    pub fs_root: u64,
    pub fs_root_gen: u64,
    pub dev_root: u64,
    pub csum_root: u64,
    pub tree_root_level: u8,
    pub fs_root_level: u8,
}

impl RootBackup {
    pub fn parse(data: &[u8], pos: usize) -> Option<RootBackup> {
        le::get(data, pos, ROOT_BACKUP_SIZE)?;
        Some(RootBackup {
            tree_root: le::u64(data, pos)?,
            tree_root_gen: le::u64(data, pos + 8)?,
            chunk_root: le::u64(data, pos + 16)?,
            chunk_root_gen: le::u64(data, pos + 24)?,
            extent_root: le::u64(data, pos + 32)?,
            extent_root_gen: le::u64(data, pos + 40)?,
            fs_root: le::u64(data, pos + 48)?,
            fs_root_gen: le::u64(data, pos + 56)?,
            dev_root: le::u64(data, pos + 64)?,
            csum_root: le::u64(data, pos + 80)?,
            tree_root_level: le::u8(data, pos + 152).unwrap_or(0),
            fs_root_level: le::u8(data, pos + 155).unwrap_or(0),
        })
    }

    /// Whether this backup slot carries a usable root.
    pub fn valid(&self) -> bool {
        self.tree_root != 0 || self.fs_root != 0
    }
}
