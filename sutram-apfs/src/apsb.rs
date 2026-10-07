//! `apfs_superblock_t` — the volume superblock (object type
//! `OBJECT_TYPE_FS`, magic `"APSB"`, ~1056 fixed bytes inside one block).

use sutram_fs::{FsError, Result};
use sutram_io::le;

use crate::nx::uuid_be;
use crate::object::{otype, ObjHdr};

/// `"APSB"` little-endian.
pub(crate) const APFS_MAGIC: u32 = 0x4253_5041;

/// `apfs_fs_flags` bits we interpret.
pub(crate) mod fs_flags {
    /// Volume stores no encrypted content (clear-text metadata + data).
    pub const UNENCRYPTED: u64 = 0x1;
}

/// `apfs_incompatible_features` bits we interpret.
pub(crate) mod incompat {
    pub const CASE_INSENSITIVE: u64 = 0x1;
    pub const NORMALIZATION_INSENSITIVE: u64 = 0x8;
    /// Sealed (integrity-protected) volume — iOS/macOS system volumes.
    pub const SEALED_VOLUME: u64 = 0x20;
}

/// Directory-record key layout selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrecLayout {
    /// `j_drec_key_t` — plain `u16 name_len` + name.
    Plain,
    /// `j_drec_hashed_key_t` — `u32 name_len_and_hash` + name.
    Hashed,
}

/// A parsed volume superblock.
#[derive(Debug, Clone)]
pub(crate) struct Apsb {
    pub hdr: ObjHdr,
    /// Absolute byte offset of the object.
    pub disk_offset: u64,
    /// `apfs_fs_index` — this volume's slot in `nx_fs_oid[]`.
    pub fs_index: u32,
    pub features: u64,
    pub ro_compat: u64,
    pub incompat: u64,
    /// `apfs_unmount_time` (ns since epoch; 0 = unclean).
    pub unmount_time: i64,
    pub alloc_count: u64,
    /// `apfs_root_tree_type` — expected `OBJECT_TYPE_FSTREE|OBJ_VIRTUAL`.
    pub root_tree_type: u32,
    /// `apfs_omap_oid` — physical block number of the volume's omap object.
    pub omap_oid: u64,
    /// `apfs_root_tree_oid` — virtual oid of the file-system B-tree root.
    pub root_tree_oid: u64,
    /// `apfs_extentref_tree_oid` — physical block of the extent-ref tree.
    pub extentref_tree_oid: u64,
    /// `apfs_snap_meta_tree_oid` — physical block of the snapshot-metadata
    /// tree (0 when absent).
    pub snap_meta_tree_oid: u64,
    pub num_files: u64,
    pub num_directories: u64,
    pub num_symlinks: u64,
    pub num_other: u64,
    pub num_snapshots: u64,
    /// `apfs_vol_uuid` (big-endian bytes → UUID string).
    pub uuid: String,
    /// `apfs_last_mod_time`.
    pub last_mod_time: i64,
    /// `apfs_fs_flags`.
    pub fs_flags: u64,
    /// `apfs_volname` (NUL-terminated UTF-8, 256 bytes).
    pub name: String,
    /// `apfs_meta_crypto` — nonzero wrapped crypto state ⇒ volume keybag in
    /// use (FileVault). We keep the raw flag, never the keys.
    pub meta_crypto_nonzero: bool,
}

impl Apsb {
    /// Parse a volume superblock block read at `off`. The caller has already
    /// verified the Fletcher-64 checksum.
    pub(crate) fn parse(block: &[u8], off: u64) -> Result<Self> {
        let hdr = ObjHdr::parse(block, off, false)?;
        if hdr.type_code() != otype::FS {
            return Err(FsError::corrupt(
                off + 24,
                format!("o_type {:#x} is not a volume superblock", hdr.otype),
            ));
        }
        if le::u32(block, 32) != Some(APFS_MAGIC) {
            return Err(FsError::corrupt(off + 32, "missing APSB magic"));
        }
        let name = le::get(block, 704, 256)
            .map(|raw| {
                let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                String::from_utf8_lossy(&raw[..end]).into_owned()
            })
            .unwrap_or_default();
        let meta_crypto_nonzero = le::get(block, 96, 20)
            .map(|c| c.iter().any(|&b| b != 0))
            .unwrap_or(false);
        Ok(Apsb {
            hdr,
            disk_offset: off,
            fs_index: le::u32(block, 36).unwrap_or(0),
            features: le::u64(block, 40).unwrap_or(0),
            ro_compat: le::u64(block, 48).unwrap_or(0),
            incompat: le::u64(block, 56).unwrap_or(0),
            unmount_time: le::u64(block, 64).unwrap_or(0) as i64,
            alloc_count: le::u64(block, 88).unwrap_or(0),
            root_tree_type: le::u32(block, 116).unwrap_or(0),
            omap_oid: le::u64(block, 128).unwrap_or(0),
            root_tree_oid: le::u64(block, 136).unwrap_or(0),
            extentref_tree_oid: le::u64(block, 144).unwrap_or(0),
            snap_meta_tree_oid: le::u64(block, 152).unwrap_or(0),
            num_files: le::u64(block, 184).unwrap_or(0),
            num_directories: le::u64(block, 192).unwrap_or(0),
            num_symlinks: le::u64(block, 200).unwrap_or(0),
            num_other: le::u64(block, 208).unwrap_or(0),
            num_snapshots: le::u64(block, 216).unwrap_or(0),
            uuid: uuid_be(block, 240).unwrap_or_default(),
            last_mod_time: le::u64(block, 256).unwrap_or(0) as i64,
            fs_flags: le::u64(block, 264).unwrap_or(0),
            name,
            meta_crypto_nonzero,
        })
    }

    /// `true` when the volume is FileVault-class encrypted (no UNENCRYPTED
    /// flag, or a wrapped volume crypto state is present). We never decrypt;
    /// this drives `meta["encrypted"]`/`meta["extent_encrypted"]` and the
    /// reader yields raw ciphertext.
    pub(crate) fn is_encrypted(&self) -> bool {
        self.fs_flags & fs_flags::UNENCRYPTED == 0 || self.meta_crypto_nonzero
    }

    /// `true` for sealed (integrity-protected) volumes.
    pub(crate) fn is_sealed(&self) -> bool {
        self.incompat & incompat::SEALED_VOLUME != 0
    }

    /// Directory-record key layout used by this volume.
    pub(crate) fn drec_layout(&self) -> DrecLayout {
        if self.incompat & (incompat::CASE_INSENSITIVE | incompat::NORMALIZATION_INSENSITIVE) != 0 {
            DrecLayout::Hashed
        } else {
            DrecLayout::Plain
        }
    }
}
