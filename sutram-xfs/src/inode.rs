//! On-disk inode (`xfs_dinode`) decoding — v1/v2 (100-byte core) and v3
//! (176-byte core, CRC + creation time + inode number + uuid).
//!
//! Field offsets follow `xfs_format.h`; all multi-byte fields are
//! big-endian except `di_crc`, which is stored little-endian.
//!
//! ```text
//!  0  di_magic u16      'IN' (0x494e)
//!  2  di_mode u16
//!  4  di_version u8      1|2 = old core, 3 = v5 core
//!  5  di_format u8       0 dev, 1 local, 2 extents, 3 btree, 4 uuid
//!  6  di_onlink u16      (v1 link count)
//!  8  di_uid u32
//! 12  di_gid u32
//! 16  di_nlink u32       (v2+/NLINKBIT)
//! ...
//! 24  di_big_nextents u64 (when DIFLAG2_NREXT64)
//! 32  di_atime  u64  {sec:32, nsec:32}
//! 40  di_mtime  u64
//! 48  di_ctime  u64
//! 56  di_size   u64
//! 64  di_nblocks u64
//! 72  di_extsize u32
//! 76  di_nextents u32
//! 80  di_anextents u16
//! 82  di_forkoff u8      attr fork offset, units of 8 bytes from fork base
//! 83  di_aformat u8
//! 90  di_flags u16
//! 92  di_gen u32
//! 96  di_next_unlinked u32
//! --- v3 only ---
//! 100 di_crc le32        <-- the little-endian exception
//! 104 di_changecount u64
//! 112 di_lsn u64
//! 120 di_flags2 u64      bit3 = bigtime timestamps, bit0 = nrext64
//! 128 di_cowextsize u32
//! 144 di_crtime u64      creation time
//! 152 di_ino u64
//! 160 di_uuid 16 bytes
//! 176 fork data          (v1/v2 forks begin at 100)
//! ```

use sutram_fs::{EntryKind, FsError, Result};
use sutram_io::le::{u16_be, u32_be, u64_be};

use crate::crc;
use crate::sb::Superblock;

pub(crate) const DINODE_MAGIC: u16 = 0x494E; // 'IN'

/// Fork format codes (di_format / di_aformat).
pub(crate) const FMT_DEV: u8 = 0;
pub(crate) const FMT_LOCAL: u8 = 1;
pub(crate) const FMT_EXTENTS: u8 = 2;
pub(crate) const FMT_BTREE: u8 = 3;
#[allow(dead_code)]
pub(crate) const FMT_UUID: u8 = 4;

/// di_flags2 bits.
const DIFLAG2_NREXT64: u64 = 1 << 0;
const DIFLAG2_BIGTIME: u64 = 1 << 3;

/// Core sizes.
const CORE_V12: usize = 100;
const CORE_V3: usize = 176;

/// Bigtime epoch: timestamps count nanoseconds from 1901-12-13, i.e.
/// `unix_ns = raw - 2^31 * 1e9` (XFS_BIGTIME_EPOCH = -S32_MIN seconds).
const BIGTIME_EPOCH_NS: i64 = (1i64 << 31) * 1_000_000_000;

/// Nanoseconds per second.
const NS_PER_SEC: i64 = 1_000_000_000;

#[derive(Debug)]
pub(crate) struct Inode {
    /// Raw inode bytes (inodesize, ≤ 2 KiB — bounded).
    pub buf: Vec<u8>,
    /// Absolute offset of this inode record.
    pub disk_off: u64,
    /// Inode number (di_ino on v3, else derived from disk position).
    pub ino: u64,
    pub mode: u16,
    pub version: u8,
    pub format: u8,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    /// Timestamps as unix nanoseconds.
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub crtime: Option<i64>,
    /// Raw on-disk timestamp values (encoding documented via flags).
    pub atime_raw: u64,
    pub mtime_raw: u64,
    pub ctime_raw: u64,
    pub crtime_raw: Option<u64>,
    pub size: u64,
    pub nblocks: u64,
    pub nextents: u64,
    pub anextents: u16,
    /// Attr fork offset in 8-byte units from fork base; 0 = no attr fork.
    pub forkoff: u8,
    pub aformat: u8,
    pub flags: u16,
    pub gen: u32,
    pub next_unlinked: u32,
    pub flags2: u64,
    pub bigtime: bool,
    /// Result of the v3 inode CRC check.
    pub crc_ok: Option<bool>,
    /// Inode core size (100 or 176).
    pub core: usize,
}

impl Inode {
    /// Decode an inode record held in `buf`.
    ///
    /// `ino_hint` is the expected inode number (used when the record is a
    /// v1/v2 inode that does not carry di_ino). Returns `Corrupt` when the
    /// record does not start with the 'IN' magic.
    pub fn parse(buf: Vec<u8>, off: u64, ino_hint: u64, sb: &Superblock) -> Result<Self> {
        if buf.len() < CORE_V12 {
            return Err(FsError::truncated(off, CORE_V12 as u64, buf.len() as u64));
        }
        if u16_be(&buf, 0) != Some(DINODE_MAGIC) {
            return Err(FsError::corrupt(off, "bad inode magic (want 'IN')"));
        }
        let version = buf[4];
        let is_v3 = version == 3;
        let core = if is_v3 { CORE_V3 } else { CORE_V12 };
        if buf.len() < core {
            return Err(FsError::truncated(off, core as u64, buf.len() as u64));
        }
        let flags2 = if is_v3 {
            u64_be(&buf, 120).unwrap_or(0)
        } else {
            0
        };
        let bigtime = sb.has_bigtime() && (flags2 & DIFLAG2_BIGTIME) != 0;
        let nrext64 = (flags2 & DIFLAG2_NREXT64) != 0;
        let nextents = if nrext64 {
            u64_be(&buf, 24).unwrap_or(0)
        } else {
            u32_be(&buf, 76).unwrap_or(0) as u64
        };
        let atime_raw = u64_be(&buf, 32).unwrap_or(0);
        let mtime_raw = u64_be(&buf, 40).unwrap_or(0);
        let ctime_raw = u64_be(&buf, 48).unwrap_or(0);
        let crtime_raw = if is_v3 {
            Some(u64_be(&buf, 144).unwrap_or(0))
        } else {
            None
        };
        let nlink = if version >= 2 {
            u32_be(&buf, 16).unwrap_or(0)
        } else {
            u16_be(&buf, 6).unwrap_or(0) as u32
        };
        let crc_ok = if is_v3 && sb.has_crc() {
            let stored = u32::from_le_bytes([buf[100], buf[101], buf[102], buf[103]]);
            crc::verify(&buf, 100, stored)
        } else {
            None
        };
        let ino = if is_v3 {
            u64_be(&buf, 152).unwrap_or(ino_hint)
        } else {
            ino_hint
        };
        let mode = u16_be(&buf, 2).unwrap_or(0);
        let format = buf[5];
        let uid = u32_be(&buf, 8).unwrap_or(0);
        let gid = u32_be(&buf, 12).unwrap_or(0);
        let size = u64_be(&buf, 56).unwrap_or(0);
        let nblocks = u64_be(&buf, 64).unwrap_or(0);
        let anextents = u16_be(&buf, 80).unwrap_or(0);
        let forkoff = buf[82];
        let aformat = buf[83];
        let flags = u16_be(&buf, 90).unwrap_or(0);
        let gen = u32_be(&buf, 92).unwrap_or(0);
        let next_unlinked = u32_be(&buf, 96).unwrap_or(0);
        Ok(Inode {
            buf,
            disk_off: off,
            ino,
            mode,
            version,
            format,
            nlink,
            uid,
            gid,
            atime: decode_ts(atime_raw, bigtime),
            mtime: decode_ts(mtime_raw, bigtime),
            ctime: decode_ts(ctime_raw, bigtime),
            crtime: crtime_raw.map(|r| decode_ts(r, bigtime)),
            atime_raw,
            mtime_raw,
            ctime_raw,
            crtime_raw,
            size,
            nblocks,
            nextents,
            anextents,
            forkoff,
            aformat,
            flags,
            gen,
            next_unlinked,
            flags2,
            bigtime,
            crc_ok,
            core,
        })
    }

    /// Entry kind from di_mode.
    pub fn kind(&self) -> EntryKind {
        match self.mode & 0xF000 {
            0x8000 => EntryKind::File,
            0x4000 => EntryKind::Directory,
            0xA000 => EntryKind::Symlink,
            _ => EntryKind::Other,
        }
    }

    /// Bytes available to both forks (the "literal area" past the core).
    pub fn lit(&self) -> &[u8] {
        &self.buf[self.core..]
    }

    /// Data fork byte slice.
    ///
    /// `di_forkoff` gives the attribute fork's start in 8-byte units from
    /// the fork base; when zero the data fork spans the whole literal area.
    pub fn dfork(&self) -> &[u8] {
        let lit = self.lit();
        if self.forkoff == 0 {
            return lit;
        }
        let end = ((self.forkoff as usize) << 3).min(lit.len());
        &lit[..end]
    }

    /// Attribute fork byte slice (None when di_forkoff == 0).
    pub fn afork(&self) -> Option<&[u8]> {
        if self.forkoff == 0 {
            return None;
        }
        let lit = self.lit();
        let start = ((self.forkoff as usize) << 3).min(lit.len());
        Some(&lit[start..])
    }

    /// Whether the record still resembles live metadata — used to skip
    /// fresh (zero-content) free inode slots when scanning finobt/inobt.
    pub fn has_residue(&self) -> bool {
        self.mode != 0
            || self.size != 0
            || self.nextents != 0
            || self.nlink != 0
            || self.atime_raw != 0
            || self.mtime_raw != 0
    }
}

/// Decode an `xfs_timestamp_t` / bigtime stamp into unix nanoseconds.
///
/// Legacy format: be64 = (sec:u32, nsec:u32), sec is signed 32-bit
/// (negative values = pre-epoch). Bigtime: u64 nanoseconds since the
/// 1901 bigtime epoch.
fn decode_ts(raw: u64, bigtime: bool) -> i64 {
    if bigtime {
        return (raw as i64).saturating_sub(BIGTIME_EPOCH_NS);
    }
    let sec = (raw >> 32) as u32 as i32 as i64;
    let nsec = raw & 0xFFFF_FFFF;
    if nsec >= NS_PER_SEC as u64 {
        // Corrupt nsec — clamp rather than propagate nonsense.
        return sec.saturating_mul(NS_PER_SEC);
    }
    sec.saturating_mul(NS_PER_SEC).saturating_add(nsec as i64)
}
