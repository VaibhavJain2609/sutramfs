//! XFS superblock and allocation-group headers (AGF/AGI/AGFL).
//!
//! **All multi-byte fields on XFS metadata are big-endian** — every decode
//! here goes through `be16`/`be32`/`be64` (explicit `from_be_bytes`), never
//! host-endian reads. The single exception is the CRC field itself, which
//! is stored little-endian on disk even in v5 (`xfs_cksum.h`).

use sutram_fs::{DetectConfidence, FsError, Result};
use sutram_io::le::{u16_be, u32_be, u64_be};
use sutram_io::ByteSource;

use crate::crc;

/// "XFSB" — superblock magic at offset 0 of every AG.
pub(crate) const SB_MAGIC: u32 = 0x5846_5342;
/// "XAGF" — free-space header at sector 1 of every AG.
pub(crate) const AGF_MAGIC: u32 = 0x5841_4746;
/// "XAGI" — inode header at sector 2 of every AG.
pub(crate) const AGI_MAGIC: u32 = 0x5841_4749;
/// "XAFL" — v5 AG free-list header at sector 3 of every AG.
pub(crate) const AGFL_MAGIC: u32 = 0x5841_464C;

/// sb_features_ro_compat bits (v5).
pub(crate) const FEAT_RO_FINOBT: u32 = 1 << 0;
#[allow(dead_code)]
pub(crate) const FEAT_RO_RMAPBT: u32 = 1 << 1;
#[allow(dead_code)]
pub(crate) const FEAT_RO_REFLINK: u32 = 1 << 2;
#[allow(dead_code)]
pub(crate) const FEAT_RO_INOBTCNT: u32 = 1 << 3;
/// sb_features_incompat bits (v5).
pub(crate) const FEAT_INC_FTYPE: u32 = 1 << 0;
pub(crate) const FEAT_INC_SPINODES: u32 = 1 << 1;
#[allow(dead_code)]
pub(crate) const FEAT_INC_META_UUID: u32 = 1 << 2;
pub(crate) const FEAT_INC_BIGTIME: u32 = 1 << 3;

/// sb_versionnum low bits = format version.
const VERSION_NUMBITS: u16 = 0x000F;
/// XFS_SB_VERSION2_CRCBIT — v4 filesystems with metadata CRCs.
const FEAT2_CRC: u32 = 0x0000_0100;
/// XFS_SB_VERSION2_FTYPE — filetype byte in dirents (v4 feature2 word).
const FEAT2_FTYPE: u32 = 0x0000_0200;


/// 64 inodes per inobt chunk record.
pub(crate) const INODES_PER_CHUNK: u32 = 64;

/// Parsed primary superblock (AG 0).
#[derive(Debug, Clone)]
pub(crate) struct Superblock {
    /// sb_versionnum low nibble (4 or 5 typically).
    pub version: u16,
    /// Raw sb_versionnum (incl. feature bits) — reported in FsInfo.
    pub versionnum: u16,
    /// sb_blocksize.
    pub blocksize: u32,
    /// sb_dblocks — total filesystem blocks.
    pub dblocks: u64,
    /// sb_rblocks — realtime device blocks.
    pub rblocks: u64,
    /// sb_uuid (16 raw bytes).
    pub uuid: [u8; 16],
    /// sb_logstart — fsblock of internal log; 0 = external/none.
    pub logstart: u64,
    /// sb_rootino — root directory inode.
    pub rootino: u64,
    /// sb_agblocks — blocks per allocation group.
    pub agblocks: u32,
    /// sb_agcount — number of allocation groups.
    pub agcount: u32,
    /// sb_logblocks — internal log length in blocks.
    pub logblocks: u32,
    /// sb_sectsize — sector size (bytes); AG headers are sector-sized.
    pub sectsize: u16,
    /// sb_inodesize — bytes per on-disk inode.
    pub inodesize: u16,
    /// sb_inopblock — inodes per block.
    pub inopblock: u16,
    /// sb_fname — volume label (12 bytes, not NUL-terminated).
    pub label: String,
    /// sb_blocklog — log2(blocksize).
    pub blocklog: u8,
    /// sb_sectlog — log2(sectsize).
    pub sectlog: u8,
    /// sb_inodelog — log2(inodesize).
    #[allow(dead_code)]
    pub inodelog: u8,
    /// sb_inopblog — log2(inopblock).
    pub inopblog: u8,
    /// sb_agblklog — log2(agblocks) rounded up.
    pub agblklog: u8,
    /// sb_inprogress — mkfs interrupted if set.
    pub inprogress: bool,
    /// sb_icount — allocated inode count.
    pub icount: u64,
    /// sb_ifree — free inode count.
    pub ifree: u64,
    /// sb_fdblocks — free data blocks.
    pub fdblocks: u64,
    /// sb_dirblklog — log2(directory block size in fs blocks).
    pub dirblklog: u8,
    /// sb_features2.
    pub features2: u32,
    /// sb_features_compat (v5).
    pub features_compat: u32,
    /// sb_features_ro_compat (v5).
    pub features_ro_compat: u32,
    /// sb_features_incompat (v5).
    pub features_incompat: u32,
    /// sb_features_log_incompat (v5).
    pub features_log_incompat: u32,
    /// sb_lsn — last log write sequence (v5).
    pub lsn: u64,
    /// sb_meta_uuid (v5; the uuid stamped into metadata blocks).
    pub meta_uuid: [u8; 16],
    /// Result of the v5 CRC check on the primary superblock.
    pub crc_ok: Option<bool>,
}

impl Superblock {
    /// v5 filesystem (CRC-enabled, dir3 blocks, v3 inodes).
    pub fn is_v5(&self) -> bool {
        self.version == 5
    }

    /// Metadata blocks carry CRCs (v5 always; v4 only with CRCBIT).
    pub fn has_crc(&self) -> bool {
        self.is_v5() || (self.features2 & FEAT2_CRC) != 0
    }

    /// Dirents carry a file-type byte (dir3/attr3 shapes).
    pub fn has_ftype(&self) -> bool {
        if self.is_v5() {
            (self.features_incompat & FEAT_INC_FTYPE) != 0
        } else {
            (self.features2 & FEAT2_FTYPE) != 0
        }
    }

    /// Free-inode btree (finobt) is live.
    pub fn has_finobt(&self) -> bool {
        self.is_v5() && (self.features_ro_compat & FEAT_RO_FINOBT) != 0
    }

    /// Sparse inode chunks are permitted (changes inobt record layout).
    pub fn has_spinodes(&self) -> bool {
        self.is_v5() && (self.features_incompat & FEAT_INC_SPINODES) != 0
    }

    /// Large (bigtime) timestamps.
    pub fn has_bigtime(&self) -> bool {
        self.is_v5() && (self.features_incompat & FEAT_INC_BIGTIME) != 0
    }

    /// Bits in an AG-relative inode number: agblklog + inopblog.
    pub fn agino_bits(&self) -> u32 {
        self.agblklog as u32 + self.inopblog as u32
    }

    /// Directory block size in bytes (blocksize << dirblklog).
    pub fn dirbsize(&self) -> u64 {
        (self.blocksize as u64) << self.dirblklog
    }

    /// Byte offset of the start of AG `agno`.
    pub fn ag_off(&self, agno: u32) -> u64 {
        agno as u64 * self.agblocks as u64 * self.blocksize as u64
    }

    /// Byte offset of fs block `fsb`.
    pub fn fsb_off(&self, fsb: u64) -> u64 {
        fsb * self.blocksize as u64
    }

    /// AG number containing fs block `fsb`.
    pub fn fsb_agno(&self, fsb: u64) -> u32 {
        (fsb >> self.agblklog) as u32
    }

    /// AG-relative block number of `fsb`.
    pub fn fsb_agbno(&self, fsb: u64) -> u32 {
        (fsb & ((1u64 << self.agblklog) - 1)) as u32
    }

    /// AG number of an inode number.
    pub fn ino_agno(&self, ino: u64) -> u32 {
        (ino >> self.agino_bits()) as u32
    }

    /// AG-relative inode number.
    pub fn ino_agino(&self, ino: u64) -> u32 {
        (ino & ((1u64 << self.agino_bits()) - 1)) as u32
    }

    /// AG-relative block of the inode's chunk.
    pub fn ino_agbno(&self, ino: u64) -> u32 {
        self.ino_agino(ino) >> self.inopblog
    }

    /// Slot of the inode inside its block.
    pub fn ino_offset(&self, ino: u64) -> u32 {
        self.ino_agino(ino) & (self.inopblock as u32 - 1)
    }

    /// Absolute byte offset of inode `ino`'s dinode record.
    pub fn ino_off(&self, ino: u64) -> u64 {
        let base = self.ag_off(self.ino_agno(ino))
            + self.ino_agbno(ino) as u64 * self.blocksize as u64;
        base + self.ino_offset(ino) as u64 * self.inodesize as u64
    }

    /// True when `ino` decodes to a plausible location.
    pub fn ino_valid(&self, ino: u64) -> bool {
        ino != 0
            && self.ino_agno(ino) < self.agcount
            && self.ino_agbno(ino) < self.agblocks
    }

    /// Read and validate the primary superblock (mount-time strictness).
    pub fn parse(src: &dyn ByteSource) -> Result<Self> {
        let buf = src.read_slice(0, 512).map_err(FsError::Io)?;
        if buf.len() < 512 {
            return Err(FsError::truncated(0, 512, buf.len() as u64));
        }
        Self::parse_buf(&buf, 0).and_then(|sb| sb.validate(src))
    }

    /// Decode the 512-byte superblock body at `off` (0 for AG 0; the
    /// structure is sector-sized and all offsets are fixed).
    pub(crate) fn parse_buf(b: &[u8], off: u64) -> Result<Self> {
        let magic = u32_be(b, 0).unwrap_or(0);
        if magic != SB_MAGIC {
            return Err(FsError::corrupt(off, "bad superblock magic (want XFSB)"));
        }
        let versionnum = u16_be(b, 100).unwrap_or(0);
        let version = versionnum & VERSION_NUMBITS;
        if !(4..=5).contains(&version) {
            return Err(FsError::unsupported(format!(
                "XFS superblock version {version}"
            )));
        }
        let blocksize = u32_be(b, 4).unwrap_or(0);
        if !(512..=65536).contains(&blocksize) || !blocksize.is_power_of_two() {
            return Err(FsError::corrupt(
                off + 4,
                format!("bad blocksize {blocksize}"),
            ));
        }
        let sectsize = u16_be(b, 102).unwrap_or(0);
        if !(512..=32768).contains(&sectsize)
            || !sectsize.is_power_of_two()
            || sectsize as u32 > blocksize
        {
            return Err(FsError::corrupt(off + 102, format!("bad sectsize {sectsize}")));
        }
        let inodesize = u16_be(b, 104).unwrap_or(0);
        if !(256..=2048).contains(&inodesize) || !inodesize.is_power_of_two() {
            return Err(FsError::corrupt(
                off + 104,
                format!("bad inodesize {inodesize}"),
            ));
        }
        let inopblock = u16_be(b, 106).unwrap_or(0);
        if inopblock == 0 || !inopblock.is_power_of_two() {
            return Err(FsError::corrupt(
                off + 106,
                format!("bad inopblock {inopblock}"),
            ));
        }
        let agblocks = u32_be(b, 84).unwrap_or(0);
        let agcount = u32_be(b, 88).unwrap_or(0);
        let dblocks = u64_be(b, 8).unwrap_or(0);
        if agblocks == 0 || agcount == 0 || dblocks == 0 {
            return Err(FsError::corrupt(
                off + 8,
                format!("impossible geometry: dblocks={dblocks} agblocks={agblocks} agcount={agcount}"),
            ));
        }
        let blocklog = b[120];
        if blocklog as u32 != blocksize.trailing_zeros() {
            return Err(FsError::corrupt(
                off + 120,
                format!("blocklog {blocklog} inconsistent with blocksize {blocksize}"),
            ));
        }
        let inopblog = b[123];
        if inopblog as u32 != inopblock.trailing_zeros() {
            return Err(FsError::corrupt(
                off + 123,
                format!("inopblog {inopblog} inconsistent with inopblock {inopblock}"),
            ));
        }
        let agblklog = b[124];
        // agblklog = ceil(log2(agblocks)); enforce a sane bound.
        if agblklog > 31
            || agblocks as u64 > (1u64 << agblklog)
            || (agblklog > 0 && agblocks as u64 <= (1u64 << (agblklog - 1)))
        {
            return Err(FsError::corrupt(
                off + 124,
                format!("agblklog {agblklog} inconsistent with agblocks {agblocks}"),
            ));
        }
        if inopblock as u32 != blocksize / inodesize as u32 {
            return Err(FsError::corrupt(
                off + 106,
                "inopblock != blocksize/inodesize",
            ));
        }
        // Last AG may be short: dblocks >= (agcount-1)*agblocks + 1.
        if (agcount as u64 - 1) * agblocks as u64 >= dblocks {
            return Err(FsError::corrupt(
                off + 88,
                format!("agcount {agcount} exceeds dblocks {dblocks}/agblocks {agblocks}"),
            ));
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&b[32..48]);
        let mut meta_uuid = [0u8; 16];
        meta_uuid.copy_from_slice(&b[248..264]);
        let mut label_raw = [0u8; 12];
        label_raw.copy_from_slice(&b[108..120]);
        let label = String::from_utf8_lossy(&label_raw)
            .trim_end_matches('\0')
            .to_string();

        Ok(Superblock {
            version,
            versionnum,
            blocksize,
            dblocks,
            rblocks: u64_be(b, 16).unwrap_or(0),
            uuid,
            logstart: u64_be(b, 48).unwrap_or(0),
            rootino: u64_be(b, 56).unwrap_or(0),
            agblocks,
            agcount,
            logblocks: u32_be(b, 96).unwrap_or(0),
            sectsize,
            inodesize,
            inopblock,
            label,
            blocklog,
            sectlog: b[121],
            inodelog: b[122],
            inopblog,
            agblklog,
            inprogress: b[126] != 0,
            icount: u64_be(b, 128).unwrap_or(0),
            ifree: u64_be(b, 136).unwrap_or(0),
            fdblocks: u64_be(b, 144).unwrap_or(0),
            dirblklog: b[192],
            features2: u32_be(b, 200).unwrap_or(0),
            features_compat: u32_be(b, 208).unwrap_or(0),
            features_ro_compat: u32_be(b, 212).unwrap_or(0),
            features_incompat: u32_be(b, 216).unwrap_or(0),
            features_log_incompat: u32_be(b, 220).unwrap_or(0),
            lsn: u64_be(b, 240).unwrap_or(0),
            meta_uuid,
            crc_ok: None,
        })
    }

    /// Second-stage validation needing the actual source (bounds, CRC).
    fn validate(mut self, src: &dyn ByteSource) -> Result<Self> {
        let fs_bytes = self.dblocks * self.blocksize as u64;
        if src.len() < self.blocksize as u64 {
            return Err(FsError::truncated(0, self.blocksize as u64, src.len()));
        }
        // A truncated last AG is fine (Lenient), but AG0 must be readable.
        if !self.ino_valid(self.rootino) {
            return Err(FsError::corrupt(
                56,
                format!("root inode {:#x} out of geometry", self.rootino),
            ));
        }
        if self.sectlog as u32 != self.sectsize.trailing_zeros()
            || self.inodelog as u32 != self.inodesize.trailing_zeros()
        {
            return Err(FsError::corrupt(
                121,
                "sectlog/inodelog inconsistent with sectsize/inodesize",
            ));
        }
        if self.is_v5() {
            // CRC covers one sector; bytes past the image are zero-padded
            // only for length purposes — read what exists.
            let need = self.sectsize as usize;
            let buf = src.read_slice(0, need).map_err(FsError::Io)?;
            if buf.len() < need {
                return Err(FsError::truncated(0, need as u64, buf.len() as u64));
            }
            let stored = u32::from_le_bytes([buf[224], buf[225], buf[226], buf[227]]);
            self.crc_ok = crc::verify(&buf, 224, stored);
        }
        let _ = fs_bytes;
        Ok(self)
    }

    /// `detect()` confidence — cheap, never panics, reads only 512 B.
    pub fn detect(src: &dyn ByteSource) -> DetectConfidence {
        let b = match src.read_slice(0, 512) {
            Ok(b) if b.len() >= 512 => b,
            _ => return DetectConfidence::None,
        };
        if u32_be(&b, 0) != Some(SB_MAGIC) {
            return DetectConfidence::None;
        }
        let mut score = 0u32;
        let version = u16_be(&b, 100).unwrap_or(0) & VERSION_NUMBITS;
        if version == 4 || version == 5 {
            score += 2;
        }
        let blocksize = u32_be(&b, 4).unwrap_or(0);
        if (512..=65536).contains(&blocksize) && blocksize.is_power_of_two() {
            score += 1;
        }
        let sectsize = u16_be(&b, 102).unwrap_or(0);
        if sectsize.is_power_of_two() && (512..=32768).contains(&sectsize) {
            score += 1;
        }
        let inodesize = u16_be(&b, 104).unwrap_or(0);
        let inopblock = u16_be(&b, 106).unwrap_or(0);
        if (256..=2048).contains(&inodesize)
            && inodesize.is_power_of_two()
            && blocksize != 0
            && inopblock as u32 == blocksize / inodesize as u32
        {
            score += 1;
        }
        if b[120] as u32 == blocksize.trailing_zeros()
            && b[121] as u32 == sectsize.trailing_zeros()
        {
            score += 1;
        }
        let agblocks = u32_be(&b, 84).unwrap_or(0) as u64;
        let agcount = u32_be(&b, 88).unwrap_or(0) as u64;
        let dblocks = u64_be(&b, 8).unwrap_or(0);
        // Last AG may be short: (agcount-1)*agblocks < dblocks <=
        // agcount*agblocks.
        if agblocks > 0
            && agcount > 0
            && dblocks > (agcount - 1) * agblocks
            && dblocks <= agblocks.saturating_mul(agcount)
        {
            score += 2;
        }
        // v5 superblock CRC is a hard proof when it verifies.
        if version == 5 {
            let stored = u32::from_le_bytes([b[224], b[225], b[226], b[227]]);
            if crc::verify(&b, 224, stored) == Some(true) {
                score += 2;
            }
        }
        match score {
            0..=3 => DetectConfidence::Low,
            4..=6 => DetectConfidence::Medium,
            7..=8 => DetectConfidence::High,
            _ => DetectConfidence::Certain,
        }
    }
}

/// One AG's parsed headers + discovered indexes.
#[derive(Debug, Clone)]
pub(crate) struct Agf {
    /// agf_seqno — kept for completeness/forensic reporting.
    #[allow(dead_code)]
    pub seqno: u32,
    /// agf_length (blocks covered by this AG).
    #[allow(dead_code)]
    pub length: u32,
    /// roots[0]=bnobt, [1]=cntbt, [2]=rmapbt (0 when absent).
    pub roots: [u32; 3],
    pub levels: [u32; 3],
    pub freeblks: u32,
    /// Longest free extent — kept for completeness.
    #[allow(dead_code)]
    pub longest: u32,
    pub crc_ok: Option<bool>,
}

#[derive(Debug, Clone)]
pub(crate) struct Agi {
    /// agi_count (allocated inode count) — kept for completeness.
    #[allow(dead_code)]
    pub count: u32,
    pub root: u32,
    pub level: u32,
    pub freecount: u32,
    /// finobt root/level (v5 ro_compat); 0 when feature absent.
    pub free_root: u32,
    pub free_level: u32,
    /// Unlinked-inode hash buckets (agino values, NULLAGINO terminated).
    pub unlinked: Vec<u32>,
    pub crc_ok: Option<bool>,
}

pub(crate) const NULLAGINO: u32 = u32::MAX;
pub(crate) const NULLAGBLOCK: u32 = u32::MAX;
pub(crate) const NULLFSBLOCK: u64 = u64::MAX;

impl Agf {
    pub fn parse(b: &[u8], off: u64, crc: bool) -> Result<Self> {
        if b.len() < 224 {
            return Err(FsError::truncated(off, 224, b.len() as u64));
        }
        if u32_be(b, 0) != Some(AGF_MAGIC) {
            return Err(FsError::corrupt(off, "bad AGF magic (want XAGF)"));
        }
        if u32_be(b, 4).unwrap_or(0) != 1 {
            return Err(FsError::corrupt(off + 4, "bad AGF version"));
        }
        let crc_ok = if crc {
            // agf_crc is __be32 — unlike sb/inode/btree crcs (le32).
            let stored = u32::from_be_bytes([b[216], b[217], b[218], b[219]]);
            crc::verify(&b[..b.len().min(512)], 216, stored)
        } else {
            None
        };
        Ok(Agf {
            seqno: u32_be(b, 8).unwrap_or(0),
            length: u32_be(b, 12).unwrap_or(0),
            roots: [
                u32_be(b, 16).unwrap_or(0),
                u32_be(b, 20).unwrap_or(0),
                u32_be(b, 24).unwrap_or(0),
            ],
            levels: [
                u32_be(b, 28).unwrap_or(0),
                u32_be(b, 32).unwrap_or(0),
                u32_be(b, 36).unwrap_or(0),
            ],
            freeblks: u32_be(b, 52).unwrap_or(0),
            longest: u32_be(b, 56).unwrap_or(0),
            crc_ok,
        })
    }
}

impl Agi {
    pub fn parse(b: &[u8], off: u64, crc: bool) -> Result<Self> {
        if b.len() < 336 {
            return Err(FsError::truncated(off, 336, b.len() as u64));
        }
        if u32_be(b, 0) != Some(AGI_MAGIC) {
            return Err(FsError::corrupt(off, "bad AGI magic (want XAGI)"));
        }
        if u32_be(b, 4).unwrap_or(0) != 1 {
            return Err(FsError::corrupt(off + 4, "bad AGI version"));
        }
        let mut unlinked = Vec::with_capacity(64);
        for i in 0..64 {
            unlinked.push(u32_be(b, 40 + i * 4).unwrap_or(NULLAGINO));
        }
        let crc_ok = if crc {
            // agi_crc is __be32 — unlike sb/inode/btree crcs (le32).
            let stored = u32::from_be_bytes([b[312], b[313], b[314], b[315]]);
            crc::verify(&b[..b.len().min(512)], 312, stored)
        } else {
            None
        };
        Ok(Agi {
            count: u32_be(b, 16).unwrap_or(0),
            root: u32_be(b, 20).unwrap_or(0),
            level: u32_be(b, 24).unwrap_or(0),
            freecount: u32_be(b, 28).unwrap_or(0),
            free_root: u32_be(b, 328).unwrap_or(0),
            free_level: u32_be(b, 332).unwrap_or(0),
            unlinked,
            crc_ok,
        })
    }
}
