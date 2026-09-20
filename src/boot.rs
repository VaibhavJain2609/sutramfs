//! NTFS boot sector / BIOS Parameter Block (BPB) parsing and detection.
//!
//! The NTFS boot sector occupies the first sector of the volume. The
//! forensically load-bearing fields are the `$MFT` / `$MFTMirr` logical
//! cluster numbers and the (signed) clusters-per-record fields that size
//! MFT FILE records and INDX index records.

use sutram_fs::{DetectConfidence, FsError, Result};
use sutram_io::le;
use sutram_io::ByteSource;

/// OEM identifier every genuine NTFS volume carries at offset 3.
pub(crate) const OEM_NTFS: &[u8; 8] = b"NTFS    ";

/// Parsed and sanity-checked NTFS boot sector.
#[derive(Debug, Clone)]
pub(crate) struct BootSector {
    /// Bytes per sector (512…4096, power of two).
    pub bytes_per_sector: u64,
    /// Sectors per cluster.
    pub sectors_per_cluster: u64,
    /// Bytes per allocation unit.
    pub cluster_size: u64,
    /// Total sectors of the volume (BNF field at 0x28).
    pub total_sectors: u64,
    /// Logical cluster number of the first $MFT cluster.
    pub mft_lcn: u64,
    /// Logical cluster number of $MFTMirr.
    pub mft_mirr_lcn: u64,
    /// Bytes per MFT (FILE) record — typically 1024.
    pub file_record_size: u64,
    /// Bytes per INDX index record — typically 4096.
    pub index_record_size: u64,
    /// Volume serial number (8 bytes at 0x48).
    pub serial: u64,
    /// Total clusters of the volume.
    pub total_clusters: u64,
}

impl BootSector {
    /// Parse and validate the boot sector at offset 0.
    ///
    /// Firmer than [`detect`]: a nonsense BPB is `Corrupt`, not a low
    /// confidence score.
    pub fn parse(src: &dyn ByteSource) -> Result<Self> {
        let b = src.read_slice(0, 512).map_err(FsError::Io)?;
        if b.len() < 512 {
            return Err(FsError::truncated(0, 512, b.len() as u64));
        }
        if &b[3..11] != OEM_NTFS {
            return Err(FsError::corrupt(3, "missing \"NTFS    \" OEM identifier"));
        }
        if b[510] != 0x55 || b[511] != 0xAA {
            return Err(FsError::corrupt(510, "missing 0x55AA boot signature"));
        }
        let bps = le::u16(&b, 11).unwrap_or(0) as u64;
        if !matches!(bps, 512 | 1024 | 2048 | 4096) {
            return Err(FsError::corrupt(11, format!("bad bytes/sector {bps}")));
        }
        let spc = le::u8(&b, 13).unwrap_or(0) as u64;
        // NTFS allows 0 here on >4KiB-sector volumes (encoded differently);
        // we require a nonzero power of two like every shipping volume.
        if spc == 0 || !spc.is_power_of_two() || spc > 128 {
            return Err(FsError::corrupt(13, format!("bad sectors/cluster {spc}")));
        }
        let total_sectors = le::u64(&b, 40).unwrap_or(0);
        if total_sectors == 0 {
            return Err(FsError::corrupt(40, "zero total sectors"));
        }
        let cluster_size = bps * spc;
        let total_clusters = total_sectors / spc;
        let mft_lcn = le::u64(&b, 48).unwrap_or(0);
        let mft_mirr_lcn = le::u64(&b, 56).unwrap_or(0);
        if mft_lcn == 0 || mft_lcn >= total_clusters {
            return Err(FsError::corrupt(
                48,
                format!("$MFT LCN {mft_lcn} out of range ({total_clusters} clusters)"),
            ));
        }
        // Clusters-per-record fields are *signed*: positive = that many
        // clusters, negative = record size is 2^|v| bytes.
        let file_record_size =
            Self::record_size(le::u8(&b, 64).unwrap_or(0) as i8, cluster_size)
                .ok_or_else(|| FsError::corrupt(64, "bad clusters-per-MFT-record"))?;
        let index_record_size =
            Self::record_size(le::u8(&b, 68).unwrap_or(0) as i8, cluster_size)
                .ok_or_else(|| FsError::corrupt(68, "bad clusters-per-index-record"))?;
        if file_record_size < bps || file_record_size > 0x1_0000 {
            return Err(FsError::corrupt(
                64,
                format!("implausible MFT record size {file_record_size}"),
            ));
        }
        let serial = le::u64(&b, 72).unwrap_or(0);
        Ok(BootSector {
            bytes_per_sector: bps,
            sectors_per_cluster: spc,
            cluster_size,
            total_sectors,
            mft_lcn,
            mft_mirr_lcn,
            file_record_size,
            index_record_size,
            serial,
            total_clusters,
        })
    }

    /// Decode a signed clusters-per-record byte: `v > 0` → `v` clusters;
    /// `v < 0` → `2^|v|` bytes.
    fn record_size(v: i8, cluster_size: u64) -> Option<u64> {
        if v > 0 {
            Some(v as u64 * cluster_size)
        } else if v < 0 {
            1u64.checked_shl((-v) as u32)
        } else {
            None
        }
    }

    /// Detection confidence for an NTFS-looking sector.
    ///
    /// The OEM string is authoritative for NTFS (nothing else legitimately
    /// carries it); structural checks raise the score to `Certain`.
    pub fn detect(src: &dyn ByteSource) -> DetectConfidence {
        let b = match src.read_slice(0, 512) {
            Ok(b) if b.len() >= 512 => b,
            _ => return DetectConfidence::None,
        };
        if &b[3..11] != OEM_NTFS {
            return DetectConfidence::None;
        }
        if b[510] != 0x55 || b[511] != 0xAA {
            return DetectConfidence::Low;
        }
        let mut score = 0u32;
        if matches!(b[0], 0xEB | 0xE9) {
            score += 1; // x86 jump
        }
        if matches!(le::u16(&b, 11), Some(512 | 1024 | 2048 | 4096)) {
            score += 1;
        }
        let spc = b[13];
        if spc != 0 && spc.is_power_of_two() && spc <= 128 {
            score += 1;
        }
        // BPB fields that NTFS always zeroes (FAT leftovers must be 0).
        if le::u16(&b, 14) == Some(0) && le::u16(&b, 22) == Some(0) && b[16] == 0 {
            score += 1;
        }
        if le::u64(&b, 40).unwrap_or(0) > 0 {
            score += 1;
        }
        if le::u64(&b, 48).unwrap_or(0) > 0 {
            score += 1;
        }
        if BootSector::parse(src).is_ok() {
            score += 2;
        }
        match score {
            0..=2 => DetectConfidence::Low,
            3..=4 => DetectConfidence::Medium,
            5..=6 => DetectConfidence::High,
            _ => DetectConfidence::Certain,
        }
    }
}
