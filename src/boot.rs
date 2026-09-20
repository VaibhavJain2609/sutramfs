//! FAT boot sector / BPB parsing and detection.

use sutram_fs::{DetectConfidence, FsError, Result};
use sutram_io::le;
use sutram_io::ByteSource;

/// FAT variant, classified by cluster count per Microsoft FAT spec
/// (the authoritative method — *not* the FS-type label string).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatType {
    /// Fewer than 4 085 clusters.
    Fat12,
    /// 4 085–65 524 clusters.
    Fat16,
    /// 65 525+ clusters.
    Fat32,
}

impl FatType {
    /// FAT entry width in bits.
    pub fn entry_bits(self) -> u32 {
        match self {
            FatType::Fat12 => 12,
            FatType::Fat16 => 16,
            FatType::Fat32 => 32,
        }
    }

    /// Cluster values ≥ this mark end-of-chain.
    pub fn eoc(self) -> u32 {
        match self {
            FatType::Fat12 => 0x0FF8,
            FatType::Fat16 => 0xFFF8,
            FatType::Fat32 => 0x0FFF_FFF8,
        }
    }

    /// Cluster value marking a bad cluster.
    pub fn bad(self) -> u32 {
        match self {
            FatType::Fat12 => 0x0FF7,
            FatType::Fat16 => 0xFFF7,
            FatType::Fat32 => 0x0FFF_FFF7,
        }
    }

    /// Mask applied to a raw FAT slot.
    pub fn mask(self) -> u32 {
        match self {
            FatType::Fat12 => 0x0FFF,
            FatType::Fat16 => 0xFFFF,
            FatType::Fat32 => 0x0FFF_FFFF,
        }
    }

    /// Name for reports.
    pub fn name(self) -> &'static str {
        match self {
            FatType::Fat12 => "FAT12",
            FatType::Fat16 => "FAT16",
            FatType::Fat32 => "FAT32",
        }
    }
}

/// Parsed and sanity-checked boot sector.
#[derive(Debug, Clone)]
pub(crate) struct BootSector {
    pub bytes_per_sector: u64,
    pub sectors_per_cluster: u64,
    pub reserved_sectors: u64,
    pub num_fats: u32,
    pub root_entry_count: u32,
    pub total_sectors: u64,
    pub media: u8,
    pub fat_size_sectors: u64,
    /// FAT32 root directory start cluster (0 for FAT12/16).
    pub root_cluster: u32,
    pub fat_type: FatType,
    /// Byte offset of the first FAT.
    pub fat_offset: u64,
    /// Byte offset/size of the fixed root-dir region (FAT12/16 only).
    pub root_dir_offset: u64,
    pub root_dir_size: u64,
    /// Byte offset of cluster 2 (first data cluster).
    pub data_offset: u64,
    /// Data cluster count (drives the FAT12/16/32 classification).
    pub count_of_clusters: u64,
    /// Bytes per cluster.
    pub cluster_size: u64,
    /// Volume serial (if the extended BPB is signed).
    pub volume_id: Option<u32>,
    /// 11-byte BPB volume label (space padded), if present.
    pub volume_label: Option<String>,
    /// OEM string.
    pub oem: String,
}

impl BootSector {
    /// Parse and validate the boot sector at offset 0.
    ///
    /// Mount-time validation is intentionally firmer than walk-time: a
    /// nonsensical BPB means this isn't a mountable FAT volume.
    pub fn parse(src: &dyn ByteSource) -> Result<Self> {
        let b = src.read_slice(0, 512).map_err(FsError::Io)?;
        if b.len() < 512 {
            return Err(FsError::truncated(0, 512, b.len() as u64));
        }
        if b[510] != 0x55 || b[511] != 0xAA {
            return Err(FsError::corrupt(510, "missing 0x55AA boot signature"));
        }
        let bps = le::u16(&b, 11).unwrap_or(0) as u64;
        if !matches!(bps, 512 | 1024 | 2048 | 4096) {
            return Err(FsError::corrupt(11, format!("bad bytes/sector {bps}")));
        }
        let spc = le::u8(&b, 13).unwrap_or(0) as u64;
        if spc == 0 || !spc.is_power_of_two() {
            return Err(FsError::corrupt(13, format!("bad sectors/cluster {spc}")));
        }
        let reserved = le::u16(&b, 14).unwrap_or(0) as u64;
        if reserved == 0 {
            return Err(FsError::corrupt(14, "reserved sectors is 0"));
        }
        let num_fats = le::u8(&b, 16).unwrap_or(0) as u32;
        if num_fats == 0 {
            return Err(FsError::corrupt(16, "zero FATs"));
        }
        let root_entry_count = le::u16(&b, 17).unwrap_or(0) as u32;
        let tot16 = le::u16(&b, 19).unwrap_or(0) as u64;
        let media = le::u8(&b, 21).unwrap_or(0);
        let fatsz16 = le::u16(&b, 22).unwrap_or(0) as u64;
        let tot32 = le::u32(&b, 32).unwrap_or(0) as u64;
        let total_sectors = if tot16 != 0 { tot16 } else { tot32 };
        if total_sectors == 0 {
            return Err(FsError::corrupt(19, "zero total sectors"));
        }

        // FAT32 fields live in the extended BPB.
        let fatsz32 = le::u32(&b, 36).unwrap_or(0) as u64;
        let fat_size_sectors = if fatsz16 != 0 { fatsz16 } else { fatsz32 };
        if fat_size_sectors == 0 {
            return Err(FsError::corrupt(22, "zero FAT size"));
        }
        let root_cluster = le::u32(&b, 44).unwrap_or(0);

        let root_dir_sectors =
            ((root_entry_count as u64 * 32) + (bps - 1)) / bps;
        let first_data_sector =
            reserved + num_fats as u64 * fat_size_sectors + root_dir_sectors;
        if total_sectors <= first_data_sector {
            return Err(FsError::corrupt(
                0,
                format!(
                    "geometry impossible: total {total_sectors} <= first data sector {first_data_sector}"
                ),
            ));
        }
        let data_sectors = total_sectors - first_data_sector;
        let count_of_clusters = data_sectors / spc;
        let fat_type = if count_of_clusters < 4085 {
            FatType::Fat12
        } else if count_of_clusters < 65525 {
            FatType::Fat16
        } else {
            FatType::Fat32
        };
        if fat_type == FatType::Fat32 && root_cluster < 2 {
            return Err(FsError::corrupt(44, "FAT32 root cluster < 2"));
        }

        // Volume id / label: extended BPB signature at 0x26 (FAT12/16) or
        // 0x42 (FAT32).
        let (sig_off, id_off, label_off) = if fat_type == FatType::Fat32 {
            (0x42usize, 0x43usize, 0x47usize)
        } else {
            (0x26usize, 0x27usize, 0x2Busize)
        };
        let (volume_id, volume_label) = if matches!(le::u8(&b, sig_off), Some(0x28 | 0x29)) {
            (
                le::u32(&b, id_off),
                le::ascii(&b, label_off, 11).filter(|s| !s.is_empty()),
            )
        } else {
            (None, None)
        };
        let oem = le::ascii(&b, 3, 8).unwrap_or_default();

        Ok(BootSector {
            bytes_per_sector: bps,
            sectors_per_cluster: spc,
            reserved_sectors: reserved,
            num_fats,
            root_entry_count,
            total_sectors,
            media,
            fat_size_sectors,
            root_cluster,
            fat_type,
            fat_offset: reserved * bps,
            root_dir_offset: (reserved + num_fats as u64 * fat_size_sectors) * bps,
            root_dir_size: root_dir_sectors * bps,
            data_offset: first_data_sector * bps,
            count_of_clusters,
            cluster_size: bps * spc,
            volume_id,
            volume_label,
            oem,
        })
    }

    /// Detection confidence for a FAT-looking sector.
    ///
    /// Cheap structural checks only — never panics, never allocates much.
    pub fn detect(src: &dyn ByteSource) -> DetectConfidence {
        let b = match src.read_slice(0, 512) {
            Ok(b) if b.len() >= 512 => b,
            _ => return DetectConfidence::None,
        };
        if b[510] != 0x55 || b[511] != 0xAA {
            return DetectConfidence::None;
        }
        // Exclusions first: other filesystems share the 55AA signature.
        if &b[3..11] == b"NTFS    " || &b[3..11] == b"EXFAT   " {
            return DetectConfidence::None;
        }
        let mut score = 0u32;
        match b[0] {
            0xEB | 0xE9 => score += 1, // jump instruction
            _ => {}
        }
        let bps = le::u16(&b, 11).unwrap_or(0);
        if matches!(bps, 512 | 1024 | 2048 | 4096) {
            score += 1;
        }
        let spc = b[13];
        if spc != 0 && spc.is_power_of_two() {
            score += 1;
        }
        if le::u16(&b, 14).unwrap_or(0) > 0 {
            score += 1;
        }
        if b[16] >= 1 && b[16] <= 4 {
            score += 1;
        }
        if matches!(b[21], 0xF0 | 0xF8..=0xFF) {
            score += 1;
        }
        // FS-type label (advisory, not authoritative)
        if b[0x36..0x3B].starts_with(b"FAT") || b[0x52..0x57].starts_with(b"FAT") {
            score += 1;
        }
        // Geometry must be coherent.
        if BootSector::parse(src).is_ok() {
            score += 2;
        }
        match score {
            0..=2 => DetectConfidence::Low,
            3..=5 => DetectConfidence::Medium,
            6..=7 => DetectConfidence::High,
            _ => DetectConfidence::Certain,
        }
    }
}
