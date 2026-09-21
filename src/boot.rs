//! exFAT boot-region parsing, checksum verification and detection.
//!
//! Layout (in sectors, `bps` = bytes/sector):
//!
//! ```text
//! sectors 0–11    main boot region
//!                 0 = boot sector, 1–8 = extended boot, 9 = OEM parameters,
//!                 10 = reserved, 11 = boot checksum (repeated u32)
//! sectors 12–23   backup boot region (same layout)
//! FatOffset..     FAT table(s), then the cluster heap at ClusterHeapOffset
//! ```
//!
//! Clusters are numbered from 2: cluster `c` starts at
//! `ClusterHeapOffset * bps + (c - 2) * cluster_size`.

use sutram_fs::{DetectConfidence, FsError, Result};
use sutram_io::le;
use sutram_io::ByteSource;

/// FAT entry value marking a bad cluster.
pub(crate) const BAD_CLUSTER: u32 = 0xFFFF_FFF7;
/// FAT entries at or above this mark end-of-chain.
pub(crate) const EOC_MIN: u32 = 0xFFFF_FFF8;

/// Parsed and sanity-checked exFAT boot sector plus boot-region health.
#[derive(Debug, Clone)]
pub(crate) struct BootSector {
    pub partition_offset_sectors: u64,
    pub volume_length_sectors: u64,
    pub fat_offset_sectors: u32,
    pub fat_length_sectors: u32,
    pub heap_offset_sectors: u32,
    pub cluster_count: u32,
    pub root_cluster: u32,
    pub serial: u32,
    pub revision: u16,
    pub volume_flags: u16,
    pub num_fats: u8,
    pub drive_select: u8,
    pub percent_in_use: u8,
    pub bytes_per_sector: u64,
    pub sectors_per_cluster: u64,
    pub cluster_size: u64,
    /// Byte offset of the first FAT.
    pub fat_offset: u64,
    /// Byte offset of cluster 2 (cluster-heap start).
    pub heap_offset: u64,
    /// Total byte length of the mounted source — clamps cluster extents.
    pub src_len: u64,
    /// Clusters whose first byte lies inside the source:
    /// `min(cluster_count, ceil((src_len - heap_offset) / cluster_size))`.
    /// Bounds allocation sizes and cluster scans — a cluster that does not
    /// exist in the image can never be read or carved.
    pub present_clusters: u64,
    /// Backup boot sector (sector 12) carries the exFAT name + signature.
    pub backup_ok: bool,
    /// Main boot-region checksum sector (11) verified.
    pub checksum_ok: bool,
    /// Backup boot-region checksum sector (23) verified.
    pub backup_checksum_ok: bool,
}

impl BootSector {
    /// Absolute byte range of cluster `c`, or `None` when out of range.
    /// The length is clamped to the end of the source, so a partially
    /// imaged tail cluster reports only its present bytes.
    pub(crate) fn cluster_range(&self, c: u32) -> Option<(u64, u64)> {
        if !self.valid_cluster(c) {
            return None;
        }
        let off = self.heap_offset + (c as u64 - 2) * self.cluster_size;
        Some((off, self.cluster_size.min(self.src_len.saturating_sub(off))))
    }

    /// Cluster index sanity: valid clusters are `2 ..= cluster_count + 1`.
    pub(crate) fn valid_cluster(&self, c: u32) -> bool {
        c >= 2 && (c as u64) < self.cluster_count as u64 + 2
    }

    /// Parse and validate the boot sector at offset 0.
    ///
    /// Mount-time validation is firmer than `detect`: a nonsensical BPB is
    /// `Corrupt`, not merely a low score.
    pub(crate) fn parse(src: &dyn ByteSource) -> Result<Self> {
        let first = src.read_slice(0, 512).map_err(FsError::Io)?;
        if first.len() < 512 {
            return Err(FsError::truncated(0, 512, first.len() as u64));
        }
        if &first[3..11] != b"EXFAT   " {
            return Err(FsError::corrupt(3, "missing \"EXFAT   \" filesystem name"));
        }
        // The MustBeZero field distinguishes exFAT from FAT lookalikes.
        if first[0x0B..0x40].iter().any(|&b| b != 0) {
            return Err(FsError::corrupt(0x0B, "MustBeZero field is non-zero"));
        }
        let bps_shift = first[0x6C];
        if !(9..=12).contains(&bps_shift) {
            return Err(FsError::corrupt(
                0x6C,
                format!("bad bytes-per-sector shift {bps_shift}"),
            ));
        }
        let bps = 1u64 << bps_shift;
        let spc_shift = first[0x6D];
        // Spec: cluster size must not exceed 32 MiB.
        if bps_shift as u32 + spc_shift as u32 > 25 {
            return Err(FsError::corrupt(
                0x6D,
                format!(
                    "cluster size 2^{} exceeds the 32 MiB exFAT limit",
                    bps_shift as u32 + spc_shift as u32
                ),
            ));
        }
        let b = src.read_slice(0, bps as usize).map_err(FsError::Io)?;
        if (b.len() as u64) < bps {
            return Err(FsError::truncated(0, bps, b.len() as u64));
        }
        if b[bps as usize - 2] != 0x55 || b[bps as usize - 1] != 0xAA {
            return Err(FsError::corrupt(bps - 2, "missing 0x55AA boot signature"));
        }
        let num_fats = b[0x6E];
        if !matches!(num_fats, 1 | 2) {
            return Err(FsError::corrupt(0x6E, format!("bad FAT count {num_fats}")));
        }
        let volume_length = le::u64(&b, 0x48).unwrap_or(0);
        if volume_length == 0 {
            return Err(FsError::corrupt(0x48, "zero volume length"));
        }
        let fat_off_s = le::u32(&b, 0x50).unwrap_or(0);
        let fat_len_s = le::u32(&b, 0x54).unwrap_or(0);
        if fat_off_s < 24 || fat_len_s == 0 {
            return Err(FsError::corrupt(
                0x50,
                format!("bad FAT geometry: offset {fat_off_s}, length {fat_len_s}"),
            ));
        }
        let heap_off_s = le::u32(&b, 0x58).unwrap_or(0);
        let fat_end = fat_off_s as u64 + num_fats as u64 * fat_len_s as u64;
        if (heap_off_s as u64) < fat_end {
            return Err(FsError::corrupt(
                0x58,
                "cluster heap overlaps the FAT/boot region",
            ));
        }
        let cluster_count = le::u32(&b, 0x5C).unwrap_or(0);
        if cluster_count == 0 {
            return Err(FsError::corrupt(0x5C, "zero clusters"));
        }
        // Spec §7.1.5: ClusterCount ≤ 2^32 − 11 (FAT addressing limit).
        // Also keeps `cluster_count + 2` and `first_cluster + n` free of
        // u32 overflow downstream.
        if cluster_count > 0xFFFF_FFF5 {
            return Err(FsError::corrupt(
                0x5C,
                format!("cluster count {cluster_count} exceeds the exFAT maximum"),
            ));
        }
        // The FAT must hold ClusterCount + 2 entries (media + EOC marks).
        if fat_len_s as u64 * bps / 4 < cluster_count as u64 + 2 {
            return Err(FsError::corrupt(
                0x54,
                "FAT too short for the declared cluster count",
            ));
        }
        let spc = 1u64 << spc_shift;
        // The cluster heap must fit inside the declared volume
        // (ClusterCount = floor((VolumeLength − ClusterHeapOffset)/spc)).
        if heap_off_s as u64 + cluster_count as u64 * spc > volume_length {
            return Err(FsError::corrupt(
                0x5C,
                "cluster heap extends beyond the volume length",
            ));
        }
        let root_cluster = le::u32(&b, 0x60).unwrap_or(0);
        if root_cluster < 2 || root_cluster as u64 >= cluster_count as u64 + 2 {
            return Err(FsError::corrupt(
                0x60,
                format!("bad root cluster {root_cluster}"),
            ));
        }
        let cluster_size = bps * spc;
        let heap_offset = heap_off_s as u64 * bps;
        if heap_offset >= src.len() {
            return Err(FsError::truncated(
                heap_offset,
                cluster_size,
                src.len().saturating_sub(heap_offset),
            ));
        }

        Ok(BootSector {
            partition_offset_sectors: le::u64(&b, 0x40).unwrap_or(0),
            volume_length_sectors: volume_length,
            fat_offset_sectors: fat_off_s,
            fat_length_sectors: fat_len_s,
            heap_offset_sectors: heap_off_s,
            cluster_count,
            root_cluster,
            serial: le::u32(&b, 0x64).unwrap_or(0),
            revision: le::u16(&b, 0x68).unwrap_or(0),
            volume_flags: le::u16(&b, 0x6A).unwrap_or(0),
            num_fats,
            drive_select: b[0x6F],
            // Spec: 0–100 = estimate, 0xFF = "not available". Do NOT
            // clamp — 0xFF→100 would fabricate a full disk.
            percent_in_use: b[0x70],
            bytes_per_sector: bps,
            sectors_per_cluster: spc,
            cluster_size,
            fat_offset: fat_off_s as u64 * bps,
            heap_offset,
            src_len: src.len(),
            present_clusters: (src.len() - heap_offset)
                .div_ceil(cluster_size)
                .min(cluster_count as u64),
            backup_ok: backup_sector_ok(src, 12, bps),
            checksum_ok: boot_checksum_ok(src, 0, bps),
            backup_checksum_ok: boot_checksum_ok(src, 12, bps),
        })
    }

    /// Detection confidence for an exFAT-looking sector.
    ///
    /// Cheap structural checks only: signature + MustBeZero discrimination,
    /// BPB sanity, backup boot sector, and the boot-region checksum.
    pub(crate) fn detect(src: &dyn ByteSource) -> DetectConfidence {
        // Read 4 KiB so 4096-byte-sector media are covered in one shot.
        let b = match src.read_slice(0, 4096) {
            Ok(b) if b.len() >= 512 => b,
            _ => return DetectConfidence::None,
        };
        if &b[3..11] != b"EXFAT   " {
            return DetectConfidence::None;
        }
        let mut score = 0u32;
        if b[0] == 0xEB && b[1] == 0x76 && b[2] == 0x90 {
            score += 2; // spec-mandated JumpBoot
        }
        if b[0x0B..0x40].iter().all(|&x| x == 0) {
            score += 2; // MustBeZero — the big FAT/exFAT discriminator
        }
        let bps_shift = b[0x6C];
        let mut bps: u64 = 0;
        if (9..=12).contains(&bps_shift) {
            bps = 1u64 << bps_shift;
            if b.len() >= bps as usize
                && b[bps as usize - 2] == 0x55
                && b[bps as usize - 1] == 0xAA
            {
                score += 2;
            } else {
                bps = 0;
            }
        }
        if bps_shift as u32 + b[0x6D] as u32 <= 25 {
            score += 1; // cluster size within the 32 MiB limit
        }
        if matches!(b[0x6E], 1 | 2) {
            score += 1; // NumberOfFats
        }
        // BPB geometry coherence.
        let vol_len = le::u64(&b, 0x48).unwrap_or(0);
        let fat_off = le::u32(&b, 0x50).unwrap_or(0) as u64;
        let fat_len = le::u32(&b, 0x54).unwrap_or(0) as u64;
        let heap_off = le::u32(&b, 0x58).unwrap_or(0) as u64;
        let clu_cnt = le::u32(&b, 0x5C).unwrap_or(0) as u64;
        let root = le::u32(&b, 0x60).unwrap_or(0);
        if vol_len > 0
            && fat_off >= 24
            && fat_len > 0
            && heap_off >= fat_off + fat_len
            && clu_cnt > 0
            && root >= 2
            && (root as u64) < clu_cnt + 2
        {
            score += 2;
        }
        if bps > 0 {
            // Backup boot sector at sector 12.
            if backup_sector_ok(src, 12, bps) {
                score += 2;
            }
            // Main boot-region checksum.
            if boot_checksum_ok(src, 0, bps) {
                score += 2;
            }
        }
        match score {
            0..=3 => DetectConfidence::Low,
            4..=7 => DetectConfidence::Medium,
            8..=11 => DetectConfidence::High,
            _ => DetectConfidence::Certain,
        }
    }
}

/// Does sector `region_sector` of the source look like an exFAT boot sector?
fn backup_sector_ok(src: &dyn ByteSource, region_sector: u64, bps: u64) -> bool {
    match src.read_slice(region_sector * bps, bps as usize) {
        Ok(b) if (b.len() as u64) >= bps => {
            &b[3..11] == b"EXFAT   "
                && b[bps as usize - 2] == 0x55
                && b[bps as usize - 1] == 0xAA
        }
        _ => false,
    }
}

/// Rolling u32 checksum over the 11 sectors of a boot region, excluding the
/// VolumeFlags (0x6A–0x6B) and PercentInUse (0x70) bytes of the boot sector.
fn boot_checksum(src: &dyn ByteSource, region_sector: u64, bps: u64) -> Option<u32> {
    let data = src
        .read_slice(region_sector * bps, (11 * bps) as usize)
        .ok()?;
    if (data.len() as u64) < 11 * bps {
        return None;
    }
    let mut sum = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        if i == 106 || i == 107 || i == 112 {
            continue; // VolumeFlags, PercentInUse — mutable at runtime
        }
        sum = ((sum & 1) << 31)
            .wrapping_add(sum >> 1)
            .wrapping_add(byte as u32);
    }
    Some(sum)
}

/// Verify the checksum sector (sector 11 of a boot region): it must be filled
/// end-to-end with the repeated little-endian checksum value.
fn boot_checksum_ok(src: &dyn ByteSource, region_sector: u64, bps: u64) -> bool {
    let Some(sum) = boot_checksum(src, region_sector, bps) else {
        return false;
    };
    let sector = match src.read_slice((region_sector + 11) * bps, bps as usize) {
        Ok(s) if (s.len() as u64) >= bps => s,
        _ => return false,
    };
    sector
        .chunks_exact(4)
        .all(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]) == sum)
}
