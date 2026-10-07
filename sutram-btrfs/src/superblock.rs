//! BTRFS superblock: parse, validate, checksum-verify, mirror fallback,
//! and the four backup tree roots that anchor COW-history recovery.
//!
//! Port of `superblock.py` (extended: mirror scanning, CRC32C validation,
//! `btrfs_root_backup` decoding — the Python version read only the primary
//! copy and never validated checksums).

use sutram_fs::{DetectConfidence, FsError, Result};
use sutram_io::{le, ByteSource};

use crate::ondisk::*;

/// `BTRFS_CSUM_TYPE_CRC32C` — the only checksum we verify.
pub const CSUM_CRC32C: u16 = 0;

/// Parsed superblock (`btrfs_super_block`, 4096 bytes). Complete-format
/// decode — some fields are kept for citation rather than read internally.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Superblock {
    /// Physical offset this copy was read from.
    pub source_offset: u64,
    /// Whether the embedded CRC32C matched (only when `csum_type == 0`).
    pub csum_ok: Option<bool>,
    pub fsid: [u8; 16],
    /// Physical address of this copy (should equal `source_offset`).
    pub bytenr: u64,
    pub flags: u64,
    /// Last committed transaction.
    pub generation: u64,
    /// Logical address of the root tree.
    pub root: u64,
    /// Logical address of the chunk tree.
    pub chunk_root: u64,
    /// Logical address of the log tree (fsync journal; may be 0).
    pub log_root: u64,
    /// Total device bytes across all members.
    pub total_bytes: u64,
    pub bytes_used: u64,
    /// Default subvolume's root dir objectid.
    pub root_dir_objectid: u64,
    pub num_devices: u64,
    pub sectorsize: u32,
    pub nodesize: u32,
    pub stripesize: u32,
    pub sys_chunk_array_size: u32,
    pub chunk_root_generation: u64,
    pub compat_flags: u64,
    pub compat_ro_flags: u64,
    pub incompat_flags: u64,
    pub csum_type: u16,
    pub root_level: u8,
    pub chunk_root_level: u8,
    pub log_root_level: u8,
    pub label: String,
    /// Raw `sys_chunk_array` bytes (`sys_chunk_array_size` long).
    pub sys_chunk_array: Vec<u8>,
    /// Previous-generation roots — the COW-history entry points.
    pub backup_roots: Vec<RootBackup>,
    /// `btrfs_dev_item` embedded in the superblock.
    pub dev_total_bytes: u64,
}

impl Superblock {
    /// Parse a 4096-byte buffer; `Err` only for short/impossible buffers.
    pub fn parse(buf: &[u8], source_offset: u64) -> Result<Superblock> {
        if buf.len() < SUPERBLOCK_SIZE {
            return Err(FsError::truncated(
                source_offset,
                SUPERBLOCK_SIZE as u64,
                buf.len() as u64,
            ));
        }
        if le::get(buf, MAGIC_OFFSET, 8) != Some(BTRFS_MAGIC.as_slice()) {
            return Err(FsError::corrupt(
                source_offset + MAGIC_OFFSET as u64,
                "bad BTRFS magic",
            ));
        }
        let sys_size = le::u32(buf, 0xA0).unwrap_or(0) as usize;
        let sys_avail = buf
            .get(SYS_CHUNK_ARRAY_OFFSET..SYS_CHUNK_ARRAY_OFFSET + SYS_CHUNK_ARRAY_SIZE)
            .unwrap_or(&[]);
        let sys_chunk_array = sys_avail[..sys_size.min(sys_avail.len())].to_vec();

        let mut backup_roots = Vec::with_capacity(4);
        for i in 0..4usize {
            if let Some(rb) = RootBackup::parse(buf, SUPER_ROOTS_OFFSET + i * ROOT_BACKUP_SIZE) {
                if rb.valid() {
                    backup_roots.push(rb);
                }
            }
        }

        let label_bytes = le::get(buf, 0x12B, 256).unwrap_or(&[]);
        let end = label_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(label_bytes.len());
        let label = String::from_utf8_lossy(&label_bytes[..end]).to_string();

        let csum_type = le::u16(buf, 0xC4).unwrap_or(0);
        let csum_ok = if csum_type == CSUM_CRC32C {
            let stored = le::u32(buf, 0).unwrap_or(0);
            Some(crc32fast::hash(&buf[CSUM_SIZE..SUPERBLOCK_SIZE]) == stored)
        } else {
            None
        };

        Ok(Superblock {
            source_offset,
            csum_ok,
            fsid: {
                let mut f = [0u8; 16];
                f.copy_from_slice(le::get(buf, 0x20, 16).unwrap_or(&[0; 16]));
                f
            },
            bytenr: le::u64(buf, 0x30).unwrap_or(0),
            flags: le::u64(buf, 0x38).unwrap_or(0),
            generation: le::u64(buf, 0x48).unwrap_or(0),
            root: le::u64(buf, 0x50).unwrap_or(0),
            chunk_root: le::u64(buf, 0x58).unwrap_or(0),
            log_root: le::u64(buf, 0x60).unwrap_or(0),
            total_bytes: le::u64(buf, 0x70).unwrap_or(0),
            bytes_used: le::u64(buf, 0x78).unwrap_or(0),
            root_dir_objectid: le::u64(buf, 0x80).unwrap_or(0),
            num_devices: le::u64(buf, 0x88).unwrap_or(0),
            sectorsize: le::u32(buf, 0x90).unwrap_or(0),
            nodesize: le::u32(buf, 0x94).unwrap_or(0),
            stripesize: le::u32(buf, 0x9C).unwrap_or(0),
            sys_chunk_array_size: sys_size as u32,
            chunk_root_generation: le::u64(buf, 0xA4).unwrap_or(0),
            compat_flags: le::u64(buf, 0xAC).unwrap_or(0),
            compat_ro_flags: le::u64(buf, 0xB4).unwrap_or(0),
            incompat_flags: le::u64(buf, 0xBC).unwrap_or(0),
            csum_type,
            root_level: le::u8(buf, 0xC6).unwrap_or(0),
            chunk_root_level: le::u8(buf, 0xC7).unwrap_or(0),
            log_root_level: le::u8(buf, 0xC8).unwrap_or(0),
            label,
            sys_chunk_array,
            backup_roots,
            dev_total_bytes: le::u64(buf, 0xC9 + 8).unwrap_or(0),
        })
    }

    /// Structural sanity beyond the magic — used by `detect`/`mount`.
    pub fn plausible(&self) -> bool {
        self.nodesize.is_power_of_two()
            && (4096..=65536).contains(&self.nodesize)
            && self.sectorsize.is_power_of_two()
            && (512..=65536).contains(&self.sectorsize)
            && self.nodesize >= self.sectorsize
            && self.total_bytes > 0
            && self.root != 0
            && self.chunk_root != 0
    }
}

/// Read and parse the superblock copy at `offset` (None if no magic /
/// unreadable).
fn read_copy(src: &dyn ByteSource, offset: u64) -> Option<Superblock> {
    let buf = src.read_slice(offset, SUPERBLOCK_SIZE).ok()?;
    if buf.len() < SUPERBLOCK_SIZE {
        return None;
    }
    Superblock::parse(&buf, offset).ok()
}

/// Pick the best superblock: all mirror copies are read; the valid copy
/// with the highest generation wins. Returns `(superblock, used_mirror)`.
pub fn read_superblock(src: &dyn ByteSource) -> Result<(Superblock, bool)> {
    let mut best: Option<Superblock> = None;
    let mut first_err: Option<FsError> = None;
    for &off in &SUPERBLOCK_MIRRORS {
        match read_copy(src, off) {
            Some(sb) => {
                // Prefer checksum-valid copies; among equal validity take
                // the newest generation.
                let better = match &best {
                    None => true,
                    Some(b) => {
                        (sb.csum_ok.unwrap_or(true), sb.generation)
                            > (b.csum_ok.unwrap_or(true), b.generation)
                    }
                };
                if better {
                    best = Some(sb);
                }
            }
            None => {
                if first_err.is_none() {
                    first_err = Some(FsError::corrupt(off, "superblock unreadable/bad magic"));
                }
            }
        }
    }
    let sb = best.ok_or_else(|| {
        first_err.unwrap_or_else(|| FsError::corrupt(SUPERBLOCK_OFFSET, "no valid BTRFS superblock"))
    })?;
    if !sb.plausible() {
        return Err(FsError::corrupt(
            sb.source_offset,
            format!(
                "implausible superblock geometry (nodesize={}, sectorsize={}, total_bytes={})",
                sb.nodesize, sb.sectorsize, sb.total_bytes
            ),
        ));
    }
    Ok((sb.clone(), sb.source_offset != SUPERBLOCK_OFFSET))
}

/// `FsParser::detect` support — cheap probe of the primary superblock,
/// then (if absent) each partition of a partition-tabled image, which is
/// the Rust port of `partition_detect.py` (that role is otherwise served
/// by `sutram_io::partition` upstream of this crate).
pub fn detect(src: &dyn ByteSource) -> DetectConfidence {
    match probe_at(src, SUPERBLOCK_OFFSET) {
        c if c >= DetectConfidence::Medium => return c,
        _ => {}
    }
    // Whole-disk image? Check each partition's volume start for the magic
    // (bounded: partition tables cap entries; each probe reads 4 KiB).
    if let Ok(parts) = sutram_io::partitions(src) {
        for p in parts.iter().take(32) {
            if probe_at(src, p.offset + SUPERBLOCK_OFFSET) >= DetectConfidence::High {
                return DetectConfidence::High;
            }
        }
    }
    DetectConfidence::None
}

/// Probe one superblock copy: magic → Medium; + geometry → High;
/// + valid checksum → Certain.
fn probe_at(src: &dyn ByteSource, offset: u64) -> DetectConfidence {
    let buf = match src.read_slice(offset, SUPERBLOCK_SIZE) {
        Ok(b) if b.len() == SUPERBLOCK_SIZE => b,
        _ => return DetectConfidence::None,
    };
    let sb = match Superblock::parse(&buf, offset) {
        Ok(s) => s,
        Err(_) => return DetectConfidence::None,
    };
    if !sb.plausible() {
        return DetectConfidence::Medium;
    }
    match sb.csum_ok {
        Some(true) => DetectConfidence::Certain,
        Some(false) => DetectConfidence::High, // magic+geometry but bad csum
        None => DetectConfidence::High,        // non-CRC32C csum: can't verify
    }
}
