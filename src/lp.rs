//! `liblp` logical-partition metadata — the on-disk format inside Android's
//! physical `super` partition that describes *dynamic partitions*.
//!
//! Layout at the start of the super device (AOSP `fs_mgr/liblp`):
//!
//! ```text
//! offset  size                       content
//! 0x0000  0x1000                     reserved (blocks accidental boot sectors)
//! 0x1000  0x1000                     LpMetadataGeometry       (primary)
//! 0x2000  0x1000                     LpMetadataGeometry       (backup)
//! 0x3000  metadata_max_size*slots    LpMetadata slots         (primary copies)
//! …       metadata_max_size*slots    LpMetadata slots         (backup copies)
//! first_logical_sector*512           logical partition data
//! ```
//!
//! Each `LpMetadata` blob is a 128- or 256-byte `LpMetadataHeader` followed
//! by four contiguous tables: partitions (52 B entries), extents (24 B),
//! groups (48 B) and block devices (64 B). Header and tables carry SHA-256
//! checksums computed with the checksum field zeroed — verified here and
//! reported, never fatal (a mismatch is itself a forensic signal).
//!
//! All fields are little-endian; sector numbers are always 512-byte
//! (`LP_SECTOR_SIZE`) regardless of `logical_block_size`.

use std::sync::Arc;

use sutram_fs::util::sanitize_name;
use sutram_fs::FsError;
use sutram_io::le;
use sutram_io::{ByteSource, SparseExtent, SparseFile, SparseKind};

use crate::layout::{Attrs, NamedSource};
use crate::names::classify_name;
use crate::sha256::sha256;
use crate::Result;

/// `LpMetadataGeometry.magic`.
pub const LP_GEOMETRY_MAGIC: u32 = 0x616C_4467;
/// `LpMetadataHeader.magic`.
pub const LP_HEADER_MAGIC: u32 = 0x414C_5030;
/// Bytes reserved at the start of a super device (`LP_PARTITION_RESERVED_BYTES`).
pub const LP_RESERVED: u64 = 0x1000;
/// Size of each geometry block (`LP_METADATA_GEOMETRY_SIZE`).
pub const LP_GEOMETRY_SIZE: u64 = 0x1000;
/// Sector size the LP format always uses (`LP_SECTOR_SIZE`).
pub const LP_SECTOR_SIZE: u64 = 512;

const GEOMETRY_STRUCT_SIZE: usize = 52;
const HEADER_MIN_SIZE: u64 = 128; // v1.0 header
const HEADER_MAX_SIZE: u64 = 4096; // hard bound on header_size field
const LP_MAJOR: u16 = 10;
const LP_MINOR_MAX: u16 = 2;

/// Per-table entry-size floors (the fields we read live inside these).
const PARTITION_ENTRY_MIN: usize = 52;
const EXTENT_ENTRY_MIN: usize = 24;
const GROUP_ENTRY_MIN: usize = 48;
const BLOCKDEV_ENTRY_MIN: usize = 64;
/// Plausibility cap — real supers hold tens of entries.
const MAX_LP_ENTRIES: u32 = 4096;
/// Plausibility cap on `metadata_max_size` (default is 64 KiB).
const MAX_METADATA_SIZE: u64 = 16 * 1024 * 1024;
/// Plausibility cap on slot count (A/B uses 2, A/B/C test rigs 3).
const MAX_SLOTS: u32 = 64;

/// `LpMetadataExtent.target_type`: dm-linear mapping into a block device.
const LP_TARGET_LINEAR: u32 = 0;
/// `LpMetadataExtent.target_type`: dm-zero hole.
const LP_TARGET_ZERO: u32 = 1;

/// `LpMetadataHeader.flags` bit: Virtual A/B device.
pub const LP_HEADER_FLAG_VIRTUAL_AB: u32 = 0x1;
/// `LpMetadataHeader.flags` bit: overlays activated via `adb remount`.
pub const LP_HEADER_FLAG_OVERLAYS_ACTIVE: u32 = 0x2;
/// `LpMetadataPartitionGroup.flags` bit: group name needs the slot suffix.
pub const LP_GROUP_SLOT_SUFFIXED: u32 = 0x1;
/// `LpMetadataBlockDevice.flags` bit: device name needs the slot suffix.
pub const LP_BLOCK_DEVICE_SLOT_SUFFIXED: u32 = 0x1;

// ---------------------------------------------------------------------------
// Decoded structures
// ---------------------------------------------------------------------------

/// `LpMetadataGeometry` — where and how many metadata copies exist.
#[derive(Debug, Clone)]
pub struct LpGeometry {
    /// Maximum bytes one metadata copy may occupy.
    pub metadata_max_size: u32,
    /// Number of metadata slots (1 = non-A/B, 2 = A/B, 3 = A/B/C).
    pub metadata_slot_count: u32,
    /// Minimal alignment for partition/extent sizes.
    pub logical_block_size: u32,
    /// Absolute offset the geometry was read from (0x1000 or 0x2000).
    pub offset: u64,
    /// Whether the SHA-256 checksum verified (false = tamper/corruption flag).
    pub checksum_ok: bool,
}

/// `LpMetadataHeader` bookkeeping.
#[derive(Debug, Clone)]
pub struct LpHeader {
    /// `major_version` (must be 10).
    pub major: u16,
    /// `minor_version` (0..=2 known).
    pub minor: u16,
    /// `flags` (`LP_HEADER_FLAG_*`), present from v1.2.
    pub flags: u32,
    /// Header SHA-256 verification result.
    pub checksum_ok: bool,
    /// Tables-region SHA-256 verification result.
    pub tables_checksum_ok: bool,
}

/// One `LpMetadataPartition` entry.
#[derive(Debug, Clone)]
pub struct LpPartition {
    /// ASCII name (may still carry a `_a`-style suffix or need one).
    pub name: String,
    /// `LP_PARTITION_ATTR_*` bitmask.
    pub attributes: u32,
    /// Index of the first extent in [`LpMetadata::extents`].
    pub first_extent_index: u32,
    /// Number of extents.
    pub num_extents: u32,
    /// Index into [`LpMetadata::groups`].
    pub group_index: u32,
}

/// One `LpMetadataExtent` entry.
#[derive(Debug, Clone)]
pub struct LpExtent {
    /// Length in 512-byte sectors.
    pub num_sectors: u64,
    /// 0 = linear, 1 = zero.
    pub target_type: u32,
    /// Linear: sector index on the target block device. Zero: must be 0.
    pub target_data: u64,
    /// Linear: index into [`LpMetadata::block_devices`].
    pub target_source: u32,
}

/// One `LpMetadataPartitionGroup` entry.
#[derive(Debug, Clone)]
pub struct LpGroup {
    /// Group name (e.g. `default`, `google_dynamic_partitions_a`).
    pub name: String,
    /// `LP_GROUP_*` flags.
    pub flags: u32,
    /// Sum cap for member partition sizes (0 = unlimited).
    pub maximum_size: u64,
}

/// One `LpMetadataBlockDevice` entry — a physical partition holding logical
/// data; index 0 is normally `super` itself.
#[derive(Debug, Clone)]
pub struct LpBlockDevice {
    /// First sector usable for logical data (after the metadata area).
    pub first_logical_sector: u64,
    /// Required alignment for extents.
    pub alignment: u32,
    /// Alignment offset for stacked devices.
    pub alignment_offset: u32,
    /// Block-device size in bytes at metadata-creation time.
    pub size: u64,
    /// GPT partition name this device maps to.
    pub partition_name: String,
    /// `LP_BLOCK_DEVICE_*` flags.
    pub flags: u32,
}

/// A fully decoded metadata slot.
#[derive(Debug)]
pub struct LpMetadata {
    /// Geometry that located this metadata.
    pub geometry: LpGeometry,
    /// Header bookkeeping.
    pub header: LpHeader,
    /// Which slot index was decoded.
    pub slot: u32,
    /// `true` when a backup metadata copy was used.
    pub from_backup: bool,
    /// Partition table.
    pub partitions: Vec<LpPartition>,
    /// Extent table.
    pub extents: Vec<LpExtent>,
    /// Group table.
    pub groups: Vec<LpGroup>,
    /// Block-device table.
    pub block_devices: Vec<LpBlockDevice>,
    /// Non-fatal findings accumulated while parsing.
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Geometry
// ---------------------------------------------------------------------------

fn parse_geometry_blob(blob: &[u8], offset: u64) -> Result<LpGeometry> {
    if blob.len() < GEOMETRY_STRUCT_SIZE {
        return Err(FsError::truncated(
            offset,
            GEOMETRY_STRUCT_SIZE as u64,
            blob.len() as u64,
        ));
    }
    if le::u32(blob, 0) != Some(LP_GEOMETRY_MAGIC) {
        return Err(FsError::corrupt(offset, "no LP geometry magic"));
    }
    let struct_size = le::u32(blob, 4).unwrap_or(0) as usize;
    if struct_size != GEOMETRY_STRUCT_SIZE {
        return Err(FsError::corrupt(
            offset + 4,
            format!("unexpected LP geometry struct_size {struct_size}"),
        ));
    }
    // Checksum covers the whole struct with the checksum field zeroed.
    let mut tmp = [0u8; GEOMETRY_STRUCT_SIZE];
    tmp.copy_from_slice(&blob[..GEOMETRY_STRUCT_SIZE]);
    tmp[8..40].fill(0);
    let checksum_ok = sha256(&tmp)[..] == blob[8..40];

    let metadata_max_size = le::u32(blob, 40).unwrap_or(0);
    let metadata_slot_count = le::u32(blob, 44).unwrap_or(0);
    let logical_block_size = le::u32(blob, 48).unwrap_or(0);

    if metadata_slot_count == 0 || metadata_slot_count > MAX_SLOTS {
        return Err(FsError::corrupt(
            offset + 44,
            format!("implausible LP metadata_slot_count {metadata_slot_count}"),
        ));
    }
    if metadata_max_size == 0
        || metadata_max_size % LP_SECTOR_SIZE as u32 != 0
        || metadata_max_size as u64 > MAX_METADATA_SIZE
    {
        return Err(FsError::corrupt(
            offset + 40,
            format!("implausible LP metadata_max_size {metadata_max_size}"),
        ));
    }
    Ok(LpGeometry {
        metadata_max_size,
        metadata_slot_count,
        logical_block_size,
        offset,
        checksum_ok,
    })
}

/// Read the LP geometry, preferring the primary copy at `0x1000` and falling
/// back to the backup at `0x2000`. `Err` means the source is not a (healthy)
/// super image.
pub fn read_geometry(src: &dyn ByteSource) -> Result<LpGeometry> {
    let primary_off = LP_RESERVED;
    let backup_off = LP_RESERVED + LP_GEOMETRY_SIZE;
    let primary = src
        .read_slice(primary_off, GEOMETRY_STRUCT_SIZE)
        .map_err(FsError::Io)?;
    match parse_geometry_blob(&primary, primary_off) {
        Ok(g) => Ok(g),
        Err(e) => {
            let backup = src
                .read_slice(backup_off, GEOMETRY_STRUCT_SIZE)
                .map_err(FsError::Io)?;
            let mut g = parse_geometry_blob(&backup, backup_off).map_err(|_| e)?;
            g.offset = backup_off;
            Ok(g)
        }
    }
}

/// Slot `n`'s primary metadata offset.
fn primary_metadata_offset(g: &LpGeometry, slot: u32) -> u64 {
    LP_RESERVED + LP_GEOMETRY_SIZE * 2 + slot as u64 * g.metadata_max_size as u64
}

/// Slot `n`'s backup metadata offset.
fn backup_metadata_offset(g: &LpGeometry, slot: u32) -> u64 {
    primary_metadata_offset(g, g.metadata_slot_count) + slot as u64 * g.metadata_max_size as u64
}

/// Total bytes the LP metadata area occupies at the head of the device.
pub fn total_metadata_size(g: &LpGeometry) -> u64 {
    LP_RESERVED + (LP_GEOMETRY_SIZE + g.metadata_max_size as u64 * g.metadata_slot_count as u64) * 2
}

// ---------------------------------------------------------------------------
// Header + tables
// ---------------------------------------------------------------------------

fn slot_suffix(slot: u32) -> String {
    // liblp: GetSlotSuffix() — '_' + ('a' + slot_number); saturates for odd slots.
    let c = (b'a' + slot.min(25) as u8) as char;
    format!("_{c}")
}

fn read_table<'a>(
    blob: &'a [u8],
    tables_size: u64,
    desc: &[u8],
    desc_off: u64,
    min_entry: usize,
    what: &str,
    warnings: &mut Vec<String>,
) -> Result<Vec<&'a [u8]>> {
    let offset = le::u32(desc, 0).unwrap_or(0) as u64;
    let num = le::u32(desc, 4).unwrap_or(0);
    let entry_size = le::u32(desc, 8).unwrap_or(0) as usize;
    if num == 0 {
        return Ok(Vec::new());
    }
    if num > MAX_LP_ENTRIES {
        return Err(FsError::corrupt(
            desc_off + 4,
            format!("LP {what} table has implausible entry count {num}"),
        ));
    }
    if entry_size < min_entry {
        return Err(FsError::corrupt(
            desc_off + 8,
            format!("LP {what} entry_size {entry_size} < {min_entry}"),
        ));
    }
    let end = offset
        .checked_add(num as u64 * entry_size as u64)
        .ok_or_else(|| FsError::corrupt(desc_off, format!("LP {what} table overflows")))?;
    if end > tables_size {
        return Err(FsError::corrupt(
            desc_off,
            format!("LP {what} table runs past tables_size ({end} > {tables_size})"),
        ));
    }
    let tables = blob
        .get(..tables_size as usize)
        .ok_or_else(|| FsError::truncated(desc_off, tables_size, blob.len() as u64))?;
    let mut out = Vec::with_capacity(num as usize);
    for i in 0..num {
        let s = offset as usize + i as usize * entry_size;
        match tables.get(s..s + entry_size) {
            Some(e) => out.push(e),
            None => {
                warnings.push(format!("LP {what} entry {i} truncated — skipped"));
                break;
            }
        }
    }
    Ok(out)
}

fn parse_metadata_blob(
    blob: &[u8],
    geometry: &LpGeometry,
    slot: u32,
    from_backup: bool,
    slot_off: u64,
    warnings: &mut Vec<String>,
) -> Result<LpMetadata> {
    if blob.len() < HEADER_MIN_SIZE as usize {
        return Err(FsError::truncated(
            slot_off,
            HEADER_MIN_SIZE,
            blob.len() as u64,
        ));
    }
    if le::u32(blob, 0) != Some(LP_HEADER_MAGIC) {
        return Err(FsError::corrupt(slot_off, "no LP metadata header magic"));
    }
    let major = le::u16(blob, 4).unwrap_or(0);
    let minor = le::u16(blob, 6).unwrap_or(0);
    let header_size = le::u32(blob, 8).unwrap_or(0) as u64;
    if !(HEADER_MIN_SIZE..=HEADER_MAX_SIZE).contains(&header_size)
        || header_size > geometry.metadata_max_size as u64
    {
        return Err(FsError::corrupt(
            slot_off + 8,
            format!("implausible LP header_size {header_size}"),
        ));
    }
    let header_blob = blob
        .get(..header_size as usize)
        .ok_or_else(|| FsError::truncated(slot_off, header_size, blob.len() as u64))?;

    // Header checksum: SHA-256 of header_size bytes with bytes 12..44 zeroed.
    let mut tmp = header_blob.to_vec();
    tmp[12..44].fill(0);
    let checksum_ok = sha256(&tmp)[..] == header_blob[12..44];

    let tables_size = le::u32(header_blob, 44).unwrap_or(0) as u64;
    let tables_checksum_ok = {
        let tables = blob
            .get(header_size as usize..(header_size + tables_size) as usize)
            .unwrap_or(&[]);
        !tables.is_empty() && sha256(tables)[..] == header_blob[48..80]
    };
    if header_size + tables_size > geometry.metadata_max_size as u64 {
        return Err(FsError::corrupt(
            slot_off + 44,
            format!("LP header+tables exceed metadata_max_size ({tables_size:#x})"),
        ));
    }
    if tables_size == 0 || tables_size > geometry.metadata_max_size as u64 {
        return Err(FsError::corrupt(
            slot_off + 44,
            format!("implausible LP tables_size {tables_size}"),
        ));
    }
    let tables_blob = blob
        .get(header_size as usize..(header_size + tables_size) as usize)
        .ok_or_else(|| {
            FsError::truncated(slot_off + header_size, tables_size, blob.len() as u64)
        })?;

    let flags = if header_size >= 132 {
        le::u32(header_blob, 128).unwrap_or(0)
    } else {
        0
    };
    let header = LpHeader {
        major,
        minor,
        flags,
        checksum_ok,
        tables_checksum_ok,
    };
    if !checksum_ok {
        warnings.push(format!(
            "LP slot {slot}: header SHA-256 mismatch (tamper or corruption)"
        ));
    }
    if !tables_checksum_ok {
        warnings.push(format!(
            "LP slot {slot}: tables SHA-256 mismatch (tamper or corruption)"
        ));
    }
    if major != LP_MAJOR {
        return Err(FsError::unsupported(format!(
            "LP metadata major version {major} (expected {LP_MAJOR})"
        )));
    }
    if minor > LP_MINOR_MAX {
        warnings.push(format!(
            "LP metadata minor version {minor} > {LP_MINOR_MAX} — parsing known fields"
        ));
    }

    // Table descriptors: offsets 80/92/104/116, 12 bytes each.
    let partitions_t = read_table(
        tables_blob,
        tables_size,
        &header_blob[80..92],
        slot_off + 80,
        PARTITION_ENTRY_MIN,
        "partitions",
        warnings,
    )?;
    let extents_t = read_table(
        tables_blob,
        tables_size,
        &header_blob[92..104],
        slot_off + 92,
        EXTENT_ENTRY_MIN,
        "extents",
        warnings,
    )?;
    let groups_t = read_table(
        tables_blob,
        tables_size,
        &header_blob[104..116],
        slot_off + 104,
        GROUP_ENTRY_MIN,
        "groups",
        warnings,
    )?;
    let bdev_t = read_table(
        tables_blob,
        tables_size,
        &header_blob[116..128],
        slot_off + 116,
        BLOCKDEV_ENTRY_MIN,
        "block_devices",
        warnings,
    )?;

    let mut partitions = Vec::with_capacity(partitions_t.len());
    for (i, e) in partitions_t.iter().enumerate() {
        let name = le::ascii(e, 0, 36).unwrap_or_default();
        partitions.push(LpPartition {
            name,
            attributes: le::u32(e, 36).unwrap_or(0),
            first_extent_index: le::u32(e, 40).unwrap_or(0),
            num_extents: le::u32(e, 44).unwrap_or(0),
            group_index: le::u32(e, 48).unwrap_or(0),
        });
        if partitions.last().map(|p| p.name.is_empty()) == Some(true) {
            warnings.push(format!("LP partition {i} has an empty name"));
        }
    }
    let mut extents = Vec::with_capacity(extents_t.len());
    for e in extents_t {
        extents.push(LpExtent {
            num_sectors: le::u64(e, 0).unwrap_or(0),
            target_type: le::u32(e, 8).unwrap_or(0),
            target_data: le::u64(e, 12).unwrap_or(0),
            target_source: le::u32(e, 20).unwrap_or(0),
        });
    }
    let mut groups = Vec::with_capacity(groups_t.len());
    for e in groups_t {
        groups.push(LpGroup {
            name: le::ascii(e, 0, 36).unwrap_or_default(),
            flags: le::u32(e, 36).unwrap_or(0),
            maximum_size: le::u64(e, 40).unwrap_or(0),
        });
    }
    let mut block_devices = Vec::with_capacity(bdev_t.len());
    for e in bdev_t {
        block_devices.push(LpBlockDevice {
            first_logical_sector: le::u64(e, 0).unwrap_or(0),
            alignment: le::u32(e, 8).unwrap_or(0),
            alignment_offset: le::u32(e, 12).unwrap_or(0),
            size: le::u64(e, 16).unwrap_or(0),
            partition_name: le::ascii(e, 24, 36).unwrap_or_default(),
            flags: le::u32(e, 60).unwrap_or(0),
        });
    }

    Ok(LpMetadata {
        geometry: geometry.clone(),
        header,
        slot,
        from_backup,
        partitions,
        extents,
        groups,
        block_devices,
        warnings: std::mem::take(warnings),
    })
}

fn parse_slot(
    src: &dyn ByteSource,
    geometry: &LpGeometry,
    slot: u32,
    backup: bool,
) -> Result<LpMetadata> {
    let off = if backup {
        backup_metadata_offset(geometry, slot)
    } else {
        primary_metadata_offset(geometry, slot)
    };
    let blob = src
        .read_slice(off, geometry.metadata_max_size as usize)
        .map_err(FsError::Io)?;
    let mut warnings = Vec::new();
    // parse_metadata_blob drains `warnings` into `md.warnings` on success.
    parse_metadata_blob(&blob, geometry, slot, backup, off, &mut warnings)
}

/// Locate and decode the best LP metadata copy.
///
/// Iterates slots 0..`metadata_slot_count`, trying each primary copy then its
/// backup; the first fully parseable header wins. Checksum mismatches are
/// recorded in [`LpMetadata::warnings`] but do not disqualify a slot.
pub fn read_metadata(src: &dyn ByteSource) -> Result<LpMetadata> {
    let geometry = read_geometry(src)?;
    let mut collected = Vec::new();
    let mut last_err = None;
    for slot in 0..geometry.metadata_slot_count {
        for backup in [false, true] {
            match parse_slot(src, &geometry, slot, backup) {
                Ok(mut md) => {
                    if backup {
                        md.warnings.push(format!(
                            "LP slot {slot}: primary metadata unreadable — using backup copy"
                        ));
                    }
                    if !geometry.checksum_ok {
                        md.warnings.push(
                            "LP geometry SHA-256 mismatch (tamper or corruption)".to_string(),
                        );
                    }
                    return Ok(md);
                }
                Err(e) => {
                    collected.push(format!(
                        "LP slot {slot}{}: {e}",
                        if backup { " (backup)" } else { "" }
                    ));
                    last_err = Some(e);
                }
            }
        }
    }
    Err(FsError::corrupt(
        0,
        format!(
            "no readable LP metadata slot ({}): {}",
            collected.join("; "),
            last_err.map(|e| e.to_string()).unwrap_or_default()
        ),
    ))
}

// ---------------------------------------------------------------------------
// Logical partition sources
// ---------------------------------------------------------------------------

/// Map `md`'s partitions to mountable [`NamedSource`]s, also returning the
/// non-fatal findings accumulated while decoding.
///
/// Every logical partition becomes a [`SparseFile`] over the super image:
/// LINEAR extents become data extents (`target_data * 512` into the source),
/// ZERO extents become holes. Extents targeting a block device other than
/// index 0 reference bytes that live in a *different* physical partition
/// (multi-LUN supers) — they are represented as holes and flagged, never
/// silently mapped to wrong bytes.
pub fn logical_partitions_verbose(
    src: Arc<dyn ByteSource>,
) -> Result<(Vec<NamedSource>, Vec<String>)> {
    let md = read_metadata(src.as_ref())?;
    let mut out = Vec::with_capacity(md.partitions.len());
    let mut warnings = md.warnings.clone();

    // Sanity: metadata area must not overlap logical data.
    if let Some(dev0) = md.block_devices.first() {
        let data_start = dev0.first_logical_sector.saturating_mul(LP_SECTOR_SIZE);
        if data_start < total_metadata_size(&md.geometry) {
            warnings.push(format!(
                "LP first_logical_sector {data_start:#x} overlaps metadata region {:#x}",
                total_metadata_size(&md.geometry)
            ));
        }
    }

    for (pi, p) in md.partitions.iter().enumerate() {
        let mut name = sanitize_name(&p.name);
        let attrs = Attrs(p.attributes);
        if name.is_empty() {
            name = format!("partition_{pi}");
        }
        if attrs.slot_suffixed() {
            name.push_str(&slot_suffix(md.slot));
        }
        let group = md
            .groups
            .get(p.group_index as usize)
            .map(|g| sanitize_name(&g.name))
            .unwrap_or_default();

        // Assemble extents.
        let first = p.first_extent_index as usize;
        let last = first.saturating_add(p.num_extents as usize);
        if last > md.extents.len() {
            warnings.push(format!(
                "LP partition {name}: extent range {first}..{last} exceeds extent table ({})",
                md.extents.len()
            ));
        }
        let mut exts = Vec::new();
        let mut out_off = 0u64;
        let mut external = false;
        for ext in md
            .extents
            .get(first..last.min(md.extents.len()))
            .unwrap_or(&[])
        {
            let len = ext.num_sectors.saturating_mul(LP_SECTOR_SIZE);
            let kind = match ext.target_type {
                LP_TARGET_LINEAR => {
                    let dev = md.block_devices.get(ext.target_source as usize);
                    if ext.target_source == 0 && dev.is_some() {
                        let src_off = ext.target_data.saturating_mul(LP_SECTOR_SIZE);
                        let end = ext
                            .target_data
                            .saturating_add(ext.num_sectors)
                            .saturating_mul(LP_SECTOR_SIZE);
                        let d = &md.block_devices[0];
                        if d.size != 0 && end > d.size {
                            warnings.push(format!(
                                "LP partition {name}: extent runs past block device size {:#x}",
                                d.size
                            ));
                        }
                        SparseKind::Data {
                            source: src.clone(),
                            src_offset: src_off,
                        }
                    } else {
                        // Bytes live on another physical partition (e.g. a
                        // second super LUN) or a device index that does not
                        // exist — never silently map wrong bytes.
                        match dev {
                            Some(d) => warnings.push(format!(
                                "LP partition {name}: extent targets block device '{}' — \
                                 not inside this source; mapped as hole",
                                d.partition_name
                            )),
                            None => warnings.push(format!(
                                "LP partition {name}: extent targets unknown block device {} — \
                                 mapped as hole",
                                ext.target_source
                            )),
                        }
                        external = true;
                        SparseKind::Zero
                    }
                }
                LP_TARGET_ZERO => SparseKind::Zero,
                other => {
                    warnings.push(format!(
                        "LP partition {name}: unknown extent target_type {other} — mapped as hole"
                    ));
                    SparseKind::Zero
                }
            };
            exts.push(SparseExtent {
                out_offset: out_off,
                len,
                kind,
            });
            out_off = out_off.saturating_add(len);
        }

        let sf = SparseFile::new(out_off, exts).map_err(FsError::from)?;
        let mut meta = std::collections::BTreeMap::new();
        meta.insert("lp_slot".to_string(), md.slot.to_string());
        if md.from_backup {
            meta.insert("lp_backup".to_string(), "true".to_string());
        }
        if external {
            meta.insert("external_extents".to_string(), "true".to_string());
        }
        meta.insert("extent_count".to_string(), p.num_extents.to_string());
        out.push(NamedSource {
            name,
            group,
            attrs,
            source: Arc::new(sf),
            role: classify_name(&p.name),
            meta,
        });
    }
    Ok((out, warnings))
}

/// The spec entry point: logical partitions of a `super` image.
///
/// Same as [`logical_partitions_verbose`] but drops the warning list —
/// use the verbose variant (or [`crate::analyze`]) to see checksum
/// mismatches, external extents and other forensic notes.
pub fn logical_partitions(src: Arc<dyn ByteSource>) -> Result<Vec<NamedSource>> {
    Ok(logical_partitions_verbose(src)?.0)
}
