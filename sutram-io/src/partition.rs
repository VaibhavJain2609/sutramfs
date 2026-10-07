//! MBR (Master Boot Record) and GPT (GUID Partition Table) parsing.
//!
//! [`partitions`] inspects sector 0 (and LBA 1 for GPT) and returns
//! [`Partition`] records carrying **byte** offsets — the unit every forensic
//! record in this project is reported in. [`open_partitions`] wraps each
//! partition in an [`OffsetView`] so filesystem parsers can mount it while
//! still being able to recover the absolute offset via
//! [`OffsetView::base_offset`].
//!
//! Layout notes:
//!
//! * MBR: boot signature `55 AA` at `0x1FE`; four 16-byte entries at `0x1BE`.
//!   Entry: status(1), CHS first(3), type(1), CHS last(3), LBA start u32,
//!   sector count u32. A type byte of `0xEE` marks a protective MBR → GPT.
//! * GPT: header `"EFI PART"` at LBA 1 (offset `0x200` for 512-byte sectors).
//!   Entries are `entry_size` records (usually 128 B) starting at
//!   `entries_lba * sector_size`; a zero type GUID means unused.
//! * Sector size: assumed 512 unless the GPT header sits at a different LBA —
//!   4Kn disks are detected by probing `0x1000` for `"EFI PART"` as well.

use std::sync::Arc;

use crate::le;
use crate::{ByteSource, Error, OffsetView, Result};

const MBR_SIG_OFF: usize = 0x1FE;
const MBR_ENTRIES_OFF: usize = 0x1BE;
const MBR_ENTRY_SIZE: usize = 16;
const MBR_ENTRIES: usize = 4;
const GPT_PROTECTIVE: u8 = 0xEE;
const GPT_SIG: &[u8; 8] = b"EFI PART";
/// Safety cap on partition-entry count — real disks use ≤ 128; this stops a
/// corrupt `num_entries` field from causing a huge allocation.
const MAX_GPT_ENTRIES: u32 = 16384;

/// Which partition table a [`Partition`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableKind {
    /// Classic DOS/MBR table.
    Mbr,
    /// UEFI GUID partition table.
    Gpt,
}

/// One partition with absolute byte addressing.
#[derive(Debug, Clone)]
pub struct Partition {
    /// Entry index within its table (0-based).
    pub index: u32,
    /// Absolute byte offset of the partition's first byte.
    pub offset: u64,
    /// Partition size in bytes.
    pub size: u64,
    /// MBR type byte, when from an MBR.
    pub ptype: Option<u8>,
    /// GPT type GUID (RFC-4122 text), when from a GPT.
    pub type_guid: Option<String>,
    /// GPT unique partition GUID.
    pub partition_guid: Option<String>,
    /// GPT UTF-16 name, or MBR-derived label if any.
    pub label: Option<String>,
    /// Whether the MBR "bootable" flag (0x80) was set.
    pub bootable: bool,
    /// Which table produced this record.
    pub table: TableKind,
}

/// A [`Partition`] together with a mounted byte view over it.
pub struct PartitionSource {
    /// Table metadata.
    pub partition: Partition,
    /// Read-only view of exactly this partition's bytes.
    pub source: OffsetView,
}

/// Parse the partition table(s) of a disk image.
///
/// Returns the entries of whichever table is present:
///
/// * protective MBR (`0xEE`) + valid GPT header → GPT entries;
/// * otherwise MBR entries (empty `Vec` if the sector has no `55 AA`
///   signature or no populated entries);
/// * corrupt structures produce [`Error::Corrupt`], never a panic.
pub fn partitions(src: &dyn ByteSource) -> Result<Vec<Partition>> {
    let sector = src
        .read_slice(0, 512)
        .map_err(Error::Io)?;
    if sector.len() < 512 {
        return Ok(Vec::new()); // too small to hold a table — not an error
    }
    if sector[MBR_SIG_OFF] != 0x55 || sector[MBR_SIG_OFF + 1] != 0xAA {
        return Ok(Vec::new());
    }

    let entries = &sector[MBR_ENTRIES_OFF..MBR_ENTRIES_OFF + MBR_ENTRIES * MBR_ENTRY_SIZE];
    let protective = entries
        .chunks(MBR_ENTRY_SIZE)
        .any(|e| e[4] == GPT_PROTECTIVE);

    if protective {
        match gpt_partitions(src) {
            Ok(v) if !v.is_empty() => return Ok(v),
            Ok(_) | Err(_) => {
                // Corrupt/absent GPT: fall through to MBR so the examiner
                // still sees the protective entry.
            }
        }
    }

    let mut out = Vec::new();
    for (i, e) in entries.chunks(MBR_ENTRY_SIZE).enumerate() {
        let ptype = e[4];
        if ptype == 0 {
            continue;
        }
        let lba_start = le::u32(e, 8).unwrap_or(0) as u64;
        let sectors = le::u32(e, 12).unwrap_or(0) as u64;
        if sectors == 0 {
            continue;
        }
        out.push(Partition {
            index: i as u32,
            offset: lba_start * 512,
            size: sectors * 512,
            ptype: Some(ptype),
            type_guid: None,
            partition_guid: None,
            label: None,
            bootable: e[0] == 0x80,
            table: TableKind::Mbr,
        });
    }
    Ok(out)
}

/// Parse the GPT. Assumes 512-byte LBAs, then probes a 4096-byte LBA if the
/// header isn't found at `0x200` (4Kn disks).
fn gpt_partitions(src: &dyn ByteSource) -> Result<Vec<Partition>> {
    for &lba_size in &[512u64, 4096] {
        let hdr = src.read_slice(lba_size, 92).map_err(Error::Io)?;
        if hdr.len() < 92 || &hdr[0..8] != GPT_SIG {
            continue;
        }
        return gpt_entries(src, lba_size, &hdr);
    }
    Err(Error::corrupt(0x200, "protective MBR but no GPT header"))
}

fn gpt_entries(src: &dyn ByteSource, lba_size: u64, hdr: &[u8]) -> Result<Vec<Partition>> {
    let entries_lba = le::u64(hdr, 72).unwrap_or(0);
    let num = le::u32(hdr, 80).unwrap_or(0);
    let entsz = le::u32(hdr, 84).unwrap_or(0) as usize;
    if !(128..=4096).contains(&entsz) {
        return Err(Error::corrupt(
            lba_size + 84,
            format!("implausible GPT entry size {entsz}"),
        ));
    }
    if num == 0 || num > MAX_GPT_ENTRIES {
        return Err(Error::corrupt(
            lba_size + 80,
            format!("implausible GPT entry count {num}"),
        ));
    }
    let base = entries_lba.saturating_mul(lba_size);
    let mut out = Vec::new();
    // Read entries in bounded blocks rather than one giant allocation.
    const BLOCK: usize = 32;
    let mut done = 0u32;
    while done < num {
        let n = (num - done).min(BLOCK as u32) as usize;
        let off = base.saturating_add(done as u64 * entsz as u64);
        let buf = src.read_slice(off, n * entsz).map_err(Error::Io)?;
        if buf.len() < n * entsz {
            break; // truncated table — emit what parsed
        }
        for (i, e) in buf.chunks(entsz).enumerate() {
            if e.iter().take(16).all(|&b| b == 0) {
                continue; // unused entry
            }
            let first = le::u64(e, 32).unwrap_or(0);
            let last = le::u64(e, 40).unwrap_or(0);
            if last < first {
                continue; // corrupt entry — skip, don't abort the table
            }
            // Checked LBA→byte math: a corrupt entry with absurd LBAs must
            // not wrap around and alias real data at low offsets.
            let (Some(offset), Some(size)) = (
                first.checked_mul(lba_size),
                last.checked_sub(first)
                    .and_then(|d| d.checked_add(1))
                    .and_then(|n| n.checked_mul(lba_size)),
            ) else {
                continue;
            };
            let label = utf16_label(&e[56..entsz.min(128)]);
            out.push(Partition {
                index: done + i as u32,
                offset,
                size,
                ptype: None,
                type_guid: le::uuid_le(e, 0),
                partition_guid: le::uuid_le(e, 16),
                label,
                bootable: false,
                table: TableKind::Gpt,
            });
        }
        done += n as u32;
    }
    Ok(out)
}

/// Decode the 72-byte UTF-16LE GPT partition name.
fn utf16_label(raw: &[u8]) -> Option<String> {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .take(36)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    if units.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&units))
}

/// Convenience: parse the table and return each partition already wrapped in
/// a mountable [`OffsetView`]. Entries whose window starts beyond the end of
/// the image are skipped (truncated image) — the
/// [`Partition`] records remain available via [`partitions`].
pub fn open_partitions(src: Arc<dyn ByteSource>) -> Result<Vec<PartitionSource>> {
    let list = partitions(src.as_ref())?;
    let mut out = Vec::with_capacity(list.len());
    for p in list {
        match OffsetView::new(src.clone(), p.offset, p.size) {
            Ok(view) => out.push(PartitionSource {
                partition: p,
                source: view,
            }),
            Err(_) => continue,
        }
    }
    Ok(out)
}
