//! MFT FILE record decoding: fixup (update-sequence-array) application,
//! header fields, and base/extension record references.
//!
//! Every sector of an on-disk FILE record ends with a 2-byte *update
//! sequence* value; the bytes that originally occupied those slots live in
//! the Update Sequence Array (USA). Applying the fixup is **mandatory** —
//! un-fixed records read as garbage at every sector trailer.

use sutram_fs::{FsError, Result};
use sutram_io::le;

/// In-use flag (`FILE.flags` bit 0).
pub(crate) const FLG_IN_USE: u16 = 0x0001;
/// Directory flag (`FILE.flags` bit 1).
pub(crate) const FLG_DIRECTORY: u16 = 0x0002;

/// A decoded MFT FILE record (fixup already applied to `data`).
#[derive(Debug)]
pub(crate) struct FileRecord {
    /// Absolute byte offset of the record on the source.
    pub offset: u64,
    /// MFT record number (index).
    pub record_no: u64,
    /// Raw signature: `"FILE"`, `"BAAD"`, or something else.
    pub signature: [u8; 4],
    /// Sequence number — bumped on each reuse of the slot.
    pub sequence: u16,
    /// Hard-link count.
    pub link_count: u16,
    /// Record flags (`FLG_IN_USE`, `FLG_DIRECTORY`).
    pub flags: u16,
    /// Used bytes of the record.
    pub used_size: u32,
    /// File reference of the base record (`0` when this *is* the base).
    /// Low 48 bits = record number, high 16 bits = sequence.
    pub base_ref: u64,
    /// Offset of the first attribute within `data`.
    pub first_attr_off: usize,
    /// The full record bytes with fixup applied.
    pub data: Vec<u8>,
}

impl FileRecord {
    /// `true` when the record is allocated to a live file.
    pub fn in_use(&self) -> bool {
        self.flags & FLG_IN_USE != 0
    }
    /// `true` when the record describes a directory.
    pub fn is_dir(&self) -> bool {
        self.flags & FLG_DIRECTORY != 0
    }
}

/// Apply the update-sequence-array fixup in place.
///
/// `usa_off`/`usa_count` come from the record header: `usa_count` is the
/// number of u16 slots (1 sequence number + one per sector). Returns the
/// number of sectors fixed up. Fails `Corrupt` when the array is out of
/// bounds or a sector trailer does not match the sequence number — the
/// classic signature of a torn write or a record that is not a record.
pub(crate) fn apply_fixup(
    data: &mut [u8],
    rec_off: u64,
    usa_off: usize,
    usa_count: usize,
    sector_size: usize,
) -> Result<usize> {
    if sector_size == 0 || data.len() % sector_size != 0 {
        return Err(FsError::corrupt(
            rec_off,
            format!(
                "record size {} not a multiple of sector size {sector_size}",
                data.len()
            ),
        ));
    }
    let sectors = data.len() / sector_size;
    if usa_count != sectors + 1 {
        return Err(FsError::corrupt(
            rec_off + 6,
            format!("USA count {usa_count} != sectors+1 {}", sectors + 1),
        ));
    }
    let usa_end = usa_off
        .checked_add(usa_count * 2)
        .ok_or_else(|| FsError::corrupt(rec_off, "USA offset overflow"))?;
    if usa_end > data.len() {
        return Err(FsError::corrupt(
            rec_off + usa_off as u64,
            "USA extends past end of record",
        ));
    }
    let seq = u16::from_le_bytes([data[usa_off], data[usa_off + 1]]);
    for i in 0..sectors {
        let trailer = (i + 1) * sector_size - 2;
        let found = u16::from_le_bytes([data[trailer], data[trailer + 1]]);
        if found != seq {
            return Err(FsError::corrupt(
                rec_off + trailer as u64,
                format!(
                    "fixup mismatch at sector {i}: trailer {found:#06x} != sequence {seq:#06x} \
                     (torn write or stale record)"
                ),
            ));
        }
        data[trailer] = data[usa_off + 2 + i * 2];
        data[trailer + 1] = data[usa_off + 3 + i * 2];
    }
    Ok(sectors)
}

/// Parse a FILE record from raw bytes (fixup applied on success).
///
/// `record_no` is the record's index in the MFT (used only for
/// diagnostics/provenance — the self-reported number at 0x2C is *not*
/// trusted for location).
pub(crate) fn parse_record(
    mut data: Vec<u8>,
    offset: u64,
    record_no: u64,
    sector_size: usize,
) -> Result<FileRecord> {
    if data.len() < 48 {
        return Err(FsError::truncated(offset, 48, data.len() as u64));
    }
    let signature = [data[0], data[1], data[2], data[3]];
    if &signature != b"FILE" && &signature != b"BAAD" {
        return Err(FsError::corrupt(
            offset,
            format!(
                "bad record signature {:02x?}",
                &signature
            ),
        ));
    }
    let usa_off = le::u16(&data, 4).unwrap_or(0) as usize;
    let usa_count = le::u16(&data, 6).unwrap_or(0) as usize;
    apply_fixup(&mut data, offset, usa_off, usa_count, sector_size)?;

    let sequence = le::u16(&data, 16).unwrap_or(0);
    let link_count = le::u16(&data, 18).unwrap_or(0);
    let first_attr_off = le::u16(&data, 20).unwrap_or(0) as usize;
    let flags = le::u16(&data, 22).unwrap_or(0);
    let used_size = le::u32(&data, 24).unwrap_or(0);
    let base_ref = le::u64(&data, 32).unwrap_or(0);
    if first_attr_off >= data.len() || first_attr_off < 0x28 {
        return Err(FsError::corrupt(
            offset + 20,
            format!("bad first-attribute offset {first_attr_off:#x}"),
        ));
    }
    Ok(FileRecord {
        offset,
        record_no,
        signature,
        sequence,
        link_count,
        flags,
        used_size,
        base_ref,
        first_attr_off,
        data,
    })
}

/// Apply the INDX-record fixup (same USA scheme, different signature).
pub(crate) fn apply_indx_fixup(
    data: &mut [u8],
    offset: u64,
    sector_size: usize,
) -> Result<()> {
    if data.len() < 24 || &data[0..4] != b"INDX" {
        return Err(FsError::corrupt(offset, "bad INDX signature"));
    }
    let usa_off = le::u16(data, 4).unwrap_or(0) as usize;
    let usa_count = le::u16(data, 6).unwrap_or(0) as usize;
    apply_fixup(data, offset, usa_off, usa_count, sector_size)?;
    Ok(())
}
