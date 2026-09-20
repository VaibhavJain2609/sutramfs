//! Directory-entry decoding: 8.3 names, LFN assembly, DOS timestamps.

use std::time::Duration;

use sutram_fs::{FsTimestamp, Timestamps};
use sutram_fs::util;
use sutram_io::le;

/// Attribute bits.
pub(crate) const ATTR_RO: u8 = 0x01;
pub(crate) const ATTR_HIDDEN: u8 = 0x02;
pub(crate) const ATTR_SYSTEM: u8 = 0x04;
pub(crate) const ATTR_VOLUME_ID: u8 = 0x08;
pub(crate) const ATTR_DIR: u8 = 0x10;
pub(crate) const ATTR_LFN: u8 = 0x0F;

/// What a 32-byte directory slot decodes to.
pub(crate) enum Slot {
    /// byte0 = 0x00 — end-of-directory marker. Anything after it is
    /// "unused" space where deleted entries often survive.
    EndOfDir,
    /// An LFN name part (deleted flag preserved).
    Lfn(LfnPart),
    /// A normal entry (live or `0xE5`-deleted).
    Entry(DirEntry),
}

/// One LFN slot: 13 UTF-16 code units + ordering.
pub(crate) struct LfnPart {
    /// Sequence number (1-based; 0x40 flag = last physical part).
    pub seq: u8,
    /// `true` when this LFN slot itself is deleted (byte0 was 0xE5 —
    /// which destroys `seq`; callers treat the name as partial).
    pub deleted: bool,
    /// LFN checksum byte (matches the 8.3 entry it precedes).
    pub checksum: u8,
    /// The 13 code units (0x0000/0xFFFF terminators included; strip later).
    pub units: [u16; 13],
}

/// A decoded non-LFN directory entry.
pub(crate) struct DirEntry {
    /// byte0 == 0xE5 → deleted.
    pub deleted: bool,
    /// Raw 8.3 name bytes.
    pub raw_name: [u8; 11],
    pub attr: u8,
    pub first_cluster: u32,
    pub size: u32,
    pub crt_tenth: u8,
    pub crt_time: u16,
    pub crt_date: u16,
    pub acc_date: u16,
    pub wrt_time: u16,
    pub wdate: u16,
}

impl DirEntry {
    pub fn is_dir(&self) -> bool {
        self.attr & ATTR_DIR != 0
    }
    pub fn is_volume_label(&self) -> bool {
        self.attr & ATTR_VOLUME_ID != 0 && self.attr & ATTR_LFN != ATTR_LFN
    }
}

/// Decode one 32-byte slot. `buf.len()` must be ≥ 32 (caller guarantees;
/// short tails are handled by the cursor).
pub(crate) fn parse_slot(buf: &[u8]) -> Slot {
    debug_assert!(buf.len() >= 32);
    let first = buf[0];
    if first == 0x00 {
        return Slot::EndOfDir;
    }
    let attr = buf[11];
    if attr == ATTR_LFN {
        // LFN slot (possibly deleted — byte0 0xE5 clobbers seq).
        let mut units = [0u16; 13];
        let fields = [(1usize, 5usize), (14, 6), (28, 2)];
        let mut i = 0;
        for (off, n) in fields {
            for j in 0..n {
                units[i] = u16::from_le_bytes([buf[off + j * 2], buf[off + j * 2 + 1]]);
                i += 1;
            }
        }
        return Slot::Lfn(LfnPart {
            seq: first & 0x3F,
            deleted: first == 0xE5,
            checksum: buf[13],
            units,
        });
    }
    let deleted = first == 0xE5;
    let mut raw_name = [0u8; 11];
    raw_name.copy_from_slice(&buf[0..11]);
    let cluster = (le::u16(buf, 20).unwrap_or(0) as u32) << 16
        | le::u16(buf, 26).unwrap_or(0) as u32;
    Slot::Entry(DirEntry {
        deleted,
        raw_name,
        attr,
        first_cluster: cluster,
        size: le::u32(buf, 28).unwrap_or(0),
        crt_tenth: buf[13],
        crt_time: le::u16(buf, 14).unwrap_or(0),
        crt_date: le::u16(buf, 16).unwrap_or(0),
        acc_date: le::u16(buf, 18).unwrap_or(0),
        wrt_time: le::u16(buf, 22).unwrap_or(0),
        wdate: le::u16(buf, 24).unwrap_or(0),
    })
}

/// Render an 8.3 name as `NAME.EXT`. For deleted entries the first byte
/// is `0xE5`; we substitute `_` (TSK convention) — the original byte is
/// documented by `meta["deleted_marker"]`.
pub(crate) fn name83(e: &DirEntry) -> String {
    let mut b = e.raw_name;
    if b[0] == 0x05 {
        b[0] = 0xE5; // escaped lead byte
    }
    if e.deleted {
        b[0] = b'_';
    }
    let base = String::from_utf8_lossy(&b[0..8]);
    let ext = String::from_utf8_lossy(&b[8..11]);
    let base = base.trim_end();
    let ext = ext.trim_end();
    if ext.is_empty() {
        util::sanitize_name(base)
    } else {
        util::sanitize_name(&format!("{base}.{ext}"))
    }
}

/// Assemble an LFN from collected parts. `parts` are in table order
/// (last chunk first, per the 0x40 "last" flag). Returns `None` when no
/// usable characters survive.
pub(crate) fn assemble_lfn(parts: &[LfnPart]) -> Option<String> {
    if parts.is_empty() {
        return None;
    }
    // Order by ascending seq (seq 1 holds chars 0–12, seq 2 the next 13, …;
    // the on-disk order is the reverse, so we sort rather than trust order).
    let mut sorted: Vec<&LfnPart> = parts.iter().collect();
    sorted.sort_by_key(|p| p.seq);
    // chars in seq order 1..N each contributing 13 units.
    let mut units: Vec<u16> = Vec::with_capacity(sorted.len() * 13);
    for p in sorted {
        units.extend_from_slice(&p.units);
    }
    // Strip at first NUL; drop 0xFFFF filler.
    let end = units
        .iter()
        .position(|&u| u == 0)
        .unwrap_or(units.len());
    let units: Vec<u16> = units[..end]
        .iter()
        .copied()
        .filter(|&u| u != 0xFFFF)
        .collect();
    if units.is_empty() {
        return None;
    }
    Some(util::sanitize_name(&String::from_utf16_lossy(&units)))
}

/// Decode the DOS date/time fields into a [`Timestamps`] set.
pub(crate) fn timestamps(e: &DirEntry) -> Timestamps {
    Timestamps {
        modified: dos_datetime(e.wdate, e.wrt_time, 0, Duration::from_secs(2), "fat-dos-write"),
        created: dos_datetime(
            e.crt_date,
            e.crt_time,
            e.crt_tenth,
            Duration::from_millis(10),
            "fat-dos-create",
        ),
        accessed: dos_date(e.acc_date),
        ..Default::default()
    }
}

/// DOS date+time. `tenth` is the 10 ms resolution creation sub-second
/// field (0–199).
fn dos_datetime(
    date: u16,
    time: u16,
    tenth: u8,
    granularity: Duration,
    enc: &'static str,
) -> Option<FsTimestamp> {
    if date == 0 {
        return None;
    }
    let year = ((date >> 9) & 0x7F) as i64 + 1980;
    let month = ((date >> 5) & 0x0F) as i64;
    let day = (date & 0x1F) as i64;
    let hour = ((time >> 11) & 0x1F) as i64;
    let min = ((time >> 5) & 0x3F) as i64;
    let sec = ((time & 0x1F) as i64) * 2 + (tenth.min(199) as i64) / 100;
    let nanos = ((tenth.min(199) as i64) % 100) * 10_000_000;
    let raw = ((date as u64) << 32) | ((time as u64) << 16) | tenth as u64;
    Some(FsTimestamp {
        value: util::unix_nanos(year, month, day, hour, min, sec, nanos),
        raw_value: raw,
        raw_encoding: enc,
        granularity,
    })
}

/// Access date only — 1-day granularity.
fn dos_date(date: u16) -> Option<FsTimestamp> {
    if date == 0 {
        return None;
    }
    dos_datetime(date, 0, 0, Duration::from_secs(86_400), "fat-dos-access-date")
}
