//! exFAT directory-entry decoding: entry types, file entry sets, the
//! 16-bit set checksum, and exFAT timestamps (DOS-style + 10 ms increments
//! + UTC offset fields).
//!
//! Entry-type byte structure (MS-EXFAT §6.2.1):
//!
//! * bit 7 — InUse: `0` marks the entry deleted/unallocated (e.g. a file
//!   set degrades `0x85 → 0x05`, `0xC0 → 0x40`, `0x41 → 0x41` — the entry
//!   *contents* are otherwise untouched, which is what makes exFAT deleted
//!   files so recoverable).
//! * bits 6–0 — type code; codes `≥ 0x40` are *secondary* entries
//!   (stream extension `0xC0`, file name `0xC1`, vendor extension, …).

use std::time::Duration;

use sutram_fs::util;
use sutram_fs::{FsTimestamp, Timestamps};
use sutram_io::le;

// --- type codes (EntryType & 0x7F) ----------------------------------------
pub(crate) const CODE_BITMAP: u8 = 0x01;
pub(crate) const CODE_UPCASE: u8 = 0x02;
pub(crate) const CODE_LABEL: u8 = 0x03;
pub(crate) const CODE_FILE: u8 = 0x05;
pub(crate) const CODE_STREAM: u8 = 0x40;
pub(crate) const CODE_NAME: u8 = 0x41;

// --- file attributes -------------------------------------------------------
pub(crate) const ATTR_RO: u16 = 0x01;
pub(crate) const ATTR_HIDDEN: u16 = 0x02;
pub(crate) const ATTR_SYSTEM: u16 = 0x04;
pub(crate) const ATTR_DIR: u16 = 0x10;
pub(crate) const ATTR_ARCHIVE: u16 = 0x20;

/// Stream-extension `GeneralSecondaryFlags` bit: data is contiguous, no
/// FAT chain is used.
pub(crate) const FLAG_NO_FAT_CHAIN: u8 = 0x02;

/// `true` when the in-use bit is set.
pub(crate) fn in_use(entry_type: u8) -> bool {
    entry_type & 0x80 != 0
}

/// Type code with the in-use bit stripped.
pub(crate) fn code(entry_type: u8) -> u8 {
    entry_type & 0x7F
}

/// `true` when this is a secondary entry (stream ext, file name, vendor…).
pub(crate) fn is_secondary(entry_type: u8) -> bool {
    code(entry_type) >= 0x40
}

/// The exFAT entry-set checksum: a byte-wise rotate-right-1 + add over the
/// whole set, *excluding* bytes 2–3 of the primary entry (the checksum field
/// itself).
///
/// `restore_inuse`: deleted sets have bit 7 cleared on every entry-type
/// byte, which breaks the stored checksum. Forensically it is useful to ask
/// "would this set checksum correctly if it were still live?" — pass `true`
/// to restore the in-use bits before summing.
pub(crate) fn set_checksum(set: &[u8], restore_inuse: bool) -> u16 {
    let mut sum = 0u16;
    for (i, &b) in set.iter().enumerate() {
        if i == 2 || i == 3 {
            continue;
        }
        let b = if restore_inuse && i % 32 == 0 {
            b | 0x80
        } else {
            b
        };
        sum = ((sum & 1) << 15)
            .wrapping_add(sum >> 1)
            .wrapping_add(b as u16);
    }
    sum
}

/// A decoded file directory entry set (primary `0x85`/`0x05` + secondaries).
#[derive(Debug, Clone)]
pub(crate) struct FileSet {
    /// In-use bit clear on the primary → deleted entry set.
    pub deleted: bool,
    pub attr: u16,
    pub secondary_count: u8,
    /// SetChecksum as stored in the primary entry.
    pub set_checksum: u16,
    /// `Some(true/false)` when the full set was present and could be
    /// verified (for deleted sets, with in-use bits restored); `None` when
    /// the set was truncated and the checksum could not be evaluated.
    pub checksum_ok: Option<bool>,
    /// Secondary entries actually present (may be < `secondary_count`).
    pub secondaries_seen: usize,
    /// All three MAC timestamps with raw encodings preserved.
    pub timestamps: Timestamps,
    /// UTC offsets in minutes, if the valid bit was set (create/mod/acc).
    pub tz_minutes: [Option<i32>; 3],
    /// A stream-extension secondary was present.
    pub has_stream: bool,
    /// `FLAG_NO_FAT_CHAIN` — data is one contiguous extent.
    pub no_fat_chain: bool,
    pub name_len: u8,
    pub name_hash: u16,
    /// ValidDataLength — the logical byte count.
    pub valid_len: u64,
    pub first_cluster: u32,
    /// DataLength — the allocated length (≥ valid_len).
    pub data_len: u64,
    /// Assembled UTF-16 name (sanitised), if any name entries survived.
    pub name: Option<String>,
}

impl FileSet {
    pub fn is_dir(&self) -> bool {
        self.attr & ATTR_DIR != 0
    }
}

/// Decode one 32-byte stream-extension entry (type byte already consumed).
fn parse_stream(s: &[u8], set: &mut FileSet) {
    set.has_stream = true;
    set.no_fat_chain = s[1] & FLAG_NO_FAT_CHAIN != 0;
    set.name_len = s[3];
    set.name_hash = le::u16(s, 4).unwrap_or(0);
    set.valid_len = le::u64(s, 8).unwrap_or(0);
    set.first_cluster = le::u32(s, 20).unwrap_or(0);
    set.data_len = le::u64(s, 24).unwrap_or(0);
}

/// Decode the 15 UTF-16 code units of one file-name entry into `units`.
fn push_name_units(s: &[u8], units: &mut Vec<u16>) {
    for j in 0..15 {
        if let Some(u) = le::u16(s, 2 + j * 2) {
            units.push(u);
        }
    }
}

/// Decode a timestamp field triplet into an [`FsTimestamp`].
///
/// `raw32` packs `time` (low u16) and `date` (high u16), DOS-style with
/// year offset 1980. `cs` is the 10 ms increment field (create/modify only;
/// pass `has_cs = false` for accessed). `tz` is the UTC-offset byte:
/// bit 7 = valid, bits 6–0 = signed offset in 15-minute units.
pub(crate) fn exfat_ts(raw32: u32, cs: u8, tz: u8, has_cs: bool) -> FsTimestamp {
    let date = (raw32 >> 16) as u16;
    let time = (raw32 & 0xFFFF) as u16;
    let year = ((date >> 9) & 0x7F) as i64 + 1980;
    let month = ((date >> 5) & 0x0F) as i64;
    let day = (date & 0x1F) as i64;
    let hour = ((time >> 11) & 0x1F) as i64;
    let min = ((time >> 5) & 0x3F) as i64;
    let sec = ((time & 0x1F) as i64) * 2;
    let nanos = if has_cs {
        (cs.min(199) as i64) * 10_000_000
    } else {
        0
    };
    let local = if date == 0 {
        None
    } else {
        util::unix_nanos(year, month, day, hour, min, sec, nanos)
    };
    // Timestamps are stored in local time; apply the UTC offset when the
    // valid bit is set so `value` is a true epoch instant.
    let value = match (local, tz_minutes(tz)) {
        (Some(l), Some(off)) => Some(l - off as i64 * 60_000_000_000),
        (l, _) => l,
    };
    FsTimestamp {
        value,
        raw_value: ((date as u64) << 32)
            | ((time as u64) << 16)
            | ((cs as u64) << 8)
            | tz as u64,
        raw_encoding: "exfat-datetime",
        granularity: if has_cs {
            Duration::from_millis(10)
        } else {
            Duration::from_secs(2)
        },
    }
}

/// Decode a UTC-offset byte → minutes east of UTC. `None` when the
/// OffsetValid bit (0x80) is clear.
pub(crate) fn tz_minutes(tz: u8) -> Option<i32> {
    if tz & 0x80 == 0 {
        return None;
    }
    // 7-bit two's-complement in 15-minute units.
    let quarters = (((tz & 0x7F) << 1) as i8) >> 1;
    Some(quarters as i32 * 15)
}

/// Parse the file entry set whose primary entry starts at `data[pos]`.
///
/// `data` is the whole directory buffer; the set may span cluster
/// boundaries. Returns the decoded set plus the number of 32-byte slots
/// consumed (1 + secondaries actually present — never more than
/// `1 + secondary_count`, and never past a non-secondary interruption, so
/// the caller resumes at the next real entry).
pub(crate) fn parse_file_set(data: &[u8], pos: usize) -> Result<(FileSet, usize), String> {
    let p = data.get(pos..pos + 32).ok_or("short primary entry")?;
    let entry_type = p[0];
    if code(entry_type) != CODE_FILE {
        return Err(format!("not a file entry: type {entry_type:#04x}"));
    }
    let deleted = !in_use(entry_type);
    let secondary_count = p[1];
    let stored_sum = le::u16(p, 2).unwrap_or(0);
    let attr = le::u16(p, 4).unwrap_or(0);

    let create_raw = le::u32(p, 8).unwrap_or(0);
    let modify_raw = le::u32(p, 12).unwrap_or(0);
    let access_raw = le::u32(p, 16).unwrap_or(0);
    let (ccs, mcs) = (p[20], p[21]);
    let (ctz, mtz, atz) = (p[22], p[23], p[24]);

    let mut set = FileSet {
        deleted,
        attr,
        secondary_count,
        set_checksum: stored_sum,
        checksum_ok: None,
        secondaries_seen: 0,
        timestamps: Timestamps {
            created: Some(exfat_ts(create_raw, ccs, ctz, true)),
            modified: Some(exfat_ts(modify_raw, mcs, mtz, true)),
            accessed: Some(exfat_ts(access_raw, 0, atz, false)),
            ..Default::default()
        },
        tz_minutes: [tz_minutes(ctz), tz_minutes(mtz), tz_minutes(atz)],
        has_stream: false,
        no_fat_chain: false,
        name_len: 0,
        name_hash: 0,
        valid_len: 0,
        first_cluster: 0,
        data_len: 0,
        name: None,
    };

    let mut units: Vec<u16> = Vec::new();
    let mut seen = 0usize;
    let mut truncated = false;
    for i in 1..=secondary_count as usize {
        let off = pos + i * 32;
        let Some(s) = data.get(off..off + 32) else {
            truncated = true;
            break;
        };
        if !is_secondary(s[0]) {
            // Another primary (or EOD) interrupts the set — it is damaged.
            truncated = true;
            break;
        }
        seen += 1;
        match code(s[0]) {
            CODE_STREAM => parse_stream(s, &mut set),
            CODE_NAME => push_name_units(s, &mut units),
            _ => {} // benign secondary (vendor ext, padding…) — skip
        }
    }

    if !truncated && seen == secondary_count as usize {
        let set_bytes = &data[pos..pos + (1 + seen) * 32];
        let computed = set_checksum(set_bytes, deleted);
        set.checksum_ok = Some(computed == stored_sum);
    }

    // Assemble the name: take the first `name_len` code units.
    if set.name_len > 0 && !units.is_empty() {
        let n = (set.name_len as usize).min(units.len());
        let name = util::sanitize_name(&String::from_utf16_lossy(&units[..n]));
        if !name.is_empty() {
            set.name = Some(name);
        }
    }
    set.secondaries_seen = seen;
    Ok((set, 1 + seen))
}

/// Decode an allocation-bitmap entry: `(flags, first_cluster, data_len)`.
pub(crate) fn parse_bitmap(s: &[u8]) -> (u8, u32, u64) {
    (
        s[1],
        le::u32(s, 20).unwrap_or(0),
        le::u64(s, 24).unwrap_or(0),
    )
}

/// Decode an up-case-table entry: `(checksum, first_cluster, data_len)`.
pub(crate) fn parse_upcase(s: &[u8]) -> (u32, u32, u64) {
    (
        le::u32(s, 4).unwrap_or(0),
        le::u32(s, 20).unwrap_or(0),
        le::u64(s, 24).unwrap_or(0),
    )
}

/// Decode a volume-label entry (11 UTF-16 code units at offset 2).
pub(crate) fn parse_label(s: &[u8]) -> String {
    let count = (s[1] as usize).min(11);
    let mut units = Vec::with_capacity(count);
    for j in 0..count {
        if let Some(u) = le::u16(s, 2 + j * 2) {
            units.push(u);
        }
    }
    util::sanitize_name(&String::from_utf16_lossy(&units))
}
