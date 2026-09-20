//! ext4 directory decoding.
//!
//! Directories are sequences of `ext4_dir_entry_2` records inside the
//! directory's data blocks (one record never crosses a block boundary):
//!
//! ```text
//! u32 inode | u16 rec_len | u8 name_len | u8 file_type | name[name_len]
//! ```
//!
//! `rec_len` covers the entry plus padding to the next entry. When ext4
//! deletes an entry it merges its `rec_len` into the previous entry (or
//! zeroes `inode` for the first entry of a block) — the bytes survive as
//! **dirent slack**, which [`carve_slack`] scans for deleted names.
//!
//! HTree (dir_index): indexed directories store their leaf blocks in the
//! same linear dirent format — a linear scan of all directory blocks is
//! *correct*, merely slower than hash lookup. The `dx_root`/`dx_node`
//! interior blocks contain `ext4_dx_entry` hash tables, not dirents; they
//! are parsed as such (skipped — `inode`/`rec_len` look like garbage) which
//! is safe because parsing is lenient. See README "Known limitations".

use sutram_fs::util;
use sutram_io::le;

/// `file_type` values (ext2_ft / ext4_ft).
pub(crate) const FT_REG: u8 = 1;
pub(crate) const FT_DIR: u8 = 2;
pub(crate) const FT_SYMLINK: u8 = 7;
pub(crate) const FT_MAX: u8 = 7;

/// A raw decoded dirent (live or slack-carved).
#[derive(Debug, Clone)]
pub(crate) struct RawDirent {
    /// Offset of this record within the directory-data buffer.
    pub pos: usize,
    /// Referenced inode (0 = inode field cleared on delete).
    pub ino: u32,
    pub rec_len: u16,
    pub file_type: u8,
    /// Sanitised lossy name.
    pub name: String,
    /// Dead space inside this entry's `rec_len` (offset,len within the
    /// dir-data buffer) that may hold carved deleted dirents.
    pub slack: Option<(usize, usize)>,
}

#[inline]
fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Minimal dirent footprint for a name of `name_len` bytes.
fn min_rec_len(name_len: u8) -> usize {
    align4(8 + name_len as usize)
}

/// Try to decode a dirent header at `pos`, requiring it to fit inside
/// `end`. Returns the fields and name bounds on success.
fn header_at(buf: &[u8], pos: usize, end: usize) -> Option<(u32, u16, u8, u8)> {
    if pos + 8 > end || pos + 8 > buf.len() {
        return None;
    }
    let ino = le::u32(buf, pos)?;
    let rec_len = le::u16(buf, pos + 4)?;
    let name_len = le::u8(buf, pos + 6)?;
    let file_type = le::u8(buf, pos + 7)?;
    if rec_len < 8 || rec_len % 4 != 0 {
        return None;
    }
    if pos + rec_len as usize > end {
        return None;
    }
    Some((ino, rec_len, name_len, file_type))
}

/// Decode one live-format dirent at `pos` (block-relative). `end` is the
/// containing block's end offset in `buf`.
pub(crate) fn dirent_at(buf: &[u8], pos: usize, end: usize) -> Option<RawDirent> {
    let (ino, rec_len, name_len, file_type) = header_at(buf, pos, end)?;
    if name_len as usize > rec_len as usize - 8 {
        return None;
    }
    let name_raw = le::get(buf, pos + 8, name_len as usize)?;
    let name = util::sanitize_name(&String::from_utf8_lossy(name_raw));
    let min = min_rec_len(name_len);
    let slack = if rec_len as usize > min + 8 {
        Some((pos + min, rec_len as usize - min))
    } else {
        None
    };
    Some(RawDirent {
        pos,
        ino,
        rec_len,
        file_type,
        name,
        slack,
    })
}

/// Does a name look like a plausible dirent name? Reject bytes ext4 can
/// never store (`NUL`, `/`) and pure-control names — keeps slack carving
/// honest without forbidding UTF-8.
fn plausible_name(raw: &[u8]) -> bool {
    !raw.is_empty()
        && raw.iter().all(|&b| b != 0 && b != b'/')
        && raw.iter().any(|&b| b >= 0x20)
}

/// Scan a slack region `[start, start+len)` inside a directory block for
/// deleted dirents. Candidates must validate as dirents whose `rec_len`
/// stays inside `block_end` (stale `rec_len`s never crossed the original
/// block boundary). Advances by 4 bytes; a hit skips ahead by its rec_len
/// so a carved entry's interior can't re-match.
pub(crate) fn carve_slack(
    buf: &[u8],
    start: usize,
    len: usize,
    block_end: usize,
) -> Vec<RawDirent> {
    let mut out = Vec::new();
    let slack_end = start.saturating_add(len).min(block_end).min(buf.len());
    let mut p = start;
    while p + 12 <= slack_end {
        match header_at(buf, p, block_end) {
            Some((ino, rec_len, name_len, file_type))
                if rec_len >= 12
                    && name_len >= 1
                    && (name_len as usize) <= rec_len as usize - 8
                    && file_type <= FT_MAX =>
            {
                let name_raw = &buf[p + 8..p + 8 + name_len as usize];
                if plausible_name(name_raw) {
                    out.push(RawDirent {
                        pos: p,
                        ino,
                        rec_len,
                        file_type,
                        name: util::sanitize_name(&String::from_utf8_lossy(name_raw)),
                        slack: None,
                    });
                    p += rec_len as usize;
                    continue;
                }
                p += 4;
            }
            _ => p += 4,
        }
    }
    out
}
