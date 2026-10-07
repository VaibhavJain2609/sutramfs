//! Windows registry hive (`regf`) parser.
//!
//! Layout: a 4096-byte `regf` base block (sequence numbers, timestamp,
//! root-cell offset, bins size) followed by `hbin` blocks of cells.
//! Every cell starts with a signed `i32` size — **negative = allocated,
//! positive = free**. Cell bodies are signatured: `nk` (key), `vk`
//! (value), `sk` (security), `lf`/`lh`/`li`/`ri` (subkey lists), `db`
//! (big-data indirection).
//!
//! APIs:
//! - [`Hive::walk`] — streaming DFS over the live key tree, yielding
//!   `Result< HiveKey >` items (corrupt cells become `Err` items and the
//!   walk continues — lenient by default).
//! - [`Hive::all_keys`] — convenience `Vec` of the good keys.
//! - [`Hive::deleted_keys`] — scans **unallocated** cells for orphan
//!   `nk`/`vk` records: the classic deleted-key recovery pass.
//!
//! Cell offsets in this format are relative to the first byte after the
//! 4096-byte base block, i.e. `file_off = 0x1000 + rel`. Every public
//! record carries both (`cell_offset` and `file_offset`) for provenance.

use crate::common::{
    ansi_str, filetime, read_to_end_bounded, utf16_str, ArtifactTimestamp, Error, Result,
    DEFAULT_MAX_INPUT,
};
use std::collections::HashSet;
use std::io::Read;

/// Base block size; hbin area starts here.
pub const BASE_BLOCK: usize = 0x1000;
/// `hbin` header size; cells follow it.
pub const HBIN_HEADER: usize = 0x20;
/// No-cell sentinel.
pub const NIL: u32 = 0xFFFF_FFFF;
/// Hard cap on live keys yielded, in case of hostile loops.
pub const MAX_KEYS: usize = 4_000_000;
/// Maximum key depth.
pub const MAX_DEPTH: usize = 512;
/// Values larger than this may live in `db` big-data segments.
pub const BIG_DATA_THRESHOLD: usize = 0x4000;

/// Registry value types (`vk` field), names per MSDN.
pub fn value_type_name(ty: u32) -> &'static str {
    match ty {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        _ => "REG_UNKNOWN",
    }
}

/// Quick signature check: `regf` magic.
pub fn detect(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == b"regf"
}

/// A decoded `vk` value record.
#[derive(Debug, Clone)]
pub struct HiveValue {
    /// Value name (`"(Default)"` for the unnamed value).
    pub name: String,
    /// Registry type (`REG_*`).
    pub ty: u32,
    /// Type name.
    pub type_name: &'static str,
    /// Raw value bytes (data cell contents, inline bytes, or the
    /// reassembled `db` segments).
    pub data: Vec<u8>,
    /// Cell-relative offset of the `vk` record.
    pub cell_offset: u32,
    /// Absolute file offset of the `vk` record.
    pub file_offset: u64,
    /// Absolute offset of the data cell, `None` when the data was stored
    /// inline in the `vk` (data ≤ 4 bytes, high bit of size set).
    pub data_offset: Option<u64>,
    /// True when the value was reassembled from `db` segments.
    pub big_data: bool,
}

impl HiveValue {
    /// Interpret the data as a NUL-separated UTF-16LE string
    /// (`REG_SZ`/`REG_EXPAND_SZ`). `None` for other types.
    pub fn as_string(&self) -> Option<String> {
        match self.ty {
            1 | 2 | 6 => Some(utf16_str(&self.data)),
            _ => None,
        }
    }

    /// Interpret the data as a `REG_DWORD` (LE or BE by type).
    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() < 4 {
            return None;
        }
        let b: [u8; 4] = self.data[..4].try_into().ok()?;
        Some(match self.ty {
            4 => u32::from_le_bytes(b),
            5 => u32::from_be_bytes(b),
            _ => return None,
        })
    }

    /// Interpret the data as `REG_MULTI_SZ` (NUL-separated UTF-16LE).
    pub fn as_multi_string(&self) -> Option<Vec<String>> {
        if self.ty != 7 {
            return None;
        }
        let mut out = Vec::new();
        let mut cur = Vec::new();
        for c in self.data.chunks_exact(2) {
            let u = u16::from_le_bytes([c[0], c[1]]);
            if u == 0 {
                if !cur.is_empty() {
                    out.push(String::from_utf16_lossy(&cur));
                    cur.clear();
                }
            } else {
                cur.push(u);
            }
        }
        if !cur.is_empty() {
            out.push(String::from_utf16_lossy(&cur));
        }
        Some(out)
    }
}

/// A decoded `nk` key record (one live-tree node).
#[derive(Debug, Clone)]
pub struct HiveKey {
    /// Key name (leaf component).
    pub name: String,
    /// Full path from the hive root, `\`-joined (e.g.
    /// `ROOT\Software\Microsoft`).
    pub path: String,
    /// Cell-relative offset of the `nk` record.
    pub cell_offset: u32,
    /// Absolute file offset of the `nk` record.
    pub file_offset: u64,
    /// `LastWriteTime` FILETIME — the key's last modification.
    pub last_write: ArtifactTimestamp,
    /// Raw `nk` flags (bit 0x20 = compressed/latin-1 name, 0x04 =
    /// predefined handle, …).
    pub flags: u16,
    /// Nesting depth (root = 0).
    pub depth: usize,
    /// Decoded values of this key.
    pub values: Vec<HiveValue>,
    /// Cell offset of the `sk` security record, when present (`NIL` →
    /// `None`). SD bytes are not decoded — the offset is provenance.
    pub security_cell: Option<u32>,
    /// Optional class-name string (rarely used; UTF-16LE cell contents).
    pub class_name: Option<String>,
}

/// A record recovered from an **unallocated** cell — deleted-forensics
/// output of [`Hive::deleted_keys`].
#[derive(Debug, Clone)]
pub struct DeletedCell {
    /// `"nk"` or `"vk"`.
    pub kind: &'static str,
    /// Cell-relative offset.
    pub cell_offset: u32,
    /// Absolute file offset.
    pub file_offset: u64,
    /// Key/value name, when decodable.
    pub name: String,
    /// `nk` last-write time (`None` for `vk`).
    pub last_write: Option<ArtifactTimestamp>,
    /// For `vk`: the registry type and inline/residual data.
    pub value: Option<(u32, Vec<u8>)>,
}

/// A `hbin` region.
#[derive(Debug, Clone)]
struct Hbin {
    /// Absolute file offset of the `hbin` header.
    file_off: usize,
    /// Declared hbin size.
    size: usize,
}

/// A parsed registry hive. Owns the image so walkers can lazily
/// resolve cells.
#[derive(Debug)]
pub struct Hive {
    data: Vec<u8>,
    hbins: Vec<Hbin>,
    /// Primary/secondary sequence numbers (`Corrupt` if they differed —
    /// see `warnings` for a torn-write note).
    pub sequence: (u32, u32),
    /// Base-block last-write FILETIME (`LastReorganize`/write time).
    pub timestamp: ArtifactTimestamp,
    /// Major/minor format version (expected 1.x).
    pub version: (u32, u32),
    /// Hive file name stored in the base block (UTF-16, often the
    /// `\SystemRoot\…` path or a GUID name).
    pub name: String,
    /// Cell offset of the root `nk`.
    pub root_cell: u32,
    /// Total size of the hbin area per the base block.
    pub bins_size: u32,
    /// Non-fatal problems found at mount (torn sequence, stray hbin
    /// bytes, …).
    pub warnings: Vec<String>,
}

impl Hive {
    /// Parse a hive image. The base block and hbin chain are strict
    /// about magic but lenient about interior corruption (recorded in
    /// [`Hive::warnings`]).
    pub fn parse(data: &[u8]) -> Result<Hive> {
        if data.len() < BASE_BLOCK {
            return Err(Error::Truncated {
                offset: 0,
                needed: BASE_BLOCK as u64,
                available: data.len() as u64,
            });
        }
        if &data[..4] != b"regf" {
            return Err(Error::Corrupt {
                offset: 0,
                msg: "bad regf magic".into(),
            });
        }
        let rd = |off: usize| -> u32 {
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        };
        let seq = (rd(4), rd(8));
        let mut warnings = Vec::new();
        if seq.0 != seq.1 {
            warnings.push(format!(
                "torn write: primary seq {} != secondary {}",
                seq.0, seq.1
            ));
        }
        let timestamp = filetime(u64::from_le_bytes(
            data[0x0C..0x14].try_into().unwrap_or([0; 8]),
        ));
        let version = (rd(0x14), rd(0x18));
        if version.0 != 1 {
            warnings.push(format!("unusual hive version {}.{}", version.0, version.1));
        }
        let root_cell = rd(0x24);
        let bins_size = rd(0x28);
        let name = utf16_str(&data[0x30..0x30 + 64]);

        // Walk the hbin chain starting at 0x1000.
        let mut hbins = Vec::new();
        let mut off = BASE_BLOCK;
        while off + HBIN_HEADER <= data.len() {
            if &data[off..off + 4] != b"hbin" {
                warnings.push(format!("no hbin sig at {off:#x}; stopping scan"));
                break;
            }
            let size = u32::from_le_bytes([
                data[off + 8],
                data[off + 9],
                data[off + 10],
                data[off + 11],
            ]) as usize;
            if size < HBIN_HEADER || off.checked_add(size).is_none_or(|e| e > data.len()) {
                warnings.push(format!("bad hbin size {size:#x} at {off:#x}"));
                break;
            }
            hbins.push(Hbin {
                file_off: off,
                size,
            });
            off += size;
        }
        if hbins.is_empty() {
            return Err(Error::Corrupt {
                offset: BASE_BLOCK as u64,
                msg: "no valid hbin blocks".into(),
            });
        }
        let hive = Hive {
            data: data.to_vec(),
            hbins,
            sequence: seq,
            timestamp,
            version,
            name,
            root_cell,
            bins_size,
            warnings,
        };
        // Root cell must resolve to an allocated nk.
        match hive.cell_body(hive.root_cell) {
            Ok((body, true, _)) if body.len() >= 0x4C && &body[..2] == b"nk" => {}
            Ok((body, true, _)) if body.len() >= 2 => {
                return Err(Error::Corrupt {
                    offset: (BASE_BLOCK + hive.root_cell as usize) as u64,
                    msg: format!(
                        "root cell is '{}', not 'nk'",
                        String::from_utf8_lossy(&body[..2])
                    ),
                });
            }
            Ok(_) => {
                return Err(Error::Corrupt {
                    offset: (BASE_BLOCK + hive.root_cell as usize) as u64,
                    msg: "root cell unallocated or undersized".into(),
                });
            }
            Err(e) => return Err(e),
        }
        Ok(hive)
    }

    /// Parse from any `Read`, bounded at `DEFAULT_MAX_INPUT` bytes.
    pub fn from_reader(r: impl Read) -> Result<Hive> {
        Self::parse(&read_to_end_bounded(r, DEFAULT_MAX_INPUT)?)
    }

    /// Resolve a cell-relative offset: returns `(body, allocated,
    /// file_off)` where `body` excludes the 4-byte size word.
    fn cell_body(&self, rel: u32) -> Result<(&[u8], bool, usize)> {
        if rel == NIL {
            return Err(Error::Corrupt {
                offset: u64::from(rel),
                msg: "nil cell reference".into(),
            });
        }
        let off = BASE_BLOCK
            .checked_add(rel as usize)
            .ok_or(Error::Corrupt {
                offset: u64::from(rel),
                msg: "cell offset overflow".into(),
            })?;
        if off + 4 > self.data.len() {
            return Err(Error::Truncated {
                offset: off as u64,
                needed: 4,
                available: self.data.len().saturating_sub(off) as u64,
            });
        }
        // Must lie inside a known hbin's cell area.
        let in_hbin = self
            .hbins
            .iter()
            .any(|h| off >= h.file_off + HBIN_HEADER && off < h.file_off + h.size);
        if !in_hbin {
            return Err(Error::Corrupt {
                offset: off as u64,
                msg: format!("cell rel {rel:#x} outside hbin cells"),
            });
        }
        let raw = i32::from_le_bytes([
            self.data[off],
            self.data[off + 1],
            self.data[off + 2],
            self.data[off + 3],
        ]);
        let size = raw.unsigned_abs() as usize;
        if size < 4 || off + size > self.data.len() {
            return Err(Error::Corrupt {
                offset: off as u64,
                msg: format!("cell size {size:#x} overruns image"),
            });
        }
        Ok((
            &self.data[off + 4..off + size],
            raw < 0,
            off,
        ))
    }

    /// Streaming DFS over the live key tree. Corrupt substructures yield
    /// `Err` items and iteration continues.
    pub fn walk(&self) -> HiveWalker<'_> {
        HiveWalker::new(self)
    }

    /// Collect all successfully-decoded live keys.
    pub fn all_keys(&self) -> Vec<HiveKey> {
        self.walk().filter_map(|r| r.ok()).collect()
    }

    /// Scan every hbin's **free** cells for orphan `nk`/`vk` signatures —
    /// the deleted-key recovery pass. Recovered records are decoded
    /// best-effort; their subkey/value links may dangle and are reported
    /// but not followed.
    pub fn deleted_keys(&self) -> Vec<DeletedCell> {
        let mut out = Vec::new();
        for h in &self.hbins {
            let mut off = h.file_off + HBIN_HEADER;
            let end = h.file_off + h.size;
            let mut guard = 0usize;
            while off + 4 <= end && off + 4 <= self.data.len() && guard < 1_000_000 {
                guard += 1;
                let raw = i32::from_le_bytes([
                    self.data[off],
                    self.data[off + 1],
                    self.data[off + 2],
                    self.data[off + 3],
                ]);
                let size = raw.unsigned_abs() as usize;
                if size < 4 || off + size > end || off + size > self.data.len() {
                    break; // corrupt cell chain — stop this hbin
                }
                if raw > 0 {
                    // Free cell — inspect the residue.
                    let body = &self.data[off + 4..off + size];
                    let rel = (off - BASE_BLOCK) as u32;
                    if body.len() >= 0x4C && &body[..2] == b"nk" {
                        if let Some(k) = decode_nk(body, rel, off, self) {
                            out.push(DeletedCell {
                                kind: "nk",
                                cell_offset: rel,
                                file_offset: off as u64,
                                name: k.name,
                                last_write: Some(k.last_write),
                                value: None,
                            });
                        }
                    } else if body.len() >= 0x14 && &body[..2] == b"vk" {
                        if let Some(v) = decode_vk(body, rel, off, self) {
                            out.push(DeletedCell {
                                kind: "vk",
                                cell_offset: rel,
                                file_offset: off as u64,
                                name: v.name,
                                last_write: None,
                                value: Some((v.ty, v.data)),
                            });
                        }
                    }
                }
                off += size;
            }
        }
        out
    }

    /// Follow a subkey list cell → vec of child `nk` cell offsets.
    /// Handles `lf`, `lh`, `li`, and `ri` (indirect) containers.
    fn subkey_offsets(&self, list_rel: u32, expect: u32, depth: usize) -> Result<Vec<u32>> {
        if list_rel == NIL || expect == 0 || depth > 8 {
            return Ok(Vec::new());
        }
        let (body, alloc, off) = self.cell_body(list_rel)?;
        if !alloc {
            return Err(Error::Corrupt {
                offset: off as u64,
                msg: "subkey list in free cell".into(),
            });
        }
        if body.len() < 4 {
            return Err(Error::Corrupt {
                offset: off as u64,
                msg: "subkey list undersized".into(),
            });
        }
        let sig = &body[..2];
        let count = u16::from_le_bytes([body[2], body[3]]) as usize;
        match sig {
            b"lf" | b"lh" => {
                let need = 4 + count.saturating_mul(8);
                if need > body.len() {
                    return Err(Error::Corrupt {
                        offset: off as u64,
                        msg: format!("{sig:?} list count {count} overruns cell"),
                    });
                }
                let mut out = Vec::with_capacity(count);
                for i in 0..count {
                    let p = 4 + i * 8;
                    out.push(u32::from_le_bytes([
                        body[p],
                        body[p + 1],
                        body[p + 2],
                        body[p + 3],
                    ]));
                }
                Ok(out)
            }
            b"li" | b"ri" => {
                let need = 4 + count.saturating_mul(4);
                if need > body.len() {
                    return Err(Error::Corrupt {
                        offset: off as u64,
                        msg: format!("{sig:?} list count {count} overruns cell"),
                    });
                }
                let mut out = Vec::new();
                for i in 0..count {
                    let p = 4 + i * 4;
                    let sub = u32::from_le_bytes([body[p], body[p + 1], body[p + 2], body[p + 3]]);
                    if sig == b"li" {
                        out.push(sub);
                    } else {
                        // ri → recurse into each sub-list
                        out.extend(self.subkey_offsets(sub, expect, depth + 1)?);
                    }
                }
                Ok(out)
            }
            _ => Err(Error::Corrupt {
                offset: off as u64,
                msg: format!(
                    "unexpected subkey list sig '{}'",
                    String::from_utf8_lossy(sig)
                ),
            }),
        }
    }

    /// Decode the value list cell of a key → decoded `HiveValue`s.
    fn key_values(&self, list_rel: u32, count: usize, warnings: &mut Vec<Error>) -> Vec<HiveValue> {
        let mut out = Vec::new();
        if count == 0 || list_rel == NIL {
            return out;
        }
        let (body, alloc, off) = match self.cell_body(list_rel) {
            Ok(t) => t,
            Err(e) => {
                warnings.push(e);
                return out;
            }
        };
        if !alloc {
            warnings.push(Error::Corrupt {
                offset: off as u64,
                msg: "value list in free cell".into(),
            });
            return out;
        }
        let need = count.saturating_mul(4);
        if need > body.len() {
            warnings.push(Error::Corrupt {
                offset: off as u64,
                msg: format!("value list count {count} overruns cell"),
            });
            return out;
        }
        for i in 0..count.min(0x10000) {
            let p = i * 4;
            let vrel = u32::from_le_bytes([body[p], body[p + 1], body[p + 2], body[p + 3]]);
            match self.cell_body(vrel) {
                Ok((vb, true, voff)) if vb.len() >= 0x14 && &vb[..2] == b"vk" => {
                    match decode_vk(vb, vrel, voff, self) {
                        Some(v) => out.push(v),
                        None => warnings.push(Error::Corrupt {
                            offset: voff as u64,
                            msg: "vk decode failed".into(),
                        }),
                    }
                }
                Ok((_, _, voff)) => warnings.push(Error::Corrupt {
                    offset: voff as u64,
                    msg: "value ref not an allocated vk".into(),
                }),
                Err(e) => warnings.push(e),
            }
        }
        out
    }

    /// Resolve a `vk` data cell, following `db` big-data indirection.
    fn vk_data(&self, data_rel: u32, size: usize) -> Result<(Vec<u8>, u64, bool)> {
        let (body, alloc, off) = self.cell_body(data_rel)?;
        if !alloc {
            return Err(Error::Corrupt {
                offset: off as u64,
                msg: "vk data in free cell".into(),
            });
        }
        if body.len() >= 8 && &body[..2] == b"db" && size > BIG_DATA_THRESHOLD {
            // db: count u16 @2, segment-list cell u32 @4.
            let seg_count = u16::from_le_bytes([body[2], body[3]]) as usize;
            let list_rel = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            let (lb, la, loff) = self.cell_body(list_rel)?;
            if !la || lb.len() < seg_count * 4 {
                return Err(Error::Corrupt {
                    offset: loff as u64,
                    msg: "db segment list bad".into(),
                });
            }
            let mut buf = Vec::with_capacity(size);
            for i in 0..seg_count {
                let p = i * 4;
                let srel = u32::from_le_bytes([lb[p], lb[p + 1], lb[p + 2], lb[p + 3]]);
                let (sb, sa, soff) = self.cell_body(srel)?;
                if !sa {
                    return Err(Error::Corrupt {
                        offset: soff as u64,
                        msg: "db segment in free cell".into(),
                    });
                }
                buf.extend_from_slice(&sb[..sb.len().min(size - buf.len().min(size))]);
            }
            buf.truncate(size);
            return Ok((buf, off as u64, true));
        }
        let take = size.min(body.len());
        Ok((body[..take].to_vec(), off as u64, false))
    }
}

/// Decode an `nk` cell body into a [`HiveKey`] (values resolved by the
/// caller — `decode_nk` leaves `values` empty except via `hive`).
fn decode_nk(body: &[u8], rel: u32, off: usize, hive: &Hive) -> Option<HiveKey> {
    if body.len() < 0x4C {
        return None;
    }
    let flags = u16::from_le_bytes([body[2], body[3]]);
    let last_write = filetime(u64::from_le_bytes(body[4..12].try_into().ok()?));
    let name_len = u16::from_le_bytes([body[0x48], body[0x49]]) as usize;
    let class_len = u16::from_le_bytes([body[0x4A], body[0x4B]]) as usize;
    let name_raw = body.get(0x4C..0x4C + name_len)?;
    let name = if flags & 0x20 != 0 {
        ansi_str(name_raw)
    } else {
        utf16_str(name_raw)
    };
    let sk = u32::from_le_bytes(body[0x2C..0x30].try_into().ok()?);
    let class_rel = u32::from_le_bytes(body[0x30..0x34].try_into().ok()?);
    let class_name = if class_len > 0 && class_rel != NIL {
        hive
            .cell_body(class_rel)
            .ok()
            .and_then(|(b, a, _)| if a { Some(utf16_str(&b[..b.len().min(class_len)])) } else { None })
    } else {
        None
    };
    Some(HiveKey {
        name,
        path: String::new(), // filled by walker
        cell_offset: rel,
        file_offset: off as u64,
        last_write,
        flags,
        depth: 0,
        values: Vec::new(),
        security_cell: if sk != NIL { Some(sk) } else { None },
        class_name,
    })
}

/// Decode a `vk` cell body.
fn decode_vk(body: &[u8], rel: u32, off: usize, hive: &Hive) -> Option<HiveValue> {
    if body.len() < 0x14 {
        return None;
    }
    let name_len = u16::from_le_bytes([body[2], body[3]]) as usize;
    let raw_size = u32::from_le_bytes(body[4..8].try_into().ok()?);
    let data_rel = u32::from_le_bytes(body[8..12].try_into().ok()?);
    let ty = u32::from_le_bytes(body[12..16].try_into().ok()?);
    let flags = u16::from_le_bytes([body[16], body[17]]);
    let name_raw = body.get(0x14..0x14 + name_len).unwrap_or(&[]);
    let name = if name_len == 0 {
        "(Default)".to_string()
    } else if flags & 1 != 0 {
        ansi_str(name_raw)
    } else {
        utf16_str(name_raw)
    };
    let (data, data_offset, big_data) = if raw_size & 0x8000_0000 != 0 {
        // Inline: low bytes of the data-offset field hold the data.
        let n = (raw_size & 0x7FFF_FFFF).min(4) as usize;
        (body[8..8 + n].to_vec(), None, false)
    } else {
        match hive.vk_data(data_rel, raw_size as usize) {
            Ok((d, doff, big)) => (d, Some(doff), big),
            Err(_) => (Vec::new(), None, false), // dangling data ptr — keep metadata
        }
    };
    Some(HiveValue {
        name,
        ty,
        type_name: value_type_name(ty),
        data,
        cell_offset: rel,
        file_offset: off as u64,
        data_offset,
        big_data,
    })
}

/// Streaming DFS iterator over live keys. Yields `Result<HiveKey>`;
/// corrupt branches produce `Err` items and are pruned, not fatal.
pub struct HiveWalker<'h> {
    hive: &'h Hive,
    /// Stack of `(nk_cell_rel, parent_path, depth)`.
    stack: Vec<(u32, String, usize)>,
    visited: HashSet<u32>,
    yielded: usize,
    /// Errors discovered while expanding a node are queued so the next
    /// `next()` returns them before continuing.
    pending: std::collections::VecDeque<Error>,
    done: bool,
}

impl<'h> HiveWalker<'h> {
    fn new(hive: &'h Hive) -> Self {
        HiveWalker {
            hive,
            stack: vec![(hive.root_cell, String::new(), 0)],
            visited: HashSet::new(),
            yielded: 0,
            pending: std::collections::VecDeque::new(),
            done: false,
        }
    }
}

impl Iterator for HiveWalker<'_> {
    type Item = Result<HiveKey>;

    fn next(&mut self) -> Option<Result<HiveKey>> {
        loop {
            if let Some(e) = self.pending.pop_front() {
                return Some(Err(e));
            }
            if self.done || self.yielded >= MAX_KEYS {
                return None;
            }
            let (rel, parent, depth) = self.stack.pop()?;
            if !self.visited.insert(rel) {
                self.pending.push_back(Error::Corrupt {
                    offset: (BASE_BLOCK + rel as usize) as u64,
                    msg: "cycle in subkey graph".into(),
                });
                continue;
            }
            if depth > MAX_DEPTH {
                self.pending.push_back(Error::Corrupt {
                    offset: (BASE_BLOCK + rel as usize) as u64,
                    msg: "depth cap".into(),
                });
                continue;
            }
            match self.hive.cell_body(rel) {
                Ok((body, true, off)) if body.len() >= 0x4C && &body[..2] == b"nk" => {
                    let mut key = match decode_nk(body, rel, off, self.hive) {
                        Some(k) => k,
                        None => {
                            self.pending.push_back(Error::Corrupt {
                                offset: off as u64,
                                msg: "nk decode failed".into(),
                            });
                            continue;
                        }
                    };
                    key.depth = depth;
                    key.path = if parent.is_empty() {
                        key.name.clone()
                    } else {
                        format!("{parent}\\{}", key.name)
                    };
                    // Expand subkeys.
                    let sub_count =
                        u32::from_le_bytes(body[0x14..0x18].try_into().unwrap_or([0; 4]));
                    let sub_list =
                        u32::from_le_bytes(body[0x1C..0x20].try_into().unwrap_or([0; 4]));
                    match self.hive.subkey_offsets(sub_list, sub_count, 0) {
                        Ok(subs) => {
                            for s in subs {
                                if self.stack.len() < MAX_KEYS {
                                    self.stack.push((s, key.path.clone(), depth + 1));
                                }
                            }
                        }
                        Err(e) => self.pending.push_back(e),
                    }
                    // Decode values; per-value errors queue as Err items.
                    let val_count =
                        u32::from_le_bytes(body[0x24..0x28].try_into().unwrap_or([0; 4]));
                    let val_list =
                        u32::from_le_bytes(body[0x28..0x2C].try_into().unwrap_or([0; 4]));
                    let mut werr = Vec::new();
                    key.values =
                        self.hive
                            .key_values(val_list, val_count as usize, &mut werr);
                    for e in werr {
                        self.pending.push_back(e);
                    }
                    self.yielded += 1;
                    return Some(Ok(key));
                }
                Ok((_, _, off)) => {
                    self.pending.push_back(Error::Corrupt {
                        offset: off as u64,
                        msg: "cell not an allocated nk".into(),
                    });
                    continue;
                }
                Err(e) => {
                    self.pending.push_back(e);
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic hive builder.
    ///
    /// ```text
    /// base block (0x1000)
    /// hbin @ 0x1000, size 0x1000
    ///   cells: rel offsets assigned by `add_cell`
    /// ```
    struct HiveBuilder {
        cells: Vec<(u32, Vec<u8>)>, // (rel_offset, cell bytes incl size word)
        next_rel: u32,
    }

    impl HiveBuilder {
        fn new() -> Self {
            HiveBuilder {
                cells: Vec::new(),
                next_rel: HBIN_HEADER as u32, // first cell after hbin hdr
            }
        }
        /// Add a cell body (without size word); returns its rel offset.
        fn cell(&mut self, body: &[u8], allocated: bool) -> u32 {
            let rel = self.next_rel;
            let size = (body.len() + 4 + 7) & !7; // 8-align
            let mut c = Vec::with_capacity(size);
            let sz: i32 = if allocated {
                -(size as i32)
            } else {
                size as i32
            };
            c.extend_from_slice(&sz.to_le_bytes());
            c.extend_from_slice(body);
            c.resize(size, 0);
            self.cells.push((rel, c));
            self.next_rel += size as u32;
            rel
        }
        fn nk(&mut self, name: &str, sub_list: u32, sub_count: u32, val_list: u32, val_count: u32, ts: u64) -> u32 {
            let mut b = vec![0u8; 0x4C];
            b[0] = b'n';
            b[1] = b'k';
            b[2..4].copy_from_slice(&0x20u16.to_le_bytes()); // ascii name
            b[4..12].copy_from_slice(&ts.to_le_bytes());
            b[0x10..0x14].copy_from_slice(&NIL.to_le_bytes()); // parent
            b[0x14..0x18].copy_from_slice(&sub_count.to_le_bytes());
            b[0x18..0x1C].copy_from_slice(&0u32.to_le_bytes());
            b[0x1C..0x20].copy_from_slice(&sub_list.to_le_bytes());
            b[0x20..0x24].copy_from_slice(&NIL.to_le_bytes());
            b[0x24..0x28].copy_from_slice(&val_count.to_le_bytes());
            b[0x28..0x2C].copy_from_slice(&val_list.to_le_bytes());
            b[0x2C..0x30].copy_from_slice(&NIL.to_le_bytes()); // sk
            b[0x30..0x34].copy_from_slice(&NIL.to_le_bytes()); // class
            b[0x48..0x4A].copy_from_slice(&(name.len() as u16).to_le_bytes());
            b.extend_from_slice(name.as_bytes());
            self.cell(&b, true)
        }
        fn vk(&mut self, name: &str, ty: u32, data_rel: u32, size: u32) -> u32 {
            let mut b = vec![0u8; 0x14];
            b[0] = b'v';
            b[1] = b'k';
            b[2..4].copy_from_slice(&(name.len() as u16).to_le_bytes());
            b[4..8].copy_from_slice(&size.to_le_bytes());
            b[8..12].copy_from_slice(&data_rel.to_le_bytes());
            b[12..16].copy_from_slice(&ty.to_le_bytes());
            b[16..18].copy_from_slice(&1u16.to_le_bytes()); // ascii name
            b.extend_from_slice(name.as_bytes());
            self.cell(&b, true)
        }
        fn lf(&mut self, kids: &[u32]) -> u32 {
            let mut b = vec![0u8; 4];
            b[0] = b'l';
            b[1] = b'f';
            b[2..4].copy_from_slice(&(kids.len() as u16).to_le_bytes());
            for &k in kids {
                b.extend_from_slice(&k.to_le_bytes());
                b.extend_from_slice(&0u32.to_le_bytes()); // hash
            }
            self.cell(&b, true)
        }
        fn val_list(&mut self, vs: &[u32]) -> u32 {
            let mut b = Vec::new();
            for &v in vs {
                b.extend_from_slice(&v.to_le_bytes());
            }
            self.cell(&b, true)
        }
        fn data(&mut self, bytes: &[u8]) -> u32 {
            self.cell(bytes, true)
        }
        /// Add a *free* cell containing residue bytes.
        fn free_cell(&mut self, body: &[u8]) -> u32 {
            self.cell(body, false)
        }
        fn build(self, root: u32) -> Vec<u8> {
            let hbin_size: usize = 0x1000;
            let mut img = vec![0u8; BASE_BLOCK + hbin_size];
            img[0..4].copy_from_slice(b"regf");
            img[4..8].copy_from_slice(&1u32.to_le_bytes());
            img[8..12].copy_from_slice(&1u32.to_le_bytes());
            img[0x0C..0x14].copy_from_slice(&133_000_000_000_000_000u64.to_le_bytes());
            img[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // major
            img[0x18..0x1C].copy_from_slice(&3u32.to_le_bytes()); // minor
            img[0x24..0x28].copy_from_slice(&root.to_le_bytes());
            img[0x28..0x2C].copy_from_slice(&(hbin_size as u32).to_le_bytes());
            // hive name
            let nm: Vec<u16> = "SYSTEM".encode_utf16().collect();
            for (i, u) in nm.iter().enumerate() {
                img[0x30 + 2 * i..0x32 + 2 * i].copy_from_slice(&u.to_le_bytes());
            }
            img[BASE_BLOCK..BASE_BLOCK + 4].copy_from_slice(b"hbin");
            img[BASE_BLOCK + 8..BASE_BLOCK + 12]
                .copy_from_slice(&(hbin_size as u32).to_le_bytes());
            for (rel, c) in self.cells {
                let off = BASE_BLOCK + rel as usize;
                img[off..off + c.len()].copy_from_slice(&c);
            }
            img
        }
    }

    fn sample() -> Vec<u8> {
        let mut h = HiveBuilder::new();
        // values for child key
        let d1 = h.data(b"\x2a\x00\x00\x00"); // REG_DWORD 42
        let v1 = h.vk("Count", 4, d1, 4);
        let s = "hello";
        let mut utf: Vec<u8> = Vec::new();
        for u in s.encode_utf16() {
            utf.extend_from_slice(&u.to_le_bytes());
        }
        utf.extend_from_slice(&[0, 0]);
        let d2 = h.data(&utf);
        let v2 = h.vk("", 1, d2, utf.len() as u32); // default REG_SZ
        // inline value (size high bit)
        let mut ib = vec![0u8; 0x14];
        ib[0] = b'v';
        ib[1] = b'k';
        ib[2..4].copy_from_slice(&3u16.to_le_bytes());
        ib[4..8].copy_from_slice(&(0x8000_0000u32 | 4).to_le_bytes());
        ib[8..12].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        ib[12..16].copy_from_slice(&4u32.to_le_bytes());
        ib[16..18].copy_from_slice(&1u16.to_le_bytes());
        ib.extend_from_slice(b"Inl");
        let v3 = h.cell(&ib, true);
        let vl = h.val_list(&[v1, v2, v3]);
        let child = h.nk("Child", NIL, 0, vl, 3, 0x1122);
        let lf = h.lf(&[child]);
        let root = h.nk("ROOT", lf, 1, NIL, 0, 0x3344);
        // deleted residue: an nk in a free cell
        let mut dead = vec![0u8; 0x4C];
        dead[0] = b'n';
        dead[1] = b'k';
        dead[2..4].copy_from_slice(&0x20u16.to_le_bytes());
        dead[4..12].copy_from_slice(&0xAA55u64.to_le_bytes());
        dead[0x48..0x4A].copy_from_slice(&7u16.to_le_bytes());
        dead.extend_from_slice(b"Deleted");
        h.free_cell(&dead);
        h.build(root)
    }

    #[test]
    fn parses_hive_tree() {
        let img = sample();
        assert!(detect(&img));
        let hive = Hive::parse(&img).expect("parse");
        assert_eq!(hive.name, "SYSTEM");
        assert_eq!(hive.version, (1, 3));
        let keys = hive.all_keys();
        assert_eq!(keys.len(), 2);
        let root = &keys[0];
        assert_eq!(root.name, "ROOT");
        assert_eq!(root.path, "ROOT");
        assert_eq!(root.last_write.raw_value, 0x3344);
        let child = keys.iter().find(|k| k.name == "Child").expect("child");
        assert_eq!(child.path, "ROOT\\Child");
        assert_eq!(child.depth, 1);
        assert_eq!(child.values.len(), 3);
        let count = child.values.iter().find(|v| v.name == "Count").unwrap();
        assert_eq!(count.as_u32(), Some(42));
        let def = child.values.iter().find(|v| v.name == "(Default)").unwrap();
        assert_eq!(def.as_string().as_deref(), Some("hello"));
        let inl = child.values.iter().find(|v| v.name == "Inl").unwrap();
        assert_eq!(inl.as_u32(), Some(0xDEADBEEF));
        assert!(inl.data_offset.is_none());
    }

    #[test]
    fn deleted_keys_found() {
        let hive = Hive::parse(&sample()).expect("parse");
        let del = hive.deleted_keys();
        assert_eq!(del.len(), 1);
        assert_eq!(del[0].kind, "nk");
        assert_eq!(del[0].name, "Deleted");
        assert_eq!(
            del[0].last_write.as_ref().map(|t| t.raw_value),
            Some(0xAA55)
        );
    }

    #[test]
    fn corrupt_cell_yields_err_item_not_panic() {
        let mut img = sample();
        // Corrupt the root's subkey list pointer to out-of-bounds.
        // root nk is at some offset; find "ROOT" name.
        let pos = img.windows(4).position(|w| w == b"ROOT").unwrap() - 0x4C;
        // `pos` is the nk body start; subkey list field lives at +0x1C.
        img[pos + 0x1C..pos + 0x20].copy_from_slice(&0x00FF_FFF0u32.to_le_bytes());
        let hive = Hive::parse(&img).expect("parse");
        let results: Vec<_> = hive.walk().collect();
        // root itself yields; bad child list → Err item, no child.
        assert!(results.iter().any(|r| r.is_ok()));
        assert!(results.iter().any(|r| r.is_err()));
    }

    #[test]
    fn cycle_safe() {
        let mut h = HiveBuilder::new();
        // a's subkey list points to b, b's points to a → cycle.
        // Build list cells first with placeholder, then patch.
        let lf_b = h.lf(&[0xDEAD_BEEF]); // patch later — instead build directly
        let a = h.nk("A", lf_b, 1, NIL, 0, 1);
        let lf_a = h.lf(&[a]);
        let b = h.nk("B", lf_a, 1, NIL, 0, 1);
        let mut img = h.build(a);
        // patch lf_b's single entry (at cell body +4) to point at b
        let lf_b_off = BASE_BLOCK + lf_b as usize;
        // find lf_b body: cell at lf_b_off; body starts +4; entries +4
        img[lf_b_off + 8..lf_b_off + 12].copy_from_slice(&b.to_le_bytes());
        let hive = Hive::parse(&img).expect("parse");
        let keys = hive.all_keys(); // must terminate
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn truncated_and_garbage() {
        let img = sample();
        for cut in 0..img.len().min(0x1400) {
            let _ = Hive::parse(&img[..cut]);
        }
        for i in 0..img.len() {
            let mut m = img.clone();
            m[i] ^= 0xFF;
            if let Ok(h) = Hive::parse(&m) {
                let _ = h.all_keys();
                let _ = h.deleted_keys();
            }
        }
    }

    #[test]
    fn rejects_non_regf() {
        assert!(matches!(
            Hive::parse(b"not a hive"),
            Err(Error::Truncated { .. })
        ));
        let mut b = vec![0u8; BASE_BLOCK + 0x1000];
        assert!(matches!(Hive::parse(&b), Err(Error::Corrupt { .. })));
        b[0..4].copy_from_slice(b"regf");
        // no hbin → corrupt
        assert!(matches!(Hive::parse(&b), Err(Error::Corrupt { .. })));
    }
}
