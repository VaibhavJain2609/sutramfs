//! Apple binary property list (`bplist00`) parser.
//!
//! Layout: `"bplist00"` header, an object table of tagged records, an
//! offset table (big-endian `u64` per object) and a 32-byte trailer that
//! locates them. Types: null/bool/fill, int (1/2/4/8/16-byte BE), real
//! (4/8-byte BE IEEE-754), date (8-byte BE double, seconds since the
//! 2001-01-01 Mac epoch), data, ASCII/UTF-8/UTF-16BE strings, uid,
//! array, dict.
//!
//! Safety: the object-reference graph is untrusted — cyclic or
//! self-referencing objects are bounded by a recursion-depth cap *and* a
//! total-node budget, so hostile tables cannot blow the stack or memory.

use crate::common::{
    mac_absolute_time, read_to_end_bounded, unix_nanos, ArtifactTimestamp, Cursor, Error, Result,
    DEFAULT_MAX_INPUT,
};
use std::fmt::Write as _;
use std::io::Read;

/// The `bplist00` magic.
pub const MAGIC: &[u8; 8] = b"bplist00";
/// Trailer size in bytes.
pub const TRAILER_LEN: usize = 32;
/// Maximum container nesting depth accepted.
pub const MAX_DEPTH: usize = 128;

/// A decoded property-list value.
#[derive(Debug, Clone, PartialEq)]
pub enum Plist {
    /// `null`/`fill` simple object.
    Null,
    /// Boolean.
    Bool(bool),
    /// Integer (16-byte objects can exceed `i64`, so `i128`).
    Int(i128),
    /// IEEE-754 real.
    Real(f64),
    /// Mac absolute-time date (8-byte double since 2001-01-01 UTC).
    Date(ArtifactTimestamp),
    /// Raw bytes.
    Data(Vec<u8>),
    /// Text (ASCII, UTF-8 or UTF-16BE on disk; always UTF-8 here).
    String(String),
    /// `UID` reference (keyed-archive object pointer).
    Uid(u64),
    /// Ordered sequence.
    Array(Vec<Plist>),
    /// Ordered key/value pairs — keys are usually `String` but the
    /// format permits any object, so pairs are kept verbatim.
    Dict(Vec<(Plist, Plist)>),
}

/// The trailer fields, exposed for provenance.
#[derive(Debug, Clone)]
pub struct Trailer {
    /// Byte width of each offset-table entry.
    pub offset_int_size: u8,
    /// Byte width of each object reference.
    pub object_ref_size: u8,
    /// Number of objects in the table.
    pub num_objects: u64,
    /// Object-table index of the root.
    pub top_object: u64,
    /// Absolute offset of the offset table.
    pub offset_table_offset: u64,
}

/// A fully parsed binary plist.
#[derive(Debug, Clone)]
pub struct Bplist {
    /// The decoded root object.
    pub root: Plist,
    /// Parsed trailer.
    pub trailer: Trailer,
    /// Absolute file offset of every object-table entry.
    pub object_offsets: Vec<u64>,
    /// Non-fatal problems (unknown markers decode to `Null` + warning).
    pub warnings: Vec<String>,
}

/// Quick signature check.
pub fn detect(data: &[u8]) -> bool {
    data.len() >= 8 + TRAILER_LEN && &data[..8] == MAGIC
}

impl Plist {
    /// Parse a `bplist00` buffer and return the root object.
    pub fn parse(data: &[u8]) -> Result<Plist> {
        Ok(Bplist::parse(data)?.root)
    }

    /// Parse from any `Read`, bounded at `DEFAULT_MAX_INPUT` bytes.
    pub fn from_reader(r: impl Read) -> Result<Plist> {
        Self::parse(&read_to_end_bounded(r, DEFAULT_MAX_INPUT)?)
    }

    /// Render the value as JSON. `Data` becomes a `"hex:…"` string and
    /// `Uid` an object `{"$uid":n}` — both documented lossy conventions
    /// (std has no base64). Non-string dict keys are rendered via their
    /// JSON text. Never fails, never panics.
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        write_json(self, &mut s);
        s
    }
}

impl Bplist {
    /// Parse a whole `bplist00` file: header, offset table, trailer,
    /// then resolve the root object.
    pub fn parse(data: &[u8]) -> Result<Bplist> {
        if data.len() < 8 + TRAILER_LEN {
            return Err(Error::Truncated {
                offset: 0,
                needed: (8 + TRAILER_LEN) as u64,
                available: data.len() as u64,
            });
        }
        if &data[..8] != MAGIC {
            return Err(Error::Corrupt {
                offset: 0,
                msg: "bad bplist00 magic".into(),
            });
        }
        // Trailer: last 32 bytes.
        let toff = data.len() - TRAILER_LEN;
        let mut tc = Cursor::at(data, toff);
        tc.skip(6)?;
        let trailer = Trailer {
            offset_int_size: tc.u8()?,
            object_ref_size: tc.u8()?,
            num_objects: tc.be_u64()?,
            top_object: tc.be_u64()?,
            offset_table_offset: tc.be_u64()?,
        };
        if trailer.offset_int_size == 0 || trailer.offset_int_size > 8 {
            return Err(Error::Corrupt {
                offset: (toff + 6) as u64,
                msg: format!("offset_int_size {}", trailer.offset_int_size),
            });
        }
        if trailer.object_ref_size == 0 || trailer.object_ref_size > 8 {
            return Err(Error::Corrupt {
                offset: (toff + 7) as u64,
                msg: format!("object_ref_size {}", trailer.object_ref_size),
            });
        }
        // The offset table must lie entirely inside the file, after the
        // header and before the trailer.
        let num = usize::try_from(trailer.num_objects).map_err(|_| Error::Corrupt {
            offset: (toff + 8) as u64,
            msg: "num_objects overflows usize".into(),
        })?;
        let ot_off = usize::try_from(trailer.offset_table_offset).map_err(|_| Error::Corrupt {
            offset: (toff + 24) as u64,
            msg: "offset_table_offset overflows usize".into(),
        })?;
        let osize = trailer.offset_int_size as usize;
        let ot_len = num.checked_mul(osize).ok_or(Error::Corrupt {
            offset: toff as u64,
            msg: "offset table size overflow".into(),
        })?;
        if ot_off < 8 || ot_off.checked_add(ot_len).is_none_or(|e| e > toff) {
            return Err(Error::Corrupt {
                offset: toff as u64,
                msg: format!(
                    "offset table ({num} x {osize} @ {ot_off:#x}) outside object region"
                ),
            });
        }
        if trailer.top_object >= trailer.num_objects {
            return Err(Error::Corrupt {
                offset: (toff + 16) as u64,
                msg: format!("top_object {} out of range", trailer.top_object),
            });
        }
        // Read the offset table (big-endian, `offset_int_size` bytes each).
        let mut object_offsets = Vec::with_capacity(num);
        for i in 0..num {
            let cell = &data[ot_off + i * osize..ot_off + (i + 1) * osize];
            let mut v: u64 = 0;
            for &b in cell {
                v = (v << 8) | b as u64;
            }
            if v >= ot_off as u64 || v < 8 {
                return Err(Error::Corrupt {
                    offset: (ot_off + i * osize) as u64,
                    msg: format!("object {i} offset {v:#x} out of bounds"),
                });
            }
            object_offsets.push(v);
        }

        // Node budget: a well-formed plist visits each object once; allow
        // 8× slack for DAG-ish sharing, then stop instead of exploding.
        let mut budget = num.saturating_mul(8).saturating_add(64).max(1024);
        let mut warnings = Vec::new();
        let root = decode_object(
            data,
            &object_offsets,
            trailer.top_object as usize,
            trailer.object_ref_size,
            0,
            &mut budget,
            &mut warnings,
        )?;
        Ok(Bplist {
            root,
            trailer,
            object_offsets,
            warnings,
        })
    }

    /// Parse from any `Read`, bounded at `DEFAULT_MAX_INPUT` bytes.
    pub fn from_reader(r: impl Read) -> Result<Bplist> {
        Self::parse(&read_to_end_bounded(r, DEFAULT_MAX_INPUT)?)
    }
}

/// Read a `count`-sized field: the marker low nibble, extended by a
/// following int object when it is `0xF`. Returns `(count, next_pos)`.
fn read_count(data: &[u8], mut pos: usize, info: u8) -> Result<(usize, usize)> {
    if info != 0x0F {
        return Ok((info as usize, pos));
    }
    // Extended count: an int object follows.
    if pos >= data.len() {
        return Err(Error::Truncated {
            offset: pos as u64,
            needed: 1,
            available: 0,
        });
    }
    let marker = data[pos];
    pos += 1;
    if marker >> 4 != 0x01 {
        return Err(Error::Corrupt {
            offset: (pos - 1) as u64,
            msg: format!("extended count marker {marker:#x}"),
        });
    }
    let n = 1usize << (marker & 0x0F);
    if n > 8 {
        return Err(Error::Corrupt {
            offset: pos as u64,
            msg: format!("extended count int {n} bytes > 8"),
        });
    }
    if pos + n > data.len() {
        return Err(Error::Truncated {
            offset: pos as u64,
            needed: n as u64,
            available: data.len().saturating_sub(pos) as u64,
        });
    }
    let mut v: usize = 0;
    for &b in &data[pos..pos + n] {
        v = (v << 8) | b as usize;
    }
    Ok((v, pos + n))
}

/// Decode the object at object-table index `idx`.
fn decode_object(
    data: &[u8],
    offsets: &[u64],
    idx: usize,
    ref_size: u8,
    depth: usize,
    budget: &mut usize,
    warnings: &mut Vec<String>,
) -> Result<Plist> {
    if depth > MAX_DEPTH {
        warnings.push(format!("depth cap {MAX_DEPTH} exceeded at object {idx}"));
        return Ok(Plist::Null);
    }
    if *budget == 0 {
        warnings.push("node budget exhausted (cyclic object graph?)".into());
        return Ok(Plist::Null);
    }
    *budget -= 1;
    let off = *offsets.get(idx).ok_or(Error::Corrupt {
        offset: 0,
        msg: format!("object ref {idx} out of range"),
    })? as usize;
    if off >= data.len() {
        return Err(Error::Truncated {
            offset: off as u64,
            needed: 1,
            available: 0,
        });
    }
    let marker = data[off];
    let ty = marker >> 4;
    let info = marker & 0x0F;
    let pos = off + 1;
    match ty {
        0x0 => Ok(match info {
            0x08 => Plist::Bool(false),
            0x09 => Plist::Bool(true),
            _ => Plist::Null, // 0x00 null, 0x0F fill, reserved values
        }),
        0x1 => {
            // int: 2^info bytes, big-endian, sign-extended into i128.
            let n = checked_pow2(info, off)? as usize;
            let raw = take(data, pos, n)?;
            let mut v: i128 = 0;
            for &b in raw {
                v = (v << 8) | b as i128;
            }
            if n < 16 && raw[0] & 0x80 != 0 {
                v -= 1i128 << (n * 8); // sign extension
            }
            Ok(Plist::Int(v))
        }
        0x2 => {
            // real: 2^info bytes BE IEEE-754 (4 or 8).
            let n = checked_pow2(info, off)? as usize;
            let raw = take(data, pos, n)?;
            Ok(Plist::Real(match n {
                4 => f32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as f64,
                8 => f64::from_be_bytes(raw.try_into().unwrap_or([0; 8])),
                _ => {
                    warnings.push(format!("real size {n} at {off:#x}"));
                    f64::NAN
                }
            }))
        }
        0x3 => {
            // date: 8-byte BE double, Mac absolute time.
            let raw = take(data, pos, 8)?;
            Ok(Plist::Date(mac_absolute_time(f64::from_be_bytes(
                raw.try_into().unwrap_or([0; 8]),
            ))))
        }
        0x4 => {
            let (n, p) = read_count(data, pos, info)?;
            Ok(Plist::Data(take(data, p, n)?.to_vec()))
        }
        0x5 => {
            let (n, p) = read_count(data, pos, info)?;
            Ok(Plist::String(
                String::from_utf8_lossy(take(data, p, n)?).into_owned(),
            ))
        }
        0x6 => {
            let (n, p) = read_count(data, pos, info)?;
            let raw = take(data, p, n.saturating_mul(2))?;
            let units: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            Ok(Plist::String(String::from_utf16_lossy(&units)))
        }
        0x7 => {
            // UTF-8 string (undocumented but emitted by NSPropertyList).
            let (n, p) = read_count(data, pos, info)?;
            Ok(Plist::String(
                String::from_utf8_lossy(take(data, p, n)?).into_owned(),
            ))
        }
        0x8 => {
            // uid: info+1 bytes BE.
            let n = info as usize + 1;
            let raw = take(data, pos, n)?;
            let mut v: u64 = 0;
            for &b in raw {
                v = (v << 8) | b as u64;
            }
            Ok(Plist::Uid(v))
        }
        0xA | 0xC => {
            // array / set: `count` object refs.
            let (n, p) = read_count(data, pos, info)?;
            let refs = read_refs(data, p, n, ref_size)?;
            let mut items = Vec::with_capacity(n.min(1 << 20));
            for r in refs {
                items.push(decode_object(
                    data,
                    offsets,
                    r,
                    ref_size,
                    depth + 1,
                    budget,
                    warnings,
                )?);
            }
            Ok(Plist::Array(items))
        }
        0xD => {
            // dict: `count` key refs then `count` value refs.
            let (n, p) = read_count(data, pos, info)?;
            let total = n.checked_mul(2).ok_or(Error::Corrupt {
                offset: off as u64,
                msg: "dict count overflow".into(),
            })?;
            let refs = read_refs(data, p, total, ref_size)?;
            let (keys, vals) = refs.split_at(n);
            let mut pairs = Vec::with_capacity(n.min(1 << 20));
            for (k, v) in keys.iter().zip(vals.iter()) {
                let key = decode_object(data, offsets, *k, ref_size, depth + 1, budget, warnings)?;
                let val = decode_object(data, offsets, *v, ref_size, depth + 1, budget, warnings)?;
                pairs.push((key, val));
            }
            Ok(Plist::Dict(pairs))
        }
        _ => {
            warnings.push(format!("unknown object marker {marker:#x} at {off:#x}"));
            Ok(Plist::Null)
        }
    }
}

/// 2^info with a sanity ceiling (int/real width is at most 16 bytes).
fn checked_pow2(info: u8, off: usize) -> Result<u32> {
    if info > 4 {
        return Err(Error::Corrupt {
            offset: off as u64,
            msg: format!("2^{info}-byte scalar > 16 bytes"),
        });
    }
    Ok(1u32 << info)
}

/// Bounds-checked slice, `Truncated` on overrun.
fn take(data: &[u8], pos: usize, n: usize) -> Result<&[u8]> {
    if pos.checked_add(n).is_none_or(|e| e > data.len()) {
        return Err(Error::Truncated {
            offset: pos as u64,
            needed: n as u64,
            available: data.len().saturating_sub(pos) as u64,
        });
    }
    Ok(&data[pos..pos + n])
}

/// Read `n` big-endian object refs of `ref_size` bytes each.
fn read_refs(data: &[u8], pos: usize, n: usize, ref_size: u8) -> Result<Vec<usize>> {
    let rs = ref_size as usize;
    let total = n.checked_mul(rs).ok_or(Error::Corrupt {
        offset: pos as u64,
        msg: "ref array size overflow".into(),
    })?;
    let raw = take(data, pos, total)?;
    let mut out = Vec::with_capacity(n.min(1 << 22));
    for i in 0..n {
        let mut v: usize = 0;
        for &b in &raw[i * rs..(i + 1) * rs] {
            v = (v << 8) | b as usize;
        }
        out.push(v);
    }
    Ok(out)
}

/// JSON escaping for strings.
fn write_json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Format nanos-since-epoch as RFC-3339 UTC (`days_from_civil` inverse,
/// after Hinnant). Returns `None` out of range.
fn iso8601(ns: i64) -> Option<String> {
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = ns.rem_euclid(1_000_000_000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    // Sanity-check via the forward conversion.
    unix_nanos(y, m, d, tod / 3600, (tod % 3600) / 60, tod % 60, nanos)?;
    Some(format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    ))
}

fn write_json(v: &Plist, out: &mut String) {
    match v {
        Plist::Null => out.push_str("null"),
        Plist::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Plist::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Plist::Real(f) => {
            if f.is_finite() {
                let _ = write!(out, "{f}");
            } else {
                out.push_str("null");
            }
        }
        Plist::Date(t) => match t.value.and_then(iso8601) {
            Some(s) => write_json_str(&s, out),
            None => out.push_str("null"),
        },
        Plist::Data(d) => {
            out.push_str("\"hex:");
            for b in d {
                let _ = write!(out, "{b:02x}");
            }
            out.push('"');
        }
        Plist::String(s) => write_json_str(s, out),
        Plist::Uid(u) => {
            let _ = write!(out, "{{\"$uid\":{u}}}");
        }
        Plist::Array(items) => {
            out.push('[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(it, out);
            }
            out.push(']');
        }
        Plist::Dict(pairs) => {
            out.push('{');
            for (i, (k, val)) in pairs.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                match k {
                    Plist::String(s) => write_json_str(s, out),
                    other => {
                        // JSON requires string keys; render the key's
                        // own JSON as the key string.
                        let mut ks = String::new();
                        write_json(other, &mut ks);
                        write_json_str(&ks, out);
                    }
                }
                out.push(':');
                write_json(val, out);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a bplist from a list of object blobs; index 0 is root.
    fn build(objects: &[&[u8]]) -> Vec<u8> {
        let mut b = MAGIC.to_vec();
        let mut offsets = Vec::new();
        for o in objects {
            offsets.push(b.len() as u64);
            b.extend_from_slice(o);
        }
        let ot_off = b.len() as u64;
        for o in &offsets {
            b.push(*o as u8); // 1-byte offsets (small test data)
        }
        // trailer
        b.extend_from_slice(&[0; 6]);
        b.push(1); // offset int size
        b.push(1); // ref size
        b.extend_from_slice(&(objects.len() as u64).to_be_bytes());
        b.extend_from_slice(&0u64.to_be_bytes()); // top object = 0
        b.extend_from_slice(&ot_off.to_be_bytes());
        b
    }

    #[test]
    fn roundtrip_dict() {
        // obj0 dict(2): keys refs [1,3], vals [2,4]
        // obj1 str "key", obj2 int 0x2A, obj3 str "arr", obj4 array [5,6]
        // obj5 bool true, obj6 utf16 "hé"
        let objs: Vec<&[u8]> = vec![
            &[0xD2, 1, 3, 2, 4],
            &[0x53, b'k', b'e', b'y'],
            &[0x10, 0x2A],
            &[0x53, b'a', b'r', b'r'],
            &[0xA2, 5, 6],
            &[0x09],
            &[0x62, 0x00, 0x68, 0x00, 0xE9],
        ];
        let b = build(&objs);
        let root = Plist::parse(&b).expect("parse");
        let json = root.to_json();
        assert!(json.contains("\"key\":42"), "{json}");
        assert!(json.contains("\"arr\":[true,\"hé\"]"), "{json}");
        assert!(detect(&b));
    }

    #[test]
    fn scalars() {
        let objs: Vec<&[u8]> = vec![
            &[0x33, 0, 0, 0, 0, 0, 0, 0, 0], // date = mac epoch
            &[0x13, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], // int64
            &[0x22, 0x40, 0x09, 0x21, 0xFB], // real f32 ~pi
            &[0x41, 0xAA],
            &[0x80, 0x00], // uid 0 (marker + 1 payload byte)
            &[0x08], // false
        ];
        // root = array of all
        let arr: &[u8] = &[0xA6, 1, 2, 3, 4, 5, 6];
        let mut all: Vec<&[u8]> = vec![arr];
        all.extend_from_slice(&objs);
        let root = Plist::parse(&build(&all)).expect("parse");
        match &root {
            Plist::Array(v) => {
                assert!(matches!(v[0], Plist::Date(_)));
                if let Plist::Int(i) = v[1] {
                    assert_eq!(i, 0x0102030405060708);
                } else {
                    panic!("obj1 not int");
                }
                assert!(matches!(v[4], Plist::Uid(0)));
                assert!(matches!(v[5], Plist::Bool(false)));
            }
            _ => panic!("not array"),
        }
        let json = root.to_json();
        assert!(json.contains("2001-01-01T00:00:00Z"), "{json}");
        assert!(json.contains("\"hex:aa\""), "{json}");
    }

    #[test]
    fn extended_count() {
        // string with extended count: 0x5F, int(1 byte)=5, "hello"
        let objs: Vec<&[u8]> = vec![&[0x5F, 0x10, 5, b'h', b'e', b'l', b'l', b'o']];
        let root = Plist::parse(&build(&objs)).expect("parse");
        assert!(matches!(root, Plist::String(ref s) if s == "hello"));
    }

    #[test]
    fn cyclic_array_safe() {
        // obj0 = array containing ref to itself.
        let objs: Vec<&[u8]> = vec![&[0xA1, 0]];
        let r = Bplist::parse(&build(&objs)).expect("parse"); // must not hang
        assert!(!r.warnings.is_empty()); // depth cap hit
    }

    #[test]
    fn truncated_and_garbage() {
        let full = build(&[&[0xD1, 1, 2], &[0x53, b'a', b'b', b'c'], &[0x11, 9]]);
        for cut in 0..full.len() {
            let _ = Bplist::parse(&full[..cut]);
        }
        for i in 0..full.len() {
            let mut m = full.clone();
            m[i] ^= 0xFF;
            let _ = Bplist::parse(&m);
        }
    }

    #[test]
    fn bad_trailer_rejected() {
        let mut b = build(&[&[0x09]]);
        let n = b.len();
        b[n - 26] = 99; // offset_int_size invalid
        assert!(matches!(Bplist::parse(&b), Err(Error::Corrupt { .. })));
        b[n - 26] = 1;
        // top_object out of range
        b[n - 12] = 7;
        assert!(matches!(Bplist::parse(&b), Err(Error::Corrupt { .. })));
    }
}
