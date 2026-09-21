//! Byte-exact ZIP image builder.
//!
//! Layout produced by [`ZipBuilder`]:
//!
//! ```text
//! [stub?]                    — optional SFX prefix (add_stub)
//! LFH + data  (per member)   — via add_*(); hidden members skip the CD
//! [data descriptor?]         — for FLAG_DD entries
//! central directory          — one 46-byte record per catalogued member
//! EOCD + comment             — finish()
//! ```

/// CRC-32 (IEEE 802.3, zip polynomial) — bitwise, test-only.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 == 1 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

/// A fixed DOS datetime for assertions: 2024-01-15 12:30:00 →
/// date 0x582F, time 0x63C0.
pub const DOS_DATE: u16 = (2024 - 1980) << 9 | 1 << 5 | 15;
pub const DOS_TIME: u16 = 12 << 11 | 30 << 5;

pub const METHOD_STORE: u16 = 0;
pub const METHOD_DEFLATE: u16 = 8;
pub const FLAG_DD: u16 = 0x0008;
#[allow(dead_code)]
pub const FLAG_UTF8: u16 = 0x0800;
#[allow(dead_code)]
pub const FLAG_ENCRYPTED: u16 = 0x0001;

fn w16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn w32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// One catalogued member's central-directory fields, saved so the CD can
/// be emitted (and optionally mutated) at `finish`.
pub(crate) struct CdRec {
    pub flags: u16,
    pub method: u16,
    pub mtime: u16,
    pub mdate: u16,
    pub crc32: u32,
    pub comp_size: u32,
    pub uncomp_size: u32,
    pub local_off: u32,
    pub name: Vec<u8>,
    pub extra: Vec<u8>,
    pub comment: Vec<u8>,
    pub made_by: u16,
    pub ext_attrs: u32,
}

pub struct ZipBuilder {
    /// Everything before the central directory.
    pub buf: Vec<u8>,
    /// Central-directory records, appended at `finish`.
    cds: Vec<CdRec>,
    /// Offset where each member's LFH was written (index = member order).
    pub member_offsets: Vec<u64>,
}

impl ZipBuilder {
    pub fn new() -> Self {
        ZipBuilder {
            buf: Vec::new(),
            cds: Vec::new(),
            member_offsets: Vec::new(),
        }
    }

    /// Pretend a self-extracting stub — all member offsets shift.
    /// (Tests prepend stubs manually post-build; kept for callers.)
    #[allow(dead_code)]
    pub fn add_stub(&mut self, stub: &[u8]) {
        self.buf.extend_from_slice(stub);
    }

    /// Write an LFH + data + optional data descriptor; record the CD
    /// fields for `finish`. Returns the LFH's absolute offset.
    pub fn add_member(
        &mut self,
        name: &str,
        data: &[u8],
        method: u16,
        flags: u16,
        extra: &[u8],
        comment: &[u8],
    ) -> u64 {
        let off = self.buf.len() as u64;
        let (stored, crc) = if method == METHOD_DEFLATE {
            (miniz_oxide::deflate::compress_to_vec(data, 6), crc32(data))
        } else {
            (data.to_vec(), crc32(data))
        };
        let real_crc = if flags & FLAG_DD != 0 { 0 } else { crc };
        let real_cs = if flags & FLAG_DD != 0 { 0 } else { stored.len() as u32 };
        let real_us = if flags & FLAG_DD != 0 { 0 } else { data.len() as u32 };
        // LFH
        w32(&mut self.buf, 0x0403_4b50);
        w16(&mut self.buf, 20); // version needed
        w16(&mut self.buf, flags);
        w16(&mut self.buf, method);
        w16(&mut self.buf, DOS_TIME);
        w16(&mut self.buf, DOS_DATE);
        w32(&mut self.buf, real_crc);
        w32(&mut self.buf, real_cs);
        w32(&mut self.buf, real_us);
        w16(&mut self.buf, name.len() as u16);
        w16(&mut self.buf, extra.len() as u16);
        self.buf.extend_from_slice(name.as_bytes());
        self.buf.extend_from_slice(extra);
        self.buf.extend_from_slice(&stored);
        if flags & FLAG_DD != 0 {
            w32(&mut self.buf, 0x0807_4b50);
            w32(&mut self.buf, crc);
            w32(&mut self.buf, stored.len() as u32);
            w32(&mut self.buf, data.len() as u32);
        }
        self.member_offsets.push(off);
        self.cds.push(CdRec {
            flags,
            method,
            mtime: DOS_TIME,
            mdate: DOS_DATE,
            crc32: crc,
            comp_size: stored.len() as u32,
            uncomp_size: data.len() as u32,
            local_off: off as u32,
            name: name.as_bytes().to_vec(),
            extra: extra.to_vec(),
            comment: comment.to_vec(),
            made_by: 20,
            ext_attrs: 0,
        });
        off
    }

    /// Member present in the archive but never catalogued — the
    /// "deleted"/hidden case. Not added to the central directory.
    pub fn add_hidden(&mut self, name: &str, data: &[u8], method: u16) -> u64 {
        let off = self.buf.len() as u64;
        let (stored, crc) = if method == METHOD_DEFLATE {
            (miniz_oxide::deflate::compress_to_vec(data, 6), crc32(data))
        } else {
            (data.to_vec(), crc32(data))
        };
        w32(&mut self.buf, 0x0403_4b50);
        w16(&mut self.buf, 20);
        w16(&mut self.buf, 0);
        w16(&mut self.buf, method);
        w16(&mut self.buf, DOS_TIME);
        w16(&mut self.buf, DOS_DATE);
        w32(&mut self.buf, crc);
        w32(&mut self.buf, stored.len() as u32);
        w32(&mut self.buf, data.len() as u32);
        w16(&mut self.buf, name.len() as u16);
        w16(&mut self.buf, 0);
        self.buf.extend_from_slice(name.as_bytes());
        self.buf.extend_from_slice(&stored);
        self.member_offsets.push(off);
        off
    }

    /// Mutate the last catalogued member's CD record (anomaly tests).
    pub fn last_cd_mut(&mut self) -> &mut CdRec {
        self.cds.last_mut().expect("no members")
    }

    /// Append the central directory and EOCD; return the archive bytes.
    pub fn finish(self, comment: &[u8]) -> Vec<u8> {
        let mut out = self.buf;
        let cd_off = out.len() as u32;
        for c in &self.cds {
            w32(&mut out, 0x0201_4b50);
            w16(&mut out, c.made_by);
            w16(&mut out, 20);
            w16(&mut out, c.flags);
            w16(&mut out, c.method);
            w16(&mut out, c.mtime);
            w16(&mut out, c.mdate);
            w32(&mut out, c.crc32);
            w32(&mut out, c.comp_size);
            w32(&mut out, c.uncomp_size);
            w16(&mut out, c.name.len() as u16);
            w16(&mut out, c.extra.len() as u16);
            w16(&mut out, c.comment.len() as u16);
            w16(&mut out, 0); // disk start
            w16(&mut out, 0); // internal attrs
            w32(&mut out, c.ext_attrs);
            w32(&mut out, c.local_off);
            out.extend_from_slice(&c.name);
            out.extend_from_slice(&c.extra);
            out.extend_from_slice(&c.comment);
        }
        let cd_size = out.len() as u32 - cd_off;
        w32(&mut out, 0x0605_4b50);
        w16(&mut out, 0); // disk
        w16(&mut out, 0); // cd start disk
        w16(&mut out, self.cds.len() as u16);
        w16(&mut out, self.cds.len() as u16);
        w32(&mut out, cd_size);
        w32(&mut out, cd_off);
        w16(&mut out, comment.len() as u16);
        out.extend_from_slice(comment);
        out
    }

    /// Like `finish`, but *omits* the EOCD — a truncated/streaming
    /// archive for the lenient path.
    pub fn finish_no_eocd(self) -> Vec<u8> {
        let mut out = self.buf;
        for c in &self.cds {
            w32(&mut out, 0x0201_4b50);
            w16(&mut out, c.made_by);
            w16(&mut out, 20);
            w16(&mut out, c.flags);
            w16(&mut out, c.method);
            w16(&mut out, c.mtime);
            w16(&mut out, c.mdate);
            w32(&mut out, c.crc32);
            w32(&mut out, c.comp_size);
            w32(&mut out, c.uncomp_size);
            w16(&mut out, c.name.len() as u16);
            w16(&mut out, c.extra.len() as u16);
            w16(&mut out, c.comment.len() as u16);
            w16(&mut out, 0);
            w16(&mut out, 0);
            w32(&mut out, c.ext_attrs);
            w32(&mut out, c.local_off);
            out.extend_from_slice(&c.name);
            out.extend_from_slice(&c.extra);
            out.extend_from_slice(&c.comment);
        }
        out
    }
}
