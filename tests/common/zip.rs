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
            c = if c & 1 == 1 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
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
pub const FLAG_UTF8: u16 = 0x0800;
pub const FLAG_ENCRYPTED: u16 = 0x0001;

fn w16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn w32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn w64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// A ZIP64 (`0x0001`) extra field carrying `vals` in declaration order.
pub fn zip64_extra(vals: &[u64]) -> Vec<u8> {
    let mut e = Vec::new();
    e.extend_from_slice(&1u16.to_le_bytes());
    e.extend_from_slice(&(vals.len() as u16 * 8).to_le_bytes());
    for &v in vals {
        e.extend_from_slice(&v.to_le_bytes());
    }
    e
}

/// A generic extra field: `tag` + `len` + `body`.
pub fn extra_field(tag: u16, body: &[u8]) -> Vec<u8> {
    let mut e = Vec::new();
    e.extend_from_slice(&tag.to_le_bytes());
    e.extend_from_slice(&(body.len() as u16).to_le_bytes());
    e.extend_from_slice(body);
    e
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
    pub cds: Vec<CdRec>,
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
        let real_cs = if flags & FLAG_DD != 0 {
            0
        } else {
            stored.len() as u32
        };
        let real_us = if flags & FLAG_DD != 0 {
            0
        } else {
            data.len() as u32
        };
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
        self.push_cd(off, name, flags, method, crc, stored.len() as u32, data.len() as u32, extra, comment, 20, 0);
        off
    }

    fn push_cd(
        &mut self,
        local_off: u64,
        name: &str,
        flags: u16,
        method: u16,
        crc32: u32,
        comp_size: u32,
        uncomp_size: u32,
        extra: &[u8],
        comment: &[u8],
        made_by: u16,
        ext_attrs: u32,
    ) {
        self.cds.push(CdRec {
            flags,
            method,
            mtime: DOS_TIME,
            mdate: DOS_DATE,
            crc32,
            comp_size,
            uncomp_size,
            local_off: local_off as u32,
            name: name.as_bytes().to_vec(),
            extra: extra.to_vec(),
            comment: comment.to_vec(),
            made_by,
            ext_attrs,
        });
    }

    /// ZIP64 catalogued member: LFH and CD carry saturated `u32` fields;
    /// real sizes ride a `0x0001` extra field in both records.
    pub fn add_member_zip64(&mut self, name: &str, data: &[u8], method: u16) -> u64 {
        let off = self.buf.len() as u64;
        let (stored, crc) = if method == METHOD_DEFLATE {
            (miniz_oxide::deflate::compress_to_vec(data, 6), crc32(data))
        } else {
            (data.to_vec(), crc32(data))
        };
        let extra = zip64_extra(&[data.len() as u64, stored.len() as u64]);
        w32(&mut self.buf, 0x0403_4b50);
        w16(&mut self.buf, 45); // version needed: 4.5 = ZIP64
        w16(&mut self.buf, 0);
        w16(&mut self.buf, method);
        w16(&mut self.buf, DOS_TIME);
        w16(&mut self.buf, DOS_DATE);
        w32(&mut self.buf, crc);
        w32(&mut self.buf, u32::MAX);
        w32(&mut self.buf, u32::MAX);
        w16(&mut self.buf, name.len() as u16);
        w16(&mut self.buf, extra.len() as u16);
        self.buf.extend_from_slice(name.as_bytes());
        self.buf.extend_from_slice(&extra);
        self.buf.extend_from_slice(&stored);
        self.member_offsets.push(off);
        self.push_cd(
            off,
            name,
            0,
            method,
            crc,
            u32::MAX,
            u32::MAX,
            &extra,
            &[],
            45,
            0,
        );
        off
    }

    /// Member written with a *signature-less* data descriptor (old-style
    /// bit-3 layout): LFH sizes are zero, and 12 raw bytes — crc, comp
    /// size, uncomp size — follow the data with no `PK\x07\x08` marker.
    /// Still catalogued in the central directory.
    pub fn add_member_dd_no_sig(&mut self, name: &str, data: &[u8], method: u16) -> u64 {
        let off = self.buf.len() as u64;
        let (stored, crc) = if method == METHOD_DEFLATE {
            (miniz_oxide::deflate::compress_to_vec(data, 6), crc32(data))
        } else {
            (data.to_vec(), crc32(data))
        };
        w32(&mut self.buf, 0x0403_4b50);
        w16(&mut self.buf, 20);
        w16(&mut self.buf, FLAG_DD);
        w16(&mut self.buf, method);
        w16(&mut self.buf, DOS_TIME);
        w16(&mut self.buf, DOS_DATE);
        w32(&mut self.buf, 0);
        w32(&mut self.buf, 0);
        w32(&mut self.buf, 0);
        w16(&mut self.buf, name.len() as u16);
        w16(&mut self.buf, 0);
        self.buf.extend_from_slice(name.as_bytes());
        self.buf.extend_from_slice(&stored);
        // 12-byte descriptor, no signature.
        w32(&mut self.buf, crc);
        w32(&mut self.buf, stored.len() as u32);
        w32(&mut self.buf, data.len() as u32);
        self.member_offsets.push(off);
        self.push_cd(
            off,
            name,
            FLAG_DD,
            method,
            crc,
            stored.len() as u32,
            data.len() as u32,
            &[],
            &[],
            20,
            0,
        );
        off
    }

    /// Member present in the archive but never catalogued — the
    /// "deleted"/hidden case. Not added to the central directory.
    pub fn add_hidden(&mut self, name: &str, data: &[u8], method: u16) -> u64 {
        self.add_hidden_opts(name, data, method, 0, &[], false, false)
    }

    /// Hidden member with full control: `flags`, `extra`, whether LFH
    /// sizes are zeroed (streaming bit-3 style), and whether a data
    /// descriptor (with signature) follows the data.
    #[allow(clippy::too_many_arguments)]
    pub fn add_hidden_opts(
        &mut self,
        name: &str,
        data: &[u8],
        method: u16,
        flags: u16,
        extra: &[u8],
        zero_sizes: bool,
        data_descriptor: bool,
    ) -> u64 {
        let off = self.buf.len() as u64;
        let (stored, crc) = if method == METHOD_DEFLATE {
            (miniz_oxide::deflate::compress_to_vec(data, 6), crc32(data))
        } else {
            (data.to_vec(), crc32(data))
        };
        let (h_crc, h_cs, h_us) = if zero_sizes {
            (0, 0, 0)
        } else {
            (crc, stored.len() as u32, data.len() as u32)
        };
        w32(&mut self.buf, 0x0403_4b50);
        w16(&mut self.buf, 20);
        w16(&mut self.buf, flags);
        w16(&mut self.buf, method);
        w16(&mut self.buf, DOS_TIME);
        w16(&mut self.buf, DOS_DATE);
        w32(&mut self.buf, h_crc);
        w32(&mut self.buf, h_cs);
        w32(&mut self.buf, h_us);
        w16(&mut self.buf, name.len() as u16);
        w16(&mut self.buf, extra.len() as u16);
        self.buf.extend_from_slice(name.as_bytes());
        self.buf.extend_from_slice(extra);
        self.buf.extend_from_slice(&stored);
        if data_descriptor {
            w32(&mut self.buf, 0x0807_4b50);
            w32(&mut self.buf, crc);
            w32(&mut self.buf, stored.len() as u32);
            w32(&mut self.buf, data.len() as u32);
        }
        self.member_offsets.push(off);
        off
    }

    /// Raw LFH (not catalogued) whose name field is declared longer than
    /// the bytes that follow — exercises the LFH-truncation path.
    pub fn add_lfh_truncated_name(&mut self, name_len: u16) -> u64 {
        let off = self.buf.len() as u64;
        w32(&mut self.buf, 0x0403_4b50);
        w16(&mut self.buf, 20);
        w16(&mut self.buf, 0);
        w16(&mut self.buf, 0);
        w16(&mut self.buf, DOS_TIME);
        w16(&mut self.buf, DOS_DATE);
        w32(&mut self.buf, 0);
        w32(&mut self.buf, 0);
        w32(&mut self.buf, 0);
        w16(&mut self.buf, name_len);
        w16(&mut self.buf, 0);
        self.buf.extend_from_slice(b"ab"); // fewer than name_len bytes
        self.member_offsets.push(off);
        off
    }

    /// Mutate the last catalogued member's CD record (anomaly tests).
    pub fn last_cd_mut(&mut self) -> &mut CdRec {
        self.cds.last_mut().expect("no members")
    }

    fn emit_cd(out: &mut Vec<u8>, cds: &[CdRec]) -> u32 {
        let cd_off = out.len() as u32;
        for c in cds {
            w32(out, 0x0201_4b50);
            w16(out, c.made_by);
            w16(out, 20);
            w16(out, c.flags);
            w16(out, c.method);
            w16(out, c.mtime);
            w16(out, c.mdate);
            w32(out, c.crc32);
            w32(out, c.comp_size);
            w32(out, c.uncomp_size);
            w16(out, c.name.len() as u16);
            w16(out, c.extra.len() as u16);
            w16(out, c.comment.len() as u16);
            w16(out, 0); // disk start
            w16(out, 0); // internal attrs
            w32(out, c.ext_attrs);
            w32(out, c.local_off);
            out.extend_from_slice(&c.name);
            out.extend_from_slice(&c.extra);
            out.extend_from_slice(&c.comment);
        }
        cd_off
    }

    /// Append the central directory and EOCD; return the archive bytes.
    pub fn finish(self, comment: &[u8]) -> Vec<u8> {
        self.finish_patched(comment, EocdPatch::default())
    }

    /// `finish` with control over EOCD fields and trailing CD junk.
    pub fn finish_patched(self, comment: &[u8], patch: EocdPatch) -> Vec<u8> {
        let mut out = self.buf;
        let cd_off = Self::emit_cd(&mut out, &self.cds);
        out.extend_from_slice(&patch.cd_tail);
        let cd_size = out.len() as u32 - cd_off;
        let n = self.cds.len() as u16;
        w32(&mut out, 0x0605_4b50);
        w16(&mut out, patch.disk);
        w16(&mut out, patch.cd_start_disk);
        w16(&mut out, patch.entries_this_disk.unwrap_or(n));
        w16(&mut out, patch.entries.unwrap_or(n));
        w32(&mut out, cd_size);
        w32(&mut out, patch.cd_off.unwrap_or(cd_off));
        w16(&mut out, comment.len() as u16);
        out.extend_from_slice(comment);
        out
    }

    /// Append the CD, a ZIP64 EOCD record + locator, and a classic EOCD
    /// whose u16/u32 fields are saturated (forcing the ZIP64 path).
    pub fn finish_zip64(self, comment: &[u8]) -> Vec<u8> {
        let mut out = self.buf;
        let cd_off = Self::emit_cd(&mut out, &self.cds) as u64;
        let cd_size = out.len() as u64 - cd_off;
        let n = self.cds.len() as u64;
        // ZIP64 EOCD record (56 bytes).
        let z64_off = out.len() as u64;
        w32(&mut out, 0x0606_4b50);
        w64(&mut out, 44); // size of remaining record
        w16(&mut out, 45); // version made by
        w16(&mut out, 45); // version needed
        w32(&mut out, 0); // this disk
        w32(&mut out, 0); // cd start disk
        w64(&mut out, n); // entries this disk
        w64(&mut out, n); // entries total
        w64(&mut out, cd_size);
        w64(&mut out, cd_off);
        // ZIP64 EOCD locator (20 bytes).
        w32(&mut out, 0x0706_4b50);
        w32(&mut out, 0); // disk holding the z64 EOCD
        w64(&mut out, z64_off);
        w32(&mut out, 1); // total disks
        // Classic EOCD with saturated fields.
        w32(&mut out, 0x0605_4b50);
        w16(&mut out, 0);
        w16(&mut out, 0);
        w16(&mut out, u16::MAX);
        w16(&mut out, u16::MAX);
        w32(&mut out, u32::MAX);
        w32(&mut out, u32::MAX);
        w16(&mut out, comment.len() as u16);
        out.extend_from_slice(comment);
        out
    }

    /// Like `finish`, but *omits* the EOCD — a truncated/streaming
    /// archive for the lenient path.
    pub fn finish_no_eocd(self) -> Vec<u8> {
        let mut out = self.buf;
        Self::emit_cd(&mut out, &self.cds);
        out
    }
}

/// EOCD fields tests may override at `finish_patched`.
#[derive(Default)]
pub struct EocdPatch {
    /// `None` writes the real record count.
    pub entries: Option<u16>,
    /// Extra (junk) bytes appended to the CD region before the EOCD;
    /// `cd_size` is inflated to cover them.
    pub cd_tail: Vec<u8>,
    /// Override the recorded central-directory offset.
    pub cd_off: Option<u32>,
    /// Disk-number fields (multi-disk archives).
    pub disk: u16,
    pub cd_start_disk: u16,
    /// Per-disk entry count (differs from `entries` on multi-disk).
    pub entries_this_disk: Option<u16>,
}
