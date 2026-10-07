//! Signature carving: the engine behind [`FileSystem::carve_region`].
//!
//! [`CarveIter`] probes a region at `align` boundaries for known file
//! signatures (`sutram_magic::detect`) and then *bounds* each hit using
//! the format knowledge in [`sutram_magic::carve_spec`]:
//!
//! * **footer-terminated** (JPEG `FF D9`, PDF `%%EOF`, ZIP EOCD, …),
//! * **declared-size** (BMP, CAB, DEX, registry hives, prefetch, squashfs,
//!   ISO 9660, …),
//! * **structure-walked** (PNG chunk chain, ISO-BMFF boxes, ELF section
//!   table, PE sections, tar blocks, pcap records, SQLite page count),
//! * **fixed records** (MFT `FILE`, INDX, boot sectors).
//!
//! Types with no reliable bound run to the next signature hit or a
//! per-type cap — the classic scalpel behaviour — and are marked
//! `exact: false` on the resulting [`CarveHit`].

use std::sync::Arc;

use sutram_io::ByteSource;
use sutram_magic::{carve_spec, CarveBound, DeclField, MagicType};

use crate::{CarveHit, FsError, Result};

/// Header probe size — must cover the largest signature offset in the
/// magic table (ISO9660 `CD001` at 0x9001 + 5).
const HEADER_PROBE: usize = 0xA000;
/// Window for forward footer scans.
const SCAN_WIN: usize = 256 * 1024;
/// Bytes of the hit excerpt carried on [`CarveHit::header`].
const EXCERPT: usize = 256;

/// Carve scan options for [`FileSystem::carve`].
#[derive(Debug, Clone)]
pub struct CarveOptions {
    /// Region start within the mounted source.
    pub offset: u64,
    /// Region length; 0 = to end of source.
    pub len: u64,
    /// Probe granularity: 512 covers every filesystem allocation unit;
    /// 1 scans every byte offset (slow).
    pub align: u64,
    /// Per-object extent cap; 0 = the type's own [`CarveSpec::max`].
    /// Applied on top of the type cap — `min` of both wins.
    pub max_size: u64,
}

impl CarveOptions {
    /// Build options for the legacy `carve_region(offset, len, align)`
    /// signature — cap is the region length itself.
    pub fn region(offset: u64, len: u64, align: u64) -> Self {
        CarveOptions {
            offset,
            len,
            align,
            max_size: 0,
        }
    }
}

/// The carving iterator produced by [`FileSystem::carve`].
pub struct CarveIter {
    src: Arc<dyn ByteSource>,
    pos: u64,
    end: u64,
    align: u64,
    max_override: u64,
}

impl CarveIter {
    pub fn new(src: Arc<dyn ByteSource>, opts: &CarveOptions) -> Result<Self> {
        if opts.align == 0 {
            return Err(FsError::InvalidInput {
                msg: "carve alignment must be > 0".into(),
            });
        }
        let total = src.len();
        let end = opts
            .offset
            .saturating_add(if opts.len == 0 { total } else { opts.len })
            .min(total)
            .max(opts.offset.min(total));
        Ok(CarveIter {
            src,
            pos: opts.offset,
            end,
            align: opts.align,
            max_override: opts.max_size,
        })
    }

    fn align_up(&self, v: u64) -> u64 {
        // align is always > 0 here (checked in `new`).
        v.saturating_add(self.align - 1) / self.align * self.align
    }

    /// From `pos` (a signature hit of `kind`), resolve the carved extent:
    /// `(extent_len, exact)`. `Ok(None)` means the bound could not be
    /// resolved — the caller falls back to scan-until-next-signature.
    fn bound_extent(&self, pos: u64, kind: MagicType, probe: &[u8]) -> Result<Option<(u64, bool)>> {
        let spec = carve_spec(kind);
        let remain = self.end - pos;
        let cap = if self.max_override == 0 {
            spec.max
        } else {
            self.max_override.min(spec.max)
        }
        .min(remain);

        let read_more = |rel: u64, n: usize| -> Result<Vec<u8>> {
            self.src
                .read_slice(pos + rel, usize::try_from(n).unwrap_or(usize::MAX))
                .map_err(FsError::Io)
        };

        let extent = match spec.bound {
            CarveBound::Fixed(n) => Some((n.min(cap), true)),
            CarveBound::Trailer(footers, eol) => {
                self.scan_trailer(pos, footers, cap, eol)?
            }
            CarveBound::ZipEocd => self.zip_eocd(pos, cap)?,
            CarveBound::Declared { offset, field, mult, add } => {
                declared_extent(probe, offset, field, mult, add, cap)
            }
            CarveBound::Riff { be } => riff_extent(probe, be, cap),
            CarveBound::PngChunks => self.png_chunks(pos, cap)?,
            CarveBound::IsoBmff => self.iso_bmff(pos, cap)?,
            CarveBound::ElfEnd => elf_extent(&read_more)?,
            CarveBound::PeEnd => self.pe_end(cap, &read_more)?,
            CarveBound::SqliteSize => sqlite_extent(probe, cap),
            CarveBound::TarEnd => self.tar_end(pos, cap)?,
            CarveBound::PcapEnd => self.pcap_end(pos, cap)?,
            CarveBound::ToNextHit => None,
        };
        // Clamp anything that overran the region.
        Ok(extent.map(|(n, exact)| (n.min(remain), exact)))
    }

    /// Forward byte-window scan for any of `footers`; extent ends just
    /// past the match, plus a trailing line ending when `eol`.
    fn scan_trailer(
        &self,
        pos: u64,
        footers: &[&[u8]],
        cap: u64,
        eol: bool,
    ) -> Result<Option<(u64, bool)>> {
        let longest = footers.iter().map(|f| f.len()).max().unwrap_or(1);
        let mut cur = 0u64; // relative offset of the window start
        // Overlap consecutive windows so a footer straddling the boundary
        // is still found.
        while cur < cap {
            let n = (cap - cur).min(SCAN_WIN as u64);
            let win = self
                .src
                .read_slice(pos + cur, usize::try_from(n).unwrap_or(usize::MAX))
                .map_err(FsError::Io)?;
            if win.is_empty() {
                return Ok(None);
            }
            for f in footers {
                if let Some(m) = find_subslice(&win, f) {
                    let mut end = cur + m as u64 + f.len() as u64;
                    if eol {
                        // absorb the label run out to the line ending —
                        // covers `%%EOF\r\n` and `-----END CERT-----`.
                        let tail = self
                            .src
                            .read_slice(pos + end, 96)
                            .map_err(FsError::Io)?;
                        end += eol_len(&tail) as u64;
                    }
                    return Ok(Some((end, true)));
                }
            }
            // window ended without a match; step forward (overlap by
            // longest footer minus 1 so a boundary match is not missed)
            let step = (win.len() as u64).saturating_sub(longest as u64 - 1);
            if step == 0 {
                return Ok(None);
            }
            cur += step;
        }
        Ok(None)
    }

    /// ZIP EOCD: extent = EOCD end + `comment_len` (u16LE at +20).
    fn zip_eocd(&self, pos: u64, cap: u64) -> Result<Option<(u64, bool)>> {
        let mut cur = 0u64;
        while cur < cap {
            let n = (cap - cur).min(SCAN_WIN as u64);
            let win = self
                .src
                .read_slice(pos + cur, usize::try_from(n).unwrap_or(usize::MAX))
                .map_err(FsError::Io)?;
            if win.is_empty() {
                return Ok(None);
            }
            if let Some(m) = find_subslice(&win, b"PK\x05\x06") {
                let rec = cur + m as u64;
                // comment length sits 20 bytes into the 22-byte record.
                let tail = self.src.read_slice(pos + rec + 20, 2).map_err(FsError::Io)?;
                let comment = if tail.len() == 2 {
                    u16::from_le_bytes([tail[0], tail[1]]) as u64
                } else {
                    0
                };
                return Ok(Some((rec + 22 + comment, true)));
            }
            let step = (win.len() as u64).saturating_sub(3);
            if step == 0 {
                return Ok(None);
            }
            cur += step;
        }
        Ok(None)
    }

    /// PNG: walk `len u32BE | type | data | crc32` chunks to IEND.
    fn png_chunks(&self, pos: u64, cap: u64) -> Result<Option<(u64, bool)>> {
        // Skip the 8-byte signature, then iterate chunk headers.
        let mut off = 8u64;
        loop {
            let hdr = self.src.read_slice(pos + off, 8).map_err(FsError::Io)?;
            if hdr.len() < 8 {
                return Ok(None);
            }
            let len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as u64;
            // chunk payload + 4-byte crc; absurd sizes abort.
            if len > cap || off + 12 + len > cap {
                return Ok(None);
            }
            off += 12 + len;
            if &hdr[4..8] == b"IEND" {
                return Ok(Some((off.min(cap), true)));
            }
            if off >= cap {
                return Ok(None);
            }
        }
    }

    /// ISO-BMFF/QuickTime box walk: `[size u32BE | type u32 | payload]`;
    /// size==1 reads a 64-bit largesize, size==0 means "to EOF".
    fn iso_bmff(&self, pos: u64, cap: u64) -> Result<Option<(u64, bool)>> {
        let mut off = 0u64;
        loop {
            let hdr = self.src.read_slice(pos + off, 16).map_err(FsError::Io)?;
            if hdr.len() < 8 {
                return Ok(None);
            }
            let size32 = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as u64;
            let (size, header) = match size32 {
                1 => {
                    if hdr.len() < 16 {
                        return Ok(None);
                    }
                    (
                        u64::from_be_bytes([
                            hdr[8], hdr[9], hdr[10], hdr[11],
                            hdr[12], hdr[13], hdr[14], hdr[15],
                        ]),
                        16,
                    )
                }
                // size==0 means "to EOF" per ISO-BMFF — the real end is
                // unknown to us, so report the cap without `exact`.
                0 => return Ok(Some((cap, false))),
                s => (s, 8),
            };
            if size < header {
                return Ok(None); // malformed — bail, caller falls back
            }
            off = match off.checked_add(size) {
                Some(v) => v,
                None => return Ok(None),
            };
            if off > cap {
                // chain ran to the cap without a terminating box
                return Ok(Some((cap, false)));
            }
            // Reached the declared end exactly.
            if off == cap {
                return Ok(Some((off, true)));
            }
        }
    }

    /// PE/COFF extent: max(raw_data_ptr + raw_data_size) over sections.
    fn pe_end(
        &self,
        cap: u64,
        read_more: &dyn Fn(u64, usize) -> Result<Vec<u8>>,
    ) -> Result<Option<(u64, bool)>> {
        let hdr = read_more(0, 512)?;
        if hdr.len() < 0x40 {
            return Ok(None);
        }
        let lfanew = u32::from_le_bytes([hdr[0x3C], hdr[0x3D], hdr[0x3E], hdr[0x3F]]) as u64;
        if lfanew >= cap || lfanew > 16 * 1024 * 1024 {
            return Ok(None);
        }
        let pe = read_more(lfanew, 24)?;
        if pe.len() < 24 || &pe[..4] != b"PE\0\0" {
            return Ok(None);
        }
        let n_sections = u16::from_le_bytes([pe[6], pe[7]]) as u64;
        let opt_size = u16::from_le_bytes([pe[20], pe[21]]) as u64;
        if n_sections == 0 || n_sections > 96 {
            return Ok(None);
        }
        let table_off = lfanew + 24 + opt_size;
        let table = read_more(table_off, (n_sections * 40) as usize)?;
        let mut end = 0u64;
        for s in table.chunks_exact(40) {
            let raw_size = u32::from_le_bytes([s[16], s[17], s[18], s[19]]) as u64;
            let raw_ptr = u32::from_le_bytes([s[20], s[21], s[22], s[23]]) as u64;
            end = end.max(raw_ptr.saturating_add(raw_size));
        }
        if end == 0 || end > cap {
            return Ok(None);
        }
        Ok(Some((end, true)))
    }

    /// tar: 512-byte headers; octal size @124; members pad to 512;
    /// stream ends at two consecutive zero blocks.
    fn tar_end(&self, pos: u64, cap: u64) -> Result<Option<(u64, bool)>> {
        let mut off = 0u64;
        let mut zeros = 0u32;
        loop {
            let hdr = self.src.read_slice(pos + off, 512).map_err(FsError::Io)?;
            if hdr.len() < 512 {
                return Ok(None);
            }
            if hdr.iter().all(|&b| b == 0) {
                zeros += 1;
                if zeros >= 2 {
                    return Ok(Some((off + 512, true)));
                }
                off += 512;
                continue;
            }
            zeros = 0;
            // member size: 12-byte octal field at offset 124
            let Some(size) = parse_octal(&hdr[124..136]) else {
                return Ok(None);
            };
            // Sanity: name field should be printable-ish.
            if hdr[0] == 0 {
                return Ok(None);
            }
            off += 512 + size.div_ceil(512) * 512;
            if off >= cap {
                return Ok(None);
            }
        }
    }

    /// libpcap: global header 24B, then `[16B hdr | incl_len bytes]`.
    fn pcap_end(&self, pos: u64, cap: u64) -> Result<Option<(u64, bool)>> {
        let gh = self.src.read_slice(pos, 24).map_err(FsError::Io)?;
        if gh.len() < 24 {
            return Ok(None);
        }
        let magic = u32::from_le_bytes([gh[0], gh[1], gh[2], gh[3]]);
        let le = matches!(magic, 0xA1B2C3D4 | 0xA1B23C4D); // stored LE
        let rd_u32 = |b: &[u8]| -> u32 {
            if le {
                u32::from_le_bytes([b[0], b[1], b[2], b[3]])
            } else {
                u32::from_be_bytes([b[0], b[1], b[2], b[3]])
            }
        };
        let mut off = 24u64;
        loop {
            if off + 16 > cap {
                return Ok(Some((off, true))); // ran out of packets
            }
            let ph = self.src.read_slice(pos + off, 16).map_err(FsError::Io)?;
            if ph.len() < 16 {
                return Ok(Some((off, true)));
            }
            let incl = rd_u32(&ph[8..12]) as u64;
            if incl > 16 * 1024 * 1024 {
                // implausible packet size — treat what we have as the file
                return Ok(Some((off, true)));
            }
            off += 16 + incl;
            if off >= cap {
                return Ok(Some((cap, false)));
            }
        }
    }

    /// For unbounded kinds: extent = bytes to the next aligned position
    /// whose probe hits a signature, or the per-type cap — whichever is
    /// first (scalpel's "carve until next header").
    fn scan_to_next(&mut self, pos: u64, kind: MagicType) -> Result<(u64, bool)> {
        let cap = {
            let spec = carve_spec(kind);
            let m = if self.max_override == 0 {
                spec.max
            } else {
                self.max_override.min(spec.max)
            };
            m.min(self.end - pos)
        };
        let mut p = pos + self.align;
        while p < pos + cap && p < self.end {
            let probe_len = HEADER_PROBE.min((self.end - p) as usize);
            let probe = self.src.read_slice(p, probe_len).map_err(FsError::Io)?;
            if sutram_magic::detect(&probe).is_some() {
                return Ok((p - pos, false));
            }
            p += self.align;
        }
        Ok((cap.min(self.end - pos), false))
    }
}

impl Iterator for CarveIter {
    type Item = Result<CarveHit>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.end {
            let pos = self.pos;
            let remain = usize::try_from(self.end - pos).unwrap_or(usize::MAX);
            let probe_len = HEADER_PROBE.min(remain);
            let probe = match self.src.read_slice(pos, probe_len) {
                Ok(h) => h,
                Err(e) => return Some(Err(FsError::Io(e))),
            };
            match sutram_magic::detect(&probe) {
                Some(kind) => {
                    let (len, exact) = match self.bound_extent(pos, kind, &probe) {
                        Ok(Some(v)) => v,
                        Ok(None) => {
                            // Unbounded / unresolvable: carve to the next
                            // aligned signature hit or the per-type cap.
                            match self.scan_to_next(pos, kind) {
                                Ok(v) => v,
                                Err(e) => return Some(Err(e)),
                            }
                        }
                        Err(e) => return Some(Err(e)),
                    };
                    let len = len.max(1).min(self.end - pos);
                    // Resume scanning past the carved extent (a small
                    // extent still advances a full alignment step).
                    self.pos = self.align_up(pos.saturating_add(len.max(self.align)));
                    let header = probe[..EXCERPT.min(probe.len())].to_vec();
                    return Some(Ok(CarveHit {
                        offset: pos,
                        len,
                        kind,
                        header,
                        exact,
                    }));
                }
                None => self.pos = pos + self.align,
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Bytes through the next `\n` (inclusive), capped at `buf`'s length.
fn eol_len(buf: &[u8]) -> usize {
    match buf.iter().position(|&b| b == b'\n') {
        Some(i) => i + 1,
        None => buf.len(),
    }
}

fn declared_extent(
    probe: &[u8],
    offset: usize,
    field: DeclField,
    mult: u64,
    add: u64,
    cap: u64,
) -> Option<(u64, bool)> {
    let v = match field {
        DeclField::U32Le => u64::from(u32::from_le_bytes(
            probe.get(offset..offset + 4)?.try_into().ok()?,
        )),
        DeclField::U32Be => u64::from(u32::from_be_bytes(
            probe.get(offset..offset + 4)?.try_into().ok()?,
        )),
        DeclField::U64Le => u64::from_le_bytes(probe.get(offset..offset + 8)?.try_into().ok()?),
    };
    let size = v.checked_mul(mult)?.checked_add(add)?;
    if size == 0 || size > cap {
        return None;
    }
    Some((size, true))
}

fn riff_extent(probe: &[u8], be: bool, cap: u64) -> Option<(u64, bool)> {
    let raw = if be {
        u32::from_be_bytes(probe.get(4..8)?.try_into().ok()?)
    } else {
        u32::from_le_bytes(probe.get(4..8)?.try_into().ok()?)
    } as u64;
    // RIFF size excludes the 8-byte header; chunks pad to even.
    let size = raw.saturating_add(8 + (raw & 1));
    if size == 0 || size > cap {
        return None;
    }
    Some((size, true))
}

fn elf_extent(read_more: &dyn Fn(u64, usize) -> Result<Vec<u8>>) -> Result<Option<(u64, bool)>> {
    let hdr = read_more(0, 64)?;
    if hdr.len() < 64 || &hdr[..4] != b"\x7fELF" {
        return Ok(None);
    }
    let is64 = hdr[4] == 2;
    let be = hdr[5] == 2;
    let r16 = |b: &[u8]| -> u64 {
        if be {
            u16::from_be_bytes([b[0], b[1]]) as u64
        } else {
            u16::from_le_bytes([b[0], b[1]]) as u64
        }
    };
    let r32 = |b: &[u8]| -> u64 {
        if be {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64
        } else {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64
        }
    };
    let r64 = |b: &[u8]| -> u64 {
        if be {
            u64::from_be_bytes(b[..8].try_into().unwrap())
        } else {
            u64::from_le_bytes(b[..8].try_into().unwrap())
        }
    };
    // field offsets per class (ELF spec)
    let (shoff, phentsize, phnum, shentsize, shnum) = if is64 {
        (
            r64(&hdr[40..48]),
            r16(&hdr[54..56]),
            r16(&hdr[56..58]),
            r16(&hdr[58..60]),
            r16(&hdr[60..62]),
        )
    } else {
        (
            r32(&hdr[32..36]),
            r16(&hdr[42..44]),
            r16(&hdr[44..46]),
            r16(&hdr[46..48]),
            r16(&hdr[48..50]),
        )
    };
    let phoff = if is64 { r64(&hdr[32..40]) } else { r32(&hdr[28..32]) };
    let sec_end = shoff.saturating_add(shentsize.saturating_mul(shnum));
    let ph_end = phoff.saturating_add(phentsize.saturating_mul(phnum));
    let end = sec_end.max(ph_end);
    if end == 0 {
        return Ok(None);
    }
    Ok(Some((end, true)))
}

fn sqlite_extent(probe: &[u8], cap: u64) -> Option<(u64, bool)> {
    let page_size = match u16::from_be_bytes(probe.get(16..18)?.try_into().ok()?) {
        1 => 65536u64,
        p => p as u64,
    };
    if !page_size.is_power_of_two() || !(512..=65536).contains(&page_size) {
        return None;
    }
    let pages = u32::from_be_bytes(probe.get(28..32)?.try_into().ok()?) as u64;
    let size = page_size.checked_mul(pages)?;
    if size == 0 || size > cap {
        return None;
    }
    Some((size, true))
}

fn parse_octal(b: &[u8]) -> Option<u64> {
    let s = std::str::from_utf8(b).ok()?.trim_matches(|c| c == ' ' || c == '\0');
    if s.is_empty() {
        return None;
    }
    u64::from_str_radix(s, 8).ok()
}
