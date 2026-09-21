//! Microsoft virtual hard disk readers: VHD (`*.vhd`) and VHDX
//! (`*.vhdx`), exposed as a read-only [`ByteSource`].
//!
//! ## VHD ("conectix")
//!
//! A VHD file ends in a 512-byte **footer** (cookie `conectix`, all
//! numeric fields big-endian) describing the disk type:
//!
//! * **fixed** (type 2) — virtual disk bytes are stored 1:1 from file
//!   offset 0; the footer only carries the virtual size;
//! * **dynamic** (type 3) — the file starts with a footer *copy*, then a
//!   1024-byte dynamic header (`cxsparse` cookie) giving the BAT offset
//!   (`table_offset`) and `block_size`. The **block allocation table**
//!   is `max_table_entries` big-endian u32 *sector offsets* (512-byte
//!   units); `0xFFFFFFFF` marks an unallocated block that reads as
//!   zeros. Each allocated block begins with a sector bitmap — one bit
//!   per 512-byte sector, padded up to a 512-byte boundary — followed by
//!   `block_size` bytes of payload. Cleared bitmap bits read as zeros.
//! * **differencing** (type 4) — needs the parent image to resolve
//!   unwritten blocks → [`Error::Unsupported`].
//!
//! Trailing garbage is tolerated: when the last 512 bytes are not a
//! footer, the tail of the file is scanned backwards for a `conectix`
//! candidate with plausible fields (bounded, see [`FOOTER_SCAN_TAIL`]).
//!
//! ## VHDX ("vhdxfile")
//!
//! All VHDX structures are little-endian:
//!
//! * 4 KiB headers at 64 KiB and 128 KiB (`head` signature + CRC-32C);
//!   the highest-sequence checksum-valid header wins.
//! * 64 KiB region tables at 192 KiB and 256 KiB (`regi` signature +
//!   CRC-32C) naming the **BAT** and **metadata** regions by GUID.
//! * The metadata region (`metadata` signature) holds File Parameters
//!   (`block_size`, `HasParent` flag), Virtual Disk Size and Logical
//!   Sector Size items.
//! * The **BAT** is an array of u64 entries: bits 0–2 = block state
//!   (`PAYLOAD_BLOCK_*`), bits 20–62 = the block's file offset in MiB
//!   units. Payload entries and per-chunk *sector bitmap* entries
//!   interleave: BAT index of payload block `b` is
//!   `b + b / chunk_ratio` where `chunk_ratio = 2²³ · logical_sector /
//!   block_size`. `NOT_PRESENT`/`UNDEFINED`/`ZERO`/`UNMAPPED` states
//!   read as zeros.
//!
//! Differencing VHDX (`HasParent` file-parameter flag or a Parent
//! Locator metadata item) → [`Error::Unsupported`].
//!
//! ## Leniency contract
//!
//! * Footer/dynamic-header checksum mismatches and header version
//!   anomalies are recorded in [`VhdSource::warnings`], not fatal.
//! * A short BAT (truncated tail of file) pads the remainder as
//!   unallocated entries — affected blocks read as zeros with a warning.
//! * A block whose BAT entry points outside the file, or whose sector
//!   bitmap is unreadable, still returns whatever payload bytes exist
//!   (evidence-shaped leniency); a truncated fixed VHD zero-fills the
//!   missing tail.
//! * VHDX `PARTIALLY_PRESENT` payload blocks only occur in differencing
//!   disks (rejected at open); if one appears anyway its stored bytes
//!   are returned rather than fabricated zeros.
//! * Un-replayed VHDX log regions produce a warning — the view may be
//!   slightly stale but is never fabricated.
//!
//! No panics on untrusted input; allocation sizes are bounded by
//! [`MAX_BAT_ENTRIES`] and friends.

use std::io;
use std::sync::Arc;

use crate::le;
use crate::{ByteSource, Error, Result};

/// VHD footer cookie ("conectix").
pub const VHD_COOKIE: &[u8] = b"conectix";

/// VHDX file signature at offset 0.
pub const VHDX_SIGNATURE: &[u8] = b"vhdxfile";

/// VHD dynamic-header cookie ("cxsparse").
const VHD_DYNAMIC_COOKIE: &[u8] = b"cxsparse";

const VHD_FOOTER_SIZE: u64 = 512;
const VHD_DYNAMIC_HEADER_SIZE: u64 = 1024;
/// How far back from EOF to scan for a footer when trailing garbage is
/// appended (real-world images pick up trailing sectors/labels).
const FOOTER_SCAN_TAIL: u64 = 256 << 10;
/// BAT entry marking an unallocated VHD block.
const VHD_BAT_UNALLOCATED: u32 = 0xFFFF_FFFF;
const SECTOR: u64 = 512;

const VHDX_HEADER_SIZE: u64 = 4096;
const VHDX_HEADER_OFF1: u64 = 64 << 10;
const VHDX_HEADER_OFF2: u64 = 128 << 10;
const VHDX_REGION_OFF1: u64 = 192 << 10;
const VHDX_REGION_OFF2: u64 = 256 << 10;
const VHDX_REGION_TABLE_SIZE: u64 = 64 << 10;
const VHDX_REGION_ENTRY_SIZE: u64 = 32;
const VHDX_MAX_REGION_ENTRIES: u32 = 2047;
/// Metadata table header size; items must live at ≥ 64 KiB within the
/// metadata region, but we only require they stay inside the region.
const VHDX_METADATA_HEADER_SIZE: u64 = 64 << 10;
/// Cap on bytes read for the metadata region.
const MAX_METADATA_REGION: u64 = 4 << 20;

/// Plausibility bound on BAT entries. 2²² blocks × 32 MiB VHDX blocks ≈
/// 128 PiB of virtual disk — refuse beyond that rather than allocate.
const MAX_BAT_ENTRIES: u64 = 1 << 22;
/// Largest block size accepted (spec allows up to 256 MiB).
const MAX_BLOCK_SIZE: u64 = 256 << 20;
/// Bound on recorded warnings.
const MAX_WARNINGS: usize = 128;

/// VHDX BAT entry states (bits 0–2 of the entry).
const PAYLOAD_NOT_PRESENT: u64 = 0;
const PAYLOAD_UNDEFINED: u64 = 1;
const PAYLOAD_ZERO: u64 = 2;
const PAYLOAD_UNMAPPED: u64 = 3;
const PAYLOAD_FULLY_PRESENT: u64 = 6;
const PAYLOAD_PARTIALLY_PRESENT: u64 = 7;

// Region / metadata item GUIDs, on-disk little-endian byte order.
const VHDX_GUID_BAT: [u8; 16] = [
    0x66, 0x77, 0xC2, 0x2D, 0x23, 0xF6, 0x00, 0x42, 0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08,
];
const VHDX_GUID_METADATA: [u8; 16] = [
    0x06, 0xA2, 0x7C, 0x8B, 0x90, 0x47, 0x9A, 0x4B, 0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E,
];
const VHDX_ITEM_FILE_PARAMS: [u8; 16] = [
    0x37, 0x67, 0xA1, 0xCA, 0x36, 0xFA, 0x43, 0x4D, 0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B,
];
const VHDX_ITEM_VDISK_SIZE: [u8; 16] = [
    0x24, 0x42, 0xA5, 0x2F, 0x1B, 0xCD, 0x76, 0x48, 0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8,
];
const VHDX_ITEM_LOGICAL_SECTOR: [u8; 16] = [
    0x1D, 0xBF, 0x41, 0x81, 0x6F, 0xA9, 0x09, 0x47, 0xBA, 0x47, 0xF2, 0x33, 0xA8, 0xFA, 0xAB, 0x5F,
];
const VHDX_ITEM_PARENT_LOCATOR: [u8; 16] = [
    0x2D, 0x5F, 0xD3, 0xA8, 0x0B, 0xB3, 0x4D, 0x45, 0xAB, 0xF7, 0xD3, 0xD8, 0x48, 0x34, 0xAB, 0x0C,
];

fn warn(warnings: &mut Vec<String>, msg: impl Into<String>) {
    if warnings.len() < MAX_WARNINGS {
        warnings.push(msg.into());
    }
}

/// CRC-32C (Castagnoli) as used by VHDX headers and region tables.
/// Table built at compile time; `pub(crate)` for the test corpus.
pub(crate) fn crc32c_zeroed(data: &[u8], zero_off: usize) -> u32 {
    const fn table() -> [u32; 256] {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 { 0x82F6_3B78 ^ (c >> 1) } else { c >> 1 };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    }
    const T: [u32; 256] = table();
    let mut c = !0u32;
    for (i, &b) in data.iter().enumerate() {
        let b = if (zero_off..zero_off + 4).contains(&i) {
            0
        } else {
            b
        };
        c = T[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

// ---------------------------------------------------------------------------
// Public metadata
// ---------------------------------------------------------------------------

/// Which container format a [`VhdSource`] decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VhdFormat {
    /// Classic VHD ("conectix" footer).
    Vhd,
    /// VHDX ("vhdxfile" signature).
    Vhdx,
}

/// Geometry of an opened VHD/VHDX image.
#[derive(Debug, Clone)]
pub struct VhdInfo {
    /// Container format.
    pub format: VhdFormat,
    /// VHD footer disk type (2 = fixed, 3 = dynamic). VHDX reports 3 —
    /// both fixed and dynamic VHDX map through the BAT the same way.
    pub disk_type: u32,
    /// Virtual disk size in bytes.
    pub virtual_size: u64,
    /// Block size for dynamic formats (`None` for fixed VHD).
    pub block_size: Option<u32>,
    /// Logical sector size (always 512 for VHD; from metadata for VHDX).
    pub logical_sector_size: u32,
    /// File offset of the block allocation table, if any.
    pub bat_offset: Option<u64>,
    /// Number of BAT entries actually loaded.
    pub bat_entries: u64,
}

// ---------------------------------------------------------------------------
// VhdSource
// ---------------------------------------------------------------------------

/// How virtual-disk bytes map onto the file.
enum Mapping {
    /// Fixed VHD: bytes `[0, virtual_size)` map 1:1 at file offset 0.
    Fixed,
    /// Dynamic VHD: u32-sector-offset BAT + per-block sector bitmaps.
    VhdDynamic {
        bat: Vec<u32>,
        block_size: u64,
        /// Bytes of sector bitmap prepended to each block, 512-aligned.
        bitmap_bytes: u64,
    },
    /// VHDX: u64 BAT entries, payload/bitmap interleaved per chunk.
    Vhdx {
        bat: Vec<u64>,
        block_size: u64,
        /// Payload blocks per sector-bitmap block.
        chunk_ratio: u64,
    },
}

/// Read-only `ByteSource` over a VHD or VHDX image.
///
/// [`VhdSource::open`] auto-detects the format (`vhdxfile` signature at
/// 0 → VHDX, otherwise the `conectix` footer). Use as a plain
/// [`ByteSource`]; container metadata via [`VhdSource::info`] and
/// [`VhdSource::warnings`].
pub struct VhdSource {
    src: Arc<dyn ByteSource>,
    mapping: Mapping,
    /// Logical image size (virtual disk size).
    len: u64,
    info: VhdInfo,
    warnings: Vec<String>,
}

impl VhdSource {
    /// Quick probe: does this look like a VHD (cookie at EOF or file
    /// start, as dynamic disks carry a footer copy at offset 0)?
    pub fn is_vhd(src: &dyn ByteSource) -> bool {
        let head_ok = src
            .read_slice(0, VHD_COOKIE.len())
            .map(|h| h == VHD_COOKIE)
            .unwrap_or(false);
        if head_ok {
            return true;
        }
        let len = src.len();
        if len < VHD_FOOTER_SIZE {
            return false;
        }
        src.read_slice(len - VHD_FOOTER_SIZE, VHD_COOKIE.len())
            .map(|t| t == VHD_COOKIE)
            .unwrap_or(false)
    }

    /// Quick probe: VHDX file signature at offset 0.
    pub fn is_vhdx(src: &dyn ByteSource) -> bool {
        src.read_slice(0, VHDX_SIGNATURE.len())
            .map(|h| h == VHDX_SIGNATURE)
            .unwrap_or(false)
    }

    /// Open a VHD or VHDX image.
    ///
    /// Differencing images (VHD type 4, VHDX `HasParent`) return
    /// [`Error::Unsupported`]; missing/invalid footers and broken VHDX
    /// headers or region tables return [`Error::Corrupt`]/[`Error::Truncated`].
    pub fn open(src: Arc<dyn ByteSource>) -> Result<Self> {
        if Self::is_vhdx(src.as_ref()) {
            Self::open_vhdx(src)
        } else {
            Self::open_vhd(src)
        }
    }

    /// Container metadata.
    pub fn info(&self) -> &VhdInfo {
        &self.info
    }

    /// Non-fatal anomalies noticed while parsing.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Fill `buf` for the range starting at `pos` (already bounded to
    /// `self.len`), covering at most the current block; returns the
    /// number of bytes produced so the caller can loop across block
    /// boundaries. Unmapped regions become zeros.
    fn read_mapped(&self, pos: u64, buf: &mut [u8]) -> io::Result<usize> {
        match &self.mapping {
            Mapping::Fixed => {
                let n = self.src.read_at(pos, buf)?;
                buf[n..].fill(0); // truncated fixed image: zeros, not a lie
                Ok(buf.len())
            }
            Mapping::VhdDynamic {
                bat,
                block_size,
                bitmap_bytes,
            } => self.read_vhd_dynamic(pos, buf, bat, *block_size, *bitmap_bytes),
            Mapping::Vhdx {
                bat,
                block_size,
                chunk_ratio,
            } => self.read_vhdx_block(pos, buf, bat, *block_size, *chunk_ratio),
        }
    }

    /// Read within one dynamic-VHD block, honouring its sector bitmap.
    /// Returns the number of bytes covered (bounded by the block end).
    fn read_vhd_dynamic(
        &self,
        pos: u64,
        buf: &mut [u8],
        bat: &[u32],
        block_size: u64,
        bitmap_bytes: u64,
    ) -> io::Result<usize> {
        let blk = pos / block_size;
        let within = pos % block_size;
        let take = buf.len().min((block_size - within) as usize);
        let Some(&entry) = bat.get(blk as usize) else {
            buf[..take].fill(0);
            return Ok(take);
        };
        if entry == VHD_BAT_UNALLOCATED {
            buf[..take].fill(0);
            return Ok(take);
        }
        let block_off = (entry as u64).saturating_mul(SECTOR);
        let data_off = block_off.saturating_add(bitmap_bytes);

        // Fetch the bitmap span covering the sectors we touch. Missing
        // bitmap bytes are treated as "sector present" — the payload may
        // still be there and reading it is more honest than zeros.
        let sec_first = within / SECTOR;
        let sec_last = (within + take as u64 - 1) / SECTOR;
        let bm_start = sec_first / 8;
        let bm_len = sec_last / 8 - bm_start + 1;
        let bitmap = self
            .src
            .read_slice(block_off + bm_start, bm_len as usize)
            .unwrap_or_default();
        let sector_present = |sec: u64| -> bool {
            let byte_idx = (sec / 8 - bm_start) as usize;
            match bitmap.get(byte_idx) {
                Some(b) => b & (0x80 >> (sec % 8)) != 0,
                None => true, // unreadable bitmap → try the data
            }
        };

        let mut i = 0usize;
        while i < take {
            let w = within + i as u64;
            let sec = w / SECTOR;
            let n = (take - i).min((SECTOR - w % SECTOR) as usize);
            if sector_present(sec) {
                let got = self.src.read_at(data_off + w, &mut buf[i..i + n])?;
                buf[i + got..i + n].fill(0);
            } else {
                buf[i..i + n].fill(0);
            }
            i += n;
        }
        Ok(take)
    }

    /// Read within one VHDX payload block via its BAT entry.
    /// Returns the number of bytes covered (bounded by the block end).
    fn read_vhdx_block(
        &self,
        pos: u64,
        buf: &mut [u8],
        bat: &[u64],
        block_size: u64,
        chunk_ratio: u64,
    ) -> io::Result<usize> {
        let blk = pos / block_size;
        let within = pos % block_size;
        let take = buf.len().min((block_size - within) as usize);
        // Payload entries interleave with one sector-bitmap entry per
        // chunk_ratio blocks.
        let bat_idx = blk + blk / chunk_ratio;
        let Some(&entry) = bat.get(bat_idx as usize) else {
            buf[..take].fill(0);
            return Ok(take);
        };
        let state = entry & 7;
        match state {
            PAYLOAD_NOT_PRESENT | PAYLOAD_UNDEFINED | PAYLOAD_ZERO | PAYLOAD_UNMAPPED => {
                buf[..take].fill(0);
            }
            PAYLOAD_FULLY_PRESENT | PAYLOAD_PARTIALLY_PRESENT => {
                // PARTIALLY_PRESENT is only valid for differencing disks
                // (rejected at open); if it appears, return stored bytes.
                let file_off = ((entry >> 20) & ((1 << 43) - 1))
                    .checked_shl(20)
                    .unwrap_or(u64::MAX)
                    .saturating_add(within);
                let got = self.src.read_at(file_off, &mut buf[..take])?;
                buf[got..take].fill(0);
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("vhdx BAT entry {bat_idx}: reserved payload state {other}"),
                ));
            }
        }
        Ok(take)
    }

    // -- VHD (classic) ----------------------------------------------------

    fn open_vhd(src: Arc<dyn ByteSource>) -> Result<Self> {
        let file_len = src.len();
        if file_len < VHD_FOOTER_SIZE {
            return Err(Error::Truncated {
                offset: 0,
                requested: VHD_FOOTER_SIZE,
                available: file_len,
            });
        }
        let mut warnings = Vec::new();
        let (footer, footer_off) = locate_vhd_footer(src.as_ref(), file_len, &mut warnings)?;

        let version = le::u32_be(&footer, 12).unwrap_or(0);
        if version != 0x0001_0000 {
            warn(
                &mut warnings,
                format!("VHD footer: version {version:#010x}, expected 0x00010000"),
            );
        }
        // Checksum = one's complement of the byte sum with the field zeroed.
        let mut sum = 0u64;
        for (i, &b) in footer.iter().enumerate() {
            if !(64..68).contains(&i) {
                sum += b as u64;
            }
        }
        let stored_sum = le::u32_be(&footer, 64).unwrap_or(0);
        if stored_sum != !(sum as u32) {
            warn(
                &mut warnings,
                format!("VHD footer at {footer_off:#x}: checksum mismatch"),
            );
        }
        let disk_type = le::u32_be(&footer, 60).unwrap_or(0);
        let current_size = le::u64_be(&footer, 48).unwrap_or(0);
        if current_size == 0 {
            return Err(Error::corrupt(
                footer_off + 48,
                "VHD footer declares a zero virtual size",
            ));
        }

        match disk_type {
            2 => {
                if current_size > file_len.saturating_sub(VHD_FOOTER_SIZE) {
                    warn(
                        &mut warnings,
                        format!(
                            "fixed VHD declares {} bytes but the file holds {} before the footer; \
                             tail reads as zeros",
                            current_size,
                            file_len.saturating_sub(VHD_FOOTER_SIZE)
                        ),
                    );
                }
                Ok(Self {
                    src,
                    mapping: Mapping::Fixed,
                    len: current_size,
                    info: VhdInfo {
                        format: VhdFormat::Vhd,
                        disk_type,
                        virtual_size: current_size,
                        block_size: None,
                        logical_sector_size: 512,
                        bat_offset: None,
                        bat_entries: 0,
                    },
                    warnings,
                })
            }
            3 => Self::open_vhd_dynamic(src, file_len, &footer, current_size, warnings),
            4 => Err(Error::unsupported(
                "VHD differencing disk: needs its parent image to resolve blocks; not supported",
            )),
            t => Err(Error::unsupported(format!("VHD disk type {t}"))),
        }
    }

    fn open_vhd_dynamic(
        src: Arc<dyn ByteSource>,
        file_len: u64,
        footer: &[u8],
        current_size: u64,
        mut warnings: Vec<String>,
    ) -> Result<Self> {
        let data_offset = le::u64_be(footer, 16).unwrap_or(0);
        if data_offset
            .checked_add(VHD_DYNAMIC_HEADER_SIZE)
            .is_none_or(|e| e > file_len)
        {
            return Err(Error::Truncated {
                offset: data_offset,
                requested: VHD_DYNAMIC_HEADER_SIZE,
                available: file_len.saturating_sub(data_offset),
            });
        }
        let dh = src
            .read_slice(data_offset, VHD_DYNAMIC_HEADER_SIZE as usize)
            .map_err(Error::Io)?;
        if dh.get(..8) != Some(VHD_DYNAMIC_COOKIE) {
            return Err(Error::corrupt(
                data_offset,
                "dynamic VHD: missing cxsparse header",
            ));
        }
        let mut sum = 0u64;
        for (i, &b) in dh.iter().enumerate() {
            if !(36..40).contains(&i) {
                sum += b as u64;
            }
        }
        if le::u32_be(&dh, 36).unwrap_or(0) != !(sum as u32) {
            warn(
                &mut warnings,
                format!("VHD dynamic header at {data_offset:#x}: checksum mismatch"),
            );
        }
        let bat_offset = le::u64_be(&dh, 16).unwrap_or(0);
        let max_table_entries = le::u32_be(&dh, 28).unwrap_or(0) as u64;
        let block_size = le::u32_be(&dh, 32).unwrap_or(0) as u64;
        if block_size == 0
            || block_size % SECTOR != 0
            || !block_size.is_power_of_two()
            || block_size > MAX_BLOCK_SIZE
        {
            return Err(Error::corrupt(
                data_offset + 32,
                format!("dynamic VHD: implausible block_size {block_size}"),
            ));
        }
        if max_table_entries > MAX_BAT_ENTRIES {
            return Err(Error::unsupported(format!(
                "dynamic VHD with {max_table_entries} BAT entries"
            )));
        }
        let needed = current_size.div_ceil(block_size);
        let n = needed.min(max_table_entries);
        if max_table_entries < needed {
            warn(
                &mut warnings,
                format!(
                    "dynamic VHD: BAT holds {max_table_entries} entries but {needed} blocks \
                     are needed; tail blocks read as zeros"
                ),
            );
        }
        let bat_len = n.saturating_mul(4);
        let raw = src.read_slice(bat_offset, bat_len as usize).map_err(Error::Io)?;
        if (raw.len() as u64) < bat_len {
            warn(
                &mut warnings,
                format!(
                    "dynamic VHD: BAT at {bat_offset:#x} truncated ({} of {bat_len} bytes); \
                     missing entries read as zeros",
                    raw.len()
                ),
            );
        }
        let mut bat = Vec::with_capacity(n as usize);
        for i in 0..n as usize {
            let e = le::u32_be(&raw, i * 4).unwrap_or(VHD_BAT_UNALLOCATED);
            bat.push(e);
        }
        // Sector bitmap: one bit per 512-byte sector of the block,
        // rounded up to a 512-byte boundary, prepended to the payload.
        let spb = block_size / SECTOR;
        let bitmap_bytes = spb.div_ceil(8).div_ceil(SECTOR) * SECTOR;

        Ok(Self {
            src,
            mapping: Mapping::VhdDynamic {
                bat,
                block_size,
                bitmap_bytes,
            },
            len: current_size,
            info: VhdInfo {
                format: VhdFormat::Vhd,
                disk_type: 3,
                virtual_size: current_size,
                block_size: Some(block_size as u32),
                logical_sector_size: 512,
                bat_offset: Some(bat_offset),
                bat_entries: n,
            },
            warnings,
        })
    }

    // -- VHDX ---------------------------------------------------------------

    fn open_vhdx(src: Arc<dyn ByteSource>) -> Result<Self> {
        let file_len = src.len();
        if file_len < VHDX_REGION_OFF2 + VHDX_REGION_TABLE_SIZE {
            return Err(Error::Truncated {
                offset: 0,
                requested: VHDX_REGION_OFF2 + VHDX_REGION_TABLE_SIZE,
                available: file_len,
            });
        }
        let mut warnings = Vec::new();

        // ---- headers: highest-sequence checksum-valid copy wins.
        let h1 = parse_vhdx_header(src.as_ref(), VHDX_HEADER_OFF1, &mut warnings);
        let h2 = parse_vhdx_header(src.as_ref(), VHDX_HEADER_OFF2, &mut warnings);
        let header = match (h1, h2) {
            (Some(a), Some(b)) => Some(if b.seq >= a.seq { b } else { a }),
            (a, b) => a.or(b),
        };
        let Some(header) = header else {
            return Err(Error::corrupt(
                VHDX_HEADER_OFF1,
                "vhdx: no checksum-valid header copy",
            ));
        };
        if header.log_length != 0 {
            warn(
                &mut warnings,
                format!(
                    "vhdx: log region holds {} un-replayed bytes; view may be stale",
                    header.log_length
                ),
            );
        }

        // ---- region table: first checksum-valid copy.
        let mut bat_region = None;
        let mut meta_region = None;
        let mut found_table = false;
        for off in [VHDX_REGION_OFF1, VHDX_REGION_OFF2] {
            let Ok(t) = src.read_slice(off, VHDX_REGION_TABLE_SIZE as usize) else {
                continue;
            };
            if t.len() != VHDX_REGION_TABLE_SIZE as usize || t.get(..4) != Some(b"regi") {
                continue;
            }
            let stored = le::u32(&t, 4).unwrap_or(0);
            if crc32c_zeroed(&t, 4) != stored {
                warn(&mut warnings, format!("vhdx: region table at {off:#x}: CRC-32C mismatch"));
                continue;
            }
            found_table = true;
            let count = le::u32(&t, 8).unwrap_or(0).min(VHDX_MAX_REGION_ENTRIES);
            for i in 0..count as u64 {
                let e = 16 + i * VHDX_REGION_ENTRY_SIZE;
                let guid = le::get(&t, e as usize, 16).unwrap_or(&[]);
                let file_off = le::u64(&t, (e + 16) as usize).unwrap_or(0);
                let length = le::u64(&t, (e + 24) as usize).unwrap_or(0);
                if guid == VHDX_GUID_BAT {
                    bat_region = Some((file_off, length));
                } else if guid == VHDX_GUID_METADATA {
                    meta_region = Some((file_off, length));
                }
            }
            break;
        }
        if !found_table {
            return Err(Error::corrupt(
                VHDX_REGION_OFF1,
                "vhdx: no checksum-valid region table",
            ));
        }
        let Some((bat_off, _bat_len)) = bat_region else {
            return Err(Error::corrupt(VHDX_REGION_OFF1, "vhdx: region table has no BAT region"));
        };
        let Some((meta_off, meta_len)) = meta_region else {
            return Err(Error::corrupt(
                VHDX_REGION_OFF1,
                "vhdx: region table has no metadata region",
            ));
        };

        // ---- metadata items ------------------------------------------
        let meta_len = meta_len.min(MAX_METADATA_REGION);
        let meta = src.read_slice(meta_off, meta_len as usize).map_err(Error::Io)?;
        if meta.get(..8) != Some(b"metadata") {
            return Err(Error::corrupt(meta_off, "vhdx: bad metadata signature"));
        }
        let item_count = le::u16(&meta, 10).unwrap_or(0).min(2047) as usize;
        let mut block_size = 0u64;
        let mut has_parent = false;
        let mut virtual_size = 0u64;
        let mut logical_sector = 0u64;
        for i in 0..item_count {
            let e = 32 + i * 32;
            let Some(item) = le::get(&meta, e, 32) else { break };
            let item_off = le::u32(item, 16).unwrap_or(0) as u64;
            let item_len = le::u32(item, 20).unwrap_or(0) as u64;
            // Item offsets are relative to the start of the metadata
            // region; keep everything inside it.
            if item_off < VHDX_METADATA_HEADER_SIZE
                || item_off.checked_add(item_len).is_none_or(|x| x > meta.len() as u64)
            {
                warn(
                    &mut warnings,
                    format!("vhdx: metadata item {i} outside the region; skipped"),
                );
                continue;
            }
            let data = &meta[item_off as usize..(item_off + item_len) as usize];
            let id = &item[..16];
            if id == VHDX_ITEM_FILE_PARAMS {
                block_size = le::u32(data, 0).unwrap_or(0) as u64;
                has_parent = le::u32(data, 4).unwrap_or(0) & 0b10 != 0;
            } else if id == VHDX_ITEM_VDISK_SIZE {
                virtual_size = le::u64(data, 0).unwrap_or(0);
            } else if id == VHDX_ITEM_LOGICAL_SECTOR {
                logical_sector = le::u32(data, 0).unwrap_or(0) as u64;
            } else if id == VHDX_ITEM_PARENT_LOCATOR {
                has_parent = true;
            }
        }
        if has_parent {
            return Err(Error::unsupported(
                "vhdx differencing disk: needs its parent image to resolve blocks; not supported",
            ));
        }
        if virtual_size == 0 {
            return Err(Error::corrupt(meta_off, "vhdx: metadata declares a zero virtual size"));
        }
        if logical_sector == 0 {
            logical_sector = 512;
        }
        if !logical_sector.is_power_of_two() || !(SECTOR..=4096).contains(&logical_sector) {
            return Err(Error::corrupt(
                meta_off,
                format!("vhdx: implausible logical sector size {logical_sector}"),
            ));
        }
        if block_size == 0
            || !block_size.is_power_of_two()
            || block_size % logical_sector != 0
            || block_size > MAX_BLOCK_SIZE
        {
            return Err(Error::corrupt(
                meta_off,
                format!("vhdx: implausible block_size {block_size}"),
            ));
        }
        // chunk_ratio = chunk size (2^23 sectors) / block size.
        let chunk_ratio = (1u64 << 23)
            .saturating_mul(logical_sector)
            / block_size;
        if chunk_ratio == 0 {
            return Err(Error::corrupt(
                meta_off,
                "vhdx: block_size exceeds the 2^23-sector chunk size",
            ));
        }
        let blocks = virtual_size.div_ceil(block_size);
        let chunks = blocks.div_ceil(chunk_ratio);
        let bat_count = chunks.saturating_mul(chunk_ratio + 1);
        if bat_count > MAX_BAT_ENTRIES {
            return Err(Error::unsupported(format!(
                "vhdx with {bat_count} BAT entries (virtual size {virtual_size})"
            )));
        }
        let raw = src
            .read_slice(bat_off, (bat_count * 8) as usize)
            .map_err(Error::Io)?;
        if (raw.len() as u64) < bat_count * 8 {
            warn(
                &mut warnings,
                format!(
                    "vhdx: BAT at {bat_off:#x} truncated ({} of {} bytes); missing entries read as zeros",
                    raw.len(),
                    bat_count * 8
                ),
            );
        }
        let mut bat = Vec::with_capacity(bat_count as usize);
        for i in 0..bat_count as usize {
            bat.push(le::u64(&raw, i * 8).unwrap_or(0));
        }

        Ok(Self {
            src,
            mapping: Mapping::Vhdx {
                bat,
                block_size,
                chunk_ratio,
            },
            len: virtual_size,
            info: VhdInfo {
                format: VhdFormat::Vhdx,
                disk_type: 3,
                virtual_size,
                block_size: Some(block_size as u32),
                logical_sector_size: logical_sector as u32,
                bat_offset: Some(bat_off),
                bat_entries: bat_count,
            },
            warnings,
        })
    }
}

struct VhdxHeader {
    seq: u64,
    log_length: u32,
}

fn parse_vhdx_header(src: &dyn ByteSource, off: u64, warnings: &mut Vec<String>) -> Option<VhdxHeader> {
    let h = src.read_slice(off, VHDX_HEADER_SIZE as usize).ok()?;
    if h.len() != VHDX_HEADER_SIZE as usize || h.get(..4) != Some(b"head") {
        return None;
    }
    let stored = le::u32(&h, 4).unwrap_or(0);
    if crc32c_zeroed(&h, 4) != stored {
        warn(warnings, format!("vhdx: header at {off:#x}: CRC-32C mismatch"));
        return None;
    }
    let version = le::u16(&h, 34).unwrap_or(0);
    if version != 1 {
        warn(warnings, format!("vhdx: header at {off:#x}: version {version}, expected 1"));
    }
    Some(VhdxHeader {
        seq: le::u64(&h, 8).unwrap_or(0),
        log_length: le::u32(&h, 36).unwrap_or(0),
    })
}

/// Locate the VHD footer: the last 512 bytes if the cookie is there,
/// else a bounded backwards scan of the file tail for a `conectix`
/// candidate with plausible fields (trailing garbage tolerance).
fn locate_vhd_footer(
    src: &dyn ByteSource,
    file_len: u64,
    warnings: &mut Vec<String>,
) -> Result<(Vec<u8>, u64)> {
    let tail_len = file_len.min(FOOTER_SCAN_TAIL); // caller guarantees ≥ 512
    let tail_start = file_len - tail_len;
    let tail = src.read_slice(tail_start, tail_len as usize).map_err(Error::Io)?;
    let max_start = tail.len() - VHD_FOOTER_SIZE as usize;
    let mut fallback: Option<usize> = None;
    for i in (0..=max_start).rev() {
        if tail.get(i..i + 8) != Some(VHD_COOKIE) {
            continue;
        }
        let f = &tail[i..i + VHD_FOOTER_SIZE as usize];
        let disk_type = le::u32_be(f, 60).unwrap_or(0);
        let current = le::u64_be(f, 48).unwrap_or(0);
        if !(2..=4).contains(&disk_type) || current == 0 {
            continue;
        }
        // A checksum-valid candidate wins immediately scanning from the
        // end; otherwise remember the last plausible one.
        let mut sum = 0u64;
        for (j, &b) in f.iter().enumerate() {
            if !(64..68).contains(&j) {
                sum += b as u64;
            }
        }
        if le::u32_be(f, 64).unwrap_or(0) == !(sum as u32) {
            if i != max_start {
                warn(
                    warnings,
                    format!(
                        "VHD footer found at {:#x} ({} bytes of trailing garbage)",
                        tail_start + i as u64,
                        max_start - i
                    ),
                );
            }
            return Ok((f.to_vec(), tail_start + i as u64));
        }
        if fallback.is_none() {
            fallback = Some(i);
        }
    }
    if let Some(i) = fallback {
        warn(
            warnings,
            format!(
                "VHD footer at {:#x} has an invalid checksum; using it anyway",
                tail_start + i as u64
            ),
        );
        let f = tail[i..i + VHD_FOOTER_SIZE as usize].to_vec();
        return Ok((f, tail_start + i as u64));
    }
    Err(Error::corrupt(
        file_len.saturating_sub(VHD_FOOTER_SIZE),
        "no VHD footer (conectix) found at or near end of file",
    ))
}

impl ByteSource for VhdSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(usize::try_from(self.len - offset).unwrap_or(usize::MAX));
        let mut done = 0usize;
        while done < want {
            let n = self.read_mapped(offset + done as u64, &mut buf[done..want])?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }
}
