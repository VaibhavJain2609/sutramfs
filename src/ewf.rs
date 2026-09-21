//! EWF (Expert Witness Format, `*.E01`) — pure-Rust read-only reader.
//!
//! An EWF segment file is a sequence of framed *sections*:
//!
//! * **file header** (13 bytes): `EVF\x09\x0d\x0a\xff\x00` signature,
//!   field markers and the segment number (1-based);
//! * **section descriptors** (76 bytes each): a NUL-padded ASCII type
//!   string, the absolute offset of the *next* descriptor, the section
//!   data size, 40 bytes of padding and an Adler-32 checksum of the first
//!   72 bytes;
//! * **`header`/`header2`** — zlib-compressed acquisition metadata
//!   (examiner, case number, notes);
//! * **`volume`/`disk`/`data`** — media geometry: chunk count,
//!   sectors-per-chunk, bytes-per-sector, sector count, media type,
//!   compression level, error granularity and the segment-set GUID.
//!   (`data` sections repeat the volume layout in single-segment files.)
//! * **`sectors`** — the chunk payload container: a run of `chunk_size`
//!   byte blocks, each either zlib-deflate compressed or stored raw
//!   followed by a 4-byte Adler-32 trailer;
//! * **`table`/`table2`** — chunk-offset tables. A 24-byte header
//!   (entry count, padding, base offset for EnCase 6+, checksum), then
//!   `count` 4-byte entries and a 4-byte footer checksum. Each entry:
//!   bit 31 = "chunk is compressed", bits 30–0 = file offset of the
//!   chunk data relative to the table base offset (usually 0, i.e.
//!   absolute). `table2` is a mirror copy kept as backup;
//! * **`error2`** — acquisition-error ranges `(start_sector, count)`
//!   recorded when the source device could not be read; EnCase zeroed
//!   those sectors during acquisition;
//! * **`hash`/`digest`** — stored MD5 (`hash`, 16 bytes) and/or
//!   MD5 + SHA-1 (`digest`) of the media data, for integrity
//!   verification by the examiner;
//! * **`next`/`done`** — end-of-segment markers. `next` means the image
//!   continues in `.E02`; `done` terminates the last segment.
//!
//! ## Supported / unsupported
//!
//! * Single-segment EWF-E01 images (EnCase/FTK/`linen` `volume`+`sectors`
//!   layout, compressed and raw chunks): **readable**.
//! * Multi-segment images (`.E02`+): detected via the `next` section and
//!   via multiple `segments` arguments → [`Error::Unsupported`]. The
//!   plumbing to glue segments exists (`ConcatSource`-style) but is not
//!   wired up yet.
//! * EWF2 (`*.Ex01`), logical evidence files (`*.L01`, media type 0x0e)
//!   and SMART `*.s01` variants: → [`Error::Unsupported`].
//! * `session`, `ltree`, `xheader`, `restart_data` and other metadata
//!   sections are tolerated (skipped), not interpreted.
//!
//! ## Leniency contract
//!
//! * Descriptor/table checksums are verified where cheap but mismatches
//!   only record a warning (`EwfSource::warnings`) — Logicube imagers
//!   ship zero checksums, so failing on them would reject real evidence.
//! * A table that lists fewer entries than the declared `chunk_count`
//!   pads the tail as *missing* chunks that read as zeros; extra entries
//!   are ignored. Either way a warning is recorded.
//! * Table entries pointing outside the segment become missing chunks
//!   (zero-filled reads) with a warning.
//! * A chunk whose zlib stream fails to decode yields `io::Error` of
//!   kind `InvalidData` on reads touching that chunk — fabricated zeros
//!   would be dishonest when the stored data exists but is corrupt.
//! * Acquisition-error (`error2`) ranges always read as zeros
//!   (matching what the acquisition tool stored) and are exposed via
//!   [`EwfSource::error_ranges`].
//!
//! Memory is bounded: the chunk index is O(chunks) as required by the
//! format (4 bytes/entry on disk), and decoded data is held only in a
//! small LRU cache of [`CHUNK_CACHE_CAP`] chunks.

use std::io;
use std::sync::{Arc, Mutex};

use crate::le;
use crate::{ByteSource, Error, Result};

/// EWF file-signature bytes (`EVF` + format marker).
pub const EWF_SIGNATURE: &[u8] = b"EVF\x09\x0d\x0a\xff\x00";

/// EWF-L01 logical-evidence signature — recognised, unsupported.
const LVF_SIGNATURE: &[u8] = b"LVF\x09\x0d\x0a\xff\x00";

const FILE_HEADER_SIZE: u64 = 13;
const SECTION_DESCRIPTOR_SIZE: u64 = 76;
/// Cap on section descriptors walked per segment — real images use ≤ ~20.
const MAX_SECTIONS: usize = 4096;
/// Cap on bytes read for a single section's data (a full `table` for
/// [`MAX_TABLE_ENTRIES`] entries is ~16 MiB).
const MAX_SECTION_DATA: u64 = 64 << 20;
/// Plausibility bound on chunk-table entries (≈128 TiB at 32 KiB chunks).
const MAX_TABLE_ENTRIES: u64 = 1 << 22;
/// Decoded-chunk LRU capacity: 8 × `chunk_size` bytes at most.
const CHUNK_CACHE_CAP: usize = 8;
/// Bound on decompressed header text kept as metadata.
const MAX_HEADER_TEXT: usize = 64 << 10;
/// Bound on recorded warnings — a corrupt file must not flood memory.
const MAX_WARNINGS: usize = 128;
/// Largest chunk we will materialise (EnCase allows ≤ 32768 sectors of
/// arbitrary size; refuse absurd geometry instead of OOMing).
const MAX_CHUNK_SIZE: u64 = 64 << 20;
/// Fallback read bound for a compressed chunk whose end offset cannot be
/// derived from the next table entry. zlib streams self-terminate, so
/// this only needs to comfortably exceed `chunk_size`.
const COMPRESSED_CHUNK_SLACK: u64 = 64 << 10;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Adler-32 (RFC 1950) — the checksum EWF section descriptors and tables use.
/// `pub(crate)` so the test corpus can write valid descriptors.
pub(crate) fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a = 1u32;
    let mut b = 0u32;
    for &x in data {
        a += x as u32;
        if a >= MOD {
            a -= MOD;
        }
        b += a;
        b %= MOD;
    }
    (b << 16) | a
}

fn warn(warnings: &mut Vec<String>, msg: impl Into<String>) {
    if warnings.len() < MAX_WARNINGS {
        warnings.push(msg.into());
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// Public metadata types
// ---------------------------------------------------------------------------

/// Integrity hashes stored in the image's `hash`/`digest` sections.
///
/// These are the acquisition tool's *claims*; verify by hashing the
/// decoded bytes yourself. Fields are `None` when absent or all-zero.
#[derive(Debug, Clone, Default)]
pub struct AcqHash {
    /// MD5 of the media data, from `hash` or `digest`.
    pub md5: Option<[u8; 16]>,
    /// SHA-1 of the media data, from `digest` (EnCase ≥ 6.12).
    pub sha1: Option<[u8; 20]>,
}

impl AcqHash {
    /// Lowercase hex rendering of the stored MD5, if present.
    pub fn md5_hex(&self) -> Option<String> {
        self.md5.map(|h| hex(&h))
    }
    /// Lowercase hex rendering of the stored SHA-1, if present.
    pub fn sha1_hex(&self) -> Option<String> {
        self.sha1.map(|h| hex(&h))
    }
    fn is_empty(&self) -> bool {
        self.md5.is_none() && self.sha1.is_none()
    }
}

/// Geometry and acquisition metadata of an opened EWF image.
#[derive(Debug, Clone)]
pub struct EwfInfo {
    /// Segment number from the file header (always 1 for now).
    pub segment_number: u16,
    /// Media type byte from the volume section (0x00 removable,
    /// 0x01 fixed, 0x03 optical, 0x0e logical, 0x10 RAM).
    pub media_type: u8,
    /// Declared compression level (0 none, 1 good, 2 best).
    pub compression_level: u8,
    /// Bytes per decoded chunk (`sectors_per_chunk * bytes_per_sector`).
    pub chunk_size: u64,
    /// Declared chunk count across all segments.
    pub chunk_count: u64,
    /// Sectors per chunk (block size), typically 64.
    pub sectors_per_chunk: u32,
    /// Bytes per sector, typically 512.
    pub bytes_per_sector: u32,
    /// Declared sector count across all segments.
    pub sector_count: u64,
    /// Sectors per error block (`error2` granularity), 0 = unset.
    pub error_granularity: u32,
    /// Segment file set identifier GUID (RFC-4122 text), if stored.
    pub set_identifier: Option<String>,
    /// Whether the image declares further segments (`.E02`+). Always
    /// `false` for successfully opened images — multi-segment input is
    /// rejected with [`Error::Unsupported`]; kept for the future
    /// multi-segment reader.
    pub multi_segment: bool,
    /// Decompressed `header`/`header2` acquisition text (lossy, bounded).
    pub acquisition_header: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal parse structures
// ---------------------------------------------------------------------------

/// Where one logical chunk's stored bytes live.
#[derive(Debug, Clone, Copy)]
enum ChunkLoc {
    /// Stored at absolute `offset` in the segment; `compressed` = zlib.
    Stored { offset: u64, compressed: bool },
    /// No usable table entry — reads as zeros (documented leniency).
    Missing,
}

/// A parsed section descriptor.
struct Section {
    name: String,
    /// Offset of the descriptor itself (for error provenance).
    desc_offset: u64,
    /// Offset of the section data (`desc_offset + 76`).
    data_offset: u64,
    /// Declared data size, clamped to the segment end.
    data_size: u64,
}

/// Media geometry parsed from `volume`/`disk`/`data` sections.
#[derive(Debug, Clone)]
struct Volume {
    media_type: u8,
    chunk_count: u64,
    sectors_per_chunk: u32,
    bytes_per_sector: u32,
    sector_count: u64,
    compression_level: u8,
    error_granularity: u32,
    set_identifier: Option<String>,
}

/// Small LRU of decoded chunks, bounded by [`CHUNK_CACHE_CAP`].
struct ChunkCache {
    /// `(chunk_index, decoded)` — most-recently-used first.
    entries: Vec<(u64, Arc<Vec<u8>>)>,
}

impl ChunkCache {
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(CHUNK_CACHE_CAP),
        }
    }

    fn get(&mut self, idx: u64) -> Option<Arc<Vec<u8>>> {
        let pos = self.entries.iter().position(|(i, _)| *i == idx)?;
        let e = self.entries.remove(pos);
        self.entries.insert(0, e);
        Some(self.entries[0].1.clone())
    }

    fn put(&mut self, idx: u64, data: Vec<u8>) -> Arc<Vec<u8>> {
        if self.entries.len() == CHUNK_CACHE_CAP {
            self.entries.pop();
        }
        self.entries.insert(0, (idx, Arc::new(data)));
        self.entries[0].1.clone()
    }
}

// ---------------------------------------------------------------------------
// EwfSource
// ---------------------------------------------------------------------------

/// Read-only `ByteSource` over a single-segment EWF (`*.E01`) image.
///
/// Build with [`EwfSource::open`]; use as a plain [`ByteSource`]
/// (`read_at`, `read_slice`, `reader_at`) or interrogate acquisition
/// metadata via [`EwfSource::info`], [`EwfSource::acquisition_hash`],
/// [`EwfSource::error_ranges`] and [`EwfSource::warnings`].
pub struct EwfSource {
    src: Arc<dyn ByteSource>,
    info: EwfInfo,
    /// Chunk location map; index = logical chunk number. Length is the
    /// usable table entries; chunk indices beyond it read as zeros.
    locs: Vec<ChunkLoc>,
    /// Logical image size in bytes.
    len: u64,
    /// Acquisition-error byte ranges that always read as zeros.
    error_ranges: Vec<(u64, u64)>,
    hash: Option<AcqHash>,
    warnings: Vec<String>,
    cache: Mutex<ChunkCache>,
}

impl EwfSource {
    /// Probe the first segment's signature without opening the image.
    pub fn is_ewf(src: &dyn ByteSource) -> bool {
        src.read_slice(0, EWF_SIGNATURE.len())
            .map(|h| h == EWF_SIGNATURE)
            .unwrap_or(false)
    }

    /// Open a single-segment EWF image.
    ///
    /// `segments` currently must hold exactly one source (the `.E01`).
    /// Passing several segments, or a lone `.E01` containing a `next`
    /// section (i.e. the image continues in `.E02`+), returns
    /// [`Error::Unsupported`]; segment 1 itself is parsed fully so the
    /// error is a definitive detection, not a guess.
    ///
    /// A source that does not start with the `EVF` signature returns
    /// [`Error::Corrupt`] at offset 0.
    pub fn open(segments: Vec<Arc<dyn ByteSource>>) -> Result<Self> {
        match segments.len() {
            0 => {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "EWF image needs at least one segment source",
                )))
            }
            1 => {}
            n => {
                return Err(Error::unsupported(format!(
                    "multi-segment EWF images are not yet supported ({n} segments given)"
                )))
            }
        }
        let src = segments[0].clone();
        let file_len = src.len();
        if file_len < FILE_HEADER_SIZE {
            return Err(Error::Truncated {
                offset: 0,
                requested: FILE_HEADER_SIZE,
                available: file_len,
            });
        }
        let head = src.read_slice(0, FILE_HEADER_SIZE as usize).map_err(Error::Io)?;
        if head[0..8] == *LVF_SIGNATURE {
            return Err(Error::unsupported(
                "EWF-L01 logical evidence files are not supported",
            ));
        }
        if head[0..8] != *EWF_SIGNATURE {
            return Err(Error::corrupt(0, "not an EWF image (bad EVF signature)"));
        }

        let mut warnings = Vec::new();
        if head[8] != 0x01 {
            warn(
                &mut warnings,
                format!("file header: start-of-fields byte is {:#04x}, expected 0x01", head[8]),
            );
        }
        let segment_number = le::u16(&head, 9).unwrap_or(0);
        if segment_number == 0 {
            warn(&mut warnings, "file header: segment number is 0, treating as 1");
        } else if segment_number != 1 {
            return Err(Error::unsupported(format!(
                "EWF segment {segment_number}: only segment 1 can be opened"
            )));
        }

        // ---- walk the section descriptors -------------------------------
        let sections = walk_sections(src.as_ref(), file_len, &mut warnings);

        // ---- harvest the sections we understand -------------------------
        let mut volume: Option<Volume> = None;
        let mut primary_locs: Vec<ChunkLoc> = Vec::new();
        let mut backup_locs: Vec<ChunkLoc> = Vec::new();
        let mut error_ranges: Vec<(u64, u64)> = Vec::new();
        let mut hash = AcqHash::default();
        let mut header_text: Option<String> = None;
        let mut multi_segment = false;

        for sec in &sections {
            match sec.name.as_str() {
                "volume" | "disk" | "data" => {
                    match parse_volume(src.as_ref(), sec, &mut warnings) {
                        Ok(v) => {
                            if let Some(prev) = &volume {
                                if v.chunk_count != prev.chunk_count
                                    || v.sector_count != prev.sector_count
                                    || v.bytes_per_sector != prev.bytes_per_sector
                                    || v.sectors_per_chunk != prev.sectors_per_chunk
                                {
                                    warn(
                                        &mut warnings,
                                        format!(
                                            "section '{}' at {:#x} disagrees with earlier geometry",
                                            sec.name, sec.desc_offset
                                        ),
                                    );
                                }
                            } else {
                                volume = Some(v);
                            }
                        }
                        Err(e) => warn(
                            &mut warnings,
                            format!("{} section at {:#x}: {e}", sec.name, sec.desc_offset),
                        ),
                    }
                }
                "table" => parse_table(src.as_ref(), sec, &mut primary_locs, &mut warnings),
                "table2" => parse_table(src.as_ref(), sec, &mut backup_locs, &mut warnings),
                "error2" => {
                    let bps = volume.as_ref().map(|v| v.bytes_per_sector).unwrap_or(0);
                    parse_error2(src.as_ref(), sec, bps, &mut error_ranges, &mut warnings);
                }
                "hash" => {
                    if let Some(d) = read_section_data(src.as_ref(), sec, 36, &mut warnings) {
                        let md5: Option<[u8; 16]> =
                            le::get(&d, 0, 16).and_then(|s| s.try_into().ok());
                        if md5.map(|h| h.iter().any(|&b| b != 0)).unwrap_or(false) {
                            hash.md5 = md5;
                        }
                    }
                }
                "digest" => {
                    if let Some(d) = read_section_data(src.as_ref(), sec, 80, &mut warnings) {
                        let md5: Option<[u8; 16]> =
                            le::get(&d, 0, 16).and_then(|s| s.try_into().ok());
                        let sha1: Option<[u8; 20]> =
                            le::get(&d, 16, 20).and_then(|s| s.try_into().ok());
                        if md5.map(|h| h.iter().any(|&b| b != 0)).unwrap_or(false) {
                            hash.md5 = md5;
                        }
                        if sha1.map(|h| h.iter().any(|&b| b != 0)).unwrap_or(false) {
                            hash.sha1 = sha1;
                        }
                    }
                }
                "header" | "header2" => {
                    if header_text.is_none() {
                        header_text = parse_header_section(src.as_ref(), sec, &mut warnings);
                    }
                }
                "next" => multi_segment = true,
                "incomplete" => warn(
                    &mut warnings,
                    format!("image carries an 'incomplete' section at {:#x}", sec.desc_offset),
                ),
                // sectors / done / session / ltree / restart_data / xheader /
                // unknown types: tolerated, not interpreted.
                _ => {}
            }
        }

        if multi_segment {
            return Err(Error::unsupported(
                "EWF image continues in further segment(s) (.E02+); \
                 multi-segment reading is not yet supported",
            ));
        }

        let vol = volume.ok_or_else(|| {
            Error::corrupt(0, "EWF image has no readable volume/disk section")
        })?;
        if vol.media_type == 0x0e {
            return Err(Error::unsupported(
                "logical evidence (media type 0x0e / L01) is not supported",
            ));
        }
        if vol.bytes_per_sector == 0 || vol.sectors_per_chunk == 0 {
            return Err(Error::corrupt(
                FILE_HEADER_SIZE,
                "volume section has zero bytes-per-sector or sectors-per-chunk",
            ));
        }
        let chunk_size = (vol.sectors_per_chunk as u64)
            .checked_mul(vol.bytes_per_sector as u64)
            .filter(|&cs| cs > 0 && cs <= MAX_CHUNK_SIZE)
            .ok_or_else(|| {
                Error::corrupt(
                    FILE_HEADER_SIZE,
                    format!(
                        "implausible chunk geometry: {} sectors/chunk x {} bytes/sector",
                        vol.sectors_per_chunk, vol.bytes_per_sector
                    ),
                )
            })?;

        // ---- pick the chunk table: primary `table`, `table2` mirror as
        // backup (it exists for exactly this failure mode).
        let mut locs = if primary_locs.len() >= backup_locs.len() {
            primary_locs
        } else {
            warn(
                &mut warnings,
                format!(
                    "'table' sections yielded {} entries, 'table2' mirror {}; using the mirror",
                    primary_locs.len(),
                    backup_locs.len()
                ),
            );
            backup_locs
        };

        // header-vs-table count mismatches: lenient, documented.
        match locs.len().cmp(&(vol.chunk_count as usize)) {
            std::cmp::Ordering::Less => warn(
                &mut warnings,
                format!(
                    "volume declares {} chunks but table lists {}; tail chunks read as zeros",
                    vol.chunk_count,
                    locs.len()
                ),
            ),
            std::cmp::Ordering::Greater => {
                warn(
                    &mut warnings,
                    format!(
                        "table lists {} entries but volume declares {} chunks; extras ignored",
                        locs.len(),
                        vol.chunk_count
                    ),
                );
                locs.truncate(vol.chunk_count as usize);
            }
            std::cmp::Ordering::Equal => {}
        }

        // Entries pointing outside the segment degrade to missing chunks.
        let mut bad = 0u64;
        for loc in &mut locs {
            if let ChunkLoc::Stored { offset, .. } = *loc {
                if offset >= file_len {
                    *loc = ChunkLoc::Missing;
                    bad += 1;
                }
            }
        }
        if bad > 0 {
            warn(
                &mut warnings,
                format!("{bad} table entr(ies) point outside the segment; those chunks read as zeros"),
            );
        }

        // Logical image size: declared sectors, capped by chunk capacity;
        // when either side is 0 trust the other (real images disagree here
        // surprisingly often).
        let by_sectors = vol.sector_count.saturating_mul(vol.bytes_per_sector as u64);
        let by_chunks = vol.chunk_count.saturating_mul(chunk_size);
        let len = match (by_sectors == 0, by_chunks == 0) {
            (false, false) => by_sectors.min(by_chunks),
            (false, true) => by_sectors,
            (true, false) => by_chunks,
            (true, true) => {
                return Err(Error::corrupt(
                    FILE_HEADER_SIZE,
                    "volume section declares zero sectors and zero chunks",
                ))
            }
        };
        if by_sectors != 0 && by_chunks != 0 && by_sectors > by_chunks {
            warn(
                &mut warnings,
                format!(
                    "declared media size {by_sectors} exceeds chunk capacity {by_chunks}; clamped"
                ),
            );
        }

        let info = EwfInfo {
            segment_number,
            media_type: vol.media_type,
            compression_level: vol.compression_level,
            chunk_size,
            chunk_count: vol.chunk_count,
            sectors_per_chunk: vol.sectors_per_chunk,
            bytes_per_sector: vol.bytes_per_sector,
            sector_count: vol.sector_count,
            error_granularity: vol.error_granularity,
            set_identifier: vol.set_identifier,
            multi_segment: false,
            acquisition_header: header_text,
        };

        let hash_opt = if hash.is_empty() { None } else { Some(hash) };
        Ok(Self {
            src,
            info,
            locs,
            len,
            error_ranges,
            hash: hash_opt,
            warnings,
            cache: Mutex::new(ChunkCache::new()),
        })
    }

    /// Geometry and acquisition metadata.
    pub fn info(&self) -> &EwfInfo {
        &self.info
    }

    /// Stored acquisition hashes (`hash`/`digest` sections), if any.
    ///
    /// These are claims made by the acquisition tool, not verification —
    /// hash the decoded bytes yourself to check them.
    pub fn acquisition_hash(&self) -> Option<&AcqHash> {
        self.hash.as_ref()
    }

    /// Byte ranges the acquisition tool could not read (`error2`
    /// section). Reads overlapping them return zeros — what the tool
    /// itself stored at acquisition time.
    pub fn error_ranges(&self) -> &[(u64, u64)] {
        &self.error_ranges
    }

    /// Non-fatal anomalies noticed while parsing (checksum mismatches,
    /// count mismatches, degraded table entries, …).
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Bytes of logical chunk `idx` that actually exist
    /// (`chunk_size`, shorter for the last chunk).
    fn chunk_len(&self, idx: u64) -> u64 {
        let start = idx.saturating_mul(self.info.chunk_size);
        self.info.chunk_size.min(self.len.saturating_sub(start))
    }

    /// Decode chunk `idx` into memory (cached).
    fn decoded_chunk(&self, idx: u64) -> io::Result<Arc<Vec<u8>>> {
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| io::Error::other("ewf chunk cache lock poisoned"))?;
            if let Some(d) = cache.get(idx) {
                return Ok(d);
            }
        }
        let data = self.decode_chunk(idx)?;
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| io::Error::other("ewf chunk cache lock poisoned"))?;
        Ok(cache.put(idx, data))
    }

    /// Fetch and decode chunk `idx`. Always returns `chunk_len` bytes
    /// (padding short stored data with zeros — a short read at the end
    /// of the segment is evidence-shaped too).
    fn decode_chunk(&self, idx: u64) -> io::Result<Vec<u8>> {
        let expected = self.chunk_len(idx);
        let expected_usize = usize::try_from(expected).unwrap_or(usize::MAX);
        let Some(&loc) = self.locs.get(idx as usize) else {
            // Beyond the parsed table: documented leniency — zeros.
            return Ok(vec![0u8; expected_usize]);
        };
        let (offset, compressed) = match loc {
            ChunkLoc::Missing => return Ok(vec![0u8; expected_usize]),
            ChunkLoc::Stored { offset, compressed } => (offset, compressed),
        };
        let file_len = self.src.len();
        if offset >= file_len {
            return Ok(vec![0u8; expected_usize]);
        }
        let avail = file_len - offset;

        // Stored length: prefer the delta to the next chunk's offset
        // (authoritative in well-formed images); otherwise a bound that
        // comfortably fits the chunk (zlib streams self-terminate; raw
        // chunks are `expected + 4` trailer bytes).
        let next_off = self
            .locs
            .get(idx as usize + 1)
            .and_then(|l| match l {
                ChunkLoc::Stored { offset: o, .. } if *o > offset => Some(*o),
                _ => None,
            });
        let bound = match next_off {
            Some(n) => (n - offset).min(avail),
            None if compressed => (expected.saturating_add(COMPRESSED_CHUNK_SLACK)).min(avail),
            None => (expected.saturating_add(4)).min(avail),
        };
        let stored = self
            .src
            .read_slice(offset, usize::try_from(bound).unwrap_or(usize::MAX))?;

        let mut out = if compressed {
            // Bound output by chunk_size (a stored chunk never legitimately
            // holds more), not by `expected` — writers may store a full
            // chunk's worth even for the tail chunk.
            let limit = usize::try_from(self.info.chunk_size).unwrap_or(usize::MAX);
            let mut d = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(
                &stored, limit,
            )
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("ewf chunk {idx} at {offset:#x}: corrupt zlib stream ({e:?})"),
                )
            })?;
            d.truncate(expected_usize);
            d
        } else {
            // Raw chunk: `expected` data bytes + 4-byte Adler-32 trailer.
            let take = stored.len().min(expected_usize);
            stored[..take].to_vec()
        };
        out.resize(expected_usize, 0);
        Ok(out)
    }
}

impl ByteSource for EwfSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let chunk_size = self.info.chunk_size;
        let mut done = 0usize;
        let mut pos = offset;
        while done < buf.len() && pos < self.len {
            let idx = pos / chunk_size;
            let within = pos % chunk_size;
            let want = (buf.len() - done)
                .min(usize::try_from(chunk_size - within).unwrap_or(usize::MAX))
                .min(usize::try_from(self.len - pos).unwrap_or(usize::MAX));
            let chunk = self.decoded_chunk(idx)?;
            let s = within as usize;
            // `chunk` is exactly chunk_len(idx) bytes and `want` is bounded
            // by both, so this cannot run out; `(*chunk)` disambiguates
            // `Vec::len` from `ByteSource::len` on the Arc.
            let n = want.min((*chunk).len().saturating_sub(s));
            buf[done..done + n].copy_from_slice(&chunk[s..s + n]);
            // Defensive zero tail (unreachable while the invariant holds).
            buf[done + n..done + want].fill(0);
            pos = pos.saturating_add(want as u64);
            done += want;
        }
        // Acquisition-error ranges read as zeros regardless of stored data.
        let end = offset.saturating_add(done as u64);
        for &(es, ee) in &self.error_ranges {
            let lo = offset.max(es);
            let hi = end.min(ee);
            if lo < hi {
                buf[((lo - offset) as usize)..((hi - offset) as usize)].fill(0);
            }
        }
        Ok(done)
    }
}

// ---------------------------------------------------------------------------
// Section walking & per-section parsers
// ---------------------------------------------------------------------------

/// Walk the descriptor chain starting after the 13-byte file header.
/// Stops at `done`, at a non-forwarding `next` pointer, or at
/// [`MAX_SECTIONS`] — corrupt chains degrade to warnings, never panics.
fn walk_sections(
    src: &dyn ByteSource,
    file_len: u64,
    warnings: &mut Vec<String>,
) -> Vec<Section> {
    let mut sections = Vec::new();
    let mut off = FILE_HEADER_SIZE;
    for _ in 0..MAX_SECTIONS {
        if off.checked_add(SECTION_DESCRIPTOR_SIZE).is_none_or(|e| e > file_len) {
            if off != file_len {
                warn(
                    warnings,
                    format!("section walk stopped at {off:#x}: no room for a descriptor"),
                );
            }
            break;
        }
        let d = match src.read_slice(off, SECTION_DESCRIPTOR_SIZE as usize) {
            Ok(d) if d.len() == SECTION_DESCRIPTOR_SIZE as usize => d,
            Ok(_) => break,
            Err(e) => {
                warn(warnings, format!("section descriptor at {off:#x}: read failed: {e}"));
                break;
            }
        };
        let name = le::ascii(&d, 0, 16).unwrap_or_default();
        let next = le::u64(&d, 16).unwrap_or(0);
        let size = le::u64(&d, 24).unwrap_or(0);
        let stored_sum = le::u32(&d, 72).unwrap_or(0);
        if adler32(&d[..72]) != stored_sum {
            warn(
                warnings,
                format!("section descriptor '{name}' at {off:#x}: Adler-32 checksum mismatch"),
            );
        }
        if name.is_empty() {
            warn(
                warnings,
                format!("section descriptor at {off:#x}: empty type; stopping walk"),
            );
            break;
        }
        let data_offset = off + SECTION_DESCRIPTOR_SIZE;
        let data_size = size.min(file_len.saturating_sub(data_offset));
        if data_size < size {
            warn(
                warnings,
                format!("section '{name}' at {off:#x}: size {size} exceeds segment end; clamped"),
            );
        }
        let is_done = name == "done";
        let is_terminator = matches!(name.as_str(), "done" | "next");
        sections.push(Section {
            name: name.clone(),
            desc_offset: off,
            data_offset,
            data_size,
        });
        if is_done {
            break;
        }
        // `next` must move forward (it points at itself for done/next
        // terminators); anything else is a corrupt chain.
        if next <= off || next > file_len {
            if !is_terminator {
                warn(
                    warnings,
                    format!(
                        "section '{name}' at {off:#x}: next-section offset {next:#x} does not advance; stopping walk"
                    ),
                );
            }
            break;
        }
        off = next;
    }
    sections
}

/// Fetch a section's data if it fits our bound; warns and returns `None`
/// on failure. `min_size` is the smallest meaningful payload.
fn read_section_data(
    src: &dyn ByteSource,
    sec: &Section,
    min_size: u64,
    warnings: &mut Vec<String>,
) -> Option<Vec<u8>> {
    if sec.data_size < min_size {
        warn(
            warnings,
            format!(
                "section '{}' at {:#x}: {} bytes, need ≥ {min_size}",
                sec.name, sec.desc_offset, sec.data_size
            ),
        );
        return None;
    }
    if sec.data_size > MAX_SECTION_DATA {
        warn(
            warnings,
            format!(
                "section '{}' at {:#x}: {} bytes exceeds bound; skipped",
                sec.name, sec.desc_offset, sec.data_size
            ),
        );
        return None;
    }
    match src.read_slice(sec.data_offset, sec.data_size as usize) {
        Ok(d) if d.len() as u64 == sec.data_size => Some(d),
        Ok(d) => {
            warn(
                warnings,
                format!(
                    "section '{}' at {:#x}: short read ({} of {} bytes)",
                    sec.name,
                    sec.desc_offset,
                    d.len(),
                    sec.data_size
                ),
            );
            None
        }
        Err(e) => {
            warn(
                warnings,
                format!("section '{}' at {:#x}: read failed: {e}", sec.name, sec.desc_offset),
            );
            None
        }
    }
}

/// Parse a `volume`/`disk`/`data` section. Two layouts exist: the 94-byte
/// ASR02 original (u32 sector count at 16) and the 1052-byte EnCase/FTK
/// layout (u64 sector count at 16, plus compression level, error
/// granularity and the set GUID).
fn parse_volume(
    src: &dyn ByteSource,
    sec: &Section,
    warnings: &mut Vec<String>,
) -> Result<Volume> {
    let data = read_section_data(src, sec, 20, warnings)
        .ok_or_else(|| Error::corrupt(sec.desc_offset, "volume section unreadable"))?;
    let wide = data.len() >= 1052;
    let sector_count = if wide {
        le::u64(&data, 16).unwrap_or(0)
    } else {
        le::u32(&data, 16).unwrap_or(0) as u64
    };
    Ok(Volume {
        media_type: le::u8(&data, 0).unwrap_or(0),
        chunk_count: le::u32(&data, 4).unwrap_or(0) as u64,
        sectors_per_chunk: le::u32(&data, 8).unwrap_or(0),
        bytes_per_sector: le::u32(&data, 12).unwrap_or(0),
        sector_count,
        compression_level: if wide { le::u8(&data, 52).unwrap_or(0) } else { 0 },
        error_granularity: if wide { le::u32(&data, 56).unwrap_or(0) } else { 0 },
        set_identifier: if wide { le::uuid_le(&data, 64) } else { None },
    })
}

/// Parse a `table`/`table2` section and append its chunk entries to
/// `out`. Layout: 24-byte header (count u32, pad u32, base offset u64 —
/// EnCase 6+, 0 before — pad u32, header Adler-32), `count` u32 entries
/// (bit 31 = compressed, bits 30–0 = chunk offset relative to base),
/// 4-byte footer checksum. A section that is too short for its declared
/// count is clamped to what fits (warning), not fatal.
fn parse_table(
    src: &dyn ByteSource,
    sec: &Section,
    out: &mut Vec<ChunkLoc>,
    warnings: &mut Vec<String>,
) {
    let Some(data) = read_section_data(src, sec, 24, warnings) else {
        return;
    };
    let declared = le::u32(&data, 0).unwrap_or(0) as u64;
    let base = le::u64(&data, 8).unwrap_or(0);
    let avail = (data.len().saturating_sub(24) / 4) as u64;
    let n = declared.min(avail);
    if declared > avail {
        warn(
            warnings,
            format!(
                "table section at {:#x}: declares {declared} entries, only {avail} fit; clamped",
                sec.desc_offset
            ),
        );
    }
    let room = MAX_TABLE_ENTRIES.saturating_sub(out.len() as u64);
    let n = n.min(room);
    if n < declared.min(avail) {
        warn(
            warnings,
            format!("chunk table exceeds {MAX_TABLE_ENTRIES} entries; truncated"),
        );
    }
    for i in 0..n {
        let raw = le::u32(&data, 24 + i as usize * 4).unwrap_or(0);
        let compressed = raw & 0x8000_0000 != 0;
        let offset = base.saturating_add((raw & 0x7fff_ffff) as u64);
        out.push(ChunkLoc::Stored { offset, compressed });
    }
}

/// Parse an `error2` section: 520-byte header (entry count u32, padding,
/// checksum), then `count` 8-byte `(start_sector, sector_count)` entries
/// and a footer checksum. Entries are converted to byte ranges.
fn parse_error2(
    src: &dyn ByteSource,
    sec: &Section,
    bytes_per_sector: u32,
    out: &mut Vec<(u64, u64)>,
    warnings: &mut Vec<String>,
) {
    let Some(data) = read_section_data(src, sec, 520, warnings) else {
        return;
    };
    let declared = le::u32(&data, 0).unwrap_or(0) as u64;
    let avail = (data.len().saturating_sub(520) / 8) as u64;
    let n = declared.min(avail).min(1 << 20);
    if declared > n {
        warn(
            warnings,
            format!(
                "error2 section at {:#x}: declares {declared} entries, {n} parsed",
                sec.desc_offset
            ),
        );
    }
    let bps = bytes_per_sector.max(1) as u64;
    for i in 0..n {
        let e = 520 + i as usize * 8;
        let start = le::u32(&data, e).unwrap_or(0) as u64;
        let count = le::u32(&data, e + 4).unwrap_or(0) as u64;
        if count == 0 {
            continue;
        }
        let (Some(lo), Some(hi)) = (
            start.checked_mul(bps),
            start.checked_add(count).and_then(|s| s.checked_mul(bps)),
        ) else {
            warn(
                warnings,
                format!("error2 entry {i} at {:#x}: sector range overflows u64; skipped", sec.desc_offset),
            );
            continue;
        };
        out.push((lo, hi));
    }
}

/// Decompress a `header`/`header2` section into bounded text. `header`
/// is ASCII-ish; `header2` is UTF-16LE (EnCase ≥ 4).
fn parse_header_section(
    src: &dyn ByteSource,
    sec: &Section,
    warnings: &mut Vec<String>,
) -> Option<String> {
    let data = read_section_data(src, sec, 2, warnings)?;
    let text = miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&data, MAX_HEADER_TEXT)
        .map_err(|e| {
            warn(
                warnings,
                format!("{} section at {:#x}: zlib decode failed ({e:?})", sec.name, sec.desc_offset),
            );
            e
        })
        .ok()?;
    if sec.name == "header2" {
        let units: Vec<u16> = text
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    } else {
        Some(String::from_utf8_lossy(&text).into_owned())
    }
}
