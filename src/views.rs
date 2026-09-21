//! Composable `ByteSource` views: sub-ranges, concatenation and sparse
//! extent maps. These are the building blocks partition tables and
//! container formats (Android sparse images, later qcow2/VMDK) sit on.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::{ByteSource, Error, FileSource, Result};

/// A read-only window into another source: bytes `[offset, offset+len)` of
/// the inner source become `[0, len)` of this view.
///
/// Used for partition views — mounting `/dev/...` partition N is just an
/// `OffsetView` over the whole-disk image. Reads are bounds-checked; nothing
/// outside the window is reachable through this view.
#[derive(Clone)]
pub struct OffsetView {
    inner: Arc<dyn ByteSource>,
    offset: u64,
    len: u64,
}

impl OffsetView {
    /// Create a view over `inner[offset .. offset+len]`.
    ///
    /// `offset + len` may exceed `inner.len()` — the view simply truncates
    /// reads at the inner end (images are often shorter than the partition
    /// table claims); `len()` still reports the *claimed* size so parsers can
    /// distinguish "partition says X" from "backing has Y".
    pub fn new(inner: Arc<dyn ByteSource>, offset: u64, len: u64) -> Result<Self> {
        if offset > inner.len() {
            return Err(Error::Truncated {
                offset,
                requested: len,
                available: inner.len().saturating_sub(offset),
            });
        }
        Ok(Self { inner, offset, len })
    }

    /// Absolute offset of this view's byte 0 in the underlying image —
    /// essential for provenance reporting.
    pub fn base_offset(&self) -> u64 {
        self.offset
    }

    /// The wrapped source.
    pub fn inner(&self) -> &Arc<dyn ByteSource> {
        &self.inner
    }
}

impl ByteSource for OffsetView {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let want = buf.len().min((self.len - offset) as usize);
        self.inner
            .read_at(self.offset.saturating_add(offset), &mut buf[..want])
    }
}

/// Several sources concatenated end-to-end into one logical source
/// (e.g. split raw images `disk.001`/`disk.002`, or a reconstructed
/// region made of several extents).
pub struct ConcatSource {
    /// `(start_offset_in_concat, source)` pairs, sorted, contiguous.
    segments: Vec<(u64, Arc<dyn ByteSource>)>,
    len: u64,
}

impl ConcatSource {
    /// Build from sources laid out contiguously in order.
    pub fn new(parts: Vec<Arc<dyn ByteSource>>) -> Self {
        let mut segments = Vec::with_capacity(parts.len());
        let mut pos = 0u64;
        for p in parts {
            let l = p.len();
            segments.push((pos, p));
            pos = pos.saturating_add(l);
        }
        Self {
            segments,
            len: pos,
        }
    }

    /// Number of segments glued together.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Open a **split-raw** image — `disk.001`/`disk.002`/…, `disk_01`,
    /// `disk_aa`/`disk_ab` (split(1)) — as one concatenated source.
    ///
    /// `path` may point at *any* segment: the naming pattern is taken
    /// from its suffix, then every sibling in the same directory with
    /// the same stem and a matching numeric (`≥ 2` digits) or
    /// `split(1)`-style alphabetic (exactly 2 lowercase letters) suffix
    /// is collected and ordered by segment number (`aa → az → ba …`,
    /// `001 → 002 → …`). All matched files are concatenated in order,
    /// whether or not `path` was the first one.
    ///
    /// A name without a recognised split suffix returns
    /// [`io::ErrorKind::InvalidInput`]; a `path` that does not exist on
    /// disk returns [`io::ErrorKind::NotFound`].
    pub fn open_split(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let members = split_members(path)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "'{}' is not a split-image segment name \
                     (expected <name>.<digits>, <name>_<digits> or <name>[_|.]<aa..>)",
                    path.display()
                ),
            )
        })?;
        if !members.iter().any(|m| m == path) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("split segment '{}' not found", path.display()),
            ));
        }
        let mut parts: Vec<Arc<dyn ByteSource>> = Vec::with_capacity(members.len());
        for m in &members {
            parts.push(Arc::new(FileSource::open(m).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("cannot open split segment '{}': {e}", m.display()),
                )
            })?));
        }
        Ok(Self::new(parts))
    }

    /// Locate the segment containing `offset` → (index, offset within segment).
    fn locate(&self, offset: u64) -> Option<(usize, u64)> {
        // segments.len() is small (split images); linear scan is fine and
        // keeps the code obviously correct.
        let mut idx = None;
        for (i, (start, src)) in self.segments.iter().enumerate() {
            // `offset - start` avoids `start + len` overflowing u64.
            if *start <= offset && offset - start < src.len() {
                idx = Some((i, offset - start));
            }
        }
        idx
    }
}

impl ByteSource for ConcatSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, mut buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let mut done = 0usize;
        let mut pos = offset;
        while !buf.is_empty() {
            let Some((i, within)) = self.locate(pos) else {
                break;
            };
            let seg = &self.segments[i].1;
            let n = seg.read_at(within, buf)?;
            if n == 0 {
                break;
            }
            done += n;
            pos = pos.saturating_add(n as u64);
            buf = &mut buf[n..];
        }
        Ok(done)
    }
}

/// Does `path` look like a member of a split-raw image?
///
/// True when the file name carries a recognised split suffix
/// (`<name>.<2+ digits>`, `<name>_<2+ digits>`, or `<name>[.|_]<exactly
/// 2 lowercase letters>` à la `split(1)`) **and** at least two matching
/// sibling files — including `path` itself — exist in its directory.
/// The 2-letter limit keeps ordinary extensions (`.raw`, `.img`, …)
/// from matching. I/O failures (unreadable directory, non-UTF-8 names)
/// yield `false`.
pub fn detect_split(path: impl AsRef<Path>) -> bool {
    let path = path.as_ref();
    match split_members(path) {
        Ok(Some(members)) => members.len() >= 2 && members.iter().any(|m| m == path),
        _ => false,
    }
}

/// Split-segment ordering key.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum SplitKey {
    /// `<name>.001`, `<name>_07`: ordered numerically (zero-padding is
    /// irrelevant — the value decides).
    Numeric(u128),
    /// `split(1)` style `aa, ab, …, az, ba` (exactly two letters).
    Alpha(String),
}

/// Parse `<stem><sep><suffix>` out of a file name. Returns
/// `(name_up_to_and_including_sep, key)` or `None` when the suffix is
/// not a recognised split convention.
fn split_suffix(name: &str) -> Option<(&str, SplitKey)> {
    // Only the last '.'/'_' may introduce the segment suffix.
    let sep = name.rfind(['.', '_'])?;
    if sep == 0 || sep + 1 == name.len() {
        return None;
    }
    let suffix = &name[sep + 1..];
    if suffix.len() >= 2 && suffix.bytes().all(|b| b.is_ascii_digit()) {
        let v = suffix.parse::<u128>().ok()?;
        return Some((&name[..sep + 1], SplitKey::Numeric(v)));
    }
    // Exactly two lowercase letters — split(1)'s default; a wider net
    // would catch ordinary file extensions.
    if suffix.len() == 2 && suffix.bytes().all(|b| b.is_ascii_lowercase()) {
        return Some((&name[..sep + 1], SplitKey::Alpha(suffix.to_string())));
    }
    None
}

/// All sibling files in `path`'s directory that share its stem and
/// suffix convention, ordered by segment number. `Ok(None)` means the
/// name carries no recognised split suffix.
fn split_members(path: &Path) -> io::Result<Option<Vec<PathBuf>>> {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return Ok(None),
    };
    let Some((prefix, key)) = split_suffix(name) else {
        return Ok(None);
    };
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut members: Vec<(SplitKey, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let Some(fname) = entry.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        if !fname.starts_with(prefix) {
            continue;
        }
        // The sibling must parse to the *same* stem+separator — this
        // excludes lookalikes like `disk.extra.003` under `disk.`.
        let Some((p2, k)) = split_suffix(&fname) else {
            continue;
        };
        if p2 != prefix {
            continue;
        }
        // Same convention only: numeric siblings join numeric, alpha join
        // alpha.
        let same_kind = matches!(
            (&key, &k),
            (SplitKey::Numeric(_), SplitKey::Numeric(_))
                | (SplitKey::Alpha(..), SplitKey::Alpha(..))
        );
        if same_kind {
            members.push((k, entry.path()));
        }
    }
    members.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(Some(members.into_iter().map(|(_, p)| p).collect()))
}

/// What backs one extent of a [`SparseFile`].
#[derive(Clone)]
pub enum SparseKind {
    /// Bytes copied from `source[src_offset .. src_offset + extent.len)`.
    Data {
        /// Backing source holding this extent's bytes.
        source: Arc<dyn ByteSource>,
        /// Offset inside `source` where the extent's bytes begin.
        src_offset: u64,
    },
    /// Extent reads as all zeroes (unwritten/discard region).
    Zero,
    /// Extent reads as a repeating little-endian `u32` pattern — Android
    /// sparse `FILL` chunks and TRIM patterns use this.
    Fill(u32),
}

/// One extent of a [`SparseFile`]: `len` output bytes starting at
/// `out_offset`, described by `kind`.
#[derive(Clone)]
pub struct SparseExtent {
    /// Output (logical image) offset where this extent starts.
    pub out_offset: u64,
    /// Length of the extent in bytes.
    pub len: u64,
    /// What produces the bytes.
    pub kind: SparseKind,
}

/// An extent-mapped read-only image: a logical byte string assembled from
/// data extents, zero holes and fill patterns.
///
/// This is the target representation for container decoders:
///
/// * Android `sparse` images — use [`SparseFile::from_android_sparse`].
/// * qcow2/VMDK/VHD decoders (planned) — emit extents into [`SparseFile::new`].
/// * EWF tables (planned) — same shape.
///
/// Reads are O(log extents) via binary search; memory is O(extents), never
/// O(image size).
pub struct SparseFile {
    extents: Vec<SparseExtent>, // sorted by out_offset, non-overlapping
    len: u64,
}

impl SparseFile {
    /// Build from extents. Extents must be sorted by `out_offset` and
    /// non-overlapping; `len` is the logical size of the output image
    /// (may exceed the last extent's end — the tail reads as zeroes).
    pub fn new(len: u64, mut extents: Vec<SparseExtent>) -> Result<Self> {
        extents.sort_by_key(|e| e.out_offset);
        for w in extents.windows(2) {
            if w[0].out_offset.saturating_add(w[0].len) > w[1].out_offset {
                return Err(Error::corrupt(
                    w[1].out_offset,
                    "sparse extents overlap",
                ));
            }
        }
        Ok(Self { extents, len })
    }

    /// All extents (for inspection/serialization).
    pub fn extents(&self) -> &[SparseExtent] {
        &self.extents
    }

    /// Index of the extent that may contain `offset` (the last extent whose
    /// `out_offset <= offset`), or `None` if offset is before extent 0.
    fn locate(&self, offset: u64) -> Option<usize> {
        self.extents
            .binary_search_by(|e| {
                if offset < e.out_offset {
                    std::cmp::Ordering::Greater
                } else if offset >= e.out_offset.saturating_add(e.len) {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()
    }

    /// Read one extent's byte at `within` offset into `buf`. Returns bytes
    /// written.
    fn read_extent(
        &self,
        ext: &SparseExtent,
        within: u64,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        // `as usize` on a >usize::MAX remainder would wrap on 32-bit targets.
        let avail = usize::try_from(ext.len - within).unwrap_or(usize::MAX);
        let n = buf.len().min(avail);
        match &ext.kind {
            SparseKind::Data { source, src_offset } => {
                source.read_at(src_offset + within, &mut buf[..n])
            }
            SparseKind::Zero => {
                buf[..n].fill(0);
                Ok(n)
            }
            SparseKind::Fill(v) => {
                let pat = v.to_le_bytes();
                for (i, b) in buf[..n].iter_mut().enumerate() {
                    *b = pat[((within + i as u64) & 3) as usize];
                }
                Ok(n)
            }
        }
    }

    /// Decode an **Android sparse image** (`*.img` produced by `img2simg`,
    /// AOSP `system.img` etc.) into a `SparseFile`.
    ///
    /// Format (all little-endian):
    ///   header: magic `0xED26FF3A`, major/minor u16, file_hdr_sz u16,
    ///           chunk_hdr_sz u16, blk_sz u32, total_blks u32,
    ///           total_chunks u32, image_checksum u32.
    ///   chunks: type u16 (`0xCAC1` RAW, `0xCAC2` FILL, `0xCAC3` DONT_CARE,
    ///           `0xCAC4` CRC32), reserved u16, chunk_sz u32 (blocks),
    ///           total_sz u32 (chunk bytes incl. header).
    pub fn from_android_sparse(src: Arc<dyn ByteSource>) -> Result<Self> {
        use crate::le;
        const MAGIC: u32 = 0xED26_FF3A;
        const CHUNK_RAW: u16 = 0xCAC1;
        const CHUNK_FILL: u16 = 0xCAC2;
        const CHUNK_DONT_CARE: u16 = 0xCAC3;
        const CHUNK_CRC32: u16 = 0xCAC4;

        let hdr = src
            .read_slice(0, 28)
            .map_err(Error::Io)?;
        if le::u32(&hdr, 0) != Some(MAGIC) {
            return Err(Error::corrupt(0, "not an Android sparse image (bad magic)"));
        }
        let file_hdr_sz = le::u16(&hdr, 8).unwrap_or(0) as u64;
        let chunk_hdr_sz = le::u16(&hdr, 10).unwrap_or(0) as u64;
        let blk_sz = le::u32(&hdr, 12).unwrap_or(0) as u64;
        let total_chunks = le::u32(&hdr, 20).unwrap_or(0) as u64;
        if blk_sz == 0 || file_hdr_sz < 28 || chunk_hdr_sz < 12 {
            return Err(Error::corrupt(0, "malformed Android sparse header"));
        }
        // Bound memory: refuse absurd chunk counts rather than OOM.
        if total_chunks > 1_000_000 {
            return Err(Error::unsupported(format!(
                "Android sparse image with {total_chunks} chunks"
            )));
        }

        let mut extents = Vec::new();
        let mut cursor = file_hdr_sz; // offset inside `src`
        let mut out = 0u64; // logical output offset
        for i in 0..total_chunks {
            let ch = src.read_slice(cursor, chunk_hdr_sz as usize).map_err(Error::Io)?;
            if ch.len() < chunk_hdr_sz as usize {
                return Err(Error::Truncated {
                    offset: cursor,
                    requested: chunk_hdr_sz,
                    available: ch.len() as u64,
                });
            }
            let ctype = le::u16(&ch, 0).unwrap_or(0);
            let chunk_blocks = le::u32(&ch, 4).unwrap_or(0) as u64;
            let total_sz = le::u32(&ch, 8).unwrap_or(0) as u64;
            // total_sz covers the chunk header itself; a smaller value is
            // corrupt and would send the cursor backwards through the image.
            if total_sz < chunk_hdr_sz {
                return Err(Error::corrupt(
                    cursor + 8,
                    format!("Android sparse chunk {i}: total_sz {total_sz} < header"),
                ));
            }
            let out_len = chunk_blocks.saturating_mul(blk_sz);
            match ctype {
                CHUNK_RAW => {
                    // Only `total_sz - header` bytes of payload follow the
                    // header; a corrupt short payload must not leak the next
                    // chunk's bytes into the output image.
                    let data_len = (total_sz - chunk_hdr_sz).min(out_len);
                    if data_len > 0 {
                        extents.push(SparseExtent {
                            out_offset: out,
                            len: data_len,
                            kind: SparseKind::Data {
                                source: src.clone(),
                                src_offset: cursor + chunk_hdr_sz,
                            },
                        });
                    }
                    if data_len < out_len {
                        extents.push(SparseExtent {
                            out_offset: out.saturating_add(data_len),
                            len: out_len - data_len,
                            kind: SparseKind::Zero,
                        });
                    }
                }
                CHUNK_FILL => {
                    let v = src
                        .read_slice(cursor + chunk_hdr_sz, 4)
                        .map_err(Error::Io)?;
                    let v = le::u32(&v, 0).unwrap_or(0);
                    extents.push(SparseExtent {
                        out_offset: out,
                        len: out_len,
                        kind: if v == 0 { SparseKind::Zero } else { SparseKind::Fill(v) },
                    });
                }
                CHUNK_DONT_CARE | CHUNK_CRC32 => {
                    if ctype == CHUNK_DONT_CARE {
                        extents.push(SparseExtent {
                            out_offset: out,
                            len: out_len,
                            kind: SparseKind::Zero,
                        });
                    }
                    // CRC32 chunks contribute no output bytes.
                }
                other => {
                    return Err(Error::unsupported(format!(
                        "Android sparse chunk type {other:#06x} at index {i}"
                    )));
                }
            }
            if ctype != CHUNK_CRC32 {
                out = out.saturating_add(out_len);
            }
            cursor = cursor.saturating_add(total_sz);
        }
        Self::new(out, extents)
    }
}

impl ByteSource for SparseFile {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let mut done = 0usize;
        let mut pos = offset;
        let mut buf_off = 0usize;
        while buf_off < buf.len() && pos < self.len {
            match self.locate(pos) {
                Some(i) => {
                    let ext = &self.extents[i];
                    let within = pos - ext.out_offset;
                    let n = match self.read_extent(ext, within, &mut buf[buf_off..]) {
                        Ok(n) => n,
                        // Return what we have so far; if nothing was read yet
                        // the error must reach the caller.
                        Err(_e) if done > 0 => break,
                        Err(e) => return Err(e),
                    };
                    if n == 0 {
                        break;
                    }
                    pos = pos.saturating_add(n as u64);
                    buf_off += n;
                    done += n;
                }
                None => {
                    // Hole: zero up to next extent or end of buffer/source.
                    let next = self
                        .extents
                        .iter()
                        .find(|e| e.out_offset > pos)
                        .map(|e| e.out_offset)
                        .unwrap_or(self.len);
                    // try_from guards the >usize::MAX hole case on 32-bit.
                    let hole = usize::try_from(next - pos).unwrap_or(usize::MAX);
                    let n = hole.min(buf.len() - buf_off);
                    buf[buf_off..buf_off + n].fill(0);
                    pos = pos.saturating_add(n as u64);
                    buf_off += n;
                    done += n;
                }
            }
        }
        Ok(done)
    }
}
