//! Android sparse image (`*.img` from `img2simg` / AOSP factory images).
//!
//! The heavy lifting — chunk-table walk and extent mapping — lives in
//! [`sutram_io::SparseFile::from_android_sparse`]; this module adds the
//! detection entry point, header bookkeeping and the extra validation the
//! forensic contract wants (chunk-table sanity, data extents provably inside
//! the backing source, `total_blks` cross-check).
//!
//! Format (all little-endian):
//!
//! ```text
//! header 28+ bytes: magic 0xED26FF3A, major u16, minor u16,
//!                   file_hdr_sz u16, chunk_hdr_sz u16, blk_sz u32,
//!                   total_blks u32, total_chunks u32, image_checksum u32
//! chunks:           type u16 (0xCAC1 RAW / 0xCAC2 FILL / 0xCAC3 DONT_CARE /
//!                   0xCAC4 CRC32), reserved u16, chunk_sz u32 (blocks),
//!                   total_sz u32 (bytes on disk incl. chunk header)
//! ```

use std::sync::Arc;

use sutram_io::le;
use sutram_io::{ByteSource, SparseFile, SparseKind};

use crate::Result;
use sutram_fs::FsError;

/// `sparse_header.magic` — bytes `3A FF 26 ED`.
pub const SPARSE_MAGIC: u32 = 0xED26_FF3A;

const SPARSE_HEADER_LEN: usize = 28;
/// Largest plausible `blk_sz` — real images use 4096; cap stops absurd math.
const MAX_BLOCK_SIZE: u64 = 1 << 24;

/// Parsed sparse-image header fields (all offsets absolute).
#[derive(Debug, Clone)]
pub struct SparseHeader {
    /// `file_hdr_sz` — bytes the header occupies on disk.
    pub file_header_size: u16,
    /// `chunk_hdr_sz` — per-chunk header size (12+).
    pub chunk_header_size: u16,
    /// `blk_sz` — output bytes per block.
    pub block_size: u32,
    /// `total_blks` — declared logical image size in blocks.
    pub total_blocks: u32,
    /// `total_chunks` — declared chunk count.
    pub total_chunks: u32,
    /// `image_checksum` — the CRC32 the writer recorded (unchecked here;
    /// `SparseFile` skips CRC chunks but reports the stored value).
    pub image_checksum: u32,
}

impl SparseHeader {
    /// Declared logical output size in bytes (`total_blks * blk_sz`).
    pub fn output_size(&self) -> u64 {
        self.total_blocks as u64 * self.block_size as u64
    }
}

/// `true` when the source begins with the Android sparse magic.
///
/// Reads only 4 bytes; safe on tiny/garbage sources.
pub fn is_android_sparse(src: &dyn ByteSource) -> bool {
    src.read_slice(0, 4).ok().and_then(|b| le::u32(&b, 0)) == Some(SPARSE_MAGIC)
}

/// Read and validate the 28-byte fixed header. `Err(FsError::Corrupt)` on
/// missing magic or implausible fields — callers that probed with
/// [`is_android_sparse`] first will only land here on real damage.
pub fn read_header(src: &dyn ByteSource) -> Result<SparseHeader> {
    let hdr = src.read_slice(0, SPARSE_HEADER_LEN).map_err(FsError::Io)?;
    if hdr.len() < SPARSE_HEADER_LEN {
        return Err(FsError::truncated(
            0,
            SPARSE_HEADER_LEN as u64,
            hdr.len() as u64,
        ));
    }
    if le::u32(&hdr, 0) != Some(SPARSE_MAGIC) {
        return Err(FsError::corrupt(0, "not an Android sparse image"));
    }
    let h = SparseHeader {
        file_header_size: le::u16(&hdr, 8).unwrap_or(0),
        chunk_header_size: le::u16(&hdr, 10).unwrap_or(0),
        block_size: le::u32(&hdr, 12).unwrap_or(0),
        total_blocks: le::u32(&hdr, 16).unwrap_or(0),
        total_chunks: le::u32(&hdr, 20).unwrap_or(0),
        image_checksum: le::u32(&hdr, 24).unwrap_or(0),
    };
    if h.file_header_size < SPARSE_HEADER_LEN as u16 {
        return Err(FsError::corrupt(8, "sparse file_hdr_sz too small"));
    }
    if h.chunk_header_size < 12 {
        return Err(FsError::corrupt(10, "sparse chunk_hdr_sz too small"));
    }
    if h.block_size == 0 || h.block_size as u64 > MAX_BLOCK_SIZE {
        return Err(FsError::corrupt(
            12,
            format!("implausible sparse block size {}", h.block_size),
        ));
    }
    Ok(h)
}

/// Decode an Android sparse image into a mountable [`SparseFile`].
///
/// Beyond [`SparseFile::from_android_sparse`] this validates that every RAW
/// data extent actually lies inside the backing source — a truncated
/// `system.img` would otherwise surface errors only when the missing tail is
/// first read, long after the container was "successfully" opened.
pub fn open_sparse(src: Arc<dyn ByteSource>) -> Result<SparseFile> {
    let header = read_header(src.as_ref())?;
    let sf = SparseFile::from_android_sparse(src.clone())?;
    let backing = src.len();
    for ext in sf.extents() {
        if let SparseKind::Data { src_offset, .. } = &ext.kind {
            let end = src_offset.saturating_add(ext.len);
            if end > backing {
                return Err(FsError::truncated(
                    *src_offset,
                    ext.len,
                    backing.saturating_sub(*src_offset),
                ));
            }
        }
    }
    let _ = header; // fields returned via inspect_sparse for reporting
    Ok(sf)
}

/// Open plus header bookkeeping: `(decoded image, header, warnings)`.
///
/// Warnings (never fatal): the decoded length disagrees with the declared
/// `total_blks * blk_sz`, or DONT_CARE/RAW chunks left output gaps.
pub fn inspect_sparse(src: Arc<dyn ByteSource>) -> Result<(SparseFile, SparseHeader, Vec<String>)> {
    let header = read_header(src.as_ref())?;
    let sf = open_sparse(src.clone())?;
    let mut warnings = chunk_warnings(src.as_ref(), &header);
    let declared = header.output_size();
    if declared != sf.len() {
        warnings.push(format!(
            "android sparse: decoded size {:#x} != declared total_blks*blk_sz {declared:#x}",
            sf.len()
        ));
    }
    Ok((sf, header, warnings))
}

/// Chunk types (AOSP `sparse_format.h`).
const CHUNK_RAW: u16 = 0xCAC1;
const CHUNK_FILL: u16 = 0xCAC2;
const CHUNK_DONT_CARE: u16 = 0xCAC3;
const CHUNK_CRC32: u16 = 0xCAC4;

/// Bound on emitted chunk warnings — a uniformly corrupt table should not
/// produce a million-entry vector.
const MAX_CHUNK_WARNINGS: usize = 32;

/// Re-walk the chunk table, reporting structural inconsistencies that
/// [`SparseFile::from_android_sparse`] absorbs silently — most importantly
/// a RAW chunk whose `total_sz` cannot hold its declared `chunk_sz` blocks
/// (the decoded extent then maps non-payload bytes).
///
/// Warnings only, never fatal: the decoder's output is still faithfully
/// "what the table declares"; we flag where declaration and reality split.
fn chunk_warnings(src: &dyn ByteSource, h: &SparseHeader) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut suppressed = 0u64;
    let warn = |warnings: &mut Vec<String>, suppressed: &mut u64, msg: String| {
        if warnings.len() < MAX_CHUNK_WARNINGS {
            warnings.push(msg);
        } else {
            *suppressed += 1;
        }
    };
    let chdr = h.chunk_header_size as u64;
    let mut cursor = h.file_header_size as u64;
    for i in 0..h.total_chunks {
        let ch = match src.read_slice(cursor, chdr as usize) {
            Ok(b) => b,
            Err(_) => {
                warn(
                    &mut warnings,
                    &mut suppressed,
                    format!("sparse chunk {i}: header read failed at {cursor:#x}"),
                );
                break;
            }
        };
        if ch.len() < 12 {
            warn(
                &mut warnings,
                &mut suppressed,
                format!("sparse chunk {i}: truncated header at {cursor:#x}"),
            );
            break;
        }
        let ctype = le::u16(&ch, 0).unwrap_or(0);
        let chunk_blocks = le::u32(&ch, 4).unwrap_or(0) as u64;
        let total_sz = le::u32(&ch, 8).unwrap_or(0) as u64;
        if total_sz < chdr {
            warn(
                &mut warnings,
                &mut suppressed,
                format!("sparse chunk {i}: total_sz {total_sz} < chunk header {chdr}"),
            );
            break; // cursor arithmetic is meaningless past this
        }
        let out_len = chunk_blocks.saturating_mul(h.block_size as u64);
        let payload = total_sz - chdr;
        let mismatch = match ctype {
            // Payload must cover exactly the declared output blocks.
            CHUNK_RAW => payload != out_len,
            // FILL carries a 4-byte pattern; CRC32 a 4-byte checksum.
            CHUNK_FILL | CHUNK_CRC32 => payload != 4,
            // DONT_CARE: any payload size is tolerated (usually 0).
            CHUNK_DONT_CARE => false,
            _ => false, // unknown types already rejected by the decoder
        };
        if mismatch {
            let detail = if payload < out_len && ctype == CHUNK_RAW {
                "decoded extent maps non-payload bytes"
            } else {
                "declared/actual chunk size disagree"
            };
            warn(
                &mut warnings,
                &mut suppressed,
                format!(
                    "sparse chunk {i} (type {ctype:#06x}): payload {payload:#x} B vs \
                     declared output {out_len:#x} B — {detail}"
                ),
            );
        }
        cursor = cursor.saturating_add(total_sz);
    }
    if suppressed > 0 {
        warnings.push(format!(
            "sparse: {suppressed} further chunk-table inconsistencies suppressed"
        ));
    }
    warnings
}
