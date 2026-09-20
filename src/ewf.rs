//! EWF (Expert Witness Format, `*.E01`) — **planned, not yet implemented**.
//!
//! This module defines the public interface so downstream code can be
//! written against it today; [`EwfSource::open`] currently returns
//! [`Error::Unsupported`].
//!
//! ## Planned design (pure Rust, no libewf FFI)
//!
//! An E01 segment is a sequence of sections:
//!
//! * file header: `EVF\x09\x0d\x0a\xff\x00` + `signature[5]` …
//! * `header`/`header2` section: acquisition metadata (zlib-compressed);
//! * `volume` section: geometry (sectors, bytes/sector, media type);
//! * `table`/`table2` sections: block maps — arrays of `(chunk_offset,
//!   flags)` entries; each chunk is a 32 KiB (typical) deflate-compressed
//!   run of image data;
//! * `digest`/`hash`/`data` sections: MD5/SHA-1 acquisition hashes (which we
//!   must expose for evidence integrity verification);
//! * `next`/`done` pointers chaining to the following segment
//!   (`.E02`, `.E03`, …) — multi-segment images will be glued together with
//!   [`crate::ConcatSource`] and the table index will surface through
//!   [`crate::SparseFile`]-style extent mapping.
//!
//! Open questions recorded for the implementor:
//!
//! * EWF2 (`Ex01`) uses a different section framing ("EWF2SMART" etc.);
//!   treat as a separate variant of the same interface.
//! * Compression inside chunks is zlib/deflate — pick `flate2`/`miniz_oxide`
//!   (pure Rust: `miniz_oxide`) when implementing.
//! * Error-handling policy: a corrupt table entry must degrade to a
//!   zero-filled extent + error record, matching the project-wide
//!   lenient-by-default rule.

use std::sync::Arc;

use crate::{ByteSource, Error, Result};

/// EWF file-signature bytes (`EVF` + version marker).
pub const EWF_SIGNATURE: &[u8] = b"EVF\x09\x0d\x0a\xff\x00";

/// Read-only `ByteSource` over an EWF image (single or multi-segment).
///
/// Not yet functional — see module docs. Kept cfg-less so capability probing
/// is uniform: `EwfSource::open(..)` → `Err(Error::Unsupported{..})`.
pub struct EwfSource {
    _private: (),
}

impl EwfSource {
    /// Probe the first segment's signature without opening the image.
    pub fn is_ewf(src: &dyn ByteSource) -> bool {
        src.read_slice(0, EWF_SIGNATURE.len())
            .map(|h| h == EWF_SIGNATURE)
            .unwrap_or(false)
    }

    /// Open an EWF image. `segments` are the `.E01`, `.E02`, … segments in
    /// order (a single-element vector for single-segment images).
    ///
    /// TODO(ewf): implement pure-Rust EWF reader (see module docs). Must
    /// never FFI to libewf; use `miniz_oxide` for chunk decompression and
    /// map tables to extents.
    pub fn open(segments: Vec<Arc<dyn ByteSource>>) -> Result<Self> {
        match segments.first() {
            Some(first) if Self::is_ewf(first.as_ref()) => Err(Error::unsupported(
                "EWF (E01) images: pure-Rust reader planned, not yet implemented",
            )),
            _ => Err(Error::corrupt(0, "not an EWF image (bad EVF signature)")),
        }
    }
}
