#![forbid(unsafe_code)]
//! # sutram-compress
//!
//! Pure-Rust decompression codecs used by the SUTRAM-FS forensic parser
//! family. Everything here decodes **untrusted, potentially hostile**
//! input: every decoder bounds its output (`max_out` — the decompression
//! -bomb guard), never panics on corrupt data, and reports failures via
//! [`CompError`] instead.
//!
//! ## Codecs
//!
//! | Module   | Format                                   | Used by                  |
//! |----------|------------------------------------------|--------------------------|
//! | [`lznt1`]  | NTFS native compression (compression units) | `sutram-ntfs`       |
//! | [`lzo1x`]  | LZO1X-1 (via `lzokay`)                  | btrfs, decmpfs           |
//! | [`lzvn`]   | Apple LZVN                               | HFS+/APFS decmpfs        |
//! | [`lzfse`]  | Apple LZFSE — *stub* (see README)        | decmpfs types 11/12      |
//! | [`lz4`]    | LZ4 block + frame                        | f2fs, squashfs           |
//! | [`zlib`]   | zlib / raw DEFLATE (via `miniz_oxide`)   | decmpfs, EWF, …          |
//! | [`zstd`]   | Zstandard (via `ruzstd`, feature `zstd`) | btrfs, squashfs          |
//!
//! All decoders share one shape:
//!
//! ```rust
//! # fn main() -> Result<(), sutram_compress::CompError> {
//! let out = sutram_compress::lz4::decompress_block(&[], 4096)?;
//! # Ok(()) }
//! ```
//!
//! `decompress(src, max_out)` returns the decoded bytes or a [`CompError`].
//! Where the format supports it, a streaming `std::io::Read` adapter is
//! also provided.

use std::fmt;

pub mod lz4;
pub mod lznt1;
pub mod lzo1x;
pub mod lzfse;
pub mod lzvn;
pub mod zlib;
pub mod zstd;

/// Unified decompression error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompError {
    /// Input ended before the stream was complete.
    Truncated {
        /// Bytes the decoder still needed (best-effort).
        needed: u64,
    },
    /// Input is structurally invalid (bad opcode, bad distance, bad magic).
    Corrupt {
        /// Human-readable detail; no secrets, safe to surface in reports.
        msg: String,
    },
    /// Decoded output would exceed the caller's `max_out` bound.
    OutputLimit {
        /// The bound that was exceeded.
        limit: u64,
    },
    /// The codec is recognised but not available in this build
    /// (e.g. LZFSE, or zstd without the `zstd` feature).
    Unsupported {
        /// Human-readable detail.
        msg: String,
    },
}

impl CompError {
    /// Convenience constructor for [`CompError::Corrupt`].
    pub fn corrupt(msg: impl Into<String>) -> Self {
        CompError::Corrupt { msg: msg.into() }
    }

    /// Convenience constructor for [`CompError::Unsupported`].
    pub fn unsupported(msg: impl Into<String>) -> Self {
        CompError::Unsupported { msg: msg.into() }
    }
}

impl fmt::Display for CompError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompError::Truncated { needed } => {
                write!(f, "compressed input truncated (needed ~{needed} more bytes)")
            }
            CompError::Corrupt { msg } => write!(f, "corrupt compressed stream: {msg}"),
            CompError::OutputLimit { limit } => {
                write!(f, "decompressed output exceeds limit of {limit} bytes")
            }
            CompError::Unsupported { msg } => write!(f, "unsupported codec: {msg}"),
        }
    }
}

impl std::error::Error for CompError {}

/// Crate-wide result type.
pub type Result<T> = std::result::Result<T, CompError>;
