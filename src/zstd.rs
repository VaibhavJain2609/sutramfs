//! Zstandard decompression via [`ruzstd`] — pure Rust, used by btrfs
//! (`BTRFS_COMPRESS_ZSTD`) and modern squashfs images.
//!
//! Enabled by the `zstd` cargo feature (on by default). Note `ruzstd`
//! 0.9 declares `rust-version = 1.87`: builds that must honour this
//! crate's MSRV 1.85 exactly should disable default features — this
//! module then compiles to a stub whose [`decompress`] returns
//! [`CompError::Unsupported`], keeping call sites identical.

#[cfg(feature = "zstd")]
mod imp {
    use std::io::Read;

    use crate::{CompError, Result};

    /// Decompress one or more concatenated zstd frames, producing at most
    /// `max_out` bytes.
    ///
    /// [`CompError::OutputLimit`] fires as soon as the decoder emits more
    /// than `max_out` bytes — the excess is never buffered (we read
    /// through `Read::take`, so a "42.zip"-style bomb cannot allocate its
    /// payload).
    pub fn decompress(src: &[u8], max_out: usize) -> Result<Vec<u8>> {
        let mut dec = ruzstd::decoding::StreamingDecoder::new(src)
            .map_err(|e| CompError::corrupt(format!("zstd frame header: {e}")))?;
        let mut out = Vec::new();
        // take(max_out + 1) distinguishes "exactly at limit" from "over
        // limit" without trusting a declared content size.
        dec.by_ref()
            .take(max_out as u64 + 1)
            .read_to_end(&mut out)
            .map_err(|e| CompError::corrupt(format!("zstd decode failed: {e}")))?;
        if out.len() > max_out {
            return Err(CompError::OutputLimit {
                limit: max_out as u64,
            });
        }
        Ok(out)
    }

    /// Streaming zstd decoder — a thin wrapper giving `std::io::Read`
    /// streaming (bounded via `Read::take`) without callers naming
    /// `ruzstd` in their own dependency list.
    pub struct ZstdDecoder<'a> {
        inner:
            ruzstd::decoding::StreamingDecoder<&'a [u8], ruzstd::decoding::FrameDecoder>,
    }

    impl<'a> ZstdDecoder<'a> {
        /// Wrap a zstd frame (or concatenated frames) in a `Read`
        /// interface.
        pub fn new(src: &'a [u8]) -> Result<Self> {
            Ok(ZstdDecoder {
                inner: ruzstd::decoding::StreamingDecoder::new(src)
                    .map_err(|e| CompError::corrupt(format!("zstd frame header: {e}")))?,
            })
        }
    }

    impl Read for ZstdDecoder<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.read(buf)
        }
    }
}

#[cfg(not(feature = "zstd"))]
mod imp {
    use crate::{CompError, Result};

    /// Stub: the `zstd` cargo feature is disabled. Returns
    /// [`CompError::Unsupported`] for every input.
    pub fn decompress(_src: &[u8], _max_out: usize) -> Result<Vec<u8>> {
        Err(CompError::unsupported(
            "sutram-compress built without the `zstd` feature",
        ))
    }
}

pub use imp::*;
