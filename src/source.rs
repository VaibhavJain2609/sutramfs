//! [`ImageRef`] → [`ByteSource`] resolution.
//!
//! Two carriers: a server-local `path` opened read-only via
//! [`FileSource`], or `inline` bytes (bounded — see
//! [`service::SutramFsService`] `max_inline_bytes`). `offset`/`length` wrap
//! the result in a [`sutram_io::OffsetView`] partition window.

use std::sync::Arc;

use sutram_fs::{FsError, Result};
use sutram_io::{ByteSource, FileSource, OffsetView};

use crate::pb::image_ref::Source as ImageSource;
use crate::pb::ImageRef;

/// Cap on `inline` image payloads — the gRPC layer's max message size also
/// applies, this is the belt to its braces. 64 MiB keeps a rogue client
/// from making the daemon retain giant buffers per mount.
pub const MAX_INLINE_BYTES: u64 = 64 * 1024 * 1024;

/// Short human-readable description for handle bookkeeping/logging.
pub fn describe(image: &ImageRef) -> String {
    let base = match &image.source {
        Some(ImageSource::Path(p)) => format!("path:{p}"),
        Some(ImageSource::Inline(b)) => format!("inline({} bytes)", b.len()),
        None => "empty".to_string(),
    };
    if image.offset != 0 || image.length != 0 {
        format!("{base}@{:#x}+{}", image.offset, image.length)
    } else {
        base
    }
}

/// Resolve an [`ImageRef`] to a [`ByteSource`].
///
/// `max_inline` caps `inline` payloads (pass [`MAX_INLINE_BYTES`] or a
/// configured limit). Window fields are validated against the source
/// length; an out-of-range `offset` is `InvalidInput`, not a silent clamp.
pub fn resolve(image: &ImageRef, max_inline: u64) -> Result<Arc<dyn ByteSource>> {
    let inner: Arc<dyn ByteSource> = match &image.source {
        Some(ImageSource::Path(p)) => {
            let src = FileSource::open(p).map_err(|e| FsError::InvalidInput {
                msg: format!("cannot open image '{p}': {e}"),
            })?;
            Arc::new(src)
        }
        Some(ImageSource::Inline(b)) => {
            if b.len() as u64 > max_inline {
                return Err(FsError::InvalidInput {
                    msg: format!(
                        "inline image too large: {} bytes (max {max_inline})",
                        b.len()
                    ),
                });
            }
            Arc::new(b.clone())
        }
        None => {
            return Err(FsError::InvalidInput {
                msg: "ImageRef carries no source (set path or inline)".into(),
            })
        }
    };

    if image.offset == 0 && image.length == 0 {
        return Ok(inner);
    }
    let total = inner.len();
    if image.offset >= total {
        return Err(FsError::InvalidInput {
            msg: format!(
                "window offset {:#x} beyond end of {}-byte source",
                image.offset, total
            ),
        });
    }
    let len = if image.length == 0 {
        total - image.offset
    } else {
        image.length.min(total - image.offset)
    };
    let view = OffsetView::new(inner, image.offset, len).map_err(FsError::from)?;
    Ok(Arc::new(view))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::ImageRef;

    #[test]
    fn inline_source_roundtrip() {
        let img = ImageRef {
            source: Some(ImageSource::Inline(vec![1u8, 2, 3])),
            offset: 0,
            length: 0,
        };
        let src = resolve(&img, MAX_INLINE_BYTES).unwrap();
        assert_eq!(src.len(), 3);
        assert_eq!(src.read_slice(0, 8).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn inline_oversize_rejected() {
        let img = ImageRef {
            source: Some(ImageSource::Inline(vec![0u8; 16])),
            offset: 0,
            length: 0,
        };
        assert!(resolve(&img, 4).is_err());
    }

    #[test]
    fn window_view_clamps_and_rejects() {
        let img = ImageRef {
            source: Some(ImageSource::Inline(vec![0u8; 4096])),
            offset: 512,
            length: 1024,
        };
        let src = resolve(&img, MAX_INLINE_BYTES).unwrap();
        assert_eq!(src.len(), 1024);

        let bad = ImageRef {
            source: Some(ImageSource::Inline(vec![0u8; 4096])),
            offset: 9999,
            length: 0,
        };
        assert!(resolve(&bad, MAX_INLINE_BYTES).is_err());
    }

    #[test]
    fn empty_ref_is_invalid() {
        let img = ImageRef {
            source: None,
            offset: 0,
            length: 0,
        };
        assert!(resolve(&img, MAX_INLINE_BYTES).is_err());
    }
}
