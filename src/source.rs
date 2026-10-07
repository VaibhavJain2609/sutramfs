//! [`ImageRef`] → [`ByteSource`] resolution.
//!
//! Two carriers: a server-local `path` opened via the format-sniffing
//! [`sutram_io::open_image`] (raw `dd`, E01, VHD/VHDX, QCOW2,
//! split-raw), or `inline` bytes (bounded — see
//! [`service::SutramFsService`] `max_inline_bytes`). `offset`/`length` wrap
//! the result in a [`sutram_io::OffsetView`] partition window.

use std::sync::Arc;

use sutram_fs::{FsError, Result};
use sutram_io::{ByteSource, OffsetView};

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
            // Format-sniffing open: raw dd/img files pass straight
            // through; E01 (with .E02+ siblings), VHD/VHDX, QCOW2 and
            // split-raw sets are decoded transparently.
            sutram_io::open_image(p).map_err(|e| FsError::InvalidInput {
                msg: format!("cannot open image '{p}': {e}"),
            })?
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
        assert_eq!(describe(&img), "empty");
    }

    #[test]
    fn describe_covers_every_carrier() {
        let path = ImageRef {
            source: Some(ImageSource::Path("/evidence/disk.img".into())),
            offset: 0,
            length: 0,
        };
        assert_eq!(describe(&path), "path:/evidence/disk.img");

        let inline = ImageRef {
            source: Some(ImageSource::Inline(vec![0u8; 7])),
            offset: 0,
            length: 0,
        };
        assert_eq!(describe(&inline), "inline(7 bytes)");

        // A partition window is appended to the carrier description.
        let win = ImageRef {
            source: Some(ImageSource::Inline(vec![0u8; 4096])),
            offset: 0x200,
            length: 0x400,
        };
        assert_eq!(describe(&win), "inline(4096 bytes)@0x200+1024");
    }

    #[test]
    fn path_source_opens_read_only() {
        // Real file on disk, opened via ImageSource::Path: FileSource
        // wraps File::open — O_RDONLY. A chmod-400 file must still work.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sutram-fsd-src-{:x}.img", std::process::id()));
        std::fs::write(&path, b"\xAA\x55-sutram").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let img = ImageRef {
            source: Some(ImageSource::Path(path.to_string_lossy().into_owned())),
            offset: 0,
            length: 0,
        };
        let src = resolve(&img, MAX_INLINE_BYTES).unwrap();
        assert_eq!(src.len(), 9);
        assert_eq!(src.read_slice(0, 16).unwrap(), b"\xAA\x55-sutram");
        // Contents are untouched — no write path exists to corrupt them.
        assert_eq!(std::fs::read(&path).unwrap(), b"\xAA\x55-sutram");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn missing_path_is_invalid_input() {
        let img = ImageRef {
            source: Some(ImageSource::Path(
                "/definitely/not/a/real/image.dd".into(),
            )),
            offset: 0,
            length: 0,
        };
        match resolve(&img, MAX_INLINE_BYTES) {
            Err(FsError::InvalidInput { msg }) => {
                assert!(msg.contains("cannot open image"), "{msg}");
            }
            Err(e) => panic!("expected InvalidInput, got {e}"),
            Ok(_) => panic!("expected InvalidInput, got a source"),
        }
    }

    #[test]
    fn length_only_window() {
        // offset = 0, length set → view shorter than the source.
        let img = ImageRef {
            source: Some(ImageSource::Inline(vec![0u8; 4096])),
            offset: 0,
            length: 1000,
        };
        let src = resolve(&img, MAX_INLINE_BYTES).unwrap();
        assert_eq!(src.len(), 1000);
    }

    #[test]
    fn oversized_length_clamps_to_source() {
        let img = ImageRef {
            source: Some(ImageSource::Inline(vec![0u8; 4096])),
            offset: 1024,
            length: u64::MAX,
        };
        let src = resolve(&img, MAX_INLINE_BYTES).unwrap();
        assert_eq!(src.len(), 4096 - 1024);
    }
}
