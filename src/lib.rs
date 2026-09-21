//! # sutram-archive
//!
//! Forensic parsers for archive/container formats — **ZIP**, **TAR** and
//! **CPIO** — exposed through the SUTRAM-FS contract (`sutram-fs` traits
//! over `sutram-io` byte sources). An archive is treated as a filesystem:
//! members become [`FsEntry`] records, `walk()` streams them one at a
//! time, and `read_file()` returns each member's (decompressed) data.
//!
//! ## Forensic features
//!
//! * **Deleted / hidden members** — ZIP local file headers unreferenced
//!   by the central directory, TAR member data surviving past a truncated
//!   archive tail, and CPIO slack after the `TRAILER!!!` marker are all
//!   emitted as `Deleted{..}` entries rather than silently skipped.
//! * **Anomaly detection** — ZIP local headers that disagree with their
//!   central-directory records (flags, method, CRC, sizes, name) are
//!   flagged via `meta["anomaly"]`; TAR superseded duplicate paths get
//!   `meta["superseded"]`.
//! * **Provenance** — `disk_offset` is the archive record that produced
//!   the entry; `allocated_ranges` are the member's absolute byte extents.
//! * **Timestamps** — DOS datetime (ZIP), octal/pax unix seconds (TAR),
//!   and unix seconds (CPIO) are decoded into MACB `FsTimestamp`s with
//!   `raw_encoding`/`granularity` preserved.
//! * **Magic verdicts** — each member's decompressed head (≤ 4 KiB) is
//!   checked by `sutram-magic`; `FsEntry.magic` carries the verdict.
//! * **Lenient by default** — corrupt records yield `Err(FsError)` items
//!   inside the walk stream; `MountOptions::strict` aborts instead.
//!
//! ## Formats
//!
//! | Parser                  | name        | formats                                  |
//! |-------------------------|-------------|------------------------------------------|
//! | [`ZipParser`]           | `"zip"`     | ZIP (incl. ZIP64, self-extracting stubs) |
//! | [`TarParser`]           | `"tar"`     | ustar / v7 / pax / GNU longname & sparse |
//! | [`CpioParser`]          | `"cpio"`    | newc (070701/070702), odc, binary        |
//! | [`SutramArchiveParser`] | `"archive"` | all three, via [`archive_detect`]        |

#![forbid(unsafe_code)]

pub mod cpio;
mod reader;
pub mod tar;
pub mod zip;

use std::sync::Arc;

use sutram_fs::{DetectConfidence, FsParser, FileSystem, MountOptions, Result};
use sutram_io::ByteSource;

pub use cpio::{CpioFs, CpioParser};
pub use tar::{TarFs, TarParser};
pub use zip::{ZipFs, ZipParser};

/// Best confidence that the source is *some* supported archive format —
/// the maximum of the ZIP, TAR and CPIO probes. Cheap: each probe reads
/// only a few KiB.
///
/// ```rust
/// use sutram_archive::archive_detect;
/// use sutram_fs::DetectConfidence;
/// let junk = vec![0u8; 4096];
/// assert_eq!(archive_detect(&junk.as_slice()), DetectConfidence::None);
/// ```
pub fn archive_detect(src: &dyn ByteSource) -> DetectConfidence {
    ZipParser
        .detect(src)
        .max(TarParser.detect(src))
        .max(CpioParser.detect(src))
}

/// Facade parser that mounts whichever archive format `detect`s best.
///
/// The inner format is chosen by confidence (ZIP > TAR > CPIO on ties);
/// the mounted [`FileSystem`] is the format-specific implementation, so
/// `info().fs_type` reports `"ZIP"` / `"TAR"` / `"CPIO"` honestly.
pub struct SutramArchiveParser;

impl FsParser for SutramArchiveParser {
    fn name(&self) -> &'static str {
        "archive"
    }

    fn detect(&self, src: &dyn ByteSource) -> DetectConfidence {
        archive_detect(src)
    }

    fn mount_with(
        &self,
        src: Arc<dyn ByteSource>,
        opts: &MountOptions,
    ) -> Result<Box<dyn FileSystem>> {
        // Order matters on ties: ZIP has the strongest signature (EOCD),
        // TAR validates a header checksum, CPIO's two-byte binary magic is
        // the weakest — prefer in that order.
        if ZipParser.detect(src.as_ref()) >= DetectConfidence::Medium {
            return ZipParser.mount_with(src, opts);
        }
        if TarParser.detect(src.as_ref()) >= DetectConfidence::Medium {
            return TarParser.mount_with(src, opts);
        }
        if CpioParser.detect(src.as_ref()) >= DetectConfidence::Medium {
            return CpioParser.mount_with(src, opts);
        }
        // Everything probed Low/None — refuse rather than guess.
        Err(sutram_fs::FsError::InvalidInput {
            msg: "not a recognised archive (zip/tar/cpio probes all failed)".into(),
        })
    }
}

#[cfg(test)]
mod tests;
