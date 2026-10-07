//! The [`FsParser`] / [`FileSystem`] trait surface every parser implements.

use std::io::Read;
use std::sync::Arc;

use sutram_io::ByteSource;

use crate::carve::CarveOptions;
use crate::types::{CarveHit, DetectConfidence, FsEntry, FsInfo};
use crate::{FsError, Result};

/// Parser behaviour knobs. Default = lenient/forensic (strict off, magic
/// checks on, orphans on).
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// When `true`, the first corruption aborts the affected walk branch
    /// with an error instead of emitting partial results. Default `false`
    /// (lenient): parsers emit every record they can parse and interleave
    /// `Err(FsError)` items for what they could not.
    pub strict: bool,
    /// Fill `FsEntry::magic` by reading each file's leading bytes through
    /// `sutram-magic`. Default `true`; cheap (bounded header read).
    pub check_magic: bool,
    /// When `true`, also emit orphan/lost entries the format permits
    /// (unreferenced inodes, unlinked cluster chains, journal orphans).
    /// Default `true` — this is a forensic tool.
    pub include_orphans: bool,
}

impl Default for MountOptions {
    fn default() -> Self {
        MountOptions {
            strict: false,
            check_magic: true,
            include_orphans: true,
        }
    }
}

impl MountOptions {
    /// Strict preset: fail fast on corruption.
    pub fn strict() -> Self {
        MountOptions {
            strict: true,
            ..Default::default()
        }
    }
}

/// A filesystem parser — the entry point each crate exposes.
///
/// ```rust,no_run
/// use sutram_fs::{FsParser, MountOptions, DetectConfidence};
/// use sutram_io::ByteSource;
/// use std::sync::Arc;
///
/// fn examine(parser: &dyn FsParser, src: Arc<dyn ByteSource>) {
///     match parser.detect(src.as_ref()) {
///         c if c >= DetectConfidence::Medium => {
///             let fs = parser.mount(src).unwrap();
///             for e in fs.walk() { /* … */ }
///         }
///         _ => eprintln!("not this filesystem"),
///     }
/// }
/// ```
pub trait FsParser: Send + Sync {
    /// Short stable name, e.g. `"fat"`, `"ntfs"`, `"ext4"`.
    fn name(&self) -> &'static str;

    /// Cheap probe — may read a few KiB from fixed offsets only; must be
    /// fast and never panic. Return the strongest honest confidence.
    fn detect(&self, src: &dyn ByteSource) -> DetectConfidence;

    /// Mount with default (lenient, forensic) options.
    fn mount(&self, src: Arc<dyn ByteSource>) -> Result<Box<dyn FileSystem>> {
        self.mount_with(src, &MountOptions::default())
    }

    /// Mount with explicit options.
    fn mount_with(&self, src: Arc<dyn ByteSource>, opts: &MountOptions)
        -> Result<Box<dyn FileSystem>>;
}

/// A mounted filesystem — a forensic evidence session.
///
/// Object safety: `walk` returns a boxed iterator; `read_file` a boxed
/// reader. Implementations must hold an `Arc<dyn ByteSource>` so returned
/// readers are `'static` and outlive the borrow.
pub trait FileSystem: Send + Sync {
    /// Volume summary.
    fn info(&self) -> FsInfo;

    /// The mounted source — for raw access, carving, and re-proof of any
    /// byte range cited in emitted records.
    fn source(&self) -> Arc<dyn ByteSource>;

    /// Stream every entry — live files/dirs, deleted entries, orphans —
    /// one at a time. **Bounded memory**: never buffer the whole tree.
    ///
    /// Items are `Result`: corruption during the walk yields
    /// `Err(FsError)` records interleaved with entries (lenient mode); in
    /// strict mode the walk aborts on first error.
    fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_>;

    /// Open an entry's data for sequential read. For deleted entries this
    /// yields the *recoverable* extents (see `allocated_ranges`); a fully
    /// overwritten entry returns `Ok` with zero bytes — check
    /// `FsEntry::status` rather than expecting an error.
    fn read_file(&self, entry: &FsEntry) -> Result<Box<dyn Read + Send>>;

    /// Read up to `buf.len()` bytes of an entry's data at `file_offset`
    /// (relative to the file's logical start, not the disk).
    fn read_file_at(
        &self,
        entry: &FsEntry,
        file_offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        let mut r = self.read_file(entry)?;
        // Skip forward — bounded by the caller's request size usage.
        let mut skipped = 0u64;
        let mut tmp = [0u8; 8192];
        while skipped < file_offset {
            let want = (file_offset - skipped).min(tmp.len() as u64) as usize;
            let n = r.read(&mut tmp[..want]).map_err(FsError::Io)?;
            if n == 0 {
                return Ok(0);
            }
            skipped += n as u64;
        }
        r.read(buf).map_err(FsError::Io)
    }

    /// Journal / change-log forensic artefacts as pseudo-entries:
    /// journaled metadata copies (ext4 jbd2), USN change records (NTFS
    /// `$UsnJrnl`), log-record headers (NTFS `$LogFile`), transaction
    /// block-lists (HFS+ journal buffer). These are *prior-state
    /// evidence* — they are not part of `walk()` and are typically
    /// emitted with `status` `Deleted{..}` and format-defined meta keys
    /// (`usn_*`, `jbd2_*`, `hfs_journal_*`, `journal`).
    ///
    /// Items are `Result`: corruption yields `Err` records interleaved
    /// with entries (lenient mode); in strict mode the first error ends
    /// the stream. Default: the parser exposes no journal — empty.
    fn journal_entries(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
        Box::new(std::iter::empty())
    }

    /// Deleted entries only — a filtered view of `walk`.
    fn deleted_entries(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
        Box::new(self.walk().filter(|item| match item {
            Ok(e) => e.is_deleted(),
            Err(_) => true, // error records pass through
        }))
    }

    /// Byte ranges of the source that hold no live-allocated data:
    /// free space + (optionally) file slack. These are the carving grounds.
    /// Default: unknown/unsupported → empty.
    fn unallocated_ranges(&self) -> Vec<(u64, u64)> {
        Vec::new()
    }

    /// Scan `[offset, offset+len)` for embedded file signatures via
    /// `sutram-magic`, at `align`-byte boundaries (512 covers every FS).
    ///
    /// Hits are *bounded* — each [`CarveHit`]'s `len` is the object's
    /// real extent where the format allows it (footer scan, declared
    /// size, chunk/box walk), marked `exact`; otherwise the extent runs
    /// to the next signature or a per-type cap. Parsers with format
    /// knowledge (e.g. FAT knows cluster alignment, NTFS knows MFT
    /// records) may override.
    fn carve_region(
        &self,
        offset: u64,
        len: u64,
        align: u64,
    ) -> Result<Box<dyn Iterator<Item = Result<CarveHit>> + Send + '_>> {
        self.carve(&CarveOptions::region(offset, len, align))
    }

    /// Signature carving with full options — see [`CarveOptions`] and
    /// the `carve` module.
    fn carve(
        &self,
        opts: &CarveOptions,
    ) -> Result<Box<dyn Iterator<Item = Result<CarveHit>> + Send + '_>> {
        Ok(Box::new(crate::carve::CarveIter::new(self.source(), opts)?))
    }
}
