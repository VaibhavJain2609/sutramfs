//! The [`ByteSource`] trait and its implementations.
//!
//! A `ByteSource` is a **read-only**, randomly addressable byte string of
//! known length — a disk image, a partition view, a file carved out of
//! unallocated space, or a test fixture in memory. Parsers are written once
//! against `&dyn ByteSource` / `Arc<dyn ByteSource>` and run unchanged over
//! any backing store.
//!
//! Contract for implementors:
//!
//! * `read_at` must be thread-safe (`Send + Sync` on the trait) and must not
//!   mutate observable state.
//! * It returns the number of bytes actually placed in `buf`; a short read is
//!   only legal at end-of-source. `read_exact_at` (provided) loops to fill or
//!   reports [`io::ErrorKind::UnexpectedEof`].
//! * `len()` must be exact and constant for the lifetime of the source.
//!
//! `File` implements `ByteSource` via positioned reads on Unix
//! (`FileExt::read_at`) and Windows (`FileExt::seek_read`). On other targets —
//! or when a `Mutex`-protected cursor is preferred — wrap the file in
//! [`std::io::BufReader`]-free [`FileSource`]. Memory-mapped I/O is
//! deliberately left out of the core impl (no `unsafe`, no mmap dependency);
//! an mmap-backed `ByteSource` can live behind a feature flag downstream.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

/// A read-only, randomly addressable byte source.
///
/// See module docs for the contract.
pub trait ByteSource: Send + Sync {
    /// Total length of the source in bytes.
    fn len(&self) -> u64;

    /// Whether the source is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read up to `buf.len()` bytes starting at absolute `offset`.
    ///
    /// Returns the number of bytes read; fewer than `buf.len()` only at EOF.
    /// Implementations must clamp at the end of the source rather than
    /// reading neighbouring data or erroring.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Fill `buf` completely starting at `offset`, or fail.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0usize;
        while filled < buf.len() {
            match self.read_at(offset + filled as u64, &mut buf[filled..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "short read at {offset:#x}: wanted {} bytes, source is {} bytes",
                            buf.len(),
                            self.len()
                        ),
                    ));
                }
                Ok(n) => filled += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Read `len` bytes at `offset` into a fresh `Vec`.
    ///
    /// The length is clamped to the end of the source; requesting bytes that
    /// start past EOF yields an empty `Vec`, never an error — forensic
    /// callers should see "as much evidence as exists".
    fn read_slice(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let total = self.len();
        if offset >= total {
            return Ok(Vec::new());
        }
        let avail = (total - offset).min(len as u64) as usize;
        let mut v = vec![0u8; avail];
        self.read_exact_at(offset, &mut v)?;
        Ok(v)
    }

    /// A streaming [`Read`] handle starting at `offset`.
    ///
    /// Convenience for consumers that want sequential access; still bounded
    /// — it pulls through `read_at` in `buf`-sized steps. Not callable on
    /// `dyn ByteSource` (the `Self: Sized` bound): wrap the object in an
    /// `Arc` first — `Arc<dyn ByteSource>` itself implements `ByteSource`.
    fn reader_at(&self, offset: u64) -> SourceReader<'_>
    where
        Self: Sized,
    {
        SourceReader::new(self, offset)
    }
}

/// Streaming reader over a borrowed [`ByteSource`], produced by
/// [`ByteSource::reader_at`]. Reads clamp at end-of-source.
pub struct SourceReader<'a> {
    src: &'a dyn ByteSource,
    pos: u64,
}

impl<'a> SourceReader<'a> {
    /// New reader positioned at `offset`.
    pub fn new(src: &'a dyn ByteSource, pos: u64) -> Self {
        Self { src, pos }
    }

    /// Current absolute position.
    pub fn position(&self) -> u64 {
        self.pos
    }
}

impl Read for SourceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.src.read_at(self.pos, buf)?;
        self.pos = self.pos.saturating_add(n as u64);
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// In-memory sources
// ---------------------------------------------------------------------------

impl ByteSource for Vec<u8> {
    fn len(&self) -> u64 {
        self.as_slice().len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.as_slice().read_at(offset, buf)
    }
}

impl ByteSource for &[u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let total = <[u8]>::len(self) as u64;
        if offset >= total {
            return Ok(0);
        }
        let start = offset as usize;
        let n = buf.len().min(<[u8]>::len(self) - start);
        buf[..n].copy_from_slice(&self[start..start + n]);
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// File-backed sources
// ---------------------------------------------------------------------------

/// Positioned-read `ByteSource` for [`File`] on Unix and Windows.
#[cfg(unix)]
impl ByteSource for File {
    fn len(&self) -> u64 {
        self.metadata().map(|m| m.len()).unwrap_or(0)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::unix::fs::FileExt;
        match FileExt::read_at(self, buf, offset) {
            // Raw character devices (`/dev/rdisk*`) reject unaligned reads
            // with EINVAL — retry through a sector-aligned bounce window.
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
                const SEC: u64 = 512;
                let a_start = offset & !(SEC - 1);
                let a_end = (offset + buf.len() as u64).div_ceil(SEC) * SEC;
                let mut tmp = vec![0u8; (a_end - a_start) as usize];
                let n = FileExt::read_at(self, &mut tmp, a_start)?;
                let base = (offset - a_start) as usize;
                let got = n.saturating_sub(base).min(buf.len());
                buf[..got].copy_from_slice(&tmp[base..base + got]);
                Ok(got)
            }
            r => r,
        }
    }
}

/// Positioned-read `ByteSource` for [`File`] on Unix and Windows.
#[cfg(windows)]
impl ByteSource for File {
    fn len(&self) -> u64 {
        self.metadata().map(|m| m.len()).unwrap_or(0)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::windows::fs::FileExt;
        FileExt::seek_read(self, buf, offset)
    }
}

/// Portable file-backed source using a mutex-guarded seek+read cursor.
///
/// Slower than the positioned-read impls but works on every platform and is
/// the only option on targets without `FileExt::read_at`/`seek_read`.
pub struct FileSource {
    file: Mutex<File>,
    len: u64,
    /// Raw character devices (macOS `/dev/rdisk*`, Linux `/dev/raw*`) reject
    /// reads whose offset or length is not a multiple of the sector size —
    /// reads must go through a sector-aligned bounce window.
    sector_bounce: bool,
}

impl FileSource {
    /// Sector size assumed for raw-device bounce alignment.
    const RAW_SECTOR: u64 = 512;

    /// Wrap an already-open `File`.
    pub fn new(file: File) -> io::Result<Self> {
        let meta = file.metadata()?;
        let mut len = meta.len();
        #[cfg(unix)]
        let sector_bounce = {
            use std::os::unix::fs::FileTypeExt;
            meta.file_type().is_char_device()
        };
        #[cfg(not(unix))]
        let sector_bounce = false;
        #[cfg(unix)]
        if len == 0 {
            len = Self::probe_len(&file);
        }
        Ok(Self {
            file: Mutex::new(file),
            len,
            sector_bounce,
        })
    }

    /// Block and character device nodes (`/dev/diskN`, `/dev/rdiskN`) report
    /// `st_size == 0` and `SEEK_END` does not resolve their size on macOS, so
    /// binary-search the readable extent with positioned reads instead —
    /// ~50 sector reads once at open. Returns 0 when nothing is readable.
    #[cfg(unix)]
    fn probe_len(file: &File) -> u64 {
        use std::os::unix::fs::FileExt;
        const SECTOR: u64 = 512;
        let mut buf = [0u8; SECTOR as usize];
        match FileExt::read_at(file, &mut buf, 0) {
            Ok(n) if n > 0 => {}
            _ => return 0,
        }
        // Invariant: sector `lo` is readable, `hi` is not.
        let (mut lo, mut hi) = (0u64, u64::MAX / SECTOR);
        while lo + 1 < hi {
            let mid = lo + (hi - lo) / 2;
            match FileExt::read_at(file, &mut buf, mid * SECTOR) {
                Ok(n) if n > 0 => lo = mid,
                _ => hi = mid,
            }
        }
        (lo + 1) * SECTOR
    }

    /// Open a path read-only.
    pub fn open(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        Self::new(File::open(path)?)
    }
}

impl ByteSource for FileSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let want = buf.len().min((self.len - offset) as usize);
        if want == 0 {
            return Ok(0);
        }
        let mut f = self
            .file
            .lock()
            .map_err(|_| io::Error::other("FileSource lock poisoned"))?;
        if !self.sector_bounce {
            f.seek(SeekFrom::Start(offset))?;
            return f.read(&mut buf[..want]);
        }
        // Raw device: widen the request to sector boundaries, read the
        // aligned window, then slice out the requested range.
        let sec = Self::RAW_SECTOR;
        let a_start = offset & !(sec - 1);
        let a_end = (offset + want as u64).div_ceil(sec) * sec;
        let a_len = (a_end - a_start) as usize;
        let mut tmp = vec![0u8; a_len];
        f.seek(SeekFrom::Start(a_start))?;
        let mut filled = 0usize;
        while filled < a_len {
            match f.read(&mut tmp[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        let base = (offset - a_start) as usize;
        let got = filled.saturating_sub(base).min(want);
        buf[..got].copy_from_slice(&tmp[base..base + got]);
        Ok(got)
    }
}

// ---------------------------------------------------------------------------
// Forwarding impls so `Arc<dyn ByteSource>` is itself a `ByteSource`.
// ---------------------------------------------------------------------------

impl<T: ByteSource + ?Sized> ByteSource for Arc<T> {
    fn len(&self) -> u64 {
        (**self).len()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read_at(offset, buf)
    }
}

impl<T: ByteSource + ?Sized> ByteSource for Box<T> {
    fn len(&self) -> u64 {
        (**self).len()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        (**self).read_at(offset, buf)
    }
}

/// Helper: turn anything `ByteSource + 'static` into a shared trait object.
pub fn into_arc<S: ByteSource + 'static>(src: S) -> Arc<dyn ByteSource> {
    Arc::new(src)
}
