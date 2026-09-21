//! QCOW2 (`*.qcow2`) — pure-Rust read-only reader.
//!
//! QCOW (QEMU Copy-On-Write) images start with a big-endian header
//! (magic `QFI\xfb`) describing a two-level cluster map:
//!
//! * `cluster_bits` gives `cluster_size = 1 << cluster_bits` (2⁹–2²¹).
//! * The **L1 table** (`l1_table_offset`, `l1_size` u64 entries) maps
//!   each range of `cluster_size / 8` guest clusters to an **L2 table**
//!   (one cluster of u64 entries). Entry bit 63 = `COPIED`, bits 9–55 =
//!   the host offset (512-aligned); a zero offset marks an unallocated
//!   table — the whole span reads as zeros.
//! * **L2 entries** (u64, big-endian): bit 62 = compressed, bit 63 =
//!   COPIED, bits 9–55 = host cluster offset, bit 0 = `ZERO` flag
//!   (preallocated-but-logically-zero cluster → zeros).
//! * **Compressed clusters** (bit 62) store a raw-DEFLATE stream (no
//!   zlib wrapper) at a byte-granular offset. The descriptor packs the
//!   offset into bits 0..`csize_shift` and `sectors − 1` into bits
//!   `csize_shift..62`, where `csize_shift = 62 − (cluster_bits − 8)`.
//!
//! Refcount tables are ignored — this reader never writes, so refcount
//! accuracy is irrelevant.
//!
//! ## Supported / unsupported
//!
//! * QCOW versions 2 and 3 with no backing file, unencrypted:
//!   **readable**, including compressed clusters.
//! * `crypt_method != 0` (AES, LUKS), a backing file (differencing),
//!   the `external data file`, `extended L2` or `compression type`
//!   incompatible features, and QCOW v0/v1: → [`Error::Unsupported`].
//! * `dirty`/`corrupt` incompatible flags and unknown feature bits are
//!   recorded in [`Qcow2Source::warnings`] — the bytes are still real.
//!
//! ## Leniency contract
//!
//! * An L1 table short of the geometry, or an L2 table read that
//!   truncates at EOF, zero-pads the missing entries (they decode as
//!   "unallocated") with a warning.
//! * Host offsets pointing outside the file read as zeros.
//! * A compressed cluster whose deflate stream fails to decode yields
//!   `io::Error(InvalidData)` on reads touching it — corrupt stored data
//!   is never silently replaced with zeros.
//!
//! Memory is bounded: L1/L2 tables are O(map size) as the format
//! requires, and decoded data is held only in a small LRU cache.

use std::io;
use std::sync::{Arc, Mutex};

use crate::le;
use crate::{ByteSource, Error, Result};

/// QCOW2 file magic (big-endian `QFI\xfb`).
pub const QCOW2_MAGIC: u32 = 0x5146_49FB;

/// QCOW2 header size we need to read (fields through v3's compression
/// type live within the first 112 bytes).
const HEADER_SIZE: usize = 112;
const MIN_CLUSTER_BITS: u32 = 9; // 512 B
const MAX_CLUSTER_BITS: u32 = 21; // 2 MiB (spec maximum)
/// Cap on L1 entries — bounds the index we hold (8 bytes each).
const MAX_L1_ENTRIES: u64 = 1 << 22;
/// Decoded-cluster LRU capacity.
const CLUSTER_CACHE_CAP: usize = 8;
/// L2-table LRU capacity (raw table bytes).
const L2_CACHE_CAP: usize = 4;
/// Bound on recorded warnings.
const MAX_WARNINGS: usize = 128;

/// Mask for the host-offset field of L1/L2 entries (bits 9–55).
const OFFSET_MASK: u64 = 0x00FF_FFFF_FFFF_FE00;
const OFLAG_COPIED: u64 = 1 << 63;
const OFLAG_COMPRESSED: u64 = 1 << 62;
const OFLAG_ZERO: u64 = 1;

// Incompatible-feature bits (qcow2 v3 header).
const INCOMPAT_DIRTY: u64 = 1;
const INCOMPAT_CORRUPT: u64 = 1 << 1;
const INCOMPAT_EXTERNAL_DATA: u64 = 1 << 2;
const INCOMPAT_COMPRESSION_TYPE: u64 = 1 << 3;
const INCOMPAT_EXTENDED_L2: u64 = 1 << 4;

fn warn(warnings: &mut Vec<String>, msg: impl Into<String>) {
    if warnings.len() < MAX_WARNINGS {
        warnings.push(msg.into());
    }
}

/// Geometry of an opened QCOW2 image.
#[derive(Debug, Clone)]
pub struct Qcow2Info {
    /// QCOW version from the header (2 or 3).
    pub version: u32,
    /// Cluster size in bytes (`1 << cluster_bits`).
    pub cluster_size: u64,
    /// Raw `cluster_bits` field.
    pub cluster_bits: u32,
    /// Virtual disk size in bytes.
    pub virtual_size: u64,
    /// Declared L1 table entry count.
    pub l1_size: u32,
    /// File offset of the L1 table.
    pub l1_table_offset: u64,
    /// L2 entries per table (`cluster_size / 8`).
    pub l2_entries: u64,
    /// Raw `crypt_method` (always 0 — encrypted images are rejected).
    pub crypt_method: u32,
    /// Raw incompatible-features bitmask (v3; 0 on v2).
    pub incompatible_features: u64,
}

/// Small LRU of decoded clusters / raw L2 tables, keyed by index.
struct Cache {
    entries: Vec<(u64, Arc<Vec<u8>>)>,
    cap: usize,
}

impl Cache {
    fn new(cap: usize) -> Self {
        Self {
            entries: Vec::with_capacity(cap),
            cap,
        }
    }

    fn get(&mut self, idx: u64) -> Option<Arc<Vec<u8>>> {
        let pos = self.entries.iter().position(|(i, _)| *i == idx)?;
        let e = self.entries.remove(pos);
        self.entries.insert(0, e);
        Some(self.entries[0].1.clone())
    }

    fn put(&mut self, idx: u64, data: Vec<u8>) -> Arc<Vec<u8>> {
        if self.entries.len() == self.cap {
            self.entries.pop();
        }
        self.entries.insert(0, (idx, Arc::new(data)));
        self.entries[0].1.clone()
    }
}

struct Caches {
    /// Decoded guest clusters by cluster index.
    clusters: Cache,
    /// Raw L2 table bytes by L1 index.
    l2: Cache,
}

/// Read-only `ByteSource` over a QCOW2 image.
///
/// Build with [`Qcow2Source::open`]; use as a plain [`ByteSource`]
/// (`read_at`, `read_slice`, `reader_at`) or inspect geometry via
/// [`Qcow2Source::info`] / [`Qcow2Source::warnings`].
pub struct Qcow2Source {
    src: Arc<dyn ByteSource>,
    info: Qcow2Info,
    /// Big-endian L1 entries.
    l1: Vec<u64>,
    len: u64,
    warnings: Vec<String>,
    caches: Mutex<Caches>,
    /// `62 − (cluster_bits − 8)` — compressed-descriptor split point.
    csize_shift: u32,
}

impl Qcow2Source {
    /// Quick probe: QCOW magic at offset 0.
    pub fn is_qcow2(src: &dyn ByteSource) -> bool {
        src.read_slice(0, 4)
            .map(|h| le::u32_be(&h, 0) == Some(QCOW2_MAGIC))
            .unwrap_or(false)
    }

    /// Open a QCOW2 image.
    ///
    /// Encrypted (`crypt_method` ≠ 0), backing-file (differencing),
    /// external-data-file, extended-L2, non-deflate-compressed and
    /// pre-v2 images return [`Error::Unsupported`]; a bad magic or
    /// implausible geometry returns [`Error::Corrupt`]/[`Error::Truncated`].
    pub fn open(src: Arc<dyn ByteSource>) -> Result<Self> {
        let file_len = src.len();
        let head = src
            .read_slice(0, HEADER_SIZE.min(file_len as usize))
            .map_err(Error::Io)?;
        if head.len() < 48 {
            return Err(Error::Truncated {
                offset: 0,
                requested: 48,
                available: head.len() as u64,
            });
        }
        if le::u32_be(&head, 0) != Some(QCOW2_MAGIC) {
            return Err(Error::corrupt(0, "not a QCOW2 image (bad QFI magic)"));
        }
        let mut warnings = Vec::new();
        let version = le::u32_be(&head, 4).unwrap_or(0);
        if !matches!(version, 2 | 3) {
            return Err(Error::unsupported(format!(
                "qcow version {version} (only qcow2 v2/v3 are readable)"
            )));
        }
        let backing_off = le::u64_be(&head, 8).unwrap_or(0);
        let backing_len = le::u32_be(&head, 16).unwrap_or(0);
        if backing_off != 0 || backing_len != 0 {
            return Err(Error::unsupported(
                "qcow2 with a backing file (differencing) needs its parent; not supported",
            ));
        }
        let cluster_bits = le::u32_be(&head, 20).unwrap_or(0);
        if !(MIN_CLUSTER_BITS..=MAX_CLUSTER_BITS).contains(&cluster_bits) {
            return Err(Error::corrupt(
                20,
                format!("qcow2: implausible cluster_bits {cluster_bits}"),
            ));
        }
        let cluster_size = 1u64 << cluster_bits;
        let virtual_size = le::u64_be(&head, 24).unwrap_or(0);
        if virtual_size == 0 {
            return Err(Error::corrupt(24, "qcow2: zero virtual disk size"));
        }
        let crypt_method = le::u32_be(&head, 32).unwrap_or(0);
        if crypt_method != 0 {
            return Err(Error::unsupported(format!(
                "qcow2 crypt_method {crypt_method} (AES/LUKS encryption)"
            )));
        }
        let l1_size = le::u32_be(&head, 36).unwrap_or(0) as u64;
        let l1_table_offset = le::u64_be(&head, 40).unwrap_or(0);
        let mut incompatible = 0u64;
        if version == 3 {
            if head.len() < HEADER_SIZE {
                return Err(Error::Truncated {
                    offset: 0,
                    requested: HEADER_SIZE as u64,
                    available: head.len() as u64,
                });
            }
            incompatible = le::u64_be(&head, 72).unwrap_or(0);
            if incompatible & INCOMPAT_DIRTY != 0 {
                warn(&mut warnings, "qcow2: 'dirty' incompatible flag is set");
            }
            if incompatible & INCOMPAT_CORRUPT != 0 {
                warn(&mut warnings, "qcow2: 'corrupt' incompatible flag is set");
            }
            if incompatible & INCOMPAT_EXTERNAL_DATA != 0 {
                return Err(Error::unsupported(
                    "qcow2 with an external data file is not supported",
                ));
            }
            if incompatible & INCOMPAT_EXTENDED_L2 != 0 {
                return Err(Error::unsupported(
                    "qcow2 extended L2 entries are not supported",
                ));
            }
            if incompatible & INCOMPAT_COMPRESSION_TYPE != 0 {
                // Non-default compression is in use; field @104.
                let ctype = le::u8(&head, 104).unwrap_or(0);
                return Err(Error::unsupported(format!(
                    "qcow2 compression_type {ctype} (only deflate is supported)"
                )));
            }
            let known = INCOMPAT_DIRTY
                | INCOMPAT_CORRUPT
                | INCOMPAT_EXTERNAL_DATA
                | INCOMPAT_COMPRESSION_TYPE
                | INCOMPAT_EXTENDED_L2;
            if incompatible & !known != 0 {
                warn(
                    &mut warnings,
                    format!(
                        "qcow2: unknown incompatible feature bits {:#x} set; continuing",
                        incompatible & !known
                    ),
                );
            }
        }
        if l1_table_offset % 8 != 0 || l1_table_offset >= file_len {
            return Err(Error::corrupt(
                40,
                format!("qcow2: implausible l1_table_offset {l1_table_offset:#x}"),
            ));
        }
        // L1 entries needed to cover the virtual size.
        let l2_entries = cluster_size / 8;
        let total_clusters = virtual_size.div_ceil(cluster_size);
        let needed_l1 = total_clusters.div_ceil(l2_entries);
        let n = l1_size.min(needed_l1).min(MAX_L1_ENTRIES);
        if l1_size < needed_l1 {
            warn(
                &mut warnings,
                format!(
                    "qcow2: L1 holds {l1_size} entries but {needed_l1} are needed; \
                     tail clusters read as zeros"
                ),
            );
        } else if needed_l1 > MAX_L1_ENTRIES {
            return Err(Error::unsupported(format!(
                "qcow2 needing {needed_l1} L1 entries (virtual size {virtual_size})"
            )));
        }
        let raw = src
            .read_slice(l1_table_offset, (n * 8) as usize)
            .map_err(Error::Io)?;
        if (raw.len() as u64) < n * 8 {
            warn(
                &mut warnings,
                format!(
                    "qcow2: L1 table at {l1_table_offset:#x} truncated ({} of {} bytes)",
                    raw.len(),
                    n * 8
                ),
            );
        }
        let mut l1 = Vec::with_capacity(n as usize);
        for i in 0..n as usize {
            l1.push(le::u64_be(&raw, i * 8).unwrap_or(0));
        }

        Ok(Self {
            src,
            info: Qcow2Info {
                version,
                cluster_size,
                cluster_bits,
                virtual_size,
                l1_size: l1_size as u32,
                l1_table_offset,
                l2_entries,
                crypt_method,
                incompatible_features: incompatible,
            },
            l1,
            len: virtual_size,
            warnings,
            caches: Mutex::new(Caches {
                clusters: Cache::new(CLUSTER_CACHE_CAP),
                l2: Cache::new(L2_CACHE_CAP),
            }),
            csize_shift: 62 - (cluster_bits - 8),
        })
    }

    /// Image geometry.
    pub fn info(&self) -> &Qcow2Info {
        &self.info
    }

    /// Non-fatal anomalies noticed while parsing.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Raw L2 table bytes for L1 index `l1i` (cached); `None` when the
    /// L1 entry is unallocated.
    fn l2_table(&self, l1i: u64) -> io::Result<Option<Arc<Vec<u8>>>> {
        let Some(&l1e) = self.l1.get(l1i as usize) else {
            return Ok(None);
        };
        let l2_off = l1e & OFFSET_MASK;
        if l2_off == 0 {
            return Ok(None);
        }
        let _ = l1e & OFLAG_COPIED; // refcount hint only; ignored for reads
        {
            let mut c = self
                .caches
                .lock()
                .map_err(|_| io::Error::other("qcow2 cache lock poisoned"))?;
            if let Some(t) = c.l2.get(l1i) {
                return Ok(Some(t));
            }
        }
        let cs = self.info.cluster_size;
        // Short reads pad with zeros — entries decode as unallocated.
        let mut t = self.src.read_slice(l2_off, cs as usize)?;
        t.resize(cs as usize, 0);
        let mut c = self
            .caches
            .lock()
            .map_err(|_| io::Error::other("qcow2 cache lock poisoned"))?;
        Ok(Some(c.l2.put(l1i, t)))
    }

    /// Decode guest cluster `ci` into memory (cached). Always returns
    /// `cluster_size` bytes (zero-padded tail).
    fn decoded_cluster(&self, ci: u64) -> io::Result<Arc<Vec<u8>>> {
        {
            let mut c = self
                .caches
                .lock()
                .map_err(|_| io::Error::other("qcow2 cache lock poisoned"))?;
            if let Some(d) = c.clusters.get(ci) {
                return Ok(d);
            }
        }
        let data = self.decode_cluster(ci)?;
        let mut c = self
            .caches
            .lock()
            .map_err(|_| io::Error::other("qcow2 cache lock poisoned"))?;
        Ok(c.clusters.put(ci, data))
    }

    fn decode_cluster(&self, ci: u64) -> io::Result<Vec<u8>> {
        let cs = self.info.cluster_size;
        let cs_us = usize::try_from(cs).unwrap_or(usize::MAX);
        let l1i = ci / self.info.l2_entries;
        let l2i = ci % self.info.l2_entries;
        let Some(table) = self.l2_table(l1i)? else {
            return Ok(vec![0u8; cs_us]);
        };
        let entry = le::u64_be(&table, l2i as usize * 8).unwrap_or(0);
        if entry & OFLAG_COMPRESSED != 0 {
            // Compressed descriptor: offset in bits 0..csize_shift,
            // (sectors−1) in bits csize_shift..62.
            let offset = entry & ((1u64 << self.csize_shift) - 1);
            let nb_sectors =
                ((entry >> self.csize_shift) & ((1u64 << (self.info.cluster_bits - 8)) - 1)) + 1;
            let comp_len = nb_sectors
                .saturating_mul(512)
                .saturating_sub(offset % 512);
            let stored = self.src.read_slice(
                offset,
                usize::try_from(comp_len).unwrap_or(usize::MAX),
            )?;
            // QCOW2 stores *raw* deflate (no zlib header).
            let mut d = miniz_oxide::inflate::decompress_to_vec_with_limit(&stored, cs_us)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("qcow2 cluster {ci} at {offset:#x}: corrupt deflate stream ({e:?})"),
                    )
                })?;
            d.resize(cs_us, 0);
            return Ok(d);
        }
        let offset = entry & OFFSET_MASK;
        if entry & OFLAG_ZERO != 0 || offset == 0 {
            return Ok(vec![0u8; cs_us]);
        }
        // Uncompressed cluster: read what's there, zero-pad the tail
        // (a truncated file is evidence-shaped too).
        let mut out = self.src.read_slice(offset, cs_us)?;
        out.resize(cs_us, 0);
        Ok(out)
    }
}

impl ByteSource for Qcow2Source {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if offset >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let cs = self.info.cluster_size;
        let mut done = 0usize;
        let mut pos = offset;
        while done < buf.len() && pos < self.len {
            let ci = pos / cs;
            let within = pos % cs;
            let want = (buf.len() - done)
                .min(usize::try_from(cs - within).unwrap_or(usize::MAX))
                .min(usize::try_from(self.len - pos).unwrap_or(usize::MAX));
            let cluster = self.decoded_cluster(ci)?;
            let s = within as usize;
            let n = want.min((*cluster).len().saturating_sub(s));
            buf[done..done + n].copy_from_slice(&cluster[s..s + n]);
            buf[done + n..done + want].fill(0);
            pos = pos.saturating_add(want as u64);
            done += want;
        }
        Ok(done)
    }
}
