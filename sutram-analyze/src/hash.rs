//! Content hashing and acquisition verification — pure Rust, no
//! ring/openssl/`digest`-crate dependencies.
//!
//! Three hasher implementations live here, each a streaming
//! `update`/`finalize` type over byte slices:
//!
//! * [`Sha256`] — FIPS 180-4 SHA-256;
//! * [`Sha1`] — FIPS 180-1 SHA-1;
//! * [`Md5`] — RFC 1321 MD5 (kept because the forensic world still
//!   indexes on it — EWF `hash`/`digest` sections store MD5/SHA-1).
//!
//! [`hash_reader`] runs all three over one `Read` in a single pass;
//! [`hash_entry`] applies it to an [`FsEntry`] via
//! [`FileSystem::read_file`], flagging short reads as `partial`.
//!
//! [`verify_source`] / [`verify_acquisition`] hash the *decoded media
//! bytes* of an EWF (`E01`) image and compare them against the
//! acquisition hashes the imaging tool stored in its `hash`/`digest`
//! sections — the "does this image still prove what it proved at
//! acquisition time" check. The result is [`AcqVerification::Verified`],
//! [`AcqVerification::Mismatch`] or [`AcqVerification::NotAvailable`]
//! (non-EWF input, or an image that stores no hash).
//!
//! All three algorithms are public so callers can hash arbitrary
//! buffers/streams without going through a mounted filesystem.

use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;

use sutram_fs::{EntryKind, FileSystem, FsEntry, FsError, Result};
use sutram_io::ewf::EwfSource;
use sutram_io::{into_arc, ByteSource, FileSource, SourceReader};

/// Read buffer size for all streaming passes in this module.
const STREAM_BUF: usize = 128 << 10;

/// Lowercase hex rendering of a digest.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Streaming SHA-256 hasher (FIPS 180-4).
#[derive(Clone)]
pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    buflen: usize,
    total: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Fresh hasher.
    pub fn new() -> Self {
        Sha256 {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0; 64],
            buflen: 0,
            total: 0,
        }
    }

    /// Feed bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buflen > 0 {
            let need = 64 - self.buflen;
            let take = need.min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buflen = 0;
            }
        }
        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            let mut b = [0u8; 64];
            b.copy_from_slice(block);
            self.compress(&b);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }

    /// Pad and produce the 32-byte digest.
    pub fn finalize(mut self) -> [u8; 32] {
        let bitlen = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buflen != 56 {
            self.update(&[0]);
        }
        self.update(&bitlen.to_be_bytes());
        debug_assert_eq!(self.buflen, 0);
        let mut out = [0u8; 32];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    /// [`finalize`](Self::finalize) as lowercase hex.
    pub fn finalize_hex(self) -> String {
        hex(&self.finalize())
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (h, v) in self.h.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *h = h.wrapping_add(v);
        }
    }
}

// ---------------------------------------------------------------------------
// SHA-1 (FIPS 180-1)
// ---------------------------------------------------------------------------

/// Streaming SHA-1 hasher (FIPS 180-1). Retained because EWF `digest`
/// sections and legacy hash sets use it — do not use for new security
/// decisions.
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    buf: [u8; 64],
    buflen: usize,
    total: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// Fresh hasher.
    pub fn new() -> Self {
        Sha1 {
            h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            buf: [0; 64],
            buflen: 0,
            total: 0,
        }
    }

    /// Feed bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buflen > 0 {
            let need = 64 - self.buflen;
            let take = need.min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buflen = 0;
            }
        }
        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            let mut b = [0u8; 64];
            b.copy_from_slice(block);
            self.compress(&b);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }

    /// Pad and produce the 20-byte digest.
    pub fn finalize(mut self) -> [u8; 20] {
        let bitlen = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buflen != 56 {
            self.update(&[0]);
        }
        self.update(&bitlen.to_be_bytes());
        debug_assert_eq!(self.buflen, 0);
        let mut out = [0u8; 20];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    /// [`finalize`](Self::finalize) as lowercase hex.
    pub fn finalize_hex(self) -> String {
        hex(&self.finalize())
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a827999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (h, v) in self.h.iter_mut().zip([a, b, c, d, e]) {
            *h = h.wrapping_add(v);
        }
    }
}

// ---------------------------------------------------------------------------
// MD5 (RFC 1321)
// ---------------------------------------------------------------------------

const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, //
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, //
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const MD5_K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// Streaming MD5 hasher (RFC 1321). Cryptographically broken — retained
/// for compatibility with acquisition formats and legacy hash sets only.
#[derive(Clone)]
pub struct Md5 {
    h: [u32; 4],
    buf: [u8; 64],
    buflen: usize,
    total: u64,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    /// Fresh hasher.
    pub fn new() -> Self {
        Md5 {
            h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            buf: [0; 64],
            buflen: 0,
            total: 0,
        }
    }

    /// Feed bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buflen > 0 {
            let need = 64 - self.buflen;
            let take = need.min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buflen = 0;
            }
        }
        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            let mut b = [0u8; 64];
            b.copy_from_slice(block);
            self.compress(&b);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }

    /// Pad and produce the 16-byte digest.
    pub fn finalize(mut self) -> [u8; 16] {
        let bitlen = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buflen != 56 {
            self.update(&[0]);
        }
        self.update(&bitlen.to_le_bytes());
        debug_assert_eq!(self.buflen, 0);
        let mut out = [0u8; 16];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// [`finalize`](Self::finalize) as lowercase hex.
    pub fn finalize_hex(self) -> String {
        hex(&self.finalize())
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        let [mut a, mut b, mut c, mut d] = self.h;
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let tmp = f
                .wrapping_add(a)
                .wrapping_add(MD5_K[i])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(tmp.rotate_left(MD5_S[i]));
        }
        for (h, v) in self.h.iter_mut().zip([a, b, c, d]) {
            *h = h.wrapping_add(v);
        }
    }
}

// ---------------------------------------------------------------------------
// Triple-pass streaming entry points
// ---------------------------------------------------------------------------

/// SHA-256 + SHA-1 + MD5 of a byte stream, computed in one pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digests {
    /// SHA-256, lowercase hex.
    pub sha256: String,
    /// SHA-1, lowercase hex.
    pub sha1: String,
    /// MD5, lowercase hex.
    pub md5: String,
}

/// Hash everything `r` yields until EOF in a single pass.
/// Returns the digests and the number of bytes consumed.
pub fn hash_reader(mut r: impl Read) -> io::Result<(Digests, u64)> {
    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    let mut md5 = Md5::new();
    let mut buf = vec![0u8; STREAM_BUF];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        sha256.update(chunk);
        sha1.update(chunk);
        md5.update(chunk);
        total = total.saturating_add(n as u64);
    }
    Ok((
        Digests {
            sha256: sha256.finalize_hex(),
            sha1: sha1.finalize_hex(),
            md5: md5.finalize_hex(),
        },
        total,
    ))
}

/// Hash a whole [`ByteSource`] in one sequential pass.
pub fn hash_source(src: &dyn ByteSource) -> Result<(Digests, u64)> {
    let (d, n) = hash_reader(SourceReader::new(src, 0))?;
    Ok((d, n))
}

/// Per-entry digest set from [`hash_entry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashResult {
    /// SHA-256, lowercase hex.
    pub sha256: String,
    /// SHA-1, lowercase hex.
    pub sha1: String,
    /// MD5, lowercase hex.
    pub md5: String,
    /// Bytes actually read from `read_file`.
    pub bytes_read: u64,
    /// `true` when fewer bytes were hashed than `FsEntry::size` claims —
    /// a partially-overwritten deleted file, a truncated read, or a
    /// parser that can only surface recoverable extents. The digests are
    /// still valid *for the bytes returned*, but they will not match a
    /// hash set built from the intact file.
    pub partial: bool,
}

/// Hash one entry's contents through [`FileSystem::read_file`].
///
/// Non-`File` kinds return [`FsError::InvalidInput`] — directories and
/// symlinks have no byte stream to digest. `partial` is set whenever the
/// reader yields less than the entry's declared `size`.
pub fn hash_entry(fs: &dyn FileSystem, entry: &FsEntry) -> Result<HashResult> {
    if entry.kind != EntryKind::File {
        return Err(FsError::InvalidInput {
            msg: format!("hash_entry: {} is a {:?}, not a file", entry.path, entry.kind),
        });
    }
    let r = fs.read_file(entry)?;
    let (d, n) = hash_reader(r)?;
    Ok(HashResult {
        sha256: d.sha256,
        sha1: d.sha1,
        md5: d.md5,
        bytes_read: n,
        partial: n < entry.size,
    })
}

// ---------------------------------------------------------------------------
// EWF acquisition verification
// ---------------------------------------------------------------------------

/// The media hashes computed while verifying an acquisition image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaHashes {
    /// MD5 of the decoded media bytes (the classic EWF acquisition hash).
    pub md5: String,
    /// SHA-1 of the decoded media bytes.
    pub sha1: String,
    /// SHA-256 of the decoded media bytes (not stored in E01, but the
    /// value a modern examiner wants recorded).
    pub sha256: String,
    /// Logical media bytes hashed.
    pub bytes_hashed: u64,
}

/// One stored-hash disagreement inside [`AcqVerification::Mismatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMismatch {
    /// Which algorithm disagreed (`"md5"` / `"sha1"`).
    pub algorithm: &'static str,
    /// Hash stored in the image's `hash`/`digest` section (hex).
    pub stored: String,
    /// Hash computed over the decoded media bytes (hex).
    pub computed: String,
}

/// Outcome of comparing computed media hashes against an EWF image's
/// stored acquisition hashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcqVerification {
    /// Every stored acquisition hash equals the computed value — the
    /// image proves the same bytes it proved at acquisition time.
    Verified {
        /// The computed media hashes (for the report).
        computed: MediaHashes,
    },
    /// At least one stored hash disagrees — the image does **not**
    /// match its acquisition record. Treat the evidence as suspect.
    Mismatch {
        /// The computed media hashes.
        computed: MediaHashes,
        /// One record per disagreeing algorithm.
        mismatches: Vec<HashMismatch>,
    },
    /// Nothing to check against: the input is not an EWF image, or the
    /// image stores no `hash`/`digest` section.
    NotAvailable {
        /// Why verification was not possible.
        reason: String,
    },
}

impl AcqVerification {
    /// `true` on [`AcqVerification::Verified`].
    pub fn is_verified(&self) -> bool {
        matches!(self, AcqVerification::Verified { .. })
    }
}

/// Verify an opened [`EwfSource`]: hash the decoded media bytes and
/// compare with `acquisition_hash()`.
///
/// MD5 and SHA-1 are checked when stored; both must match for
/// `Verified`. An image carrying neither yields `NotAvailable`.
pub fn verify_ewf(ewf: &EwfSource) -> Result<AcqVerification> {
    let stored_md5 = ewf.acquisition_hash().and_then(|h| h.md5_hex());
    let stored_sha1 = ewf.acquisition_hash().and_then(|h| h.sha1_hex());
    if stored_md5.is_none() && stored_sha1.is_none() {
        return Ok(AcqVerification::NotAvailable {
            reason: "EWF image stores no acquisition hash (no usable hash/digest section)"
                .to_string(),
        });
    }
    let (d, n) = hash_source(ewf)?;
    let computed = MediaHashes {
        md5: d.md5,
        sha1: d.sha1,
        sha256: d.sha256,
        bytes_hashed: n,
    };
    let mut mismatches = Vec::new();
    if let Some(stored) = &stored_md5 {
        if *stored != computed.md5 {
            mismatches.push(HashMismatch {
                algorithm: "md5",
                stored: stored.clone(),
                computed: computed.md5.clone(),
            });
        }
    }
    if let Some(stored) = &stored_sha1 {
        if *stored != computed.sha1 {
            mismatches.push(HashMismatch {
                algorithm: "sha1",
                stored: stored.clone(),
                computed: computed.sha1.clone(),
            });
        }
    }
    Ok(if mismatches.is_empty() {
        AcqVerification::Verified { computed }
    } else {
        AcqVerification::Mismatch {
            computed,
            mismatches,
        }
    })
}

/// Verify a single-segment EWF image already open as a `ByteSource`
/// (or a lone `.E01`). Non-EWF input returns `NotAvailable`, never an
/// error — callers can probe any image unconditionally.
///
/// For multi-segment images (`.E01` + `.E02` + …) open them with
/// [`EwfSource::open`] yourself and call [`verify_ewf`].
pub fn verify_source(src: Arc<dyn ByteSource>) -> Result<AcqVerification> {
    if !EwfSource::is_ewf(src.as_ref()) {
        return Ok(AcqVerification::NotAvailable {
            reason: "not an EWF (E01) image — raw images store no acquisition hash".to_string(),
        });
    }
    let ewf = EwfSource::open(vec![src])?;
    verify_ewf(&ewf)
}

/// Verify the acquisition hashes of an EWF image on disk.
///
/// Convenience wrapper: opens `image_path` and delegates to
/// [`verify_source`]. Use [`EwfSource::open`] + [`verify_ewf`] for
/// multi-segment image sets.
pub fn verify_acquisition(image_path: impl AsRef<Path>) -> Result<AcqVerification> {
    let src = into_arc(FileSource::open(image_path).map_err(FsError::Io)?);
    verify_source(src)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::Cursor;

    use sutram_fs::{FsEntryStatus, FsInfo, RecoveryState, Timestamps};

    // -- FIPS 180-4 SHA-256 vectors -------------------------------------

    fn sha256_of(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize_hex()
    }

    #[test]
    fn sha256_fips_vectors() {
        assert_eq!(
            sha256_of(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_of(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_of(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        let mil = vec![b'a'; 1_000_000];
        assert_eq!(
            sha256_of(&mil),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn sha256_split_updates() {
        // Feeding in odd-sized chunks must equal the one-shot digest.
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let want = sha256_of(&data);
        for step in [1usize, 63, 64, 65, 127, 4096] {
            let mut h = Sha256::new();
            for c in data.chunks(step) {
                h.update(c);
            }
            assert_eq!(h.finalize_hex(), want, "chunk size {step}");
        }
    }

    // -- FIPS 180-1 / RFC 3174 SHA-1 vectors -----------------------------

    fn sha1_of(data: &[u8]) -> String {
        let mut h = Sha1::new();
        h.update(data);
        h.finalize_hex()
    }

    #[test]
    fn sha1_vectors() {
        assert_eq!(sha1_of(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            sha1_of(b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            sha1_of(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        let mil = vec![b'a'; 1_000_000];
        assert_eq!(
            sha1_of(&mil),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
        // 512-bit boundary: exactly 64 bytes.
        let b64 = vec![b'x'; 64];
        let mut h1 = Sha1::new();
        h1.update(&b64);
        let mut h2 = Sha1::new();
        h2.update(&b64[..31]);
        h2.update(&b64[31..]);
        assert_eq!(h1.finalize_hex(), h2.finalize_hex());
    }

    // -- RFC 1321 MD5 vectors --------------------------------------------

    fn md5_of(data: &[u8]) -> String {
        let mut h = Md5::new();
        h.update(data);
        h.finalize_hex()
    }

    #[test]
    fn md5_rfc1321_suite() {
        assert_eq!(md5_of(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_of(b"a"), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(md5_of(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_of(b"message digest"),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            md5_of(b"abcdefghijklmnopqrstuvwxyz"),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        assert_eq!(
            md5_of(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
        assert_eq!(
            md5_of(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn md5_split_updates() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i * 7 % 256) as u8).collect();
        let want = md5_of(&data);
        for step in [1usize, 55, 56, 57, 64, 1000] {
            let mut h = Md5::new();
            for c in data.chunks(step) {
                h.update(c);
            }
            assert_eq!(h.finalize_hex(), want, "chunk size {step}");
        }
    }

    // -- hash_reader / hash_entry ----------------------------------------

    #[test]
    fn hash_reader_one_pass() {
        let (d, n) = hash_reader(Cursor::new(b"hello world!")).unwrap();
        assert_eq!(n, 12);
        assert_eq!(
            d.sha256,
            "7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9"
        );
        assert_eq!(d.sha1, "430ce34d020724ed75a196dfc2ad67c77772d169");
        assert_eq!(d.md5, "fc3ff98e8c6a0d3087d515c0473f8677");
    }

    /// Minimal in-memory `FileSystem` for hash_entry tests.
    struct MemFs {
        data: HashMap<u64, Vec<u8>>,
        src: Arc<Vec<u8>>,
    }

    impl FileSystem for MemFs {
        fn info(&self) -> FsInfo {
            FsInfo {
                fs_type: "mem".into(),
                ..Default::default()
            }
        }
        fn source(&self) -> Arc<dyn ByteSource> {
            self.src.clone()
        }
        fn walk(&self) -> Box<dyn Iterator<Item = Result<FsEntry>> + Send + '_> {
            Box::new(std::iter::empty())
        }
        fn read_file(&self, entry: &FsEntry) -> Result<Box<dyn Read + Send>> {
            match self.data.get(&entry.entry_id) {
                Some(d) => Ok(Box::new(Cursor::new(d.clone()))),
                None => Err(FsError::NotFound {
                    path: entry.path.clone(),
                }),
            }
        }
    }

    fn entry(id: u64, path: &str, size: u64, kind: EntryKind) -> FsEntry {
        FsEntry {
            path: path.to_string(),
            name: path.rsplit('/').next().unwrap_or(path).to_string(),
            entry_id: id,
            kind,
            size,
            disk_offset: 0,
            allocated_ranges: vec![],
            timestamps: Timestamps::default(),
            status: FsEntryStatus::Live,
            meta: HashMap::new(),
            magic: None,
        }
    }

    #[test]
    fn hash_entry_roundtrip() {
        let mut data = HashMap::new();
        data.insert(1u64, b"hello world!".to_vec());
        let fs = MemFs {
            data,
            src: Arc::new(Vec::new()),
        };
        let e = entry(1, "/hello.txt", 12, EntryKind::File);
        let h = hash_entry(&fs, &e).unwrap();
        assert_eq!(
            h.sha256,
            "7509e5bda0c762d2bac7f90d758b5b2263fa01ccbc542ab5e3df163be08e6ca9"
        );
        assert_eq!(h.bytes_read, 12);
        assert!(!h.partial);
    }

    #[test]
    fn hash_entry_marks_partial_read() {
        // Deleted entry whose recoverable extents yield fewer bytes than
        // the recorded size → `partial` must be set.
        let mut data = HashMap::new();
        data.insert(1u64, b"only".to_vec());
        let fs = MemFs {
            data,
            src: Arc::new(Vec::new()),
        };
        let mut e = entry(1, "/_gone.bin", 100, EntryKind::File);
        e.status = FsEntryStatus::Deleted {
            recovery: RecoveryState::PartiallyOverwritten {
                recovered_bytes: 4,
                total_bytes: 100,
            },
        };
        let h = hash_entry(&fs, &e).unwrap();
        assert_eq!(h.bytes_read, 4);
        assert!(h.partial);
    }

    #[test]
    fn hash_entry_rejects_non_file() {
        let fs = MemFs {
            data: HashMap::new(),
            src: Arc::new(Vec::new()),
        };
        let dir = entry(9, "/sub", 0, EntryKind::Directory);
        assert!(matches!(
            hash_entry(&fs, &dir),
            Err(FsError::InvalidInput { .. })
        ));
        let link = entry(10, "/l", 0, EntryKind::Symlink);
        assert!(matches!(
            hash_entry(&fs, &link),
            Err(FsError::InvalidInput { .. })
        ));
    }

    #[test]
    fn hash_entry_propagates_read_failures() {
        let fs = MemFs {
            data: HashMap::new(),
            src: Arc::new(Vec::new()),
        };
        assert_eq!(fs.info().fs_type, "mem");
        let _ = fs.source();
        assert_eq!(fs.walk().count(), 0);
        let e = entry(55, "/missing.bin", 8, EntryKind::File);
        assert!(matches!(
            hash_entry(&fs, &e),
            Err(FsError::NotFound { .. })
        ));
    }

    #[test]
    fn default_hashers_match_new() {
        assert_eq!(Sha256::default().finalize_hex(), sha256_of(b""));
        assert_eq!(Sha1::default().finalize_hex(), sha1_of(b""));
        assert_eq!(Md5::default().finalize_hex(), md5_of(b""));
    }

    // -- EWF verification -------------------------------------------------
    //
    // Minimal E01 builder: uncompressed chunks only (no miniz_oxide needed),
    // enough for verify_source/verify_ewf to exercise real parsing.

    fn adler32(data: &[u8]) -> u32 {
        const MOD: u32 = 65521;
        let (mut a, mut b) = (1u32, 0u32);
        for &x in data {
            a += x as u32;
            if a >= MOD {
                a -= MOD;
            }
            b += a;
            b %= MOD;
        }
        (b << 16) | a
    }

    struct E01Builder {
        img: Vec<u8>,
        last_desc: Option<usize>,
    }

    impl E01Builder {
        fn new() -> Self {
            let mut img = Vec::new();
            img.extend_from_slice(sutram_io::ewf::EWF_SIGNATURE);
            img.push(0x01);
            img.extend_from_slice(&1u16.to_le_bytes());
            img.extend_from_slice(&0u16.to_le_bytes());
            E01Builder {
                img,
                last_desc: None,
            }
        }
        fn section(&mut self, name: &str, data: &[u8]) -> usize {
            let off = self.img.len();
            if let Some(p) = self.last_desc {
                self.img[p + 16..p + 24].copy_from_slice(&(off as u64).to_le_bytes());
                let s = adler32(&self.img[p..p + 72]);
                self.img[p + 72..p + 76].copy_from_slice(&s.to_le_bytes());
            }
            let mut d = vec![0u8; 76];
            let n = name.len().min(16);
            d[..n].copy_from_slice(&name.as_bytes()[..n]);
            d[24..32].copy_from_slice(&(data.len() as u64).to_le_bytes());
            self.img.extend_from_slice(&d);
            self.img.extend_from_slice(data);
            self.last_desc = Some(off);
            off
        }
        fn finish(self) -> Vec<u8> {
            let mut s = self;
            if let Some(p) = s.last_desc {
                let self_off = p as u64;
                s.img[p + 16..p + 24].copy_from_slice(&self_off.to_le_bytes());
                let sum = adler32(&s.img[p..p + 72]);
                s.img[p + 72..p + 76].copy_from_slice(&sum.to_le_bytes());
            }
            s.img
        }
    }

    const E01_CHUNK: usize = 32 * 1024;

    /// Build a single-segment E01 holding `media` as uncompressed chunks.
    /// `md5`/`sha1` are written into `hash`/`digest` sections when given.
    fn build_e01(media: &[u8], md5: Option<[u8; 16]>, sha1: Option<[u8; 20]>) -> Vec<u8> {
        let n_chunks = media.len().div_ceil(E01_CHUNK).max(1);
        let mut w = E01Builder::new();

        // volume section (1052 bytes, EnCase-style)
        let mut v = vec![0u8; 1052];
        v[0] = 0x01;
        v[4..8].copy_from_slice(&(n_chunks as u32).to_le_bytes());
        v[8..12].copy_from_slice(&64u32.to_le_bytes()); // sectors/chunk
        v[12..16].copy_from_slice(&512u32.to_le_bytes()); // bytes/sector
        let sectors = media.len().div_ceil(512) as u64;
        v[16..24].copy_from_slice(&sectors.to_le_bytes());
        v[36] = 0x03;
        let sum = adler32(&v[..1048]);
        v[1048..1052].copy_from_slice(&sum.to_le_bytes());
        w.section("volume", &v);

        // sectors: raw chunk payloads + 4-byte adler trailers
        let mut payloads = Vec::new();
        let mut entries = Vec::new();
        for i in 0..n_chunks {
            let data = &media[i * E01_CHUNK..media.len().min((i + 1) * E01_CHUNK)];
            entries.push(payloads.len() as u32);
            payloads.extend_from_slice(data);
            payloads.extend_from_slice(&adler32(data).to_le_bytes());
        }
        let desc = w.section("sectors", &payloads);
        for e in entries.iter_mut() {
            *e += (desc + 76) as u32; // absolute offsets
        }

        // table: 24-byte header + entries + footer
        let mut t = vec![0u8; 24 + entries.len() * 4 + 4];
        t[0..4].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        for (i, e) in entries.iter().enumerate() {
            t[24 + i * 4..28 + i * 4].copy_from_slice(&e.to_le_bytes());
        }
        let h = adler32(&t[..20]);
        t[20..24].copy_from_slice(&h.to_le_bytes());
        let f = adler32(&t[24..24 + entries.len() * 4]);
        let n = t.len();
        t[n - 4..].copy_from_slice(&f.to_le_bytes());
        w.section("table", &t.clone());
        w.section("table2", &t);

        if let Some(m) = md5 {
            let mut s = vec![0u8; 36];
            s[..16].copy_from_slice(&m);
            let c = adler32(&s[..32]);
            s[32..36].copy_from_slice(&c.to_le_bytes());
            w.section("hash", &s);

            let mut d = vec![0u8; 80];
            d[..16].copy_from_slice(&m);
            if let Some(s1) = sha1 {
                d[16..36].copy_from_slice(&s1);
            }
            let c = adler32(&d[..76]);
            d[76..80].copy_from_slice(&c.to_le_bytes());
            w.section("digest", &d);
        }
        w.section("done", &[]);
        w.finish()
    }

    fn digest_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn ewf_verify_ok() {
        // Sector-granular media (EWF logical size is a whole number of
        // 512-byte sectors — the acquisition hash covers that padding).
        let media: Vec<u8> = (0..(2 * E01_CHUNK + 3 * 512) as u32)
            .map(|i| (i * 31 % 256) as u8)
            .collect();
        let (d, _) = hash_reader(Cursor::new(&media)).unwrap();
        let md5: [u8; 16] = digest_bytes(&d.md5).try_into().unwrap();
        let sha1: [u8; 20] = digest_bytes(&d.sha1).try_into().unwrap();
        let img = build_e01(&media, Some(md5), Some(sha1));

        let ewf = EwfSource::open(vec![into_arc(img)]).unwrap();
        match verify_ewf(&ewf).unwrap() {
            AcqVerification::Verified { computed } => {
                assert_eq!(computed.md5, d.md5);
                assert_eq!(computed.sha1, d.sha1);
                assert_eq!(computed.sha256, d.sha256);
                assert_eq!(computed.bytes_hashed, media.len() as u64);
            }
            other => panic!("expected Verified, got {other:?}"),
        }
        // same through the Arc<dyn ByteSource> entry point
        let img = build_e01(&media, Some(md5), Some(sha1));
        assert!(verify_source(into_arc(img)).unwrap().is_verified());
    }

    #[test]
    fn ewf_verify_mismatch() {
        let media = vec![0xAAu8; E01_CHUNK + 512];
        let bad_md5 = [0xDEu8; 16];
        let img = build_e01(&media, Some(bad_md5), None);
        match verify_source(into_arc(img)).unwrap() {
            AcqVerification::Mismatch {
                computed,
                mismatches,
            } => {
                assert_eq!(mismatches.len(), 1);
                assert_eq!(mismatches[0].algorithm, "md5");
                assert_eq!(mismatches[0].stored, "dededededededededededededededede");
                assert_eq!(mismatches[0].computed, computed.md5);
                assert_eq!(computed.bytes_hashed, media.len() as u64);
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn ewf_verify_sha1_mismatch() {
        // Correct MD5 but a bogus stored SHA-1 → single "sha1" mismatch.
        let media = vec![5u8; E01_CHUNK];
        let (d, _) = hash_reader(Cursor::new(&media)).unwrap();
        let md5: [u8; 16] = digest_bytes(&d.md5).try_into().unwrap();
        let img = build_e01(&media, Some(md5), Some([0xAB; 20]));
        match verify_source(into_arc(img)).unwrap() {
            AcqVerification::Mismatch { mismatches, .. } => {
                assert_eq!(mismatches.len(), 1);
                assert_eq!(mismatches[0].algorithm, "sha1");
                assert_eq!(mismatches[0].computed, d.sha1);
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_acquisition_on_disk_file() {
        // The path-based wrapper: write a tiny E01 to a temp file.
        let media = vec![42u8; 512 * 3];
        let (d, _) = hash_reader(Cursor::new(&media)).unwrap();
        let md5: [u8; 16] = digest_bytes(&d.md5).try_into().unwrap();
        let img = build_e01(&media, Some(md5), None);
        let mut p = std::env::temp_dir();
        p.push(format!("sutram_analyze_verify_{}.E01", std::process::id()));
        std::fs::write(&p, &img).unwrap();
        let v = verify_acquisition(&p).unwrap();
        assert!(v.is_verified(), "{v:?}");
        std::fs::remove_file(&p).ok();
        // Missing file → Io error, not a panic.
        p.set_file_name("sutram_analyze_verify_missing.E01");
        assert!(matches!(
            verify_acquisition(&p),
            Err(FsError::Io(_))
        ));
        // A raw (non-EWF) file → NotAvailable.
        let media2 = vec![0u8; 512];
        let mut p2 = std::env::temp_dir();
        p2.push(format!("sutram_analyze_raw_{}.dd", std::process::id()));
        std::fs::write(&p2, &media2).unwrap();
        match verify_acquisition(&p2).unwrap() {
            AcqVerification::NotAvailable { reason } => {
                assert!(reason.contains("not an EWF"), "{reason}");
            }
            other => panic!("expected NotAvailable, got {other:?}"),
        }
        std::fs::remove_file(&p2).ok();
    }

    #[test]
    fn ewf_verify_not_available() {
        // EWF image without any hash/digest section.
        let media = vec![7u8; 1000];
        let img = build_e01(&media, None, None);
        match verify_source(into_arc(img)).unwrap() {
            AcqVerification::NotAvailable { reason } => {
                assert!(reason.contains("no acquisition hash"), "{reason}");
            }
            other => panic!("expected NotAvailable, got {other:?}"),
        }
        // Non-EWF input entirely.
        match verify_source(into_arc(vec![0u8; 512])).unwrap() {
            AcqVerification::NotAvailable { reason } => {
                assert!(reason.contains("not an EWF"), "{reason}");
            }
            other => panic!("expected NotAvailable, got {other:?}"),
        }
    }
}
