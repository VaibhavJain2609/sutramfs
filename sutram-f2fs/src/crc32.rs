//! IEEE CRC-32 (reflected, poly `0xEDB88320`) as used by F2FS checksums.
//!
//! F2FS checksums (`f2fs_crc32`) are the kernel `crc32()` — zlib-convention
//! CRC-32 — seeded with the superblock magic (`0xF2F52010`). The `crc`
//! argument is the previously *returned* value, so calls chain: feeding the
//! result back in extends the stream. The trailing checksum word itself is
//! skipped via [`crc32_skip`] by resuming after the stored field.
//!
//! Bitwise implementation — the largest inputs here are a few KiB
//! (superblock/checkpoint/orphan blocks), so table-free is plenty.

/// Update a running CRC-32 (zlib convention: argument and result are the
/// post-inversion values, so `crc32(crc32(seed, a), b) == crc32(seed, a+b)`).
pub(crate) fn crc32(seed: u32, data: &[u8]) -> u32 {
    let mut c = !seed;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

/// F2FS checksum of `data`: CRC-32 seeded with the superblock magic.
pub(crate) fn f2fs_crc32(magic_seed: u32, data: &[u8]) -> u32 {
    crc32(magic_seed, data)
}
