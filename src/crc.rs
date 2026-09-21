//! CRC-32C (Castagnoli) for XFS v5 self-describing metadata.
//!
//! XFS v5 stamps every metadata object (superblock, AGF/AGI/AGFL, btree
//! blocks, dir/attr blocks, inodes, symlink blocks, remote attr blocks)
//! with a CRC32C.  The on-disk recipe, per `xfs_cksum.h`:
//!
//! 1. zero the 4-byte crc field,
//! 2. `crc = crc32c(seed = 0xFFFF_FFFF, object_bytes)`,
//! 3. store `!crc` at the field offset — **little-endian** for the
//!    superblock, inodes and btree blocks (`__le32` fields), but
//!    **big-endian** for AGF/AGI/AGFL sector headers and dir3/attr3/
//!    symlink block headers (`__be32` fields). Callers pick the
//!    byte order per object type.
//!
//! [`crc32c`] mirrors the Linux `crc32c(seed, buf)` contract: the seed is
//! the running CRC state verbatim — no implicit complement — and the
//! return value is the raw state (no final xor).  `verify()` therefore
//! compares `stored == !crc32c(!0, obj)` exactly as the kernel does.

/// Reflected CRC-32C polynomial.
const POLY: u32 = 0x82F6_3B78;

/// XFS CRC seed (`XFS_CRC_SEED`).
pub(crate) const CRC_SEED: u32 = !0;

/// Table generated at compile time — no unsafe, no runtime init.
const TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// Linux-style `crc32c(seed, buf)`: seed is the raw CRC state, result is
/// the raw final state (no xorout applied inside).
pub(crate) fn crc32c(seed: u32, buf: &[u8]) -> u32 {
    let mut crc = seed;
    for &b in buf {
        crc = TABLE[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

/// Compute the value that should sit in the crc field: CRC of `buf` with
/// the crc field (4 bytes at `crc_off`) treated as zero, complemented and
/// returned in host order (store/compare as little-endian on disk).
pub(crate) fn xfs_cksum(buf: &[u8], crc_off: usize) -> Option<u32> {
    if crc_off.checked_add(4)? > buf.len() {
        return None;
    }
    let mut crc = crc32c(CRC_SEED, &buf[..crc_off]);
    crc = crc32c(crc, &[0; 4]);
    crc = crc32c(crc, &buf[crc_off + 4..]);
    Some(!crc)
}

/// Verify an object's embedded crc field.
///
/// `stored_le` is the raw 4 on-disk bytes at `crc_off`. Returns `None`
/// when the buffer is too short to contain the field.
pub(crate) fn verify(buf: &[u8], crc_off: usize, stored_le: u32) -> Option<bool> {
    xfs_cksum(buf, crc_off).map(|c| c == stored_le)
}
