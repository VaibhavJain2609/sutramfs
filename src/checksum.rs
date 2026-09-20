//! The Fletcher-64 checksum used by every APFS object (`obj_phys_t.o_cksum`).
//!
//! APFS's integrity model: every on-disk object is one or more blocks and the
//! first 8 bytes hold a Fletcher-64 checksum over the rest of the object. The
//! variant is the ZFS-style one described in the Apple File System Reference:
//!
//! 1. Treat `block[8..]` as little-endian `u32` words. Accumulate
//!    `sum1 = (sum1 + w) mod (2^32-1)`, `sum2 = (sum2 + sum1) mod (2^32-1)`.
//! 2. `c1 = (2^32-1) - ((sum1 + sum2) mod (2^32-1))`,
//!    `c2 = (2^32-1) - ((sum1 + c1)   mod (2^32-1))`.
//! 3. `o_cksum = (c2 << 32) | c1`.
//!
//! Verification runs the same accumulator over the payload *and* then the
//! stored checksum word pair: a valid object ends with both sums at zero.

const MOD: u64 = 0xFFFF_FFFF; // 2^32 - 1

/// Fletcher-64 accumulator over `data` (length must be a multiple of 4),
/// continuing from `(sum1, sum2)`.
fn accumulate(data: &[u8], mut sum1: u64, mut sum2: u64) -> (u64, u64) {
    for w in data.chunks_exact(4) {
        let word = u32::from_le_bytes([w[0], w[1], w[2], w[3]]) as u64;
        sum1 = (sum1 + word) % MOD;
        sum2 = (sum2 + sum1) % MOD;
    }
    (sum1, sum2)
}

/// Compute the checksum for an object whose payload is `payload`
/// (everything after the 8-byte `o_cksum` field). Returns the `u64` stored
/// little-endian at `block[0..8]`. Test-only: the parser only *verifies*.
#[cfg(test)]
pub(crate) fn fletcher64_payload(payload: &[u8]) -> u64 {
    let (sum1, sum2) = accumulate(payload, 0, 0);
    let c1 = MOD - ((sum1 + sum2) % MOD);
    let c2 = MOD - ((sum1 + c1) % MOD);
    (c2 << 32) | c1
}

/// Compute the checksum of a whole object block; `block[0..8]` is ignored.
#[cfg(test)]
pub(crate) fn fletcher64(block: &[u8]) -> u64 {
    if block.len() < 8 {
        return fletcher64_payload(&[]);
    }
    fletcher64_payload(&block[8..])
}

/// Verify the Fletcher-64 stored at `block[0..8]`.
///
/// `block` must be a multiple of 4 bytes and at least 8 bytes long. A stored
/// checksum of all-zero or all-ones is rejected outright (APFS treats those
/// as "not checksummed").
pub(crate) fn verify(block: &[u8]) -> bool {
    if block.len() < 8 || block.len() % 4 != 0 {
        return false;
    }
    let stored = u64::from_le_bytes(block[0..8].try_into().unwrap_or_default());
    if stored == 0 || stored == u64::MAX {
        return false;
    }
    let (sum1, sum2) = accumulate(&block[8..], 0, 0);
    let (sum1, sum2) = accumulate(&block[..8], sum1, sum2);
    sum1 == 0 && sum2 == 0
}
