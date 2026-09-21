//! Apple LZFSE — **deferred stub**.
//!
//! LZFSE (LZVN + tANS entropy coding, ~2 000 lines of finely-tuned
//! finite-state-entropy tables) backs decmpfs compression types 11
//! (inline) and 12 (resource fork) on recent macOS. A correct pure-Rust
//! port is feasible — Apple's reference implementation is BSD-licensed
//! and self-contained — but it is substantially more work than LZVN and
//! is deliberately not in this crate yet.
//!
//! The `lzfse` cargo feature exists as a stable opt-in point: enabling it
//! today changes nothing (the stub remains honest rather than half
//! decoding). When a decoder lands it will live behind this feature so
//! the dependency-free core stays lean.
//!
//! [`decompress`] always returns [`CompError::Unsupported`] — callers
//! should surface that to the user exactly as the parser would an
//! unsupported filesystem feature.

use crate::{CompError, Result};

/// Always returns [`CompError::Unsupported`] — LZFSE decoding is not
/// implemented in this release. Kept as a function (not a constant) so
/// the call sites compile identically before and after the codec lands.
pub fn decompress(_src: &[u8], _max_out: usize) -> Result<Vec<u8>> {
    Err(CompError::unsupported(
        "lzfse decoding not yet implemented (see sutram-compress README)",
    ))
}
