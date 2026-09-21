//! # sutram-magic
//!
//! File-signature ("magic bytes") detection and **masquerade checking** for
//! the SUTRAM-FS forensic parser family.
//!
//! Two entry points:
//!
//! * [`detect`] / [`detect_all`] — identify a buffer's type from its first
//!   bytes (with optional trailer verification via [`has_trailer`]).
//! * [`check_entry`] — compare a *filename's declared type* (extension)
//!   against the *detected type* of its content, producing a
//!   [`MagicVerdict`] with a severity and human-readable reasons — e.g. a
//!   `resume.docx` whose header is `MZ` (a Windows executable) is a
//!   high-severity masquerade flag, while a `.docx` that is really a ZIP is
//!   expected (OOXML *is* a ZIP container) and not a mismatch.
//!
//! The database is a compile-time `const` table ([`SIGNATURES`]) — no
//! network, no `unsafe`, no allocation during detection. Extend it by adding
//! rows; the tests enforce a minimum coverage floor.
//!
//! ## Notes for callers
//!
//! * Pass as many leading bytes as practical — most signatures live at
//!   offset 0, but filesystem signatures sit deep (ext at `0x438`, btrfs at
//!   `0x10040`, ISO9660 at `0x8001`). For per-file checks 4 KiB is plenty.
//! * Detection is header-first; files with no recognised signature produce
//!   `None`, which [`check_entry`] reports as an `Info`-level verdict — never
//!   silently "clean".

#![forbid(unsafe_code)]

mod table;
mod types;
mod verdict;

pub use table::{Signature, EXT_TO_TYPE, SIGNATURES, TRAILERS};
pub use types::{Category, MagicType};
pub use verdict::{
    check_entry, check_entry_sized, detect, detect_all, has_trailer, MagicVerdict, Severity,
};

#[cfg(test)]
mod tests;
