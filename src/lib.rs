//! # sutram-archive
//!
//! Forensic parsers for archive/container formats — **ZIP**, **TAR** and
//! **CPIO** — exposed through the SUTRAM-FS contract (`sutram-fs` traits
//! over `sutram-io` byte sources). An archive is treated as a filesystem:
//! members become [`FsEntry`] records, `walk()` streams them one at a
//! time, and `read_file()` returns each member's (decompressed) data.

#![forbid(unsafe_code)]

mod reader;
pub mod cpio;
pub mod tar;
pub mod zip;

pub use cpio::{CpioFs, CpioParser};
pub use tar::{TarFs, TarParser};
pub use zip::{ZipFs, ZipParser};
