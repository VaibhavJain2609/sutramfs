//! # sutram-archive
//!
//! Forensic parsers for archive/container formats — **ZIP**, **TAR** and
//! **CPIO** — exposed through the SUTRAM-FS contract (`sutram-fs` traits
//! over `sutram-io` byte sources). An archive is treated as a filesystem:
//! members become [`FsEntry`] records, `walk()` streams them one at a
//! time, and `read_file()` returns each member's (decompressed) data.

#![forbid(unsafe_code)]

// Temporary until the parsers land (removed with the ZIP feature).
#[allow(dead_code)]
mod reader;
