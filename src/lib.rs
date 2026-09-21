//! # sutram-capi
//!
//! C FFI (`cdylib`) and Python bindings for the SUTRAM-FS forensic
//! filesystem parser family.
//!
//! * `include/sutram.h` documents the exported C surface
//!   (`sutram_open_image`, `sutram_detect`, `sutram_list_entries`,
//!   `sutram_list_jsonl`, `sutram_read_file`, `sutram_free_*`).
//! * `core` holds all logic in safe Rust; `ffi` is the only module
//!   containing `unsafe` — the boundary itself.
//! * The `python` cargo feature (off by default) adds a `sutramfs` PyO3
//!   module; it needs a Python toolchain at build time
//!   (`PYO3_PYTHON=/path/to/python`).

pub mod core;
pub mod ffi;
pub mod json;

#[cfg(feature = "python")]
mod python;
