//! # sutram-part
//!
//! Android partition-layer parser for the SUTRAM-FS family — the layer that
//! turns a seized device image (or a single `*.img` from a factory package)
//! into mountable [`sutram_io::ByteSource`] views that `sutram-f2fs`,
//! `sutram-ext4`, … can run on.
//!
//! Layers handled:
//!
//! * **Android sparse images** (`simg`, magic `0xED26FF3A`) — detected here,
//!   decoded by [`sutram_io::SparseFile::from_android_sparse`]; chunk-table
//!   validation and size cross-checks added on top ([`sparse`]).
//! * **`super` / dynamic partitions** — the `liblp` metadata (geometry +
//!   versioned header + partition/extent/group/block-device tables) is
//!   decoded from its slot area, checksums *verified* (mismatch = warning,
//!   never fatal — tamper is a finding), and each logical partition is
//!   exposed as an extent-mapped [`NamedSource`] ([`lp`],
//!   [`logical_partitions`]).
//! * **AVB vbmeta** — header/footer/descriptor parse reporting algorithm,
//!   rollback index and the dm-verity disabling flags ([`vbmeta`]).
//! * **GPT with Android naming** — physical tables come from `sutram-io`;
//!   this crate adds the `boot`/`vendor`/`userdata`/`super`/`metadata`/
//!   `persist`… role heuristics and `_a`/`_b` slot-suffix handling
//!   ([`names`], [`classify_name`]).
//! * **Encryption flags** — `crypt_ftr` footers and the `metadata` partition
//!   are *flagged* (never decrypted) so ciphertext is never walked as a
//!   filesystem ([`fbe`]).
//!
//! The single-call entry point is [`analyze`]:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use sutram_io::{ByteSource, FileSource};
//!
//! let src = Arc::new(FileSource::open("super.img")?) as Arc<dyn ByteSource>;
//! let layout = sutram_part::analyze(src)?;
//! println!("{:?}", layout.container);
//! for p in &layout.partitions {
//!     println!("{}  group={}  {:#x} B", p.name, p.group, p.source.len());
//! }
//! for w in &layout.warnings { eprintln!("note: {w}"); }
//! # Ok::<(), sutram_fs::FsError>(())
//! ```

#![forbid(unsafe_code)]

/// SHA-256 used for `liblp` checksum verification — exposed (hidden) so the
/// synthetic-image builders in `tests/common` can emit *valid* checksums.
#[doc(hidden)]
pub mod sha256;

pub mod fbe;
pub mod lp;
pub mod names;
pub mod sparse;
pub mod vbmeta;

mod layout;

/// Result alias for this crate — the project-wide [`FsError`] taxonomy.
pub type Result<T> = std::result::Result<T, FsError>;

pub use sutram_fs::FsError;

pub use fbe::{CryptFooter, CryptoKind};
pub use layout::{analyze, AndroidLayout, Attrs, ContainerKind, CryptoFinding, NamedSource};
pub use lp::{
    logical_partitions, logical_partitions_verbose, read_geometry, read_metadata, LpBlockDevice,
    LpExtent, LpGeometry, LpGroup, LpHeader, LpMetadata, LpPartition,
};
pub use names::{classify_name, has_slot_suffix, notable_flag, split_slot_suffix, PartitionRole};
pub use sparse::{inspect_sparse, is_android_sparse, open_sparse, read_header, SparseHeader};
pub use vbmeta::{
    find_vbmeta, parse as parse_vbmeta, parse_at as parse_vbmeta_at,
    parse_footer as parse_vbmeta_footer, DmVerityState, VbmetaDescriptor, VbmetaFooter, VbmetaInfo,
};

#[cfg(test)]
mod tests;
