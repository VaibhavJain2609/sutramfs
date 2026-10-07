//! # sutram-aff4
//!
//! Read-only **AFF4-L** (Advanced Forensic Format 4 — *Logical* profile)
//! evidence-container reader for the SUTRAM-FS family.
//!
//! An AFF4-L container is an ordinary **ZIP archive of stored
//! (uncompressed) members**. Alongside the evidence files it carries:
//!
//! * `information.turtle` — an RDF manifest recording, per member subject
//!   IRI (`aff4://<container-uuid>/<member-name>`), the content hashes the
//!   acquiring tool computed (`aff4:hash <aff4:sha256=…>`);
//! * `container.description` — the container ARN;
//! * `version.txt` — the AFF4 spec version.
//!
//! The ZIP layer is reused from [`sutram_archive::ZipParser`] — no zip
//! code lives here. Member records keep the absolute offset of the zip
//! record that produced them (provenance), the member's byte extents, and
//! every hash the manifest recorded. [`Aff4Container::verify`] recomputes
//! the digest over the member's bytes and compares — see [`Verification`].
//!
//! ## Honest limits
//!
//! * **AFF4-L only.** AFF4 image streams (`aff4:ImageStream` / map-based
//!   volume segments) and legacy AFF4 volumes are not decoded; only the
//!   logical profile's stored-member layout is.
//! * The manifest reader is a **purpose-built extractor**, not an RDF
//!   parser: it recovers subjects and their `hash` objects from Turtle
//!   statements. Blank-node collections, unusual datatypes and exotic
//!   syntax degrade to notes/warnings, never to panics.
//! * Only **SHA-256** hashes are recomputed today. Manifests that record
//!   `sha1`/`sha512`/`md5` only yield
//!   [`NotVerifiable::UnsupportedAlgorithm`].
//! * A missing or malformed manifest opens anyway (degraded mode):
//!   members list and extract; `verify` reports
//!   [`NotVerifiable::NoManifest`].
//!
//! ```rust,no_run
//! use sutram_aff4::{Aff4Container, Verification};
//!
//! let c = Aff4Container::open_path("case.aff4")?;
//! for m in c.evidence_members() {
//!     match c.verify(m)? {
//!         Verification::Verified { .. } => println!("{}: verified", m.name),
//!         v => println!("{}: {v:?}", m.name),
//!     }
//! }
//! # Ok::<(), sutram_fs::FsError>(())
//! ```

#![forbid(unsafe_code)]

mod container;
mod manifest;
mod sha256;
#[cfg(test)]
mod tests;

pub use container::{
    Aff4Container, Aff4Member, ManifestStatus, MemberRole, NotVerifiable, Verification,
};
pub use manifest::{HashAlgorithm, ManifestSubject, StoredHash};

// Re-exported so callers can name the error type without taking their own
// sutram-fs dependency pin.
pub use sutram_fs::{FsError, Result};

/// SHA-256 hex digest of `data`. Exposed (hidden) so the synthetic
/// AFF4-L builders in `tests/common` can embed real manifest digests;
/// not part of the stable API.
#[doc(hidden)]
pub fn sha256_hex(data: &[u8]) -> String {
    sha256::sha256_hex(data)
}
