//! Encryption footer detection — flag only, never decrypt.
//!
//! Two on-disk artefacts matter at the partition layer:
//!
//! * **Legacy `crypt_ftr` footer** — vold's FDE / "encryptable" userdata
//!   footer, magic `0xD0B5B1C4` (LE), stored in the last 16 KiB
//!   (`CRYPT_FOOTER_OFFSET`) of the userdata device. Its `flags`/
//!   `crypt_type`/`crypto_type_name` fields tell whether the partition is
//!   fully encrypted, in-progress, or default-key FBE.
//! * **FBE metadata encryption** (Android 9+): the wrapped key lives as
//!   KeyMint keyblobs *inside the `metadata` partition's filesystem* — a
//!   raw-format signature does not exist, so detection is structural: a
//!   `metadata`-named GPT partition plus `crypt_ftr` on userdata are the
//!   signals [`detect`](Self) reports.
//!
//! Decryption is deliberately out of scope — this layer flags encrypted
//! regions so downstream parsers don't walk ciphertext as a filesystem.

use sutram_io::le;
use sutram_io::ByteSource;

/// `crypt_ftr.magic` (CRYPT_MNT_MAGIC), little-endian u32.
pub const CRYPT_FTR_MAGIC: u32 = 0xD0B5_B1C4;
/// `CRYPT_FOOTER_OFFSET` — the footer lives this far from the device end.
pub const CRYPT_FOOTER_OFFSET: u64 = 0x4000;

/// `crypt_ftr.flags` bit: master key stored unencrypted.
pub const CRYPT_MNT_KEY_UNENCRYPTED: u32 = 0x1;
/// `crypt_ftr.flags` bit: in-place encryption still running.
pub const CRYPT_ENCRYPTION_IN_PROGRESS: u32 = 0x2;

/// What a detected crypto artefact implies about the partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoKind {
    /// `crypt_ftr` present — the userdata device is/was encrypted (FDE, or
    /// "encryptable" FBE in-place conversion bookkeeping; the footer alone
    /// cannot distinguish them).
    CryptFooter,
    /// Separate `metadata` partition present — the KeyMint keyblob file
    /// inside it implies FBE *metadata* encryption is configured.
    MetadataPartition,
}

impl CryptoKind {
    /// Short label.
    pub fn as_str(self) -> &'static str {
        match self {
            CryptoKind::CryptFooter => "crypt_footer",
            CryptoKind::MetadataPartition => "metadata_partition",
        }
    }
}

/// Parsed `crypt_ftr` fields (partial — forensic reporting only).
#[derive(Debug, Clone)]
pub struct CryptFooter {
    /// Absolute offset of the footer within the examined source.
    pub offset: u64,
    /// `major_version`.`minor_version`.
    pub version: (u16, u16),
    /// `ftr_size` — bytes the footer occupies.
    pub ftr_size: u32,
    /// `flags` — `CRYPT_MNT_*` / `CRYPT_ENCRYPTION_*`.
    pub flags: u32,
    /// `keysize` — master key length.
    pub keysize: u32,
    /// `crypt_type` — how the master key was encrypted
    /// (0 = password, 1 = default, 2 = pattern, 3 = pin).
    pub crypt_type: u32,
    /// `fs_size` — encrypted filesystem size in 512-byte sectors.
    pub fs_size: u64,
    /// `failed_decrypt_count`.
    pub failed_decrypt_count: u32,
    /// `crypto_type_name` — e.g. `aes-cbc-essiv:sha256`, `aes-256-xts`.
    pub crypto_type_name: String,
}

/// Look for a `crypt_ftr` at `len - 0x4000`. Returns `Ok(None)` when the
/// source is too small or the magic is absent — absence is normal on
/// non-encryptable devices.
pub fn find_crypt_footer(src: &dyn ByteSource) -> Option<CryptFooter> {
    let len = src.len();
    if len < CRYPT_FOOTER_OFFSET + 64 {
        return None;
    }
    let off = len - CRYPT_FOOTER_OFFSET;
    let buf = src.read_slice(off, 128).ok()?;
    if le::u32(&buf, 0) != Some(CRYPT_FTR_MAGIC) {
        return None;
    }
    Some(CryptFooter {
        offset: off,
        version: (le::u16(&buf, 4).unwrap_or(0), le::u16(&buf, 6).unwrap_or(0)),
        ftr_size: le::u32(&buf, 8).unwrap_or(0),
        flags: le::u32(&buf, 12).unwrap_or(0),
        keysize: le::u32(&buf, 16).unwrap_or(0),
        crypt_type: le::u32(&buf, 20).unwrap_or(0),
        fs_size: le::u64(&buf, 24).unwrap_or(0),
        failed_decrypt_count: le::u32(&buf, 32).unwrap_or(0),
        crypto_type_name: le::ascii(&buf, 36, 64).unwrap_or_default(),
    })
}
