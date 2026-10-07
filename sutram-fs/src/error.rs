//! The [`FsError`] taxonomy — every failure is a value, never a panic.

use std::fmt;
use std::io;

/// Result alias for filesystem operations.
pub type Result<T> = std::result::Result<T, FsError>;

/// Everything that can go wrong parsing or walking a filesystem.
///
/// `Corrupt`, `Truncated` and `Io` carry byte offsets wherever possible so
/// error records preserve provenance — an examiner can always ask "which
/// bytes produced this failure?".
#[derive(Debug)]
pub enum FsError {
    /// A structure is malformed. `offset` is where the offending bytes live.
    Corrupt {
        /// Absolute byte offset of the corrupt field/record.
        offset: u64,
        /// What was expected vs found.
        msg: String,
    },
    /// The image ended before a structure did.
    Truncated {
        /// Where the read started.
        offset: u64,
        /// How many bytes the structure needed.
        needed: u64,
        /// How many bytes remained in the source.
        available: u64,
    },
    /// The format/feature is recognised but not supported by this parser
    /// (e.g. an unsupported version, compression, encryption).
    Unsupported {
        /// What is unsupported.
        msg: String,
    },
    /// Underlying I/O failure from the [`sutram_io::ByteSource`].
    Io(io::Error),
    /// A path/entry lookup found nothing.
    NotFound {
        /// What was looked up.
        path: String,
    },
    /// Caller handed us something invalid (not a corrupt *image*).
    InvalidInput {
        /// What was wrong.
        msg: String,
    },
}

impl FsError {
    /// Convenience constructor for [`FsError::Corrupt`].
    pub fn corrupt(offset: u64, msg: impl Into<String>) -> Self {
        FsError::Corrupt {
            offset,
            msg: msg.into(),
        }
    }

    /// Convenience constructor for [`FsError::Unsupported`].
    pub fn unsupported(msg: impl Into<String>) -> Self {
        FsError::Unsupported { msg: msg.into() }
    }

    /// Convenience constructor for [`FsError::Truncated`].
    pub fn truncated(offset: u64, needed: u64, available: u64) -> Self {
        FsError::Truncated {
            offset,
            needed,
            available,
        }
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsError::Corrupt { offset, msg } => {
                write!(f, "corrupt structure at {offset:#x}: {msg}")
            }
            FsError::Truncated {
                offset,
                needed,
                available,
            } => write!(
                f,
                "truncated at {offset:#x}: needed {needed} bytes, {available} available"
            ),
            FsError::Unsupported { msg } => write!(f, "unsupported: {msg}"),
            FsError::Io(e) => write!(f, "i/o error: {e}"),
            FsError::NotFound { path } => write!(f, "not found: {path}"),
            FsError::InvalidInput { msg } => write!(f, "invalid input: {msg}"),
        }
    }
}

impl std::error::Error for FsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FsError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for FsError {
    fn from(e: io::Error) -> Self {
        FsError::Io(e)
    }
}

impl From<sutram_io::Error> for FsError {
    fn from(e: sutram_io::Error) -> Self {
        match e {
            sutram_io::Error::Io(e) => FsError::Io(e),
            sutram_io::Error::Corrupt { offset, msg } => FsError::Corrupt { offset, msg },
            sutram_io::Error::Unsupported { msg } => FsError::Unsupported { msg },
            sutram_io::Error::Truncated {
                offset,
                requested,
                available,
            } => FsError::Truncated {
                offset,
                needed: requested,
                available,
            },
        }
    }
}
