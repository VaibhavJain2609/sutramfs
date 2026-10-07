//! Error type for the I/O layer.
//!
//! Parser crates translate these into their own `FsError` taxonomy; keeping a
//! distinct type here preserves *where* a failure happened (which container
//! layer) before it is wrapped.

use std::fmt;
use std::io;

/// Result alias used throughout `sutram-io`.
pub type Result<T> = std::result::Result<T, Error>;

/// Failures that can occur while reading a [`crate::ByteSource`] or parsing a
/// container structure (partition table, sparse image).
#[derive(Debug)]
pub enum Error {
    /// Underlying I/O failure from the source.
    Io(io::Error),
    /// A structure was well-located but its contents are malformed.
    ///
    /// `offset` is the absolute byte offset of the offending field so callers
    /// can preserve provenance.
    Corrupt { offset: u64, msg: String },
    /// The container/encoding is recognised but not (yet) readable by this
    /// crate — e.g. EWF segments, encrypted volumes.
    Unsupported { msg: String },
    /// A read ran past the end of the source.
    Truncated {
        offset: u64,
        requested: u64,
        available: u64,
    },
}

impl Error {
    /// Convenience constructor for [`Error::Corrupt`].
    pub fn corrupt(offset: u64, msg: impl Into<String>) -> Self {
        Error::Corrupt {
            offset,
            msg: msg.into(),
        }
    }

    /// Convenience constructor for [`Error::Unsupported`].
    pub fn unsupported(msg: impl Into<String>) -> Self {
        Error::Unsupported { msg: msg.into() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o error: {e}"),
            Error::Corrupt { offset, msg } => {
                write!(f, "corrupt structure at offset {offset:#x}: {msg}")
            }
            Error::Unsupported { msg } => write!(f, "unsupported: {msg}"),
            Error::Truncated {
                offset,
                requested,
                available,
            } => write!(
                f,
                "truncated source: wanted {requested} bytes at {offset:#x}, \
                 {available} available"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
