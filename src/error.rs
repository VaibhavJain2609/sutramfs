//! Error taxonomy for `sutram-reputation`.
//!
//! Per CONVENTIONS.md error taxonomy: malformed upstream data →
//! [`RepError::Parse`]; source IO → [`RepError::Io`]; recognised but
//! unsupported (offline, uploads disabled, no sandbox) →
//! [`RepError::Unsupported`]; bad caller argument →
//! [`RepError::InvalidInput`]. Transport failures get their own variants
//! because HTTP status is forensically meaningful (404 = "not in corpus",
//! 429 = "rate limited").

use std::fmt;

/// Errors surfaced by reputation transports, caches, and providers.
#[derive(Debug)]
pub enum RepError {
    /// The HTTP request never produced a usable response (DNS, TLS,
    /// timeout, connection reset, …).
    Transport(String),
    /// The server answered with a non-success status. `body` is the
    /// bounded response excerpt (≤ 2 KiB stored).
    Http {
        /// HTTP status code.
        status: u16,
        /// Truncated response body for the record.
        body: String,
    },
    /// Response or import payload could not be parsed.
    Parse(String),
    /// Filesystem IO (cache file, import/export path).
    Io(std::io::Error),
    /// Recognised but disabled/unavailable operation: querying without a
    /// transport, uploading without `allow_uploads`, sandbox without a
    /// provider, …
    Unsupported(String),
    /// Bad caller argument (e.g. non-hex hash).
    InvalidInput(String),
}

impl fmt::Display for RepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RepError::Transport(m) => write!(f, "transport error: {m}"),
            RepError::Http { status, body } => {
                write!(f, "HTTP {status}: {}", crate::util::truncate(body, 120))
            }
            RepError::Parse(m) => write!(f, "parse error: {m}"),
            RepError::Io(e) => write!(f, "io error: {e}"),
            RepError::Unsupported(m) => write!(f, "unsupported: {m}"),
            RepError::InvalidInput(m) => write!(f, "invalid input: {m}"),
        }
    }
}

impl std::error::Error for RepError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RepError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RepError {
    fn from(e: std::io::Error) -> Self {
        RepError::Io(e)
    }
}
