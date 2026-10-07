//! HTTP transport abstraction.
//!
//! The reputation core is **HTTP-free**: [`ReputationService`] talks to a
//! [`HttpTransport`] trait object, so the air-gapped default build has no
//! sockets, no TLS, no C code. Tests inject a mock; a connected deployment
//! enables feature `net` for [`UreqTransport`], or supplies its own
//! implementation (e.g. a corporate proxy client).

use crate::error::RepError;

/// HTTP verb the transport must perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// GET — used for `files/{hash}` lookups (the only default path).
    Get,
    /// POST — used ONLY by the explicit opt-in `submit_file` upload API.
    Post,
}

/// A bounded HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Status code.
    pub status: u16,
    /// Body as text (VT is JSON). Transports should bound this; we clamp
    /// to 4 MiB on receipt regardless.
    pub body: String,
}

/// Pluggable HTTP transport. Implementations must be thread-safe:
/// `lookup_many` issues requests from worker threads.
pub trait HttpTransport: Send + Sync {
    /// Perform one request. `body` is present only for `Post`.
    ///
    /// Implementations should apply a sane timeout and return
    /// [`RepError::Transport`] on connection-level failures rather than
    /// panicking.
    fn request(
        &self,
        method: HttpMethod,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, RepError>;

    /// Implementation name for logs/reports (`"ureq"`, `"mock"`, …).
    fn name(&self) -> &'static str;
}

/// Blocking transport backed by [`ureq`] — enabled by feature `net`.
///
/// **Dependency note:** `ureq`+rustls transitively compiles `ring`
/// (asm/C). Per CONVENTIONS.md this is a deliberate, feature-gated
/// exception: the default build never includes it, and the forensic
/// platform ships air-gapped.
#[cfg(feature = "net")]
pub struct UreqTransport {
    agent: ureq::Agent,
}

#[cfg(feature = "net")]
impl UreqTransport {
    /// New transport with a 30 s global timeout.
    pub fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .build();
        UreqTransport {
            agent: ureq::Agent::new_with_config(config),
        }
    }
}

#[cfg(feature = "net")]
impl Default for UreqTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "net")]
impl HttpTransport for UreqTransport {
    fn request(
        &self,
        method: HttpMethod,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, RepError> {
        // ureq's typed builders differ per method: GET yields
        // `RequestBuilder<WithoutBody>` (`.call()`), POST yields
        // `RequestBuilder<WithBody>` (`.send(body)`).
        let mut resp = match method {
            HttpMethod::Get => {
                let mut req = self.agent.get(url);
                for (k, v) in headers {
                    req = req.header(*k, *v);
                }
                req.call().map_err(transport_err)?
            }
            HttpMethod::Post => {
                let mut req = self.agent.post(url);
                for (k, v) in headers {
                    req = req.header(*k, *v);
                }
                match body {
                    Some(b) => req.send(b).map_err(transport_err)?,
                    None => req.send_empty().map_err(transport_err)?,
                }
            }
        };
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| RepError::Transport(format!("reading body: {e}")))?;
        Ok(HttpResponse { status, body })
    }

    fn name(&self) -> &'static str {
        "ureq"
    }
}

#[cfg(feature = "net")]
fn transport_err(e: ureq::Error) -> RepError {
    match e {
        ureq::Error::StatusCode(code) => RepError::Http {
            status: code,
            body: String::new(),
        },
        other => RepError::Transport(other.to_string()),
    }
}
