//! Reputation caches.
//!
//! Two layers, both keyed by the lowercased hash and carrying a
//! wall-clock `fetched` timestamp so TTL decisions survive restarts:
//!
//! * [`MemCache`] — always on, `HashMap` inside the service.
//! * [`SqliteCache`] — feature `cache`, survives process restarts.
//!
//! Negative results ("hash not in corpus", VT 404) are cached too — as a
//! marker row — so re-walking an image doesn't burn quota on the same
//! unknown hashes. A cached negative is still a cache *hit*; the verdict
//! it yields is `Unknown`.

use std::collections::HashMap;
#[cfg(feature = "cache")]
use std::sync::{Mutex, MutexGuard};

use crate::report::VtResult;
#[cfg(feature = "cache")]
use crate::util::unix_now;

/// One cached outcome for a hash.
#[derive(Debug, Clone)]
pub(crate) enum Cached {
    /// VT returned a file record.
    Found(Box<VtResult>),
    /// VT 404 — known-looked-up, not in corpus. `fetched` is the unix time.
    NotFound,
}

/// In-memory cache: `hash -> (fetched_unix, Cached)`.
#[derive(Debug, Default)]
pub(crate) struct MemCache {
    map: HashMap<String, (i64, Cached)>,
}

impl MemCache {
    /// Get a non-expired entry.
    pub(crate) fn get(&self, hash: &str, ttl_secs: i64, now: i64) -> Option<&Cached> {
        self.map.get(hash).and_then(|(fetched, c)| {
            if now - fetched <= ttl_secs {
                Some(c)
            } else {
                None
            }
        })
    }

    /// Store/replace an entry, timestamped `now`.
    pub(crate) fn put(&mut self, hash: &str, entry: Cached, now: i64) {
        self.map.insert(hash.to_string(), (now, entry));
    }

    /// Entries older than the TTL are considered misses but kept; this
    /// drops them outright (call between case runs).
    pub(crate) fn evict_expired(&mut self, ttl_secs: i64, now: i64) {
        self.map
            .retain(|_, (fetched, _)| now - *fetched <= ttl_secs);
    }
}

/// Persistent cache backed by SQLite — feature `cache` only.
///
/// **Dependency note:** `rusqlite` with `bundled` compiles the SQLite C
/// amalgamation — a documented, feature-gated exception to the project's
/// pure-Rust rule. Schema is a single table; the JSON column is the
/// serialised [`VtResult`].
///
/// ```text
/// CREATE TABLE rep_cache (
///     sha256  TEXT PRIMARY KEY,
///     fetched INTEGER NOT NULL,   -- unix seconds
///     found   INTEGER NOT NULL,   -- 1 = record, 0 = known-404
///     json    TEXT                -- VtResult JSON when found=1
/// );
/// ```
#[cfg(feature = "cache")]
pub struct SqliteCache {
    conn: Mutex<rusqlite::Connection>,
}

#[cfg(feature = "cache")]
impl SqliteCache {
    /// Open (creating) a cache database at `path`.
    pub fn open(path: &std::path::Path) -> Result<Self, crate::RepError> {
        let conn = rusqlite::Connection::open(path).map_err(sqlite_err)?;
        let c = SqliteCache {
            conn: Mutex::new(conn),
        };
        c.init()?;
        Ok(c)
    }

    /// In-memory database — same schema, no persistence (tests, tmp work).
    pub fn in_memory() -> Result<Self, crate::RepError> {
        let conn = rusqlite::Connection::open_in_memory().map_err(sqlite_err)?;
        let c = SqliteCache {
            conn: Mutex::new(conn),
        };
        c.init()?;
        Ok(c)
    }

    fn init(&self) -> Result<(), crate::RepError> {
        self.lock()
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS rep_cache (
                    sha256  TEXT PRIMARY KEY,
                    fetched INTEGER NOT NULL,
                    found   INTEGER NOT NULL,
                    json    TEXT
                );",
            )
            .map_err(sqlite_err)
    }

    fn lock(&self) -> MutexGuard<'_, rusqlite::Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Fetch a cached entry; `min_fetched` implements the TTL
    /// (`unix_now() - ttl_secs`).
    pub(crate) fn get(&self, hash: &str, min_fetched: i64) -> Option<Cached> {
        let conn = self.lock();
        let row = conn
            .query_row(
                "SELECT found, json FROM rep_cache WHERE sha256 = ?1 AND fetched >= ?2",
                rusqlite::params![hash, min_fetched],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?)),
            )
            .ok()?;
        match row {
            (1, Some(json)) => serde_json::from_str::<VtResult>(&json)
                .ok()
                .map(|v| Cached::Found(Box::new(v))),
            (1, None) => None, // corrupt row — treat as miss
            _ => Some(Cached::NotFound),
        }
    }

    /// Store a lookup outcome, timestamped now.
    pub(crate) fn put(&self, hash: &str, entry: &Cached) -> Result<(), crate::RepError> {
        let (found, json) = match entry {
            Cached::Found(v) => (
                1i64,
                Some(serde_json::to_string(v.as_ref()).map_err(|e| {
                    crate::RepError::Parse(format!("serialising cache entry: {e}"))
                })?),
            ),
            Cached::NotFound => (0i64, None),
        };
        self.lock()
            .execute(
                "INSERT OR REPLACE INTO rep_cache (sha256, fetched, found, json)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![hash, unix_now(), found, json],
            )
            .map_err(sqlite_err)?;
        Ok(())
    }
}

#[cfg(feature = "cache")]
fn sqlite_err(e: rusqlite::Error) -> crate::RepError {
    crate::RepError::Io(std::io::Error::new(
        std::io::ErrorKind::Other,
        e.to_string(),
    ))
}
