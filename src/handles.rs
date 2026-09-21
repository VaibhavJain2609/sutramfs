//! Mount-handle table with sliding-TTL eviction.
//!
//! A successful `Mount` RPC produces an opaque id; the [`Mount`] it points
//! at owns the `Box<dyn FileSystem>`, the evidence/job correlation ids from
//! the request metadata, and bookkeeping for eviction. Every `get` slides
//! the expiry forward (a mounted image stays alive while it is being
//! examined); `sweep` drops whatever has gone quiet for longer than the
//! TTL.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use sutram_fs::FileSystem;

/// Default mount TTL: 30 minutes idle.
pub const DEFAULT_TTL: Duration = Duration::from_secs(30 * 60);

/// One mounted image.
pub struct Mount {
    /// The mounted filesystem — read-only forensic session.
    pub fs: Box<dyn FileSystem>,
    /// Name of the parser that owns this mount (`"fat"`, `"ntfs"`, …).
    pub parser: &'static str,
    /// `FsInfo::fs_type` captured at mount (`"FAT32"`, …).
    pub fs_type: String,
    /// Human-readable source description (path or `inline(N bytes)`).
    pub image_desc: String,
    /// `x-evidence-id` request metadata, when supplied.
    pub evidence_id: Option<String>,
    /// `x-job-id` request metadata, when supplied.
    pub job_id: Option<String>,
    /// Idle lifetime before eviction.
    pub ttl: Duration,
    created: Instant,
    created_wall: SystemTime,
    last_used: Mutex<Instant>,
}

impl Mount {
    /// Record activity — slides the TTL window forward.
    pub fn touch(&self) {
        if let Ok(mut t) = self.last_used.lock() {
            *t = Instant::now();
        }
    }

    /// `true` once the handle has been idle for `ttl`.
    pub fn expired(&self) -> bool {
        let last = self.last_used.lock().map(|t| *t).unwrap_or(self.created);
        last.elapsed() >= self.ttl
    }

    /// Unix seconds at which the handle currently expires (sliding).
    pub fn expires_at_unix(&self) -> u64 {
        let last = self.last_used.lock().map(|t| *t).unwrap_or(self.created);
        let idle_base = last.saturating_duration_since(self.created);
        self.created_wall
            .checked_add(idle_base + self.ttl)
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Evidence-correlation map echoed into RPC responses.
    pub fn meta(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        if let Some(v) = &self.evidence_id {
            m.insert("evidence_id".into(), v.clone());
        }
        if let Some(v) = &self.job_id {
            m.insert("job_id".into(), v.clone());
        }
        m
    }
}

/// Opaque-id → [`Mount`] map with sliding-TTL eviction.
///
/// `get` returns `None` for unknown *and* expired ids — from the client's
/// perspective an expired handle simply does not exist.
pub struct HandleTable {
    inner: Mutex<HashMap<String, Arc<Mount>>>,
    ttl: Duration,
    next: AtomicU64,
}

impl HandleTable {
    /// New table; mounts idle longer than `ttl` are evicted by [`sweep`].
    ///
    /// [`sweep`]: HandleTable::sweep
    pub fn new(ttl: Duration) -> Self {
        HandleTable {
            inner: Mutex::new(HashMap::new()),
            ttl,
            next: AtomicU64::new(1),
        }
    }

    /// The table's TTL — applied to mounts that don't override it.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Insert a mount (its `ttl` is forced to the table's); returns the id.
    ///
    /// Ids are opaque but unique per process lifetime:
    /// `mh-<counter>-<mount-time-nanos>`.
    pub fn insert(&self, mut m: Mount) -> String {
        m.ttl = self.ttl;
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        let nanos = m
            .created_wall
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let id = format!("mh-{n:08x}-{nanos:016x}");
        if let Ok(mut t) = self.inner.lock() {
            t.insert(id.clone(), Arc::new(m));
        }
        id
    }

    /// Look a live handle up; `None` for unknown or expired ids.
    /// A hit slides the TTL forward.
    pub fn get(&self, id: &str) -> Option<Arc<Mount>> {
        let m = self.inner.lock().ok()?.get(id).cloned()?;
        if m.expired() {
            // Leave removal to the sweeper; just refuse the lookup.
            return None;
        }
        m.touch();
        Some(m)
    }

    /// Drop a handle (Unmount RPC). `Some` when it existed.
    pub fn remove(&self, id: &str) -> Option<Arc<Mount>> {
        self.inner.lock().ok()?.remove(id)
    }

    /// Evict every expired mount; returns how many were dropped.
    pub fn sweep(&self) -> usize {
        let mut t = match self.inner.lock() {
            Ok(t) => t,
            Err(_) => return 0,
        };
        let before = t.len();
        t.retain(|_, m| !m.expired());
        before - t.len()
    }

    /// Live (possibly expired-but-unswept) handle count — for tests/ops.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|t| t.len()).unwrap_or(0)
    }

    /// `true` when the table holds no handles.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot of handle ids — diagnostics only.
    pub fn ids(&self) -> Vec<String> {
        self.inner
            .lock()
            .map(|t| t.keys().cloned().collect())
            .unwrap_or_default()
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new(DEFAULT_TTL)
    }
}

/// Construct a [`Mount`] bookkeeping record. Separate from `insert` so the
/// service can build the reply (`expires_at`, meta) before handing over
/// ownership.
pub fn new_mount(
    fs: Box<dyn FileSystem>,
    parser: &'static str,
    image_desc: String,
    evidence_id: Option<String>,
    job_id: Option<String>,
) -> Mount {
    let fs_type = fs.info().fs_type.clone();
    Mount {
        fs,
        parser,
        fs_type,
        image_desc,
        evidence_id,
        job_id,
        ttl: DEFAULT_TTL,
        created: Instant::now(),
        created_wall: SystemTime::now(),
        last_used: Mutex::new(Instant::now()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc as StdArc;
    use sutram_fs::{FsInfo, FsEntry, Result as FsResult};

    /// Minimal FileSystem stub for handle-lifecycle tests.
    struct StubFs;
    impl FileSystem for StubFs {
        fn info(&self) -> FsInfo {
            FsInfo {
                fs_type: "STUB".into(),
                ..Default::default()
            }
        }
        fn source(&self) -> StdArc<dyn sutram_io::ByteSource> {
            StdArc::new(Vec::<u8>::new())
        }
        fn walk(&self) -> Box<dyn Iterator<Item = FsResult<FsEntry>> + Send + '_> {
            Box::new(std::iter::empty())
        }
        fn read_file(&self, _e: &FsEntry) -> FsResult<Box<dyn std::io::Read + Send>> {
            Ok(Box::new(std::io::Cursor::new(Vec::<u8>::new())))
        }
    }

    fn stub_mount() -> Mount {
        new_mount(Box::new(StubFs), "stub", "test".into(), None, None)
    }

    #[test]
    fn insert_get_remove_cycle() {
        let t = HandleTable::new(Duration::from_secs(60));
        let id = t.insert(stub_mount());
        assert!(id.starts_with("mh-"));
        let m = t.get(&id).expect("handle must be live");
        assert_eq!(m.parser, "stub");
        assert_eq!(m.fs_type, "STUB");
        assert!(t.remove(&id).is_some());
        assert!(t.get(&id).is_none(), "removed handle must not resolve");
        assert!(t.is_empty());
    }

    #[test]
    fn expired_handle_refuses_get_and_sweeps() {
        let t = HandleTable::new(Duration::from_millis(1));
        let id = t.insert(stub_mount());
        std::thread::sleep(Duration::from_millis(5));
        assert!(t.get(&id).is_none(), "expired handle must not resolve");
        assert_eq!(t.len(), 1, "expired-but-unswept still occupies the table");
        assert_eq!(t.sweep(), 1);
        assert!(t.is_empty());
    }

    #[test]
    fn get_slides_ttl() {
        let t = HandleTable::new(Duration::from_millis(60));
        let id = t.insert(stub_mount());
        for _ in 0..5 {
            std::thread::sleep(Duration::from_millis(20));
            assert!(t.get(&id).is_some(), "active handle must stay live");
        }
        // Total elapsed (~100ms) exceeds ttl; each get slid the window.
        assert!(t.get(&id).is_some());
    }

    #[test]
    fn meta_carries_evidence_ids() {
        let mut m = stub_mount();
        m.evidence_id = Some("EV-42".into());
        m.job_id = Some("JOB-7".into());
        let meta = m.meta();
        assert_eq!(meta.get("evidence_id").unwrap(), "EV-42");
        assert_eq!(meta.get("job_id").unwrap(), "JOB-7");
        assert!(m.expires_at_unix() > 0);
    }
}
