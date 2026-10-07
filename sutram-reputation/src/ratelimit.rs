//! Token-bucket rate limiter honouring VirusTotal's public-tier quota
//! (4 requests/minute by default).
//!
//! [`TokenBucket`] is the pure, clock-injected core — tests drive it with
//! synthetic `Instant`s. [`RateLimiter`] wraps it in a `Mutex` and blocks
//! the calling thread until a token is available; `lookup_many` workers
//! all funnel through one limiter, so parallelism never exceeds quota.

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Recover a poisoned lock: a panicking worker must not wedge the
/// limiter (and there is no parsed data inside to distrust).
fn lock(m: &Mutex<TokenBucket>) -> MutexGuard<'_, TokenBucket> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Token bucket with injectable clock (testable without sleeping).
///
/// * capacity = `requests_per_minute` (a fresh bucket allows a burst of
///   `rpm` requests),
/// * refill = `rpm` tokens per 60 s, continuous.
#[derive(Debug)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    /// A bucket allowing `requests_per_minute` tokens per minute, starting
    /// full. `rpm` of 0 disables the limiter (always ready).
    pub fn new(requests_per_minute: u32) -> Self {
        let rpm = requests_per_minute.max(1) as f64;
        TokenBucket {
            capacity: rpm,
            tokens: rpm,
            refill_per_sec: rpm / 60.0,
            last: Instant::now(),
        }
    }

    /// Unlimited bucket (private-tier keys, tests).
    pub fn unlimited() -> Self {
        TokenBucket {
            capacity: f64::INFINITY,
            tokens: f64::INFINITY,
            refill_per_sec: f64::INFINITY,
            last: Instant::now(),
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        self.last = now;
    }

    /// Tokens available right now (after refilling to `now`).
    pub fn available(&mut self, now: Instant) -> f64 {
        self.refill(now);
        self.tokens
    }

    /// Take one token if available at `now`.
    pub fn try_take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// How long until the next token is available, measured from `now`.
    /// `Duration::ZERO` when a token is ready now.
    pub fn time_until_ready(&self, now: Instant) -> Duration {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        let projected = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if projected >= 1.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64((1.0 - projected) / self.refill_per_sec)
        }
    }
}

/// Thread-safe blocking wrapper. One limiter per [`crate::ReputationService`].
#[derive(Debug)]
pub struct RateLimiter {
    bucket: Mutex<TokenBucket>,
}

impl RateLimiter {
    /// `rpm = 4` honours VT's public tier; `rpm = 0` disables limiting.
    pub fn new(requests_per_minute: u32) -> Self {
        RateLimiter {
            bucket: Mutex::new(if requests_per_minute == 0 {
                TokenBucket::unlimited()
            } else {
                TokenBucket::new(requests_per_minute)
            }),
        }
    }

    /// Block until a request slot is available, then consume it.
    pub fn acquire(&self) {
        loop {
            let wait = {
                let mut b = lock(&self.bucket);
                let now = Instant::now();
                if b.try_take(now) {
                    return;
                }
                b.time_until_ready(now)
            };
            std::thread::sleep(wait);
        }
    }

    /// Non-blocking check — for callers that would rather defer than wait.
    pub fn try_acquire(&self) -> bool {
        lock(&self.bucket).try_take(Instant::now())
    }
}
