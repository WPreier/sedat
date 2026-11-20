//! Connection, rate, and size limits.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;

use crate::config::LimitsConfig;

/// Shared limiter state for the process.
#[derive(Debug)]
pub struct Limiter {
    cfg: LimitsConfig,
    active: AtomicUsize,
    buckets: DashMap<IpAddr, Mutex<TokenBucket>>,
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last: Instant,
    rate: f64,
    burst: f64,
}

impl Limiter {
    /// Create from config.
    pub fn new(cfg: LimitsConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            active: AtomicUsize::new(0),
            buckets: DashMap::new(),
        })
    }

    /// Try to accept a new connection. Returns `false` if at capacity.
    pub fn try_acquire_connection(&self) -> bool {
        let mut cur = self.active.load(Ordering::Relaxed);
        loop {
            if cur >= self.cfg.max_connections {
                return false;
            }
            match self
                .active
                .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(v) => cur = v,
            }
        }
    }

    /// Release a connection slot.
    pub fn release_connection(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }

    /// Current active connections.
    pub fn active_connections(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// Rate-limit check for `ip`. Returns `false` when limited.
    pub fn check_rate(&self, ip: IpAddr) -> bool {
        let rate = f64::from(self.cfg.rate_limit_per_ip);
        let burst = f64::from(self.cfg.rate_limit_burst);
        let entry = self
            .buckets
            .entry(ip)
            .or_insert_with(|| Mutex::new(TokenBucket::new(rate, burst)));
        let mut b = entry.lock();
        b.rate = rate;
        b.burst = burst;
        b.try_take(1.0)
    }

    /// Configured header byte limit.
    pub fn max_header_bytes(&self) -> usize {
        self.cfg.max_header_bytes
    }

    /// Configured header count limit.
    pub fn max_headers(&self) -> usize {
        self.cfg.max_headers
    }

    /// Configured body limit.
    pub fn max_body_bytes(&self) -> usize {
        self.cfg.max_body_bytes
    }

    /// Request timeout.
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.cfg.request_timeout_secs)
    }

    /// Idle timeout.
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.cfg.idle_timeout_secs)
    }

    /// HTTP/3 connection limit.
    pub fn max_h3_connections(&self) -> usize {
        self.cfg.max_h3_connections
    }

    /// HTTP/3 stream limit.
    pub fn max_h3_streams(&self) -> usize {
        self.cfg.max_h3_streams
    }
}

impl TokenBucket {
    fn new(rate: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            last: Instant::now(),
            rate,
            burst,
        }
    }

    fn try_take(&mut self, n: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.last = now;
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

/// Guard that releases a connection slot on drop.
pub struct ConnectionGuard {
    limiter: Arc<Limiter>,
}

impl ConnectionGuard {
    /// Acquire or return `None` if limited.
    pub fn acquire(limiter: Arc<Limiter>) -> Option<Self> {
        if limiter.try_acquire_connection() {
            Some(Self { limiter })
        } else {
            None
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.limiter.release_connection();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_burst() {
        let cfg = LimitsConfig {
            rate_limit_per_ip: 1,
            rate_limit_burst: 3,
            ..Default::default()
        };
        let lim = Limiter::new(cfg);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert!(lim.check_rate(ip));
        assert!(lim.check_rate(ip));
        assert!(lim.check_rate(ip));
        assert!(!lim.check_rate(ip));
    }

    #[test]
    fn connection_cap() {
        let cfg = LimitsConfig {
            max_connections: 2,
            ..Default::default()
        };
        let lim = Limiter::new(cfg);
        let g1 = ConnectionGuard::acquire(lim.clone()).unwrap();
        let g2 = ConnectionGuard::acquire(lim.clone()).unwrap();
        assert!(ConnectionGuard::acquire(lim.clone()).is_none());
        drop(g1);
        assert!(ConnectionGuard::acquire(lim).is_some());
        drop(g2);
    }
}
