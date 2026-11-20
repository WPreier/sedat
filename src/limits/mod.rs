//! Connection, rate, size limits, and temporary IP bans.

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
    ips: DashMap<IpAddr, Mutex<IpLimitState>>,
}

#[derive(Debug)]
struct IpLimitState {
    bucket: TokenBucket,
    /// Consecutive rate-limit denials (reset on allow).
    strikes: u32,
    /// Absolute deadline while banned (`None` = not banned).
    banned_until: Option<Instant>,
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last: Instant,
    rate: f64,
    burst: f64,
}

/// Outcome of a rate / ban check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateOutcome {
    /// Request may proceed.
    Allow,
    /// Token bucket empty; not (yet) under a temporary ban.
    RateLimited,
    /// IP is under an active temporary ban (fail-closed until TTL).
    Banned,
}

/// Side-effect events from a rate check (for tracing / JSONL audit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanLifecycle {
    /// Ban just applied after enough consecutive strikes.
    Applied {
        /// Configured ban TTL in seconds.
        duration_secs: u64,
        /// Strike count that triggered the ban.
        strikes: u32,
    },
    /// Previous ban TTL elapsed; IP is clear again.
    Expired,
}

/// Full result of [`Limiter::check_rate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateCheck {
    /// Allow / rate-limit / ban decision.
    pub outcome: RateOutcome,
    /// Optional ban/unban lifecycle event to log.
    pub lifecycle: Option<BanLifecycle>,
}

impl Limiter {
    /// Create from config.
    pub fn new(cfg: LimitsConfig) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            active: AtomicUsize::new(0),
            ips: DashMap::new(),
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

    /// Rate-limit + temporary ban check for `ip`.
    ///
    /// `limits` is taken from the live config (reload-friendly). When
    /// `ban_after_rate_limit_strikes == 0`, bans are disabled.
    /// Once banned, requests are rejected until `ban_duration_secs` elapses
    /// (fail-closed).
    pub fn check_rate(&self, ip: IpAddr, limits: &LimitsConfig) -> RateCheck {
        let rate = f64::from(limits.rate_limit_per_ip);
        let burst = f64::from(limits.rate_limit_burst);
        let strike_threshold = limits.ban_after_rate_limit_strikes;
        let ban_secs = limits.ban_duration_secs;

        let entry = self
            .ips
            .entry(ip)
            .or_insert_with(|| Mutex::new(IpLimitState::new(rate, burst)));
        let mut st = entry.lock();
        st.bucket.rate = rate;
        st.bucket.burst = burst;

        let now = Instant::now();
        let mut lifecycle = None;

        // Expire ban if TTL passed.
        if let Some(until) = st.banned_until {
            if now >= until {
                st.banned_until = None;
                st.strikes = 0;
                lifecycle = Some(BanLifecycle::Expired);
            } else {
                return RateCheck {
                    outcome: RateOutcome::Banned,
                    lifecycle: None,
                };
            }
        }

        if st.bucket.try_take(1.0) {
            st.strikes = 0;
            return RateCheck {
                outcome: RateOutcome::Allow,
                lifecycle,
            };
        }

        // Token bucket empty → strike.
        st.strikes = st.strikes.saturating_add(1);
        if strike_threshold > 0 && ban_secs > 0 && st.strikes >= strike_threshold {
            st.banned_until = Some(now + Duration::from_secs(ban_secs));
            let strikes = st.strikes;
            st.strikes = 0;
            return RateCheck {
                outcome: RateOutcome::Banned,
                lifecycle: Some(BanLifecycle::Applied {
                    duration_secs: ban_secs,
                    strikes,
                }),
            };
        }

        RateCheck {
            outcome: RateOutcome::RateLimited,
            lifecycle,
        }
    }

    /// Whether `ip` is currently banned (test / admin helper).
    #[must_use]
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        let Some(entry) = self.ips.get(&ip) else {
            return false;
        };
        let st = entry.lock();
        st.banned_until
            .is_some_and(|until| Instant::now() < until)
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

impl IpLimitState {
    fn new(rate: f64, burst: f64) -> Self {
        Self {
            bucket: TokenBucket::new(rate, burst),
            strikes: 0,
            banned_until: None,
        }
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
    use std::thread;

    #[test]
    fn rate_limit_burst() {
        let cfg = LimitsConfig {
            rate_limit_per_ip: 1,
            rate_limit_burst: 3,
            ban_after_rate_limit_strikes: 0,
            ..Default::default()
        };
        let lim = Limiter::new(cfg.clone());
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::Allow);
        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::Allow);
        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::Allow);
        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::RateLimited);
    }

    #[test]
    fn temporary_ban_after_strikes() {
        let cfg = LimitsConfig {
            rate_limit_per_ip: 1,
            rate_limit_burst: 1,
            ban_after_rate_limit_strikes: 3,
            ban_duration_secs: 2,
            ..Default::default()
        };
        let lim = Limiter::new(cfg.clone());
        let ip: IpAddr = "9.9.9.9".parse().unwrap();

        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::Allow);
        // strike 1
        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::RateLimited);
        // strike 2
        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::RateLimited);
        // strike 3 → ban applied
        let third = lim.check_rate(ip, &cfg);
        assert_eq!(third.outcome, RateOutcome::Banned);
        assert!(matches!(
            third.lifecycle,
            Some(BanLifecycle::Applied {
                duration_secs: 2,
                strikes: 3
            })
        ));
        assert!(lim.is_banned(ip));

        // Still banned without new lifecycle
        let still = lim.check_rate(ip, &cfg);
        assert_eq!(still.outcome, RateOutcome::Banned);
        assert!(still.lifecycle.is_none());

        thread::sleep(Duration::from_millis(2100));
        let after = lim.check_rate(ip, &cfg);
        // Ban expired; may Allow or RateLimited depending on tokens.
        assert!(matches!(
            after.lifecycle,
            Some(BanLifecycle::Expired)
        ));
        assert!(!lim.is_banned(ip));
    }

    #[test]
    fn bans_disabled_when_strikes_zero() {
        let cfg = LimitsConfig {
            rate_limit_per_ip: 1,
            rate_limit_burst: 1,
            ban_after_rate_limit_strikes: 0,
            ban_duration_secs: 60,
            ..Default::default()
        };
        let lim = Limiter::new(cfg.clone());
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::Allow);
        for _ in 0..20 {
            assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::RateLimited);
        }
        assert!(!lim.is_banned(ip));
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
