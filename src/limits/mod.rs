//! Connection, rate, size limits, and temporary IP bans.

mod ban_share;

pub use ban_share::{
    instant_to_system, system_to_instant, BanShareStore, SharedBanView, BAN_SHARE_SECRET_ENV,
};

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;
use tracing::warn;

use crate::config::LimitsConfig;

/// Shared limiter state for the process.
#[derive(Debug)]
pub struct Limiter {
    /// Live edge limits (updated on admin/SIGHUP reload — P14.1).
    cfg: Mutex<LimitsConfig>,
    active: AtomicUsize,
    ips: DashMap<IpAddr, Mutex<IpLimitState>>,
    /// Optional file-backed replica ban share (P12.6); swapped on reload (P14.6).
    share: Mutex<Option<Arc<BanShareStore>>>,
    /// Requests denied by token-bucket rate limit (P17.4).
    rate_limited_total: AtomicU64,
    /// Requests denied while under (or newly entering) a temporary IP ban (P17.4).
    ban_hits_total: AtomicU64,
}

/// Result of attempting to hot-swap the ban-share store on reload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanShareReloadNote {
    /// Share stayed off.
    UnchangedOff,
    /// Share stayed on (rebuilt or same).
    Replaced,
    /// Share newly enabled.
    Enabled,
    /// Share turned off.
    Disabled,
    /// New share config invalid; previous store kept (fail-closed).
    KeptFailClosed(String),
}

impl BanShareReloadNote {
    /// Compact suffix for admin reload replies.
    #[must_use]
    pub fn reply_suffix(&self) -> String {
        match self {
            Self::UnchangedOff => String::new(),
            Self::Replaced => " ban_share=replaced".into(),
            Self::Enabled => " ban_share=enabled".into(),
            Self::Disabled => " ban_share=disabled".into(),
            Self::KeptFailClosed(_) => " ban_share=kept_fail_closed".into(),
        }
    }
}

#[derive(Debug)]
struct IpLimitState {
    bucket: TokenBucket,
    /// Consecutive rate-limit denials (reset on allow).
    strikes: u32,
    /// Absolute deadline while banned (`None` = not banned).
    banned_until: Option<Instant>,
    /// Last time an `Extended` audit was emitted (throttle).
    last_extend_audit: Option<Instant>,
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
    /// Ban TTL refreshed because the IP kept hitting while banned (P12.2).
    Extended {
        /// New TTL window in seconds (`ban_duration_secs` from now).
        duration_secs: u64,
        /// Remaining seconds before this extend.
        previous_remaining_secs: u64,
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

/// One active temporary ban (for admin listing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanEntry {
    /// Banned client address.
    pub ip: IpAddr,
    /// Approximate seconds remaining until TTL expiry.
    pub remaining_secs: u64,
}

impl Limiter {
    /// Create from config (no ban share).
    pub fn new(cfg: LimitsConfig) -> Arc<Self> {
        Self::new_with_share(cfg, None)
    }

    /// Create with optional shared ban store (P12.6).
    pub fn new_with_share(cfg: LimitsConfig, share: Option<Arc<BanShareStore>>) -> Arc<Self> {
        Arc::new(Self {
            cfg: Mutex::new(cfg),
            active: AtomicUsize::new(0),
            ips: DashMap::new(),
            share: Mutex::new(share),
            rate_limited_total: AtomicU64::new(0),
            ban_hits_total: AtomicU64::new(0),
        })
    }

    /// Replace live limit knobs after a successful config reload (P14.1 / P14.6).
    ///
    /// Also rebuilds the ban-share store when path/secret/poll change. Invalid
    /// share config keeps the previous store (fail-closed).
    pub fn reconfigure(&self, cfg: LimitsConfig) -> BanShareReloadNote {
        let note = self.swap_ban_share(&cfg);
        *self.cfg.lock() = cfg;
        note
    }

    fn swap_ban_share(&self, cfg: &LimitsConfig) -> BanShareReloadNote {
        match BanShareStore::try_from_limits(cfg) {
            Ok(new_share) => {
                let mut slot = self.share.lock();
                let was = slot.is_some();
                let now = new_share.is_some();
                *slot = new_share;
                match (was, now) {
                    (false, false) => BanShareReloadNote::UnchangedOff,
                    (false, true) => BanShareReloadNote::Enabled,
                    (true, false) => BanShareReloadNote::Disabled,
                    (true, true) => BanShareReloadNote::Replaced,
                }
            }
            Err(e) => {
                warn!(error = %e, "ban share reload rejected; previous store kept");
                BanShareReloadNote::KeptFailClosed(e)
            }
        }
    }

    /// Snapshot of the live limits (for tests / status).
    #[must_use]
    pub fn limits_snapshot(&self) -> LimitsConfig {
        self.cfg.lock().clone()
    }

    /// Whether a shared ban file is configured.
    #[must_use]
    pub fn ban_share_enabled(&self) -> bool {
        self.share.lock().is_some()
    }

    /// Try to accept a new connection. Returns `false` if at capacity.
    pub fn try_acquire_connection(&self) -> bool {
        let max = self.cfg.lock().max_connections;
        let mut cur = self.active.load(Ordering::Relaxed);
        loop {
            if cur >= max {
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

    /// Cumulative rate-limit denials (Prometheus `sedat_rate_limited_total`).
    #[must_use]
    pub fn rate_limited_total(&self) -> u64 {
        self.rate_limited_total.load(Ordering::Relaxed)
    }

    /// Cumulative ban-path denials (Prometheus `sedat_ban_hits_total`).
    #[must_use]
    pub fn ban_hits_total(&self) -> u64 {
        self.ban_hits_total.load(Ordering::Relaxed)
    }

    /// Rate-limit + temporary ban check for `ip`.
    ///
    /// `limits` is taken from the live config (reload-friendly). When
    /// `ban_after_rate_limit_strikes == 0`, bans are disabled.
    /// Once banned, requests are rejected until `ban_duration_secs` elapses
    /// (fail-closed). When `ban_extend_while_banned` is true (default), each
    /// hit while banned refreshes the TTL (sliding window).
    pub fn check_rate(&self, ip: IpAddr, limits: &LimitsConfig) -> RateCheck {
        self.maybe_pull_share();

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

        // Expire ban if TTL passed; otherwise optionally slide the window.
        if let Some(until) = st.banned_until {
            if now >= until {
                st.banned_until = None;
                st.strikes = 0;
                st.last_extend_audit = None;
                lifecycle = Some(BanLifecycle::Expired);
            } else {
                let remaining = until.saturating_duration_since(now).as_secs().max(1);
                let mut extend_life = None;
                if limits.ban_extend_while_banned && ban_secs > 0 {
                    let new_until = now + Duration::from_secs(ban_secs);
                    st.banned_until = Some(new_until);
                    self.publish_ban_share(ip, new_until);
                    let interval = limits.ban_extend_min_interval_secs;
                    let audit_ok = match st.last_extend_audit {
                        None => true,
                        Some(t) => interval == 0 || now.duration_since(t).as_secs() >= interval,
                    };
                    if audit_ok {
                        st.last_extend_audit = Some(now);
                        extend_life = Some(BanLifecycle::Extended {
                            duration_secs: ban_secs,
                            previous_remaining_secs: remaining,
                        });
                    }
                }
                self.ban_hits_total.fetch_add(1, Ordering::Relaxed);
                return RateCheck {
                    outcome: RateOutcome::Banned,
                    lifecycle: extend_life,
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
            let new_until = now + Duration::from_secs(ban_secs);
            st.banned_until = Some(new_until);
            st.last_extend_audit = None;
            let strikes = st.strikes;
            st.strikes = 0;
            drop(st);
            self.publish_ban_share(ip, new_until);
            self.ban_hits_total.fetch_add(1, Ordering::Relaxed);
            return RateCheck {
                outcome: RateOutcome::Banned,
                lifecycle: Some(BanLifecycle::Applied {
                    duration_secs: ban_secs,
                    strikes,
                }),
            };
        }

        self.rate_limited_total.fetch_add(1, Ordering::Relaxed);
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
        st.banned_until.is_some_and(|until| Instant::now() < until)
    }

    /// List active temporary bans (expires stale entries while scanning).
    #[must_use]
    pub fn list_bans(&self) -> Vec<BanEntry> {
        let now = Instant::now();
        let mut out = Vec::new();
        for entry in self.ips.iter() {
            let mut st = entry.value().lock();
            let Some(until) = st.banned_until else {
                continue;
            };
            if now >= until {
                st.banned_until = None;
                st.strikes = 0;
                st.last_extend_audit = None;
                continue;
            }
            out.push(BanEntry {
                ip: *entry.key(),
                remaining_secs: until.saturating_duration_since(now).as_secs().max(1),
            });
        }
        out.sort_by_key(|e| e.ip);
        out
    }

    /// Count of currently active temporary bans (P16.3 metrics).
    #[must_use]
    pub fn bans_active(&self) -> usize {
        self.list_bans().len()
    }

    /// Clear an active temporary ban. Returns `true` if the IP was banned.
    ///
    /// Also clears an already-expired ban marker; that still returns `false`
    /// (no active ban to lift).
    pub fn unban(&self, ip: IpAddr) -> bool {
        let Some(entry) = self.ips.get(&ip) else {
            // Still publish tombstone so replicas clear.
            self.publish_unban_share(ip);
            return false;
        };
        let mut st = entry.lock();
        let now = Instant::now();
        let cleared = match st.banned_until {
            Some(until) if now < until => {
                st.banned_until = None;
                st.strikes = 0;
                st.last_extend_audit = None;
                true
            }
            Some(_) => {
                st.banned_until = None;
                st.strikes = 0;
                st.last_extend_audit = None;
                false
            }
            None => false,
        };
        drop(st);
        self.publish_unban_share(ip);
        cleared
    }

    /// Pull shared bans into local state (throttled via store poll interval).
    pub fn sync_ban_share(&self) {
        self.pull_share_now();
    }

    fn maybe_pull_share(&self) {
        let share = self.share.lock().clone();
        let Some(share) = share else {
            return;
        };
        if share.should_pull() {
            self.pull_share_now();
        }
    }

    fn pull_share_now(&self) {
        let share = self.share.lock().clone();
        let Some(share) = share else {
            return;
        };
        match share.pull() {
            Ok(views) => {
                for v in views {
                    self.apply_shared_view(v);
                }
            }
            Err(e) => {
                warn!(error = %e, "ban share pull failed (local state unchanged)");
            }
        }
    }

    fn apply_shared_view(&self, view: SharedBanView) {
        let (rate, burst) = {
            let c = self.cfg.lock();
            (
                f64::from(c.rate_limit_per_ip),
                f64::from(c.rate_limit_burst),
            )
        };
        let entry = self
            .ips
            .entry(view.ip)
            .or_insert_with(|| Mutex::new(IpLimitState::new(rate, burst)));
        let mut st = entry.lock();
        match view.until {
            None => {
                st.banned_until = None;
                st.strikes = 0;
                st.last_extend_audit = None;
            }
            Some(until_sys) => {
                let until_i = system_to_instant(until_sys);
                let now = Instant::now();
                if until_i <= now {
                    st.banned_until = None;
                    st.strikes = 0;
                    st.last_extend_audit = None;
                    return;
                }
                match st.banned_until {
                    Some(local) if local >= until_i => {}
                    _ => {
                        st.banned_until = Some(until_i);
                    }
                }
            }
        }
    }

    fn publish_ban_share(&self, ip: IpAddr, until: Instant) {
        let share = self.share.lock().clone();
        let Some(share) = share else {
            return;
        };
        if let Err(e) = share.publish_ban(ip, instant_to_system(until)) {
            warn!(error = %e, %ip, "ban share publish_ban failed");
        }
    }

    fn publish_unban_share(&self, ip: IpAddr) {
        let share = self.share.lock().clone();
        let Some(share) = share else {
            return;
        };
        if let Err(e) = share.publish_unban(ip) {
            warn!(error = %e, %ip, "ban share publish_unban failed");
        }
    }

    /// Configured header byte limit.
    pub fn max_header_bytes(&self) -> usize {
        self.cfg.lock().max_header_bytes
    }

    /// Configured header count limit.
    pub fn max_headers(&self) -> usize {
        self.cfg.lock().max_headers
    }

    /// Configured body limit.
    pub fn max_body_bytes(&self) -> usize {
        self.cfg.lock().max_body_bytes
    }

    /// Request timeout.
    pub fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.cfg.lock().request_timeout_secs)
    }

    /// Idle timeout.
    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.cfg.lock().idle_timeout_secs)
    }

    /// HTTP/3 connection limit.
    pub fn max_h3_connections(&self) -> usize {
        self.cfg.lock().max_h3_connections
    }

    /// HTTP/3 stream limit.
    pub fn max_h3_streams(&self) -> usize {
        self.cfg.lock().max_h3_streams
    }
}

impl IpLimitState {
    fn new(rate: f64, burst: f64) -> Self {
        Self {
            bucket: TokenBucket::new(rate, burst),
            strikes: 0,
            banned_until: None,
            last_extend_audit: None,
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
    fn reconfigure_updates_connection_cap() {
        let lim = Limiter::new(LimitsConfig {
            max_connections: 1,
            ..Default::default()
        });
        let g1 = ConnectionGuard::acquire(lim.clone()).expect("first slot");
        assert!(ConnectionGuard::acquire(lim.clone()).is_none());
        let _ = lim.reconfigure(LimitsConfig {
            max_connections: 2,
            ..Default::default()
        });
        assert_eq!(lim.limits_snapshot().max_connections, 2);
        let g2 = ConnectionGuard::acquire(lim.clone()).expect("second slot after reconfigure");
        assert!(ConnectionGuard::acquire(lim.clone()).is_none());
        drop((g1, g2));
    }

    #[test]
    fn reconfigure_ban_share_enable_disable_and_fail_closed() {
        std::env::remove_var(BAN_SHARE_SECRET_ENV);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bans.json");
        let lim = Limiter::new(LimitsConfig::default());
        assert!(!lim.ban_share_enabled());

        let note = lim.reconfigure(LimitsConfig {
            ban_share_path: path.to_string_lossy().into(),
            ban_share_secret: "hot-reload-secret-32bytes!!!!!!".into(),
            ban_share_poll_secs: 1,
            ..Default::default()
        });
        assert_eq!(note, BanShareReloadNote::Enabled);
        assert!(lim.ban_share_enabled());
        assert_eq!(note.reply_suffix(), " ban_share=enabled");

        let note = lim.reconfigure(LimitsConfig {
            ban_share_path: path.to_string_lossy().into(),
            ban_share_secret: "hot-reload-secret-rotated!!!!!!".into(),
            ban_share_poll_secs: 2,
            ..Default::default()
        });
        assert_eq!(note, BanShareReloadNote::Replaced);
        assert!(lim.ban_share_enabled());

        let note = lim.reconfigure(LimitsConfig {
            ban_share_path: path.to_string_lossy().into(),
            ban_share_secret: String::new(),
            ..Default::default()
        });
        assert!(matches!(note, BanShareReloadNote::KeptFailClosed(_)));
        assert!(
            lim.ban_share_enabled(),
            "invalid share keeps previous store"
        );
        assert_eq!(note.reply_suffix(), " ban_share=kept_fail_closed");

        let note = lim.reconfigure(LimitsConfig::default());
        assert_eq!(note, BanShareReloadNote::Disabled);
        assert!(!lim.ban_share_enabled());
    }

    #[test]
    fn rate_and_ban_hit_counters() {
        let cfg = LimitsConfig {
            rate_limit_per_ip: 1,
            rate_limit_burst: 1,
            ban_after_rate_limit_strikes: 2,
            ban_duration_secs: 60,
            ..Default::default()
        };
        let lim = Limiter::new(cfg.clone());
        let ip: IpAddr = "198.51.100.9".parse().unwrap();
        assert_eq!(lim.rate_limited_total(), 0);
        assert_eq!(lim.ban_hits_total(), 0);
        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::Allow);
        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::RateLimited);
        assert_eq!(lim.rate_limited_total(), 1);
        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::Banned);
        assert_eq!(lim.ban_hits_total(), 1);
        assert_eq!(lim.rate_limited_total(), 1);
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

        // Still banned; default sliding extend emits Extended
        let still = lim.check_rate(ip, &cfg);
        assert_eq!(still.outcome, RateOutcome::Banned);
        assert!(matches!(
            still.lifecycle,
            Some(BanLifecycle::Extended {
                duration_secs: 2,
                ..
            })
        ));

        thread::sleep(Duration::from_millis(2100));
        let after = lim.check_rate(ip, &cfg);
        // Ban expired; may Allow or RateLimited depending on tokens.
        assert!(matches!(after.lifecycle, Some(BanLifecycle::Expired)));
        assert!(!lim.is_banned(ip));
    }

    #[test]
    fn sliding_ban_extends_ttl() {
        let cfg = LimitsConfig {
            rate_limit_per_ip: 1,
            rate_limit_burst: 1,
            ban_after_rate_limit_strikes: 2,
            ban_duration_secs: 1,
            ban_extend_while_banned: true,
            ban_extend_min_interval_secs: 0,
            ..Default::default()
        };
        let lim = Limiter::new(cfg.clone());
        let ip: IpAddr = "203.0.113.50".parse().unwrap();

        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::Allow);
        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::RateLimited);
        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::Banned);

        // Without extend, 1s ban would expire after ~1100ms; keep hitting so it slides.
        for _ in 0..4 {
            thread::sleep(Duration::from_millis(400));
            let r = lim.check_rate(ip, &cfg);
            assert_eq!(r.outcome, RateOutcome::Banned);
            assert!(matches!(r.lifecycle, Some(BanLifecycle::Extended { .. })));
        }
        assert!(lim.is_banned(ip));

        // Stop hitting; TTL from last extend (~1s) elapses.
        thread::sleep(Duration::from_millis(1100));
        let after = lim.check_rate(ip, &cfg);
        assert!(matches!(after.lifecycle, Some(BanLifecycle::Expired)));
        assert!(!lim.is_banned(ip));
    }

    #[test]
    fn sliding_ban_disabled_keeps_fixed_ttl() {
        let cfg = LimitsConfig {
            rate_limit_per_ip: 1,
            rate_limit_burst: 1,
            ban_after_rate_limit_strikes: 2,
            ban_duration_secs: 2,
            ban_extend_while_banned: false,
            ..Default::default()
        };
        let lim = Limiter::new(cfg.clone());
        let ip: IpAddr = "203.0.113.51".parse().unwrap();

        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::Allow);
        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::RateLimited);
        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::Banned);

        let still = lim.check_rate(ip, &cfg);
        assert_eq!(still.outcome, RateOutcome::Banned);
        assert!(still.lifecycle.is_none());
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
    fn list_and_unban() {
        let cfg = LimitsConfig {
            rate_limit_per_ip: 1,
            rate_limit_burst: 1,
            ban_after_rate_limit_strikes: 2,
            ban_duration_secs: 60,
            ..Default::default()
        };
        let lim = Limiter::new(cfg.clone());
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        assert!(lim.list_bans().is_empty());
        assert!(!lim.unban(ip));

        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::Allow);
        assert_eq!(lim.check_rate(ip, &cfg).outcome, RateOutcome::RateLimited);
        let banned = lim.check_rate(ip, &cfg);
        assert_eq!(banned.outcome, RateOutcome::Banned);
        assert!(lim.is_banned(ip));

        let list = lim.list_bans();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].ip, ip);
        assert!(list[0].remaining_secs > 0 && list[0].remaining_secs <= 60);

        assert!(lim.unban(ip));
        assert!(!lim.is_banned(ip));
        assert!(lim.list_bans().is_empty());
        assert!(!lim.unban(ip));
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

    #[test]
    fn shared_ban_propagates_between_limiters() {
        std::env::remove_var(BAN_SHARE_SECRET_ENV);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bans.json");
        let secret = "replica-share-secret-test!!";
        let base = LimitsConfig {
            rate_limit_per_ip: 1,
            rate_limit_burst: 1,
            ban_after_rate_limit_strikes: 2,
            ban_duration_secs: 60,
            ban_extend_while_banned: false,
            ban_share_path: path.to_string_lossy().into(),
            ban_share_secret: secret.into(),
            ban_share_poll_secs: 1,
            ..Default::default()
        };
        let share_a = BanShareStore::try_from_limits(&base).unwrap().unwrap();
        let share_b = BanShareStore::try_from_limits(&base).unwrap().unwrap();
        let a = Limiter::new_with_share(base.clone(), Some(share_a));
        let b = Limiter::new_with_share(base.clone(), Some(share_b));
        let ip: IpAddr = "203.0.113.77".parse().unwrap();

        assert_eq!(a.check_rate(ip, &base).outcome, RateOutcome::Allow);
        assert_eq!(a.check_rate(ip, &base).outcome, RateOutcome::RateLimited);
        assert_eq!(a.check_rate(ip, &base).outcome, RateOutcome::Banned);
        assert!(a.is_banned(ip));
        assert!(!b.is_banned(ip));

        b.sync_ban_share();
        assert!(b.is_banned(ip), "replica B should see shared ban");

        assert!(b.unban(ip));
        a.sync_ban_share();
        assert!(!a.is_banned(ip), "replica A should see shared unban");
    }
}
