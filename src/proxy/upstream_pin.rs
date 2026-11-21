//! Upstream IP pin / allowlist (DNS rebinding defense) with hostname pins
//! and cached DNS re-resolution (P12.5).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::lookup_host;

use crate::config::{ip_in_cidr, parse_cidr};

/// Default DNS cache refresh interval for upstream pins (seconds).
pub const DEFAULT_DNS_REFRESH_SECS: u64 = 60;

/// Cached DNS answers for hostname pins / upstream hosts.
#[derive(Clone, Debug, Default)]
pub struct DnsCache {
    inner: Arc<DashMap<String, CacheEntry>>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    ips: Vec<IpAddr>,
    fetched_at: Instant,
}

/// Expanded pin after resolving hostname literals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpandedPin {
    /// Empty allowlist → unrestricted.
    Unrestricted,
    /// Restricted to CIDRs and/or exact IPs from hostname pins.
    Restricted {
        /// IP/CIDR entries from config.
        cidrs: Vec<(IpAddr, u8)>,
        /// IPs resolved from hostname literals in the allowlist.
        host_ips: Vec<IpAddr>,
    },
}

impl DnsCache {
    /// Empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up A/AAAA for `host`, using cache while younger than `refresh`.
    ///
    /// `refresh == Duration::ZERO` → always re-query DNS (no cache hit).
    pub async fn lookup_ips(
        &self,
        host: &str,
        refresh: Duration,
    ) -> std::io::Result<Vec<IpAddr>> {
        let key = host.trim().to_ascii_lowercase();
        if key.is_empty() {
            return Ok(Vec::new());
        }
        if !refresh.is_zero() {
            if let Some(entry) = self.inner.get(&key) {
                if entry.fetched_at.elapsed() < refresh {
                    return Ok(entry.ips.clone());
                }
            }
        }
        let ips = resolve_ips_now(&key).await?;
        self.inner.insert(
            key,
            CacheEntry {
                ips: ips.clone(),
                fetched_at: Instant::now(),
            },
        );
        Ok(ips)
    }

    /// Resolve `host:port` to socket addrs (IP literals skip DNS).
    pub async fn resolve_host_addrs(
        &self,
        host: &str,
        port: u16,
        refresh: Duration,
    ) -> std::io::Result<Vec<SocketAddr>> {
        let host = host.trim();
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        // Strip brackets from [ipv6]
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let ips = self.lookup_ips(host, refresh).await?;
        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }

    /// Seed cache (unit tests).
    #[cfg(test)]
    pub fn put_for_test(&self, host: &str, ips: Vec<IpAddr>) {
        self.inner.insert(
            host.trim().to_ascii_lowercase(),
            CacheEntry {
                ips,
                fetched_at: Instant::now(),
            },
        );
    }

    /// Backdate cache entry for TTL tests.
    #[cfg(test)]
    pub fn age_for_test(&self, host: &str, age: Duration) {
        let key = host.trim().to_ascii_lowercase();
        if let Some(mut e) = self.inner.get_mut(&key) {
            e.fetched_at = Instant::now()
                .checked_sub(age)
                .unwrap_or_else(Instant::now);
        }
    }
}

async fn resolve_ips_now(host: &str) -> std::io::Result<Vec<IpAddr>> {
    let mut ips: Vec<IpAddr> = lookup_host((host, 80u16)).await?.map(|a| a.ip()).collect();
    ips.sort_unstable();
    ips.dedup();
    Ok(ips)
}

/// Whether `ip` is permitted by an already-expanded pin.
#[must_use]
pub fn ip_allowed_by_pin(ip: IpAddr, pin: &ExpandedPin) -> bool {
    match pin {
        ExpandedPin::Unrestricted => true,
        ExpandedPin::Restricted { cidrs, host_ips } => {
            cidrs.iter().any(|(net, prefix)| ip_in_cidr(ip, *net, *prefix))
                || host_ips.iter().any(|h| *h == ip)
        }
    }
}

/// Whether `ip` is permitted by the route pin (CIDR/IP entries only; no hostname expand).
///
/// Empty `allowlist` → all IPs allowed (pin disabled). Hostname literals are ignored here —
/// prefer [`expand_allowlist`] + [`ip_allowed_by_pin`] at connect time.
#[must_use]
pub fn upstream_ip_allowed(ip: IpAddr, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    allowlist.iter().any(|c| match parse_cidr(c) {
        Ok((net, prefix)) => ip_in_cidr(ip, net, prefix),
        Err(_) => false,
    })
}

/// Filter resolved addresses by an expanded pin.
#[must_use]
pub fn filter_pinned_addrs_expanded(
    addrs: &[SocketAddr],
    pin: &ExpandedPin,
) -> Vec<SocketAddr> {
    match pin {
        ExpandedPin::Unrestricted => addrs.to_vec(),
        ExpandedPin::Restricted { .. } => addrs
            .iter()
            .copied()
            .filter(|a| ip_allowed_by_pin(a.ip(), pin))
            .collect(),
    }
}

/// Filter resolved addresses to those matching the pin (CIDR/IP only).
#[must_use]
pub fn filter_pinned_addrs(addrs: &[SocketAddr], allowlist: &[String]) -> Vec<SocketAddr> {
    if allowlist.is_empty() {
        return addrs.to_vec();
    }
    addrs
        .iter()
        .copied()
        .filter(|a| upstream_ip_allowed(a.ip(), allowlist))
        .collect()
}

/// Expand allowlist: CIDR/IP keep as-is; hostnames resolve via [`DnsCache`].
///
/// Fail-closed: if the allowlist is non-empty but expands to **no** CIDRs and
/// **no** host IPs (e.g. all hostname lookups failed), returns
/// [`ExpandedPin::Restricted`] with empty sets (nothing matches).
pub async fn expand_allowlist(
    allowlist: &[String],
    cache: &DnsCache,
    refresh: Duration,
) -> ExpandedPin {
    if allowlist.is_empty() {
        return ExpandedPin::Unrestricted;
    }
    let mut cidrs = Vec::new();
    let mut host_ips = Vec::new();
    for entry in allowlist {
        let e = entry.trim();
        if e.is_empty() {
            continue;
        }
        if let Ok((net, prefix)) = parse_cidr(e) {
            cidrs.push((net, prefix));
            continue;
        }
        match cache.lookup_ips(e, refresh).await {
            Ok(ips) => host_ips.extend(ips),
            Err(_) => {
                // Fail-closed: skip failed hostname; may leave pin empty.
            }
        }
    }
    host_ips.sort_unstable();
    host_ips.dedup();
    ExpandedPin::Restricted { cidrs, host_ips }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_permits_all() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(upstream_ip_allowed(ip, &[]));
        assert!(ip_allowed_by_pin(ip, &ExpandedPin::Unrestricted));
    }

    #[test]
    fn pin_rejects_outside_cidr() {
        let allow = vec!["10.0.0.0/8".into()];
        assert!(upstream_ip_allowed("10.1.2.3".parse().unwrap(), &allow));
        assert!(!upstream_ip_allowed("203.0.113.9".parse().unwrap(), &allow));
    }

    #[test]
    fn filter_keeps_matching_only() {
        let addrs: Vec<SocketAddr> = vec![
            "10.0.0.5:9080".parse().unwrap(),
            "203.0.113.1:9080".parse().unwrap(),
        ];
        let allow = vec!["10.0.0.0/8".into()];
        let f = filter_pinned_addrs(&addrs, &allow);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].ip().to_string(), "10.0.0.5");
    }

    #[tokio::test]
    async fn hostname_pin_expands_from_cache() {
        let cache = DnsCache::new();
        cache.put_for_test("backend.internal", vec!["10.0.0.5".parse().unwrap()]);
        let pin = expand_allowlist(
            &["backend.internal".into()],
            &cache,
            Duration::from_secs(60),
        )
        .await;
        assert!(ip_allowed_by_pin("10.0.0.5".parse().unwrap(), &pin));
        assert!(!ip_allowed_by_pin("10.0.0.6".parse().unwrap(), &pin));
    }

    #[tokio::test]
    async fn hostname_pin_fail_closed_when_unresolved() {
        let cache = DnsCache::new();
        // No cache entry; lookup of reserved invalid TLD should fail or empty.
        let pin = expand_allowlist(
            &["this-host-does-not-exist.invalid".into()],
            &cache,
            Duration::ZERO,
        )
        .await;
        match &pin {
            ExpandedPin::Restricted { cidrs, host_ips } => {
                assert!(cidrs.is_empty());
                assert!(host_ips.is_empty());
            }
            ExpandedPin::Unrestricted => panic!("expected restricted empty"),
        }
        assert!(!ip_allowed_by_pin("127.0.0.1".parse().unwrap(), &pin));
    }

    #[tokio::test]
    async fn dns_cache_respects_refresh_ttl() {
        let cache = DnsCache::new();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        cache.put_for_test("cached.example", vec![ip]);
        let fresh = cache
            .lookup_ips("cached.example", Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(fresh, vec![ip]);

        // Still within TTL even if aged a little.
        cache.age_for_test("cached.example", Duration::from_secs(1));
        let still = cache
            .lookup_ips("cached.example", Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(still, vec![ip]);
    }

    #[tokio::test]
    async fn mixed_cidr_and_hostname_pin() {
        let cache = DnsCache::new();
        cache.put_for_test("db.internal", vec!["198.51.100.7".parse().unwrap()]);
        let pin = expand_allowlist(
            &["10.0.0.0/8".into(), "db.internal".into()],
            &cache,
            Duration::from_secs(30),
        )
        .await;
        assert!(ip_allowed_by_pin("10.1.2.3".parse().unwrap(), &pin));
        assert!(ip_allowed_by_pin("198.51.100.7".parse().unwrap(), &pin));
        assert!(!ip_allowed_by_pin("203.0.113.1".parse().unwrap(), &pin));
    }

    #[tokio::test]
    async fn resolve_ip_literal_skips_cache() {
        let cache = DnsCache::new();
        let addrs = cache
            .resolve_host_addrs("127.0.0.1", 9080, Duration::from_secs(60))
            .await
            .unwrap();
        assert_eq!(addrs, vec!["127.0.0.1:9080".parse().unwrap()]);
    }
}
