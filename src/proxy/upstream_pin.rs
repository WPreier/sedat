//! Upstream IP pin / allowlist (DNS rebinding defense).

use std::net::{IpAddr, SocketAddr};

use crate::config::ip_in_allowlist;

/// Whether `ip` is permitted by the route pin.
///
/// Empty `allowlist` → all IPs allowed (pin disabled).
#[must_use]
pub fn upstream_ip_allowed(ip: IpAddr, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    ip_in_allowlist(ip, allowlist)
}

/// Filter resolved addresses to those matching the pin.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_permits_all() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(upstream_ip_allowed(ip, &[]));
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
}
