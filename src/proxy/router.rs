//! Virtual-host / path-prefix routing.

use crate::config::{PathRoute, RoutesConfig};

/// Resolved upstream route.
#[derive(Debug, Clone)]
pub struct RouteMatch {
    /// Matched host.
    pub host: String,
    /// Matched path prefix.
    pub prefix: String,
    /// Upstream base URL.
    pub upstream: String,
    /// Upstream IP/CIDR pin (empty = unrestricted).
    pub upstream_allowlist: Vec<String>,
    /// Optional client cert PEM for upstream mTLS (empty = off).
    pub upstream_mtls_cert: String,
    /// Optional client key PEM for upstream mTLS.
    pub upstream_mtls_key: String,
    /// Optional CA PEM to verify upstream TLS (empty = webpki roots).
    pub upstream_mtls_ca: String,
}

/// Resolve host + path to a route. Longest matching prefix wins. Unknown host → `None`.
pub fn resolve_route(routes: &RoutesConfig, host: &str, path: &str) -> Option<RouteMatch> {
    let host_lc = host.to_ascii_lowercase();
    let vhost = routes
        .hosts
        .iter()
        .find(|h| h.host.eq_ignore_ascii_case(&host_lc))?;

    let mut best: Option<&PathRoute> = None;
    for p in &vhost.paths {
        if path.starts_with(&p.prefix) {
            match best {
                None => best = Some(p),
                Some(cur) if p.prefix.len() > cur.prefix.len() => best = Some(p),
                _ => {}
            }
        }
    }
    best.map(|p| RouteMatch {
        host: vhost.host.clone(),
        prefix: p.prefix.clone(),
        upstream: p.upstream.clone(),
        upstream_allowlist: p.upstream_allowlist.clone(),
        upstream_mtls_cert: p.upstream_mtls_cert.clone(),
        upstream_mtls_key: p.upstream_mtls_key.clone(),
        upstream_mtls_ca: p.upstream_mtls_ca.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HostRoute, PathRoute, RoutesConfig};

    #[test]
    fn longest_prefix() {
        let routes = RoutesConfig {
            hosts: vec![HostRoute {
                host: "example.com".into(),
                paths: vec![
                    PathRoute {
                        prefix: "/".into(),
                        upstream: "http://127.0.0.1:1".into(),
                        ..Default::default()
                    },
                    PathRoute {
                        prefix: "/api".into(),
                        upstream: "http://127.0.0.1:2".into(),
                        ..Default::default()
                    },
                ],
            }],
        };
        let m = resolve_route(&routes, "example.com", "/api/v1").unwrap();
        assert_eq!(m.upstream, "http://127.0.0.1:2");
    }

    #[test]
    fn unknown_host() {
        let routes = RoutesConfig { hosts: vec![] };
        assert!(resolve_route(&routes, "nope", "/").is_none());
    }
}
