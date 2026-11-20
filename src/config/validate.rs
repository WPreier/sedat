//! Regex and semantic validation for client-visible config fields.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::OnceLock;

use regex::Regex;

use super::schema::SedatConfig;

/// Validation failure with best-effort line number.
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// 1-based line hint.
    pub line: usize,
    /// Reason.
    pub message: String,
}

fn host_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$|^localhost$|^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-f:]+\]?$").expect("host regex")
    })
}

fn path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^/[\x20-\x7E]*$").expect("path regex"))
}

fn upstream_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^https?://[A-Za-z0-9.\-:\[\]]+(:\d{1,5})?(/[\x20-\x7E]*)?$")
            .expect("upstream regex")
    })
}

fn listen_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$|^\[?[0-9a-fA-F:]+\]?:\d{1,5}$|^[A-Za-z0-9.\-]+:\d{1,5}$")
            .expect("listen regex")
    })
}

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[^@\s]+@[^@\s]+\.[^@\s]+$").expect("email regex"))
}

fn find_line(text: &str, needle: &str) -> usize {
    text.lines()
        .enumerate()
        .find(|(_, l)| l.contains(needle))
        .map(|(i, _)| i + 1)
        .unwrap_or(1)
}

fn err(line: usize, message: impl Into<String>) -> ValidationError {
    ValidationError {
        line,
        message: message.into(),
    }
}

/// Validate a parsed config against regex/semantic rules.
pub fn validate_config(cfg: &SedatConfig, source: &str) -> Result<(), ValidationError> {
    for field in [
        &cfg.server.listen,
        &cfg.server.listen_tls,
        &cfg.server.http_redirect_listen,
    ] {
        if !listen_re().is_match(field) {
            return Err(err(
                find_line(source, field),
                format!("invalid listen address `{field}`"),
            ));
        }
    }

    if !cfg.embedded_docs.sedat_path.starts_with('/')
        || !path_re().is_match(&cfg.embedded_docs.sedat_path)
    {
        return Err(err(
            find_line(source, &cfg.embedded_docs.sedat_path),
            "embedded_docs.sedat_path must be an absolute path",
        ));
    }
    if !cfg.embedded_docs.seda_path.starts_with('/')
        || !path_re().is_match(&cfg.embedded_docs.seda_path)
    {
        return Err(err(
            find_line(source, &cfg.embedded_docs.seda_path),
            "embedded_docs.seda_path must be an absolute path",
        ));
    }

    match cfg.proxy_protocol.outbound.as_str() {
        "off" | "v1" | "v2" => {}
        other => {
            return Err(err(
                find_line(source, other),
                format!("proxy_protocol.outbound must be off|v1|v2, got `{other}`"),
            ));
        }
    }

    match cfg.proxy_protocol.inbound_placement.as_str() {
        "before_tls" | "after_tls" => {}
        other => {
            return Err(err(
                find_line(source, other),
                format!(
                    "proxy_protocol.inbound_placement must be before_tls|after_tls, got `{other}`"
                ),
            ));
        }
    }

    for cidr in &cfg.proxy_protocol.inbound_allowlist {
        if parse_cidr(cidr).is_err() {
            return Err(err(
                find_line(source, cidr),
                format!("invalid CIDR `{cidr}`"),
            ));
        }
    }
    if cfg.proxy_protocol.inbound_enabled && cfg.proxy_protocol.inbound_allowlist.is_empty() {
        return Err(err(
            find_line(source, "inbound_enabled"),
            "inbound PROXY enabled but inbound_allowlist is empty (fail-closed)",
        ));
    }

    for mode in [&cfg.hardening.landlock, &cfg.hardening.seccomp] {
        match mode.as_str() {
            "auto" | "off" | "required" => {}
            other => {
                return Err(err(
                    find_line(source, other),
                    format!("hardening mode must be auto|off|required, got `{other}`"),
                ));
            }
        }
    }

    if !crate::proxy::valid_header_name(&cfg.logging.request_id_header) {
        return Err(err(
            find_line(source, &cfg.logging.request_id_header),
            format!(
                "logging.request_id_header must be a valid HTTP token, got `{}`",
                cfg.logging.request_id_header
            ),
        ));
    }

    if let Some(ref addr) = cfg.server.metrics_listen {
        if !addr.is_empty() {
            if !listen_re().is_match(addr) {
                return Err(err(
                    find_line(source, addr),
                    format!("invalid metrics_listen address `{addr}`"),
                ));
            }
            if !is_loopback_listen(addr) {
                return Err(err(
                    find_line(source, addr),
                    format!(
                        "metrics_listen must be loopback only (127.0.0.1 / ::1), got `{addr}`"
                    ),
                ));
            }
        }
    }

    if cfg.acme.enabled {
        if cfg.acme.domains.is_empty() {
            return Err(err(
                find_line(source, "[acme]"),
                "acme.enabled requires at least one domain",
            ));
        }
        if !cfg.acme.email.is_empty() && !email_re().is_match(&cfg.acme.email) {
            return Err(err(
                find_line(source, &cfg.acme.email),
                format!("invalid acme.email `{}`", cfg.acme.email),
            ));
        }
        for d in &cfg.acme.domains {
            if !host_re().is_match(d) {
                return Err(err(
                    find_line(source, d),
                    format!("invalid acme domain `{d}`"),
                ));
            }
        }
        match cfg.acme.dns_provider.as_str() {
            "file" | "cloudflare" => {}
            other => {
                return Err(err(
                    find_line(source, other),
                    format!("unknown dns_provider `{other}`"),
                ));
            }
        }
    }

    if cfg.tls.enabled
        && !cfg.acme.enabled
        && (cfg
            .tls
            .cert_path
            .as_ref()
            .map(|s| s.is_empty())
            .unwrap_or(true)
            || cfg
                .tls
                .key_path
                .as_ref()
                .map(|s| s.is_empty())
                .unwrap_or(true))
    {
        return Err(err(
            find_line(source, "[tls]"),
            "tls.enabled without ACME requires cert_path and key_path",
        ));
    }

    for host in &cfg.routes.hosts {
        if !host_re().is_match(&host.host) {
            return Err(err(
                find_line(source, &host.host),
                format!("invalid host `{}`", host.host),
            ));
        }
        if host.paths.is_empty() {
            return Err(err(
                find_line(source, &host.host),
                format!("host `{}` has no paths", host.host),
            ));
        }
        for p in &host.paths {
            if !p.prefix.starts_with('/') || !path_re().is_match(&p.prefix) {
                return Err(err(
                    find_line(source, &p.prefix),
                    format!("invalid path prefix `{}`", p.prefix),
                ));
            }
            if p.prefix.contains("..") {
                return Err(err(
                    find_line(source, &p.prefix),
                    "path prefix must not contain `..`",
                ));
            }
            if !upstream_re().is_match(&p.upstream) {
                return Err(err(
                    find_line(source, &p.upstream),
                    format!("invalid upstream URL `{}`", p.upstream),
                ));
            }
            if p.upstream.starts_with("https://") {
                // MVP forwards plain HTTP to upstream; https upstream not yet supported.
                return Err(err(
                    find_line(source, &p.upstream),
                    "upstream must be http:// (TLS to backend not supported in MVP)",
                ));
            }
        }
    }

    if cfg.limits.max_connections == 0 {
        return Err(err(1, "limits.max_connections must be > 0"));
    }
    if cfg.experimental.h3 && !cfg!(feature = "http3") {
        // Allow config parse; runtime will warn and refuse to enable.
    }

    Ok(())
}

/// True if listen address host is loopback (IPv4 127/8 or IPv6 ::1 / localhost).
fn is_loopback_listen(addr: &str) -> bool {
    let host = if let Some(h) = addr.rsplit_once(':') {
        // Handle [ipv6]:port
        let raw = h.0;
        raw.trim_start_matches('[').trim_end_matches(']')
    } else {
        addr
    };
    match IpAddr::from_str(host) {
        Ok(IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => v6.is_loopback(),
        Err(_) => host.eq_ignore_ascii_case("localhost"),
    }
}

/// Parse `a.b.c.d/nn` or single IP as /32.
pub fn parse_cidr(s: &str) -> Result<(IpAddr, u8), String> {
    if let Some((ip, prefix)) = s.split_once('/') {
        let addr = IpAddr::from_str(ip.trim()).map_err(|e| e.to_string())?;
        let p: u8 = prefix.trim().parse().map_err(|e| format!("{e}"))?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if p > max {
            return Err(format!("prefix {p} too large for {addr}"));
        }
        Ok((addr, p))
    } else {
        let addr = IpAddr::from_str(s.trim()).map_err(|e| e.to_string())?;
        let p = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Ok((addr, p))
    }
}

/// Check whether `ip` is inside any CIDR string in `list`.
#[must_use]
pub fn ip_in_allowlist(ip: IpAddr, list: &[String]) -> bool {
    list.iter().any(|c| match parse_cidr(c) {
        Ok((net, prefix)) => ip_in_cidr(ip, net, prefix),
        Err(_) => false,
    })
}

fn ip_in_cidr(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let ip = u128::from(ip);
            let net = u128::from(net);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (ip & mask) == (net & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_toml;

    #[test]
    fn rejects_bad_host() {
        let toml = r#"
schema_version = 1
[[routes.hosts]]
host = "bad host!!"
[[routes.hosts.paths]]
prefix = "/"
upstream = "http://127.0.0.1:9080"
"#;
        let err = parse_toml(toml).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("invalid host") || msg.contains("validation"),
            "{msg}"
        );
    }

    #[test]
    fn rejects_path_traversal_prefix() {
        let toml = r#"
schema_version = 1
[[routes.hosts]]
host = "localhost"
[[routes.hosts.paths]]
prefix = "/../secret"
upstream = "http://127.0.0.1:9080"
"#;
        let err = parse_toml(toml).unwrap_err();
        assert!(err.to_string().contains(".."), "{err}");
    }

    #[test]
    fn cidr_allowlist() {
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(ip_in_allowlist(ip, &["10.0.0.0/8".into()]));
        assert!(!ip_in_allowlist(ip, &["192.168.0.0/16".into()]));
    }
}
