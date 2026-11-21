//! Regex and semantic validation for client-visible config fields.

use std::net::IpAddr;
use std::path::Path;
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

    if !crate::audit::valid_audit_path(&cfg.logging.audit_jsonl) {
        return Err(err(
            find_line(source, &cfg.logging.audit_jsonl),
            format!(
                "logging.audit_jsonl must be empty or a local file path, got `{}`",
                cfg.logging.audit_jsonl
            ),
        ));
    }

    if !crate::audit::valid_audit_path(&cfg.server.admin_token_file) {
        return Err(err(
            find_line(source, &cfg.server.admin_token_file),
            format!(
                "server.admin_token_file must be empty or a local file path, got `{}`",
                cfg.server.admin_token_file
            ),
        ));
    }
    if cfg.server.admin_token.len() > 512 {
        return Err(err(
            find_line(source, "admin_token"),
            "server.admin_token must be at most 512 bytes",
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
        if cfg.acme.renew_days_before == 0 || cfg.acme.renew_days_before > 90 {
            return Err(err(
                find_line(source, "renew_days_before").max(find_line(source, "[acme]")),
                "acme.renew_days_before must be 1..=90",
            ));
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
            let is_https = p.upstream.starts_with("https://");
            let has_cert = !p.upstream_mtls_cert.trim().is_empty();
            let has_key = !p.upstream_mtls_key.trim().is_empty();
            let has_ca = !p.upstream_mtls_ca.trim().is_empty();
            if has_cert != has_key {
                return Err(err(
                    find_line(
                        source,
                        if has_cert {
                            &p.upstream_mtls_cert
                        } else {
                            &p.upstream_mtls_key
                        },
                    ),
                    "upstream_mtls_cert and upstream_mtls_key must both be set or both empty",
                ));
            }
            if (has_cert || has_ca) && !is_https {
                return Err(err(
                    find_line(source, &p.upstream),
                    "upstream_mtls_* requires https:// upstream (default remains http://)",
                ));
            }
            if has_cert {
                if !Path::new(p.upstream_mtls_cert.trim()).is_file() {
                    return Err(err(
                        find_line(source, &p.upstream_mtls_cert),
                        format!(
                            "upstream_mtls_cert file not found: {}",
                            p.upstream_mtls_cert.trim()
                        ),
                    ));
                }
                if !Path::new(p.upstream_mtls_key.trim()).is_file() {
                    return Err(err(
                        find_line(source, &p.upstream_mtls_key),
                        format!(
                            "upstream_mtls_key file not found: {}",
                            p.upstream_mtls_key.trim()
                        ),
                    ));
                }
            }
            if has_ca && !Path::new(p.upstream_mtls_ca.trim()).is_file() {
                return Err(err(
                    find_line(source, &p.upstream_mtls_ca),
                    format!(
                        "upstream_mtls_ca file not found: {}",
                        p.upstream_mtls_ca.trim()
                    ),
                ));
            }
            for entry in &p.upstream_allowlist {
                if !is_allowlist_entry(entry) {
                    return Err(err(
                        find_line(source, entry),
                        format!(
                            "invalid upstream_allowlist entry `{entry}` (need IP/CIDR or hostname)"
                        ),
                    ));
                }
            }
        }
    }

    if cfg.limits.max_connections == 0 {
        return Err(err(1, "limits.max_connections must be > 0"));
    }
    if cfg.limits.ban_after_rate_limit_strikes > 0 && cfg.limits.ban_duration_secs == 0 {
        return Err(err(
            find_line(source, "ban_duration_secs"),
            "limits.ban_duration_secs must be > 0 when ban_after_rate_limit_strikes > 0",
        ));
    }
    if !crate::audit::valid_audit_path(&cfg.limits.ban_share_path) {
        return Err(err(
            find_line(source, &cfg.limits.ban_share_path),
            "limits.ban_share_path must be empty or a local file path",
        ));
    }
    if !crate::audit::valid_audit_path(&cfg.limits.ban_share_secret_file) {
        return Err(err(
            find_line(source, &cfg.limits.ban_share_secret_file),
            "limits.ban_share_secret_file must be empty or a local file path",
        ));
    }
    if !cfg.limits.ban_share_path.trim().is_empty() {
        // Fail-closed: path requires a secret from env / file / inline.
        let env_ok = std::env::var("SEDAT_BAN_SHARE_SECRET")
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let file_ok = {
            let f = cfg.limits.ban_share_secret_file.trim();
            !f.is_empty()
                && std::fs::read_to_string(f)
                    .map(|c| !c.trim().is_empty())
                    .unwrap_or(false)
        };
        let inline_ok = !cfg.limits.ban_share_secret.trim().is_empty();
        if !env_ok && !file_ok && !inline_ok {
            return Err(err(
                find_line(source, "ban_share_path"),
                "limits.ban_share_path requires SEDAT_BAN_SHARE_SECRET, ban_share_secret_file, or ban_share_secret (fail-closed)",
            ));
        }
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

/// True if `s` is a valid IP/CIDR or hostname token for allowlists / pins.
#[must_use]
pub fn is_allowlist_entry(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() {
        return false;
    }
    parse_cidr(t).is_ok() || host_re().is_match(t)
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

/// True if `ip` lies in `net`/`prefix`.
#[must_use]
pub fn ip_in_cidr(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
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

    #[test]
    fn allowlist_entry_accepts_hostname() {
        assert!(is_allowlist_entry("10.0.0.0/8"));
        assert!(is_allowlist_entry("127.0.0.1"));
        assert!(is_allowlist_entry("backend.internal"));
        assert!(is_allowlist_entry("localhost"));
        assert!(!is_allowlist_entry("bad host!!"));
        assert!(!is_allowlist_entry(""));
    }

    #[test]
    fn allows_hostname_in_upstream_allowlist() {
        let toml = r#"
schema_version = 1
[[routes.hosts]]
host = "localhost"
[[routes.hosts.paths]]
prefix = "/"
upstream = "http://127.0.0.1:9080"
upstream_allowlist = ["backend.internal", "10.0.0.0/8"]
upstream_dns_refresh_secs = 30
"#;
        parse_toml(toml).expect("hostname pin should validate");
    }

    #[test]
    fn allows_https_upstream_without_mtls() {
        let toml = r#"
schema_version = 1
[[routes.hosts]]
host = "localhost"
[[routes.hosts.paths]]
prefix = "/"
upstream = "https://127.0.0.1:9443"
"#;
        parse_toml(toml).expect("https upstream should validate");
    }

    #[test]
    fn rejects_mtls_on_http_upstream() {
        let toml = r#"
schema_version = 1
[[routes.hosts]]
host = "localhost"
[[routes.hosts.paths]]
prefix = "/"
upstream = "http://127.0.0.1:9080"
upstream_mtls_cert = "/tmp/client.crt"
upstream_mtls_key = "/tmp/client.key"
"#;
        let err = parse_toml(toml).unwrap_err();
        assert!(
            err.to_string().contains("https://") || err.to_string().contains("upstream_mtls"),
            "{err}"
        );
    }
}
