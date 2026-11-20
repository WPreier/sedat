//! Security-relevant config diff for reload audit logging.

use crate::config::SedatConfig;

/// One trust-boundary / security-relevant change between configs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityChange {
    /// Dotted config key path.
    pub key: String,
    /// Previous value (display form).
    pub old: String,
    /// New value (display form).
    pub new: String,
}

/// Diff security-relevant fields. Fail-closed reload logic is unchanged — this is audit only.
#[must_use]
pub fn security_diff(old: &SedatConfig, new: &SedatConfig) -> Vec<SecurityChange> {
    let mut out = Vec::new();
    push(
        &mut out,
        "server.listen",
        &old.server.listen,
        &new.server.listen,
    );
    push(
        &mut out,
        "server.listen_tls",
        &old.server.listen_tls,
        &new.server.listen_tls,
    );
    push(
        &mut out,
        "server.http_redirect_listen",
        &old.server.http_redirect_listen,
        &new.server.http_redirect_listen,
    );
    push_opt(
        &mut out,
        "server.user",
        old.server.user.as_deref(),
        new.server.user.as_deref(),
    );
    push_opt(
        &mut out,
        "server.group",
        old.server.group.as_deref(),
        new.server.group.as_deref(),
    );
    push(
        &mut out,
        "server.state_dir",
        &old.server.state_dir,
        &new.server.state_dir,
    );
    push(
        &mut out,
        "server.admin_socket",
        &old.server.admin_socket,
        &new.server.admin_socket,
    );
    push_opt(
        &mut out,
        "server.admin_group",
        old.server.admin_group.as_deref(),
        new.server.admin_group.as_deref(),
    );
    push_opt(
        &mut out,
        "server.metrics_listen",
        old.server.metrics_listen.as_deref(),
        new.server.metrics_listen.as_deref(),
    );

    push(
        &mut out,
        "proxy_protocol.outbound",
        &old.proxy_protocol.outbound,
        &new.proxy_protocol.outbound,
    );
    push(
        &mut out,
        "proxy_protocol.inbound_enabled",
        &old.proxy_protocol.inbound_enabled.to_string(),
        &new.proxy_protocol.inbound_enabled.to_string(),
    );
    push(
        &mut out,
        "proxy_protocol.inbound_placement",
        &old.proxy_protocol.inbound_placement,
        &new.proxy_protocol.inbound_placement,
    );
    push(
        &mut out,
        "proxy_protocol.inbound_allowlist",
        &format!("{:?}", old.proxy_protocol.inbound_allowlist),
        &format!("{:?}", new.proxy_protocol.inbound_allowlist),
    );

    push(
        &mut out,
        "tls.enabled",
        &old.tls.enabled.to_string(),
        &new.tls.enabled.to_string(),
    );
    push_opt(
        &mut out,
        "tls.cert_path",
        old.tls.cert_path.as_deref(),
        new.tls.cert_path.as_deref(),
    );
    push_opt(
        &mut out,
        "tls.key_path",
        old.tls.key_path.as_deref(),
        new.tls.key_path.as_deref(),
    );

    push(
        &mut out,
        "acme.enabled",
        &old.acme.enabled.to_string(),
        &new.acme.enabled.to_string(),
    );
    push(
        &mut out,
        "acme.directory",
        &old.acme.directory,
        &new.acme.directory,
    );
    push(
        &mut out,
        "acme.domains",
        &format!("{:?}", old.acme.domains),
        &format!("{:?}", new.acme.domains),
    );
    push(
        &mut out,
        "acme.dns_provider",
        &old.acme.dns_provider,
        &new.acme.dns_provider,
    );

    push(
        &mut out,
        "hardening.landlock",
        &old.hardening.landlock,
        &new.hardening.landlock,
    );
    push(
        &mut out,
        "hardening.seccomp",
        &old.hardening.seccomp,
        &new.hardening.seccomp,
    );

    push(
        &mut out,
        "limits.max_connections",
        &old.limits.max_connections.to_string(),
        &new.limits.max_connections.to_string(),
    );
    push(
        &mut out,
        "limits.max_header_bytes",
        &old.limits.max_header_bytes.to_string(),
        &new.limits.max_header_bytes.to_string(),
    );
    push(
        &mut out,
        "limits.max_body_bytes",
        &old.limits.max_body_bytes.to_string(),
        &new.limits.max_body_bytes.to_string(),
    );
    push(
        &mut out,
        "limits.rate_limit_per_ip",
        &old.limits.rate_limit_per_ip.to_string(),
        &new.limits.rate_limit_per_ip.to_string(),
    );

    push(
        &mut out,
        "experimental.h3",
        &old.experimental.h3.to_string(),
        &new.experimental.h3.to_string(),
    );

    push(
        &mut out,
        "logging.request_id",
        &old.logging.request_id.to_string(),
        &new.logging.request_id.to_string(),
    );
    push(
        &mut out,
        "logging.request_id_header",
        &old.logging.request_id_header,
        &new.logging.request_id_header,
    );
    push(
        &mut out,
        "logging.audit_jsonl",
        &old.logging.audit_jsonl,
        &new.logging.audit_jsonl,
    );
    push(
        &mut out,
        "logging.audit_jsonl_max_bytes",
        &old.logging.audit_jsonl_max_bytes.to_string(),
        &new.logging.audit_jsonl_max_bytes.to_string(),
    );

    // Route upstreams — compact summary of host→upstream pairs.
    let old_routes = route_summary(old);
    let new_routes = route_summary(new);
    push(&mut out, "routes.upstreams", &old_routes, &new_routes);

    out
}

fn route_summary(cfg: &SedatConfig) -> String {
    let mut parts = Vec::new();
    for h in &cfg.routes.hosts {
        for p in &h.paths {
            parts.push(format!("{}{}→{}", h.host, p.prefix, p.upstream));
        }
    }
    parts.sort();
    parts.join(";")
}

fn push(out: &mut Vec<SecurityChange>, key: &str, old: &str, new: &str) {
    if old != new {
        out.push(SecurityChange {
            key: key.into(),
            old: old.into(),
            new: new.into(),
        });
    }
}

fn push_opt(out: &mut Vec<SecurityChange>, key: &str, old: Option<&str>, new: Option<&str>) {
    let o = old.unwrap_or("");
    let n = new.unwrap_or("");
    push(out, key, o, n);
}

/// Format changes as a single-line audit summary for logs / admin reply.
#[must_use]
pub fn format_audit_summary(changes: &[SecurityChange]) -> String {
    if changes.is_empty() {
        return "no security-relevant changes".into();
    }
    changes
        .iter()
        .map(|c| format!("{}: {:?} → {:?}", c.key, c.old, c.new))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_toml;

    #[test]
    fn detects_inbound_proxy_toggle() {
        let a = parse_toml(crate::DEFAULT_CONFIG_TOML).unwrap();
        let mut b = a.clone();
        b.proxy_protocol.inbound_enabled = true;
        b.proxy_protocol.inbound_allowlist = vec!["10.0.0.0/8".into()];
        let d = security_diff(&a, &b);
        assert!(d.iter().any(|c| c.key == "proxy_protocol.inbound_enabled"));
        assert!(d
            .iter()
            .any(|c| c.key == "proxy_protocol.inbound_allowlist"));
    }

    #[test]
    fn empty_when_identical() {
        let a = parse_toml(crate::DEFAULT_CONFIG_TOML).unwrap();
        assert!(security_diff(&a, &a).is_empty());
    }
}
