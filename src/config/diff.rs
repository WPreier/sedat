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
    // Do not log raw token values — only whether a token is configured.
    push(
        &mut out,
        "server.admin_token_set",
        &(!old.server.admin_token.trim().is_empty()).to_string(),
        &(!new.server.admin_token.trim().is_empty()).to_string(),
    );
    push(
        &mut out,
        "server.admin_token_file",
        &old.server.admin_token_file,
        &new.server.admin_token_file,
    );
    push(
        &mut out,
        "server.admin_token_overlap_secs",
        &old.server.admin_token_overlap_secs.to_string(),
        &new.server.admin_token_overlap_secs.to_string(),
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
        "acme.dns_webhook_url",
        &old.acme.dns_webhook_url,
        &new.acme.dns_webhook_url,
    );
    push(
        &mut out,
        "acme.cloudflare_zone_id",
        &old.acme.cloudflare_zone_id.clone().unwrap_or_default(),
        &new.acme.cloudflare_zone_id.clone().unwrap_or_default(),
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
        "limits.ban_after_rate_limit_strikes",
        &old.limits.ban_after_rate_limit_strikes.to_string(),
        &new.limits.ban_after_rate_limit_strikes.to_string(),
    );
    push(
        &mut out,
        "limits.ban_duration_secs",
        &old.limits.ban_duration_secs.to_string(),
        &new.limits.ban_duration_secs.to_string(),
    );
    push(
        &mut out,
        "limits.ban_extend_while_banned",
        &old.limits.ban_extend_while_banned.to_string(),
        &new.limits.ban_extend_while_banned.to_string(),
    );
    push(
        &mut out,
        "limits.ban_extend_min_interval_secs",
        &old.limits.ban_extend_min_interval_secs.to_string(),
        &new.limits.ban_extend_min_interval_secs.to_string(),
    );
    push(
        &mut out,
        "limits.ban_share_path",
        &old.limits.ban_share_path,
        &new.limits.ban_share_path,
    );
    push(
        &mut out,
        "limits.ban_share_secret_set",
        &(!old.limits.ban_share_secret.trim().is_empty()).to_string(),
        &(!new.limits.ban_share_secret.trim().is_empty()).to_string(),
    );
    push(
        &mut out,
        "limits.ban_share_secret_file",
        &old.limits.ban_share_secret_file,
        &new.limits.ban_share_secret_file,
    );
    push(
        &mut out,
        "limits.ban_share_poll_secs",
        &old.limits.ban_share_poll_secs.to_string(),
        &new.limits.ban_share_poll_secs.to_string(),
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
    push(
        &mut out,
        "logging.audit_jsonl_max_age_secs",
        &old.logging.audit_jsonl_max_age_secs.to_string(),
        &new.logging.audit_jsonl_max_age_secs.to_string(),
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
            let pin = if p.upstream_allowlist.is_empty() {
                String::new()
            } else {
                format!(
                    "[{}]@{}s",
                    p.upstream_allowlist.join(","),
                    p.upstream_dns_refresh_secs
                )
            };
            parts.push(format!("{}{}→{}{}", h.host, p.prefix, p.upstream, pin));
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

/// Process-bound knobs that cannot be applied by live reload (P15.3).
///
/// Captured once at boot so operators can see when a successful `reload` still
/// requires a process restart for listen/sandbox/metrics/ACME-cold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartOnlySnapshot {
    /// Bound plain HTTP listen address.
    pub listen: String,
    /// Bound HTTPS listen address.
    pub listen_tls: String,
    /// Bound HTTP→HTTPS redirect listen address.
    pub http_redirect_listen: String,
    /// Metrics sidecar bind (`None`/empty = not started).
    pub metrics_listen: String,
    /// Landlock mode applied at boot.
    pub landlock: String,
    /// Seccomp mode applied at boot.
    pub seccomp: String,
    /// Whether an ACME renewal loop was started at boot.
    pub acme_started: bool,
}

impl RestartOnlySnapshot {
    /// Snapshot restart-only fields from the config used to start the process.
    #[must_use]
    pub fn from_boot(cfg: &SedatConfig, acme_started: bool) -> Self {
        Self {
            listen: cfg.server.listen.clone(),
            listen_tls: cfg.server.listen_tls.clone(),
            http_redirect_listen: cfg.server.http_redirect_listen.clone(),
            metrics_listen: cfg.server.metrics_listen.clone().unwrap_or_default(),
            landlock: cfg.hardening.landlock.clone(),
            seccomp: cfg.hardening.seccomp.clone(),
            acme_started,
        }
    }
}

/// Stable Prometheus label set for restart-only knobs (P16.1).
///
/// Always emitted as `sedat_restart_required{key="…"}` so scrapers see a fixed
/// series cardinality (0 = applied / matching boot, 1 = restart still required).
pub const RESTART_ONLY_KEYS: &[&str] = &[
    "server.listen",
    "server.listen_tls",
    "server.http_redirect_listen",
    "server.metrics_listen",
    "hardening.landlock",
    "hardening.seccomp",
    "acme.enable",
];

/// Keys that changed vs boot and still need a process restart to take effect.
#[must_use]
pub fn restart_required_keys(boot: &RestartOnlySnapshot, cfg: &SedatConfig) -> Vec<&'static str> {
    let mut keys = Vec::new();
    if boot.listen != cfg.server.listen {
        keys.push("server.listen");
    }
    if boot.listen_tls != cfg.server.listen_tls {
        keys.push("server.listen_tls");
    }
    if boot.http_redirect_listen != cfg.server.http_redirect_listen {
        keys.push("server.http_redirect_listen");
    }
    let metrics = cfg.server.metrics_listen.clone().unwrap_or_default();
    if boot.metrics_listen != metrics {
        keys.push("server.metrics_listen");
    }
    if boot.landlock != cfg.hardening.landlock {
        keys.push("hardening.landlock");
    }
    if boot.seccomp != cfg.hardening.seccomp {
        keys.push("hardening.seccomp");
    }
    if !boot.acme_started && cfg.acme.enabled {
        keys.push("acme.enable");
    }
    keys
}

/// Per-key 0/1 values for Prometheus (`1` = restart required for that key).
#[must_use]
pub fn restart_required_gauges(
    boot: &RestartOnlySnapshot,
    cfg: &SedatConfig,
) -> Vec<(&'static str, u8)> {
    let drift = restart_required_keys(boot, cfg);
    RESTART_ONLY_KEYS
        .iter()
        .map(|&key| (key, u8::from(drift.contains(&key))))
        .collect()
}

/// Compact suffix for admin reload/status replies (` restart_required=a,b` or empty).
#[must_use]
pub fn format_restart_required_note(keys: &[&str]) -> String {
    if keys.is_empty() {
        String::new()
    } else {
        format!(" restart_required={}", keys.join(","))
    }
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

    #[test]
    fn restart_required_detects_listen_and_acme_cold() {
        let a = parse_toml(crate::DEFAULT_CONFIG_TOML).unwrap();
        let boot = RestartOnlySnapshot::from_boot(&a, false);
        assert!(restart_required_keys(&boot, &a).is_empty());

        let mut b = a.clone();
        b.server.listen = "127.0.0.1:18080".into();
        b.hardening.seccomp = "required".into();
        b.acme.enabled = true;
        let keys = restart_required_keys(&boot, &b);
        assert!(keys.contains(&"server.listen"));
        assert!(keys.contains(&"hardening.seccomp"));
        assert!(keys.contains(&"acme.enable"));
        assert_eq!(
            format_restart_required_note(&keys),
            format!(" restart_required={}", keys.join(","))
        );
    }

    #[test]
    fn restart_required_skips_acme_when_loop_started() {
        let a = parse_toml(crate::DEFAULT_CONFIG_TOML).unwrap();
        let boot = RestartOnlySnapshot::from_boot(&a, true);
        let mut b = a.clone();
        b.acme.enabled = true;
        assert!(!restart_required_keys(&boot, &b).contains(&"acme.enable"));
    }

    #[test]
    fn restart_required_gauges_fixed_cardinality() {
        let a = parse_toml(crate::DEFAULT_CONFIG_TOML).unwrap();
        let boot = RestartOnlySnapshot::from_boot(&a, false);
        let gauges = restart_required_gauges(&boot, &a);
        assert_eq!(gauges.len(), RESTART_ONLY_KEYS.len());
        assert!(gauges.iter().all(|(_, v)| *v == 0));

        let mut b = a.clone();
        b.server.listen = "127.0.0.1:18080".into();
        let gauges = restart_required_gauges(&boot, &b);
        assert_eq!(gauges.len(), RESTART_ONLY_KEYS.len());
        let listen = gauges
            .iter()
            .find(|(k, _)| *k == "server.listen")
            .unwrap();
        assert_eq!(listen.1, 1);
        assert!(gauges
            .iter()
            .filter(|(k, _)| *k != "server.listen")
            .all(|(_, v)| *v == 0));
    }
}
