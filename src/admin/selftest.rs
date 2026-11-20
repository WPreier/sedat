//! Admin `selftest` — structured runtime health checks for operators.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Instant;

use crate::admin::auth::resolve_admin_token;
use crate::admin::AdminState;
use crate::config::CURRENT_SCHEMA_VERSION;
use crate::proxy::encode_proxy_v2;

/// One selftest check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelftestCheck {
    /// Short check id.
    pub name: &'static str,
    /// Whether the check passed.
    pub ok: bool,
    /// Human-readable detail (no secrets).
    pub detail: String,
}

/// Full selftest report.
#[derive(Debug, Clone)]
pub struct SelftestReport {
    /// Individual checks.
    pub checks: Vec<SelftestCheck>,
    /// Process uptime.
    pub uptime_secs: u64,
}

impl SelftestReport {
    /// True when every check passed.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }

    /// Names of failed checks.
    #[must_use]
    pub fn failed_names(&self) -> Vec<String> {
        self.checks
            .iter()
            .filter(|c| !c.ok)
            .map(|c| c.name.to_string())
            .collect()
    }

    /// Wire format for the admin socket.
    #[must_use]
    pub fn format_reply(&self) -> String {
        let mut out = String::new();
        if self.ok() {
            out.push_str("OK selftest\n");
        } else {
            out.push_str(&format!(
                "ERR selftest failed={}\n",
                self.failed_names().join(",")
            ));
        }
        out.push_str(&format!("uptime_secs={}\n", self.uptime_secs));
        for c in &self.checks {
            let mark = if c.ok { "PASS" } else { "FAIL" };
            out.push_str(&format!("{mark} {} {}\n", c.name, c.detail));
        }
        out
    }
}

fn check(name: &'static str, ok: bool, detail: impl Into<String>) -> SelftestCheck {
    SelftestCheck {
        name,
        ok,
        detail: detail.into(),
    }
}

/// Run operator selftest against live admin state.
#[must_use]
pub fn run_selftest(state: &AdminState) -> SelftestReport {
    let cfg = state.config.load();
    let mut checks = Vec::new();

    checks.push(check(
        "schema_version",
        cfg.schema_version == CURRENT_SCHEMA_VERSION,
        format!(
            "active={} expected={}",
            cfg.schema_version, CURRENT_SCHEMA_VERSION
        ),
    ));

    for (name, addr) in [
        ("listen", cfg.server.listen.as_str()),
        ("listen_tls", cfg.server.listen_tls.as_str()),
        (
            "http_redirect_listen",
            cfg.server.http_redirect_listen.as_str(),
        ),
    ] {
        let ok = addr.parse::<SocketAddr>().is_ok();
        checks.push(check(
            name,
            ok,
            if ok {
                format!("parseable={addr}")
            } else {
                format!("unparseable={addr}")
            },
        ));
    }

    let state_dir = Path::new(&cfg.server.state_dir);
    checks.push(check(
        "state_dir",
        state_dir.is_dir() || state_dir.exists(),
        format!("path={}", state_dir.display()),
    ));

    let sock = Path::new(&cfg.server.admin_socket);
    let sock_parent_ok = sock
        .parent()
        .map(|p| p.as_os_str().is_empty() || p.exists() || p == Path::new("."))
        .unwrap_or(true);
    checks.push(check(
        "admin_socket_parent",
        sock_parent_ok,
        format!("socket={}", sock.display()),
    ));

    let token_required = resolve_admin_token(&cfg).is_some();
    checks.push(check(
        "admin_auth",
        true, // configuration presence is informational; both modes are valid
        if token_required {
            "token_required=true"
        } else {
            "token_required=false (FS ACL only)"
        },
    ));

    checks.push(check(
        "proxy_outbound",
        matches!(cfg.proxy_protocol.outbound.as_str(), "off" | "v1" | "v2"),
        format!("outbound={}", cfg.proxy_protocol.outbound),
    ));

    let placement_ok = matches!(
        cfg.proxy_protocol.inbound_placement.as_str(),
        "before_tls" | "after_tls"
    );
    checks.push(check(
        "proxy_inbound_placement",
        placement_ok,
        format!("placement={}", cfg.proxy_protocol.inbound_placement),
    ));

    let client: SocketAddr = "203.0.113.10:443".parse().unwrap();
    let server: SocketAddr = "198.51.100.1:443".parse().unwrap();
    let v2 = encode_proxy_v2(client, server);
    checks.push(check(
        "proxy_v2_encode",
        v2.len() >= 16 && v2.starts_with(crate::proxy::PROXY_V2_SIG),
        format!("bytes={}", v2.len()),
    ));

    checks.push(check(
        "limits_connections",
        cfg.limits.max_connections > 0,
        format!(
            "max={} active={}",
            cfg.limits.max_connections,
            state.limiter.active_connections()
        ),
    ));
    checks.push(check(
        "limits_rate",
        cfg.limits.rate_limit_per_ip > 0 && cfg.limits.rate_limit_burst > 0,
        format!(
            "per_ip={} burst={}",
            cfg.limits.rate_limit_per_ip, cfg.limits.rate_limit_burst
        ),
    ));

    let tls_on = cfg.tls.enabled || cfg.acme.enabled;
    if let Some(ref cert) = cfg.tls.cert_path {
        let p = Path::new(cert);
        checks.push(check(
            "tls_cert_path",
            !tls_on || p.is_file(),
            format!("path={cert} exists={}", p.is_file()),
        ));
    } else {
        checks.push(check(
            "tls_cert_path",
            true,
            if tls_on {
                "no static cert_path (ACME or ephemeral ok)"
            } else {
                "tls disabled"
            },
        ));
    }
    if let Some(ref key) = cfg.tls.key_path {
        let p = Path::new(key);
        checks.push(check(
            "tls_key_path",
            !tls_on || p.is_file(),
            format!("path={key} exists={}", p.is_file()),
        ));
    } else {
        checks.push(check(
            "tls_key_path",
            true,
            if tls_on {
                "no static key_path (ACME or ephemeral ok)"
            } else {
                "tls disabled"
            },
        ));
    }

    if let Some(ref st) = state.acme_status {
        let s = st.lock();
        checks.push(check(
            "acme_status",
            s.last_error.is_none() || s.last_success_unix.is_some(),
            format!(
                "directory={} last_success={:?} last_error={:?}",
                s.directory, s.last_success_unix, s.last_error
            ),
        ));
    } else {
        checks.push(check(
            "acme_status",
            true,
            if cfg.acme.enabled {
                "acme enabled but status handle unset"
            } else {
                "acme disabled"
            },
        ));
    }

    checks.push(check(
        "audit_jsonl",
        true,
        if state.audit.enabled() {
            format!("enabled path={:?}", state.audit.path())
        } else {
            "disabled".into()
        },
    ));

    let uptime_secs = state.started_at.elapsed().as_secs();
    checks.push(check(
        "uptime",
        true,
        format!("secs={uptime_secs}"),
    ));

    SelftestReport {
        checks,
        uptime_secs,
    }
}

/// Process start marker used for uptime (shared helper for AdminState construction).
#[must_use]
pub fn now_start() -> Instant {
    Instant::now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditSink;
    use crate::config::SedatConfig;
    use crate::limits::Limiter;
    use arc_swap::ArcSwap;
    use std::sync::Arc;

    fn state_with_cfg(cfg: SedatConfig) -> AdminState {
        AdminState {
            user_config: "x".into(),
            state_dir: cfg.server.state_dir.clone().into(),
            config: Arc::new(ArcSwap::from_pointee(cfg)),
            limiter: Limiter::new(Default::default()),
            acme_status: None,
            audit: AuditSink::disabled(),
            started_at: now_start(),
        }
    }

    #[test]
    fn selftest_passes_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = SedatConfig {
            schema_version: CURRENT_SCHEMA_VERSION,
            server: Default::default(),
            tls: Default::default(),
            acme: Default::default(),
            routes: Default::default(),
            proxy_protocol: Default::default(),
            limits: Default::default(),
            embedded_docs: Default::default(),
            experimental: Default::default(),
            logging: Default::default(),
            hardening: Default::default(),
        };
        cfg.server.state_dir = dir.path().to_string_lossy().into();
        cfg.server.admin_socket = dir.path().join("admin.sock").to_string_lossy().into();
        let state = state_with_cfg(cfg);
        let report = run_selftest(&state);
        assert!(report.ok(), "failed={:?}", report.failed_names());
        let reply = report.format_reply();
        assert!(reply.starts_with("OK selftest\n"), "{reply}");
        assert!(reply.contains("PASS proxy_v2_encode"));
    }

    #[test]
    fn selftest_fails_bad_schema() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = SedatConfig {
            schema_version: 999,
            server: Default::default(),
            tls: Default::default(),
            acme: Default::default(),
            routes: Default::default(),
            proxy_protocol: Default::default(),
            limits: Default::default(),
            embedded_docs: Default::default(),
            experimental: Default::default(),
            logging: Default::default(),
            hardening: Default::default(),
        };
        cfg.server.state_dir = dir.path().to_string_lossy().into();
        let state = state_with_cfg(cfg);
        let report = run_selftest(&state);
        assert!(!report.ok());
        assert!(report.failed_names().contains(&"schema_version".into()));
    }
}
