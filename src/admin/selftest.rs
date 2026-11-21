//! Admin `selftest` — structured runtime health checks for operators.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use serde_json::json;

use crate::admin::AdminState;
use crate::config::{is_allowlist_entry, parse_cidr, CURRENT_SCHEMA_VERSION};
use crate::proxy::encode_proxy_v2;
use crate::tls::ensure_crypto_provider;

/// Cap concurrent upstream probes so admin socket stays responsive.
const MAX_UPSTREAM_PROBES: usize = 3;
/// Per-step timeout (DNS resolve, TCP connect, TLS handshake).
const PROBE_TIMEOUT: Duration = Duration::from_millis(400);

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

    /// Wire format for the admin socket (human-readable).
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

    /// Machine-readable JSON body (plus OK/ERR header line).
    #[must_use]
    pub fn format_reply_json(&self) -> String {
        let checks: Vec<_> = self
            .checks
            .iter()
            .map(|c| {
                json!({
                    "name": c.name,
                    "ok": c.ok,
                    "detail": c.detail,
                })
            })
            .collect();
        let body = json!({
            "ok": self.ok(),
            "uptime_secs": self.uptime_secs,
            "failed": self.failed_names(),
            "checks": checks,
        });
        let header = if self.ok() {
            "OK selftest json\n".to_string()
        } else {
            format!(
                "ERR selftest json failed={}\n",
                self.failed_names().join(",")
            )
        };
        format!("{header}{body}\n")
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

    let token_required = state.tokens.is_required();
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

    checks.push(check_allowlists(&cfg));
    checks.extend(probe_upstreams(&cfg));

    let uptime_secs = state.started_at.elapsed().as_secs();
    checks.push(check("uptime", true, format!("secs={uptime_secs}")));

    SelftestReport {
        checks,
        uptime_secs,
    }
}

fn check_allowlists(cfg: &crate::config::SedatConfig) -> SelftestCheck {
    let mut bad = Vec::new();
    let mut n_proxy = 0usize;
    let mut n_up = 0usize;

    if cfg.proxy_protocol.inbound_enabled {
        if cfg.proxy_protocol.inbound_allowlist.is_empty() {
            bad.push("inbound_allowlist empty while inbound_enabled".into());
        }
        for e in &cfg.proxy_protocol.inbound_allowlist {
            n_proxy += 1;
            if parse_cidr(e).is_err() {
                bad.push(format!("inbound_allowlist unparseable `{e}`"));
            }
        }
    } else {
        for e in &cfg.proxy_protocol.inbound_allowlist {
            n_proxy += 1;
            if parse_cidr(e).is_err() {
                bad.push(format!("inbound_allowlist unparseable `{e}`"));
            }
        }
    }

    for host in &cfg.routes.hosts {
        for path in &host.paths {
            for e in &path.upstream_allowlist {
                n_up += 1;
                if !is_allowlist_entry(e) {
                    bad.push(format!(
                        "upstream_allowlist host={} prefix={} unparseable `{e}`",
                        host.host, path.prefix
                    ));
                }
            }
        }
    }

    if bad.is_empty() {
        check(
            "allowlists",
            true,
            format!("ok proxy_entries={n_proxy} upstream_entries={n_up}"),
        )
    } else {
        check(
            "allowlists",
            false,
            format!("bad={} sample={}", bad.len(), bad.first().unwrap()),
        )
    }
}

#[derive(Clone)]
struct UpstreamTarget {
    label: String,
    host: String,
    port: u16,
    https: bool,
}

fn collect_upstream_targets(cfg: &crate::config::SedatConfig) -> Vec<UpstreamTarget> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for host in &cfg.routes.hosts {
        for path in &host.paths {
            if out.len() >= MAX_UPSTREAM_PROBES {
                return out;
            }
            let Ok(uri) = path.upstream.parse::<http::Uri>() else {
                continue;
            };
            let scheme = uri.scheme_str().unwrap_or("http");
            let https = scheme.eq_ignore_ascii_case("https");
            let Some(auth) = uri.authority() else {
                continue;
            };
            let h = auth.host().to_string();
            let port = auth.port_u16().unwrap_or(if https { 443 } else { 80 });
            let key = format!("{h}:{port}:{https}");
            if !seen.insert(key) {
                continue;
            }
            out.push(UpstreamTarget {
                label: format!("{}{} -> {}", host.host, path.prefix, path.upstream),
                host: h,
                port,
                https,
            });
        }
    }
    out
}

fn resolve_addrs(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let (tx, rx) = mpsc::channel();
    let host = host.to_string();
    std::thread::Builder::new()
        .name("sedat-selftest-dns".into())
        .spawn(move || {
            let res = format!("{host}:{port}")
                .to_socket_addrs()
                .map(|i| i.collect::<Vec<_>>())
                .map_err(|e| e.to_string());
            let _ = tx.send(res);
        })
        .map_err(|e| e.to_string())?;
    match rx.recv_timeout(PROBE_TIMEOUT) {
        Ok(Ok(addrs)) if !addrs.is_empty() => Ok(addrs),
        Ok(Ok(_)) => Err("no addresses".into()),
        Ok(Err(e)) => Err(e),
        Err(_) => Err("dns timeout".into()),
    }
}

fn tcp_connect(addrs: &[SocketAddr]) -> Result<TcpStream, String> {
    let mut last = "no address".to_string();
    for addr in addrs.iter().take(3) {
        match TcpStream::connect_timeout(addr, PROBE_TIMEOUT) {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(PROBE_TIMEOUT));
                let _ = s.set_write_timeout(Some(PROBE_TIMEOUT));
                return Ok(s);
            }
            Err(e) => last = format!("{addr}: {e}"),
        }
    }
    Err(last)
}

fn tls_alpn_probe(host: &str, stream: TcpStream) -> Result<String, String> {
    ensure_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let server_name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    let conn =
        rustls::ClientConnection::new(Arc::new(config), server_name).map_err(|e| e.to_string())?;
    let mut sock = stream;
    let mut conn = conn;
    let deadline = Instant::now() + PROBE_TIMEOUT;
    while conn.is_handshaking() {
        if Instant::now() >= deadline {
            return Err("tls handshake timeout".into());
        }
        match conn.complete_io(&mut sock) {
            Ok((0, 0)) => return Err("tls handshake stalled".into()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    let alpn = conn
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_else(|| "none".into());
    let _ = sock.shutdown(std::net::Shutdown::Both);
    Ok(alpn)
}

fn probe_upstreams(cfg: &crate::config::SedatConfig) -> Vec<SelftestCheck> {
    let targets = collect_upstream_targets(cfg);
    if targets.is_empty() {
        return vec![
            check("upstream_tcp", true, "skipped=no_routes"),
            check("upstream_tls_alpn", true, "skipped=no_https_routes"),
        ];
    }

    let mut tcp_ok = 0usize;
    let mut tcp_fail = 0usize;
    let mut tcp_notes = Vec::new();
    let mut tls_ok = 0usize;
    let mut tls_fail = 0usize;
    let mut tls_skip = 0usize;
    let mut tls_notes = Vec::new();

    for t in &targets {
        match resolve_addrs(&t.host, t.port).and_then(|a| tcp_connect(&a)) {
            Ok(stream) => {
                tcp_ok += 1;
                if t.https {
                    match tls_alpn_probe(&t.host, stream) {
                        Ok(alpn) => {
                            tls_ok += 1;
                            tls_notes.push(format!("{} alpn={alpn}", t.label));
                        }
                        Err(e) => {
                            tls_fail += 1;
                            tls_notes.push(format!("{} err={e}", t.label));
                        }
                    }
                } else {
                    tls_skip += 1;
                    drop(stream);
                }
            }
            Err(e) => {
                tcp_fail += 1;
                tcp_notes.push(format!("{} err={e}", t.label));
                if t.https {
                    tls_fail += 1;
                    tls_notes.push(format!("{} skipped=tcp_failed", t.label));
                } else {
                    tls_skip += 1;
                }
            }
        }
    }

    let tcp_detail = if tcp_fail == 0 {
        format!(
            "ok={tcp_ok} fail=0 probed={} sample={}",
            targets.len(),
            targets.first().map(|t| t.label.as_str()).unwrap_or("-")
        )
    } else {
        format!(
            "ok={tcp_ok} fail={tcp_fail} sample={}",
            tcp_notes.first().cloned().unwrap_or_default()
        )
    };

    let tls_detail = if targets.iter().all(|t| !t.https) {
        format!("skipped=no_https_routes http_only={tls_skip}")
    } else if tls_fail == 0 {
        format!(
            "ok={tls_ok} fail=0 skip={tls_skip} sample={}",
            tls_notes.first().cloned().unwrap_or_else(|| "-".into())
        )
    } else {
        format!(
            "ok={tls_ok} fail={tls_fail} skip={tls_skip} sample={}",
            tls_notes.first().cloned().unwrap_or_default()
        )
    };

    vec![
        check("upstream_tcp", tcp_fail == 0, tcp_detail),
        check("upstream_tls_alpn", tls_fail == 0, tls_detail),
    ]
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
        let tokens = crate::admin::LiveAdminTokens::from_config(&cfg);
        AdminState {
            user_config: "x".into(),
            state_dir: cfg.server.state_dir.clone().into(),
            config: Arc::new(ArcSwap::from_pointee(cfg)),
            tokens,
            limiter: Limiter::new(Default::default()),
            tls: None,
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
        assert!(reply.contains("PASS allowlists"));
        assert!(reply.contains("PASS upstream_tcp"));
        assert!(reply.contains("PASS upstream_tls_alpn"));
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

    #[test]
    fn selftest_json_and_allowlists() {
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
        cfg.server.admin_socket = dir.path().join("a.sock").to_string_lossy().into();
        cfg.proxy_protocol.inbound_allowlist = vec!["10.0.0.0/8".into(), "not-a-cidr".into()];
        let state = state_with_cfg(cfg);
        let report = run_selftest(&state);
        assert!(
            report.failed_names().contains(&"allowlists".into()),
            "failed={:?}",
            report.failed_names()
        );
        let json = report.format_reply_json();
        assert!(json.contains("\"ok\":false"), "{json}");
        assert!(json.contains("\"name\":\"allowlists\""), "{json}");
        assert!(json.starts_with("ERR selftest json"), "{json}");
    }

    #[test]
    fn selftest_tcp_to_local_listener() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _accept = std::thread::spawn(move || {
            let _ = listener.accept();
        });

        let dir = tempfile::tempdir().unwrap();
        let mut cfg = SedatConfig {
            schema_version: CURRENT_SCHEMA_VERSION,
            server: Default::default(),
            tls: Default::default(),
            acme: Default::default(),
            routes: crate::config::RoutesConfig {
                hosts: vec![crate::config::HostRoute {
                    host: "localhost".into(),
                    paths: vec![crate::config::PathRoute {
                        prefix: "/".into(),
                        upstream: format!("http://{addr}"),
                        ..Default::default()
                    }],
                }],
            },
            proxy_protocol: Default::default(),
            limits: Default::default(),
            embedded_docs: Default::default(),
            experimental: Default::default(),
            logging: Default::default(),
            hardening: Default::default(),
        };
        cfg.server.state_dir = dir.path().to_string_lossy().into();
        cfg.server.admin_socket = dir.path().join("a.sock").to_string_lossy().into();
        let state = state_with_cfg(cfg);
        let report = run_selftest(&state);
        let tcp = report
            .checks
            .iter()
            .find(|c| c.name == "upstream_tcp")
            .unwrap();
        assert!(tcp.ok, "upstream_tcp detail={}", tcp.detail);
        assert!(report.checks.iter().any(|c| c.name == "allowlists" && c.ok));
    }
}
