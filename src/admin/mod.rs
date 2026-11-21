//! Unix-domain admin socket (status / reload / cert-info) + optional loopback metrics sidecar.

mod auth;
mod selftest;

pub use auth::{parse_auth_line, resolve_admin_token, token_matches, ADMIN_TOKEN_ENV};
pub use selftest::{now_start, run_selftest, SelftestCheck, SelftestReport};

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{info, warn};

use crate::acme::AcmeStatus;
use crate::audit::AuditSink;
use crate::config::{self, format_audit_summary, security_diff, SedatConfig};
use crate::limits::Limiter;

/// Shared admin state.
#[derive(Clone)]
pub struct AdminState {
    /// User config path.
    pub user_config: std::path::PathBuf,
    /// State directory.
    pub state_dir: std::path::PathBuf,
    /// Live config.
    pub config: Arc<ArcSwap<SedatConfig>>,
    /// Limiter for stats.
    pub limiter: Arc<Limiter>,
    /// ACME status (optional).
    pub acme_status: Option<Arc<parking_lot::Mutex<AcmeStatus>>>,
    /// Shared JSONL audit sink.
    pub audit: AuditSink,
    /// Process/admin start time (uptime for selftest).
    pub started_at: Instant,
}

/// Apply admin socket filesystem ACL: `0600` owner-only, or `0660` + group when configured.
#[cfg(unix)]
pub fn apply_admin_socket_acl(socket_path: &Path, admin_group: Option<&str>) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(gname) = admin_group {
        use nix::unistd::{chown, Gid, Group};
        let group = Group::from_name(gname)
            .map_err(std::io::Error::other)?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("admin_group `{gname}` not found"),
                )
            })?;
        chown(socket_path, None, Some(Gid::from_raw(group.gid.as_raw())))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))?;
        info!(
            path = %socket_path.display(),
            group = gname,
            mode = "0660",
            "admin socket group ACL applied"
        );
    } else {
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
        info!(
            path = %socket_path.display(),
            mode = "0600",
            "admin socket owner-only ACL applied"
        );
    }
    Ok(())
}

/// Run admin socket accept loop (Unix). On Windows, logs and returns immediately.
pub async fn serve_admin(socket_path: &Path, state: AdminState) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::net::UnixListener;

        if socket_path.exists() {
            let _ = std::fs::remove_file(socket_path);
        }
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(socket_path)?;
        let admin_group = state.config.load().server.admin_group.clone();
        if let Err(e) = apply_admin_socket_acl(socket_path, admin_group.as_deref()) {
            warn!(error = %e, "admin socket ACL failed; continuing with umask default");
        }
        info!(path = %socket_path.display(), "admin socket listening");

        loop {
            let (conn, _) = listener.accept().await?;
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_client(conn, state).await {
                    warn!(error = %e, "admin client error");
                }
            });
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (socket_path, state);
        warn!("admin Unix socket not available on this platform");
        std::future::pending::<()>().await;
        Ok(())
    }
}

/// Optional loopback-only HTTP sidecar exposing `GET /metrics` in Prometheus text format.
///
/// Binds only the configured address (validation already enforces loopback). Never a public
/// control plane — operators should firewall/deny non-loopback at the host level as well.
pub async fn serve_metrics_sidecar(addr: std::net::SocketAddr, state: AdminState) -> std::io::Result<()> {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Method, Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use http_body_util::Full;
    use bytes::Bytes;
    use std::convert::Infallible;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "metrics sidecar listening (loopback)");
    loop {
        let (stream, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            warn!(%peer, "rejected non-loopback metrics scrape");
            continue;
        }
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let state = state.clone();
                async move {
                    let resp = if req.method() == Method::GET && req.uri().path() == "/metrics" {
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(hyper::header::CONTENT_TYPE, "text/plain; version=0.0.4")
                            .body(Full::new(Bytes::from(prometheus_text(&state))))
                            .unwrap()
                    } else {
                        Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Full::new(Bytes::from_static(b"not found")))
                            .unwrap()
                    };
                    Ok::<_, Infallible>(resp)
                }
            });
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}

#[cfg(unix)]
async fn handle_client(conn: tokio::net::UnixStream, state: AdminState) -> std::io::Result<()> {
    let (reader, mut writer) = conn.into_split();
    let mut lines = BufReader::new(reader).lines();
    let mut authed = false;
    while let Some(line) = lines.next_line().await? {
        let (reply, done) = dispatch_admin_line(&state, &mut authed, &line);
        writer.write_all(reply.as_bytes()).await?;
        if done {
            break;
        }
    }
    Ok(())
}

/// Process one admin protocol line. Returns `(reply, close_connection)`.
///
/// When a token is configured, `AUTH <token>` is required before other commands
/// (except `help` / `quit`). Empty token config → FS ACL only (dev-friendly).
#[must_use]
pub fn dispatch_admin_line(state: &AdminState, authed: &mut bool, line: &str) -> (String, bool) {
    let expected = resolve_admin_token(&state.config.load());
    let token_required = expected.is_some();

    if let Some(presented) = parse_auth_line(line) {
        return match &expected {
            None => (
                "ERR auth not required (no admin token configured)\n".into(),
                false,
            ),
            Some(exp) => {
                if presented.is_empty() {
                    warn!(target: "sedat::audit", "admin AUTH missing token");
                    state.audit.emit_admin_auth_fail("missing_token");
                    *authed = false;
                    ("ERR auth failed\n".into(), false)
                } else if token_matches(presented, exp) {
                    *authed = true;
                    info!(target: "sedat::audit", "admin AUTH ok");
                    ("OK auth\n".into(), false)
                } else {
                    warn!(target: "sedat::audit", "admin AUTH failed");
                    state.audit.emit_admin_auth_fail("bad_token");
                    *authed = false;
                    ("ERR auth failed\n".into(), false)
                }
            }
        };
    }

    let trimmed = line.trim();
    let (verb, args) = match trimmed.split_once(char::is_whitespace) {
        Some((v, rest)) => (v.to_ascii_lowercase(), rest.trim()),
        None => (trimmed.to_ascii_lowercase(), ""),
    };

    if matches!(verb.as_str(), "quit" | "exit") {
        return ("OK bye\n".into(), true);
    }
    if verb == "help" {
        let help = if token_required {
            "commands: AUTH <token> | status | health | metrics | reload | cert | selftest [json] | bans | unban <ip> | quit\n"
        } else {
            "commands: status | health | metrics | reload | cert | selftest [json] | bans | unban <ip> | quit\n"
        };
        return (help.into(), false);
    }

    if token_required && !*authed {
        warn!(target: "sedat::audit", command = %verb, "admin command rejected (auth required)");
        state.audit.emit_admin_auth_fail("required");
        return ("ERR auth required (send AUTH <token> first)\n".into(), false);
    }

    let reply = match verb.as_str() {
        "status" | "stats" => format_status(state),
        "health" | "ready" => "OK healthy\n".to_string(),
        "metrics" => {
            let body = prometheus_text(state);
            format!("OK metrics\n{body}")
        }
        "reload" => match config::try_reload(&state.user_config, &state.state_dir) {
            Ok(active) => {
                let prev = state.config.load_full();
                let changes = security_diff(&prev, &active.config);
                let summary = format_audit_summary(&changes);
                for c in &changes {
                    info!(
                        target: "sedat::audit",
                        key = %c.key,
                        old = %c.old,
                        new = %c.new,
                        "config reload security diff"
                    );
                }
                if let Err(e) = state.audit.reconfigure(
                    &active.config.logging.audit_jsonl,
                    active.config.logging.audit_jsonl_max_bytes,
                ) {
                    warn!(error = %e, "audit jsonl reconfigure failed");
                }
                state.audit.emit_config_reload(&changes, &summary);
                state.config.store(Arc::new(active.config));
                format!("OK reload audit={summary}\n")
            }
            Err(e) => format!("ERR reload: {e}\n"),
        },
        "cert" | "cert-info" | "cert_info" => format_cert(state),
        "selftest" | "self-test" | "self_test" => {
            let want_json = matches!(
                args.to_ascii_lowercase().as_str(),
                "json" | "--json" | "-json"
            );
            let report = run_selftest(state);
            let failed = report.failed_names();
            state.audit.emit_admin_selftest(report.ok(), &failed);
            if report.ok() {
                info!(target: "sedat::audit", "admin selftest ok");
            } else {
                warn!(
                    target: "sedat::audit",
                    failed = %failed.join(","),
                    "admin selftest failed"
                );
            }
            if want_json {
                report.format_reply_json()
            } else {
                report.format_reply()
            }
        }
        "bans" | "ban-list" | "ban_list" => format_bans(state),
        "unban" => admin_unban(state, args),
        other => format!("ERR unknown command: {other}\n"),
    };
    (reply, false)
}

fn format_bans(state: &AdminState) -> String {
    let bans = state.limiter.list_bans();
    let mut out = format!("OK bans n={}\n", bans.len());
    for b in bans {
        out.push_str(&format!("{} remaining_secs={}\n", b.ip, b.remaining_secs));
    }
    out
}

fn admin_unban(state: &AdminState, args: &str) -> String {
    if args.is_empty() {
        return "ERR unban: usage unban <ip>\n".into();
    }
    let Ok(ip) = args.parse::<std::net::IpAddr>() else {
        return format!("ERR unban: invalid ip `{args}`\n");
    };
    if state.limiter.unban(ip) {
        info!(target: "sedat::audit", peer = %ip, "admin unban");
        state.audit.emit_admin_unban(&ip.to_string());
        format!("OK unban {ip}\n")
    } else {
        format!("ERR unban: not banned `{ip}`\n")
    }
}

fn format_status(state: &AdminState) -> String {
    let cfg = state.config.load();
    format!(
        "OK sedat {} connections={} listen={} tls_enabled={} h3={}\n",
        crate::VERSION,
        state.limiter.active_connections(),
        cfg.server.listen,
        cfg.tls.enabled || cfg.acme.enabled,
        cfg.experimental.h3
    )
}

/// Prometheus text exposition (no `OK` prefix — for sidecar `/metrics`).
pub fn prometheus_text(state: &AdminState) -> String {
    let cfg = state.config.load();
    format!(
        "# HELP sedat_info SeDat build info.\n\
         # TYPE sedat_info gauge\n\
         sedat_info{{version=\"{}\"}} 1\n\
         # HELP sedat_connections_active Active proxy connections.\n\
         # TYPE sedat_connections_active gauge\n\
         sedat_connections_active {}\n\
         # HELP sedat_schema_version Active config schema version.\n\
         # TYPE sedat_schema_version gauge\n\
         sedat_schema_version {}\n\
         # HELP sedat_inbound_proxy_enabled Whether inbound PROXY is enabled.\n\
         # TYPE sedat_inbound_proxy_enabled gauge\n\
         sedat_inbound_proxy_enabled {}\n\
         # HELP sedat_inbound_proxy_after_tls Inbound PROXY placement is after_tls.\n\
         # TYPE sedat_inbound_proxy_after_tls gauge\n\
         sedat_inbound_proxy_after_tls {}\n\
         # HELP sedat_audit_dropped_total JSONL audit events dropped (lock busy or I/O error).\n\
         # TYPE sedat_audit_dropped_total counter\n\
         sedat_audit_dropped_total {}\n",
        crate::VERSION,
        state.limiter.active_connections(),
        cfg.schema_version,
        u8::from(cfg.proxy_protocol.inbound_enabled),
        u8::from(cfg.proxy_protocol.inbound_placement == "after_tls"),
        state.audit.dropped(),
    )
}

fn format_cert(state: &AdminState) -> String {
    if let Some(ref st) = state.acme_status {
        let s = st.lock();
        format!(
            "OK cert directory={} last_success={:?} last_error={:?}\n",
            s.directory, s.last_success_unix, s.last_error
        )
    } else {
        "OK cert acme=disabled\n".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::Limiter;

    fn sample_state_with(mut cfg: SedatConfig, audit: AuditSink) -> AdminState {
        std::env::remove_var(ADMIN_TOKEN_ENV);
        cfg.server.admin_token_file.clear();
        AdminState {
            user_config: "x".into(),
            state_dir: "y".into(),
            config: Arc::new(ArcSwap::from_pointee(cfg)),
            limiter: Limiter::new(Default::default()),
            acme_status: None,
            audit,
            started_at: now_start(),
        }
    }

    fn sample_state() -> AdminState {
        let cfg = SedatConfig {
            schema_version: 1,
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
        sample_state_with(cfg, AuditSink::disabled())
    }

    #[test]
    fn status_format() {
        let state = sample_state();
        assert!(format_status(&state).starts_with("OK sedat"));
        let metrics = prometheus_text(&state);
        assert!(metrics.contains("sedat_connections_active"));
        assert!(metrics.contains("sedat_schema_version 1"));
        assert!(metrics.contains("# TYPE sedat_info gauge"));
        assert!(metrics.contains("# TYPE sedat_audit_dropped_total counter"));
        assert!(metrics.contains("sedat_audit_dropped_total 0"));
    }

    #[test]
    fn metrics_expose_audit_dropped_counter() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("a.jsonl");
        let audit = AuditSink::open(audit_path.to_str().unwrap(), 0).unwrap();
        let cfg = SedatConfig {
            schema_version: 1,
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
        let state = sample_state_with(cfg, audit.clone());

        let before = prometheus_text(&state);
        assert!(before.contains("sedat_audit_dropped_total 0"), "{before}");

        // Hold the audit lock so a concurrent emit is dropped (non-blocking).
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let holder = audit.clone();
        let t = std::thread::spawn(move || {
            holder.with_lock_held_for_test(|| {
                ready_tx.send(()).unwrap();
                done_rx.recv().unwrap();
            });
        });
        ready_rx.recv().unwrap();
        audit.emit_proxy_deny("rate_limit", 429, "127.0.0.1:1", Some("drop-me"), None, None);
        assert!(audit.dropped() >= 1);
        done_tx.send(()).unwrap();
        t.join().unwrap();

        let after = prometheus_text(&state);
        assert!(
            after.contains(&format!("sedat_audit_dropped_total {}", audit.dropped())),
            "{after}"
        );

        let mut authed = false;
        let (reply, _) = dispatch_admin_line(&state, &mut authed, "metrics");
        assert!(reply.starts_with("OK metrics\n"), "{reply}");
        assert!(
            reply.contains("sedat_audit_dropped_total"),
            "admin metrics missing counter: {reply}"
        );
    }

    #[test]
    fn token_required_rejects_until_auth() {
        let mut cfg = SedatConfig {
            schema_version: 1,
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
        cfg.server.admin_token = "good-token".into();
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("a.jsonl");
        let audit = AuditSink::open(audit_path.to_str().unwrap(), 0).unwrap();
        let state = sample_state_with(cfg, audit);
        let mut authed = false;

        let (r, _) = dispatch_admin_line(&state, &mut authed, "status");
        assert!(r.starts_with("ERR auth required"), "{r}");
        assert!(!authed);

        let (r, _) = dispatch_admin_line(&state, &mut authed, "AUTH bad");
        assert!(r.starts_with("ERR auth failed"), "{r}");
        assert!(!authed);

        let (r, _) = dispatch_admin_line(&state, &mut authed, "AUTH good-token");
        assert_eq!(r, "OK auth\n");
        assert!(authed);

        let (r, _) = dispatch_admin_line(&state, &mut authed, "health");
        assert_eq!(r, "OK healthy\n");

        let text = std::fs::read_to_string(&audit_path).unwrap();
        assert!(text.contains("\"event\":\"admin_auth_fail\""));
        assert!(text.contains("\"reason\":\"required\"") || text.contains("\"reason\":\"bad_token\""));
    }

    #[test]
    fn no_token_allows_commands() {
        let state = sample_state();
        let mut authed = false;
        let (r, _) = dispatch_admin_line(&state, &mut authed, "health");
        assert_eq!(r, "OK healthy\n");
    }

    #[test]
    fn selftest_command_ok() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = SedatConfig {
            schema_version: crate::config::CURRENT_SCHEMA_VERSION,
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
        let audit_path = dir.path().join("audit.jsonl");
        let audit = AuditSink::open(audit_path.to_str().unwrap(), 0).unwrap();
        let state = sample_state_with(cfg, audit);
        let mut authed = false;
        let (r, _) = dispatch_admin_line(&state, &mut authed, "selftest");
        assert!(r.starts_with("OK selftest\n"), "{r}");
        let text = std::fs::read_to_string(&audit_path).unwrap();
        assert!(text.contains("\"event\":\"admin_selftest\""));
        assert!(text.contains("\"ok\":true"));
    }

    #[test]
    fn bans_and_unban_commands() {
        use crate::config::LimitsConfig;
        use crate::limits::RateOutcome;
        use std::net::IpAddr;

        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit.jsonl");
        let audit = AuditSink::open(audit_path.to_str().unwrap(), 0).unwrap();

        let limits = LimitsConfig {
            rate_limit_per_ip: 1,
            rate_limit_burst: 1,
            ban_after_rate_limit_strikes: 2,
            ban_duration_secs: 120,
            ..Default::default()
        };
        let lim = Limiter::new(limits.clone());
        let ip: IpAddr = "203.0.113.50".parse().unwrap();
        assert_eq!(lim.check_rate(ip, &limits).outcome, RateOutcome::Allow);
        assert_eq!(lim.check_rate(ip, &limits).outcome, RateOutcome::RateLimited);
        assert_eq!(lim.check_rate(ip, &limits).outcome, RateOutcome::Banned);

        let mut cfg = SedatConfig {
            schema_version: 1,
            server: Default::default(),
            tls: Default::default(),
            acme: Default::default(),
            routes: Default::default(),
            proxy_protocol: Default::default(),
            limits: limits.clone(),
            embedded_docs: Default::default(),
            experimental: Default::default(),
            logging: Default::default(),
            hardening: Default::default(),
        };
        cfg.server.admin_token = "ban-token".into();
        let mut state = sample_state_with(cfg, audit);
        state.limiter = lim;

        let mut authed = false;
        let (r, _) = dispatch_admin_line(&state, &mut authed, "bans");
        assert!(r.starts_with("ERR auth required"), "{r}");

        let (r, _) = dispatch_admin_line(&state, &mut authed, "AUTH ban-token");
        assert_eq!(r, "OK auth\n");

        let (r, _) = dispatch_admin_line(&state, &mut authed, "bans");
        assert!(r.starts_with("OK bans n=1\n"), "{r}");
        assert!(r.contains("203.0.113.50 remaining_secs="), "{r}");

        let (r, _) = dispatch_admin_line(&state, &mut authed, "unban");
        assert!(r.starts_with("ERR unban: usage"), "{r}");

        let (r, _) = dispatch_admin_line(&state, &mut authed, "unban not-an-ip");
        assert!(r.starts_with("ERR unban: invalid ip"), "{r}");

        let (r, _) = dispatch_admin_line(&state, &mut authed, "unban 203.0.113.50");
        assert_eq!(r, "OK unban 203.0.113.50\n");

        let (r, _) = dispatch_admin_line(&state, &mut authed, "bans");
        assert_eq!(r, "OK bans n=0\n");

        let (r, _) = dispatch_admin_line(&state, &mut authed, "unban 203.0.113.50");
        assert!(r.starts_with("ERR unban: not banned"), "{r}");

        let text = std::fs::read_to_string(&audit_path).unwrap();
        assert!(text.contains("\"event\":\"admin_unban\""));
        assert!(text.contains("203.0.113.50"));
        assert!(text.contains("\"source\":\"admin\""));
    }

    #[test]
    fn help_lists_bans_unban() {
        let state = sample_state();
        let mut authed = false;
        let (r, _) = dispatch_admin_line(&state, &mut authed, "help");
        assert!(r.contains("bans"), "{r}");
        assert!(r.contains("unban <ip>"), "{r}");
        assert!(r.contains("selftest [json]"), "{r}");
    }

    #[test]
    fn selftest_json_command() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = SedatConfig {
            schema_version: crate::config::CURRENT_SCHEMA_VERSION,
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
        let state = sample_state_with(cfg, AuditSink::disabled());
        let mut authed = false;
        let (r, _) = dispatch_admin_line(&state, &mut authed, "selftest json");
        assert!(r.starts_with("OK selftest json\n"), "{r}");
        assert!(r.contains("\"ok\":true"), "{r}");
        assert!(r.contains("\"name\":\"upstream_tcp\""), "{r}");
        assert!(r.contains("\"name\":\"allowlists\""), "{r}");
    }

    #[test]
    #[cfg(unix)]
    fn admin_acl_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("admin.sock");
        std::fs::write(&sock, b"").unwrap();
        apply_admin_socket_acl(&sock, None).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
