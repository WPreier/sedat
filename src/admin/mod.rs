//! Unix-domain admin socket (status / reload / cert-info) + optional loopback metrics sidecar.

mod auth;
mod selftest;

pub use auth::{
    metrics_token_authorized, parse_auth_line, parse_bearer_authorization, resolve_admin_token,
    token_matches, LiveAdminTokens, TokenReloadOutcome, TokenReloadWouldDisable, ADMIN_TOKEN_ENV,
    DEFAULT_TOKEN_OVERLAP_SECS,
};
pub use selftest::{now_start, run_selftest, SelftestCheck, SelftestReport};
pub use crate::config::RestartOnlySnapshot;

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{info, warn};

use crate::acme::AcmeStatus;
use crate::audit::AuditSink;
use crate::config::{
    self, format_audit_summary, format_restart_required_note, restart_required_gauges,
    restart_required_keys, security_diff, SedatConfig,
};
use crate::limits::Limiter;
use crate::tls::TlsState;

/// Shared admin state.
#[derive(Clone)]
pub struct AdminState {
    /// User config path.
    pub user_config: std::path::PathBuf,
    /// State directory.
    pub state_dir: std::path::PathBuf,
    /// Live config.
    pub config: Arc<ArcSwap<SedatConfig>>,
    /// Live admin/metrics token gate (P12.3 hot-rotate + overlap).
    pub tokens: LiveAdminTokens,
    /// Limiter for stats (limits reconfigured on reload — P14.1).
    pub limiter: Arc<Limiter>,
    /// Optional TLS hot-swap target for static cert reload (P14.1).
    pub tls: Option<TlsState>,
    /// Running ACME manager for live config swap (P14.6); `None` if ACME never started.
    pub acme: Option<Arc<crate::acme::AcmeManager>>,
    /// ACME status (optional; usually `acme.status` when ACME started).
    pub acme_status: Option<Arc<parking_lot::Mutex<AcmeStatus>>>,
    /// Shared JSONL audit sink.
    pub audit: AuditSink,
    /// Process/admin start time (uptime for selftest).
    pub started_at: Instant,
    /// Restart-only knobs as bound/applied at process start (P15.3 drift detection).
    pub boot: RestartOnlySnapshot,
}

/// Apply admin socket filesystem ACL: `0600` owner-only, or `0660` + group when configured.
#[cfg(unix)]
pub fn apply_admin_socket_acl(
    socket_path: &Path,
    admin_group: Option<&str>,
) -> std::io::Result<()> {
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

/// Listen for Unix `SIGHUP` and apply the same live reload as admin `reload` (P14.1).
#[cfg(unix)]
pub async fn serve_sighup_reload(state: AdminState) {
    use tokio::signal::unix::{signal, SignalKind};
    let mut hup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "SIGHUP handler not installed");
            return;
        }
    };
    info!("SIGHUP reload handler ready");
    while hup.recv().await.is_some() {
        let reply = apply_live_reload(&state);
        if reply.starts_with("OK") {
            info!(%reply, "SIGHUP config reload ok");
        } else {
            warn!(%reply, "SIGHUP config reload failed (previous active kept)");
        }
    }
}

/// Optional loopback-only HTTP sidecar exposing `GET /metrics` in Prometheus text format.
///
/// Binds only the configured address (validation already enforces loopback). Never a public
/// control plane — operators should firewall/deny non-loopback at the host level as well.
///
/// When an admin token is configured (same sources as the Unix socket), scrapes must send
/// `Authorization: Bearer <token>` (fail-closed). Empty token config → loopback-only (dev).
pub async fn serve_metrics_sidecar(
    addr: std::net::SocketAddr,
    state: AdminState,
) -> std::io::Result<()> {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::Request;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let token_required = state.tokens.is_required();
    info!(
        %addr,
        token_required,
        "metrics sidecar listening (loopback)"
    );
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
                    let auth = req
                        .headers()
                        .get(hyper::header::AUTHORIZATION)
                        .and_then(|v| v.to_str().ok());
                    let resp =
                        metrics_sidecar_response(&state, req.method(), req.uri().path(), auth);
                    Ok::<_, Infallible>(resp)
                }
            });
            let _ = http1::Builder::new().serve_connection(io, svc).await;
        });
    }
}

/// Build the HTTP response for one metrics-sidecar request (testable without a listener).
#[must_use]
pub fn metrics_sidecar_response(
    state: &AdminState,
    method: &hyper::Method,
    path: &str,
    authorization: Option<&str>,
) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::{Method, Response, StatusCode};

    if *method != Method::GET || path != "/metrics" {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from_static(b"not found")))
            .unwrap();
    }

    let required = state.tokens.is_required();
    if !state.tokens.metrics_authorized(authorization) {
        let reason = if required && authorization.is_none() {
            "metrics_required"
        } else {
            "metrics_bad_token"
        };
        warn!(target: "sedat::audit", reason, "metrics scrape rejected (auth)");
        state.audit.emit_metrics_auth_fail(reason);
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(
                hyper::header::WWW_AUTHENTICATE,
                "Bearer realm=\"sedat-metrics\"",
            )
            .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from_static(b"unauthorized")))
            .unwrap();
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/plain; version=0.0.4")
        .body(Full::new(Bytes::from(prometheus_text(state))))
        .unwrap()
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
    let token_required = state.tokens.is_required();

    if let Some(presented) = parse_auth_line(line) {
        if !token_required {
            return (
                "ERR auth not required (no admin token configured)\n".into(),
                false,
            );
        }
        if presented.is_empty() {
            warn!(target: "sedat::audit", "admin AUTH missing token");
            state.audit.emit_admin_auth_fail("missing_token");
            *authed = false;
            return ("ERR auth failed\n".into(), false);
        }
        if state.tokens.matches_presented(presented) {
            *authed = true;
            info!(target: "sedat::audit", "admin AUTH ok");
            return ("OK auth\n".into(), false);
        }
        warn!(target: "sedat::audit", "admin AUTH failed");
        state.audit.emit_admin_auth_fail("bad_token");
        *authed = false;
        return ("ERR auth failed\n".into(), false);
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
            "commands: AUTH <token> | status | health | ready | metrics | reload | reload-token | cert | selftest [json] | bans | unban <ip> | quit\n"
        } else {
            "commands: status | health | ready | metrics | reload | reload-token | cert | selftest [json] | bans | unban <ip> | quit\n"
        };
        return (help.into(), false);
    }

    if token_required && !*authed {
        warn!(target: "sedat::audit", command = %verb, "admin command rejected (auth required)");
        state.audit.emit_admin_auth_fail("required");
        return (
            "ERR auth required (send AUTH <token> first)\n".into(),
            false,
        );
    }

    let reply = match verb.as_str() {
        "status" | "stats" => format_status(state),
        "health" => format_health(state),
        "ready" => format_ready(state),
        "metrics" => {
            let body = prometheus_text(state);
            format!("OK metrics\n{body}")
        }
        "reload" => apply_live_reload(state),
        "reload-token" | "token-reload" | "reload_token" | "token_reload" => {
            reload_admin_token(state)
        }
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

/// Apply a validated config reload (admin `reload` or Unix SIGHUP).
///
/// Updates: routes/proxy via `config` ArcSwap, live limits, ban-share store,
/// audit sink, admin token gate, static TLS, and live ACME knobs (when the
/// renewal loop was started at boot). Still restart-only: listen addresses,
/// Landlock/seccomp, metrics bind address changes, and enabling ACME when it
/// was off at process start.
pub fn apply_live_reload(state: &AdminState) -> String {
    match config::try_reload(&state.user_config, &state.state_dir) {
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
                active.config.logging.audit_jsonl_max_age_secs,
            ) {
                warn!(error = %e, "audit jsonl reconfigure failed");
            }
            let ban_note = state
                .limiter
                .reconfigure(active.config.limits.clone())
                .reply_suffix();
            let cert_note = reload_static_tls(state, &active.config);
            let acme_note = reload_acme(state, &active.config);
            let overlap = active.config.server.admin_token_overlap_secs;
            let token_note = match state.tokens.reload_from_config(&active.config, overlap) {
                Ok(outcome) => {
                    audit_token_reload(state, &outcome);
                    format_token_reload_note(&outcome)
                }
                Err(TokenReloadWouldDisable) => {
                    warn!(
                        target: "sedat::audit",
                        "config reload kept previous admin token (new sources empty)"
                    );
                    state
                        .audit
                        .emit_admin_token_reload("rejected_would_disable", None);
                    " token=kept_fail_closed".into()
                }
            };
            let restart_keys = restart_required_keys(&state.boot, &active.config);
            if !restart_keys.is_empty() {
                warn!(
                    keys = %restart_keys.join(","),
                    "config reload has restart-only drift; process restart required for those keys"
                );
            }
            let restart_note = format_restart_required_note(&restart_keys);
            state
                .audit
                .emit_config_reload(&changes, &summary, &restart_keys);
            state.config.store(Arc::new(active.config));
            format!(
                "OK reload audit={summary}{token_note}{cert_note}{ban_note}{acme_note}{restart_note}\n"
            )
        }
        Err(e) => format!("ERR reload: {e}\n"),
    }
}

/// Hot-swap ACME knobs when a renewal loop is already running.
fn reload_acme(state: &AdminState, cfg: &SedatConfig) -> String {
    match (&state.acme, cfg.acme.enabled) {
        (Some(mgr), _) => {
            mgr.replace_config(cfg.acme.clone());
            info!(
                enabled = cfg.acme.enabled,
                "ACME live config swapped on reload"
            );
            " acme=config_swapped".into()
        }
        (None, true) => {
            warn!("ACME enabled in new config but loop was not started at boot; restart required");
            " acme=restart_required_to_enable".into()
        }
        (None, false) => String::new(),
    }
}

/// Hot-swap static TLS material when cert/key paths are set and `tls` is wired.
fn reload_static_tls(state: &AdminState, cfg: &SedatConfig) -> String {
    let Some(tls) = state.tls.as_ref() else {
        return String::new();
    };
    let (Some(cert), Some(key)) = (&cfg.tls.cert_path, &cfg.tls.key_path) else {
        return String::new();
    };
    if cert.trim().is_empty() || key.trim().is_empty() {
        return String::new();
    }
    match crate::tls::load_server_config(std::path::Path::new(cert), std::path::Path::new(key)) {
        Ok(sc) => {
            tls.swap(sc);
            info!(cert = %cert, "static TLS cert hot-swapped on reload");
            " tls=swapped".into()
        }
        Err(e) => {
            warn!(error = %e, cert = %cert, "static TLS reload failed; previous cert kept");
            " tls=kept_load_error".into()
        }
    }
}

fn reload_admin_token(state: &AdminState) -> String {
    let cfg = state.config.load_full();
    let overlap = cfg.server.admin_token_overlap_secs;
    match state.tokens.reload_from_config(&cfg, overlap) {
        Ok(outcome) => {
            audit_token_reload(state, &outcome);
            info!(target: "sedat::audit", ?outcome, "admin token reload ok");
            match outcome {
                TokenReloadOutcome::UnchangedEmpty => {
                    "OK reload-token unchanged (auth off)\n".into()
                }
                TokenReloadOutcome::Unchanged => "OK reload-token unchanged\n".into(),
                TokenReloadOutcome::Enabled => "OK reload-token enabled\n".into(),
                TokenReloadOutcome::Rotated { overlap_secs } => {
                    format!("OK reload-token rotated overlap_secs={overlap_secs}\n")
                }
            }
        }
        Err(TokenReloadWouldDisable) => {
            warn!(
                target: "sedat::audit",
                "admin reload-token rejected (would disable auth)"
            );
            state
                .audit
                .emit_admin_token_reload("rejected_would_disable", None);
            "ERR reload-token: new token sources empty (fail-closed; previous token kept)\n".into()
        }
    }
}

fn audit_token_reload(state: &AdminState, outcome: &TokenReloadOutcome) {
    let (name, overlap) = match outcome {
        TokenReloadOutcome::UnchangedEmpty => ("unchanged_empty", None),
        TokenReloadOutcome::Unchanged => ("unchanged", None),
        TokenReloadOutcome::Enabled => ("enabled", None),
        TokenReloadOutcome::Rotated { overlap_secs } => ("rotated", Some(*overlap_secs)),
    };
    state.audit.emit_admin_token_reload(name, overlap);
}

fn format_token_reload_note(outcome: &TokenReloadOutcome) -> String {
    match outcome {
        TokenReloadOutcome::UnchangedEmpty | TokenReloadOutcome::Unchanged => String::new(),
        TokenReloadOutcome::Enabled => " token=enabled".into(),
        TokenReloadOutcome::Rotated { overlap_secs } => {
            format!(" token=rotated overlap_secs={overlap_secs}")
        }
    }
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
    let restart_note = format_restart_required_note(&restart_required_keys(&state.boot, &cfg));
    format!(
        "OK sedat {} connections={} listen={} tls_enabled={} h3={}{restart_note}\n",
        crate::VERSION,
        state.limiter.active_connections(),
        cfg.server.listen,
        cfg.tls.enabled || cfg.acme.enabled,
        cfg.experimental.h3
    )
}

/// Liveness: process is up. Annotates `restart_required` but does not fail (P17.1).
fn format_health(state: &AdminState) -> String {
    let cfg = state.config.load();
    let restart_note = format_restart_required_note(&restart_required_keys(&state.boot, &cfg));
    format!("OK healthy{restart_note}\n")
}

/// Readiness: fail-closed when boot-bound config drifted vs live (P17.1).
fn format_ready(state: &AdminState) -> String {
    let cfg = state.config.load();
    let keys = restart_required_keys(&state.boot, &cfg);
    let restart_note = format_restart_required_note(&keys);
    if keys.is_empty() {
        format!("OK ready{restart_note}\n")
    } else {
        format!("ERR not_ready{restart_note}\n")
    }
}

/// Prometheus text exposition (no `OK` prefix — for sidecar `/metrics`).
pub fn prometheus_text(state: &AdminState) -> String {
    let cfg = state.config.load();
    let mut out = format!(
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
         sedat_audit_dropped_total {}\n\
         # HELP sedat_uptime_seconds Seconds since process/admin start.\n\
         # TYPE sedat_uptime_seconds gauge\n\
         sedat_uptime_seconds {}\n\
         # HELP sedat_bans_active Active temporary IP bans.\n\
         # TYPE sedat_bans_active gauge\n\
         sedat_bans_active {}\n",
        crate::VERSION,
        state.limiter.active_connections(),
        cfg.schema_version,
        u8::from(cfg.proxy_protocol.inbound_enabled),
        u8::from(cfg.proxy_protocol.inbound_placement == "after_tls"),
        state.audit.dropped(),
        state.started_at.elapsed().as_secs(),
        state.limiter.bans_active(),
    );
    // P16.1: fixed-cardinality restart-only drift (same keys as P15.3 selftest/status).
    out.push_str(
        "# HELP sedat_restart_required Restart required for this boot-bound config key (1=yes).\n\
         # TYPE sedat_restart_required gauge\n",
    );
    for (key, v) in restart_required_gauges(&state.boot, &cfg) {
        out.push_str(&format!("sedat_restart_required{{key=\"{key}\"}} {v}\n"));
    }
    out
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

    fn sample_state_with(cfg: SedatConfig, audit: AuditSink) -> AdminState {
        std::env::remove_var(ADMIN_TOKEN_ENV);
        let tokens = LiveAdminTokens::from_config(&cfg);
        let boot = RestartOnlySnapshot::from_boot(&cfg, false);
        AdminState {
            user_config: "x".into(),
            state_dir: "y".into(),
            config: Arc::new(ArcSwap::from_pointee(cfg)),
            tokens,
            limiter: Limiter::new(Default::default()),
            tls: None,
            acme: None,
            acme_status: None,
            audit,
            started_at: now_start(),
            boot,
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
        let status = format_status(&state);
        assert!(status.starts_with("OK sedat"), "{status}");
        assert!(!status.contains("restart_required="), "{status}");
        let metrics = prometheus_text(&state);
        assert!(metrics.contains("sedat_connections_active"));
        assert!(metrics.contains("sedat_schema_version 1"));
        assert!(metrics.contains("# TYPE sedat_info gauge"));
        assert!(metrics.contains("# TYPE sedat_audit_dropped_total counter"));
        assert!(metrics.contains("sedat_audit_dropped_total 0"));
        assert!(metrics.contains("# TYPE sedat_restart_required gauge"));
        assert!(metrics.contains("sedat_restart_required{key=\"server.listen\"} 0"));
        assert!(metrics.contains("sedat_restart_required{key=\"acme.enable\"} 0"));
        assert!(metrics.contains("# TYPE sedat_uptime_seconds gauge"));
        assert!(metrics.contains("sedat_uptime_seconds "));
        assert!(metrics.contains("# TYPE sedat_bans_active gauge"));
        assert!(metrics.contains("sedat_bans_active 0"));
    }

    #[test]
    fn metrics_expose_uptime_and_bans_active() {
        use crate::config::LimitsConfig;
        use crate::limits::RateOutcome;
        use std::net::IpAddr;
        use std::thread;
        use std::time::Duration;

        let limits = LimitsConfig {
            rate_limit_per_ip: 1,
            rate_limit_burst: 1,
            ban_after_rate_limit_strikes: 2,
            ban_duration_secs: 120,
            ..Default::default()
        };
        let lim = Limiter::new(limits.clone());
        let mut state = sample_state();
        state.limiter = lim.clone();

        let before = prometheus_text(&state);
        assert!(before.contains("sedat_bans_active 0"), "{before}");
        assert!(before.contains("sedat_uptime_seconds "), "{before}");

        thread::sleep(Duration::from_millis(20));
        let mid = prometheus_text(&state);
        let uptime_line = mid
            .lines()
            .find(|l| l.starts_with("sedat_uptime_seconds "))
            .expect("uptime gauge");
        let secs: u64 = uptime_line
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        assert!(secs < 60, "unexpected uptime {secs}");

        let ip: IpAddr = "203.0.113.77".parse().unwrap();
        assert_eq!(lim.check_rate(ip, &limits).outcome, RateOutcome::Allow);
        assert_eq!(
            lim.check_rate(ip, &limits).outcome,
            RateOutcome::RateLimited
        );
        assert_eq!(lim.check_rate(ip, &limits).outcome, RateOutcome::Banned);
        assert_eq!(lim.bans_active(), 1);

        let after = prometheus_text(&state);
        assert!(after.contains("sedat_bans_active 1"), "{after}");
    }

    #[test]
    fn status_reports_restart_required_drift() {
        let state = sample_state();
        let mut cfg = (*state.config.load_full()).clone();
        cfg.server.listen = "127.0.0.1:18080".into();
        cfg.hardening.landlock = "required".into();
        state.config.store(Arc::new(cfg));
        let status = format_status(&state);
        assert!(status.contains("restart_required="), "{status}");
        assert!(status.contains("server.listen"), "{status}");
        assert!(status.contains("hardening.landlock"), "{status}");
    }

    #[test]
    fn metrics_expose_restart_required_gauges() {
        let state = sample_state();
        let before = prometheus_text(&state);
        assert!(
            before.contains("sedat_restart_required{key=\"server.listen\"} 0"),
            "{before}"
        );
        assert!(
            before.contains("sedat_restart_required{key=\"hardening.seccomp\"} 0"),
            "{before}"
        );

        let mut cfg = (*state.config.load_full()).clone();
        cfg.server.metrics_listen = Some("127.0.0.1:19100".into());
        cfg.hardening.seccomp = "required".into();
        state.config.store(Arc::new(cfg));
        let after = prometheus_text(&state);
        assert!(
            after.contains("sedat_restart_required{key=\"server.metrics_listen\"} 1"),
            "{after}"
        );
        assert!(
            after.contains("sedat_restart_required{key=\"hardening.seccomp\"} 1"),
            "{after}"
        );
        assert!(
            after.contains("sedat_restart_required{key=\"server.listen\"} 0"),
            "{after}"
        );
    }

    #[test]
    fn metrics_expose_audit_dropped_counter() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("a.jsonl");
        let audit = AuditSink::open(audit_path.to_str().unwrap(), 0, 0).unwrap();
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
        audit.emit_proxy_deny(
            "rate_limit",
            429,
            "127.0.0.1:1",
            Some("drop-me"),
            None,
            None,
        );
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
        let audit = AuditSink::open(audit_path.to_str().unwrap(), 0, 0).unwrap();
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
        assert!(
            text.contains("\"reason\":\"required\"") || text.contains("\"reason\":\"bad_token\"")
        );
    }

    #[test]
    fn no_token_allows_commands() {
        let state = sample_state();
        let mut authed = false;
        let (r, _) = dispatch_admin_line(&state, &mut authed, "health");
        assert_eq!(r, "OK healthy\n");
        let (r, _) = dispatch_admin_line(&state, &mut authed, "ready");
        assert_eq!(r, "OK ready\n");
    }

    #[test]
    fn ready_fails_on_restart_required_drift() {
        let state = sample_state();
        let mut cfg = (*state.config.load_full()).clone();
        cfg.server.listen = "127.0.0.1:18080".into();
        state.config.store(Arc::new(cfg));

        let mut authed = false;
        let (r, _) = dispatch_admin_line(&state, &mut authed, "health");
        assert!(r.starts_with("OK healthy"), "{r}");
        assert!(r.contains("restart_required=server.listen"), "{r}");

        let (r, _) = dispatch_admin_line(&state, &mut authed, "ready");
        assert!(r.starts_with("ERR not_ready"), "{r}");
        assert!(r.contains("restart_required=server.listen"), "{r}");
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
        let audit = AuditSink::open(audit_path.to_str().unwrap(), 0, 0).unwrap();
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
        let audit = AuditSink::open(audit_path.to_str().unwrap(), 0, 0).unwrap();

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
        assert_eq!(
            lim.check_rate(ip, &limits).outcome,
            RateOutcome::RateLimited
        );
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
        assert!(r.contains("reload-token"), "{r}");
    }

    #[test]
    fn live_reload_updates_limits_and_swaps_tls() {
        use crate::tls::{self, TlsState};

        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let user = dir.path().join("sedat.toml");

        let (cert_a, key_a) = tls::generate_self_signed("a.example").unwrap();
        let (cert_b, key_b) = tls::generate_self_signed("b.example").unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, &cert_a).unwrap();
        std::fs::write(&key_path, &key_a).unwrap();

        let toml_v1 = format!(
            r#"
schema_version = 1
[server]
listen = "127.0.0.1:0"
listen_tls = "127.0.0.1:0"
state_dir = "{state}"
[tls]
enabled = true
cert_path = "{cert}"
key_path = "{key}"
[limits]
max_connections = 32
[[routes.hosts]]
host = "localhost"
[[routes.hosts.paths]]
prefix = "/"
upstream = "http://127.0.0.1:9"
"#,
            state = state_dir.display().to_string().replace('\\', "/"),
            cert = cert_path.display().to_string().replace('\\', "/"),
            key = key_path.display().to_string().replace('\\', "/"),
        );
        std::fs::write(&user, &toml_v1).unwrap();
        let active = config::load_and_activate(&user, Some(&state_dir)).unwrap();

        let sc = tls::load_server_config(&cert_path, &key_path).unwrap();
        let tls_state = TlsState::new(sc);
        let limiter = Limiter::new(active.config.limits.clone());
        let tokens = LiveAdminTokens::from_config(&active.config);
        let boot = RestartOnlySnapshot::from_boot(&active.config, false);
        let state = AdminState {
            user_config: user.clone(),
            state_dir: state_dir.clone(),
            config: Arc::new(ArcSwap::from_pointee(active.config)),
            tokens,
            limiter: limiter.clone(),
            tls: Some(tls_state.clone()),
            acme: None,
            acme_status: None,
            audit: AuditSink::disabled(),
            started_at: now_start(),
            boot,
        };

        // Point files at cert B and raise connection cap.
        std::fs::write(&cert_path, &cert_b).unwrap();
        std::fs::write(&key_path, &key_b).unwrap();
        let toml_v2 = toml_v1.replace("max_connections = 32", "max_connections = 64");
        std::fs::write(&user, &toml_v2).unwrap();

        let reply = apply_live_reload(&state);
        assert!(reply.starts_with("OK reload"), "{reply}");
        assert!(reply.contains("tls=swapped"), "{reply}");
        assert_eq!(limiter.limits_snapshot().max_connections, 64);
        assert_eq!(state.config.load().limits.max_connections, 64);
        // Acceptor still builds after swap (material replaced).
        let _ = tls_state.acceptor();
    }

    #[test]
    fn reload_audit_includes_restart_required_keys() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&state_dir).unwrap();
        let user = dir.path().join("sedat.toml");
        let audit_path = dir.path().join("audit.jsonl");
        let audit = AuditSink::open(audit_path.to_str().unwrap(), 0, 0).unwrap();

        let toml_v1 = format!(
            r#"
schema_version = 1
[server]
listen = "127.0.0.1:18080"
listen_tls = "127.0.0.1:0"
state_dir = "{state}"
[logging]
audit_jsonl = "{audit}"
[limits]
max_connections = 16
[[routes.hosts]]
host = "localhost"
[[routes.hosts.paths]]
prefix = "/"
upstream = "http://127.0.0.1:9"
"#,
            state = state_dir.display().to_string().replace('\\', "/"),
            audit = audit_path.display().to_string().replace('\\', "/"),
        );
        std::fs::write(&user, &toml_v1).unwrap();
        let active = config::load_and_activate(&user, Some(&state_dir)).unwrap();
        let boot = RestartOnlySnapshot::from_boot(&active.config, false);
        let tokens = LiveAdminTokens::from_config(&active.config);
        let state = AdminState {
            user_config: user.clone(),
            state_dir: state_dir.clone(),
            config: Arc::new(ArcSwap::from_pointee(active.config)),
            tokens,
            limiter: Limiter::new(Default::default()),
            tls: None,
            acme: None,
            acme_status: None,
            audit,
            started_at: now_start(),
            boot,
        };

        let toml_v2 = toml_v1.replace("127.0.0.1:18080", "127.0.0.1:18081");
        std::fs::write(&user, &toml_v2).unwrap();
        let reply = apply_live_reload(&state);
        assert!(reply.starts_with("OK reload"), "{reply}");
        assert!(reply.contains("restart_required=server.listen"), "{reply}");

        let text = std::fs::read_to_string(&audit_path).unwrap();
        let line = text
            .lines()
            .find(|l| l.contains("\"config_reload\""))
            .expect("config_reload audit line");
        assert!(
            line.contains("\"restart_required\"") && line.contains("server.listen"),
            "{line}"
        );
    }

    #[test]
    fn reload_token_rotates_with_overlap() {
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("admin.token");
        std::fs::write(&token_path, b"old-secret\n").unwrap();
        let audit_path = dir.path().join("a.jsonl");
        let audit = AuditSink::open(audit_path.to_str().unwrap(), 0, 0).unwrap();

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
        cfg.server.admin_token_file = token_path.to_string_lossy().into();
        cfg.server.admin_token_overlap_secs = 120;
        let state = sample_state_with(cfg, audit);

        let mut authed = false;
        let (r, _) = dispatch_admin_line(&state, &mut authed, "AUTH old-secret");
        assert_eq!(r, "OK auth\n");

        std::fs::write(&token_path, b"new-secret\n").unwrap();
        let (r, _) = dispatch_admin_line(&state, &mut authed, "reload-token");
        assert!(
            r.starts_with("OK reload-token rotated overlap_secs=120"),
            "{r}"
        );

        // New connection style: previous still accepted during overlap.
        let mut a2 = false;
        let (r, _) = dispatch_admin_line(&state, &mut a2, "AUTH old-secret");
        assert_eq!(r, "OK auth\n", "previous token should work in overlap");
        let mut a3 = false;
        let (r, _) = dispatch_admin_line(&state, &mut a3, "AUTH new-secret");
        assert_eq!(r, "OK auth\n");

        // Fail-closed: empty file must not disable auth.
        std::fs::write(&token_path, b"\n").unwrap();
        let (r, _) = dispatch_admin_line(&state, &mut authed, "reload-token");
        assert!(r.starts_with("ERR reload-token:"), "{r}");
        assert!(state.tokens.is_required());

        let text = std::fs::read_to_string(&audit_path).unwrap();
        assert!(text.contains("\"event\":\"admin_token_reload\""));
        assert!(text.contains("\"outcome\":\"rotated\""));
        assert!(text.contains("\"outcome\":\"rejected_would_disable\""));
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

    #[test]
    fn metrics_sidecar_open_without_token() {
        std::env::remove_var(ADMIN_TOKEN_ENV);
        let state = sample_state();
        let resp = metrics_sidecar_response(&state, &hyper::Method::GET, "/metrics", None);
        assert_eq!(resp.status(), hyper::StatusCode::OK);
        assert!(prometheus_text(&state).contains("sedat_info"));
    }

    #[test]
    fn metrics_sidecar_requires_bearer_when_token_set() {
        std::env::remove_var(ADMIN_TOKEN_ENV);
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("a.jsonl");
        let audit = AuditSink::open(audit_path.to_str().unwrap(), 0, 0).unwrap();
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
        cfg.server.admin_token = "metrics-secret".into();
        let state = sample_state_with(cfg, audit);

        let resp = metrics_sidecar_response(&state, &hyper::Method::GET, "/metrics", None);
        assert_eq!(resp.status(), hyper::StatusCode::UNAUTHORIZED);

        let resp = metrics_sidecar_response(
            &state,
            &hyper::Method::GET,
            "/metrics",
            Some("Bearer wrong"),
        );
        assert_eq!(resp.status(), hyper::StatusCode::UNAUTHORIZED);

        let resp = metrics_sidecar_response(
            &state,
            &hyper::Method::GET,
            "/metrics",
            Some("Bearer metrics-secret"),
        );
        assert_eq!(resp.status(), hyper::StatusCode::OK);

        // Admin socket still works with AUTH (unchanged).
        let mut authed = false;
        let (r, _) = dispatch_admin_line(&state, &mut authed, "status");
        assert!(r.starts_with("ERR auth required"), "{r}");
        let (r, _) = dispatch_admin_line(&state, &mut authed, "AUTH metrics-secret");
        assert_eq!(r, "OK auth\n");
        let (r, _) = dispatch_admin_line(&state, &mut authed, "health");
        assert_eq!(r, "OK healthy\n");

        let text = std::fs::read_to_string(&audit_path).unwrap();
        assert!(text.contains("\"event\":\"metrics_auth_fail\""));
        assert!(
            text.contains("\"reason\":\"metrics_required\"")
                || text.contains("\"reason\":\"metrics_bad_token\"")
        );
    }
}
