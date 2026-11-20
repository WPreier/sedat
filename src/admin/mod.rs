//! Unix-domain admin socket (status / reload / cert-info) + optional loopback metrics sidecar.

use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::{info, warn};

use crate::acme::AcmeStatus;
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
    while let Some(line) = lines.next_line().await? {
        let cmd = line.trim().to_ascii_lowercase();
        let reply = match cmd.as_str() {
            "status" | "stats" => format_status(&state),
            "health" | "ready" => "OK healthy\n".to_string(),
            "metrics" => {
                let body = prometheus_text(&state);
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
                    state.config.store(Arc::new(active.config));
                    format!("OK reload audit={summary}\n")
                }
                Err(e) => format!("ERR reload: {e}\n"),
            },
            "cert" | "cert-info" | "cert_info" => format_cert(&state),
            "help" => "commands: status | health | metrics | reload | cert | quit\n".into(),
            "quit" | "exit" => {
                writer.write_all(b"OK bye\n").await?;
                break;
            }
            other => format!("ERR unknown command: {other}\n"),
        };
        writer.write_all(reply.as_bytes()).await?;
    }
    Ok(())
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
         sedat_inbound_proxy_after_tls {}\n",
        crate::VERSION,
        state.limiter.active_connections(),
        cfg.schema_version,
        u8::from(cfg.proxy_protocol.inbound_enabled),
        u8::from(cfg.proxy_protocol.inbound_placement == "after_tls"),
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
        AdminState {
            user_config: "x".into(),
            state_dir: "y".into(),
            config: Arc::new(ArcSwap::from_pointee(cfg)),
            limiter: Limiter::new(Default::default()),
            acme_status: None,
        }
    }

    #[test]
    fn status_format() {
        let state = sample_state();
        assert!(format_status(&state).starts_with("OK sedat"));
        let metrics = prometheus_text(&state);
        assert!(metrics.contains("sedat_connections_active"));
        assert!(metrics.contains("sedat_schema_version 1"));
        assert!(metrics.contains("# TYPE sedat_info gauge"));
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
