//! SeDat binary entrypoint.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;
use tracing::{info, warn};

use sedat::acme::{self, AcmeManager, AcmePaths};
use sedat::admin::{self, AdminState};
use sedat::audit::AuditSink;
use sedat::config::{self, SedatConfig};
use sedat::hardening;
use sedat::logging;
use sedat::proxy::{self, ProxyState};
use sedat::tls::{self, TlsState};
use sedat::VERSION;

#[derive(Debug, Parser)]
#[command(name = "sedat", version = VERSION, about = "Minimal high-security reverse proxy")]
struct Cli {
    /// Path to user TOML config.
    #[arg(long, default_value = "sedat.toml")]
    config: PathBuf,

    /// Override plain HTTP listen address.
    #[arg(long)]
    listen: Option<String>,

    /// Write default config and activate it.
    #[arg(long)]
    resetconfig: bool,

    /// Validate config and exit.
    #[arg(long)]
    validate: bool,

    /// Rewrite user config through the schema migration helper (fail-closed), then exit.
    #[arg(long)]
    migrate_config: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.resetconfig {
        let active = config::reset_config(&cli.config, None)?;
        println!(
            "reset config written to {} (active: {})",
            active.user_path.display(),
            active.active_path.display()
        );
        if cli.validate || cli.listen.is_none() {
            // continue to validate path below if requested; otherwise exit success
        }
    }

    if !cli.config.exists() && !cli.resetconfig {
        anyhow::bail!(
            "config not found: {} (use --resetconfig to create a default)",
            cli.config.display()
        );
    }

    if cli.migrate_config {
        let text = std::fs::read_to_string(&cli.config)?;
        let migrated = config::migrate_toml(&text)?;
        std::fs::write(&cli.config, &migrated)?;
        let ver = config::peek_schema_version(&migrated)?;
        println!(
            "migrated {} to schema_version={} (fail-closed path)",
            cli.config.display(),
            ver
        );
        return Ok(());
    }

    let mut active = config::load_and_activate(&cli.config, None)?;
    if let Some(listen) = &cli.listen {
        active.config.server.listen = listen.clone();
    }

    logging::init(&active.config.logging.level);
    sedat::tls::ensure_crypto_provider();

    if cli.validate {
        println!(
            "config OK (schema_version={})",
            active.config.schema_version
        );
        return Ok(());
    }

    run(active.config, cli.config).await
}

async fn run(cfg: SedatConfig, user_config: PathBuf) -> anyhow::Result<()> {
    std::fs::create_dir_all(&cfg.server.state_dir)?;

    let http_addr: SocketAddr = cfg.server.listen.parse()?;
    let http_listener = TcpListener::bind(http_addr).await?;
    info!(%http_addr, "bound HTTP");

    let mut tls_state: Option<TlsState> = None;
    let mut tls_listener = None;
    let mut acme_mgr: Option<Arc<AcmeManager>> = None;

    if cfg.tls.enabled || cfg.acme.enabled {
        if let (Some(cert), Some(key)) = (&cfg.tls.cert_path, &cfg.tls.key_path) {
            let sc =
                tls::load_server_config(std::path::Path::new(cert), std::path::Path::new(key))?;
            tls_state = Some(TlsState::new(sc));
        } else if cfg.acme.enabled {
            let paths = AcmePaths::new(&cfg.server.state_dir);
            let mgr = AcmeManager::new(cfg.acme.clone(), paths, None);
            mgr.install_self_signed_for_domains()
                .await
                .map_err(anyhow::Error::msg)?;
            let (cert, key) = acme::load_existing_cert(&mgr.paths)?
                .ok_or_else(|| anyhow::anyhow!("ACME self-signed install produced no cert"))?;
            let sc = tls::server_config_from_pem(&cert, &key)?;
            let ts = TlsState::new(sc);
            let mgr = AcmeManager::new(
                cfg.acme.clone(),
                AcmePaths::new(&cfg.server.state_dir),
                Some(ts.clone()),
            );
            tls_state = Some(ts);
            let mgr = Arc::new(mgr);
            acme_mgr = Some(mgr.clone());
            tokio::spawn(mgr.renewal_loop());
        } else {
            // Dev convenience: generate ephemeral self-signed when TLS enabled without paths.
            let (cert, key) = tls::generate_self_signed("localhost")?;
            let sc = tls::server_config_from_pem(&cert, &key)?;
            tls_state = Some(TlsState::new(sc));
        }

        let tls_addr: SocketAddr = cfg.server.listen_tls.parse()?;
        tls_listener = Some(TcpListener::bind(tls_addr).await?);
        info!(%tls_addr, "bound HTTPS");
    }

    // Privilege drop after bind, then optional Landlock/seccomp sandbox.
    match hardening::drop_privileges(&cfg.server)? {
        hardening::DropResult::Dropped { user } => info!(user, "running unprivileged"),
        hardening::DropResult::Skipped => {}
        hardening::DropResult::Unsupported => {
            warn!("privilege drop unsupported on this platform");
        }
    }
    {
        let owned_ro: Vec<PathBuf> = [
            cfg.tls.cert_path.as_ref().map(PathBuf::from),
            cfg.tls.key_path.as_ref().map(PathBuf::from),
        ]
        .into_iter()
        .flatten()
        .collect();
        let ro_refs: Vec<&std::path::Path> = owned_ro.iter().map(|p| p.as_path()).collect();
        match hardening::apply_sandbox(
            &cfg.hardening,
            std::path::Path::new(&cfg.server.state_dir),
            &ro_refs,
        )? {
            hardening::SandboxResult::Applied { landlock, seccomp } => {
                info!(%landlock, %seccomp, "sandbox ready")
            }
            hardening::SandboxResult::Disabled => {}
            hardening::SandboxResult::Skipped { reason } => {
                info!(%reason, "sandbox skipped")
            }
        }
    }
    hardening::sd_notify_ready();

    let audit = match AuditSink::from_logging(
        &cfg.logging.audit_jsonl,
        cfg.logging.audit_jsonl_max_bytes,
        cfg.logging.audit_jsonl_max_age_secs,
    ) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "audit jsonl open failed; audit disabled");
            AuditSink::disabled()
        }
    };
    if audit.enabled() {
        info!(path = ?audit.path(), "audit jsonl enabled");
        audit.emit_startup(VERSION);
    }
    let state = ProxyState::with_audit(cfg.clone(), audit.clone());
    let acme_status = acme_mgr.as_ref().map(|m| m.status.clone());

    // Admin socket + optional loopback metrics sidecar + SIGHUP reload (P14.1/P14.6)
    {
        let acme_started = acme_mgr.is_some();
        let admin_state = AdminState {
            user_config,
            state_dir: PathBuf::from(&cfg.server.state_dir),
            config: state.config.clone(),
            tokens: admin::LiveAdminTokens::from_config(&cfg),
            limiter: state.limiter.clone(),
            tls: tls_state.clone(),
            acme: acme_mgr,
            acme_status,
            audit,
            started_at: admin::now_start(),
            boot: admin::RestartOnlySnapshot::from_boot(&cfg, acme_started),
        };
        let sock = PathBuf::from(&cfg.server.admin_socket);
        let admin_for_metrics = admin_state.clone();
        let admin_for_sighup = admin_state.clone();
        tokio::spawn(async move {
            if let Err(e) = admin::serve_admin(&sock, admin_state).await {
                warn!(error = %e, "admin socket terminated");
            }
        });
        #[cfg(unix)]
        tokio::spawn(async move {
            admin::serve_sighup_reload(admin_for_sighup).await;
        });
        #[cfg(not(unix))]
        let _ = admin_for_sighup;
        if let Some(ref listen) = cfg.server.metrics_listen {
            if !listen.is_empty() {
                if let Ok(addr) = listen.parse::<SocketAddr>() {
                    tokio::spawn(async move {
                        if let Err(e) = admin::serve_metrics_sidecar(addr, admin_for_metrics).await
                        {
                            warn!(error = %e, "metrics sidecar terminated");
                        }
                    });
                } else {
                    warn!(%listen, "invalid metrics_listen; sidecar not started");
                }
            }
        }
    }

    // Optional redirect listener
    if cfg.tls.enabled || cfg.acme.enabled {
        if let Ok(addr) = cfg.server.http_redirect_listen.parse::<SocketAddr>() {
            if let Ok(listener) = TcpListener::bind(addr).await {
                let https_port = cfg
                    .server
                    .listen_tls
                    .rsplit(':')
                    .next()
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(443);
                tokio::spawn(async move {
                    let _ = tls::serve_redirect(listener, https_port).await;
                });
            }
        }
    }

    // HTTP/3 experimental
    #[cfg(feature = "http3")]
    if sedat::http3::h3_enabled(&cfg) {
        if let Some(ref ts) = tls_state {
            let addr: SocketAddr = cfg.server.listen_tls.parse()?;
            let st = state.clone();
            let ts = ts.clone();
            let lim = state.limiter.clone();
            tokio::spawn(async move {
                if let Err(e) = sedat::http3::serve_http3(addr, st, ts, lim).await {
                    warn!(error = %e, "HTTP/3 listener stopped");
                }
            });
        }
    }
    #[cfg(not(feature = "http3"))]
    if cfg.experimental.h3 {
        warn!("experimental.h3=true but binary built without feature `http3`");
    }

    let http_state = state.clone();
    let http_task = tokio::spawn(async move { proxy::serve_http(http_listener, http_state).await });

    if let (Some(listener), Some(ts)) = (tls_listener, tls_state) {
        let https_state = state.clone();
        tokio::spawn(async move { tls::serve_https(listener, https_state, ts).await });
    }

    info!(version = VERSION, "SeDat running");
    http_task.await??;
    Ok(())
}
