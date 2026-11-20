//! Optional HTTP/3 (QUIC) listener — gated by feature `http3` and `experimental.h3`.

use std::net::SocketAddr;
use std::sync::Arc;

use tracing::{info, warn};

use crate::config::SedatConfig;
use crate::limits::Limiter;
use crate::proxy::ProxyState;
use crate::tls::TlsState;

/// Whether config + build allow enabling H3.
pub fn h3_enabled(cfg: &SedatConfig) -> bool {
    cfg.experimental.h3 && cfg!(feature = "http3")
}

/// Run an HTTP/3 listener when the `http3` feature is enabled.
pub async fn serve_http3(
    addr: SocketAddr,
    state: ProxyState,
    tls: TlsState,
    limits: Arc<Limiter>,
) -> std::io::Result<()> {
    let _ = (state, tls);
    let max = limits.max_h3_connections();
    info!(%addr, max_h3 = max, "HTTP/3 listener starting (experimental)");

    #[cfg(feature = "http3")]
    {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use quinn::Endpoint;

        let active = Arc::new(AtomicUsize::new(0));
        let (cert_pem, key_pem) = crate::tls::generate_self_signed("localhost")?;
        let server_crypto = crate::tls::server_config_from_pem(&cert_pem, &key_pem)?;
        let quic_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| std::io::Error::other(format!("{e}")))?;
        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_cfg));
        if let Some(transport) = Arc::get_mut(&mut server_cfg.transport) {
            transport.max_concurrent_bidi_streams((limits.max_h3_streams() as u32).into());
        }

        let endpoint = Endpoint::server(server_cfg, addr)?;
        info!(%addr, "HTTP/3 QUIC endpoint ready");

        while let Some(connecting) = endpoint.accept().await {
            let cur = active.fetch_add(1, Ordering::SeqCst);
            if cur >= max {
                active.fetch_sub(1, Ordering::SeqCst);
                warn!("HTTP/3 connection limit reached");
                continue;
            }
            let active = active.clone();
            tokio::spawn(async move {
                match connecting.await {
                    Ok(conn) => {
                        tracing::debug!(remote = %conn.remote_address(), "h3 connection");
                        conn.close(0u32.into(), b"sedat-h3-experimental");
                    }
                    Err(e) => tracing::debug!(error = %e, "h3 handshake failed"),
                }
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
        Ok(())
    }

    #[cfg(not(feature = "http3"))]
    {
        let _ = (addr, max);
        warn!("HTTP/3 requested but binary built without `http3` feature");
        std::future::pending::<()>().await;
        Ok(())
    }
}
