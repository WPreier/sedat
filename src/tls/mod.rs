//! rustls TLS termination with cert hot-swap.

use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, Once};

use arc_swap::ArcSwap;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

static INSTALL_CRYPTO: Once = Once::new();

/// Install the process-wide rustls crypto provider (ring). Safe to call repeatedly.
pub fn ensure_crypto_provider() {
    INSTALL_CRYPTO.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

use crate::config::SedatConfig;
use crate::limits::ConnectionGuard;
use crate::proxy::{
    accept_with_inbound_proxy_placement, apply_inbound_after_tls, handle_request, PrefixedIo,
    ProxyState,
};

use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};

/// Hot-swappable TLS acceptor.
#[derive(Clone)]
pub struct TlsState {
    /// Current server config.
    pub config: Arc<ArcSwap<ServerConfig>>,
}

impl TlsState {
    /// Build from rustls ServerConfig.
    pub fn new(server: ServerConfig) -> Self {
        Self {
            config: Arc::new(ArcSwap::from_pointee(server)),
        }
    }

    /// Replace certificate/key material (keeps previous if caller fails before swap).
    pub fn swap(&self, server: ServerConfig) {
        self.config.store(Arc::new(server));
    }

    /// Current acceptor snapshot.
    pub fn acceptor(&self) -> TlsAcceptor {
        TlsAcceptor::from(self.config.load_full())
    }
}

/// Load PEM cert + key into a rustls ServerConfig (TLS 1.2/1.3, ALPN h2/http1.1).
pub fn load_server_config(cert_path: &Path, key_path: &Path) -> io::Result<ServerConfig> {
    let cert_pem = fs::read(cert_path)?;
    let key_pem = fs::read(key_path)?;
    server_config_from_pem(&cert_pem, &key_pem)
}

/// Build ServerConfig from PEM bytes.
pub fn server_config_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> io::Result<ServerConfig> {
    let mut certs = Vec::new();
    let mut reader = io::Cursor::new(cert_pem);
    for item in rustls_pemfile::certs(&mut reader) {
        certs.push(item.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?);
    }
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no certificates",
        ));
    }

    let mut key_reader = io::Cursor::new(key_pem);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key"))?;

    build_server_config(certs, key)
}

fn build_server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> io::Result<ServerConfig> {
    ensure_crypto_provider();
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Generate a self-signed cert for local tests (rcgen).
pub fn generate_self_signed(host: &str) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let cert =
        rcgen::generate_simple_self_signed(vec![host.to_string()]).map_err(io::Error::other)?;
    let cert_pem = cert.cert.pem().into_bytes();
    let key_pem = cert.key_pair.serialize_pem().into_bytes();
    Ok((cert_pem, key_pem))
}

/// HTTPS accept loop with HTTP/1.1 and HTTP/2 (via ALPN).
pub async fn serve_https(
    listener: TcpListener,
    state: ProxyState,
    tls: TlsState,
) -> io::Result<()> {
    info!(addr = %listener.local_addr()?, "HTTPS listener ready");
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        let tls = tls.clone();
        let Some(_slot) = ConnectionGuard::acquire(state.limiter.clone()) else {
            warn!(%peer, "connection limit reached");
            continue;
        };
        tokio::spawn(async move {
            let _slot = _slot;
            let cfg = state.config.load();
            let pp = cfg.proxy_protocol.clone();
            let accepted = match accept_with_inbound_proxy_placement(
                stream,
                peer,
                pp.inbound_enabled,
                &pp.inbound_allowlist,
                &pp.inbound_placement,
            )
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(reason)) => {
                    warn!(
                        %peer,
                        reason = reason.as_str(),
                        "rejected inbound PROXY on HTTPS (plaintext stage)"
                    );
                    state.audit.emit_proxy_reject(
                        &peer.to_string(),
                        reason.as_str(),
                        "plaintext",
                    );
                    return;
                }
                Err(e) => {
                    tracing::debug!(error = %e, %peer, "inbound PROXY probe failed");
                    return;
                }
            };
            let (stream, client_before_tls) = accepted;
            let idle = state.limiter.request_timeout();
            let acceptor = tls.acceptor();
            let mut tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(error = %e, %peer, "TLS handshake failed");
                    return;
                }
            };
            // PP2-over-TLS: parse PROXY on the decrypted stream after handshake.
            let after = match apply_inbound_after_tls(
                &mut tls_stream,
                peer,
                pp.inbound_enabled,
                &pp.inbound_allowlist,
                &pp.inbound_placement,
            )
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(reason)) => {
                    warn!(
                        %peer,
                        reason = reason.as_str(),
                        "rejected inbound PROXY after TLS"
                    );
                    state.audit.emit_proxy_reject(
                        &peer.to_string(),
                        reason.as_str(),
                        "after_tls",
                    );
                    return;
                }
                Err(e) => {
                    tracing::debug!(error = %e, %peer, "post-TLS PROXY probe failed");
                    return;
                }
            };
            // after_tls: trust post-handshake PROXY rewrite; otherwise keep pre-TLS client.
            let client = if pp.inbound_placement == "after_tls" && pp.inbound_enabled {
                after.0
            } else {
                client_before_tls
            };
            let leftover = after.1;
            let (_, server_conn) = tls_stream.get_ref();
            let sni = server_conn.server_name().map(|s| s.to_string());
            let alpn = server_conn
                .alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).into_owned());
            let io = TokioIo::new(PrefixedIo::new(tls_stream, leftover));
            let svc = service_fn(move |req| {
                let state = state.clone();
                let sni = sni.clone();
                async move { handle_request(req, client, state, sni).await }
            });
            let serve = async {
                if alpn.as_deref() == Some("h2") {
                    http2::Builder::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await
                        .map_err(io::Error::other)
                } else {
                    http1::Builder::new()
                        .serve_connection(io, svc)
                        .await
                        .map_err(io::Error::other)
                }
            };
            match tokio::time::timeout(idle, serve).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::debug!(error = %e, %peer, "HTTPS connection closed"),
                Err(_) => tracing::debug!(%peer, "HTTPS connection idle/request timeout"),
            }
        });
    }
}

/// Optional HTTP→HTTPS redirect listener.
pub async fn serve_redirect(listener: TcpListener, https_port: u16) -> io::Result<()> {
    use http_body_util::Full;
    use hyper::Response;
    use hyper::StatusCode;

    info!(addr = %listener.local_addr()?, "HTTP redirect listener ready");
    loop {
        let (stream, peer) = listener.accept().await?;
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(
                move |req: hyper::Request<hyper::body::Incoming>| async move {
                    let host = req
                        .headers()
                        .get(hyper::header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("localhost");
                    let host_only = host.split(':').next().unwrap_or(host);
                    let path = req
                        .uri()
                        .path_and_query()
                        .map(|p| p.as_str())
                        .unwrap_or("/");
                    let loc = format!("https://{host_only}:{https_port}{path}");
                    let resp = Response::builder()
                        .status(StatusCode::PERMANENT_REDIRECT)
                        .header(hyper::header::LOCATION, loc)
                        .body(Full::new(Bytes::from_static(b"")))
                        .unwrap();
                    Ok::<_, Infallible>(resp)
                },
            );
            let _ = http1::Builder::new().serve_connection(io, svc).await;
            let _ = peer;
        });
    }
}

use bytes::Bytes;
use std::convert::Infallible;

/// Resolve TLS material from config (static files or self-signed fallback for tests).
pub fn resolve_tls_config(cfg: &SedatConfig) -> io::Result<Option<TlsState>> {
    if !cfg.tls.enabled && !cfg.acme.enabled {
        return Ok(None);
    }
    if let (Some(cert), Some(key)) = (&cfg.tls.cert_path, &cfg.tls.key_path) {
        let sc = load_server_config(Path::new(cert), Path::new(key))?;
        return Ok(Some(TlsState::new(sc)));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_loads() {
        let (cert, key) = generate_self_signed("localhost").unwrap();
        let cfg = server_config_from_pem(&cert, &key).unwrap();
        assert!(!cfg.alpn_protocols.is_empty());
    }
}
