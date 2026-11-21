//! Optional HTTP/3 (QUIC) listener — gated by feature `http3` and `experimental.h3`.
//!
//! With `http3` enabled, accepted connections are driven through hyperium `h3` /
//! `h3-quinn` and requests are handed to [`crate::proxy::handle_request`].

use std::net::SocketAddr;
use std::sync::Arc;

use tracing::{debug, info, warn};

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
    let max = limits.max_h3_connections();
    info!(%addr, max_h3 = max, "HTTP/3 listener starting (experimental)");

    #[cfg(feature = "http3")]
    {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use quinn::Endpoint;

        let active = Arc::new(AtomicUsize::new(0));
        // Snapshot TLS material; ALPN must be `h3` for QUIC (TCP path keeps h2/http1.1).
        let mut server_crypto = (*tls.config.load_full()).clone();
        server_crypto.alpn_protocols = vec![b"h3".to_vec()];
        let quic_cfg = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| std::io::Error::other(format!("{e}")))?;
        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(quic_cfg));
        if let Some(transport) = Arc::get_mut(&mut server_cfg.transport) {
            transport.max_concurrent_bidi_streams((limits.max_h3_streams() as u32).into());
            transport.max_concurrent_uni_streams(32u32.into());
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
            let state = state.clone();
            let limits = limits.clone();
            tokio::spawn(async move {
                match connecting.await {
                    Ok(conn) => {
                        let peer = conn.remote_address();
                        debug!(%peer, "h3 connection");
                        if let Err(e) = drive_h3_connection(conn, peer, state, limits).await {
                            debug!(%peer, error = %e, "h3 connection ended");
                        }
                    }
                    Err(e) => debug!(error = %e, "h3 handshake failed"),
                }
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
        Ok(())
    }

    #[cfg(not(feature = "http3"))]
    {
        let _ = (addr, max, state, tls);
        warn!("HTTP/3 requested but binary built without `http3` feature");
        std::future::pending::<()>().await;
        Ok(())
    }
}

#[cfg(feature = "http3")]
async fn drive_h3_connection(
    conn: quinn::Connection,
    peer: SocketAddr,
    state: ProxyState,
    limits: Arc<Limiter>,
) -> Result<(), String> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;

    let max_streams = limits.max_h3_streams();
    let streams_inflight = Arc::new(AtomicUsize::new(0));
    let quic = h3_quinn::Connection::new(conn);
    let mut h3_conn = h3::server::Connection::<_, Bytes>::new(quic)
        .await
        .map_err(|e| format!("h3 handshake: {e}"))?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let cur = streams_inflight.fetch_add(1, Ordering::SeqCst);
                if cur >= max_streams {
                    streams_inflight.fetch_sub(1, Ordering::SeqCst);
                    warn!(%peer, "HTTP/3 stream limit reached");
                    continue;
                }
                let state = state.clone();
                let limits = limits.clone();
                let streams_inflight = streams_inflight.clone();
                tokio::spawn(async move {
                    let _ = handle_h3_request(resolver, peer, state, limits).await;
                    streams_inflight.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Ok(None) => break,
            Err(e) => {
                debug!(%peer, error = %e, "h3 accept ended");
                break;
            }
        }
    }
    Ok(())
}

#[cfg(feature = "http3")]
async fn handle_h3_request<C>(
    resolver: h3::server::RequestResolver<C, bytes::Bytes>,
    peer: SocketAddr,
    state: ProxyState,
    limits: Arc<Limiter>,
) -> Result<(), String>
where
    C: h3::quic::Connection<bytes::Bytes>,
    C::BidiStream: Send + 'static,
{
    use bytes::{Buf, BytesMut};
    use http_body_util::{BodyExt, Full};

    let (req, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|e| format!("h3 resolve: {e}"))?;

    let max_body = limits.max_body_bytes();
    let mut body = BytesMut::new();
    loop {
        match stream.recv_data().await {
            Ok(Some(mut chunk)) => {
                while chunk.has_remaining() {
                    let n = chunk.remaining();
                    if body.len() + n > max_body {
                        let _ = stream
                            .send_response(
                                http::Response::builder()
                                    .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                                    .body(())
                                    .unwrap(),
                            )
                            .await;
                        let _ = stream.finish().await;
                        return Err("h3 body too large".into());
                    }
                    body.extend_from_slice(chunk.chunk());
                    chunk.advance(n);
                }
            }
            Ok(None) => break,
            Err(e) => return Err(format!("h3 recv body: {e}")),
        }
    }
    let _ = stream.recv_trailers().await;

    let req = req.map(|_| Full::new(body.freeze()));
    let resp = crate::proxy::handle_request(req, peer, state, None)
        .await
        .unwrap_or_else(|infallible| match infallible {});

    let status = resp.status();
    let headers = resp.headers().clone();
    let mut builder = http::Response::builder().status(status);
    for (k, v) in headers.iter() {
        builder = builder.header(k, v);
    }
    let h3_resp = builder
        .body(())
        .map_err(|e| format!("h3 resp build: {e}"))?;
    stream
        .send_response(h3_resp)
        .await
        .map_err(|e| format!("h3 send_response: {e}"))?;

    let collected = resp
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    if !collected.is_empty() {
        stream
            .send_data(collected)
            .await
            .map_err(|e| format!("h3 send_data: {e}"))?;
    }
    stream
        .finish()
        .await
        .map_err(|e| format!("h3 finish: {e}"))?;
    Ok(())
}
