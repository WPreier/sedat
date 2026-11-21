//! Optional HTTP/3 (QUIC) listener — gated by feature `http3` and `experimental.h3`.
//!
//! With `http3` enabled, accepted connections are driven through hyperium `h3` /
//! `h3-quinn` and requests are handed to [`crate::proxy::handle_request`].
//!
//! Request and response bodies are streamed (no full intermediate buffer on the
//! H3 edge); size is tracked against `max_body_bytes` and oversize is fail-closed.

use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(feature = "http3")]
use tracing::debug;
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
#[derive(Debug, thiserror::Error)]
enum H3BodyError {
    #[error("request body exceeds limit")]
    TooLarge,
    #[error("h3 recv body: {0}")]
    Recv(String),
}

#[cfg(feature = "http3")]
enum PumpOutcome<S> {
    Complete(S),
    TooLarge(S),
    Failed(S, String),
}

/// Hyper body backed by an mpsc of H3 DATA frames (no full-buffer assemble).
#[cfg(feature = "http3")]
struct H3ChanBody {
    rx: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, H3BodyError>>,
}

#[cfg(feature = "http3")]
impl hyper::body::Body for H3ChanBody {
    type Data = bytes::Bytes;
    type Error = H3BodyError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(buf))) => Poll::Ready(Some(Ok(hyper::body::Frame::data(buf)))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(feature = "http3")]
async fn pump_h3_request_body<S>(
    mut stream: h3::server::RequestStream<S, bytes::Bytes>,
    max_body: usize,
    tx: tokio::sync::mpsc::Sender<Result<bytes::Bytes, H3BodyError>>,
) -> PumpOutcome<h3::server::RequestStream<S, bytes::Bytes>>
where
    S: h3::quic::RecvStream + h3::quic::SendStream<bytes::Bytes>,
{
    use bytes::Buf;

    let mut seen = 0usize;
    loop {
        match stream.recv_data().await {
            Ok(Some(mut chunk)) => {
                while chunk.has_remaining() {
                    let n = chunk.remaining();
                    if seen.saturating_add(n) > max_body {
                        let _ = tx.send(Err(H3BodyError::TooLarge)).await;
                        stream.stop_sending(h3::error::Code::H3_NO_ERROR);
                        return PumpOutcome::TooLarge(stream);
                    }
                    seen += n;
                    let data = bytes::Bytes::copy_from_slice(chunk.chunk());
                    chunk.advance(n);
                    if tx.send(Ok(data)).await.is_err() {
                        // Consumer dropped (e.g. early deny); stop reading and keep stream.
                        stream.stop_sending(h3::error::Code::H3_NO_ERROR);
                        return PumpOutcome::Complete(stream);
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                let msg = e.to_string();
                let _ = tx.send(Err(H3BodyError::Recv(msg.clone()))).await;
                return PumpOutcome::Failed(stream, msg);
            }
        }
    }
    let _ = stream.recv_trailers().await;
    drop(tx);
    PumpOutcome::Complete(stream)
}

#[cfg(feature = "http3")]
async fn send_h3_empty_status<S>(
    stream: &mut h3::server::RequestStream<S, bytes::Bytes>,
    status: http::StatusCode,
) -> Result<(), String>
where
    S: h3::quic::SendStream<bytes::Bytes>,
{
    let h3_resp = http::Response::builder()
        .status(status)
        .body(())
        .map_err(|e| format!("h3 resp build: {e}"))?;
    stream
        .send_response(h3_resp)
        .await
        .map_err(|e| format!("h3 send_response: {e}"))?;
    stream
        .finish()
        .await
        .map_err(|e| format!("h3 finish: {e}"))?;
    Ok(())
}

#[cfg(feature = "http3")]
async fn stream_h3_response<S, B>(
    stream: &mut h3::server::RequestStream<S, bytes::Bytes>,
    resp: http::Response<B>,
    max_body: usize,
) -> Result<(), String>
where
    S: h3::quic::SendStream<bytes::Bytes>,
    B: hyper::body::Body,
    B::Data: bytes::Buf,
    B::Error: std::fmt::Display,
{
    use bytes::Buf;
    use http_body_util::BodyExt;
    use std::pin::pin;

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

    let mut body = pin!(resp.into_body());
    let mut sent = 0usize;
    while let Some(frame) = body.as_mut().frame().await {
        let frame = frame.map_err(|e| format!("h3 resp body: {e}"))?;
        if let Ok(mut data) = frame.into_data() {
            let n = data.remaining();
            if n == 0 {
                continue;
            }
            if sent.saturating_add(n) > max_body {
                stream.stop_stream(h3::error::Code::H3_NO_ERROR);
                return Err("h3 response body too large".into());
            }
            sent += n;
            let chunk = data.copy_to_bytes(n);
            stream
                .send_data(chunk)
                .await
                .map_err(|e| format!("h3 send_data: {e}"))?;
        }
    }
    stream
        .finish()
        .await
        .map_err(|e| format!("h3 finish: {e}"))?;
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
    let (req, stream) = resolver
        .resolve_request()
        .await
        .map_err(|e| format!("h3 resolve: {e}"))?;

    let max_body = limits.max_body_bytes();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, H3BodyError>>(8);
    let (ret_tx, ret_rx) = tokio::sync::oneshot::channel::<
        PumpOutcome<h3::server::RequestStream<C::BidiStream, bytes::Bytes>>,
    >();

    tokio::spawn(async move {
        let outcome = pump_h3_request_body(stream, max_body, tx).await;
        let _ = ret_tx.send(outcome);
    });

    let req = req.map(|_| H3ChanBody { rx });
    let resp = crate::proxy::handle_request(req, peer, state, None)
        .await
        .unwrap_or_else(|infallible| match infallible {});

    let mut stream = match ret_rx.await {
        Ok(PumpOutcome::Complete(s)) => s,
        Ok(PumpOutcome::TooLarge(mut s)) => {
            let _ = send_h3_empty_status(&mut s, http::StatusCode::PAYLOAD_TOO_LARGE).await;
            return Err("h3 body too large".into());
        }
        Ok(PumpOutcome::Failed(mut s, msg)) => {
            let _ = send_h3_empty_status(&mut s, http::StatusCode::BAD_REQUEST).await;
            return Err(msg);
        }
        Err(_) => return Err("h3 body pump dropped".into()),
    };

    stream_h3_response(&mut stream, resp, max_body).await
}
