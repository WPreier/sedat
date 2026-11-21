//! Upstream forwarding with optional PROXY header, IP pin, and HTTPS/mTLS.
//!
//! Request bodies are written with HTTP/1.1 chunked transfer (no full-buffer).
//! Response bodies are streamed via a channel under `max_body_bytes` (fail-closed).

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use hyper::{Request, Response, Uri};
use rustls::pki_types::ServerName;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::ProxyProtocolConfig;

use super::proxy_protocol::{encode_proxy_v1, encode_proxy_v2, ProxyVersion};
use super::router::RouteMatch;
use super::upstream_mtls::{build_upstream_client_config, UpstreamTlsPaths};
use super::upstream_pin::{
    expand_allowlist, filter_pinned_addrs_expanded, ip_allowed_by_pin, DnsCache, ExpandedPin,
};

/// Boxed body error used across proxy responses.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// Streaming / full response body type.
pub type ForwardBody = http_body_util::combinators::BoxBody<Bytes, BoxError>;

/// Proxy forwarding error.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Bad upstream URL.
    #[error("invalid upstream URL: {0}")]
    BadUpstream(String),
    /// Connect/IO failure.
    #[error("upstream I/O: {0}")]
    Io(#[from] std::io::Error),
    /// Hyper client error.
    #[error("hyper: {0}")]
    Hyper(String),
    /// Body too large.
    #[error("request body exceeds limit")]
    BodyTooLarge,
    /// Resolved / connected upstream IP not in route allowlist (fail-closed).
    #[error("upstream IP not allowed by pin: {0}")]
    UpstreamNotAllowed(String),
    /// Upstream TLS / mTLS setup or handshake failed.
    #[error("upstream TLS: {0}")]
    Tls(String),
}

/// Optional request-id injection: `(header_name, value)` set on the upstream
/// HTTP request **after** any PROXY framing.
pub type RequestIdFwd<'a> = Option<(&'a str, &'a str)>;

/// Hyper body fed by upstream response DATA chunks.
struct UpstreamChanBody {
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
}

impl Body for UpstreamChanBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(Ok(buf))) => Poll::Ready(Some(Ok(Frame::data(buf)))),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn box_upstream_body(body: UpstreamChanBody) -> ForwardBody {
    body.map_err(|e| -> BoxError { Box::new(e) }).boxed()
}

/// Forward `req` to the matched upstream.
pub async fn proxy_request<B>(
    req: Request<B>,
    client_addr: SocketAddr,
    route: &RouteMatch,
    pp: &ProxyProtocolConfig,
    max_body: usize,
    request_id: RequestIdFwd<'_>,
    dns_cache: &DnsCache,
) -> Result<Response<ForwardBody>, ProxyError>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let upstream_base: Uri = route
        .upstream
        .parse()
        .map_err(|_| ProxyError::BadUpstream(route.upstream.clone()))?;
    let scheme = upstream_base.scheme_str().unwrap_or("http");
    let use_tls = scheme.eq_ignore_ascii_case("https");
    let authority = upstream_base
        .authority()
        .ok_or_else(|| ProxyError::BadUpstream(route.upstream.clone()))?
        .clone();
    let host = authority.host();
    let port = authority
        .port_u16()
        .unwrap_or(if use_tls { 443 } else { 80 });

    let (parts, body) = req.into_parts();

    // Rebuild path: strip matched prefix unless prefix is `/`.
    let orig_path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let forward_path = if route.prefix == "/" {
        orig_path.to_string()
    } else {
        let stripped = orig_path.strip_prefix(&route.prefix).unwrap_or(orig_path);
        if stripped.is_empty() {
            "/".into()
        } else if stripped.starts_with('/') {
            stripped.to_string()
        } else {
            format!("/{stripped}")
        }
    };

    let version = ProxyVersion::parse(&pp.outbound);
    let refresh = Duration::from_secs(route.upstream_dns_refresh_secs);
    let stream =
        connect_pinned_upstream(host, port, &route.upstream_allowlist, dns_cache, refresh).await?;

    // Plain HTTP upstream: optional PROXY framing, then HTTP.
    // HTTPS / mTLS: ClientHello must be first on the wire — skip outbound PROXY
    // (set outbound=off for clarity; non-off is ignored here with a debug log).
    if use_tls {
        if !matches!(version, ProxyVersion::Off) {
            tracing::debug!(
                outbound = %pp.outbound,
                "skipping outbound PROXY for https upstream (TLS handshake first)"
            );
        }
        let client_cfg = build_upstream_client_config(&UpstreamTlsPaths {
            cert: &route.upstream_mtls_cert,
            key: &route.upstream_mtls_key,
            ca: &route.upstream_mtls_ca,
        })
        .map_err(|e| ProxyError::Tls(e.to_string()))?;
        let connector = TlsConnector::from(client_cfg);
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| ProxyError::Tls(format!("invalid SNI host `{host}`: {e}")))?;
        let tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| ProxyError::Tls(e.to_string()))?;
        exchange_http(
            tls,
            &parts,
            &forward_path,
            &authority,
            body,
            max_body,
            request_id,
        )
        .await
    } else {
        let mut stream = stream;
        let local = stream.local_addr()?;
        match version {
            ProxyVersion::Off => {}
            ProxyVersion::V1 => {
                let hdr = encode_proxy_v1(client_addr, local);
                stream.write_all(&hdr).await?;
            }
            ProxyVersion::V2 => {
                let hdr = encode_proxy_v2(client_addr, local);
                stream.write_all(&hdr).await?;
            }
        }
        exchange_http(
            stream,
            &parts,
            &forward_path,
            &authority,
            body,
            max_body,
            request_id,
        )
        .await
    }
}

async fn write_chunked_request<S, B>(
    stream: &mut S,
    parts: &http::request::Parts,
    forward_path: &str,
    authority: &http::uri::Authority,
    body: B,
    max_body: usize,
    request_id: RequestIdFwd<'_>,
) -> Result<(), ProxyError>
where
    S: AsyncWrite + Unpin,
    B: Body,
    B::Error: std::error::Error,
{
    let method = parts.method.as_str();
    let mut out = format!("{method} {forward_path} HTTP/1.1\r\n");
    out.push_str(&format!("Host: {authority}\r\n"));
    out.push_str("Connection: close\r\n");
    out.push_str("Transfer-Encoding: chunked\r\n");
    for (name, value) in parts.headers.iter() {
        let n = name.as_str();
        if n.eq_ignore_ascii_case("host")
            || n.eq_ignore_ascii_case("connection")
            || n.eq_ignore_ascii_case("transfer-encoding")
            || n.eq_ignore_ascii_case("content-length")
            || n.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        // Drop inbound copy of the correlation header; we re-inject a sanitized value.
        if let Some((hdr, _)) = request_id {
            if n.eq_ignore_ascii_case(hdr) {
                continue;
            }
        }
        if let Ok(v) = value.to_str() {
            out.push_str(n);
            out.push_str(": ");
            out.push_str(v);
            out.push_str("\r\n");
        }
    }
    if let Some((hdr, id)) = request_id {
        out.push_str(hdr);
        out.push_str(": ");
        out.push_str(id);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    stream.write_all(out.as_bytes()).await?;

    let mut seen = 0usize;
    let mut body = std::pin::pin!(body);
    while let Some(frame) = body.as_mut().frame().await {
        let frame = frame.map_err(|e| ProxyError::Hyper(e.to_string()))?;
        if let Ok(mut data) = frame.into_data() {
            use bytes::Buf;
            let n = data.remaining();
            if n == 0 {
                continue;
            }
            if seen.saturating_add(n) > max_body {
                return Err(ProxyError::BodyTooLarge);
            }
            seen += n;
            let chunk = data.copy_to_bytes(n);
            let header = format!("{n:x}\r\n");
            stream.write_all(header.as_bytes()).await?;
            stream.write_all(&chunk).await?;
            stream.write_all(b"\r\n").await?;
        }
    }
    stream.write_all(b"0\r\n\r\n").await?;
    Ok(())
}

/// Read until `\r\n\r\n`; returns (header_bytes_without_terminator, leftover_body).
async fn read_response_head<S: AsyncRead + Unpin>(
    stream: &mut S,
    max_header_bytes: usize,
) -> Result<(Vec<u8>, Bytes), ProxyError> {
    let mut buf = BytesMut::with_capacity(512);
    let mut tmp = [0u8; 512];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(ProxyError::Hyper("incomplete upstream response".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > max_header_bytes {
            return Err(ProxyError::Hyper(
                "upstream response headers too large".into(),
            ));
        }
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = buf[..pos].to_vec();
            let leftover = buf.split_off(pos + 4).freeze();
            return Ok((header, leftover));
        }
    }
}

fn parse_status_and_headers(
    header_bytes: &[u8],
) -> Result<(u16, http::HeaderMap, Option<usize>), ProxyError> {
    let header_str =
        std::str::from_utf8(header_bytes).map_err(|e| ProxyError::Hyper(e.to_string()))?;
    let mut lines = header_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| ProxyError::Hyper("missing status".into()))?;
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let code: u16 = parts
        .next()
        .ok_or_else(|| ProxyError::Hyper("missing status code".into()))?
        .parse()
        .map_err(|e| ProxyError::Hyper(format!("{e}")))?;

    let mut headers = http::HeaderMap::new();
    let mut content_length = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if k.eq_ignore_ascii_case("transfer-encoding") || k.eq_ignore_ascii_case("connection") {
                continue;
            }
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().ok();
            }
            if let (Ok(name), Ok(value)) = (
                http::HeaderName::from_bytes(k.as_bytes()),
                http::HeaderValue::from_str(v),
            ) {
                headers.append(name, value);
            }
        }
    }
    Ok((code, headers, content_length))
}

async fn pump_response_body<S: AsyncRead + Unpin + Send + 'static>(
    mut stream: S,
    leftover: Bytes,
    content_length: Option<usize>,
    max_body: usize,
    tx: tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
) {
    let mut seen = 0usize;

    if !leftover.is_empty() {
        if leftover.len() > max_body {
            let _ = tx
                .send(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "response body exceeds limit",
                )))
                .await;
            return;
        }
        if let Some(cl) = content_length {
            if leftover.len() > cl {
                let _ = tx
                    .send(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "response longer than Content-Length",
                    )))
                    .await;
                return;
            }
        }
        seen = leftover.len();
        if tx.send(Ok(leftover)).await.is_err() {
            return;
        }
    }

    let mut tmp = [0u8; 16 * 1024];
    loop {
        if let Some(cl) = content_length {
            if seen >= cl {
                break;
            }
        }
        let want = match content_length {
            Some(cl) => (cl - seen).min(tmp.len()),
            None => tmp.len(),
        };
        let n = match stream.read(&mut tmp[..want]).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return;
            }
        };
        if seen.saturating_add(n) > max_body {
            let _ = tx
                .send(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "response body exceeds limit",
                )))
                .await;
            return;
        }
        seen += n;
        if tx
            .send(Ok(Bytes::copy_from_slice(&tmp[..n])))
            .await
            .is_err()
        {
            return;
        }
    }
}

async fn exchange_http<S, B>(
    mut stream: S,
    parts: &http::request::Parts,
    forward_path: &str,
    authority: &http::uri::Authority,
    body: B,
    max_body: usize,
    request_id: RequestIdFwd<'_>,
) -> Result<Response<ForwardBody>, ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    write_chunked_request(
        &mut stream,
        parts,
        forward_path,
        authority,
        body,
        max_body,
        request_id,
    )
    .await?;

    // Cap header block similarly to request header limits (16 KiB default).
    let (header_bytes, leftover) = read_response_head(&mut stream, 16_384).await?;
    let (code, headers, content_length) = parse_status_and_headers(&header_bytes)?;

    if let Some(cl) = content_length {
        if cl > max_body {
            return Err(ProxyError::BodyTooLarge);
        }
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(8);
    tokio::spawn(async move {
        pump_response_body(stream, leftover, content_length, max_body, tx).await;
    });

    let mut builder = Response::builder().status(code);
    for (k, v) in headers.iter() {
        builder = builder.header(k, v);
    }
    builder
        .body(box_upstream_body(UpstreamChanBody { rx }))
        .map_err(|e| ProxyError::Hyper(e.to_string()))
}

/// Resolve `host:port` (cached), apply optional IP/hostname pin, connect.
async fn connect_pinned_upstream(
    host: &str,
    port: u16,
    allowlist: &[String],
    dns_cache: &DnsCache,
    refresh: Duration,
) -> Result<TcpStream, ProxyError> {
    let resolved = dns_cache
        .resolve_host_addrs(host, port, refresh)
        .await
        .map_err(ProxyError::Io)?;
    if resolved.is_empty() {
        return Err(ProxyError::UpstreamNotAllowed(format!(
            "no addresses for {host}:{port}"
        )));
    }

    let pin = expand_allowlist(allowlist, dns_cache, refresh).await;
    if matches!(
        &pin,
        ExpandedPin::Restricted { cidrs, host_ips }
            if cidrs.is_empty() && host_ips.is_empty()
    ) {
        return Err(ProxyError::UpstreamNotAllowed(format!(
            "allowlist {allowlist:?} resolved empty (fail-closed) for {host}:{port}"
        )));
    }

    let candidates = filter_pinned_addrs_expanded(&resolved, &pin);
    if candidates.is_empty() {
        let ips: Vec<String> = resolved.iter().map(|a| a.ip().to_string()).collect();
        return Err(ProxyError::UpstreamNotAllowed(format!(
            "resolved [{ips}] not in allowlist {allowlist:?} for {host}:{port}",
            ips = ips.join(", ")
        )));
    }

    let mut last_err: Option<std::io::Error> = None;
    for addr in candidates {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                if let Ok(peer) = stream.peer_addr() {
                    if !ip_allowed_by_pin(peer.ip(), &pin) {
                        return Err(ProxyError::UpstreamNotAllowed(format!(
                            "connected peer {} rejected by pin",
                            peer.ip()
                        )));
                    }
                }
                return Ok(stream);
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(ProxyError::Io(last_err.unwrap_or_else(|| {
        std::io::Error::other("all pinned upstream connects failed")
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use tokio::io::DuplexStream;

    #[tokio::test]
    async fn chunked_request_and_streamed_response() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            // Read request until end chunk.
            loop {
                let n = server.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(5).any(|w| w == b"0\r\n\r\n") {
                    break;
                }
            }
            assert!(
                std::str::from_utf8(&buf)
                    .unwrap()
                    .contains("Transfer-Encoding: chunked"),
                "request should be chunked"
            );
            assert!(
                buf.windows(9).any(|w| w == b"stream-me")
                    || buf.windows(9).any(|w| w == b"9\r\nstre")
            );
            let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong";
            server.write_all(resp).await.unwrap();
        });

        let parts = Request::builder()
            .method("POST")
            .uri("http://example/x")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let body = Full::new(Bytes::from_static(b"stream-me"));
        let resp = exchange_http(
            client,
            &parts,
            "/x",
            &"example".parse().unwrap(),
            body,
            1024,
            None,
        )
        .await
        .unwrap();
        assert_eq!(resp.status(), 200);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"pong");
    }

    #[tokio::test]
    async fn oversize_request_body_fail_closed() {
        let (client, _server): (DuplexStream, DuplexStream) = tokio::io::duplex(1024);
        let parts = Request::builder()
            .method("POST")
            .uri("http://example/x")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let body = Full::new(Bytes::from(vec![b'x'; 64]));
        let err = exchange_http(
            client,
            &parts,
            "/x",
            &"example".parse().unwrap(),
            body,
            16,
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProxyError::BodyTooLarge));
    }
}
