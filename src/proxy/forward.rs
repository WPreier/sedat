//! Upstream forwarding with optional PROXY header, IP pin, and HTTPS/mTLS.
//!
//! Request bodies are written with HTTP/1.1 chunked transfer (no full-buffer).
//! Response bodies are streamed via a channel under `max_body_bytes` (fail-closed),
//! including decoded upstream `Transfer-Encoding: chunked` payloads.

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

/// How to read the upstream response body after headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamBodyMode {
    ContentLength(usize),
    Chunked,
    UntilEof,
}

fn parse_status_and_headers(
    header_bytes: &[u8],
) -> Result<(u16, http::HeaderMap, UpstreamBodyMode), ProxyError> {
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
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if k.eq_ignore_ascii_case("connection") {
                continue;
            }
            if k.eq_ignore_ascii_case("transfer-encoding") {
                // RFC 9112: TE takes precedence over Content-Length.
                if v.to_ascii_lowercase()
                    .split(',')
                    .any(|t| t.trim() == "chunked")
                {
                    chunked = true;
                }
                continue;
            }
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().ok();
                continue; // decide after TE; only forward when not chunked
            }
            if let (Ok(name), Ok(value)) = (
                http::HeaderName::from_bytes(k.as_bytes()),
                http::HeaderValue::from_str(v),
            ) {
                headers.append(name, value);
            }
        }
    }

    let mode = if chunked {
        UpstreamBodyMode::Chunked
    } else if let Some(cl) = content_length {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(b"content-length"),
            http::HeaderValue::from_str(&cl.to_string()),
        ) {
            headers.insert(name, value);
        }
        UpstreamBodyMode::ContentLength(cl)
    } else {
        UpstreamBodyMode::UntilEof
    };
    Ok((code, headers, mode))
}

fn parse_chunk_size_line(line: &[u8]) -> Result<usize, std::io::Error> {
    let line = std::str::from_utf8(line).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("chunk size utf8: {e}"),
        )
    })?;
    let hex = line.split(';').next().unwrap_or(line).trim();
    usize::from_str_radix(hex, 16).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid chunk size `{hex}`: {e}"),
        )
    })
}

/// Buffered reader over leftover + TCP for response body framing.
struct BodyBuf<S> {
    stream: S,
    buf: BytesMut,
}

impl<S: AsyncRead + Unpin> BodyBuf<S> {
    fn new(stream: S, leftover: Bytes) -> Self {
        let mut buf = BytesMut::new();
        if !leftover.is_empty() {
            buf.extend_from_slice(&leftover);
        }
        Self { stream, buf }
    }

    async fn fill(&mut self) -> std::io::Result<usize> {
        let mut tmp = [0u8; 16 * 1024];
        let n = self.stream.read(&mut tmp).await?;
        if n > 0 {
            self.buf.extend_from_slice(&tmp[..n]);
        }
        Ok(n)
    }

    async fn read_until_crlf(&mut self) -> std::io::Result<Bytes> {
        loop {
            if let Some(pos) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let line = self.buf.split_to(pos).freeze();
                let _ = self.buf.split_to(2);
                return Ok(line);
            }
            if self.fill().await? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof before CRLF",
                ));
            }
        }
    }

    async fn read_exact(&mut self, n: usize) -> std::io::Result<Bytes> {
        while self.buf.len() < n {
            if self.fill().await? == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof in body",
                ));
            }
        }
        Ok(self.buf.split_to(n).freeze())
    }

    async fn read_some(&mut self, max: usize) -> std::io::Result<Option<Bytes>> {
        if self.buf.is_empty() && self.fill().await? == 0 {
            return Ok(None);
        }
        let n = self.buf.len().min(max);
        Ok(Some(self.buf.split_to(n).freeze()))
    }
}

async fn pump_response_body<S: AsyncRead + Unpin + Send + 'static>(
    stream: S,
    leftover: Bytes,
    mode: UpstreamBodyMode,
    max_body: usize,
    tx: tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
) {
    let mut br = BodyBuf::new(stream, leftover);
    match mode {
        UpstreamBodyMode::Chunked => {
            if let Err(e) = pump_chunked_body(&mut br, max_body, &tx).await {
                let _ = tx.send(Err(e)).await;
            }
        }
        UpstreamBodyMode::ContentLength(cl) => {
            if let Err(e) = pump_content_length_body(&mut br, cl, max_body, &tx).await {
                let _ = tx.send(Err(e)).await;
            }
        }
        UpstreamBodyMode::UntilEof => {
            if let Err(e) = pump_until_eof_body(&mut br, max_body, &tx).await {
                let _ = tx.send(Err(e)).await;
            }
        }
    }
}

async fn pump_chunked_body<S: AsyncRead + Unpin>(
    br: &mut BodyBuf<S>,
    max_body: usize,
    tx: &tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
) -> std::io::Result<()> {
    let mut seen = 0usize;
    loop {
        let size_line = br.read_until_crlf().await?;
        let size = parse_chunk_size_line(&size_line)?;
        if size == 0 {
            // Trailers: read header lines until empty line.
            loop {
                let trailer = br.read_until_crlf().await?;
                if trailer.is_empty() {
                    break;
                }
            }
            return Ok(());
        }
        if seen.saturating_add(size) > max_body {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response body exceeds limit",
            ));
        }
        let data = br.read_exact(size).await?;
        let crlf = br.read_exact(2).await?;
        if crlf.as_ref() != b"\r\n" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing CRLF after chunk data",
            ));
        }
        seen += size;
        if !data.is_empty() && tx.send(Ok(data)).await.is_err() {
            return Ok(());
        }
    }
}

async fn pump_content_length_body<S: AsyncRead + Unpin>(
    br: &mut BodyBuf<S>,
    content_length: usize,
    max_body: usize,
    tx: &tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
) -> std::io::Result<()> {
    if content_length > max_body {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "response body exceeds limit",
        ));
    }
    let mut seen = 0usize;
    while seen < content_length {
        let want = (content_length - seen).min(16 * 1024);
        let Some(chunk) = br.read_some(want).await? else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof before Content-Length",
            ));
        };
        seen += chunk.len();
        if tx.send(Ok(chunk)).await.is_err() {
            return Ok(());
        }
    }
    Ok(())
}

async fn pump_until_eof_body<S: AsyncRead + Unpin>(
    br: &mut BodyBuf<S>,
    max_body: usize,
    tx: &tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
) -> std::io::Result<()> {
    let mut seen = 0usize;
    loop {
        let Some(chunk) = br.read_some(16 * 1024).await? else {
            return Ok(());
        };
        if seen.saturating_add(chunk.len()) > max_body {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "response body exceeds limit",
            ));
        }
        seen += chunk.len();
        if tx.send(Ok(chunk)).await.is_err() {
            return Ok(());
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
    let (code, headers, mode) = parse_status_and_headers(&header_bytes)?;

    if let UpstreamBodyMode::ContentLength(cl) = mode {
        if cl > max_body {
            return Err(ProxyError::BodyTooLarge);
        }
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(8);
    tokio::spawn(async move {
        pump_response_body(stream, leftover, mode, max_body, tx).await;
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

    #[tokio::test]
    async fn decodes_upstream_chunked_response() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
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
            // Multi-chunk + trailer; payload must decode to "hello-world".
            let resp = b"HTTP/1.1 200 OK\r\n\
Transfer-Encoding: chunked\r\n\
\r\n\
5\r\nhello\r\n\
6\r\n-world\r\n\
0\r\n\
X-Trailer: 1\r\n\
\r\n";
            server.write_all(resp).await.unwrap();
        });

        let parts = Request::builder()
            .method("GET")
            .uri("http://example/x")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let body = Full::new(Bytes::new());
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
        assert!(resp.headers().get("transfer-encoding").is_none());
        assert!(resp.headers().get("content-length").is_none());
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"hello-world");
    }

    #[tokio::test]
    async fn chunked_response_oversize_fail_closed() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
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
            let resp = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Transfer-Encoding: chunked\r\n",
                "\r\n",
                "20\r\n",
                "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\r\n",
                "0\r\n\r\n",
            );
            server.write_all(resp.as_bytes()).await.unwrap();
        });

        let parts = Request::builder()
            .method("GET")
            .uri("http://example/x")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let body = Full::new(Bytes::new());
        let resp = exchange_http(
            client,
            &parts,
            "/x",
            &"example".parse().unwrap(),
            body,
            16,
            None,
        )
        .await
        .unwrap();
        let err = resp.into_body().collect().await.unwrap_err();
        assert!(
            err.to_string().contains("exceeds limit"),
            "unexpected err: {err}"
        );
    }

    #[test]
    fn parse_detects_chunked_mode() {
        let (code, headers, mode) = parse_status_and_headers(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 99\r\nX-A: 1",
        )
        .unwrap();
        assert_eq!(code, 200);
        assert!(matches!(mode, UpstreamBodyMode::Chunked));
        assert!(headers.get("content-length").is_none());
        assert!(headers.get("x-a").is_some());
    }
}
