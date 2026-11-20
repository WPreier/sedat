//! Upstream forwarding with optional PROXY header.

use std::net::SocketAddr;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, Uri};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::ProxyProtocolConfig;

use super::proxy_protocol::{encode_proxy_v1, encode_proxy_v2, ProxyVersion};
use super::router::RouteMatch;

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
}

/// Optional request-id injection: `(header_name, value)` set on the upstream
/// HTTP request **after** any PROXY framing.
pub type RequestIdFwd<'a> = Option<(&'a str, &'a str)>;

/// Forward `req` to the matched upstream.
pub async fn proxy_request(
    req: Request<Incoming>,
    client_addr: SocketAddr,
    route: &RouteMatch,
    pp: &ProxyProtocolConfig,
    max_body: usize,
    request_id: RequestIdFwd<'_>,
) -> Result<Response<Full<Bytes>>, ProxyError> {
    let upstream_base: Uri = route
        .upstream
        .parse()
        .map_err(|_| ProxyError::BadUpstream(route.upstream.clone()))?;
    let authority = upstream_base
        .authority()
        .ok_or_else(|| ProxyError::BadUpstream(route.upstream.clone()))?
        .clone();
    let host = authority.host();
    let port = authority.port_u16().unwrap_or(80);
    let upstream_addr = format!("{host}:{port}");

    let (parts, body) = req.into_parts();
    let collected = body
        .collect()
        .await
        .map_err(|e| ProxyError::Hyper(e.to_string()))?;
    let bytes = collected.to_bytes();
    if bytes.len() > max_body {
        return Err(ProxyError::BodyTooLarge);
    }

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

    let target: Uri = format!("http://{authority}{forward_path}")
        .parse()
        .map_err(|e| ProxyError::Hyper(format!("{e}")))?;

    let version = ProxyVersion::parse(&pp.outbound);
    let mut stream = TcpStream::connect(&upstream_addr).await?;
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

    // Manual HTTP/1.1 request write to keep PROXY on same TCP stream.
    // Request-id is an HTTP header after PROXY framing (not a PROXY TLV).
    let method = parts.method.as_str();
    let mut out = format!("{method} {forward_path} HTTP/1.1\r\n");
    out.push_str(&format!("Host: {authority}\r\n"));
    out.push_str("Connection: close\r\n");
    for (name, value) in parts.headers.iter() {
        let n = name.as_str();
        if n.eq_ignore_ascii_case("host")
            || n.eq_ignore_ascii_case("connection")
            || n.eq_ignore_ascii_case("transfer-encoding")
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
    out.push_str(&format!("Content-Length: {}\r\n\r\n", bytes.len()));
    stream.write_all(out.as_bytes()).await?;
    if !bytes.is_empty() {
        stream.write_all(&bytes).await?;
    }

    // Read raw response
    use tokio::io::AsyncReadExt;
    let mut resp_buf = Vec::with_capacity(4096);
    stream.read_to_end(&mut resp_buf).await?;
    parse_http_response(&resp_buf, target)
}

fn parse_http_response(buf: &[u8], _target: Uri) -> Result<Response<Full<Bytes>>, ProxyError> {
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| ProxyError::Hyper("incomplete upstream response".into()))?;
    let header_bytes = &buf[..header_end];
    let body = Bytes::copy_from_slice(&buf[header_end + 4..]);
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
    let mut builder = Response::builder().status(code);
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if k.eq_ignore_ascii_case("transfer-encoding") || k.eq_ignore_ascii_case("connection") {
                continue;
            }
            builder = builder.header(k, v);
        }
    }
    builder
        .body(Full::new(body))
        .map_err(|e| ProxyError::Hyper(e.to_string()))
}
