//! Upstream forwarding with optional PROXY header, IP pin, and HTTPS/mTLS.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Body;
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

/// Forward `req` to the matched upstream.
pub async fn proxy_request<B>(
    req: Request<B>,
    client_addr: SocketAddr,
    route: &RouteMatch,
    pp: &ProxyProtocolConfig,
    max_body: usize,
    request_id: RequestIdFwd<'_>,
    dns_cache: &DnsCache,
) -> Result<Response<Full<Bytes>>, ProxyError>
where
    B: Body + Send,
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

    let target: Uri = format!("{scheme}://{authority}{forward_path}")
        .parse()
        .map_err(|e| ProxyError::Hyper(format!("{e}")))?;

    let version = ProxyVersion::parse(&pp.outbound);
    let refresh = Duration::from_secs(route.upstream_dns_refresh_secs);
    let mut stream =
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
    } else {
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
    }

    if use_tls {
        let client_cfg = build_upstream_client_config(&UpstreamTlsPaths {
            cert: &route.upstream_mtls_cert,
            key: &route.upstream_mtls_key,
            ca: &route.upstream_mtls_ca,
        })
        .map_err(|e| ProxyError::Tls(e.to_string()))?;
        let connector = TlsConnector::from(client_cfg);
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| ProxyError::Tls(format!("invalid SNI host `{host}`: {e}")))?;
        let mut tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| ProxyError::Tls(e.to_string()))?;
        exchange_http(
            &mut tls,
            &parts,
            &forward_path,
            &authority,
            &bytes,
            request_id,
            target,
        )
        .await
    } else {
        exchange_http(
            &mut stream,
            &parts,
            &forward_path,
            &authority,
            &bytes,
            request_id,
            target,
        )
        .await
    }
}

async fn exchange_http<S>(
    stream: &mut S,
    parts: &http::request::Parts,
    forward_path: &str,
    authority: &http::uri::Authority,
    bytes: &Bytes,
    request_id: RequestIdFwd<'_>,
    target: Uri,
) -> Result<Response<Full<Bytes>>, ProxyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Manual HTTP/1.1 request write to keep PROXY on same TCP stream.
    // Request-id is an HTTP header after PROXY framing (not a PROXY TLV).
    // For HTTPS, PROXY (if any) is written before the TLS handshake.
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
        stream.write_all(bytes).await?;
    }

    let mut resp_buf = Vec::with_capacity(4096);
    stream.read_to_end(&mut resp_buf).await?;
    parse_http_response(&resp_buf, target)
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
