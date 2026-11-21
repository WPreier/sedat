//! HTTP reverse-proxy core (HTTP/1.1 + HTTP/2 capable via hyper).

mod forward;
mod proxy_protocol;
mod request_id;
mod router;
mod upstream_mtls;
mod upstream_pin;

pub use forward::{proxy_request, ProxyError, RequestIdFwd};
pub use upstream_mtls::{build_upstream_client_config, UpstreamTlsPaths};
pub use proxy_protocol::{
    accept_with_inbound_proxy, accept_with_inbound_proxy_placement, apply_inbound_after_tls,
    encode_proxy_v1, encode_proxy_v2, inbound_on_plaintext, inbound_on_tls, inbound_proxy_trusted,
    probe_inbound_proxy_reader, PrefixedIo, PrefixedStream, ProxyRejectReason, ProxyVersion,
    PROXY_V2_SIG,
};
pub use request_id::{
    generate_request_id, http_headers_complete, resolve_request_id, resolve_request_id_from_raw,
    sanitize_request_id, valid_header_name, DEFAULT_REQUEST_ID_HEADER, MAX_REQUEST_ID_LEN,
};
pub use router::{resolve_route, RouteMatch};
pub use upstream_pin::{filter_pinned_addrs, upstream_ip_allowed};

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::audit::AuditSink;
use crate::config::SedatConfig;
use crate::embed;
use crate::limits::{BanLifecycle, ConnectionGuard, Limiter, RateOutcome};
use crate::DEFAULT_404_HTML;

/// Shared runtime state for the proxy.
#[derive(Clone)]
pub struct ProxyState {
    /// Hot-swappable config.
    pub config: Arc<ArcSwap<SedatConfig>>,
    /// Edge limits.
    pub limiter: Arc<Limiter>,
    /// JSONL audit sink (may be disabled).
    pub audit: AuditSink,
}

impl ProxyState {
    /// Build from config (opens audit file when `logging.audit_jsonl` is set).
    pub fn new(config: SedatConfig) -> Self {
        let audit = match AuditSink::from_logging(
            &config.logging.audit_jsonl,
            config.logging.audit_jsonl_max_bytes,
            config.logging.audit_jsonl_max_age_secs,
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "audit jsonl open failed; audit disabled");
                AuditSink::disabled()
            }
        };
        Self::with_audit(config, audit)
    }

    /// Build with an explicit audit sink (shared with admin).
    pub fn with_audit(config: SedatConfig, audit: AuditSink) -> Self {
        let limiter = Limiter::new(config.limits.clone());
        Self {
            config: Arc::new(ArcSwap::from_pointee(config)),
            limiter,
            audit,
        }
    }
}

fn attach_request_id(
    mut resp: Response<BoxBody>,
    header_name: &str,
    rid: Option<&str>,
) -> Response<BoxBody> {
    if let Some(id) = rid {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(header_name.as_bytes()),
            http::HeaderValue::from_str(id),
        ) {
            resp.headers_mut().insert(name, value);
        }
    }
    resp
}

/// Pre-hyper HTTP/1 early reject: response header + JSONL + tracing with request_id.
async fn write_early_http_deny(
    stream: &mut PrefixedStream,
    state: &ProxyState,
    cfg: &SedatConfig,
    peer: SocketAddr,
    header_block: &[u8],
    status: StatusCode,
    reason: &str,
    body: &str,
) {
    use tokio::io::AsyncWriteExt;

    let rid = resolve_request_id_from_raw(
        header_block,
        cfg.logging.request_id,
        &cfg.logging.request_id_header,
    );
    state.audit.emit_proxy_deny(
        reason,
        status.as_u16(),
        &peer.to_string(),
        rid.as_deref(),
        None,
        None,
    );
    warn!(
        request_id = rid.as_deref().unwrap_or("-"),
        %peer,
        reason,
        status = status.as_u16(),
        "early HTTP reject"
    );

    let reason_phrase = status.canonical_reason().unwrap_or("Error");
    let mut resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n",
        status.as_u16(),
        reason_phrase,
        body.len()
    );
    if let Some(ref id) = rid {
        resp.push_str(&format!("{}: {id}\r\n", cfg.logging.request_id_header));
    }
    resp.push_str("\r\n");
    resp.push_str(body);
    let _ = stream.write_all(resp.as_bytes()).await;
}

fn deny_response(
    state: &ProxyState,
    cfg: &SedatConfig,
    peer: SocketAddr,
    rid: Option<&str>,
    reason: &str,
    status: StatusCode,
    body: &str,
    host: Option<&str>,
    path: Option<&str>,
) -> Response<BoxBody> {
    state.audit.emit_proxy_deny(
        reason,
        status.as_u16(),
        &peer.to_string(),
        rid,
        host,
        path,
    );
    attach_request_id(
        html_response(status, body),
        &cfg.logging.request_id_header,
        rid,
    )
}

type BoxBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

fn full_body(data: impl Into<Bytes>) -> BoxBody {
    Full::new(data.into())
        .map_err(|never: Infallible| match never {})
        .boxed()
}

/// Build a simple HTML/text response.
pub fn html_response(status: StatusCode, body: &str) -> Response<BoxBody> {
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(full_body(body.to_owned()))
        .expect("response")
}

/// Reject obvious HTTP request-smuggling shapes (CL + TE together).
fn has_smuggling_headers(req: &Request<Incoming>) -> bool {
    let has_te = req
        .headers()
        .keys()
        .any(|k| k.as_str().eq_ignore_ascii_case("transfer-encoding"));
    let has_cl = req
        .headers()
        .keys()
        .any(|k| k.as_str().eq_ignore_ascii_case("content-length"));
    has_te && has_cl
}

/// Scan raw HTTP/1 header block for CL+TE (hyper may normalize before the handler).
#[must_use]
pub fn raw_http_headers_smuggling(buf: &[u8]) -> bool {
    let end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(buf.len());
    let text = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
    let mut cl = false;
    let mut te = false;
    for line in text.split("\r\n").skip(1) {
        if line.starts_with("content-length:") {
            cl = true;
        }
        if line.starts_with("transfer-encoding:") {
            te = true;
        }
    }
    cl && te
}

/// Read until end of HTTP/1 headers (or `max` bytes), for pre-hyper smuggling checks.
async fn read_http_header_block(
    stream: &mut PrefixedStream,
    max: usize,
) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while buf.len() < max {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n" {
            break;
        }
    }
    Ok(buf)
}

/// Handle a single HTTP request.
pub async fn handle_request(
    req: Request<Incoming>,
    peer: SocketAddr,
    state: ProxyState,
    tls_sni: Option<String>,
) -> Result<Response<BoxBody>, Infallible> {
    let cfg = state.config.load_full();
    let rid = resolve_request_id(
        req.headers(),
        cfg.logging.request_id,
        &cfg.logging.request_id_header,
    );
    let rid_ref = rid.as_deref();
    let path = req.uri().path().to_string();

    let rate = state.limiter.check_rate(peer.ip(), &cfg.limits);
    if let Some(ref life) = rate.lifecycle {
        match life {
            BanLifecycle::Applied {
                duration_secs,
                strikes,
            } => {
                warn!(
                    request_id = rid_ref.unwrap_or("-"),
                    %peer,
                    duration_secs,
                    strikes,
                    "temporary IP ban applied"
                );
                state.audit.emit_ip_ban(
                    &peer.to_string(),
                    rid_ref,
                    *duration_secs,
                    *strikes,
                );
            }
            BanLifecycle::Extended {
                duration_secs,
                previous_remaining_secs,
            } => {
                warn!(
                    request_id = rid_ref.unwrap_or("-"),
                    %peer,
                    duration_secs,
                    previous_remaining_secs,
                    "temporary IP ban extended"
                );
                state.audit.emit_ip_ban_extend(
                    &peer.to_string(),
                    rid_ref,
                    *duration_secs,
                    *previous_remaining_secs,
                );
            }
            BanLifecycle::Expired => {
                info!(
                    request_id = rid_ref.unwrap_or("-"),
                    %peer,
                    "temporary IP ban expired"
                );
                state.audit.emit_ip_unban(&peer.to_string(), rid_ref);
            }
        }
    }
    match rate.outcome {
        RateOutcome::Allow => {}
        RateOutcome::RateLimited => {
            return Ok(deny_response(
                &state,
                &cfg,
                peer,
                rid_ref,
                "rate_limit",
                StatusCode::TOO_MANY_REQUESTS,
                "<h1>429 Too Many Requests</h1>",
                None,
                Some(&path),
            ));
        }
        RateOutcome::Banned => {
            return Ok(deny_response(
                &state,
                &cfg,
                peer,
                rid_ref,
                "ip_banned",
                StatusCode::FORBIDDEN,
                "<h1>403 Forbidden</h1><p>Temporarily banned</p>",
                None,
                Some(&path),
            ));
        }
    }

    if has_smuggling_headers(&req) {
        return Ok(deny_response(
            &state,
            &cfg,
            peer,
            rid_ref,
            "smuggling",
            StatusCode::BAD_REQUEST,
            "<h1>400 Bad Request</h1><p>Transfer-Encoding and Content-Length conflict</p>",
            None,
            Some(&path),
        ));
    }

    let header_bytes: usize = req
        .headers()
        .iter()
        .map(|(k, v)| k.as_str().len() + v.as_bytes().len())
        .sum();
    if header_bytes > state.limiter.max_header_bytes()
        || req.headers().len() > state.limiter.max_headers()
    {
        return Ok(deny_response(
            &state,
            &cfg,
            peer,
            rid_ref,
            "header_bomb",
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "<h1>431 Request Header Fields Too Large</h1>",
            None,
            Some(&path),
        ));
    }

    if let Some(auth) = req.uri().authority() {
        if req.method() != Method::CONNECT {
            let host_hdr = req
                .headers()
                .get(hyper::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !host_hdr.is_empty() && !host_hdr.eq_ignore_ascii_case(auth.as_str()) {
                return Ok(deny_response(
                    &state,
                    &cfg,
                    peer,
                    rid_ref,
                    "absolute_uri_host_mismatch",
                    StatusCode::BAD_REQUEST,
                    "<h1>400 Bad Request</h1><p>Absolute-URI / Host mismatch</p>",
                    Some(host_hdr),
                    Some(&path),
                ));
            }
        }
    }

    if path.contains('\\') || path_has_traversal(&path) {
        return Ok(deny_response(
            &state,
            &cfg,
            peer,
            rid_ref,
            "path_traversal",
            StatusCode::BAD_REQUEST,
            "<h1>400 Bad Request</h1><p>Invalid path</p>",
            None,
            Some(&path),
        ));
    }

    if let Some(resp) = embed::maybe_serve(&cfg.embedded_docs, &path) {
        return Ok(attach_request_id(
            resp,
            &cfg.logging.request_id_header,
            rid_ref,
        ));
    }

    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .unwrap_or_default();

    if host.is_empty() {
        return Ok(deny_response(
            &state,
            &cfg,
            peer,
            rid_ref,
            "missing_host",
            StatusCode::BAD_REQUEST,
            "<h1>400 Bad Request</h1><p>Missing Host</p>",
            None,
            Some(&path),
        ));
    }

    if let Some(ref sni) = tls_sni {
        if !sni.eq_ignore_ascii_case(&host) && host != "localhost" {
            return Ok(deny_response(
                &state,
                &cfg,
                peer,
                rid_ref,
                "sni_host_mismatch",
                StatusCode::MISDIRECTED_REQUEST,
                "<h1>421 Misdirected Request</h1><p>SNI/Host mismatch</p>",
                Some(&host),
                Some(&path),
            ));
        }
    }

    let Some(route) = resolve_route(&cfg.routes, &host, &path) else {
        return Ok(deny_response(
            &state,
            &cfg,
            peer,
            rid_ref,
            "unknown_host_or_path",
            StatusCode::NOT_FOUND,
            DEFAULT_404_HTML,
            Some(&host),
            Some(&path),
        ));
    };

    let rid_fwd = rid
        .as_deref()
        .map(|id| (cfg.logging.request_id_header.as_str(), id));

    match proxy_request(
        req,
        peer,
        &route,
        &cfg.proxy_protocol,
        state.limiter.max_body_bytes(),
        rid_fwd,
    )
    .await
    {
        Ok(resp) => {
            let (mut parts, body) = resp.into_parts();
            if let Some(ref id) = rid {
                if let (Ok(name), Ok(value)) = (
                    http::HeaderName::from_bytes(cfg.logging.request_id_header.as_bytes()),
                    http::HeaderValue::from_str(id),
                ) {
                    parts.headers.insert(name, value);
                }
                info!(
                    request_id = %id,
                    %peer,
                    %host,
                    %path,
                    status = %parts.status,
                    "proxied"
                );
            }
            let bytes = body
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            Ok(Response::from_parts(parts, full_body(bytes)))
        }
        Err(e) => {
            if let Some(ref id) = rid {
                warn!(request_id = %id, error = %e, "upstream proxy error");
            } else {
                warn!(error = %e, "upstream proxy error");
            }
            let reason = match &e {
                ProxyError::UpstreamNotAllowed(_) => "upstream_ip_pin",
                _ => "upstream_error",
            };
            state.audit.emit_proxy_deny(
                reason,
                StatusCode::BAD_GATEWAY.as_u16(),
                &peer.to_string(),
                rid_ref,
                Some(&host),
                Some(&path),
            );
            Ok(attach_request_id(
                html_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("<h1>502 Bad Gateway</h1><p>{e}</p>"),
                ),
                &cfg.logging.request_id_header,
                rid_ref,
            ))
        }
    }
}

fn path_has_traversal(path: &str) -> bool {
    path.split('/').any(|s| s == "..")
}

/// Accept loop for plain HTTP/1.1 (with inbound PROXY policy + idle timeout).
pub async fn serve_http(listener: TcpListener, state: ProxyState) -> std::io::Result<()> {
    info!(addr = %listener.local_addr()?, "HTTP listener ready");
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        let Some(_slot) = ConnectionGuard::acquire(state.limiter.clone()) else {
            warn!(%peer, "connection limit reached");
            continue;
        };
        tokio::spawn(async move {
            let _slot = _slot;
            let cfg = state.config.load();
            let accepted = match accept_with_inbound_proxy_placement(
                stream,
                peer,
                cfg.proxy_protocol.inbound_enabled,
                &cfg.proxy_protocol.inbound_allowlist,
                &cfg.proxy_protocol.inbound_placement,
            )
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(reason)) => {
                    warn!(
                        %peer,
                        reason = reason.as_str(),
                        "rejected inbound PROXY (plaintext)"
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
            let (mut stream, client) = accepted;
            let idle = state.limiter.request_timeout();
            let max_hdr = state.limiter.max_header_bytes();
            let cfg_early = state.config.load_full();
            // Pre-hyper raw scan: hyper may drop CL or TE before our handler sees both.
            let header_block = match read_http_header_block(&mut stream, max_hdr).await {
                Ok(b) => b,
                Err(e) => {
                    tracing::debug!(error = %e, %peer, "header read failed");
                    return;
                }
            };
            if !http_headers_complete(&header_block) {
                write_early_http_deny(
                    &mut stream,
                    &state,
                    &cfg_early,
                    peer,
                    &header_block,
                    StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                    "header_bomb",
                    "Request Header Fields Too Large",
                )
                .await;
                return;
            }
            if raw_http_headers_smuggling(&header_block) {
                write_early_http_deny(
                    &mut stream,
                    &state,
                    &cfg_early,
                    peer,
                    &header_block,
                    StatusCode::BAD_REQUEST,
                    "smuggling",
                    "Transfer-Encoding and Content-Length conflict",
                )
                .await;
                return;
            }
            let (inner, unread) = stream.into_parts();
            let mut replay = header_block;
            replay.extend_from_slice(&unread);
            let stream = PrefixedStream::new(inner, replay);
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let state = state.clone();
                async move { handle_request(req, client, state, None).await }
            });
            let serve = http1::Builder::new().serve_connection(io, svc);
            match tokio::time::timeout(idle, serve).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::debug!(error = %e, %peer, "connection closed"),
                Err(_) => tracing::debug!(%peer, "connection idle/request timeout"),
            }
        });
    }
}

#[cfg(test)]
mod smuggling_tests {
    use super::raw_http_headers_smuggling;

    #[test]
    fn detects_cl_te() {
        let raw = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(raw_http_headers_smuggling(raw));
    }

    #[test]
    fn allows_cl_only() {
        let raw = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\n";
        assert!(!raw_http_headers_smuggling(raw));
    }
}
