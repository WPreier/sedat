//! P10.2: JSONL audit lines for proxy denials include request_id.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use sedat::audit::AuditSink;
use sedat::config::{
    HostRoute, PathRoute, ProxyProtocolConfig, RoutesConfig, SedatConfig, ServerConfig,
};
use sedat::proxy::{handle_request, ProxyState};
use tokio::net::TcpListener;

fn test_config(upstream: &str, audit_path: &str) -> SedatConfig {
    let mut logging = sedat::config::LoggingConfig::default();
    logging.audit_jsonl = audit_path.into();
    logging.audit_jsonl_max_bytes = 0;
    SedatConfig {
        schema_version: 1,
        server: ServerConfig::default(),
        tls: Default::default(),
        acme: Default::default(),
        routes: RoutesConfig {
            hosts: vec![HostRoute {
                host: "localhost".into(),
                paths: vec![PathRoute {
                    prefix: "/".into(),
                    upstream: upstream.into(),
                    ..Default::default()
                }],
            }],
        },
        proxy_protocol: ProxyProtocolConfig {
            outbound: "off".into(),
            inbound_enabled: false,
            inbound_allowlist: vec![],
            inbound_placement: "before_tls".into(),
        },
        limits: {
            let mut l = sedat::config::LimitsConfig::default();
            l.rate_limit_per_ip = 1;
            l.rate_limit_burst = 1;
            l.ban_after_rate_limit_strikes = 0; // isolate rate_limit audit path
            l
        },
        embedded_docs: Default::default(),
        experimental: Default::default(),
        logging,
        hardening: Default::default(),
    }
}

#[tokio::test]
async fn rate_limit_writes_audit_with_request_id() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_str = audit_path.to_str().unwrap();

    let cfg = test_config("http://127.0.0.1:9", audit_str);
    let audit = AuditSink::open(audit_str, 0).unwrap();
    let state = ProxyState::with_audit(cfg, audit);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let st = state.clone();
    tokio::spawn(async move {
        loop {
            let (stream, peer) = listener.accept().await.unwrap();
            let st = st.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let st = st.clone();
                    async move { handle_request(req, peer, st, None).await }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(30)).await;

    async fn hit(addr: std::net::SocketAddr, id: &str) -> StatusCode {
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .uri("/")
            .header("host", "localhost")
            .header("x-request-id", id)
            .body(Full::new(Bytes::new()))
            .unwrap();
        sender.send_request(req).await.unwrap().status()
    }

    // First request consumes the burst token (may 502 to dead upstream or 200).
    let _ = hit(addr, "first-ok").await;
    // Second should 429 and audit.
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri("/")
        .header("host", "localhost")
        .header("x-request-id", "denied-42")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let echoed = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(echoed, "denied-42", "429 must echo request_id");

    let text = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        text.contains("\"event\":\"proxy_deny\""),
        "audit missing proxy_deny: {text}"
    );
    assert!(
        text.contains("\"reason\":\"rate_limit\""),
        "audit missing rate_limit: {text}"
    );
    assert!(
        text.contains("\"request_id\":\"denied-42\""),
        "audit missing request_id: {text}"
    );
}

#[tokio::test]
async fn early_smuggling_writes_audit_with_request_id() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_str = audit_path.to_str().unwrap();

    let mut cfg = test_config("http://127.0.0.1:9", audit_str);
    cfg.limits.rate_limit_per_ip = 10_000;
    cfg.limits.rate_limit_burst = 10_000;
    let audit = AuditSink::open(audit_str, 0).unwrap();
    let state = ProxyState::with_audit(cfg, audit);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = sedat::proxy::serve_http(listener, state).await;
    });
    tokio::time::sleep(Duration::from_millis(40)).await;

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = b"POST / HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: early-audit-9\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n";
    stream.write_all(req).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("timeout")
        .unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("400"), "got {resp}");
    assert!(
        resp.to_ascii_lowercase()
            .contains("x-request-id: early-audit-9"),
        "got {resp}"
    );

    let text = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        text.contains("\"reason\":\"smuggling\""),
        "audit missing smuggling: {text}"
    );
    assert!(
        text.contains("\"request_id\":\"early-audit-9\""),
        "audit missing request_id: {text}"
    );
}
