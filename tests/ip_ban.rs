//! P10.3: temporary IP bans after consecutive rate-limit strikes.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use sedat::audit::AuditSink;
use sedat::config::{
    HostRoute, LimitsConfig, LoggingConfig, PathRoute, ProxyProtocolConfig, RoutesConfig,
    SedatConfig, ServerConfig,
};
use sedat::proxy::{handle_request, ProxyState};
use tokio::net::TcpListener;

fn test_config(audit_path: &str) -> SedatConfig {
    let mut logging = LoggingConfig::default();
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
                    upstream: "http://127.0.0.1:9".into(),
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
        limits: LimitsConfig {
            rate_limit_per_ip: 1,
            rate_limit_burst: 1,
            ban_after_rate_limit_strikes: 2,
            ban_duration_secs: 60,
            ban_extend_while_banned: true,
            ban_extend_min_interval_secs: 0, // audit every extend in test
            ..Default::default()
        },
        embedded_docs: {
            let mut e = sedat::config::EmbeddedDocsConfig::default();
            e.enabled = false;
            e
        },
        experimental: Default::default(),
        logging,
        hardening: Default::default(),
    }
}

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

#[tokio::test]
async fn bans_after_rate_limit_series_and_audits() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let audit_str = audit_path.to_str().unwrap();

    let cfg = test_config(audit_str);
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

    // 1) consumes burst → likely 502 (dead upstream) but allowed
    let _ = hit(addr, "allow-1").await;
    // 2) rate limited (strike 1)
    assert_eq!(hit(addr, "rl-1").await, StatusCode::TOO_MANY_REQUESTS);
    // 3) strike 2 → ban → 403
    assert_eq!(hit(addr, "ban-trigger").await, StatusCode::FORBIDDEN);
    // 4) still banned → sliding extend
    assert_eq!(hit(addr, "still-banned").await, StatusCode::FORBIDDEN);

    let text = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        text.contains("\"event\":\"ip_ban\""),
        "missing ip_ban: {text}"
    );
    assert!(
        text.contains("\"request_id\":\"ban-trigger\""),
        "missing ban request_id: {text}"
    );
    assert!(
        text.contains("\"event\":\"ip_ban_extend\""),
        "missing ip_ban_extend: {text}"
    );
    assert!(
        text.contains("\"request_id\":\"still-banned\""),
        "missing extend request_id: {text}"
    );
    assert!(
        text.contains("\"reason\":\"ip_banned\""),
        "missing ip_banned deny: {text}"
    );
}
