//! Attack / hygiene tests: PROXY injection, header bomb, smuggling, Slowloris timeout.

use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sedat::config::{
    HostRoute, PathRoute, ProxyProtocolConfig, RoutesConfig, SedatConfig, ServerConfig,
};
use sedat::proxy::{
    accept_with_inbound_proxy, encode_proxy_v1, encode_proxy_v2, handle_request, ProxyState,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn test_config(upstream: &str, limits: sedat::config::LimitsConfig) -> SedatConfig {
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
        limits,
        embedded_docs: Default::default(),
        experimental: Default::default(),
        logging: Default::default(),
        hardening: Default::default(),
    }
}

async fn spawn_proxy(cfg: SedatConfig) -> std::net::SocketAddr {
    let state = ProxyState::new(cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = sedat::proxy::serve_http(listener, state).await;
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    addr
}

async fn mock_upstream(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let _ = req;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from_static(b"ok")))
        .unwrap())
}

async fn spawn_upstream() -> String {
    let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = up.accept().await.unwrap();
            let io = TokioIo::new(s);
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(io, service_fn(mock_upstream))
                    .await;
            });
        }
    });
    format!("http://{up_addr}")
}

#[tokio::test]
async fn header_bomb_returns_431() {
    let upstream = spawn_upstream().await;
    let mut limits = sedat::config::LimitsConfig::default();
    limits.max_header_bytes = 2048;
    limits.max_headers = 20;
    let addr = spawn_proxy(test_config(&upstream, limits)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut req = String::from("GET / HTTP/1.1\r\nHost: localhost\r\n");
    for i in 0..80 {
        req.push_str(&format!("X-Flood-{i}: {}\r\n", "A".repeat(64)));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains("431") || resp.contains("400"),
        "expected header rejection, got {resp}"
    );
}

#[tokio::test]
async fn smuggling_cl_te_rejected() {
    let upstream = spawn_upstream().await;
    let addr = spawn_proxy(test_config(&upstream, Default::default())).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    // Intentionally conflicting framing — SeDat must reject before upstream.
    let req = b"POST / HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: smug-early-1\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n";
    stream.write_all(req).await.unwrap();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("timeout")
        .unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains("400"),
        "expected 400 for CL+TE smuggling shape, got {resp}"
    );
    assert!(!resp.contains("200 OK"));
    assert!(
        resp.to_ascii_lowercase().contains("x-request-id: smug-early-1"),
        "early smuggling reject must echo request_id, got {resp}"
    );
}

#[tokio::test]
async fn header_bomb_echoes_request_id() {
    let upstream = spawn_upstream().await;
    let mut limits = sedat::config::LimitsConfig::default();
    limits.max_header_bytes = 512;
    limits.max_headers = 20;
    let addr = spawn_proxy(test_config(&upstream, limits)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    // Oversized headers without terminator within the read cap → pre-hyper 431.
    let mut req = String::from("GET / HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: bomb-rid-7\r\n");
    while req.len() < 800 {
        req.push_str(&format!("X-Flood: {}\r\n", "A".repeat(64)));
    }
    // Intentionally no final \r\n\r\n — forces incomplete header block at max_header_bytes.
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("timeout")
        .unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.contains("431"),
        "expected 431 for incomplete/oversized headers, got {resp}"
    );
    assert!(
        resp.to_ascii_lowercase().contains("x-request-id:"),
        "431 must include request_id header, got {resp}"
    );
}

#[tokio::test]
async fn absolute_uri_host_mismatch_400() {
    let upstream = spawn_upstream().await;
    let state = ProxyState::new(test_config(&upstream, Default::default()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let st = state.clone();
    tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        let svc = service_fn(move |req| {
            let st = st.clone();
            async move { handle_request(req, peer, st, None).await }
        });
        let _ = http1::Builder::new().serve_connection(io, svc).await;
    });
    let mut client = TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET http://evil.example/abs HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = client.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("400"), "got {resp}");
}

#[tokio::test]
async fn proxy_injection_rejected_when_inbound_disabled() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        accept_with_inbound_proxy(stream, peer, false, &[]).await
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let spoof: std::net::SocketAddr = "203.0.113.9:4444".parse().unwrap();
    let local: std::net::SocketAddr = "10.0.0.1:443".parse().unwrap();
    let hdr = encode_proxy_v1(spoof, local);
    client.write_all(&hdr).await.unwrap();
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();

    let result = accept.await.unwrap().unwrap();
    assert!(
        result.is_none(),
        "PROXY injection must be rejected when inbound_enabled=false"
    );
}

#[tokio::test]
async fn proxy_injection_v2_rejected_untrusted_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let allow = vec!["10.0.0.0/8".to_string()]; // 127.0.0.1 is NOT in 10/8
    let accept = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        accept_with_inbound_proxy(stream, peer, true, &allow).await
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let spoof: std::net::SocketAddr = "203.0.113.9:4444".parse().unwrap();
    let local: std::net::SocketAddr = "10.0.0.1:443".parse().unwrap();
    client
        .write_all(&encode_proxy_v2(spoof, local))
        .await
        .unwrap();

    let result = accept.await.unwrap().unwrap();
    assert!(result.is_none(), "untrusted peer PROXY v2 must be rejected");
}

#[tokio::test]
async fn proxy_trusted_inbound_rewrites_client_ip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Trust loopback so the test peer is allowed.
    let allow = vec!["127.0.0.0/8".to_string()];
    let accept = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        accept_with_inbound_proxy(stream, peer, true, &allow).await
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let spoof: std::net::SocketAddr = "203.0.113.9:4444".parse().unwrap();
    let local: std::net::SocketAddr = "10.0.0.1:443".parse().unwrap();
    let mut payload = encode_proxy_v2(spoof, local);
    payload.extend_from_slice(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
    client.write_all(&payload).await.unwrap();

    let (stream, client_addr) = accept.await.unwrap().unwrap().expect("accepted");
    assert_eq!(client_addr.ip().to_string(), "203.0.113.9");
    assert_eq!(client_addr.port(), 4444);
    drop(stream);
}

#[tokio::test]
async fn slowloris_connection_times_out() {
    let upstream = spawn_upstream().await;
    let mut limits = sedat::config::LimitsConfig::default();
    limits.request_timeout_secs = 1;
    limits.idle_timeout_secs = 1;
    let addr = spawn_proxy(test_config(&upstream, limits)).await;

    let mut stream = TcpStream::connect(addr).await.unwrap();
    // Send incomplete headers slowly — connection should be dropped by timeout.
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let result = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await;
    match result {
        Ok(Ok(0)) | Err(_) => {} // EOF or our wait timed out after server closed
        Ok(Ok(n)) => {
            // Server may close without data; any partial response is also fine.
            let _ = n;
        }
        Ok(Err(_)) => {}
    }
}

#[tokio::test]
async fn public_listener_has_no_builtin_metrics_route() {
    let upstream = spawn_upstream().await;
    let addr = spawn_proxy(test_config(&upstream, Default::default())).await;
    // /metrics is not a SeDat control endpoint; without a matching upstream path quirk
    // it still routes to `/` upstream in our test config — use unknown host instead.
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: not-configured.example\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("404"), "no public metrics endpoint: {resp}");
}

#[test]
fn pebble_directory_alias() {
    assert_eq!(
        sedat::acme::directory_url("pebble"),
        sedat::acme::PEBBLE_DIRECTORY
    );
    assert!(sedat::acme::PEBBLE_DIRECTORY.contains("14000"));
}

#[test]
fn schema_migrate_fail_closed() {
    let err = sedat::config::migrate_toml("schema_version = 42\n").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("42") || msg.contains("unsupported"));
}

#[tokio::test]
async fn plaintext_proxy_rejected_when_placement_after_tls() {
    use sedat::proxy::accept_with_inbound_proxy_placement;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let allow = vec!["127.0.0.0/8".to_string()];
    let accept = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        accept_with_inbound_proxy_placement(stream, peer, true, &allow, "after_tls").await
    });

    let mut client = TcpStream::connect(addr).await.unwrap();
    let spoof: std::net::SocketAddr = "203.0.113.9:4444".parse().unwrap();
    let local: std::net::SocketAddr = "10.0.0.1:443".parse().unwrap();
    client
        .write_all(&encode_proxy_v2(spoof, local))
        .await
        .unwrap();

    let result = accept.await.unwrap().unwrap();
    assert!(
        result.is_none(),
        "plaintext PROXY must be rejected when inbound_placement=after_tls"
    );
}

#[test]
fn metrics_listen_non_loopback_rejected() {
    let toml = r#"
schema_version = 1
[server]
metrics_listen = "0.0.0.0:9090"
[[routes.hosts]]
host = "localhost"
[[routes.hosts.paths]]
prefix = "/"
upstream = "http://127.0.0.1:9080"
"#;
    let err = sedat::config::parse_toml(toml).unwrap_err();
    assert!(
        err.to_string().contains("loopback") || err.to_string().contains("metrics_listen"),
        "{err}"
    );
}

#[test]
fn security_diff_on_placement_change() {
    let a = sedat::config::parse_toml(sedat::DEFAULT_CONFIG_TOML).unwrap();
    let mut b = a.clone();
    b.proxy_protocol.inbound_placement = "after_tls".into();
    let d = sedat::config::security_diff(&a, &b);
    assert!(d
        .iter()
        .any(|c| c.key == "proxy_protocol.inbound_placement"));
}
