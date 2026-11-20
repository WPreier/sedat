//! P10.6: upstream IP pin / allowlist fail-closed.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sedat::config::{
    HostRoute, PathRoute, ProxyProtocolConfig, RoutesConfig, SedatConfig, ServerConfig,
};
use sedat::proxy::{handle_request, ProxyState};
use tokio::net::TcpListener;

fn cfg(upstream: &str, allowlist: Vec<String>) -> SedatConfig {
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
                    upstream_allowlist: allowlist,
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
        limits: Default::default(),
        embedded_docs: {
            let mut e = sedat::config::EmbeddedDocsConfig::default();
            e.enabled = false;
            e
        },
        experimental: Default::default(),
        logging: Default::default(),
        hardening: Default::default(),
    }
}

async fn spawn_upstream() -> std::net::SocketAddr {
    let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = up.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (s, _) = up.accept().await.unwrap();
            let io = TokioIo::new(s);
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|_req: Request<hyper::body::Incoming>| async {
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::from_static(b"ok")))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            });
        }
    });
    addr
}

async fn hit(proxy: std::net::SocketAddr) -> (StatusCode, String) {
    let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri("/")
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn allowlist_matching_loopback_ok() {
    let up = spawn_upstream().await;
    let state = ProxyState::new(cfg(
        &format!("http://{up}"),
        vec!["127.0.0.1".into(), "127.0.0.0/8".into()],
    ));
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
    let (status, body) = hit(addr).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn allowlist_rejects_wrong_pin() {
    let up = spawn_upstream().await;
    // Pin to a documentation IP that cannot be the loopback upstream.
    let state = ProxyState::new(cfg(&format!("http://{up}"), vec!["203.0.113.9".into()]));
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
    let (status, body) = hit(addr).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert!(
        body.contains("not allowed") || body.contains("pin") || body.contains("allowlist"),
        "{body}"
    );
}
