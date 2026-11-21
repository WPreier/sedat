//! Phase 2 integration: HTTP/1.1 proxy → mock upstream.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
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
use sedat::proxy::{handle_request, resolve_route, ProxyState};
use tokio::net::TcpListener;

async fn mock_upstream(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let collected = req
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let body = if method == hyper::Method::POST {
        format!(
            "upstream-ok path={path} echo={}",
            String::from_utf8_lossy(&collected)
        )
    } else {
        format!("upstream-ok path={path}")
    };
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

/// Captures the inbound `x-request-id` seen by the upstream.
async fn mock_upstream_capture_rid(
    req: Request<hyper::body::Incoming>,
    seen: Arc<Mutex<Option<String>>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let rid = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    *seen.lock().unwrap() = rid;
    let body = format!("upstream-ok path={}", req.uri().path());
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

fn test_config(upstream: &str) -> SedatConfig {
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
        limits: Default::default(),
        embedded_docs: Default::default(),
        experimental: Default::default(),
        logging: Default::default(),
        hardening: Default::default(),
    }
}

#[tokio::test]
async fn proxies_known_host() {
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

    let cfg = test_config(&format!("http://{up_addr}"));
    let state = ProxyState::new(cfg);
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

    tokio::time::sleep(Duration::from_millis(50)).await;

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri("/hello")
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(
        String::from_utf8_lossy(&bytes).contains("upstream-ok"),
        "body={:?}",
        String::from_utf8_lossy(&bytes)
    );
}

#[test]
fn unknown_host_rejects() {
    let cfg = test_config("http://127.0.0.1:9");
    assert!(resolve_route(&cfg.routes, "unknown.example", "/").is_none());
}

#[test]
fn embedded_docs_route() {
    let cfg = test_config("http://127.0.0.1:9");
    assert!(sedat::embed::maybe_serve(&cfg.embedded_docs, "/sedat").is_some());
}

#[tokio::test]
async fn forwards_and_echoes_request_id() {
    let seen = Arc::new(Mutex::new(None));
    let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up.local_addr().unwrap();
    let seen_up = seen.clone();
    tokio::spawn(async move {
        loop {
            let (s, _) = up.accept().await.unwrap();
            let seen = seen_up.clone();
            let io = TokioIo::new(s);
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            let seen = seen.clone();
                            async move { mock_upstream_capture_rid(req, seen).await }
                        }),
                    )
                    .await;
            });
        }
    });

    let cfg = test_config(&format!("http://{up_addr}"));
    let state = ProxyState::new(cfg);
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

    tokio::time::sleep(Duration::from_millis(50)).await;

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri("/rid")
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let echoed = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .expect("response must echo x-request-id")
        .to_owned();
    assert_eq!(echoed.len(), 32);
    let upstream = seen
        .lock()
        .unwrap()
        .clone()
        .expect("upstream saw x-request-id");
    assert_eq!(upstream, echoed);
}

#[tokio::test]
async fn propagates_client_request_id() {
    let seen = Arc::new(Mutex::new(None));
    let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up.local_addr().unwrap();
    let seen_up = seen.clone();
    tokio::spawn(async move {
        loop {
            let (s, _) = up.accept().await.unwrap();
            let seen = seen_up.clone();
            let io = TokioIo::new(s);
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            let seen = seen.clone();
                            async move { mock_upstream_capture_rid(req, seen).await }
                        }),
                    )
                    .await;
            });
        }
    });

    let cfg = test_config(&format!("http://{up_addr}"));
    let state = ProxyState::new(cfg);
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

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_id = "client-corr-42";
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri("/rid-prop")
        .header("host", "localhost")
        .header("x-request-id", client_id)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let echoed = resp
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert_eq!(echoed, client_id);
    let upstream = seen.lock().unwrap().clone().unwrap();
    assert_eq!(upstream, client_id);
}

#[tokio::test]
async fn post_body_streams_chunked_to_upstream() {
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

    let cfg = test_config(&format!("http://{up_addr}"));
    let state = ProxyState::new(cfg);
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

    tokio::time::sleep(Duration::from_millis(50)).await;

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("POST")
        .uri("/echo")
        .header("host", "localhost")
        .body(Full::new(Bytes::from_static(b"chunk-me")))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("echo=chunk-me"), "unexpected body: {text}");
}

#[tokio::test]
async fn oversize_body_fail_closed_413() {
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

    let mut cfg = test_config(&format!("http://{up_addr}"));
    cfg.limits.max_body_bytes = 16;
    let state = ProxyState::new(cfg);
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

    tokio::time::sleep(Duration::from_millis(50)).await;

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("POST")
        .uri("/big")
        .header("host", "localhost")
        .body(Full::new(Bytes::from(vec![b'x'; 64])))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
