//! P14.2 / P14.3 — HTTP/3 request proxy + streamed bodies (feature `http3`).
//!
//! ```text
//! cargo test --features http3 --test h3_proxy
//! ```

#[cfg(not(feature = "http3"))]
#[test]
fn h3_proxy_skipped_without_feature() {
    eprintln!("skip: rebuild with `--features http3` to run the H3 proxy smoke test");
}

#[cfg(feature = "http3")]
mod proxy {
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::{Buf, Bytes};
    use http_body_util::{BodyExt, Full};
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Method, Request, Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use quinn::crypto::rustls::QuicClientConfig;
    use quinn::{ClientConfig, Endpoint};
    use rustls::ClientConfig as RustlsClientConfig;
    use sedat::config::{
        HostRoute, PathRoute, ProxyProtocolConfig, RoutesConfig, SedatConfig, ServerConfig,
    };
    use sedat::http3;
    use sedat::limits::Limiter;
    use sedat::proxy::ProxyState;
    use sedat::tls::TlsState;
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::time::timeout;

    #[derive(Debug)]
    struct NoVerifier;

    impl rustls::client::danger::ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

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
        let body = if method == Method::POST {
            format!(
                "h3-upstream path={path} echo={}",
                String::from_utf8_lossy(&collected)
            )
        } else {
            format!("h3-upstream path={path}")
        };
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from(body)))
            .unwrap())
    }

    fn quic_client() -> Endpoint {
        sedat::tls::ensure_crypto_provider();
        let mut crypto = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let quic = QuicClientConfig::try_from(crypto).expect("quic client crypto");
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(quic)));
        endpoint
    }

    async fn spawn_upstream() -> SocketAddr {
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = up.accept().await.unwrap();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let _ = http1::Builder::new()
                        .serve_connection(io, service_fn(mock_upstream))
                        .await;
                });
            }
        });
        up_addr
    }

    async fn spawn_h3(up_addr: SocketAddr, max_body_bytes: usize) -> SocketAddr {
        sedat::tls::ensure_crypto_provider();
        let (cert, key) = sedat::tls::generate_self_signed("localhost").unwrap();
        let sc = sedat::tls::server_config_from_pem(&cert, &key).unwrap();
        let tls_state = TlsState::new(sc);
        let mut limits = sedat::config::LimitsConfig::default();
        limits.max_h3_connections = 8;
        limits.max_h3_streams = 16;
        limits.max_body_bytes = max_body_bytes;
        let cfg = SedatConfig {
            schema_version: 1,
            server: ServerConfig {
                listen: "127.0.0.1:0".into(),
                listen_tls: "127.0.0.1:0".into(),
                ..Default::default()
            },
            tls: Default::default(),
            acme: Default::default(),
            routes: RoutesConfig {
                hosts: vec![HostRoute {
                    host: "localhost".into(),
                    paths: vec![PathRoute {
                        prefix: "/".into(),
                        upstream: format!("http://{up_addr}"),
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
            limits: limits.clone(),
            embedded_docs: Default::default(),
            experimental: sedat::config::ExperimentalConfig { h3: true },
            logging: Default::default(),
            hardening: Default::default(),
        };
        let limiter = Limiter::new(limits);
        let state = ProxyState::new(cfg);

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        drop(sock);
        tokio::spawn(async move {
            let _ = http3::serve_http3(addr, state, tls_state, limiter).await;
        });
        tokio::time::sleep(Duration::from_millis(80)).await;
        addr
    }

    async fn h3_exchange(
        addr: SocketAddr,
        method: Method,
        path: &str,
        body: Option<Bytes>,
    ) -> (StatusCode, String) {
        let endpoint = quic_client();
        let conn = endpoint
            .connect(addr, "localhost")
            .unwrap()
            .await
            .expect("quic connect");
        let quic = h3_quinn::Connection::new(conn);
        let (mut driver, mut send_request) = h3::client::new(quic).await.expect("h3 client");
        tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        let req = Request::builder()
            .method(method)
            .uri(format!("https://localhost{path}"))
            .header("host", "localhost")
            .body(())
            .unwrap();
        let mut stream = send_request.send_request(req).await.expect("send_request");
        if let Some(buf) = body {
            stream.send_data(buf).await.expect("send_data");
        }
        stream.finish().await.expect("finish request");
        let resp = stream.recv_response().await.expect("recv_response");
        let status = resp.status();
        let mut out = Vec::new();
        while let Some(chunk) = stream.recv_data().await.expect("recv_data") {
            out.extend_from_slice(chunk.chunk());
        }
        endpoint.close(0u32.into(), b"done");
        (status, String::from_utf8_lossy(&out).into_owned())
    }

    #[tokio::test]
    async fn h3_get_proxies_to_upstream() {
        let up = spawn_upstream().await;
        let addr = spawn_h3(up, 1024 * 1024).await;
        let run = async {
            let (status, text) = h3_exchange(addr, Method::GET, "/hello", None).await;
            assert_eq!(status, StatusCode::OK);
            assert!(
                text.contains("h3-upstream path=/hello"),
                "unexpected body: {text}"
            );
        };
        timeout(Duration::from_secs(10), run)
            .await
            .expect("h3 GET smoke exceeded timeout");
    }

    #[tokio::test]
    async fn h3_post_body_streams_to_upstream() {
        let up = spawn_upstream().await;
        let addr = spawn_h3(up, 1024 * 1024).await;
        let run = async {
            let (status, text) = h3_exchange(
                addr,
                Method::POST,
                "/echo",
                Some(Bytes::from_static(b"stream-me")),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert!(text.contains("echo=stream-me"), "unexpected body: {text}");
        };
        timeout(Duration::from_secs(10), run)
            .await
            .expect("h3 POST smoke exceeded timeout");
    }

    #[tokio::test]
    async fn h3_oversize_body_fail_closed_413() {
        let up = spawn_upstream().await;
        let addr = spawn_h3(up, 16).await;
        let run = async {
            let big = Bytes::from(vec![b'x'; 64]);
            let (status, _) = h3_exchange(addr, Method::POST, "/big", Some(big)).await;
            assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        };
        timeout(Duration::from_secs(10), run)
            .await
            .expect("h3 oversize smoke exceeded timeout");
    }
}
