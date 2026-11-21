//! P14.2 — HTTP/3 request proxy smoke test (feature `http3`).
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
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::{Buf, Bytes};
    use http_body_util::Full;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response, StatusCode};
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
        let body = format!("h3-upstream path={}", req.uri().path());
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

    #[tokio::test]
    async fn h3_get_proxies_to_upstream() {
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

        sedat::tls::ensure_crypto_provider();
        let (cert, key) = sedat::tls::generate_self_signed("localhost").unwrap();
        let sc = sedat::tls::server_config_from_pem(&cert, &key).unwrap();
        let tls_state = TlsState::new(sc);
        let mut limits = sedat::config::LimitsConfig::default();
        limits.max_h3_connections = 8;
        limits.max_h3_streams = 16;
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

        let run = async {
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
                .uri("https://localhost/hello")
                .header("host", "localhost")
                .body(())
                .unwrap();
            let mut stream = send_request.send_request(req).await.expect("send_request");
            stream.finish().await.expect("finish request");
            let resp = stream.recv_response().await.expect("recv_response");
            assert_eq!(resp.status(), StatusCode::OK);
            let mut body = Vec::new();
            while let Some(chunk) = stream.recv_data().await.expect("recv_data") {
                body.extend_from_slice(chunk.chunk());
            }
            let text = String::from_utf8_lossy(&body);
            assert!(
                text.contains("h3-upstream path=/hello"),
                "unexpected body: {text}"
            );
            endpoint.close(0u32.into(), b"done");
        };

        timeout(Duration::from_secs(10), run)
            .await
            .expect("h3 proxy smoke exceeded timeout");
    }
}
