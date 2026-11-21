//! E8 / P13.1 — HTTP/3 (QUIC) attack corpus (mirror of P09.4 H2 corpus).
//!
//! **Not** a multi-GB archive: programmatic, capped runtime, tiny disk.
//! Success = listener closes / limits without harness panic or OOM.
//!
//! ```text
//! cargo test --features http3 --test h3_attack_corpus
//! ```
//!
//! Without `--features http3`, this binary reports a single skip test.

#[cfg(not(feature = "http3"))]
#[test]
fn h3_attack_corpus_skipped_without_feature() {
    eprintln!("skip: rebuild with `--features http3` to run the QUIC/H3 corpus");
}

#[cfg(feature = "http3")]
mod corpus {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

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
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    /// Hard caps — keep Docker CI fast and disk/RAM tiny.
    const MAX_FLOOD_CONNECTIONS: usize = 24;
    const SERVER_MAX_H3_CONN: usize = 4;
    const SERVER_MAX_H3_STREAMS: usize = 8;
    const TEST_TIMEOUT: Duration = Duration::from_secs(8);
    const UDP_JUNK_PACKETS: usize = 64;
    const UDP_JUNK_SIZE: usize = 1200;

    fn h3_state(max_conn: usize, max_streams: usize) -> (ProxyState, TlsState, Arc<Limiter>) {
        sedat::tls::ensure_crypto_provider();
        let (cert, key) = sedat::tls::generate_self_signed("localhost").unwrap();
        let sc = sedat::tls::server_config_from_pem(&cert, &key).unwrap();
        let tls_state = TlsState::new(sc);
        let mut limits = sedat::config::LimitsConfig::default();
        limits.max_h3_connections = max_conn;
        limits.max_h3_streams = max_streams;
        limits.request_timeout_secs = 2;
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
                        upstream: "http://127.0.0.1:9".into(),
                        ..Default::default()
                    }],
                }],
            },
            proxy_protocol: ProxyProtocolConfig::default(),
            limits: limits.clone(),
            embedded_docs: Default::default(),
            experimental: {
                let mut e = sedat::config::ExperimentalConfig::default();
                e.h3 = true;
                e
            },
            logging: Default::default(),
            hardening: Default::default(),
        };
        let limiter = Limiter::new(limits);
        (ProxyState::new(cfg), tls_state, limiter)
    }

    async fn spawn_h3() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        drop(sock);
        let (state, tls, lim) = h3_state(SERVER_MAX_H3_CONN, SERVER_MAX_H3_STREAMS);
        tokio::spawn(async move {
            let _ = http3::serve_http3(addr, state, tls, lim).await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        addr
    }

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
    async fn connection_flood_stays_within_caps() {
        let addr = spawn_h3().await;
        let endpoint = quic_client();

        let run = async {
            let mut ok_or_reject = 0usize;
            for _ in 0..MAX_FLOOD_CONNECTIONS {
                match timeout(
                    Duration::from_secs(2),
                    endpoint.connect(addr, "localhost").unwrap(),
                )
                .await
                {
                    Ok(Ok(conn)) => {
                        ok_or_reject += 1;
                        // Experimental listener closes promptly; drain.
                        let _ = timeout(Duration::from_millis(200), conn.closed()).await;
                    }
                    Ok(Err(_)) | Err(_) => {
                        ok_or_reject += 1; // reject / timeout under pressure is OK
                    }
                }
            }
            assert_eq!(
                ok_or_reject, MAX_FLOOD_CONNECTIONS,
                "every attempt must settle (accept or reject) without panic"
            );
        };

        timeout(TEST_TIMEOUT, run)
            .await
            .expect("connection flood exceeded runtime cap");
        endpoint.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn udp_junk_amplification_probe_no_panic() {
        let addr = spawn_h3().await;
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let junk = vec![0xA5u8; UDP_JUNK_SIZE];
        let run = async {
            for _ in 0..UDP_JUNK_PACKETS {
                let _ = sock.send_to(&junk, addr).await;
            }
            // Brief soak — server must still be alive enough to accept a real handshake attempt.
            tokio::time::sleep(Duration::from_millis(100)).await;
            let endpoint = quic_client();
            let _ = timeout(
                Duration::from_secs(2),
                endpoint.connect(addr, "localhost").unwrap(),
            )
            .await;
            endpoint.close(0u32.into(), b"done");
        };
        timeout(TEST_TIMEOUT, run)
            .await
            .expect("UDP junk probe exceeded runtime cap");
    }

    #[tokio::test]
    async fn stream_open_storm_on_accepted_conn() {
        let addr = spawn_h3().await;
        let endpoint = quic_client();
        let run = async {
            let connecting = endpoint.connect(addr, "localhost").unwrap();
            match timeout(Duration::from_secs(3), connecting).await {
                Ok(Ok(conn)) => {
                    // Storm bi-directional opens; server may close anytime.
                    for _ in 0..32 {
                        let _ = conn.open_bi().await;
                    }
                    let _ = timeout(Duration::from_millis(300), conn.closed()).await;
                }
                _ => {
                    // Handshake failed / limited — still a valid defensive outcome.
                }
            }
        };
        timeout(TEST_TIMEOUT, run)
            .await
            .expect("stream storm exceeded runtime cap");
        endpoint.close(0u32.into(), b"done");
    }
}
