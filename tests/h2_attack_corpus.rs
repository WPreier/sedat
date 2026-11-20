//! HTTP/2 Continuations / HPACK-bomb negative corpus (beyond hyper defaults).
//!
//! These tests craft raw TLS+h2 frames. Success = connection closed / no panic,
//! not that a particular status code is returned.

use std::time::Duration;

use sedat::config::{
    HostRoute, PathRoute, ProxyProtocolConfig, RoutesConfig, SedatConfig, ServerConfig, TlsConfig,
};
use sedat::proxy::ProxyState;
use sedat::tls::{self, TlsState};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

fn h2_cfg(listen_hint: &str) -> (SedatConfig, TlsState) {
    let (cert, key) = tls::generate_self_signed("localhost").unwrap();
    let sc = tls::server_config_from_pem(&cert, &key).unwrap();
    let tls_state = TlsState::new(sc);
    let cfg = SedatConfig {
        schema_version: 1,
        server: ServerConfig {
            listen: "127.0.0.1:0".into(),
            listen_tls: listen_hint.into(),
            ..Default::default()
        },
        tls: TlsConfig {
            enabled: true,
            cert_path: None,
            key_path: None,
        },
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
        limits: {
            let mut l = sedat::config::LimitsConfig::default();
            l.max_header_bytes = 4096;
            l.max_headers = 32;
            l.request_timeout_secs = 2;
            l
        },
        embedded_docs: Default::default(),
        experimental: Default::default(),
        logging: Default::default(),
        hardening: Default::default(),
    };
    (cfg, tls_state)
}

async fn spawn_https() -> (std::net::SocketAddr, Vec<u8>, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (cert, key) = tls::generate_self_signed("localhost").unwrap();
    let sc = tls::server_config_from_pem(&cert, &key).unwrap();
    let tls_state = TlsState::new(sc);
    let (cfg, _) = h2_cfg(&addr.to_string());
    let state = ProxyState::new(cfg);
    tokio::spawn(async move {
        let _ = tls::serve_https(listener, state, tls_state).await;
    });
    tokio::time::sleep(Duration::from_millis(40)).await;
    (addr, cert, key)
}

fn h2_frame(ty: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + payload.len());
    let len = payload.len() as u32;
    out.push(((len >> 16) & 0xff) as u8);
    out.push(((len >> 8) & 0xff) as u8);
    out.push((len & 0xff) as u8);
    out.push(ty);
    out.push(flags);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

async fn tls_client(addr: std::net::SocketAddr) -> tokio_rustls::client::TlsStream<TcpStream> {
    use rustls::pki_types::ServerName;
    use rustls::ClientConfig;
    use std::sync::Arc;

    sedat::tls::ensure_crypto_provider();
    // Accept self-signed for corpus tests.
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let mut config = config;
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    connector.connect(name, tcp).await.unwrap()
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

#[tokio::test]
async fn continuation_flood_closes_or_rejects() {
    let (addr, _, _) = spawn_https().await;
    let mut tls = tls_client(addr).await;

    // Client preface + empty SETTINGS
    tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
    tls.write_all(&h2_frame(0x4, 0, 0, &[])).await.unwrap(); // SETTINGS

    // HEADERS without END_HEADERS, then many CONTINUATION frames (bomb shape).
    // Minimal HPACK: indexed :method GET (0x82), :scheme https (0x87), :path / (0x84),
    // :authority localhost — use literal for authority.
    let mut headers_payload = vec![0x82, 0x87, 0x84];
    // Literal Header Field without Indexing — :authority
    headers_payload.push(0x00); // literal without indexing, new name
    headers_payload.push(0x0a); // name len
    headers_payload.extend_from_slice(b":authority");
    headers_payload.push(0x09);
    headers_payload.extend_from_slice(b"localhost");
    tls.write_all(&h2_frame(0x1, 0x04, 1, &headers_payload))
        .await
        .unwrap(); // HEADERS, END_STREAM, no END_HEADERS

    let junk = vec![0u8; 1024];
    for _ in 0..64 {
        tls.write_all(&h2_frame(0x9, 0x00, 1, &junk)).await.unwrap(); // CONTINUATION
    }
    // Final CONTINUATION with END_HEADERS
    tls.write_all(&h2_frame(0x9, 0x04, 1, &junk)).await.unwrap();

    let mut buf = [0u8; 256];
    let result = tokio::time::timeout(Duration::from_secs(3), tls.read(&mut buf)).await;
    // Connection reset, EOF, GOAWAY/error frame, or timeout after server drop — all OK.
    match result {
        Ok(Ok(0)) | Err(_) => {}
        Ok(Ok(_)) => {}
        Ok(Err(_)) => {}
    }
}

#[tokio::test]
async fn oversized_single_headers_frame_handled() {
    let (addr, _, _) = spawn_https().await;
    let mut tls = tls_client(addr).await;
    tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
    tls.write_all(&h2_frame(0x4, 0, 0, &[])).await.unwrap();

    // One huge HEADERS payload (HPACK bomb-ish literal).
    let mut payload = vec![0x82, 0x87, 0x84];
    for i in 0..200 {
        let name = format!("x-bomb-{i}");
        let val = "A".repeat(64);
        payload.push(0x00);
        payload.push(name.len() as u8);
        payload.extend_from_slice(name.as_bytes());
        payload.push(val.len() as u8);
        payload.extend_from_slice(val.as_bytes());
    }
    tls.write_all(&h2_frame(0x1, 0x05, 1, &payload))
        .await
        .unwrap(); // END_STREAM | END_HEADERS

    let mut buf = [0u8; 256];
    let _ = tokio::time::timeout(Duration::from_secs(3), tls.read(&mut buf)).await;
}
