//! P10.7: optional HTTPS upstream + mTLS client certificate.

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sedat::config::{
    HostRoute, PathRoute, ProxyProtocolConfig, RoutesConfig, SedatConfig,
    ServerConfig as SedatServer,
};
use sedat::proxy::{handle_request, ProxyState};
use sedat::tls::ensure_crypto_provider;
use tempfile::tempdir;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

struct MtlsMaterial {
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
}

fn mint_mtls_material() -> MtlsMaterial {
    let mut ca_params = CertificateParams::new(vec!["SedatUpstreamCA".into()]).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "SedatUpstreamCA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    server_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    let mut client_params = CertificateParams::new(vec!["sedat-client".into()]).unwrap();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "sedat-client");
    client_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();

    MtlsMaterial {
        ca_pem: ca_cert.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    }
}

fn server_config_require_client(mat: &MtlsMaterial) -> Arc<ServerConfig> {
    ensure_crypto_provider();
    let mut roots = RootCertStore::empty();
    let mut reader = std::io::Cursor::new(mat.ca_pem.as_bytes());
    for item in rustls_pemfile::certs(&mut reader) {
        roots.add(item.unwrap()).unwrap();
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();

    let mut cert_reader = std::io::Cursor::new(mat.server_cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .map(|r| r.unwrap())
        .collect();
    let mut key_reader = std::io::Cursor::new(mat.server_key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .unwrap()
        .unwrap();

    let mut cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

async fn spawn_mtls_upstream(mat: &MtlsMaterial) -> std::net::SocketAddr {
    let acceptor = TlsAcceptor::from(server_config_require_client(mat));
    let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = up.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = up.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let io = TokioIo::new(tls);
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|_req: Request<hyper::body::Incoming>| async {
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(Full::new(Bytes::from_static(b"mtls-ok")))
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

fn cfg_https(upstream: &str, cert: &str, key: &str, ca: &str) -> SedatConfig {
    SedatConfig {
        schema_version: 1,
        server: SedatServer::default(),
        tls: Default::default(),
        acme: Default::default(),
        routes: RoutesConfig {
            hosts: vec![HostRoute {
                host: "localhost".into(),
                paths: vec![PathRoute {
                    prefix: "/".into(),
                    upstream: upstream.into(),
                    upstream_mtls_cert: cert.into(),
                    upstream_mtls_key: key.into(),
                    upstream_mtls_ca: ca.into(),
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

async fn spawn_proxy(cfg: SedatConfig) -> std::net::SocketAddr {
    let state = ProxyState::new(cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, peer) = listener.accept().await.unwrap();
            let state = state.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = hyper::service::service_fn(move |req| {
                    let state = state.clone();
                    async move { handle_request(req, peer, state, None).await }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn upstream_mtls_ok_with_client_cert() {
    let dir = tempdir().unwrap();
    let mat = mint_mtls_material();
    let ca = dir.path().join("ca.crt");
    let cert = dir.path().join("client.crt");
    let key = dir.path().join("client.key");
    fs::write(&ca, &mat.ca_pem).unwrap();
    fs::write(&cert, &mat.client_cert_pem).unwrap();
    fs::write(&key, &mat.client_key_pem).unwrap();

    let up = spawn_mtls_upstream(&mat).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let proxy = spawn_proxy(cfg_https(
        &format!("https://localhost:{}", up.port()),
        cert.to_str().unwrap(),
        key.to_str().unwrap(),
        ca.to_str().unwrap(),
    ))
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (status, body) = hit(proxy).await;
    assert_eq!(status, StatusCode::OK, "body={body}");
    assert!(body.contains("mtls-ok"), "{body}");
}

#[tokio::test]
async fn upstream_mtls_fails_without_client_cert() {
    let dir = tempdir().unwrap();
    let mat = mint_mtls_material();
    let ca = dir.path().join("ca.crt");
    fs::write(&ca, &mat.ca_pem).unwrap();

    let up = spawn_mtls_upstream(&mat).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    // HTTPS + custom CA, but no client cert → handshake rejected by upstream.
    let proxy = spawn_proxy(cfg_https(
        &format!("https://localhost:{}", up.port()),
        "",
        "",
        ca.to_str().unwrap(),
    ))
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (status, body) = hit(proxy).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "body={body}");
}
