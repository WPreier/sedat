//! P10.8: ACME ARI parse/schedule + mock directory/renewalInfo HTTP.

use std::convert::Infallible;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
};
use sedat::acme::{
    certificate_id_from_pem, directory_renewal_info_url, fetch_ari_for_cert,
    fetch_renewal_info_base, not_after_from_pem, parse_renewal_info_json, schedule_renewal,
    RenewSchedule,
};
use tokio::net::TcpListener;

async fn spawn_ari_mock(cert_id: &str) -> (String, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let dir_url = format!("{base}/dir");
    let ri_base = format!("{base}/ri");
    let dir_body = format!(
        r#"{{"newNonce":"{base}/nonce","newAccount":"{base}/acct","newOrder":"{base}/order","renewalInfo":"{ri_base}"}}"#
    );
    let ri_path = format!("/ri/{cert_id}");
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let dir_body = dir_body.clone();
            let ri_path = ri_path.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let _ = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req: Request<hyper::body::Incoming>| {
                            let dir_body = dir_body.clone();
                            let ri_path = ri_path.clone();
                            async move {
                                let path = req.uri().path().to_string();
                                let resp = if path == "/dir" {
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "application/json")
                                        .body(Full::new(Bytes::from(dir_body)))
                                        .unwrap()
                                } else if path == ri_path {
                                    let body = r#"{
                                      "suggestedWindow": {
                                        "start": "2030-01-02T04:00:00Z",
                                        "end": "2030-01-03T04:00:00Z"
                                      },
                                      "explanationURL": "https://acme.example.com/docs/ari"
                                    }"#;
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "application/json")
                                        .header("retry-after", "3600")
                                        .body(Full::new(Bytes::from(body)))
                                        .unwrap()
                                } else {
                                    Response::builder()
                                        .status(StatusCode::NOT_FOUND)
                                        .body(Full::new(Bytes::from_static(b"nope")))
                                        .unwrap()
                                };
                                Ok::<_, Infallible>(resp)
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    (dir_url, ri_base)
}

fn mint_ee_with_aki() -> (Vec<u8>, String) {
    let mut ca_params = CertificateParams::new(vec!["Test CA".into()]).unwrap();
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut ee = CertificateParams::new(vec!["localhost".into()]).unwrap();
    ee.distinguished_name = DistinguishedName::new();
    ee.distinguished_name
        .push(DnType::CommonName, "localhost");
    ee.use_authority_key_identifier_extension = true;
    let ee_key = KeyPair::generate().unwrap();
    let ee_cert = ee.signed_by(&ee_key, &ca_cert, &ca_key).unwrap();
    let pem = ee_cert.pem().into_bytes();
    let id = certificate_id_from_pem(&pem).unwrap();
    (pem, id)
}

#[tokio::test]
async fn fetch_ari_from_mock_directory() {
    let (pem, cert_id) = mint_ee_with_aki();
    let (dir_url, _ri_base) = spawn_ari_mock(&cert_id).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let base = fetch_renewal_info_base(&dir_url).await.unwrap().unwrap();
    assert!(base.contains("/ri"), "{base}");
    assert_eq!(directory_renewal_info_url(
        &serde_json::json!({"renewalInfo": base.clone()}).to_string()
    ).as_deref(), Some(base.as_str()));

    let (info, retry) = fetch_ari_for_cert(&base, &cert_id).await.unwrap();
    assert_eq!(retry, Duration::from_secs(3600));
    assert!(info.explanation_url.is_some());

    let now = SystemTime::now();
    match schedule_renewal(now, Some(&info.window), not_after_from_pem(&pem).ok(), 30, 0.0)
    {
        RenewSchedule::Later {
            reason: "ari_suggested_window",
            at,
        } => assert!(at > now),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn parses_rfc_ari_example() {
    let info = parse_renewal_info_json(
        r#"{
          "suggestedWindow": {
            "start": "2025-01-02T04:00:00Z",
            "end": "2025-01-03T04:00:00Z"
          },
          "explanationURL": "https://acme.example.com/docs/ari"
        }"#,
    )
    .unwrap();
    assert_eq!(
        info.explanation_url.as_deref(),
        Some("https://acme.example.com/docs/ari")
    );
}
