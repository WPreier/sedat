//! HTTP fetch for ACME directory + ARI renewalInfo (GET, no JWS).

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;

use super::ari::{
    directory_renewal_info_url, parse_renewal_info_json, parse_retry_after,
    renewal_info_request_url, AriInfo,
};

/// Fetch ACME directory and return the `renewalInfo` base URL if present.
pub async fn fetch_renewal_info_base(directory_url: &str) -> Result<Option<String>, String> {
    let body = http_get_text(directory_url).await?;
    Ok(directory_renewal_info_url(&body))
}

/// GET `{renewalInfo}/{cert_id}` and parse the suggested window + Retry-After hint.
pub async fn fetch_ari_for_cert(
    renewal_info_base: &str,
    cert_id: &str,
) -> Result<(AriInfo, Duration), String> {
    let url = renewal_info_request_url(renewal_info_base, cert_id);
    let (status, retry_hdr, body) = http_get(url.as_str()).await?;
    if status != StatusCode::OK {
        return Err(format!("ARI HTTP {status}: {body}"));
    }
    let info = parse_renewal_info_json(&body)?;
    let retry = parse_retry_after(retry_hdr.as_deref());
    Ok((info, retry))
}

async fn http_get_text(url: &str) -> Result<String, String> {
    let (_s, _r, body) = http_get(url).await?;
    Ok(body)
}

async fn http_get(url: &str) -> Result<(StatusCode, Option<String>, String), String> {
    crate::tls::ensure_crypto_provider();
    let pebbleish =
        url.contains("14000") || url.contains("pebble") || url.contains("127.0.0.1");
    let tls = if pebbleish {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();
    let client = HyperClient::builder(TokioExecutor::new())
        .build::<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>(https);
    let req = Request::builder()
        .method(Method::GET)
        .uri(url)
        .header(http::header::USER_AGENT, "sedat-acme-ari/0.1")
        .body(Full::new(Bytes::new()))
        .map_err(|e| e.to_string())?;
    let rsp = client
        .request(req)
        .await
        .map_err(|e| format!("ARI GET: {e}"))?;
    let status = rsp.status();
    let retry = rsp
        .headers()
        .get(http::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body_bytes = rsp
        .into_body()
        .collect()
        .await
        .map_err(|e| format!("ARI body: {e}"))?
        .to_bytes();
    let body = String::from_utf8_lossy(&body_bytes).into_owned();
    Ok((status, retry, body))
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
