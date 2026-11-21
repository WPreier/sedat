//! HTTP clients for ACME (Pebble tolerates private CA via custom verifier).

use std::sync::Arc;

use bytes::Bytes;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use instant_acme::{BodyWrapper, HttpClient};

/// Build an ACME HTTP client. For Pebble (private CA), TLS verification is relaxed.
///
/// `instant-acme` 0.8's Hyper client impl already sets User-Agent; we only need a
/// TLS stack that accepts Pebble's private CA.
pub fn acme_http_client(directory: &str) -> Result<Box<dyn HttpClient>, String> {
    if directory.contains("14000") || directory.contains("pebble") {
        Ok(Box::new(pebble_hyper_client()?))
    } else {
        Ok(Box::new(secure_hyper_client()?))
    }
}

fn pebble_hyper_client(
) -> Result<HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, BodyWrapper<Bytes>>, String> {
    crate::tls::ensure_crypto_provider();
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Ok(HyperClient::builder(TokioExecutor::new()).build(https))
}

fn secure_hyper_client(
) -> Result<HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, BodyWrapper<Bytes>>, String> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|e| e.to_string())?
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();
    Ok(HyperClient::builder(TokioExecutor::new()).build(https))
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
