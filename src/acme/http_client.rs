//! HTTP clients for ACME (Pebble tolerates private CA via custom verifier).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http::Request;
use http_body_util::Full;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use instant_acme::{BytesResponse, Error as AcmeError, HttpClient};

/// Build an ACME HTTP client. For Pebble (private CA), TLS verification is relaxed.
pub fn acme_http_client(directory: &str) -> Result<Box<dyn HttpClient>, String> {
    if directory.contains("14000") || directory.contains("pebble") {
        Ok(Box::new(PebbleClient::try_new()?))
    } else {
        // Use instant-acme default path via Account::create (native roots).
        // Callers should use Account::create for non-Pebble; this is only for create_with_http.
        Ok(Box::new(PebbleClient::try_new_secure()?))
    }
}

struct PebbleClient(HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>);

impl PebbleClient {
    fn try_new() -> Result<Self, String> {
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
        Ok(Self(
            HyperClient::builder(TokioExecutor::new()).build(https),
        ))
    }

    fn try_new_secure() -> Result<Self, String> {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|e| e.to_string())?
            .https_only()
            .enable_http1()
            .enable_http2()
            .build();
        Ok(Self(
            HyperClient::builder(TokioExecutor::new()).build(https),
        ))
    }
}

impl HttpClient for PebbleClient {
    fn request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, AcmeError>> + Send>> {
        let fut = self.0.request(req);
        Box::pin(async move {
            match fut.await {
                Ok(rsp) => Ok(BytesResponse::from(rsp)),
                Err(e) => Err(AcmeError::Other(Box::new(e))),
            }
        })
    }
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
