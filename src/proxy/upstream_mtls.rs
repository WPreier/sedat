//! Optional TLS / mTLS client config for HTTPS upstreams.

use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};

use crate::tls::ensure_crypto_provider;

/// PEM paths for optional upstream TLS client auth / custom CA.
#[derive(Debug, Clone, Default)]
pub struct UpstreamTlsPaths<'a> {
    /// Client certificate PEM path (empty = no client auth).
    pub cert: &'a str,
    /// Client private key PEM path.
    pub key: &'a str,
    /// CA PEM to verify the upstream server (empty = webpki roots).
    pub ca: &'a str,
}

/// Build a rustls `ClientConfig` for an HTTPS upstream.
///
/// - Empty cert+key → no client authentication (TLS only).
/// - Both cert+key set → mTLS client certificate.
/// - Empty CA → public [`webpki_roots`] trust store.
/// - CA set → only that PEM trust anchors (typical for private upstream CAs).
pub fn build_upstream_client_config(paths: &UpstreamTlsPaths<'_>) -> io::Result<Arc<ClientConfig>> {
    ensure_crypto_provider();

    let mut roots = RootCertStore::empty();
    if paths.ca.trim().is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    } else {
        let ca_pem = fs::read(paths.ca.trim())?;
        let mut reader = io::Cursor::new(ca_pem);
        let mut added = 0usize;
        for item in rustls_pemfile::certs(&mut reader) {
            let der = item.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            roots
                .add(der)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            added += 1;
        }
        if added == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upstream_mtls_ca contains no certificates",
            ));
        }
    }

    let builder = ClientConfig::builder().with_root_certificates(roots);

    let has_cert = !paths.cert.trim().is_empty();
    let has_key = !paths.key.trim().is_empty();
    if has_cert != has_key {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "upstream_mtls_cert and upstream_mtls_key must both be set or both empty",
        ));
    }

    let mut cfg = if has_cert {
        let certs = load_certs(Path::new(paths.cert.trim()))?;
        let key = load_private_key(Path::new(paths.key.trim()))?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
    } else {
        builder.with_no_client_auth()
    };

    // Upstream HTTP/1.1 only in the manual PROXY+HTTP write path.
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let pem = fs::read(path)?;
    let mut reader = io::Cursor::new(pem);
    let mut certs = Vec::new();
    for item in rustls_pemfile::certs(&mut reader) {
        certs.push(item.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?);
    }
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no certificates in upstream_mtls_cert",
        ));
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let pem = fs::read(path)?;
    let mut reader = io::Cursor::new(pem);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "no private key in upstream_mtls_key",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    };
    use tempfile::tempdir;

    fn write_pem_pair(dir: &Path, name: &str, cert_pem: &str, key_pem: &str) -> (String, String) {
        let cert = dir.join(format!("{name}.crt"));
        let key = dir.join(format!("{name}.key"));
        fs::write(&cert, cert_pem).unwrap();
        fs::write(&key, key_pem).unwrap();
        (
            cert.to_string_lossy().into_owned(),
            key.to_string_lossy().into_owned(),
        )
    }

    #[test]
    fn builds_mtls_config_with_custom_ca() {
        let dir = tempdir().unwrap();
        let mut ca_params = CertificateParams::new(vec!["SedatTestCA".into()]).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "SedatTestCA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

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

        let ca_path = dir.path().join("ca.crt");
        fs::write(&ca_path, ca_cert.pem()).unwrap();
        let (cert, key) = write_pem_pair(
            dir.path(),
            "client",
            &client_cert.pem(),
            &client_key.serialize_pem(),
        );

        let cfg = build_upstream_client_config(&UpstreamTlsPaths {
            cert: &cert,
            key: &key,
            ca: &ca_path.to_string_lossy(),
        })
        .unwrap();
        assert!(cfg.alpn_protocols.contains(&b"http/1.1".to_vec()));
    }

    #[test]
    fn rejects_cert_without_key() {
        let err = build_upstream_client_config(&UpstreamTlsPaths {
            cert: "/tmp/x.crt",
            key: "",
            ca: "",
        })
        .unwrap_err();
        assert!(err.to_string().contains("both"));
    }
}
