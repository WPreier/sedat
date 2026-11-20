//! ACME DNS-01 certificate management via `instant-acme`.

mod dns;
mod http_client;
mod renew;

pub use http_client::acme_http_client;

pub use dns::{DnsProvider, FileDnsProvider};
pub use renew::{AcmeManager, AcmeStatus};

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use tracing::info;

use crate::config::AcmeConfig;

/// Let's Encrypt staging directory.
pub const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
/// Let's Encrypt production directory.
pub const LETSENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Pebble default directory (local).
pub const PEBBLE_DIRECTORY: &str = "https://localhost:14000/dir";

/// Resolve ACME directory URL from config value.
pub fn directory_url(name_or_url: &str) -> String {
    match name_or_url {
        "staging" => LETSENCRYPT_STAGING.to_string(),
        "production" => LETSENCRYPT_PRODUCTION.to_string(),
        "pebble" => PEBBLE_DIRECTORY.to_string(),
        other => other.to_string(),
    }
}

/// Paths used for ACME persistence under `state_dir`.
#[derive(Debug, Clone)]
pub struct AcmePaths {
    /// State directory.
    pub state_dir: PathBuf,
    /// Account JSON.
    pub account_path: PathBuf,
    /// Certificate PEM.
    pub cert_path: PathBuf,
    /// Private key PEM.
    pub key_path: PathBuf,
}

impl AcmePaths {
    /// Build under `state_dir`.
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        let state_dir = state_dir.into();
        Self {
            account_path: state_dir.join("acme_account.json"),
            cert_path: state_dir.join("cert.pem"),
            key_path: state_dir.join("key.pem"),
            state_dir,
        }
    }

    /// Ensure state directory exists.
    pub fn ensure(&self) -> io::Result<()> {
        fs::create_dir_all(&self.state_dir)
    }
}

/// Build a DNS provider from config.
pub fn dns_from_config(cfg: &AcmeConfig) -> Box<dyn DnsProvider> {
    match cfg.dns_provider.as_str() {
        "cloudflare" => Box::new(dns::CloudflareDnsProvider::new(
            cfg.cloudflare_api_token.clone().unwrap_or_default(),
        )),
        _ => Box::new(FileDnsProvider::new(PathBuf::from(&cfg.dns_file))),
    }
}

/// Check whether cert/key already exist on disk.
pub fn load_existing_cert(paths: &AcmePaths) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    if paths.cert_path.exists() && paths.key_path.exists() {
        let cert = fs::read(&paths.cert_path)?;
        let key = fs::read(&paths.key_path)?;
        info!(cert = %paths.cert_path.display(), "loaded existing ACME/static cert");
        Ok(Some((cert, key)))
    } else {
        Ok(None)
    }
}

/// Persist cert material; does not delete previous files until write succeeds.
pub fn persist_cert(paths: &AcmePaths, cert_pem: &[u8], key_pem: &[u8]) -> io::Result<()> {
    paths.ensure()?;
    let cert_tmp = paths.cert_path.with_extension("pem.tmp");
    let key_tmp = paths.key_path.with_extension("pem.tmp");
    fs::write(&cert_tmp, cert_pem)?;
    fs::write(&key_tmp, key_pem)?;
    fs::rename(&cert_tmp, &paths.cert_path)?;
    fs::rename(&key_tmp, &paths.key_path)?;
    Ok(())
}

/// Write challenge token for file-based DNS providers / operators.
pub fn write_dns_challenge_file(path: &Path, domain: &str, content: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = format!("_acme-challenge.{domain}. IN TXT \"{content}\"\n");
    fs::write(path, body)
}
