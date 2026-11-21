//! ACME DNS-01 certificate management via `instant-acme`.

mod ari;
mod ari_fetch;
mod dns;
mod http_client;
mod renew;

pub use ari::{
    certificate_id_from_pem, directory_renewal_info_url, fallback_renew_at, not_after_from_pem,
    parse_renewal_info_json, parse_retry_after, pick_renewal_instant, schedule_renewal,
    sleep_until, AriInfo, AriWindow, RenewSchedule,
};
pub use ari_fetch::{fetch_ari_for_cert, fetch_renewal_info_base};
pub use http_client::acme_http_client;

pub use dns::{
    challenge_fqdn, resolve_secret, CloudflareDnsProvider, DnsHttpTransport, DnsProvider,
    FileDnsProvider, HyperDnsTransport, WebhookDnsProvider, CLOUDFLARE_TOKEN_ENV,
    WEBHOOK_BEARER_ENV,
};
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
///
/// Default / unknown → `file` (staging-safe). API providers fail closed at call
/// time if secrets/URLs are missing; construction errors map to a file provider
/// only when the feature cannot even build an HTTP client (logged).
pub fn dns_from_config(cfg: &AcmeConfig) -> Box<dyn DnsProvider> {
    match cfg.dns_provider.as_str() {
        "cloudflare" => {
            let token = resolve_secret(CLOUDFLARE_TOKEN_ENV, cfg.cloudflare_api_token.as_deref());
            let zone = cfg
                .cloudflare_zone_id
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            match CloudflareDnsProvider::new(token, zone) {
                Ok(p) => Box::new(p),
                Err(e) => {
                    tracing::error!(error = %e, "cloudflare DNS provider init failed; refusing silent fallback");
                    // Fail closed: empty-token cloudflare still constructed without HTTP? new() only fails on TLS client.
                    // Return a cloudflare provider that will error on present (token may be set).
                    Box::new(CloudflareDnsProvider::with_transport(
                        resolve_secret(CLOUDFLARE_TOKEN_ENV, cfg.cloudflare_api_token.as_deref()),
                        cfg.cloudflare_zone_id
                            .clone()
                            .filter(|s| !s.trim().is_empty()),
                        "https://api.cloudflare.com/client/v4",
                        std::sync::Arc::new(FailingTransport(e)),
                    ))
                }
            }
        }
        "webhook" => {
            let bearer = resolve_secret(WEBHOOK_BEARER_ENV, cfg.dns_webhook_bearer.as_deref());
            match WebhookDnsProvider::new(cfg.dns_webhook_url.clone(), bearer) {
                Ok(p) => Box::new(p),
                Err(e) => Box::new(WebhookDnsProvider::with_transport(
                    cfg.dns_webhook_url.clone(),
                    resolve_secret(WEBHOOK_BEARER_ENV, cfg.dns_webhook_bearer.as_deref()),
                    std::sync::Arc::new(FailingTransport(e)),
                )),
            }
        }
        _ => Box::new(FileDnsProvider::new(PathBuf::from(&cfg.dns_file))),
    }
}

/// Transport that always errors (used when Hyper client cannot be built).
struct FailingTransport(String);

impl DnsHttpTransport for FailingTransport {
    fn send<'a>(
        &'a self,
        _method: http::Method,
        _url: &'a str,
        _headers: Vec<(String, String)>,
        _body: Option<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = dns::DnsHttpResult> + Send + 'a>> {
        let msg = self.0.clone();
        Box::pin(async move { Err(format!("dns http client unavailable: {msg}")) })
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
