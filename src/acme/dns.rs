//! DNS-01 provider trait and implementations.

use std::fs;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use tracing::info;

/// Async DNS-01 challenge provider.
pub trait DnsProvider: Send + Sync {
    /// Present TXT record for `_acme-challenge.{domain}`.
    fn present<'a>(
        &'a self,
        domain: &'a str,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    /// Clean up TXT record.
    fn cleanup<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// Writes challenge material to a local file for manual/Pebble/mock DNS.
pub struct FileDnsProvider {
    path: PathBuf,
}

impl FileDnsProvider {
    /// Create provider writing to `path`.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl DnsProvider for FileDnsProvider {
    fn present<'a>(
        &'a self,
        domain: &'a str,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            if let Some(parent) = self.path.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let body = format!("_acme-challenge.{domain}. IN TXT \"{token}\"\n");
            fs::write(&self.path, &body).map_err(|e| e.to_string())?;
            info!(file = %self.path.display(), domain, "DNS-01 challenge written (file provider)");
            Ok(())
        })
    }

    fn cleanup<'a>(
        &'a self,
        _domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let _ = fs::remove_file(&self.path);
            Ok(())
        })
    }
}

/// Cloudflare DNS provider stub (API calls documented; token required for live use).
pub struct CloudflareDnsProvider {
    api_token: String,
}

impl CloudflareDnsProvider {
    /// Create with API token (may be empty in tests).
    pub fn new(api_token: String) -> Self {
        Self { api_token }
    }
}

impl DnsProvider for CloudflareDnsProvider {
    fn present<'a>(
        &'a self,
        domain: &'a str,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            if self.api_token.is_empty() {
                return Err(
                    "cloudflare dns provider: missing api token (set acme.cloudflare_api_token)"
                        .into(),
                );
            }
            // Live HTTP API left for production wiring; fail-closed without network side effects
            // in CI. Operators use file provider + external automation or extend this trait.
            let _ = (domain, token);
            Err(
                "cloudflare live API not enabled in this build; use dns_provider=file or extend trait"
                    .into(),
            )
        })
    }

    fn cleanup<'a>(
        &'a self,
        _domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { Ok(()) })
    }
}
