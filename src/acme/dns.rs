//! DNS-01 provider trait and implementations.
//!
//! Built-ins: `file` (default / staging-safe), `cloudflare` (API), `webhook` (generic HTTP).

use std::fs;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderValue, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use serde_json::{json, Value};
use tracing::{debug, info, warn};

/// Env override for Cloudflare API token (wins over config when non-empty).
pub const CLOUDFLARE_TOKEN_ENV: &str = "SEDAT_CLOUDFLARE_API_TOKEN";
/// Env override for webhook bearer token.
pub const WEBHOOK_BEARER_ENV: &str = "SEDAT_DNS_WEBHOOK_BEARER";

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

/// Result of one DNS HTTP call: `(status, body)`.
pub type DnsHttpResult = Result<(u16, String), String>;

/// Minimal HTTP surface used by API-backed DNS providers (injectable for tests).
pub trait DnsHttpTransport: Send + Sync {
    /// Perform one HTTP request; return status + body text.
    fn send<'a>(
        &'a self,
        method: Method,
        url: &'a str,
        headers: Vec<(String, String)>,
        body: Option<String>,
    ) -> Pin<Box<dyn Future<Output = DnsHttpResult> + Send + 'a>>;
}

/// Production HTTPS client (native roots).
pub struct HyperDnsTransport {
    client: HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>,
}

impl HyperDnsTransport {
    /// Build a TLS-verifying HTTPS client.
    pub fn try_new() -> Result<Self, String> {
        crate::tls::ensure_crypto_provider();
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|e| e.to_string())?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        Ok(Self {
            client: HyperClient::builder(TokioExecutor::new()).build(https),
        })
    }
}

impl DnsHttpTransport for HyperDnsTransport {
    fn send<'a>(
        &'a self,
        method: Method,
        url: &'a str,
        headers: Vec<(String, String)>,
        body: Option<String>,
    ) -> Pin<Box<dyn Future<Output = DnsHttpResult> + Send + 'a>> {
        Box::pin(async move {
            let payload = body.unwrap_or_default();
            let mut builder = Request::builder().method(method).uri(url);
            for (k, v) in &headers {
                builder = builder.header(k.as_str(), v.as_str());
            }
            if builder
                .headers_ref()
                .and_then(|h| h.get(http::header::USER_AGENT))
                .is_none()
            {
                builder = builder.header(
                    http::header::USER_AGENT,
                    HeaderValue::from_static("sedat-acme-dns/0.1"),
                );
            }
            let req = builder
                .body(Full::new(Bytes::from(payload)))
                .map_err(|e| e.to_string())?;
            let resp = self.client.request(req).await.map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let collected = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| e.to_string())?;
            let text = String::from_utf8_lossy(collected.to_bytes().as_ref()).into_owned();
            Ok((status, text))
        })
    }
}

/// ACME challenge FQDN (`_acme-challenge.` + domain, trailing dot stripped).
pub fn challenge_fqdn(domain: &str) -> String {
    let d = domain.trim_end_matches('.');
    format!("_acme-challenge.{d}")
}

/// Resolve secret: non-empty env wins, else config value.
pub fn resolve_secret(env_key: &str, configured: Option<&str>) -> String {
    if let Ok(v) = std::env::var(env_key) {
        let t = v.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    configured.unwrap_or("").trim().to_string()
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

/// Cloudflare DNS-01 via API v4 (zone lookup + TXT create/delete).
pub struct CloudflareDnsProvider {
    api_token: String,
    /// Optional zone id; when empty, look up by walking domain labels.
    zone_id: Option<String>,
    /// API base (default `https://api.cloudflare.com/client/v4`); override in tests.
    api_base: String,
    http: Arc<dyn DnsHttpTransport>,
}

impl CloudflareDnsProvider {
    /// Live provider with Hyper transport.
    pub fn new(api_token: String, zone_id: Option<String>) -> Result<Self, String> {
        Ok(Self {
            api_token,
            zone_id,
            api_base: "https://api.cloudflare.com/client/v4".into(),
            http: Arc::new(HyperDnsTransport::try_new()?),
        })
    }

    /// Test/injectable constructor.
    pub fn with_transport(
        api_token: String,
        zone_id: Option<String>,
        api_base: impl Into<String>,
        http: Arc<dyn DnsHttpTransport>,
    ) -> Self {
        Self {
            api_token,
            zone_id,
            api_base: api_base.into(),
            http,
        }
    }

    fn auth_headers(&self) -> Result<Vec<(String, String)>, String> {
        if self.api_token.is_empty() {
            return Err(
                "cloudflare dns provider: missing api token (set SEDAT_CLOUDFLARE_API_TOKEN or acme.cloudflare_api_token)"
                    .into(),
            );
        }
        Ok(vec![
            ("Authorization".into(), format!("Bearer {}", self.api_token)),
            ("Content-Type".into(), "application/json".into()),
        ])
    }

    async fn resolve_zone_id(&self, domain: &str) -> Result<String, String> {
        if let Some(z) = self.zone_id.as_ref().filter(|s| !s.is_empty()) {
            return Ok(z.clone());
        }
        let d = domain.trim_end_matches('.');
        let mut labels: Vec<&str> = d.split('.').collect();
        while labels.len() >= 2 {
            let candidate = labels.join(".");
            let url = format!(
                "{}/zones?name={}&status=active",
                self.api_base,
                urlencoding_lite(&candidate)
            );
            let (status, body) = self
                .http
                .send(Method::GET, &url, self.auth_headers()?, None)
                .await?;
            if !(200..300).contains(&status) {
                return Err(format!(
                    "cloudflare zone lookup HTTP {status}: {}",
                    truncate(&body, 200)
                ));
            }
            let v: Value = serde_json::from_str(&body)
                .map_err(|e| format!("cloudflare zone lookup JSON: {e}"))?;
            if v.get("success") == Some(&Value::Bool(false)) {
                return Err(format!(
                    "cloudflare zone lookup failed: {}",
                    truncate(&body, 200)
                ));
            }
            if let Some(id) = v
                .pointer("/result/0/id")
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
            {
                debug!(zone = %candidate, zone_id = id, "cloudflare zone resolved");
                return Ok(id.to_string());
            }
            labels.remove(0);
        }
        Err(format!(
            "cloudflare: no active zone found for domain `{domain}`"
        ))
    }

    async fn list_txt_ids(&self, zone_id: &str, fqdn: &str) -> Result<Vec<String>, String> {
        let url = format!(
            "{}/zones/{zone_id}/dns_records?type=TXT&name={}",
            self.api_base,
            urlencoding_lite(fqdn)
        );
        let (status, body) = self
            .http
            .send(Method::GET, &url, self.auth_headers()?, None)
            .await?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "cloudflare list TXT HTTP {status}: {}",
                truncate(&body, 200)
            ));
        }
        let v: Value =
            serde_json::from_str(&body).map_err(|e| format!("cloudflare list TXT JSON: {e}"))?;
        let mut ids = Vec::new();
        if let Some(arr) = v.get("result").and_then(|r| r.as_array()) {
            for rec in arr {
                if let Some(id) = rec.get("id").and_then(|x| x.as_str()) {
                    ids.push(id.to_string());
                }
            }
        }
        Ok(ids)
    }

    async fn delete_record(&self, zone_id: &str, id: &str) -> Result<(), String> {
        let url = format!("{}/zones/{zone_id}/dns_records/{id}", self.api_base);
        let (status, body) = self
            .http
            .send(Method::DELETE, &url, self.auth_headers()?, None)
            .await?;
        if !(200..300).contains(&status) {
            return Err(format!(
                "cloudflare delete TXT HTTP {status}: {}",
                truncate(&body, 200)
            ));
        }
        Ok(())
    }
}

impl DnsProvider for CloudflareDnsProvider {
    fn present<'a>(
        &'a self,
        domain: &'a str,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let fqdn = challenge_fqdn(domain);
            let zone_id = self.resolve_zone_id(domain).await?;
            // Replace any existing challenge TXT for this name (idempotent renewals).
            for id in self.list_txt_ids(&zone_id, &fqdn).await? {
                self.delete_record(&zone_id, &id).await?;
            }
            let url = format!("{}/zones/{zone_id}/dns_records", self.api_base);
            let payload = json!({
                "type": "TXT",
                "name": fqdn,
                "content": token,
                "ttl": 120,
            })
            .to_string();
            let (status, body) = self
                .http
                .send(Method::POST, &url, self.auth_headers()?, Some(payload))
                .await?;
            if !(200..300).contains(&status) {
                return Err(format!(
                    "cloudflare create TXT HTTP {status}: {}",
                    truncate(&body, 240)
                ));
            }
            let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            if v.get("success") == Some(&Value::Bool(false)) {
                return Err(format!(
                    "cloudflare create TXT failed: {}",
                    truncate(&body, 240)
                ));
            }
            info!(%fqdn, %zone_id, "DNS-01 TXT created (cloudflare)");
            Ok(())
        })
    }

    fn cleanup<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            if self.api_token.is_empty() {
                warn!("cloudflare cleanup skipped: empty api token");
                return Ok(());
            }
            let fqdn = challenge_fqdn(domain);
            let zone_id = match self.resolve_zone_id(domain).await {
                Ok(z) => z,
                Err(e) => {
                    warn!(error = %e, "cloudflare cleanup: zone resolve failed");
                    return Ok(());
                }
            };
            for id in self.list_txt_ids(&zone_id, &fqdn).await? {
                self.delete_record(&zone_id, &id).await?;
            }
            info!(%fqdn, "DNS-01 TXT cleaned (cloudflare)");
            Ok(())
        })
    }
}

/// Generic HTTP webhook DNS-01 provider.
///
/// POSTs JSON `{action, domain, fqdn, token?}` to `url`. Optional bearer auth.
/// Staging-safe: requires an explicit URL (no default endpoint).
pub struct WebhookDnsProvider {
    url: String,
    bearer: String,
    http: Arc<dyn DnsHttpTransport>,
}

impl WebhookDnsProvider {
    /// Live provider with Hyper transport.
    pub fn new(url: String, bearer: String) -> Result<Self, String> {
        Ok(Self {
            url,
            bearer,
            http: Arc::new(HyperDnsTransport::try_new()?),
        })
    }

    /// Test/injectable constructor.
    pub fn with_transport(
        url: impl Into<String>,
        bearer: impl Into<String>,
        http: Arc<dyn DnsHttpTransport>,
    ) -> Self {
        Self {
            url: url.into(),
            bearer: bearer.into(),
            http,
        }
    }

    fn headers(&self) -> Vec<(String, String)> {
        let mut h = vec![("Content-Type".into(), "application/json".into())];
        if !self.bearer.is_empty() {
            h.push(("Authorization".into(), format!("Bearer {}", self.bearer)));
        }
        h
    }

    async fn post_action(
        &self,
        action: &str,
        domain: &str,
        token: Option<&str>,
    ) -> Result<(), String> {
        if self.url.trim().is_empty() {
            return Err("webhook dns provider: missing url (set acme.dns_webhook_url)".into());
        }
        let fqdn = challenge_fqdn(domain);
        let mut body = json!({
            "action": action,
            "domain": domain.trim_end_matches('.'),
            "fqdn": fqdn,
        });
        if let Some(t) = token {
            body["token"] = Value::String(t.to_string());
        }
        let (status, resp) = self
            .http
            .send(
                Method::POST,
                &self.url,
                self.headers(),
                Some(body.to_string()),
            )
            .await?;
        if !(200..300).contains(&status) && status != StatusCode::NO_CONTENT.as_u16() {
            return Err(format!(
                "webhook dns {action} HTTP {status}: {}",
                truncate(&resp, 200)
            ));
        }
        info!(%action, %fqdn, "DNS-01 webhook call ok");
        Ok(())
    }
}

impl DnsProvider for WebhookDnsProvider {
    fn present<'a>(
        &'a self,
        domain: &'a str,
        token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { self.post_action("present", domain, Some(token)).await })
    }

    fn cleanup<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { self.post_action("cleanup", domain, None).await })
    }
}

fn truncate(s: &str, max: usize) -> String {
    let t = s.replace('\n', " ");
    if t.len() <= max {
        t
    } else {
        format!("{}…", &t[..max])
    }
}

/// Minimal URL-encoding for query values (unreserved + alnum pass through).
fn urlencoding_lite(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MockHttp {
        /// Recorded method+url+body triples.
        log: Mutex<Vec<(String, String, Option<String>)>>,
        /// Scripted responses keyed by substring of URL (first match).
        script: Mutex<Vec<(String, u16, String)>>,
    }

    impl MockHttp {
        fn new(script: Vec<(String, u16, String)>) -> Arc<Self> {
            Arc::new(Self {
                log: Mutex::new(Vec::new()),
                script: Mutex::new(script),
            })
        }
    }

    impl DnsHttpTransport for MockHttp {
        fn send<'a>(
            &'a self,
            method: Method,
            url: &'a str,
            _headers: Vec<(String, String)>,
            body: Option<String>,
        ) -> Pin<Box<dyn Future<Output = DnsHttpResult> + Send + 'a>> {
            Box::pin(async move {
                self.log.lock().unwrap().push((
                    method.as_str().to_string(),
                    url.to_string(),
                    body.clone(),
                ));
                let mut script = self.script.lock().unwrap();
                if let Some(i) = script.iter().position(|(pat, _, _)| url.contains(pat)) {
                    let (_pat, status, resp) = script.remove(i);
                    return Ok((status, resp));
                }
                Err(format!("mock: no scripted response for {url}"))
            })
        }
    }

    #[tokio::test]
    async fn cloudflare_present_looks_up_zone_creates_txt() {
        let http = MockHttp::new(vec![
            (
                "zones?name=www.example.com".into(),
                200,
                r#"{"success":true,"result":[]}"#.into(),
            ),
            (
                "zones?name=example.com".into(),
                200,
                r#"{"success":true,"result":[{"id":"zone-1"}]}"#.into(),
            ),
            (
                "dns_records?type=TXT".into(),
                200,
                r#"{"success":true,"result":[]}"#.into(),
            ),
            (
                "/zones/zone-1/dns_records".into(),
                200,
                r#"{"success":true,"result":{"id":"rec-1"}}"#.into(),
            ),
        ]);
        let p = CloudflareDnsProvider::with_transport(
            "tok".into(),
            None,
            "https://cf.test/client/v4",
            http.clone(),
        );
        p.present("www.example.com", "challenge-token")
            .await
            .unwrap();
        let log = http.log.lock().unwrap();
        assert!(log
            .iter()
            .any(|(m, u, _)| m == "GET" && u.contains("zones?name=example.com")));
        assert!(log.iter().any(|(m, u, b)| {
            m == "POST"
                && u.ends_with("/zones/zone-1/dns_records")
                && b.as_ref().is_some_and(|s| s.contains("challenge-token"))
        }));
    }

    #[tokio::test]
    async fn cloudflare_present_fail_closed_without_token() {
        let http = MockHttp::new(vec![]);
        let p = CloudflareDnsProvider::with_transport(
            String::new(),
            None,
            "https://cf.test/client/v4",
            http,
        );
        let err = p.present("example.com", "t").await.unwrap_err();
        assert!(err.contains("missing api token"));
    }

    #[tokio::test]
    async fn webhook_present_posts_json() {
        let http = MockHttp::new(vec![("hooks.example".into(), 204, String::new())]);
        let p =
            WebhookDnsProvider::with_transport("https://hooks.example/dns", "secret", http.clone());
        p.present("example.com", "tok").await.unwrap();
        let log = http.log.lock().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].0, "POST");
        let body = log[0].2.as_ref().unwrap();
        assert!(body.contains("\"action\":\"present\""));
        assert!(body.contains("\"token\":\"tok\""));
        assert!(body.contains("_acme-challenge.example.com"));
    }

    #[tokio::test]
    async fn webhook_requires_url() {
        let http = MockHttp::new(vec![]);
        let p = WebhookDnsProvider::with_transport("", "", http);
        let err = p.present("example.com", "t").await.unwrap_err();
        assert!(err.contains("missing url"));
    }

    #[test]
    fn challenge_fqdn_strips_trailing_dot() {
        assert_eq!(
            challenge_fqdn("example.com."),
            "_acme-challenge.example.com"
        );
    }
}
