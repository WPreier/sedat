//! ACME issuance / renewal loop with fail-closed cert retention and optional ARI.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tracing::{info, warn};

use crate::config::AcmeConfig;
use crate::tls::{server_config_from_pem, TlsState};

use super::ari::{
    certificate_id_from_pem, not_after_from_pem, random_jitter_01, schedule_renewal, sleep_until,
    RenewSchedule,
};
use super::ari_fetch::{fetch_ari_for_cert, fetch_renewal_info_base};
use super::dns::DnsProvider;
use super::{directory_url, persist_cert, AcmePaths};

/// Observable ACME status for admin socket.
#[derive(Debug, Clone, Default)]
pub struct AcmeStatus {
    /// Last successful issue/renew timestamp (unix secs), if any.
    pub last_success_unix: Option<u64>,
    /// Last error message.
    pub last_error: Option<String>,
    /// Directory URL in use.
    pub directory: String,
    /// Last ARI schedule reason (`ari_suggested_window`, `expiry_fallback`, …).
    pub last_schedule_reason: Option<String>,
    /// Whether the last schedule used a live ARI window.
    pub ari_active: bool,
}

/// Manages ACME lifecycle; on failure keeps previous cert in [`TlsState`].
pub struct AcmeManager {
    /// Config snapshot.
    pub cfg: AcmeConfig,
    /// Persistence paths.
    pub paths: AcmePaths,
    /// DNS provider.
    pub dns: Box<dyn DnsProvider>,
    /// Optional TLS hot-swap target.
    pub tls: Option<TlsState>,
    /// Status.
    pub status: Arc<parking_lot::Mutex<AcmeStatus>>,
}

impl AcmeManager {
    /// Construct manager.
    pub fn new(
        cfg: AcmeConfig,
        paths: AcmePaths,
        dns: Box<dyn DnsProvider>,
        tls: Option<TlsState>,
    ) -> Self {
        let directory = directory_url(&cfg.directory);
        Self {
            cfg,
            paths,
            dns,
            tls,
            status: Arc::new(parking_lot::Mutex::new(AcmeStatus {
                directory,
                ..Default::default()
            })),
        }
    }

    /// Attempt full DNS-01 certificate obtain via `instant-acme`.
    ///
    /// On any failure, previous certificate remains active (fail-closed).
    /// With Pebble + `PEBBLE_VA_ALWAYS_VALID=1`, the file DNS provider is enough for CI.
    pub async fn order_once(&self) -> Result<(), String> {
        if self.cfg.domains.is_empty() {
            return Err("no ACME domains configured".into());
        }
        let directory = directory_url(&self.cfg.directory);
        info!(%directory, domains = ?self.cfg.domains, "ACME order starting");

        match issue_certificate(&self.cfg, &self.paths, self.dns.as_ref(), &directory).await {
            Ok((cert_pem, key_pem)) => {
                self.install_cert(&cert_pem, &key_pem)?;
                Ok(())
            }
            Err(e) => {
                self.status.lock().last_error = Some(e.clone());
                warn!(error = %e, "ACME order failed; previous certificate retained");
                Err(e)
            }
        }
    }

    fn install_cert(&self, cert_pem: &[u8], key_pem: &[u8]) -> Result<(), String> {
        let sc = server_config_from_pem(cert_pem, key_pem).map_err(|e| e.to_string())?;
        persist_cert(&self.paths, cert_pem, key_pem).map_err(|e| e.to_string())?;
        if let Some(ref tls) = self.tls {
            tls.swap(sc);
        }
        let mut st = self.status.lock();
        st.last_success_unix = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );
        st.last_error = None;
        info!("certificate installed and hot-swapped");
        Ok(())
    }

    /// Install a self-signed cert for configured domains (dev / offline tests).
    pub async fn install_self_signed_for_domains(&self) -> Result<(), String> {
        let names = if self.cfg.domains.is_empty() {
            vec!["localhost".to_string()]
        } else {
            self.cfg.domains.clone()
        };
        let domain = names[0].clone();
        let _ = self.dns.present(&domain, "self-signed-dev").await;
        let cert = rcgen::generate_simple_self_signed(names).map_err(|e| e.to_string())?;
        let cert_pem = cert.cert.pem().into_bytes();
        let key_pem = cert.key_pair.serialize_pem().into_bytes();
        self.install_cert(&cert_pem, &key_pem)
    }

    /// Background renewal loop: ARI window when available, else expiry fallback.
    ///
    /// Wakes at least every 24h to re-fetch ARI / re-evaluate. Failures use
    /// exponential backoff; previous cert is always retained on order errors.
    pub async fn renewal_loop(self: Arc<Self>) {
        let mut backoff = Duration::from_secs(30);
        let max_backoff = Duration::from_secs(3600);
        let max_sleep = Duration::from_secs(24 * 3600);
        loop {
            if !self.paths.cert_path.exists() || !self.paths.key_path.exists() {
                info!("no certificate on disk; issuing");
                match self.order_once().await {
                    Ok(()) => backoff = Duration::from_secs(30),
                    Err(_) => {
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(max_backoff);
                    }
                }
                continue;
            }

            match self.plan_renewal().await {
                RenewSchedule::Now { reason } => {
                    info!(reason, "ACME renewal due");
                    match self.order_once().await {
                        Ok(()) => backoff = Duration::from_secs(30),
                        Err(_) => {
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(max_backoff);
                        }
                    }
                }
                RenewSchedule::Later { at, reason } => {
                    let now = SystemTime::now();
                    let delay = sleep_until(now, at, max_sleep);
                    info!(reason, ?delay, "ACME renewal sleep");
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    /// Decide whether to renew now or sleep (ARI → expiry fallback → 24h).
    pub async fn plan_renewal(&self) -> RenewSchedule {
        let now = SystemTime::now();
        let cert_pem = std::fs::read(&self.paths.cert_path).ok();
        let not_after = cert_pem.as_ref().and_then(|p| not_after_from_pem(p).ok());

        let mut ari_window = None;
        let mut ari_active = false;
        if self.cfg.ari {
            if let Some(ref pem) = cert_pem {
                match self.try_fetch_ari(pem).await {
                    Ok(Some(window)) => {
                        ari_window = Some(window);
                        ari_active = true;
                    }
                    Ok(None) => {
                        info!("ACME ARI unavailable; using expiry fallback");
                    }
                    Err(e) => {
                        warn!(error = %e, "ACME ARI fetch failed; using expiry fallback");
                    }
                }
            }
        }

        let schedule = schedule_renewal(
            now,
            ari_window.as_ref(),
            not_after,
            self.cfg.renew_days_before,
            random_jitter_01(),
        );
        {
            let mut st = self.status.lock();
            st.ari_active = ari_active;
            st.last_schedule_reason = Some(match &schedule {
                RenewSchedule::Now { reason } => (*reason).to_string(),
                RenewSchedule::Later { reason, .. } => (*reason).to_string(),
            });
        }
        schedule
    }

    async fn try_fetch_ari(
        &self,
        cert_pem: &[u8],
    ) -> Result<Option<super::ari::AriWindow>, String> {
        let directory = directory_url(&self.cfg.directory);
        let Some(base) = fetch_renewal_info_base(&directory).await? else {
            return Ok(None);
        };
        let cert_id = certificate_id_from_pem(cert_pem)?;
        let (info, _retry) = fetch_ari_for_cert(&base, &cert_id).await?;
        Ok(Some(info.window))
    }
}

async fn issue_certificate(
    cfg: &AcmeConfig,
    paths: &AcmePaths,
    dns: &dyn DnsProvider,
    directory: &str,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    use instant_acme::{Account, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus};

    paths.ensure().map_err(|e| e.to_string())?;

    let contact: Vec<String> = if cfg.email.is_empty() {
        vec![]
    } else {
        vec![format!("mailto:{}", cfg.email)]
    };
    let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();

    let new_account = NewAccount {
        contact: &contacts,
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let (account, creds) = if directory.contains("14000") || directory.contains("pebble") {
        let http = super::http_client::acme_http_client(directory)?;
        Account::create_with_http(&new_account, directory, None, http)
            .await
            .map_err(|e| format!("ACME account (pebble): {e}"))?
    } else {
        Account::create(&new_account, directory, None)
            .await
            .map_err(|e| format!("ACME account: {e}"))?
    };

    if let Ok(json) = serde_json::to_string_pretty(&creds) {
        let _ = std::fs::write(&paths.account_path, json);
    }

    let identifiers: Vec<Identifier> = cfg
        .domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await
        .map_err(|e| format!("ACME new_order: {e}"))?;

    let authorizations = order
        .authorizations()
        .await
        .map_err(|e| format!("ACME authorizations: {e}"))?;

    for authz in &authorizations {
        let Identifier::Dns(domain) = &authz.identifier;
        let domain = domain.clone();
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or_else(|| format!("no DNS-01 challenge for {domain}"))?;
        let key_auth = order.key_authorization(challenge);
        let dns_value = key_auth.dns_value();
        dns.present(&domain, &dns_value)
            .await
            .map_err(|e| format!("dns present: {e}"))?;
        order
            .set_challenge_ready(&challenge.url)
            .await
            .map_err(|e| format!("set_challenge_ready: {e}"))?;
    }

    // Poll until ready (Pebble with ALWAYS_VALID is fast).
    let mut delay = Duration::from_millis(250);
    for _ in 0..40 {
        tokio::time::sleep(delay).await;
        let state = order
            .refresh()
            .await
            .map_err(|e| format!("order refresh: {e}"))?;
        match state.status {
            OrderStatus::Ready => break,
            OrderStatus::Invalid => {
                return Err("ACME order became invalid".into());
            }
            _ => {
                delay = (delay * 2).min(Duration::from_secs(2));
            }
        }
    }
    let status = order.state().status;
    if status != OrderStatus::Ready {
        return Err(format!("ACME order not ready (status={status:?})"));
    }

    // CSR via rcgen
    let mut params =
        rcgen::CertificateParams::new(cfg.domains.clone()).map_err(|e| e.to_string())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key_pair = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| format!("CSR: {e}"))?;
    order
        .finalize(csr.der().as_ref())
        .await
        .map_err(|e| format!("finalize: {e}"))?;

    let mut cert_pem = None;
    delay = Duration::from_millis(250);
    for _ in 0..40 {
        tokio::time::sleep(delay).await;
        match order.certificate().await {
            Ok(Some(chain)) => {
                cert_pem = Some(chain.into_bytes());
                break;
            }
            Ok(None) => {
                delay = (delay * 2).min(Duration::from_secs(2));
            }
            Err(e) => return Err(format!("certificate: {e}")),
        }
    }
    let cert_pem = cert_pem.ok_or_else(|| "ACME certificate not issued in time".to_string())?;
    let key_pem = key_pair.serialize_pem().into_bytes();

    for d in &cfg.domains {
        let _ = dns.cleanup(d).await;
    }

    Ok((cert_pem, key_pem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::FileDnsProvider;
    use tempfile::tempdir;

    #[tokio::test]
    async fn self_signed_hot_swap() {
        let dir = tempdir().unwrap();
        let paths = AcmePaths::new(dir.path());
        let cfg = AcmeConfig {
            domains: vec!["localhost".into()],
            ..Default::default()
        };
        let dns = Box::new(FileDnsProvider::new(dir.path().join("dns.txt")));
        let (cert, key) = crate::tls::generate_self_signed("localhost").unwrap();
        let sc = server_config_from_pem(&cert, &key).unwrap();
        let tls = TlsState::new(sc);
        let mgr = AcmeManager::new(cfg, paths, dns, Some(tls));
        mgr.install_self_signed_for_domains().await.unwrap();
        assert!(mgr.paths.cert_path.exists());
    }

    #[tokio::test]
    async fn failed_order_keeps_existing_cert() {
        let dir = tempdir().unwrap();
        let paths = AcmePaths::new(dir.path());
        let cfg = AcmeConfig {
            domains: vec!["localhost".into()],
            directory: "https://127.0.0.1:1/dir".into(), // unreachable
            ..Default::default()
        };
        let dns = Box::new(FileDnsProvider::new(dir.path().join("dns.txt")));
        let (cert, key) = crate::tls::generate_self_signed("localhost").unwrap();
        persist_cert(&paths, &cert, &key).unwrap();
        let sc = server_config_from_pem(&cert, &key).unwrap();
        let tls = TlsState::new(sc);
        let mgr = AcmeManager::new(cfg, paths.clone(), dns, Some(tls));
        let _ = mgr.order_once().await;
        assert!(paths.cert_path.exists());
    }
}
