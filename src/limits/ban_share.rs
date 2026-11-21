//! File-backed shared ban state across SeDat replicas (P12.6).
//!
//! **Design choice:** atomic JSON map on a shared filesystem path (Docker volume /
//! NFS), not Redis/etcd/UDP gossip. Reasons: single-binary friendly, trivial to
//! test with a bind-mount, no extra services, fail-closed integrity via HMAC.
//!
//! Conflict policy:
//! - Active bans: **max `until_ms` wins**
//! - Unban: tombstone (`until_ms = 0`); last write clears the local ban on pull

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::config::LimitsConfig;

/// Env override for the share HMAC secret (wins over config / secret file).
pub const BAN_SHARE_SECRET_ENV: &str = "SEDAT_BAN_SHARE_SECRET";

/// On-disk document version.
const DOC_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BanShareDoc {
    v: u32,
    /// IP string → record (BTreeMap for stable MAC input).
    bans: BTreeMap<String, BanShareRec>,
    /// Hex-encoded HMAC-SHA256 over canonical payload (no `mac` field).
    mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BanShareRec {
    /// Unix epoch milliseconds; `0` = unban tombstone.
    until_ms: u64,
    /// Last update time (ms) for tombstone ordering.
    updated_ms: u64,
}

/// Shared ban file store (cheap to clone via [`Arc`]).
#[derive(Debug)]
pub struct BanShareStore {
    path: PathBuf,
    secret: Vec<u8>,
    poll_secs: u64,
    last_pull_ms: AtomicU64,
    /// Serialize read-modify-write.
    write_lock: Mutex<()>,
}

/// One pulled record for the limiter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedBanView {
    /// Banned client.
    pub ip: IpAddr,
    /// Absolute expiry, or `None` if tombstone (unban).
    pub until: Option<SystemTime>,
}

impl BanShareStore {
    /// Build from limits config. `Ok(None)` when path empty (disabled).
    ///
    /// Fail-closed: non-empty path requires a non-empty secret
    /// (`SEDAT_BAN_SHARE_SECRET` → `ban_share_secret_file` → `ban_share_secret`).
    pub fn try_from_limits(limits: &LimitsConfig) -> Result<Option<Arc<Self>>, String> {
        let path = limits.ban_share_path.trim();
        if path.is_empty() {
            return Ok(None);
        }
        let secret = resolve_share_secret(limits)?;
        if secret.is_empty() {
            return Err(
                "limits.ban_share_path set but share secret empty (set SEDAT_BAN_SHARE_SECRET, ban_share_secret_file, or ban_share_secret)"
                    .into(),
            );
        }
        let poll = if limits.ban_share_poll_secs == 0 {
            1
        } else {
            limits.ban_share_poll_secs
        };
        let store = Arc::new(Self {
            path: PathBuf::from(path),
            secret: secret.into_bytes(),
            poll_secs: poll,
            last_pull_ms: AtomicU64::new(0),
            write_lock: Mutex::new(()),
        });
        if let Some(parent) = store.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| format!("ban_share_path parent: {e}"))?;
            }
        }
        Ok(Some(store))
    }

    /// Shared file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether a pull is due.
    #[must_use]
    pub fn should_pull(&self) -> bool {
        let last = self.last_pull_ms.load(Ordering::Relaxed);
        let now = unix_now_ms();
        now.saturating_sub(last) >= self.poll_secs.saturating_mul(1000)
    }

    /// Mark pull time (call after successful pull).
    pub fn mark_pulled(&self) {
        self.last_pull_ms.store(unix_now_ms(), Ordering::Relaxed);
    }

    /// Upsert an active ban (`until`); conflict = max expiry.
    pub fn publish_ban(&self, ip: IpAddr, until: SystemTime) -> std::io::Result<()> {
        let until_ms = system_to_ms(until);
        let now = unix_now_ms();
        self.with_doc(|doc| {
            let key = ip.to_string();
            let ent = doc.bans.entry(key).or_insert(BanShareRec {
                until_ms: 0,
                updated_ms: 0,
            });
            if until_ms >= ent.until_ms {
                ent.until_ms = until_ms;
            }
            ent.updated_ms = now;
        })
    }

    /// Publish an unban tombstone.
    pub fn publish_unban(&self, ip: IpAddr) -> std::io::Result<()> {
        let now = unix_now_ms();
        self.with_doc(|doc| {
            doc.bans.insert(
                ip.to_string(),
                BanShareRec {
                    until_ms: 0,
                    updated_ms: now,
                },
            );
        })
    }

    /// Load and verify all records (fail-closed on bad MAC).
    pub fn pull(&self) -> std::io::Result<Vec<SharedBanView>> {
        let doc = match self.load_doc() {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.mark_pulled();
                return Ok(Vec::new());
            }
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for (ip_s, rec) in &doc.bans {
            let Ok(ip) = ip_s.parse::<IpAddr>() else {
                continue;
            };
            if rec.until_ms == 0 {
                out.push(SharedBanView { ip, until: None });
            } else {
                out.push(SharedBanView {
                    ip,
                    until: Some(ms_to_system(rec.until_ms)),
                });
            }
        }
        self.mark_pulled();
        Ok(out)
    }

    fn with_doc(&self, f: impl FnOnce(&mut BanShareDoc)) -> std::io::Result<()> {
        let _guard = self.write_lock.lock();
        let mut doc = match self.load_doc() {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BanShareDoc {
                v: DOC_VERSION,
                bans: BTreeMap::new(),
                mac: String::new(),
            },
            Err(e) => {
                // Fail-closed: do not clobber a file we cannot authenticate.
                warn!(error = %e, path = %self.path.display(), "ban share load failed");
                return Err(e);
            }
        };
        f(&mut doc);
        self.store_doc(&doc)
    }

    fn load_doc(&self) -> std::io::Result<BanShareDoc> {
        let mut f = File::open(&self.path)?;
        let mut buf = String::new();
        f.read_to_string(&mut buf)?;
        let doc: BanShareDoc = serde_json::from_str(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if doc.v != DOC_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported ban share version {}", doc.v),
            ));
        }
        let expected = mac_hex(&self.secret, &canonical_payload(&doc));
        if !constant_time_eq(expected.as_bytes(), doc.mac.as_bytes()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "ban share HMAC mismatch (fail-closed)",
            ));
        }
        Ok(doc)
    }

    fn store_doc(&self, doc: &BanShareDoc) -> std::io::Result<()> {
        let mut out = BanShareDoc {
            v: DOC_VERSION,
            bans: doc.bans.clone(),
            mac: String::new(),
        };
        out.mac = mac_hex(&self.secret, &canonical_payload(&out));
        let json = serde_json::to_vec_pretty(&out)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&json)?;
            f.write_all(b"\n")?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

fn resolve_share_secret(limits: &LimitsConfig) -> Result<String, String> {
    if let Ok(v) = std::env::var(BAN_SHARE_SECRET_ENV) {
        let t = v.trim();
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }
    let file = limits.ban_share_secret_file.trim();
    if !file.is_empty() {
        let contents =
            fs::read_to_string(file).map_err(|e| format!("ban_share_secret_file `{file}`: {e}"))?;
        let t = contents.trim();
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }
    Ok(limits.ban_share_secret.trim().to_string())
}

fn canonical_payload(doc: &BanShareDoc) -> Vec<u8> {
    // Stable JSON without mac.
    let body = serde_json::json!({
        "v": doc.v,
        "bans": doc.bans,
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

fn mac_hex(secret: &[u8], msg: &[u8]) -> String {
    hex::encode(hmac_sha256(secret, msg))
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let dig = Sha256::digest(key);
        key_block[..32].copy_from_slice(&dig);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner.finalize());
    let out = outer.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn system_to_ms(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn ms_to_system(ms: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms)
}

/// Convert a future/past [`SystemTime`] into a related [`Instant`].
#[must_use]
pub fn system_to_instant(t: SystemTime) -> Instant {
    let now_s = SystemTime::now();
    let now_i = Instant::now();
    match t.duration_since(now_s) {
        Ok(d) => now_i + d,
        Err(e) => now_i.checked_sub(e.duration()).unwrap_or(now_i),
    }
}

/// Convert [`Instant`] deadline to [`SystemTime`] (approximate).
#[must_use]
pub fn instant_to_system(until: Instant) -> SystemTime {
    let now_i = Instant::now();
    let now_s = SystemTime::now();
    if until > now_i {
        now_s + until.duration_since(now_i)
    } else {
        now_s
            .checked_sub(now_i.duration_since(until))
            .unwrap_or(now_s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits_for(path: &Path, secret: &str) -> LimitsConfig {
        LimitsConfig {
            ban_share_path: path.to_string_lossy().into(),
            ban_share_secret: secret.into(),
            ban_share_poll_secs: 1,
            ..Default::default()
        }
    }

    #[test]
    fn disabled_when_path_empty() {
        let lim = LimitsConfig::default();
        assert!(BanShareStore::try_from_limits(&lim).unwrap().is_none());
    }

    #[test]
    fn path_without_secret_fails_closed() {
        let lim = LimitsConfig {
            ban_share_path: "/tmp/bans.json".into(),
            ban_share_secret: String::new(),
            ..Default::default()
        };
        std::env::remove_var(BAN_SHARE_SECRET_ENV);
        let err = BanShareStore::try_from_limits(&lim).unwrap_err();
        assert!(err.contains("secret"), "{err}");
    }

    #[test]
    fn max_expiry_and_unban_roundtrip() {
        std::env::remove_var(BAN_SHARE_SECRET_ENV);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared_bans.json");
        let store = BanShareStore::try_from_limits(&limits_for(&path, "test-secret-32b-minimum!!"))
            .unwrap()
            .unwrap();

        let ip: IpAddr = "203.0.113.50".parse().unwrap();
        let soon = SystemTime::now() + Duration::from_secs(30);
        let later = SystemTime::now() + Duration::from_secs(120);
        store.publish_ban(ip, soon).unwrap();
        store.publish_ban(ip, later).unwrap();

        let views = store.pull().unwrap();
        let v = views.iter().find(|v| v.ip == ip).unwrap();
        let until = v.until.unwrap();
        assert!(until >= later - Duration::from_secs(1));

        store.publish_unban(ip).unwrap();
        let views = store.pull().unwrap();
        let v = views.iter().find(|v| v.ip == ip).unwrap();
        assert!(v.until.is_none());
    }

    #[test]
    fn bad_mac_rejected() {
        std::env::remove_var(BAN_SHARE_SECRET_ENV);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared_bans.json");
        let store = BanShareStore::try_from_limits(&limits_for(&path, "secret-a-aaaaaaaaaaaa"))
            .unwrap()
            .unwrap();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        store
            .publish_ban(ip, SystemTime::now() + Duration::from_secs(10))
            .unwrap();

        let store_b = BanShareStore::try_from_limits(&limits_for(&path, "secret-b-bbbbbbbbbbbb"))
            .unwrap()
            .unwrap();
        let err = store_b.pull().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn two_stores_share_max_expiry() {
        std::env::remove_var(BAN_SHARE_SECRET_ENV);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared_bans.json");
        let secret = "shared-replica-secret-ok!!";
        let a = BanShareStore::try_from_limits(&limits_for(&path, secret))
            .unwrap()
            .unwrap();
        let b = BanShareStore::try_from_limits(&limits_for(&path, secret))
            .unwrap()
            .unwrap();

        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        a.publish_ban(ip, SystemTime::now() + Duration::from_secs(40))
            .unwrap();
        b.publish_ban(ip, SystemTime::now() + Duration::from_secs(90))
            .unwrap();

        let views = a.pull().unwrap();
        let until = views.iter().find(|v| v.ip == ip).unwrap().until.unwrap();
        let remaining = until
            .duration_since(SystemTime::now())
            .unwrap_or_default()
            .as_secs();
        assert!(
            remaining > 60,
            "expected max expiry retained, got {remaining}s"
        );
    }
}
