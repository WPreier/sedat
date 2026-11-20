//! Append-only JSONL audit sink (SIEM-friendly).
//!
//! Disabled by default (`logging.audit_jsonl` empty). Writes never block the
//! request path for long: a contended lock drops the event and increments
//! [`AuditSink::dropped`].

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{json, Value};
use tracing::warn;

use crate::config::SecurityChange;

/// Shared audit sink (cheap to clone).
#[derive(Clone, Debug)]
pub struct AuditSink {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    state: Mutex<SinkState>,
    dropped: AtomicU64,
}

#[derive(Debug, Default)]
struct SinkState {
    path: Option<PathBuf>,
    max_bytes: u64,
    file: Option<File>,
}

impl AuditSink {
    /// Disabled sink (no file writes).
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(SinkState::default()),
                dropped: AtomicU64::new(0),
            }),
        }
    }

    /// Open (or create) sink from config path. Empty path → disabled.
    pub fn open(path: &str, max_bytes: u64) -> std::io::Result<Self> {
        let sink = Self::disabled();
        sink.reconfigure(path, max_bytes)?;
        Ok(sink)
    }

    /// From logging config helpers.
    pub fn from_logging(audit_jsonl: &str, max_bytes: u64) -> std::io::Result<Self> {
        Self::open(audit_jsonl, max_bytes)
    }

    /// Events dropped because the sink lock was busy or I/O failed.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }

    /// Whether a path is currently configured.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.inner.state.lock().path.is_some()
    }

    /// Current path (if any).
    #[must_use]
    pub fn path(&self) -> Option<PathBuf> {
        self.inner.state.lock().path.clone()
    }

    /// Re-open / disable when config reloads. Empty `path` disables.
    pub fn reconfigure(&self, path: &str, max_bytes: u64) -> std::io::Result<()> {
        let mut st = self.inner.state.lock();
        st.max_bytes = max_bytes;
        let trimmed = path.trim();
        if trimmed.is_empty() {
            st.path = None;
            st.file = None;
            return Ok(());
        }
        let p = PathBuf::from(trimmed);
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let file = open_append(&p)?;
        st.path = Some(p);
        st.file = Some(file);
        Ok(())
    }

    /// Emit a structured event as one JSON line. Never panics; may drop.
    pub fn emit(&self, mut fields: Value) {
        if !fields.is_object() {
            return;
        }
        if let Some(obj) = fields.as_object_mut() {
            obj.entry("ts".to_string())
                .or_insert_with(|| json!(rfc3339_now()));
            obj.entry("v".to_string()).or_insert_with(|| json!(1));
        }
        let Ok(line) = serde_json::to_string(&fields) else {
            self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Some(mut guard) = self.inner.state.try_lock() else {
            self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if guard.path.is_none() {
            return;
        }
        if let Err(e) = write_line(&mut guard, &line) {
            self.inner.dropped.fetch_add(1, Ordering::Relaxed);
            warn!(error = %e, "audit jsonl write failed");
        }
    }

    /// Config reload security-diff audit (no request_id).
    pub fn emit_config_reload(&self, changes: &[SecurityChange], summary: &str) {
        let changes_json: Vec<Value> = changes
            .iter()
            .map(|c| {
                json!({
                    "key": c.key,
                    "old": c.old,
                    "new": c.new,
                })
            })
            .collect();
        self.emit(json!({
            "event": "config_reload",
            "request_id": Value::Null,
            "peer": Value::Null,
            "summary": summary,
            "changes": changes_json,
        }));
    }

    /// Proxy denial / security hygiene event (includes `request_id` when present).
    pub fn emit_proxy_deny(
        &self,
        reason: &str,
        status: u16,
        peer: &str,
        request_id: Option<&str>,
        host: Option<&str>,
        path: Option<&str>,
    ) {
        self.emit(json!({
            "event": "proxy_deny",
            "reason": reason,
            "status": status,
            "peer": peer,
            "request_id": request_id,
            "host": host,
            "path": path,
        }));
    }

    /// Process start marker.
    pub fn emit_startup(&self, version: &str) {
        self.emit(json!({
            "event": "startup",
            "request_id": Value::Null,
            "peer": Value::Null,
            "version": version,
        }));
    }

    /// Temporary IP ban applied after consecutive rate-limit strikes.
    pub fn emit_ip_ban(
        &self,
        peer: &str,
        request_id: Option<&str>,
        duration_secs: u64,
        strikes: u32,
    ) {
        self.emit(json!({
            "event": "ip_ban",
            "peer": peer,
            "request_id": request_id,
            "duration_secs": duration_secs,
            "strikes": strikes,
        }));
    }

    /// Temporary IP ban expired (cleared on next request after TTL).
    pub fn emit_ip_unban(&self, peer: &str, request_id: Option<&str>) {
        self.emit(json!({
            "event": "ip_unban",
            "peer": peer,
            "request_id": request_id,
        }));
    }
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn write_line(st: &mut SinkState, line: &str) -> std::io::Result<()> {
    let path = st.path.clone().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "audit path unset")
    })?;
    if st.max_bytes > 0 {
        if let Ok(meta) = fs::metadata(&path) {
            if meta.len() >= st.max_bytes {
                st.file = None;
                let rotated = path.with_extension("jsonl.1");
                let _ = fs::remove_file(&rotated);
                fs::rename(&path, &rotated)?;
                st.file = Some(open_append(&path)?);
            }
        }
    }
    if st.file.is_none() {
        st.file = Some(open_append(&path)?);
    }
    let file = st.file.as_mut().expect("file just opened");
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

/// Validate that `audit_jsonl` is empty or a plausible filesystem path (no NUL).
#[must_use]
pub fn valid_audit_path(path: &str) -> bool {
    let t = path.trim();
    if t.is_empty() {
        return true;
    }
    if t.contains('\0') || t.len() > 512 {
        return false;
    }
    // Reject obvious URL schemes — audit is a local file only.
    if t.contains("://") {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecurityChange;

    #[test]
    fn disabled_emits_nothing() {
        let s = AuditSink::disabled();
        s.emit_proxy_deny("rate_limit", 429, "127.0.0.1:1", Some("abc"), None, None);
        assert!(!s.enabled());
        assert_eq!(s.dropped(), 0);
    }

    #[test]
    fn writes_jsonl_with_request_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let s = AuditSink::open(path.to_str().unwrap(), 0).unwrap();
        s.emit_proxy_deny(
            "smuggling",
            400,
            "10.0.0.1:9",
            Some("req-42"),
            Some("localhost"),
            Some("/x"),
        );
        let text = fs::read_to_string(&path).unwrap();
        let line = text.lines().next().unwrap();
        let v: Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["event"], "proxy_deny");
        assert_eq!(v["request_id"], "req-42");
        assert_eq!(v["reason"], "smuggling");
        assert_eq!(v["status"], 400);
        assert!(v.get("ts").is_some());
        assert_eq!(v["v"], 1);
    }

    #[test]
    fn config_reload_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let s = AuditSink::open(path.to_str().unwrap(), 0).unwrap();
        let changes = vec![SecurityChange {
            key: "proxy_protocol.inbound_enabled".into(),
            old: "false".into(),
            new: "true".into(),
        }];
        s.emit_config_reload(&changes, "proxy_protocol.inbound_enabled: \"false\" → \"true\"");
        let text = fs::read_to_string(&path).unwrap();
        let v: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(v["event"], "config_reload");
        assert!(v["request_id"].is_null());
        assert_eq!(v["changes"][0]["key"], "proxy_protocol.inbound_enabled");
    }

    #[test]
    fn rotates_when_max_bytes_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let s = AuditSink::open(path.to_str().unwrap(), 80).unwrap();
        for i in 0..20 {
            s.emit_proxy_deny(
                "rate_limit",
                429,
                "127.0.0.1:1",
                Some(&format!("id-{i}")),
                None,
                None,
            );
        }
        assert!(path.exists());
        let rotated = path.with_extension("jsonl.1");
        assert!(
            rotated.exists(),
            "expected rotation to {}",
            rotated.display()
        );
    }

    #[test]
    fn path_validation() {
        assert!(valid_audit_path(""));
        assert!(valid_audit_path("./state/audit.jsonl"));
        assert!(!valid_audit_path("https://evil.example/x"));
        assert!(!valid_audit_path("a\0b"));
    }
}
