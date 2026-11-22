//! Append-only JSONL audit sink (SIEM-friendly).
//!
//! Disabled by default (`logging.audit_jsonl` empty). Writes never block the
//! request path for long: a contended lock drops the event and increments
//! [`AuditSink::dropped`].
//!
//! Rotation (either trigger renames the active file to `*.jsonl.1`):
//! - **size** — `audit_jsonl_max_bytes` (`0` = off)
//! - **age** — `audit_jsonl_max_age_secs` (`0` = off; P12.4)

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use parking_lot::Mutex;
use serde_json::{json, Value};
use tracing::warn;

use crate::config::SecurityChange;

/// Stable Prometheus label set for HTTP-path `proxy_deny` reasons (P17.2).
///
/// Always emitted as `sedat_proxy_deny_total{reason="…"}` (fixed cardinality).
/// Unknown reasons map to `"other"`.
pub const PROXY_DENY_REASONS: &[&str] = &[
    "rate_limit",
    "ip_banned",
    "smuggling",
    "header_bomb",
    "absolute_uri_host_mismatch",
    "path_traversal",
    "missing_host",
    "sni_host_mismatch",
    "unknown_host_or_path",
    "body_too_large",
    "upstream_ip_pin",
    "upstream_error",
    "other",
];

const PROXY_DENY_REASON_COUNT: usize = 13;

const _: () = assert!(PROXY_DENY_REASONS.len() == PROXY_DENY_REASON_COUNT);

/// Stable Prometheus reason labels for pre-HTTP PROXY rejects (P17.3).
pub const PROXY_REJECT_REASONS: &[&str] = &[
    "untrusted_or_disabled",
    "plaintext_when_after_tls",
    "malformed",
    "other",
];

/// Stable Prometheus stage labels for pre-HTTP PROXY rejects (P17.3).
pub const PROXY_REJECT_STAGES: &[&str] = &["plaintext", "after_tls", "other"];

const PROXY_REJECT_REASON_COUNT: usize = 4;
const PROXY_REJECT_STAGE_COUNT: usize = 3;
const PROXY_REJECT_SERIES: usize = PROXY_REJECT_REASON_COUNT * PROXY_REJECT_STAGE_COUNT;

const _: () = assert!(PROXY_REJECT_REASONS.len() == PROXY_REJECT_REASON_COUNT);
const _: () = assert!(PROXY_REJECT_STAGES.len() == PROXY_REJECT_STAGE_COUNT);

/// Shared audit sink (cheap to clone).
#[derive(Clone, Debug)]
pub struct AuditSink {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    state: Mutex<SinkState>,
    dropped: AtomicU64,
    /// Per-reason HTTP-path security denial counts (even when JSONL is disabled).
    proxy_deny: [AtomicU64; PROXY_DENY_REASON_COUNT],
    /// Per-(reason,stage) inbound PROXY reject counts (P17.3).
    proxy_reject: [AtomicU64; PROXY_REJECT_SERIES],
}

fn proxy_deny_index(reason: &str) -> usize {
    PROXY_DENY_REASONS
        .iter()
        .position(|&r| r == reason)
        .unwrap_or(PROXY_DENY_REASON_COUNT - 1)
}

fn proxy_reject_index(reason: &str, stage: &str) -> usize {
    let ri = PROXY_REJECT_REASONS
        .iter()
        .position(|&r| r == reason)
        .unwrap_or(PROXY_REJECT_REASON_COUNT - 1);
    let si = PROXY_REJECT_STAGES
        .iter()
        .position(|&s| s == stage)
        .unwrap_or(PROXY_REJECT_STAGE_COUNT - 1);
    ri * PROXY_REJECT_STAGE_COUNT + si
}

#[derive(Debug, Default)]
struct SinkState {
    path: Option<PathBuf>,
    max_bytes: u64,
    /// Rotate when the current segment is at least this old (`0` = disabled).
    max_age_secs: u64,
    /// Start of the current file segment (for age rotation).
    segment_started: Option<SystemTime>,
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
                proxy_deny: std::array::from_fn(|_| AtomicU64::new(0)),
                proxy_reject: std::array::from_fn(|_| AtomicU64::new(0)),
            }),
        }
    }

    /// Open (or create) sink from config path. Empty path → disabled.
    ///
    /// `max_bytes` / `max_age_secs`: `0` disables that rotation trigger.
    pub fn open(path: &str, max_bytes: u64, max_age_secs: u64) -> std::io::Result<Self> {
        let sink = Self::disabled();
        sink.reconfigure(path, max_bytes, max_age_secs)?;
        Ok(sink)
    }

    /// From logging config helpers.
    pub fn from_logging(
        audit_jsonl: &str,
        max_bytes: u64,
        max_age_secs: u64,
    ) -> std::io::Result<Self> {
        Self::open(audit_jsonl, max_bytes, max_age_secs)
    }

    /// Events dropped because the sink lock was busy or I/O failed.
    ///
    /// Exposed as Prometheus counter `sedat_audit_dropped_total` (admin/metrics).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.inner.dropped.load(Ordering::Relaxed)
    }

    /// Per-reason `proxy_deny` counts for Prometheus (P17.2; fixed cardinality).
    #[must_use]
    pub fn proxy_deny_gauges(&self) -> Vec<(&'static str, u64)> {
        PROXY_DENY_REASONS
            .iter()
            .enumerate()
            .map(|(i, &reason)| {
                (
                    reason,
                    self.inner.proxy_deny[i].load(Ordering::Relaxed),
                )
            })
            .collect()
    }

    /// Count for one reason label (unknown → `"other"` bucket).
    #[must_use]
    pub fn proxy_deny_count(&self, reason: &str) -> u64 {
        let i = proxy_deny_index(reason);
        self.inner.proxy_deny[i].load(Ordering::Relaxed)
    }

    fn record_proxy_deny(&self, reason: &str) {
        let i = proxy_deny_index(reason);
        self.inner.proxy_deny[i].fetch_add(1, Ordering::Relaxed);
    }

    /// Per-(reason,stage) `proxy_reject` counts for Prometheus (P17.3).
    #[must_use]
    pub fn proxy_reject_gauges(&self) -> Vec<(&'static str, &'static str, u64)> {
        let mut out = Vec::with_capacity(PROXY_REJECT_SERIES);
        for (ri, &reason) in PROXY_REJECT_REASONS.iter().enumerate() {
            for (si, &stage) in PROXY_REJECT_STAGES.iter().enumerate() {
                let i = ri * PROXY_REJECT_STAGE_COUNT + si;
                out.push((
                    reason,
                    stage,
                    self.inner.proxy_reject[i].load(Ordering::Relaxed),
                ));
            }
        }
        out
    }

    /// Count for one reject reason/stage pair (unknown → `"other"` buckets).
    #[must_use]
    pub fn proxy_reject_count(&self, reason: &str, stage: &str) -> u64 {
        let i = proxy_reject_index(reason, stage);
        self.inner.proxy_reject[i].load(Ordering::Relaxed)
    }

    fn record_proxy_reject(&self, reason: &str, stage: &str) {
        let i = proxy_reject_index(reason, stage);
        self.inner.proxy_reject[i].fetch_add(1, Ordering::Relaxed);
    }

    /// Hold the sink lock while `f` runs (unit tests: force try_lock drops).
    #[cfg(test)]
    pub fn with_lock_held_for_test<R>(&self, f: impl FnOnce() -> R) -> R {
        let _guard = self.inner.state.lock();
        f()
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
    pub fn reconfigure(
        &self,
        path: &str,
        max_bytes: u64,
        max_age_secs: u64,
    ) -> std::io::Result<()> {
        let mut st = self.inner.state.lock();
        st.max_bytes = max_bytes;
        st.max_age_secs = max_age_secs;
        let trimmed = path.trim();
        if trimmed.is_empty() {
            st.path = None;
            st.file = None;
            st.segment_started = None;
            return Ok(());
        }
        let p = PathBuf::from(trimmed);
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let started = segment_start_for_path(&p);
        let file = open_append(&p)?;
        st.path = Some(p);
        st.file = Some(file);
        st.segment_started = Some(started);
        Ok(())
    }

    /// Backdate the current segment start (unit tests for age rotation).
    #[cfg(test)]
    pub fn set_segment_started_for_test(&self, started: SystemTime) {
        self.inner.state.lock().segment_started = Some(started);
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
    ///
    /// `restart_required` lists boot-bound keys that still need a process restart
    /// after this successful reload (P16.2; empty when none).
    pub fn emit_config_reload(
        &self,
        changes: &[SecurityChange],
        summary: &str,
        restart_required: &[&str],
    ) {
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
            "restart_required": restart_required,
        }));
    }

    /// Proxy denial / security hygiene event (includes `request_id` when present).
    ///
    /// Always increments Prometheus `sedat_proxy_deny_total{reason=…}` even when
    /// JSONL audit is disabled (P17.2).
    pub fn emit_proxy_deny(
        &self,
        reason: &str,
        status: u16,
        peer: &str,
        request_id: Option<&str>,
        host: Option<&str>,
        path: Option<&str>,
    ) {
        self.record_proxy_deny(reason);
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

    /// Inbound PROXY framing rejected before HTTP (no request_id; connection dropped).
    ///
    /// `stage` is `plaintext` or `after_tls`. `reason` uses [`crate::proxy::ProxyRejectReason::as_str`].
    /// Always increments Prometheus `sedat_proxy_reject_total{reason,stage}` (P17.3).
    pub fn emit_proxy_reject(&self, peer: &str, reason: &str, stage: &str) {
        self.record_proxy_reject(reason, stage);
        self.emit(json!({
            "event": "proxy_reject",
            "request_id": Value::Null,
            "peer": peer,
            "reason": reason,
            "stage": stage,
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

    /// Ban TTL refreshed because the IP kept hitting while banned (P12.2).
    pub fn emit_ip_ban_extend(
        &self,
        peer: &str,
        request_id: Option<&str>,
        duration_secs: u64,
        previous_remaining_secs: u64,
    ) {
        self.emit(json!({
            "event": "ip_ban_extend",
            "peer": peer,
            "request_id": request_id,
            "duration_secs": duration_secs,
            "previous_remaining_secs": previous_remaining_secs,
        }));
    }

    /// Admin socket manually cleared a temporary IP ban (`unban <ip>`).
    pub fn emit_admin_unban(&self, peer: &str) {
        self.emit(json!({
            "event": "admin_unban",
            "request_id": Value::Null,
            "peer": peer,
            "source": "admin",
        }));
    }

    /// Failed admin socket authentication (token required / wrong token).
    /// Never includes the presented secret.
    pub fn emit_admin_auth_fail(&self, reason: &str) {
        self.emit(json!({
            "event": "admin_auth_fail",
            "request_id": Value::Null,
            "peer": Value::Null,
            "reason": reason,
        }));
    }

    /// Admin token live reload / rotate (P12.3). Never includes secret material.
    pub fn emit_admin_token_reload(&self, outcome: &str, overlap_secs: Option<u64>) {
        self.emit(json!({
            "event": "admin_token_reload",
            "request_id": Value::Null,
            "peer": Value::Null,
            "outcome": outcome,
            "overlap_secs": overlap_secs,
        }));
    }

    /// Failed metrics-sidecar Bearer authentication (P12.1).
    /// Never includes the presented secret.
    pub fn emit_metrics_auth_fail(&self, reason: &str) {
        self.emit(json!({
            "event": "metrics_auth_fail",
            "request_id": Value::Null,
            "peer": Value::Null,
            "reason": reason,
        }));
    }

    /// Admin `selftest` result summary (optional ops audit).
    pub fn emit_admin_selftest(&self, ok: bool, failed: &[String]) {
        self.emit(json!({
            "event": "admin_selftest",
            "request_id": Value::Null,
            "peer": Value::Null,
            "ok": ok,
            "failed": failed,
        }));
    }
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// Prefer birth time when available; else modified-at-open; else now.
fn segment_start_for_path(path: &Path) -> SystemTime {
    match fs::metadata(path) {
        Ok(meta) => meta
            .created()
            .or_else(|_| meta.modified())
            .unwrap_or_else(|_| SystemTime::now()),
        Err(_) => SystemTime::now(),
    }
}

fn needs_age_rotate(st: &SinkState) -> bool {
    if st.max_age_secs == 0 {
        return false;
    }
    let Some(started) = st.segment_started else {
        return false;
    };
    match SystemTime::now().duration_since(started) {
        Ok(age) => age >= Duration::from_secs(st.max_age_secs),
        Err(_) => false,
    }
}

fn needs_size_rotate(st: &SinkState, path: &Path) -> bool {
    if st.max_bytes == 0 {
        return false;
    }
    fs::metadata(path)
        .map(|m| m.len() >= st.max_bytes)
        .unwrap_or(false)
}

fn rotate_file(st: &mut SinkState, path: &Path) -> std::io::Result<()> {
    st.file = None;
    let rotated = path.with_extension("jsonl.1");
    let _ = fs::remove_file(&rotated);
    if path.exists() {
        fs::rename(path, &rotated)?;
    }
    st.file = Some(open_append(path)?);
    st.segment_started = Some(SystemTime::now());
    Ok(())
}

fn write_line(st: &mut SinkState, line: &str) -> std::io::Result<()> {
    let path = st
        .path
        .clone()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "audit path unset"))?;
    if needs_size_rotate(st, &path) || needs_age_rotate(st) {
        rotate_file(st, &path)?;
    }
    if st.file.is_none() {
        st.file = Some(open_append(&path)?);
        if st.segment_started.is_none() {
            st.segment_started = Some(SystemTime::now());
        }
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
        // Counters still advance when JSONL is off (P17.2).
        assert_eq!(s.proxy_deny_count("rate_limit"), 1);
    }

    #[test]
    fn proxy_deny_counters_fixed_cardinality() {
        let s = AuditSink::disabled();
        assert_eq!(s.proxy_deny_gauges().len(), PROXY_DENY_REASONS.len());
        assert!(s.proxy_deny_gauges().iter().all(|(_, v)| *v == 0));

        s.emit_proxy_deny("smuggling", 400, "127.0.0.1:1", None, None, None);
        s.emit_proxy_deny("smuggling", 400, "127.0.0.1:2", None, None, None);
        s.emit_proxy_deny("not_a_real_reason", 500, "127.0.0.1:3", None, None, None);

        assert_eq!(s.proxy_deny_count("smuggling"), 2);
        assert_eq!(s.proxy_deny_count("other"), 1);
        assert_eq!(s.proxy_deny_count("rate_limit"), 0);
        let gauges = s.proxy_deny_gauges();
        assert_eq!(gauges.len(), PROXY_DENY_REASONS.len());
        assert_eq!(
            gauges.iter().find(|(r, _)| *r == "smuggling").unwrap().1,
            2
        );
        assert_eq!(gauges.iter().find(|(r, _)| *r == "other").unwrap().1, 1);
    }

    #[test]
    fn writes_proxy_reject() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.jsonl");
        let s = AuditSink::open(path.to_str().unwrap(), 0, 0).unwrap();
        s.emit_proxy_reject("127.0.0.1:9", "untrusted_or_disabled", "plaintext");
        let text = std::fs::read_to_string(&path).unwrap();
        let v: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(v["event"], "proxy_reject");
        assert_eq!(v["reason"], "untrusted_or_disabled");
        assert_eq!(v["stage"], "plaintext");
        assert!(v["request_id"].is_null());
        assert_eq!(s.proxy_reject_count("untrusted_or_disabled", "plaintext"), 1);
    }

    #[test]
    fn proxy_reject_counters_fixed_cardinality() {
        let s = AuditSink::disabled();
        assert_eq!(s.proxy_reject_gauges().len(), PROXY_REJECT_SERIES);
        assert!(s.proxy_reject_gauges().iter().all(|(_, _, v)| *v == 0));

        s.emit_proxy_reject("127.0.0.1:1", "malformed", "after_tls");
        s.emit_proxy_reject("127.0.0.1:2", "malformed", "after_tls");
        s.emit_proxy_reject("127.0.0.1:3", "weird", "plaintext");

        assert_eq!(s.proxy_reject_count("malformed", "after_tls"), 2);
        assert_eq!(s.proxy_reject_count("other", "plaintext"), 1);
        assert_eq!(s.proxy_reject_count("untrusted_or_disabled", "plaintext"), 0);
    }

    #[test]
    fn writes_jsonl_with_request_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let s = AuditSink::open(path.to_str().unwrap(), 0, 0).unwrap();
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
        let s = AuditSink::open(path.to_str().unwrap(), 0, 0).unwrap();
        let changes = vec![SecurityChange {
            key: "proxy_protocol.inbound_enabled".into(),
            old: "false".into(),
            new: "true".into(),
        }];
        s.emit_config_reload(
            &changes,
            "proxy_protocol.inbound_enabled: \"false\" → \"true\"",
            &["server.listen", "hardening.seccomp"],
        );
        let text = fs::read_to_string(&path).unwrap();
        let v: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(v["event"], "config_reload");
        assert!(v["request_id"].is_null());
        assert_eq!(v["changes"][0]["key"], "proxy_protocol.inbound_enabled");
        assert_eq!(v["restart_required"][0], "server.listen");
        assert_eq!(v["restart_required"][1], "hardening.seccomp");
    }

    #[test]
    fn config_reload_empty_restart_required() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let s = AuditSink::open(path.to_str().unwrap(), 0, 0).unwrap();
        s.emit_config_reload(&[], "none", &[]);
        let text = fs::read_to_string(&path).unwrap();
        let v: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(v["event"], "config_reload");
        assert_eq!(v["restart_required"], json!([]));
    }

    #[test]
    fn rotates_when_max_bytes_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let s = AuditSink::open(path.to_str().unwrap(), 80, 0).unwrap();
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
    fn rotates_when_max_age_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let s = AuditSink::open(path.to_str().unwrap(), 0, 1).unwrap();
        s.emit_startup("age-1");
        assert!(path.exists());
        assert!(!path.with_extension("jsonl.1").exists());

        s.set_segment_started_for_test(SystemTime::now() - Duration::from_secs(2));
        s.emit_startup("age-2");

        let rotated = path.with_extension("jsonl.1");
        assert!(
            rotated.exists(),
            "expected age rotation to {}",
            rotated.display()
        );
        let fresh = fs::read_to_string(&path).unwrap();
        assert!(fresh.contains("age-2"), "{fresh}");
        let old = fs::read_to_string(&rotated).unwrap();
        assert!(old.contains("age-1"), "{old}");
    }

    #[test]
    fn path_validation() {
        assert!(valid_audit_path(""));
        assert!(valid_audit_path("./state/audit.jsonl"));
        assert!(!valid_audit_path("https://evil.example/x"));
        assert!(!valid_audit_path("a\0b"));
    }

    #[test]
    fn drops_when_lock_busy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let s = AuditSink::open(path.to_str().unwrap(), 0, 0).unwrap();
        let s2 = s.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            s2.with_lock_held_for_test(|| {
                ready_tx.send(()).unwrap();
                done_rx.recv().unwrap();
            });
        });
        ready_rx.recv().unwrap();
        let before = s.dropped();
        s.emit_startup("0.0.0-test");
        assert!(s.dropped() > before);
        done_tx.send(()).unwrap();
        t.join().unwrap();
    }
}
