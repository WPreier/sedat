//! Admin socket capability-token helpers (constant-time verify).

use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::config::SedatConfig;

/// Environment variable that overrides config / token file when non-empty.
pub const ADMIN_TOKEN_ENV: &str = "SEDAT_ADMIN_TOKEN";

/// Default dual-token overlap window (seconds) after a successful rotate.
pub const DEFAULT_TOKEN_OVERLAP_SECS: u64 = 300;

/// Resolve the expected admin token from env / file / config (no live cache).
///
/// Precedence (first non-empty wins):
/// 1. `SEDAT_ADMIN_TOKEN` environment variable
/// 2. Contents of `server.admin_token_file` (trimmed)
/// 3. `server.admin_token` config string
///
/// Empty result → token auth **disabled** (filesystem ACL only; fine for local
/// dev, not recommended alone in production).
///
/// Prefer [`LiveAdminTokens`] at runtime so rotation is fail-closed and can keep
/// a previous token during an overlap window.
#[must_use]
pub fn resolve_admin_token(cfg: &SedatConfig) -> Option<String> {
    if let Ok(v) = std::env::var(ADMIN_TOKEN_ENV) {
        let t = v.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    let file = cfg.server.admin_token_file.trim();
    if !file.is_empty() {
        if let Ok(contents) = std::fs::read_to_string(file) {
            let t = contents.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    let inline = cfg.server.admin_token.trim();
    if inline.is_empty() {
        None
    } else {
        Some(inline.to_string())
    }
}

/// Outcome of refreshing the live admin token from sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenReloadOutcome {
    /// Still no token configured.
    UnchangedEmpty,
    /// Same token as before.
    Unchanged,
    /// Auth newly enabled (was off).
    Enabled,
    /// Current token replaced; previous may remain valid for `overlap_secs`.
    Rotated {
        /// Overlap window applied (0 = hard cut).
        overlap_secs: u64,
    },
}

/// Fail-closed rejection when a reload would clear a configured token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenReloadWouldDisable;

impl std::fmt::Display for TokenReloadWouldDisable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("new token sources empty; refusing to disable admin auth (fail-closed)")
    }
}

#[derive(Debug, Clone)]
struct TokenSnapshot {
    current: Option<String>,
    previous: Option<String>,
    previous_until: Option<Instant>,
}

/// Live admin/metrics token gate with optional dual-token overlap (P12.3).
///
/// Updated via admin `reload-token` (or as part of config `reload`) — not on every
/// request — so a briefly empty/unreadable token file cannot silently open auth.
#[derive(Debug, Clone)]
pub struct LiveAdminTokens {
    inner: Arc<Mutex<TokenSnapshot>>,
}

impl LiveAdminTokens {
    /// Build from an already-resolved token (startup).
    #[must_use]
    pub fn new(initial: Option<String>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TokenSnapshot {
                current: initial,
                previous: None,
                previous_until: None,
            })),
        }
    }

    /// Resolve sources and construct (startup helper).
    #[must_use]
    pub fn from_config(cfg: &SedatConfig) -> Self {
        Self::new(resolve_admin_token(cfg))
    }

    /// Whether a non-empty current token is configured (auth required).
    #[must_use]
    pub fn is_required(&self) -> bool {
        self.inner.lock().current.is_some()
    }

    /// Constant-time match against current and (if still in window) previous.
    #[must_use]
    pub fn matches_presented(&self, presented: &str) -> bool {
        if presented.is_empty() {
            return false;
        }
        let snap = self.inner.lock();
        if let Some(ref cur) = snap.current {
            if token_matches(presented, cur) {
                return true;
            }
        }
        if let (Some(ref prev), Some(until)) = (&snap.previous, snap.previous_until) {
            if Instant::now() < until && token_matches(presented, prev) {
                return true;
            }
        }
        false
    }

    /// Metrics Bearer gate using the live store (fail-closed when required).
    #[must_use]
    pub fn metrics_authorized(&self, authorization_header: Option<&str>) -> bool {
        if !self.is_required() {
            return true;
        }
        let Some(raw) = authorization_header else {
            return false;
        };
        let Some(presented) = parse_bearer_authorization(raw) else {
            return false;
        };
        self.matches_presented(presented)
    }

    /// Re-read env / file / config into the live store.
    ///
    /// Fail-closed: if a token is currently required and sources resolve empty,
    /// the store is **unchanged** and [`TokenReloadWouldDisable`] is returned.
    pub fn reload_from_config(
        &self,
        cfg: &SedatConfig,
        overlap_secs: u64,
    ) -> Result<TokenReloadOutcome, TokenReloadWouldDisable> {
        let newly = resolve_admin_token(cfg);
        let mut snap = self.inner.lock();
        match (&snap.current, newly) {
            (Some(_), None) => Err(TokenReloadWouldDisable),
            (None, None) => Ok(TokenReloadOutcome::UnchangedEmpty),
            (None, Some(n)) => {
                snap.current = Some(n);
                snap.previous = None;
                snap.previous_until = None;
                Ok(TokenReloadOutcome::Enabled)
            }
            (Some(old), Some(n)) if token_matches(old, &n) => Ok(TokenReloadOutcome::Unchanged),
            (Some(old), Some(n)) => {
                if overlap_secs > 0 {
                    snap.previous = Some(old.clone());
                    snap.previous_until =
                        Some(Instant::now() + Duration::from_secs(overlap_secs));
                } else {
                    snap.previous = None;
                    snap.previous_until = None;
                }
                snap.current = Some(n);
                Ok(TokenReloadOutcome::Rotated { overlap_secs })
            }
        }
    }
}

/// Constant-time token compare via SHA-256 digests (does not log either value).
#[must_use]
pub fn token_matches(provided: &str, expected: &str) -> bool {
    let a = Sha256::digest(provided.as_bytes());
    let b = Sha256::digest(expected.as_bytes());
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract a Bearer token from an HTTP `Authorization` header value.
///
/// Accepts `Bearer <token>` (case-insensitive scheme). Returns `None` if missing
/// or not Bearer. Empty token string is returned as `Some("")` for fail-closed
/// handling by the caller.
#[must_use]
pub fn parse_bearer_authorization(header_value: &str) -> Option<&str> {
    let trimmed = header_value.trim();
    let (scheme, rest) = trimmed
        .split_once(char::is_whitespace)
        .map(|(s, r)| (s, r.trim()))
        .unwrap_or((trimmed, ""));
    if scheme.eq_ignore_ascii_case("bearer") {
        Some(rest)
    } else {
        None
    }
}

/// Whether a metrics scrape is authorized given the optional expected token.
///
/// - `expected = None` → auth disabled (loopback-only still applies at the listener).
/// - `expected = Some(t)` → require `Authorization: Bearer <t>` (constant-time).
#[must_use]
pub fn metrics_token_authorized(expected: Option<&str>, authorization_header: Option<&str>) -> bool {
    let Some(exp) = expected else {
        return true;
    };
    let Some(raw) = authorization_header else {
        return false;
    };
    let Some(presented) = parse_bearer_authorization(raw) else {
        return false;
    };
    if presented.is_empty() {
        return false;
    }
    token_matches(presented, exp)
}

/// Parse an `AUTH <token>` line (case-insensitive command, token is rest of line).
#[must_use]
pub fn parse_auth_line(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    let (cmd, rest) = trimmed
        .split_once(char::is_whitespace)
        .map(|(c, r)| (c, r.trim()))
        .unwrap_or((trimmed, ""));
    if cmd.eq_ignore_ascii_case("auth") && !rest.is_empty() {
        Some(rest)
    } else if cmd.eq_ignore_ascii_case("auth") {
        Some("")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SedatConfig;

    #[test]
    fn ct_eq_accepts_match() {
        assert!(token_matches("s3cret", "s3cret"));
        assert!(!token_matches("s3cret", "S3cret"));
        assert!(!token_matches("short", "longer-token"));
    }

    #[test]
    fn parse_auth() {
        assert_eq!(parse_auth_line("AUTH mytoken"), Some("mytoken"));
        assert_eq!(parse_auth_line("auth  x y"), Some("x y"));
        assert_eq!(parse_auth_line("AUTH"), Some(""));
        assert!(parse_auth_line("status").is_none());
    }

    #[test]
    fn resolve_inline_token() {
        let mut cfg = SedatConfig {
            schema_version: 1,
            server: Default::default(),
            tls: Default::default(),
            acme: Default::default(),
            routes: Default::default(),
            proxy_protocol: Default::default(),
            limits: Default::default(),
            embedded_docs: Default::default(),
            experimental: Default::default(),
            logging: Default::default(),
            hardening: Default::default(),
        };
        // Clear env interference for this test when possible.
        std::env::remove_var(ADMIN_TOKEN_ENV);
        assert!(resolve_admin_token(&cfg).is_none());
        cfg.server.admin_token = "from-config".into();
        assert_eq!(resolve_admin_token(&cfg).as_deref(), Some("from-config"));
    }

    #[test]
    fn bearer_and_metrics_gate() {
        assert_eq!(
            parse_bearer_authorization("Bearer secret-token"),
            Some("secret-token")
        );
        assert_eq!(
            parse_bearer_authorization("bearer  secret-token"),
            Some("secret-token")
        );
        assert!(parse_bearer_authorization("Basic abc").is_none());
        assert!(parse_bearer_authorization("Bearer").is_some_and(|t| t.is_empty()));

        assert!(metrics_token_authorized(None, None));
        assert!(metrics_token_authorized(None, Some("Bearer x")));
        assert!(!metrics_token_authorized(Some("secret"), None));
        assert!(!metrics_token_authorized(Some("secret"), Some("Bearer wrong")));
        assert!(metrics_token_authorized(
            Some("secret"),
            Some("Bearer secret")
        ));
    }

    #[test]
    fn live_tokens_rotate_with_overlap_and_fail_closed() {
        std::env::remove_var(ADMIN_TOKEN_ENV);
        let mut cfg = SedatConfig {
            schema_version: 1,
            server: Default::default(),
            tls: Default::default(),
            acme: Default::default(),
            routes: Default::default(),
            proxy_protocol: Default::default(),
            limits: Default::default(),
            embedded_docs: Default::default(),
            experimental: Default::default(),
            logging: Default::default(),
            hardening: Default::default(),
        };
        cfg.server.admin_token = "alpha".into();
        let live = LiveAdminTokens::from_config(&cfg);
        assert!(live.is_required());
        assert!(live.matches_presented("alpha"));

        cfg.server.admin_token = "beta".into();
        let out = live.reload_from_config(&cfg, 60).unwrap();
        assert_eq!(out, TokenReloadOutcome::Rotated { overlap_secs: 60 });
        assert!(live.matches_presented("beta"));
        assert!(live.matches_presented("alpha")); // overlap

        cfg.server.admin_token.clear();
        assert_eq!(
            live.reload_from_config(&cfg, 60),
            Err(TokenReloadWouldDisable)
        );
        assert!(live.matches_presented("beta")); // unchanged
    }

    #[test]
    fn live_tokens_hard_cut_when_overlap_zero() {
        std::env::remove_var(ADMIN_TOKEN_ENV);
        let mut cfg = SedatConfig {
            schema_version: 1,
            server: Default::default(),
            tls: Default::default(),
            acme: Default::default(),
            routes: Default::default(),
            proxy_protocol: Default::default(),
            limits: Default::default(),
            embedded_docs: Default::default(),
            experimental: Default::default(),
            logging: Default::default(),
            hardening: Default::default(),
        };
        cfg.server.admin_token = "one".into();
        let live = LiveAdminTokens::from_config(&cfg);
        cfg.server.admin_token = "two".into();
        assert_eq!(
            live.reload_from_config(&cfg, 0).unwrap(),
            TokenReloadOutcome::Rotated { overlap_secs: 0 }
        );
        assert!(live.matches_presented("two"));
        assert!(!live.matches_presented("one"));
    }
}
