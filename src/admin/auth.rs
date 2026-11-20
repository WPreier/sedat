//! Admin socket capability-token helpers (constant-time verify).

use sha2::{Digest, Sha256};

use crate::config::SedatConfig;

/// Environment variable that overrides config / token file when non-empty.
pub const ADMIN_TOKEN_ENV: &str = "SEDAT_ADMIN_TOKEN";

/// Resolve the expected admin token.
///
/// Precedence (first non-empty wins):
/// 1. `SEDAT_ADMIN_TOKEN` environment variable
/// 2. Contents of `server.admin_token_file` (trimmed)
/// 3. `server.admin_token` config string
///
/// Empty result → token auth **disabled** (filesystem ACL only; fine for local
/// dev, not recommended alone in production).
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
}
