//! Request correlation IDs (`x-request-id` by default).
//!
//! Propagated as an **HTTP header after PROXY framing** (not a PROXY v2 TLV), so the
//! same correlation works with outbound PROXY `off` / `v1` / `v2`.

use http::HeaderMap;
use tracing::warn;

/// Default HTTP header name (lowercase; HTTP/2 style).
pub const DEFAULT_REQUEST_ID_HEADER: &str = "x-request-id";

/// Maximum accepted / generated id length (fail-safe: oversized inbound → regenerate).
pub const MAX_REQUEST_ID_LEN: usize = 128;

/// Resolve a request id for logging and upstream propagation.
///
/// When `enabled` is false, returns `None` (no generation / forced injection).
/// When enabled: reuse a valid inbound header value, otherwise generate a new id.
#[must_use]
pub fn resolve_request_id(headers: &HeaderMap, enabled: bool, header_name: &str) -> Option<String> {
    if !enabled {
        return None;
    }
    if let Some(raw) = headers
        .get(header_name)
        .or_else(|| {
            // Accept common casing variants when header_name is the canonical default.
            if header_name.eq_ignore_ascii_case(DEFAULT_REQUEST_ID_HEADER) {
                headers.get("X-Request-ID")
            } else {
                None
            }
        })
        .and_then(|v| v.to_str().ok())
    {
        if let Some(id) = sanitize_request_id(raw) {
            return Some(id);
        }
        warn!(
            header = %header_name,
            "invalid inbound request-id; generating a new one"
        );
    }
    Some(generate_request_id())
}

/// Resolve a request id from a raw HTTP/1 header block (pre-hyper early rejects).
///
/// Same rules as [`resolve_request_id`]: disabled → `None`; reuse valid inbound;
/// otherwise generate.
#[must_use]
pub fn resolve_request_id_from_raw(
    header_block: &[u8],
    enabled: bool,
    header_name: &str,
) -> Option<String> {
    if !enabled {
        return None;
    }
    let text = String::from_utf8_lossy(header_block);
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case(header_name) {
            if let Some(id) = sanitize_request_id(value) {
                return Some(id);
            }
            warn!(
                header = %header_name,
                "invalid inbound request-id in raw headers; generating a new one"
            );
            break;
        }
    }
    Some(generate_request_id())
}

/// Whether `buf` ends with a complete HTTP/1 header terminator (`\r\n\r\n`).
#[must_use]
pub fn http_headers_complete(buf: &[u8]) -> bool {
    buf.len() >= 4 && buf[buf.len() - 4..] == *b"\r\n\r\n"
}

/// Accept only printable safe tokens (A–Z a–z 0–9 `_` `-` `.`).
#[must_use]
pub fn sanitize_request_id(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_REQUEST_ID_LEN {
        return None;
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(trimmed.to_string())
}

/// Generate a 128-bit random id as lowercase hex (32 chars).
#[must_use]
pub fn generate_request_id() -> String {
    let mut buf = [0u8; 16];
    if getrandom::fill(&mut buf).is_err() {
        // Extremely unlikely; fall back to time-based uniqueness.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        buf[..8].copy_from_slice(&(nanos as u64).to_be_bytes());
        buf[8..].copy_from_slice(&((!nanos) as u64).to_be_bytes());
    }
    hex::encode(buf)
}

/// Validate a configured header name (HTTP token, lowercase preferred).
#[must_use]
pub fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && name
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn generates_when_missing() {
        let h = HeaderMap::new();
        let id = resolve_request_id(&h, true, DEFAULT_REQUEST_ID_HEADER).unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn reuses_valid_inbound() {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::HeaderName::from_static("x-request-id"),
            HeaderValue::from_static("abc-DEF_01.2"),
        );
        let id = resolve_request_id(&h, true, DEFAULT_REQUEST_ID_HEADER).unwrap();
        assert_eq!(id, "abc-DEF_01.2");
    }

    #[test]
    fn regenerates_invalid_inbound() {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::HeaderName::from_static("x-request-id"),
            HeaderValue::from_static("bad id with spaces!"),
        );
        let id = resolve_request_id(&h, true, DEFAULT_REQUEST_ID_HEADER).unwrap();
        assert_ne!(id, "bad id with spaces!");
        assert_eq!(id.len(), 32);
    }

    #[test]
    fn disabled_returns_none() {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::HeaderName::from_static("x-request-id"),
            HeaderValue::from_static("keep-me"),
        );
        assert!(resolve_request_id(&h, false, DEFAULT_REQUEST_ID_HEADER).is_none());
    }

    #[test]
    fn header_name_rules() {
        assert!(valid_header_name("x-request-id"));
        assert!(valid_header_name("X-Correlation-ID"));
        assert!(!valid_header_name(""));
        assert!(!valid_header_name("bad header"));
        assert!(!valid_header_name("-leading"));
    }

    #[test]
    fn raw_header_reuses_and_generates() {
        let raw = b"GET / HTTP/1.1\r\nHost: x\r\nX-Request-Id: early-99\r\n\r\n";
        let id = resolve_request_id_from_raw(raw, true, DEFAULT_REQUEST_ID_HEADER).unwrap();
        assert_eq!(id, "early-99");

        let bare = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let gen = resolve_request_id_from_raw(bare, true, DEFAULT_REQUEST_ID_HEADER).unwrap();
        assert_eq!(gen.len(), 32);

        assert!(resolve_request_id_from_raw(raw, false, DEFAULT_REQUEST_ID_HEADER).is_none());
        assert!(http_headers_complete(raw));
        assert!(!http_headers_complete(b"GET / HTTP/1.1\r\nHost: x\r\n"));
    }
}
