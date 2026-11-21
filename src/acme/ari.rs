//! ACME Renewal Information (ARI / RFC 9773) helpers.
//!
//! Implemented without upgrading `instant-acme` (still 0.7): directory + renewalInfo
//! are plain HTTP GETs (no JWS). When the CA has no `renewalInfo`, callers fall back
//! to `notAfter − renew_days_before`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use x509_parser::prelude::*;

/// Suggested renewal window from an ARI response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AriWindow {
    /// Inclusive window start.
    pub start: SystemTime,
    /// Inclusive window end (treat as “renew by”).
    pub end: SystemTime,
}

/// Parsed ARI body (RFC 9773 §4.2).
#[derive(Debug, Clone)]
pub struct AriInfo {
    /// CA-suggested window.
    pub window: AriWindow,
    /// Optional operator documentation URL.
    pub explanation_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AriInfoJson {
    suggested_window: SuggestedWindowJson,
    #[serde(rename = "explanationURL")]
    explanation_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SuggestedWindowJson {
    start: String,
    end: String,
}

#[derive(Debug, Deserialize)]
struct DirectoryJson {
    #[serde(rename = "renewalInfo")]
    renewal_info: Option<String>,
}

/// Extract `renewalInfo` base URL from an ACME directory document body.
#[must_use]
pub fn directory_renewal_info_url(directory_body: &str) -> Option<String> {
    serde_json::from_str::<DirectoryJson>(directory_body)
        .ok()?
        .renewal_info
        .filter(|u| !u.is_empty())
}

/// Parse ARI JSON into [`AriInfo`].
pub fn parse_renewal_info_json(body: &str) -> Result<AriInfo, String> {
    let raw: AriInfoJson = serde_json::from_str(body).map_err(|e| format!("ARI JSON: {e}"))?;
    let start = parse_rfc3339(&raw.suggested_window.start)?;
    let end = parse_rfc3339(&raw.suggested_window.end)?;
    if end < start {
        return Err("ARI suggestedWindow end before start".into());
    }
    Ok(AriInfo {
        window: AriWindow { start, end },
        explanation_url: raw.explanation_url,
    })
}

fn parse_rfc3339(s: &str) -> Result<SystemTime, String> {
    let dt = chrono::DateTime::parse_from_rfc3339(s).map_err(|e| format!("ARI time `{s}`: {e}"))?;
    let secs = dt.timestamp();
    if secs < 0 {
        return Err(format!("ARI time `{s}` before Unix epoch"));
    }
    let nanos = dt.timestamp_subsec_nanos();
    Ok(UNIX_EPOCH + Duration::new(secs as u64, nanos))
}

/// First PEM certificate → ARI certificate identifier (`aki.serial`, base64url).
pub fn certificate_id_from_pem(cert_pem: &[u8]) -> Result<String, String> {
    let mut reader = std::io::Cursor::new(cert_pem);
    let der = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| "no certificate in PEM".to_string())?
        .map_err(|e| format!("PEM cert: {e}"))?;
    certificate_id_from_der(der.as_ref())
}

fn certificate_id_from_der(der: &[u8]) -> Result<String, String> {
    let (_, parsed) = parse_x509_certificate(der).map_err(|e| format!("x509 parse: {e}"))?;
    let aki: &[u8] = parsed
        .iter_extensions()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki_ext) => {
                aki_ext.key_identifier.as_ref().map(|ki| {
                    let b: &[u8] = ki.0;
                    b
                })
            }
            _ => None,
        })
        .ok_or_else(|| {
            "certificate missing Authority Key Identifier (required for ARI)".to_string()
        })?;
    let serial = parsed.tbs_certificate.raw_serial();
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(aki),
        URL_SAFE_NO_PAD.encode(serial)
    ))
}

/// Leaf certificate `notAfter` as [`SystemTime`].
pub fn not_after_from_pem(cert_pem: &[u8]) -> Result<SystemTime, String> {
    let mut reader = std::io::Cursor::new(cert_pem);
    let der = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| "no certificate in PEM".to_string())?
        .map_err(|e| format!("PEM cert: {e}"))?;
    let (_, parsed) =
        parse_x509_certificate(der.as_ref()).map_err(|e| format!("x509 parse: {e}"))?;
    let na = parsed.validity().not_after;
    // x509-parser 0.16: ASN1Time → seconds since epoch via `timestamp()`.
    let secs = na.timestamp();
    if secs < 0 {
        return Err("notAfter before Unix epoch".into());
    }
    Ok(UNIX_EPOCH + Duration::from_secs(secs as u64))
}

/// Build renewalInfo request URL: `{base}/{cert_id}` (trim trailing slash on base).
#[must_use]
pub fn renewal_info_request_url(base: &str, cert_id: &str) -> String {
    let base = base.trim_end_matches('/');
    format!("{base}/{cert_id}")
}

/// Pick a renewal instant inside `[start, end]` with uniform jitter in `0.0..=1.0`.
///
/// If `now` is already past `end`, returns `now` (renew immediately).
/// If `now` is inside the window, jitters between `now` and `end`.
#[must_use]
pub fn pick_renewal_instant(now: SystemTime, window: &AriWindow, jitter_01: f64) -> SystemTime {
    let jitter = jitter_01.clamp(0.0, 1.0);
    if now >= window.end {
        return now;
    }
    let start = if now > window.start {
        now
    } else {
        window.start
    };
    if start >= window.end {
        return now;
    }
    let span = window
        .end
        .duration_since(start)
        .unwrap_or(Duration::ZERO)
        .as_secs_f64();
    let offset = Duration::from_secs_f64(span * jitter);
    start + offset
}

/// Fallback renew-at: `not_after − renew_days_before` (clamped to `now` if already due).
#[must_use]
pub fn fallback_renew_at(
    now: SystemTime,
    not_after: SystemTime,
    renew_days_before: u64,
) -> SystemTime {
    let lead = Duration::from_secs(renew_days_before.saturating_mul(86_400));
    let target = not_after.checked_sub(lead).unwrap_or(now);
    if target <= now {
        now
    } else {
        target
    }
}

/// Scheduling decision for the renewal loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewSchedule {
    /// Attempt issuance/renewal immediately.
    Now {
        /// Human-readable reason.
        reason: &'static str,
    },
    /// Sleep until approximately this instant (caller may cap / re-evaluate).
    Later {
        /// When to wake for renewal (or ARI re-check).
        at: SystemTime,
        /// Human-readable reason.
        reason: &'static str,
    },
}

/// Combine optional ARI window with cert expiry fallback.
///
/// - ARI present → jittered instant in suggested window (or now if overdue).
/// - Else → `notAfter − renew_days_before` when `not_after` known.
/// - Else → re-check in 24h (safe default; no blind mass renew).
#[must_use]
pub fn schedule_renewal(
    now: SystemTime,
    ari: Option<&AriWindow>,
    not_after: Option<SystemTime>,
    renew_days_before: u64,
    jitter_01: f64,
) -> RenewSchedule {
    if let Some(window) = ari {
        let at = pick_renewal_instant(now, window, jitter_01);
        if at <= now {
            return RenewSchedule::Now {
                reason: "ari_window_due",
            };
        }
        return RenewSchedule::Later {
            at,
            reason: "ari_suggested_window",
        };
    }
    if let Some(na) = not_after {
        let at = fallback_renew_at(now, na, renew_days_before);
        if at <= now {
            return RenewSchedule::Now {
                reason: "expiry_fallback_due",
            };
        }
        return RenewSchedule::Later {
            at,
            reason: "expiry_fallback",
        };
    }
    RenewSchedule::Later {
        at: now + Duration::from_secs(24 * 3600),
        reason: "no_cert_metadata_retry_24h",
    }
}

/// Parse `Retry-After` as delta-seconds (HTTP-date ignored → default).
///
/// Default **6h** when missing/invalid (RFC 9773 clients should re-query periodically).
#[must_use]
pub fn parse_retry_after(header: Option<&str>) -> Duration {
    let Some(raw) = header.map(str::trim).filter(|s| !s.is_empty()) else {
        return Duration::from_secs(6 * 3600);
    };
    if let Ok(secs) = raw.parse::<u64>() {
        return Duration::from_secs(secs.min(7 * 24 * 3600));
    }
    Duration::from_secs(6 * 3600)
}

/// Uniform jitter in `0.0..1.0` from OS randomness (falls back to 0.5).
#[must_use]
pub fn random_jitter_01() -> f64 {
    let mut buf = [0u8; 8];
    if getrandom::fill(&mut buf).is_err() {
        return 0.5;
    }
    let v = u64::from_le_bytes(buf);
    (v as f64) / (u64::MAX as f64)
}

/// Sleep duration until `at`, floored at zero, capped at `max`.
#[must_use]
pub fn sleep_until(now: SystemTime, at: SystemTime, max: Duration) -> Duration {
    at.duration_since(now).unwrap_or(Duration::ZERO).min(max)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};

    #[test]
    fn parses_directory_renewal_info() {
        let body = r#"{"newNonce":"x","newAccount":"y","newOrder":"z","renewalInfo":"https://acme.example/ri/"}"#;
        assert_eq!(
            directory_renewal_info_url(body).as_deref(),
            Some("https://acme.example/ri/")
        );
        assert!(directory_renewal_info_url(r#"{"newOrder":"z"}"#).is_none());
    }

    #[test]
    fn parses_ari_json_rfc_example() {
        const INFO: &str = r#"{
          "suggestedWindow": {
            "start": "2025-01-02T04:00:00Z",
            "end": "2025-01-03T04:00:00Z"
          },
          "explanationURL": "https://acme.example.com/docs/ari"
        }"#;
        let info = parse_renewal_info_json(INFO).unwrap();
        assert_eq!(
            info.explanation_url.as_deref(),
            Some("https://acme.example.com/docs/ari")
        );
        let start = info.window.start.duration_since(UNIX_EPOCH).unwrap();
        let end = info.window.end.duration_since(UNIX_EPOCH).unwrap();
        assert!(end > start);
        assert_eq!(start.as_secs(), 1_735_790_400); // 2025-01-02T04:00:00Z
    }

    #[test]
    fn schedule_prefers_ari_window() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let window = AriWindow {
            start: UNIX_EPOCH + Duration::from_secs(2_000),
            end: UNIX_EPOCH + Duration::from_secs(3_000),
        };
        match schedule_renewal(now, Some(&window), None, 30, 0.0) {
            RenewSchedule::Later { at, reason } => {
                assert_eq!(at, window.start);
                assert_eq!(reason, "ari_suggested_window");
            }
            other => panic!("unexpected {other:?}"),
        }
        match schedule_renewal(now, Some(&window), None, 30, 1.0) {
            RenewSchedule::Later { at, .. } => assert_eq!(at, window.end),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn schedule_ari_overdue_is_now() {
        let now = UNIX_EPOCH + Duration::from_secs(5_000);
        let window = AriWindow {
            start: UNIX_EPOCH + Duration::from_secs(2_000),
            end: UNIX_EPOCH + Duration::from_secs(3_000),
        };
        assert!(matches!(
            schedule_renewal(now, Some(&window), None, 30, 0.5),
            RenewSchedule::Now {
                reason: "ari_window_due"
            }
        ));
    }

    #[test]
    fn schedule_expiry_fallback() {
        let now = UNIX_EPOCH + Duration::from_secs(0);
        let not_after = UNIX_EPOCH + Duration::from_secs(40 * 86_400);
        match schedule_renewal(now, None, Some(not_after), 30, 0.0) {
            RenewSchedule::Later { at, reason } => {
                assert_eq!(reason, "expiry_fallback");
                assert_eq!(at, UNIX_EPOCH + Duration::from_secs(10 * 86_400));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn cert_id_and_not_after_from_ca_signed() {
        let mut ca_params = CertificateParams::new(vec!["Test CA".into()]).unwrap();
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let mut ee = CertificateParams::new(vec!["localhost".into()]).unwrap();
        ee.distinguished_name = DistinguishedName::new();
        ee.distinguished_name.push(DnType::CommonName, "localhost");
        ee.use_authority_key_identifier_extension = true;
        let ee_key = KeyPair::generate().unwrap();
        let ee_cert = ee.signed_by(&ee_key, &ca_cert, &ca_key).unwrap();

        let pem = ee_cert.pem();
        let id = certificate_id_from_pem(pem.as_bytes()).unwrap();
        assert!(id.contains('.'), "{id}");
        assert!(!id.starts_with('.'));
        let na = not_after_from_pem(pem.as_bytes()).unwrap();
        assert!(na > SystemTime::now());
    }

    #[test]
    fn renewal_info_url_join() {
        assert_eq!(
            renewal_info_request_url("https://acme.example/ri/", "abc.def"),
            "https://acme.example/ri/abc.def"
        );
    }

    #[test]
    fn retry_after_seconds() {
        assert_eq!(parse_retry_after(Some("120")), Duration::from_secs(120));
        assert_eq!(parse_retry_after(None), Duration::from_secs(6 * 3600));
    }
}
