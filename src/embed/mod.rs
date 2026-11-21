//! Embedded documentation routes (`/sedat`, `/seda`).

use std::convert::Infallible;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Response, StatusCode};

use crate::config::EmbeddedDocsConfig;
use crate::proxy::{BoxError, ForwardBody};

const SEDAT_DOC: &str = include_str!("../../assets/docs/sedat.md");
const SEDA_DOC: &str = include_str!("../../assets/docs/seda.md");

fn md_response(body: &str) -> Response<ForwardBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "text/markdown; charset=utf-8")
        .body(
            Full::new(Bytes::from(body.to_owned()))
                .map_err(|n: Infallible| -> BoxError { match n {} })
                .boxed(),
        )
        .expect("response")
}

/// Serve embedded docs if the path matches and docs are enabled.
pub fn maybe_serve(cfg: &EmbeddedDocsConfig, path: &str) -> Option<Response<ForwardBody>> {
    if !cfg.enabled {
        return None;
    }
    if path == cfg.sedat_path || path == format!("{}/", cfg.sedat_path) {
        return Some(md_response(SEDAT_DOC));
    }
    if path == cfg.seda_path || path == format!("{}/", cfg.seda_path) {
        return Some(md_response(SEDA_DOC));
    }
    None
}

/// Raw SeDat doc bytes (for tests).
pub fn sedat_doc() -> &'static str {
    SEDAT_DOC
}

/// Raw Seda doc bytes (for tests).
pub fn seda_doc() -> &'static str {
    SEDA_DOC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_when_enabled() {
        let cfg = EmbeddedDocsConfig::default();
        assert!(maybe_serve(&cfg, "/sedat").is_some());
        assert!(maybe_serve(&cfg, "/seda").is_some());
        assert!(maybe_serve(&cfg, "/other").is_none());
    }

    #[test]
    fn off_when_disabled() {
        let cfg = EmbeddedDocsConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(maybe_serve(&cfg, "/sedat").is_none());
    }
}
