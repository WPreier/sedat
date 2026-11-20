//! SeDat — minimal high-security reverse proxy.
//!
//! Companion to [Seda](https://github.com/WPreier/seda).

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod acme;
pub mod admin;
pub mod audit;
pub mod config;
pub mod embed;
pub mod hardening;
pub mod limits;
pub mod logging;
pub mod proxy;
pub mod tls;

/// HTTP/3 experimental module (feature `http3`).
pub mod http3;

/// Crate version from Cargo.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Embedded default 404 HTML body.
pub const DEFAULT_404_HTML: &str = include_str!("../assets/404.html");

/// Embedded default configuration TOML.
pub const DEFAULT_CONFIG_TOML: &str = include_str!("../assets/default_config.toml");
