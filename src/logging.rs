//! Non-blocking logging setup (bounded channel; never blocks request path).

use tracing_subscriber::{fmt, EnvFilter};

/// Initialize global subscriber from a level string (`info`, `debug`, …).
pub fn init(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}
