//! TOML configuration lifecycle: parse, validate, activate, reload (fail-closed).

mod diff;
mod migrate;
mod schema;
mod validate;

pub use diff::{
    format_audit_summary, format_restart_required_note, restart_required_gauges,
    restart_required_keys, security_diff, RestartOnlySnapshot, SecurityChange, RESTART_ONLY_KEYS,
};
pub use migrate::{migrate_toml, migration_path, peek_schema_version, upgrade_notes};
pub use schema::*;
pub use validate::{
    ip_in_allowlist, ip_in_cidr, is_allowlist_entry, parse_cidr, validate_config, ValidationError,
};

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Name of the hidden active config file.
pub const ACTIVE_CONFIG_NAME: &str = ".sedat.active.toml";

/// Current supported schema version.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Errors while loading or activating configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// TOML syntax error with approximate line.
    #[error("TOML parse error at line {line}: {message}")]
    Parse {
        /// 1-based line number when available.
        line: usize,
        /// Parser message.
        message: String,
    },
    /// Semantic validation failure.
    #[error("validation error at line {line}: {message}")]
    Validation {
        /// 1-based line hint (best-effort).
        line: usize,
        /// Human-readable reason.
        message: String,
    },
    /// Unsupported schema version.
    #[error("unsupported schema_version {found}; supported: {CURRENT_SCHEMA_VERSION}")]
    SchemaVersion {
        /// Version found in file.
        found: u32,
    },
}

impl From<ValidationError> for ConfigError {
    fn from(value: ValidationError) -> Self {
        ConfigError::Validation {
            line: value.line,
            message: value.message,
        }
    }
}

/// Result of a successful load+activate cycle.
#[derive(Debug, Clone)]
pub struct ActiveConfig {
    /// Validated configuration.
    pub config: SedatConfig,
    /// Path to the hidden active copy.
    pub active_path: PathBuf,
    /// Path to the user-editable config.
    pub user_path: PathBuf,
}

/// Parse TOML text into [`SedatConfig`] without activating.
pub fn parse_toml(text: &str) -> Result<SedatConfig, ConfigError> {
    let raw: SedatConfig = toml::from_str(text).map_err(|e| {
        let line = e.span().map(|s| offset_to_line(text, s.start)).unwrap_or(1);
        ConfigError::Parse {
            line,
            message: e.message().to_string(),
        }
    })?;
    if raw.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(ConfigError::SchemaVersion {
            found: raw.schema_version,
        });
    }
    validate_config(&raw, text)?;
    Ok(raw)
}

/// Load user config, validate, and write the active copy (mode 0600 on Unix).
pub fn load_and_activate(
    user_path: &Path,
    state_dir: Option<&Path>,
) -> Result<ActiveConfig, ConfigError> {
    let text = fs::read_to_string(user_path)?;
    let config = parse_toml(&text)?;
    let active_dir = state_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| config.server.state_dir.clone().into());
    fs::create_dir_all(&active_dir)?;
    let active_path = active_dir.join(ACTIVE_CONFIG_NAME);
    write_active(&active_path, &text)?;
    Ok(ActiveConfig {
        config,
        active_path,
        user_path: user_path.to_path_buf(),
    })
}

/// Load the currently active config from disk (if present).
pub fn load_active(state_dir: &Path) -> Result<SedatConfig, ConfigError> {
    let path = state_dir.join(ACTIVE_CONFIG_NAME);
    let text = fs::read_to_string(path)?;
    parse_toml(&text)
}

/// Attempt reload from user path. On failure, previous active config is left untouched.
pub fn try_reload(user_path: &Path, state_dir: &Path) -> Result<ActiveConfig, ConfigError> {
    // Validate first by parsing into memory; only then overwrite active.
    let text = fs::read_to_string(user_path)?;
    let config = parse_toml(&text)?;
    let active_path = state_dir.join(ACTIVE_CONFIG_NAME);
    write_active(&active_path, &text)?;
    Ok(ActiveConfig {
        config,
        active_path,
        user_path: user_path.to_path_buf(),
    })
}

/// Write embedded default config to `user_path` and activate it.
pub fn reset_config(
    user_path: &Path,
    state_dir: Option<&Path>,
) -> Result<ActiveConfig, ConfigError> {
    if let Some(parent) = user_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(user_path, crate::DEFAULT_CONFIG_TOML)?;
    load_and_activate(user_path, state_dir)
}

fn write_active(path: &Path, text: &str) -> Result<(), ConfigError> {
    fs::write(path, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

fn offset_to_line(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())]
        .bytes()
        .filter(|b| *b == b'\n')
        .count()
        + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parse_default_config() {
        let cfg = parse_toml(crate::DEFAULT_CONFIG_TOML).expect("default must parse");
        assert_eq!(cfg.schema_version, 1);
        assert!(cfg.embedded_docs.enabled);
    }

    #[test]
    fn syntax_error_reports_line() {
        let bad = "schema_version = 1\n[server\nlisten = \"x\"\n";
        let err = parse_toml(bad).unwrap_err();
        match err {
            ConfigError::Parse { line, .. } => assert!(line >= 2),
            other => panic!("unexpected {other}"),
        }
    }

    #[test]
    fn reload_keeps_old_on_failure() {
        let dir = tempdir().unwrap();
        let user = dir.path().join("sedat.toml");
        let state = dir.path().join("state");
        fs::create_dir_all(&state).unwrap();
        fs::write(&user, crate::DEFAULT_CONFIG_TOML).unwrap();
        let active = load_and_activate(&user, Some(&state)).unwrap();
        assert!(active.active_path.exists());

        fs::write(&user, "schema_version = 1\nthis is = broken [[[\n").unwrap();
        let err = try_reload(&user, &state).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
        let still = load_active(&state).unwrap();
        assert_eq!(still.schema_version, 1);
    }

    #[test]
    fn resetconfig_writes_default() {
        let dir = tempdir().unwrap();
        let user = dir.path().join("sedat.toml");
        let state = dir.path().join("state");
        let active = reset_config(&user, Some(&state)).unwrap();
        assert!(user.exists());
        assert!(active.active_path.exists());
    }
}
