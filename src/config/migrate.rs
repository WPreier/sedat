//! Config schema migration helpers (fail-closed).
//!
//! Operators upgrade by raising `schema_version` only after applying the
//! documented transforms for each step. Unknown or future versions are rejected.

use super::{ConfigError, CURRENT_SCHEMA_VERSION};

/// Describe how to move from `from` to `to` (inclusive path).
///
/// Returns `None` when no supported path exists (caller must fail closed).
#[must_use]
pub fn migration_path(from: u32, to: u32) -> Option<&'static str> {
    if from == to {
        return Some("no-op: already at target schema_version");
    }
    if to != CURRENT_SCHEMA_VERSION {
        return None;
    }
    match from {
        // Future: map 0 → 1 (or N → N+1) with documented field renames here.
        _ => None,
    }
}

/// Extract `schema_version` from TOML text without full validation.
pub fn peek_schema_version(text: &str) -> Result<u32, ConfigError> {
    #[derive(serde::Deserialize)]
    struct OnlyVersion {
        schema_version: u32,
    }
    let v: OnlyVersion = toml::from_str(text).map_err(|e| {
        let line = e
            .span()
            .map(|s| {
                text[..s.start.min(text.len())]
                    .bytes()
                    .filter(|b| *b == b'\n')
                    .count()
                    + 1
            })
            .unwrap_or(1);
        ConfigError::Parse {
            line,
            message: e.message().to_string(),
        }
    })?;
    Ok(v.schema_version)
}

/// Migrate TOML text toward [`CURRENT_SCHEMA_VERSION`].
///
/// Currently only identity for version 1. Older/unknown versions fail closed with
/// [`ConfigError::SchemaVersion`] or a validation-style message describing the gap.
pub fn migrate_toml(text: &str) -> Result<String, ConfigError> {
    let found = peek_schema_version(text)?;
    if found == CURRENT_SCHEMA_VERSION {
        return Ok(text.to_string());
    }
    match migration_path(found, CURRENT_SCHEMA_VERSION) {
        Some(_steps) => {
            // Future: apply mechanical transforms, then set schema_version = CURRENT.
            Err(ConfigError::SchemaVersion { found })
        }
        None => Err(ConfigError::SchemaVersion { found }),
    }
}

/// Human-readable upgrade notes for docs / CLI.
#[must_use]
pub fn upgrade_notes() -> &'static str {
    "\
SeDat config upgrades are fail-closed:
1. Read schema_version in the user TOML.
2. If it equals CURRENT_SCHEMA_VERSION (1), load+validate as usual.
3. If it is older and a migration_path exists, run `sedat --migrate-config`
   (or call config::migrate::migrate_toml), review the rewritten file, then reload.
4. If it is newer/unknown, refuse to start — never silently ignore fields.
"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_v1() {
        let t = "schema_version = 1\n[server]\nlisten = \"127.0.0.1:1\"\n";
        let out = migrate_toml(t).unwrap();
        assert_eq!(out, t);
    }

    #[test]
    fn unknown_version_fails_closed() {
        let t = "schema_version = 99\n";
        let err = migrate_toml(t).unwrap_err();
        assert!(matches!(err, ConfigError::SchemaVersion { found: 99 }));
    }

    #[test]
    fn peek_version() {
        assert_eq!(peek_schema_version("schema_version = 1\n").unwrap(), 1);
    }

    #[test]
    fn no_path_from_future() {
        assert!(migration_path(2, CURRENT_SCHEMA_VERSION).is_none());
    }
}
