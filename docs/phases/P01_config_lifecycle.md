# Phase 1 – Config Lifecycle

## 1. Ziel / Nicht-Ziele

**Ziel:** TOML laden/validieren/aktivieren, Fail-Closed, `--resetconfig`.

**Nicht-Ziele:** Netzlogik.

## 2. Defaults

- Active copy: `.sedat.active.toml`, mode `0600` (Unix)
- `schema_version = 1` + fail-closed `migrate_toml` / `--migrate-config`
- Regex on hosts/paths/upstreams/listen/CIDRs

## 3. Testmatrix

| Art | Test |
|-----|------|
| Unit | `parse_default_config`, syntax line, validation host/path |
| Integration | reload keeps old on failure |
| Example | `cargo run --example config_demo` |

## 4. Beispiel

```bash
cargo run --example config_demo
# == good.toml: OK
# == bad_line_12.toml: FAIL: validation error at line … invalid host
```

## 5. Spec-Diff

`CONFIG.md` expanded to match schema; default asset `assets/default_config.toml`.

## 6. Risiken

Line numbers are best-effort from TOML span / needle search.
