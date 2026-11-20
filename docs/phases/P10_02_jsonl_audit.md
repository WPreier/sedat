# P10.2 – E5 JSONL-Audit-Log

## Summary

Optional append-only **JSONL** audit sink for SIEM / ops. Disabled by default
(fail-closed: no file until explicitly configured). Complements P09.7
`sedat::audit` tracing lines and includes **`request_id`** on proxy denials
when request-id generation is enabled (P10.1).

## Config

```toml
[logging]
# empty = off (default)
audit_jsonl = "./state/audit.jsonl"
audit_jsonl_max_bytes = 10485760   # rotate to *.jsonl.1; 0 = never
```

## Event shapes (`v: 1`)

Common fields: `ts` (RFC3339), `v`, `event`, `request_id` (string or null), `peer` (string or null).

| `event` | When | Notes |
|---------|------|--------|
| `startup` | Process start (sink enabled) | `version` |
| `config_reload` | Admin `reload` success | `summary`, `changes[]`; `request_id` null |
| `proxy_deny` | Edge rejection / upstream error | `reason`, `status`, `host`, `path`; **`request_id` when available** |
| `ip_ban` / `ip_unban` | Temporary ban lifecycle (P10.3) | `duration_secs` / `strikes` on ban; **`request_id` when available** |
| `admin_auth_fail` | Admin token rejected / missing (P10.4) | `reason` only — never the secret |

`proxy_deny` reasons include: `rate_limit`, `smuggling`, `header_bomb`,
`absolute_uri_host_mismatch`, `path_traversal`, `missing_host`,
`sni_host_mismatch`, `unknown_host_or_path`, `upstream_error`.

## Safety

- Request path uses `try_lock`; contended / I/O failure → drop + counter (never blocks).
- Path validation rejects URLs / NUL; empty path disables.
- Reload reconfigures the sink when `audit_jsonl` changes.

## Tests

- Unit: `src/audit.rs`
- Integration: `tests/audit_jsonl.rs`

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest cargo test audit
```
