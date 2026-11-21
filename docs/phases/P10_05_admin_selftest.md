# P10.5 – E6 Admin-selftest

## Summary

Admin socket command `selftest` runs a structured set of operator health checks
(config, listens, state dir, PROXY encode probe, limits, TLS paths, ACME/audit
status, uptime). Requires `AUTH` when a token is configured (P10.4). Results are
written to JSONL as `admin_selftest` when the audit sink is enabled.

## Protocol

```text
AUTH <token>          # if token configured
selftest
OK selftest
uptime_secs=12
PASS schema_version active=1 expected=1
PASS listen parseable=127.0.0.1:8080
...
```

On failure:

```text
ERR selftest failed=schema_version,state_dir
FAIL schema_version ...
```

Aliases: `self-test`, `self_test`.

## Checks (non-exhaustive)

| Check | Meaning |
|-------|---------|
| `schema_version` | Matches `CURRENT_SCHEMA_VERSION` |
| `listen` / `listen_tls` / `http_redirect_listen` | Parse as socket addresses |
| `state_dir` | Path exists |
| `admin_socket_parent` | Parent directory exists |
| `admin_auth` | Reports whether token is required (always PASS) |
| `proxy_outbound` / `proxy_inbound_placement` | Known enum values |
| `proxy_v2_encode` | Outbound PROXY v2 encoder produces a valid signature |
| `limits_*` | Non-zero connection/rate knobs; shows active connections |
| `tls_cert_path` / `tls_key_path` | Files exist when TLS on + static paths set |
| `acme_status` | ACME handle / disabled |
| `audit_jsonl` | Enabled path or disabled |
| `allowlists` | PROXY/upstream CIDR entries parse (P11.6) |
| `upstream_tcp` / `upstream_tls_alpn` | Short-timeout connectivity (P11.6) |
| `uptime` | Seconds since admin state creation |

Optional: `selftest json` → JSON document after the OK/ERR header (P11.6).

## Tests

- `src/admin/selftest.rs`
- `src/admin` `selftest_command_ok`

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest cargo test selftest
printf 'selftest\n' | socat - UNIX-CONNECT:./state/admin.sock
```
