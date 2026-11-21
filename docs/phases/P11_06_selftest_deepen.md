# P11.6 – Deepen admin selftest

## Summary

Extend `selftest` with allowlist parse checks, short-timeout upstream TCP (and
TLS/ALPN for `https://` upstreams), plus optional machine-readable JSON output.
Probes are capped and timed so the admin socket cannot hang.

## Protocol

```text
selftest              # human PASS/FAIL lines (unchanged shape)
selftest json         # aliases: --json | -json
OK selftest json
{"ok":true,"uptime_secs":12,"failed":[],"checks":[{"name":"...","ok":true,"detail":"..."}]}
```

## New / updated checks

| Check | Meaning |
|-------|---------|
| `allowlists` | Every `inbound_allowlist` / `upstream_allowlist` entry parses as IP/CIDR; inbound enabled ⇒ non-empty list |
| `upstream_tcp` | Up to 3 unique upstreams: DNS+TCP with **400ms** timeouts (`skipped=no_routes` if none) |
| `upstream_tls_alpn` | For `https://` targets: rustls handshake + report negotiated ALPN (`h2` / `http/1.1`); skipped when no HTTPS routes |

Fail-safe: max **3** upstream probes; DNS/connect/handshake each bounded by `PROBE_TIMEOUT` (400ms).

## Tests

- `src/admin/selftest` — `selftest_json_and_allowlists`, `selftest_tcp_to_local_listener`
- `src/admin` — `selftest_json_command`, `selftest_command_ok`

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib selftest && cargo test --lib selftest_json"
printf 'selftest json\n' | socat - UNIX-CONNECT:./state/admin.sock
```
