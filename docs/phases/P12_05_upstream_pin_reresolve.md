# P12.5 – Upstream pin hostname + DNS re-resolve

## Summary

Extends the P10.6 upstream IP pin:

1. **Hostname literals** in `upstream_allowlist` (beside IP/CIDR)
2. **Cached DNS re-resolution** for the upstream host and hostname pins
3. **Fail-closed** when the expanded pin is empty or resolved peers leave it

## Config

```toml
[[routes.hosts.paths]]
prefix = "/"
upstream = "http://backend.internal:9080"
upstream_allowlist = ["10.0.0.0/8", "db.internal"]  # IP/CIDR and/or hostname
upstream_dns_refresh_secs = 60                       # default; 0 = every connect
```

| Key | Default | Notes |
|-----|---------|-------|
| `upstream_allowlist` | `[]` | Empty = unrestricted |
| `upstream_dns_refresh_secs` | `60` | Cache TTL; `0` forces fresh DNS each connect |

## Behavior

| Situation | Result |
|-----------|--------|
| Allowlist empty | Connect as before (no pin) |
| Hostname pin resolves to IPs | Those IPs join the pin set |
| Hostname pin DNS fails / empty | That entry contributes nothing |
| All entries expand empty | **Fail-closed** → 502 |
| Resolved upstream IPs ∩ pin = ∅ | **Fail-closed** → 502 |
| Connected peer leaves pin | **Fail-closed** → 502 |

IP literals in the upstream URL skip DNS. Cache is process-wide (`DnsCache` on
`ProxyState`).

## Tests

- Unit: `src/proxy/upstream_pin` (hostname expand, TTL, fail-closed empty)
- Unit: `src/config` `allows_hostname_in_upstream_allowlist`
- Integration: `tests/upstream_pin.rs` `hostname_literal_pin_allows_localhost`

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib upstream_pin && cargo test --test upstream_pin"
```
