# P10.6 – E3 Upstream-IP-Pin

## Summary

Per-route **upstream IP allowlist**. When non-empty, SeDat resolves the upstream
host, keeps only addresses matching the pin, connects to a matching address, and
re-checks the connected peer. Empty allowlist = no pin (backward compatible).

## Config

```toml
[[routes.hosts.paths]]
prefix = "/"
upstream = "http://backend.internal:9080"
upstream_allowlist = ["10.0.0.5", "10.0.0.0/8"]  # empty = unrestricted
# hostname literals + DNS refresh: see P12.5
```

| Behavior | Result |
|----------|--------|
| Allowlist empty | DNS + connect as before |
| Resolved IPs none in allowlist | **Fail-closed** → 502 (`upstream_ip_pin`) |
| Connect succeeds but peer leaves pin | Fail-closed |

## Security

Mitigates DNS rebinding / unexpected upstream IPs after resolver compromise or
hostile DNS updates when an explicit pin is configured.

## Tests

- Unit: `src/proxy/upstream_pin.rs`
- Integration: `tests/upstream_pin.rs`

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest cargo test upstream_pin
```
