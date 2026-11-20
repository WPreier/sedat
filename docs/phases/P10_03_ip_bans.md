# P10.3 – Temporäre IP-Bans nach Rate-Limit-Serien

## Summary

After **N consecutive** token-bucket denials for the same client IP, SeDat
applies a temporary ban. While banned, requests are **fail-closed** (`403`)
until `ban_duration_secs` elapses. Ban apply / expire are logged via `tracing`
and, when enabled, JSONL audit events (`ip_ban` / `ip_unban`) including
`request_id` when available.

## Config

```toml
[limits]
rate_limit_per_ip = 100
rate_limit_burst = 20
# Consecutive 429s before ban; 0 = disable bans
ban_after_rate_limit_strikes = 20
ban_duration_secs = 60
```

| Knob | Default | Notes |
|------|---------|--------|
| `ban_after_rate_limit_strikes` | `20` | `0` disables temporary bans |
| `ban_duration_secs` | `60` | Must be `> 0` when strikes `> 0` (validation) |

A successful (allowed) request resets the consecutive strike counter.

## HTTP status

| Situation | Status | Audit `reason` / event |
|-----------|--------|-------------------------|
| Token bucket empty | `429` | `proxy_deny` / `rate_limit` |
| Ban just applied / still active | `403` | `ip_ban` (+ `proxy_deny` / `ip_banned`) |
| Ban TTL elapsed | (next check) | `ip_unban`; then allow or `429` as usual |

## Tests

- Unit: `src/limits` (`temporary_ban_after_strikes`, `bans_disabled_when_strikes_zero`)
- Integration: `tests/ip_ban.rs`

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest cargo test ip_ban
docker run --rm -v "%CD%":/src -w /src rust:latest cargo test --lib limits
```
