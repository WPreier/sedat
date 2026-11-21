# P12.2 – Sliding / extending bans

## Summary

When a client IP is **already banned** and keeps sending requests, SeDat
refreshes the ban TTL to `now + ban_duration_secs` (sliding window). The
window does **not** grow beyond `ban_duration_secs` from the last hit.

## Config (safe defaults)

```toml
[limits]
ban_after_rate_limit_strikes = 20
ban_duration_secs = 60
ban_extend_while_banned = true      # default on
ban_extend_min_interval_secs = 1    # JSONL throttle; TTL still slides every hit
```

| Key | Default | Notes |
|-----|---------|-------|
| `ban_extend_while_banned` | `true` | `false` = fixed TTL (P10.3 behavior) |
| `ban_extend_min_interval_secs` | `1` | Min seconds between `ip_ban_extend` audits; `0` = every extend |

Bans remain disabled when `ban_after_rate_limit_strikes = 0`.

## Audit

| Event | When |
|-------|------|
| `ip_ban` | Ban first applied after strikes |
| `ip_ban_extend` | TTL refreshed (throttled by min interval) — fields `duration_secs`, `previous_remaining_secs` |
| `ip_unban` | TTL elapsed on next check |
| `admin_unban` | Manual clear via admin socket |

## Behavior

| Situation | HTTP | Lifecycle |
|-----------|------|-----------|
| Ban applied | 403 | `Applied` → `ip_ban` |
| Hit while banned (extend on) | 403 | `Extended` → `ip_ban_extend` (throttled) |
| Hit while banned (extend off) | 403 | none |
| TTL elapsed | allow / 429 | `Expired` → `ip_unban` |

Admin socket `bans` / `unban` unchanged.

## Tests

- Unit: `src/limits` `sliding_ban_extends_ttl`, `sliding_ban_disabled_keeps_fixed_ttl`,
  updated `temporary_ban_after_strikes`
- Integration: `tests/ip_ban.rs` expects `ip_ban_extend`

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib sliding_ban && cargo test ip_ban"
```
