# P16.3 – Prometheus uptime + bans_active

## Summary

Ops dashboards already scrape connections, audit drops, and restart-required
drift. Missing: process uptime and how many temporary IP bans are active.

**Fix:** Emit two gauges on admin `metrics` / loopback `/metrics`:

```text
# HELP sedat_uptime_seconds Seconds since process/admin start.
# TYPE sedat_uptime_seconds gauge
sedat_uptime_seconds 42
# HELP sedat_bans_active Active temporary IP bans.
# TYPE sedat_bans_active gauge
sedat_bans_active 0
```

| Change | Detail |
|--------|--------|
| `src/limits/mod.rs` | `Limiter::bans_active()` |
| `src/admin/mod.rs` | Append gauges in `prometheus_text` |

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib -- metrics_expose_uptime_and_bans status_format --nocapture"
```
