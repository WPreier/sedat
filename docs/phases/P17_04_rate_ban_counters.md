# P17.4 – Prometheus rate_limit / ban hit counters

## Summary

Token-bucket rate limits and temporary IP bans (T13) were visible via JSONL /
admin `bans`, but not as scrapable counters.

**Fix:** `Limiter` increments process-lifetime counters; admin/metrics expose:

```text
# TYPE sedat_rate_limited_total counter
sedat_rate_limited_total 0
# TYPE sedat_ban_hits_total counter
sedat_ban_hits_total 0
```

| Metric | When incremented |
|--------|------------------|
| `sedat_rate_limited_total` | `RateOutcome::RateLimited` |
| `sedat_ban_hits_total` | `RateOutcome::Banned` (active ban hit or newly applied) |

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib -- rate_and_ban_hit metrics_expose_rate_and_ban --nocapture"
```
