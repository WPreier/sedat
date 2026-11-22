# P17.2 – Prometheus `sedat_proxy_deny_total`

## Summary

HTTP-path security denials already emit JSONL `proxy_deny` (and tracing). Scrapers
had no counter without parsing logs — weak for T4/T6/T13 dashboards.

**Fix:** `AuditSink::emit_proxy_deny` always increments a fixed-cardinality
counter (even when JSONL is disabled). Admin/`/metrics` expose:

```text
# HELP sedat_proxy_deny_total HTTP-path security denials by reason.
# TYPE sedat_proxy_deny_total counter
sedat_proxy_deny_total{reason="rate_limit"} 0
sedat_proxy_deny_total{reason="ip_banned"} 0
…
sedat_proxy_deny_total{reason="other"} 0
```

Unknown reasons map to `other`.

| Change | Detail |
|--------|--------|
| `src/audit.rs` | `PROXY_DENY_REASONS`, per-reason atomics, `proxy_deny_gauges` |
| `src/admin/mod.rs` | Append counters in `prometheus_text` |

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib -- proxy_deny_counters metrics_expose_proxy_deny --nocapture"
```
