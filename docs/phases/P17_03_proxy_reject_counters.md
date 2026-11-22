# P17.3 – Prometheus `sedat_proxy_reject_total`

## Summary

Pre-HTTP inbound PROXY rejects already emit JSONL `proxy_reject` (T1/T12).
Scrapers need counters without log parsing.

**Fix:** `AuditSink::emit_proxy_reject` always increments fixed-cardinality
`sedat_proxy_reject_total{reason,stage}` (even when JSONL is off).

```text
# TYPE sedat_proxy_reject_total counter
sedat_proxy_reject_total{reason="untrusted_or_disabled",stage="plaintext"} 0
…
```

Unknown reason/stage map to `other`.

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib -- proxy_reject_counters metrics_expose_proxy_reject --nocapture"
```
