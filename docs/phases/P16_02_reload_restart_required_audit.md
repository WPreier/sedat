# P16.2 – `restart_required` on config_reload JSONL

## Summary

P15.3 annotates admin text; P16.1 exposes Prometheus gauges. Log/SIEM pipelines
still needed to scrape metrics or parse `status`/`reload` replies to learn that
a successful reload left boot-bound knobs unapplied.

**Fix:** Every `config_reload` JSONL event includes `restart_required` (string
array of keys; empty when none) from the same boot-vs-live snapshot.

```json
{
  "event": "config_reload",
  "summary": "…",
  "changes": […],
  "restart_required": ["server.listen", "hardening.seccomp"]
}
```

| Change | Detail |
|--------|--------|
| `src/audit.rs` | `emit_config_reload(…, restart_required)` |
| `src/admin/mod.rs` | Pass `restart_required_keys` on successful reload |

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib -- config_reload_lines config_reload_empty_restart reload_audit_includes_restart --nocapture"
```
