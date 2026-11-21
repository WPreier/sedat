# P12.4 – Time-based audit log rotation

## Summary

`logging.audit_jsonl` can rotate by **age** in addition to the existing
**size** trigger. Either condition renames the active file to `*.jsonl.1`
and opens a fresh segment.

## Config (safe defaults)

```toml
[logging]
audit_jsonl = "./state/audit.jsonl"
audit_jsonl_max_bytes = 10485760   # size; 0 = off (default 10 MiB)
audit_jsonl_max_age_secs = 0       # age; 0 = off (default) e.g. 86400 = daily
```

| Key | Default | Notes |
|-----|---------|-------|
| `audit_jsonl_max_bytes` | `10485760` | Unchanged from P10.2 |
| `audit_jsonl_max_age_secs` | `0` | Opt-in; no surprise renames on quiet installs |

Segment age is tracked from file birth/open (or after a rotate). Checks run
on each successful write path (same as size).

## Behavior

| Trigger | Action |
|---------|--------|
| Size ≥ `max_bytes` (>0) | Rotate → `*.jsonl.1` |
| Segment age ≥ `max_age_secs` (>0) | Rotate → `*.jsonl.1` |
| Both off (`0`) | Never rotate |

Only one backup name (`*.jsonl.1`) is kept (same as size-only).

## Tests

- `src/audit` `rotates_when_max_bytes_exceeded`
- `src/audit` `rotates_when_max_age_exceeded`

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib rotates_when_max"
```
