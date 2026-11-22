# SeDat – Roadmap P16 (ops visibility)

Follow-ups after **P15** (restart-required drift in v0.1.34). Source: empty
IDEAS ops backlog + hardening visibility.
**E9** stays rejected.

Implement as **separate steps**; after each: Zwischenfazit, verify, patch bump,
commit + push/PR, wait for review.

## Suggested order

```text
P16.1 Prometheus restart_required gauge   ← done (v0.1.35)
P16.2 config_reload restart_required JSONL ← done (v0.1.36)
P16.3 Prometheus uptime + bans_active     ← next
… later: remaining ops/hardening …
```

## Step breakdown

### P16.1 – Prometheus `sedat_restart_required` gauge

| | |
|--|--|
| **Status** | **done** (v0.1.35) |
| **Behavior** | Expose `sedat_restart_required{key="…"}` (0/1) for all boot-bound keys from the P15.3 snapshot |
| **Phase note** | [phases/P16_01_restart_required_gauge.md](phases/P16_01_restart_required_gauge.md) |
| **Depends on** | P15.3 (v0.1.34) |

### P16.2 – `restart_required` on config_reload JSONL

| | |
|--|--|
| **Status** | **done** (v0.1.36) |
| **Behavior** | `config_reload` audit events include `restart_required: […]` for SIEM/log alerts |
| **Phase note** | [phases/P16_02_reload_restart_required_audit.md](phases/P16_02_reload_restart_required_audit.md) |
| **Depends on** | P15.3 (v0.1.34) |

### P16.3 – Prometheus uptime + bans_active

| | |
|--|--|
| **Status** | **planned** |
| **Behavior** | Expose `sedat_uptime_seconds` and `sedat_bans_active` gauges on admin/metrics for ops dashboards |
| **Depends on** | — |

## Status board

| Step | Item | Status |
|------|------|--------|
| 1 | Prometheus restart_required gauge | **done** (v0.1.35) |
| 2 | config_reload restart_required JSONL | **done** (v0.1.36) |
| 3 | Prometheus uptime + bans_active | planned |
