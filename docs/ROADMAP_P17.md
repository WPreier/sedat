# SeDat – Roadmap P17 (ops / security visibility)

Follow-ups after **P16 complete** (v0.1.37). Source: empty IDEAS ops table +
residual notes in [THREAT_MODEL.md](THREAT_MODEL.md) (health channel, T1/T13
abuse metrics, T10 sandbox).
**E9** stays rejected.

Implement as **separate steps**; after each: Zwischenfazit, verify, patch bump,
commit + push/PR, wait for review.

## Suggested order

```text
P17.1 health vs ready (restart_required)  ← done (v0.1.38)
P17.2 Prometheus proxy_deny counters      ← done (v0.1.39)
P17.3 Prometheus proxy_reject counters    ← done (v0.1.40)
P17.4 Prometheus rate_limit / ban hit counters ← done (v0.1.41)
P17.5 Selftest reports Landlock/seccomp mode ← done (v0.1.42)
```

## Step breakdown

### P17.1 – Split `health` / `ready`; ready fails on restart_required

| | |
|--|--|
| **Status** | **done** (v0.1.38) |
| **Behavior** | `health` = liveness (`OK healthy`, optional `restart_required` note). `ready` = readiness; `ERR not_ready restart_required=…` when boot-bound knobs drifted (same keys as P15.3) |
| **Phase note** | [phases/P17_01_ready_restart_required.md](phases/P17_01_ready_restart_required.md) |

### P17.2 – Prometheus `sedat_proxy_deny_total`

| | |
|--|--|
| **Status** | **done** (v0.1.39) |
| **Behavior** | Fixed-cardinality `sedat_proxy_deny_total{reason="…"}` for HTTP-path security denials |
| **Phase note** | [phases/P17_02_proxy_deny_counters.md](phases/P17_02_proxy_deny_counters.md) |

### P17.3 – Prometheus `sedat_proxy_reject_total`

| | |
|--|--|
| **Status** | **done** (v0.1.40) |
| **Behavior** | Fixed-cardinality `sedat_proxy_reject_total{reason,stage}` for pre-HTTP PROXY rejects |
| **Phase note** | [phases/P17_03_proxy_reject_counters.md](phases/P17_03_proxy_reject_counters.md) |

### P17.4 – Prometheus rate-limit / ban hit counters

| | |
|--|--|
| **Status** | **done** (v0.1.41) |
| **Behavior** | `sedat_rate_limited_total` / `sedat_ban_hits_total` for flood visibility (T13) |
| **Phase note** | [phases/P17_04_rate_ban_counters.md](phases/P17_04_rate_ban_counters.md) |

### P17.5 – Selftest Landlock/seccomp mode

| | |
|--|--|
| **Status** | **done** (v0.1.42) |
| **Behavior** | Selftest checks `hardening_landlock` / `hardening_seccomp` (PASS with mode detail; FAIL on invalid enum) |
| **Phase note** | [phases/P17_05_selftest_sandbox_modes.md](phases/P17_05_selftest_sandbox_modes.md) |

## Status board

| Step | Item | Status |
|------|------|--------|
| 1 | health vs ready (restart_required) | **done** (v0.1.38) |
| 2 | Prometheus proxy_deny counters | **done** (v0.1.39) |
| 3 | Prometheus proxy_reject counters | **done** (v0.1.40) |
| 4 | Prometheus rate_limit / ban hit counters | **done** (v0.1.41) |
| 5 | Selftest Landlock/seccomp mode | **done** (v0.1.42) |
