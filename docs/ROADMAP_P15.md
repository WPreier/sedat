# SeDat – Roadmap P15 (ops / CI hardening)

Follow-ups after **P14 complete** (v0.1.30). Source: CI reliability + [IDEAS.md](IDEAS.md).
**E9** stays rejected.

Implement as **separate steps**; after each: Zwischenfazit, verify, patch bump,
commit + push/PR, wait for review.

## Suggested order

```text
P15.1 Stabilize Pebble CI        ← done (v0.1.31–0.1.32)
P15.2 instant-acme 0.8 (token)   ← done (v0.1.33)
P15.3 Restart-required drift     ← done (v0.1.34)
… later: [ROADMAP_P16.md](ROADMAP_P16.md) …
```

## Step breakdown

### P15.1 – Stabilize Pebble CI

| | |
|--|--|
| **Status** | **done** (v0.1.32) |
| **Behavior** | Fix Compose Pebble ENTRYPOINT + User-Agent; pin `pebble:2.7.0`; harden CI wait/diagnostics |
| **Phase note** | [phases/P15_01_pebble_ci_stabilize.md](phases/P15_01_pebble_ci_stabilize.md) |

### P15.2 – instant-acme 0.8 (optional Challenge.token)

| | |
|--|--|
| **Status** | **done** (v0.1.33) |
| **Behavior** | Upgrade `instant-acme` so token-less challenges deserialize; unpin Pebble `:latest` |
| **Phase note** | [phases/P15_02_instant_acme_token.md](phases/P15_02_instant_acme_token.md) |

### P15.3 – Restart-required drift reporting

| | |
|--|--|
| **Status** | **done** (v0.1.34) |
| **Behavior** | Boot `RestartOnlySnapshot`; `status`/`reload` note + selftest fail when listen/sandbox/metrics/ACME-cold drift |
| **Phase note** | [phases/P15_03_restart_required_drift.md](phases/P15_03_restart_required_drift.md) |

## Status board

| Step | Item | Status |
|------|------|--------|
| 1 | Stabilize Pebble CI | **done** (v0.1.32) |
| 2 | instant-acme 0.8 (token) | **done** (v0.1.33) |
| 3 | Restart-required drift | **done** (v0.1.34) |
