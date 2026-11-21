# SeDat – Roadmap P15 (ops / CI hardening)

Follow-ups after **P14 complete** (v0.1.30). Source: CI reliability + [IDEAS.md](IDEAS.md).
**E9** stays rejected.

Implement as **separate steps**; after each: Zwischenfazit, verify, patch bump,
commit + push/PR, wait for review.

## Suggested order

```text
P15.1 Stabilize Pebble CI        ← done (v0.1.31–0.1.32)
… later: remaining ops/hardening from IDEAS …
```

## Step breakdown

### P15.1 – Stabilize Pebble CI

| | |
|--|--|
| **Status** | **done** (v0.1.32) |
| **Behavior** | Fix Compose Pebble ENTRYPOINT + User-Agent; pin `pebble:2.7.0`; harden CI wait/diagnostics |
| **Phase note** | [phases/P15_01_pebble_ci_stabilize.md](phases/P15_01_pebble_ci_stabilize.md) |

## Status board

| Step | Item | Status |
|------|------|--------|
| 1 | Stabilize Pebble CI | **done** (v0.1.32) |
