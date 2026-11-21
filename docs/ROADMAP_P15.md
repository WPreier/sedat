# SeDat – Roadmap P15 (ops / CI hardening)

Follow-ups after **P14 complete** (v0.1.30). Source: CI reliability + [IDEAS.md](IDEAS.md).
**E9** stays rejected.

Implement as **separate steps**; after each: Zwischenfazit, verify, patch bump,
commit + push/PR, wait for review.

## Suggested order

```text
P15.1 Stabilize Pebble CI        ← done (v0.1.31)
… later: remaining ops/hardening from IDEAS …
```

## Step breakdown

### P15.1 – Stabilize Pebble CI

| | |
|--|--|
| **Status** | **done** (v0.1.31) |
| **Behavior** | Fix Compose Pebble command for current image ENTRYPOINT; harden CI wait/diagnostics so ACME issuance is reliable |
| **Phase note** | [phases/P15_01_pebble_ci_stabilize.md](phases/P15_01_pebble_ci_stabilize.md) |

## Status board

| Step | Item | Status |
|------|------|--------|
| 1 | Stabilize Pebble CI | **done** (v0.1.31) |
