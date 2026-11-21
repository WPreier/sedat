# SeDat – Roadmap P12 (post-P11 backlog)

Follow-ups from [IDEAS.md](IDEAS.md) after **P11 complete** (v0.1.16).
**E8** stays later (large); **E9** stays rejected.

Implement as **separate steps**; after each: Zwischenfazit, verify, patch bump,
commit + push/PR, wait for review.

## Suggested order

```text
P12.1 Metrics-sidecar token     ← reuse admin token; Bearer on /metrics
P12.2 Sliding / extending bans  ← TTL refresh on strike while banned
P12.3 Token rotation w/o reload ← hot-swap admin (and metrics) token
P12.4 Time-based audit rotate   ← age rotate beside size rotate
P12.5 Upstream pin re-resolve   ← hostname literal + periodic DNS refresh
P12.6 Shared ban state (replicas) ← multi-instance (larger)
… later: E8 H3 corpus, multiple DNS providers …
```

## Step breakdown

### P12.1 – Metrics sidecar token

| | |
|--|--|
| **Status** | **done** (v0.1.17) |
| **Behavior** | When admin token is configured, loopback `GET /metrics` requires `Authorization: Bearer <token>` (fail-closed). Empty token → unchanged loopback-only. Admin Unix socket AUTH unchanged. |
| **Phase note** | [phases/P12_01_metrics_sidecar_token.md](phases/P12_01_metrics_sidecar_token.md) |

### P12.2 – Sliding / extending bans

| | |
|--|--|
| **Status** | pending |
| **Behavior** | Extend ban TTL when abuse continues while already banned |

### P12.3 – Token rotation without reload

| | |
|--|--|
| **Status** | pending |
| **Behavior** | Hot-swap admin/metrics token (file watch and/or admin command) |

### P12.4 – Time-based audit log rotation

| | |
|--|--|
| **Status** | pending |
| **Behavior** | Age-based rotate for `audit_jsonl` beside size rotate |

### P12.5 – Upstream pin hostname + re-resolve

| | |
|--|--|
| **Status** | pending |
| **Behavior** | Pin by hostname literal + periodic DNS refresh |

### P12.6 – Shared ban state across replicas

| | |
|--|--|
| **Status** | pending (large) |
| **Behavior** | Share temporary bans across SeDat instances |

## Status board

| Step | Item | Status |
|------|------|--------|
| 1 | Metrics-sidecar token | **done** (v0.1.17) |
| 2 | Sliding / extending bans | pending |
| 3 | Token rotation w/o reload | pending |
| 4 | Time-based audit rotate | pending |
| 5 | Upstream pin re-resolve | pending |
| 6 | Shared ban state | pending |
