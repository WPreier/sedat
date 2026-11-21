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
| **Status** | **done** (v0.1.18) |
| **Behavior** | Extend ban TTL when abuse continues while already banned (`ban_extend_while_banned`, JSONL `ip_ban_extend`) |
| **Phase note** | [phases/P12_02_sliding_bans.md](phases/P12_02_sliding_bans.md) |

### P12.3 – Token rotation without reload

| | |
|--|--|
| **Status** | **done** (v0.1.19) |
| **Behavior** | Admin `reload-token` re-reads env/file/config into live gate; dual-token overlap; fail-closed if sources empty |
| **Phase note** | [phases/P12_03_token_rotation.md](phases/P12_03_token_rotation.md) |

### P12.4 – Time-based audit log rotation

| | |
|--|--|
| **Status** | **done** (v0.1.20) |
| **Behavior** | Age-based rotate via `audit_jsonl_max_age_secs` (default 0) beside size rotate |
| **Phase note** | [phases/P12_04_audit_age_rotate.md](phases/P12_04_audit_age_rotate.md) |

### P12.5 – Upstream pin hostname + re-resolve

| | |
|--|--|
| **Status** | **done** (v0.1.21) |
| **Behavior** | Hostname literals in pin + cached DNS refresh (`upstream_dns_refresh_secs`); fail-closed if expanded pin empty / peer leaves set |
| **Phase note** | [phases/P12_05_upstream_pin_reresolve.md](phases/P12_05_upstream_pin_reresolve.md) |

### P12.6 – Shared ban state across replicas

| | |
|--|--|
| **Status** | pending (large) |
| **Behavior** | Share temporary bans across SeDat instances |

## Status board

| Step | Item | Status |
|------|------|--------|
| 1 | Metrics-sidecar token | **done** (v0.1.17) |
| 2 | Sliding / extending bans | **done** (v0.1.18) |
| 3 | Token rotation w/o reload | **done** (v0.1.19) |
| 4 | Time-based audit rotate | **done** (v0.1.20) |
| 5 | Upstream pin re-resolve | **done** (v0.1.21) |
| 6 | Shared ban state | pending |
