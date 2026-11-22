# SeDat – Roadmap P16 (ops visibility)

Follow-ups after **P15** (restart-required drift in v0.1.34). Source: empty
IDEAS ops backlog + hardening visibility.
**E9** stays rejected.

Implement as **separate steps**; after each: Zwischenfazit, verify, patch bump,
commit + push/PR, wait for review.

## Suggested order

```text
P16.1 Prometheus restart_required gauge   ← next
… later: remaining ops/hardening …
```

## Step breakdown

### P16.1 – Prometheus `sedat_restart_required` gauge

| | |
|--|--|
| **Status** | **planned** |
| **Behavior** | Expose `sedat_restart_required{key="…"}` (or a single gauge + labeled keys) from the same boot-vs-live snapshot as P15.3, so scrapers/alerts catch restart-only drift without parsing admin text |
| **Depends on** | P15.3 (v0.1.34) |

## Status board

| Step | Item | Status |
|------|------|--------|
| 1 | Prometheus restart_required gauge | planned |
