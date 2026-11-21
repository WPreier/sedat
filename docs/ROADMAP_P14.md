# SeDat – Roadmap P14 (post-P13)

Follow-ups after **P13 complete** (v0.1.24). Source: [IDEAS.md](IDEAS.md).
**E9** stays rejected. Fuller HTTP/3 request proxy waits on compatible `h3-quinn`.

Implement as **separate steps**; after each: Zwischenfazit, verify, patch bump,
commit + push/PR, wait for review.

## Suggested order

```text
P14.1 Broaden hot-reload   ← live limits + static TLS + SIGHUP
… later: remaining ops/hardening from IDEAS …
```

## Step breakdown

### P14.1 – Broaden hot-reload

| | |
|--|--|
| **Status** | **done** (v0.1.25) |
| **Behavior** | Admin/`SIGHUP` reload applies live limits + optional static cert swap; document restart-only knobs |
| **Phase note** | [phases/P14_01_hot_reload_broaden.md](phases/P14_01_hot_reload_broaden.md) |

## Status board

| Step | Item | Status |
|------|------|--------|
| 1 | Broaden hot-reload | **done** (v0.1.25) |
