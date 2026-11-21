# SeDat – Roadmap P14 (post-P13)

Follow-ups after **P13 complete** (v0.1.24). Source: [IDEAS.md](IDEAS.md).
**E9** stays rejected.

Implement as **separate steps**; after each: Zwischenfazit, verify, patch bump,
commit + push/PR, wait for review.

## Suggested order

```text
P14.1 Broaden hot-reload      ← done (v0.1.25)
P14.2 H3 full request proxy   ← done (v0.1.26; h3-quinn 0.0.10)
… later: remaining ops/hardening from IDEAS …
```

## Step breakdown

### P14.1 – Broaden hot-reload

| | |
|--|--|
| **Status** | **done** (v0.1.25) |
| **Behavior** | Admin/`SIGHUP` reload applies live limits + optional static cert swap; document restart-only knobs |
| **Phase note** | [phases/P14_01_hot_reload_broaden.md](phases/P14_01_hot_reload_broaden.md) |

### P14.2 – HTTP/3 request proxy

| | |
|--|--|
| **Status** | **done** (v0.1.26) |
| **Behavior** | Feature `http3` wires `h3` + `h3-quinn`; accepted streams go through `handle_request` with body/stream caps |
| **Phase note** | [phases/P14_02_h3_request_proxy.md](phases/P14_02_h3_request_proxy.md) |

## Status board

| Step | Item | Status |
|------|------|--------|
| 1 | Broaden hot-reload | **done** (v0.1.25) |
| 2 | H3 full request proxy | **done** (v0.1.26) |
