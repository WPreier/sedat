# SeDat – Roadmap P14 (post-P13)

Follow-ups after **P13 complete** (v0.1.24). Source: [IDEAS.md](IDEAS.md).
**E9** stays rejected.

Implement as **separate steps**; after each: Zwischenfazit, verify, patch bump,
commit + push/PR, wait for review.

## Suggested order

```text
P14.1 Broaden hot-reload         ← done (v0.1.25)
P14.2 H3 full request proxy      ← done (v0.1.26; h3-quinn 0.0.10)
P14.3 H3 streamed bodies         ← done (v0.1.27)
P14.4 TCP upstream body stream   ← done (v0.1.28)
P14.5 Upstream chunked decode    ← done (v0.1.29)
P14.6 Hot-reload remaining knobs ← done (v0.1.30)
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

### P14.3 – HTTP/3 streamed bodies

| | |
|--|--|
| **Status** | **done** (v0.1.27) |
| **Behavior** | Stream H3 request/response bodies (no full edge buffer); `max_body_bytes` fail-closed → 413 |
| **Phase note** | [phases/P14_03_h3_streamed_bodies.md](phases/P14_03_h3_streamed_bodies.md) |

### P14.4 – TCP upstream body streaming

| | |
|--|--|
| **Status** | **done** (v0.1.28) |
| **Behavior** | Chunked request write + channel-streamed upstream response; oversize → 413 |
| **Phase note** | [phases/P14_04_tcp_upstream_stream.md](phases/P14_04_tcp_upstream_stream.md) |

### P14.5 – Upstream chunked decode

| | |
|--|--|
| **Status** | **done** (v0.1.29) |
| **Behavior** | Decode upstream `Transfer-Encoding: chunked` into streamed payload; TE > CL |
| **Phase note** | [phases/P14_05_upstream_chunked_decode.md](phases/P14_05_upstream_chunked_decode.md) |

### P14.6 – Hot-reload remaining knobs

| | |
|--|--|
| **Status** | **done** (v0.1.30) |
| **Behavior** | Ban-share store swap (fail-closed) + live ACME config when loop started; document remaining restart-only |
| **Phase note** | [phases/P14_06_hot_reload_remaining.md](phases/P14_06_hot_reload_remaining.md) |

## Status board

| Step | Item | Status |
|------|------|--------|
| 1 | Broaden hot-reload | **done** (v0.1.25) |
| 2 | H3 full request proxy | **done** (v0.1.26) |
| 3 | H3 streamed bodies | **done** (v0.1.27) |
| 4 | TCP upstream body streaming | **done** (v0.1.28) |
| 5 | Upstream chunked decode | **done** (v0.1.29) |
| 6 | Hot-reload remaining knobs | **done** (v0.1.30) |
