# Phase 6 – HTTP/3

## 1. Ziel / Nicht-Ziele

**Ziel:** Optional QUIC/H3 behind feature `http3` + `experimental.h3`.

**Nicht-Ziele:** H3 as primary path.

## 2. Defaults

- Off by default
- Separate `max_h3_connections` / `max_h3_streams`

## 3. Testmatrix

| Art | Test |
|-----|------|
| Build | `--features http3` |
| Smoke | QUIC accept + connection limit |
| Fallback | h2 when UDP blocked (client-side) |

## 4. Beispiel

`examples/http3/`

## 5. Spec-Diff

`OPERATIONS.md` firewall UDP 443; ADR-009.

## 6. Risiken

Request bridging shipped in **P14.2**; streamed bodies in **P14.3** (still
experimental / feature-gated). See
[P14_02_h3_request_proxy.md](P14_02_h3_request_proxy.md) and
[P14_03_h3_streamed_bodies.md](P14_03_h3_streamed_bodies.md).
