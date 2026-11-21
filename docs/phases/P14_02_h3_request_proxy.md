# P14.2 – HTTP/3 request proxy (h3 / h3-quinn)

## Summary

`h3-quinn` **0.0.10** builds against quinn 0.11, so the experimental QUIC
listener can drive real HTTP/3 requests instead of accept/limit-only.

| Piece | Behavior |
|-------|----------|
| Feature `http3` | Optional deps: `quinn` + `h3` 0.0.8 + `h3-quinn` 0.0.10 |
| Accept path | Same caps: `max_h3_connections` / `max_h3_streams` |
| Per request | Resolve H3 request → buffer body (≤ `max_body_bytes`) → `proxy::handle_request` → send response |
| TLS | Snapshot from `TlsState`; ALPN forced to `h3` for QUIC |

## Limits / non-goals

- Request/response bodies were fully buffered in this step; **P14.3** streams
  them on the H3 edge.
- Still behind `experimental.h3` + feature flag; h1/h2 remain primary.
- Attack corpus (P13.1) unchanged in intent; still exercises caps.

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --features http3 --test h3_proxy --test h3_attack_corpus -- --nocapture"
```
