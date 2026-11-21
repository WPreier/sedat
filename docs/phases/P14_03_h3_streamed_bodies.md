# P14.3 – HTTP/3 streamed bodies

## Summary

P14.2 proxied H3 requests but assembled the full request body before
`handle_request` and collected the full response before `send_data`. This step
streams on the H3 edge:

| Direction | Behavior |
|-----------|----------|
| Request | H3 DATA frames → mpsc → `H3ChanBody` (hyper `Body`); running size vs `max_body_bytes` |
| Oversize | Fail-closed: stop reading, answer **413 Payload Too Large** |
| Response | `Body::frame` loop → `send_data` (no `collect`); same size cap |

TCP upstream buffering for HTTP/1.1 is addressed in **P14.4** (chunked write +
streamed response). Proxy success path no longer re-buffers the upstream
response when attaching request-id headers.

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --features http3 --test h3_proxy -- --nocapture"
```

Expect GET + POST stream + oversize **413**.
