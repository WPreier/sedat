# P14.4 – TCP upstream body streaming (chunked)

## Summary

After H3-edge streaming (P14.3), the TCP/HTTP/1.1 forward path still assembled
full request bodies before writing upstream. This step closes that gap:

| Direction | Behavior |
|-----------|----------|
| Request → upstream | `Transfer-Encoding: chunked`; frames written as they arrive; size vs `max_body_bytes` |
| Oversize request | Fail-closed → `ProxyError::BodyTooLarge` → client **413** |
| Upstream → client | Headers parsed first; body pumped through an mpsc channel (no `read_to_end`) under the same size cap |

Upstream `Transfer-Encoding: chunked` decoding is not implemented here; typical
`Content-Length` / connection-close bodies are streamed. H3 clients continue to
benefit because `proxy_request` no longer buffers the full request first.

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --test proxy_h1 --lib proxy::forward::tests -- --nocapture"
```

Expect POST chunked echo + oversize **413**, plus duplex unit tests.
