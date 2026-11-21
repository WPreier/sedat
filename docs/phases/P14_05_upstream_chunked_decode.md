# P14.5 – Upstream `Transfer-Encoding: chunked` decode

## Summary

P14.4 streamed upstream response bytes but treated chunked framing as opaque
payload when `Transfer-Encoding: chunked` was present (headers were stripped,
body not decoded). This step decodes chunked upstream responses end-to-end:

| Behavior | Detail |
|----------|--------|
| Detect | `Transfer-Encoding` containing `chunked` (RFC 9112: ignores `Content-Length`) |
| Decode | Hex size lines + data + CRLF; trailers after `0` chunk discarded |
| Stream | Decoded payload frames via the existing mpsc body under `max_body_bytes` |
| Fail-closed | Chunk that would exceed the limit → body error / no silent truncate |

Forwarded client headers never include upstream `Transfer-Encoding` or a stale
`Content-Length` when the mode was chunked.

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib proxy::forward::tests -- --nocapture"
```

Expect `decodes_upstream_chunked_response` + oversize chunked + prior CL tests.
