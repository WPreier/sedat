# P11.3 – PROXY-reject JSONL audit

## Summary

When inbound PROXY framing is **rejected** (connection dropped before HTTP),
SeDat emits a JSONL `proxy_reject` event (when audit is enabled). This covers
injection attempts, untrusted peers, `after_tls` plaintext framing, and
malformed headers — including the HTTPS plaintext stage and post-TLS PP2 path.

## Event

```json
{
  "ts": "...",
  "v": 1,
  "event": "proxy_reject",
  "request_id": null,
  "peer": "127.0.0.1:54321",
  "reason": "untrusted_or_disabled",
  "stage": "plaintext"
}
```

| Field | Values |
|-------|--------|
| `reason` | `untrusted_or_disabled` · `plaintext_when_after_tls` · `malformed` |
| `stage` | `plaintext` (pre-TLS / HTTP accept) · `after_tls` (PP2-over-TLS probe) |
| `request_id` | always `null` (pre-HTTP) |

## API

Accept helpers now return `Result<(stream, addr), ProxyRejectReason>` inside
`io::Result` (instead of `Option`). Call sites in `serve_http` / `serve_https`
audit on `Err(reason)`.

## Tests

- Unit: `src/audit` `writes_proxy_reject`
- Integration: `tests/attack_hygiene` (`proxy_injection_*`, `plaintext_proxy_rejected_*`, `proxy_reject_writes_jsonl_audit`)

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib writes_proxy_reject && cargo test --test attack_hygiene proxy_"
```
