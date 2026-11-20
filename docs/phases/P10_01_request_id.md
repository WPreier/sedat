# P10.1 – Request-ID über PROXY

## Summary

SeDat assigns a correlation id to each proxied request, forwards it to the
upstream as an HTTP header **after** any outbound PROXY framing, echoes it on
the client response, and includes it in structured logs.

## Header vs PROXY TLV

| Choice | Decision |
|--------|----------|
| **Primary** | HTTP header `x-request-id` (configurable via `logging.request_id_header`) |
| **PROXY v2 TLV** | **Not used** |

Rationale: an HTTP header works with outbound PROXY `off`, `v1`, and `v2`; Seda
and Mock-Seda already speak HTTP; operators and CDNs already understand
`x-request-id`. A custom PP2 TLV would require upstream parser support and would
not apply when PROXY is off.

Wire order on the upstream TCP stream:

```text
[PROXY v1/v2 header bytes | optional]
HTTP/1.1 request line + headers (including x-request-id) + body
```

## Behavior

- **Enabled by default** (`logging.request_id = true`).
- If the client sends a **valid** id (≤128 chars, `[A-Za-z0-9._-]+`), reuse it.
- Invalid / oversized inbound values are **discarded and replaced** (request still proceeds; fail-safe, not a hard reject).
- When disabled, no forced generation/injection (existing client headers pass through unchanged like other hop headers).

## Config

```toml
[logging]
level = "info"
request_id = true
request_id_header = "x-request-id"
```

## Tests

- Unit: `src/proxy/request_id.rs`
- Integration: `tests/proxy_h1.rs` (`forwards_and_echoes_request_id`, `propagates_client_request_id`)

## Verify

```bash
# Docker (recommended on Windows hosts without rustup)
docker run --rm -v "%CD%":/src -w /src rust:latest cargo test --test proxy_h1 request_id

# Or full suite
docker run --rm -v "%CD%":/src -w /src rust:latest cargo test
```
