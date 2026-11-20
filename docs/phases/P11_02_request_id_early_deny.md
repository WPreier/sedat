# P11.2 – Request-ID on early denial paths

## Summary

Every HTTP denial that SeDat answers (handler denials **and** pre-hyper early
rejects) now carries the configured correlation header (default `x-request-id`)
when `logging.request_id = true`, and the same id is written to JSONL
`proxy_deny` / related audit fields and tracing.

## Coverage

| Path | Status | Header | Audit |
|------|--------|--------|-------|
| Rate limit | 429 | yes (`deny_response`) | `proxy_deny` / `rate_limit` |
| Temporary IP ban | 403 | yes | `proxy_deny` / `ip_banned` (+ `ip_ban`) |
| Smuggling (handler CL+TE) | 400 | yes | `proxy_deny` / `smuggling` |
| **Smuggling (pre-hyper raw)** | 400 | **yes (new)** | **yes (new)** |
| Header bomb (handler) | 431 | yes | `proxy_deny` / `header_bomb` |
| **Incomplete / oversized header block (pre-hyper)** | 431 | **yes (new)** | **yes (new)** |
| Absolute-URI / Host mismatch, path traversal, missing Host | 400 | yes | yes |
| SNI/Host mismatch | 421 | yes | yes |
| Unknown host/path | 404 | yes | yes |
| Upstream / pin failure | 502 | yes | yes |

Still out of scope (pre-HTTP, no response body): connection-cap drop, inbound
PROXY reject → **P11.3** (PROXY-reject JSONL).

## Pre-hyper behavior

Before hyper parses the request, SeDat reads a raw header block:

1. If the block is incomplete at `max_header_bytes` → **431** + `request_id`
2. If CL+TE conflict → **400** + `request_id`
3. Id is reused from a valid inbound header in the raw block, else generated

## Tests

- Unit: `src/proxy/request_id` `raw_header_reuses_and_generates`
- Integration: `tests/attack_hygiene` (`smuggling_cl_te_rejected`, `header_bomb_echoes_request_id`)
- Integration: `tests/audit_jsonl` (`rate_limit_…`, `early_smuggling_writes_audit_with_request_id`)

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest sh -c \
  "cargo test --lib raw_header_reuses && cargo test --test attack_hygiene smuggling_cl_te && cargo test --test attack_hygiene header_bomb_echoes && cargo test --test audit_jsonl"
```
