# P10.7 – E1 optional Upstream mTLS

## Summary

Optional **HTTPS to upstream** with optional **client certificate (mTLS)**.
Safe defaults stay off: routes continue to use plaintext `http://` unless you
opt in. This is a *kann, nicht muss* hardening control for private upstreams.

## Config

```toml
[[routes.hosts.paths]]
prefix = "/"
# Default / recommended for Seda on a private net:
# upstream = "http://127.0.0.1:9080"

# Optional HTTPS upstream (TLS to backend):
upstream = "https://backend.internal:9443"
# Optional mTLS client identity (both or neither):
upstream_mtls_cert = "./certs/sedat-client.crt"
upstream_mtls_key  = "./certs/sedat-client.key"
# CA to verify the upstream server (recommended for private CAs).
# Empty → public webpki roots (not suitable for private CAs).
upstream_mtls_ca   = "./certs/upstream-ca.crt"
```

| Setting | Default | Meaning |
|---------|---------|---------|
| `upstream = "http://…"` | typical | Plaintext (unchanged) |
| `upstream = "https://…"` | opt-in | TLS after TCP connect |
| `upstream_mtls_cert` / `_key` | empty | Off; both required together for mTLS |
| `upstream_mtls_ca` | empty | webpki roots if HTTPS; set for private CA |

## Behavior

1. Resolve / optional IP pin (P10.6) → TCP connect.
2. For `https://`: **TLS ClientHello first** (outbound PROXY framing is skipped;
   set `proxy_protocol.outbound = "off"` for clarity when using HTTPS upstreams).
3. Optional client cert presented when cert+key paths are set.
4. HTTP/1.1 request (incl. request-id header) over the TLS stream.

Fail-closed: missing PEM files at config validate; TLS/handshake errors → 502.

## Security

- Default off — no new trust surface for existing `http://` deployments.
- Private CA via `upstream_mtls_ca` avoids trusting the public web PKI for
  internal backends.
- Combine with `upstream_allowlist` to pin peer IPs.

## Tests

- Unit: `src/proxy/upstream_mtls.rs`
- Validate: HTTPS allowed; mTLS on `http://` rejected
- Integration: `tests/upstream_mtls.rs` (mock mTLS upstream)

## Verify

```bash
docker run --rm -v "%CD%":/src -w /src rust:latest cargo test upstream_mtls
```
