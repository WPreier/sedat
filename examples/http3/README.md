# Phase 6 – HTTP/3 (experimental)

Build with feature flag:

```bash
cargo build --features http3
```

Config:

```toml
[experimental]
h3 = true
```

Firewall: allow **UDP 443** (or your `listen_tls` port).

Smoke with curl (if built with HTTP/3):

```bash
curl --http3 -k https://127.0.0.1:8443/ -H 'Host: localhost'
```

If UDP is blocked, clients fall back to HTTP/2 over TCP (ALPN `h2`).
H3 has separate `limits.max_h3_connections` / `max_h3_streams`.
