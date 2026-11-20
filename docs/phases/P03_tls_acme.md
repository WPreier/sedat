# Phase 3 – TLS & ACME DNS-01

## 1. Ziel / Nicht-Ziele

**Ziel:** rustls TLS, SNI, cert hot-swap, ACME DNS-01 via `instant-acme`, Pebble-ready.

**Nicht-Ziele:** HTTP-01 as sole challenge; OCSP hard dependency.

## 2. Defaults

- TLS 1.2 + 1.3, ALPN `h2`, `http/1.1`
- ACME directory `staging` in examples
- DNS provider `file` (+ Cloudflare stub)
- Failed renew keeps previous cert

## 3. Testmatrix

| Art | Test |
|-----|------|
| Unit | self-signed loads into rustls |
| Integration | self-signed install + failed order retains cert |
| Compose | Pebble profile (manual/E2E) |

## 4. Beispiel

`examples/acme_staging/`

## 5. Spec-Diff

`SECURITY.md` TLS policy; ACME paths under state dir.

## 6. Risiken

Full CSR finalize against live LE needs network; offline CI uses self-signed + account/DNS present paths.
