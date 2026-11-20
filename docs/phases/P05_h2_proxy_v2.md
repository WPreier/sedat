# Phase 5 – HTTP/2 + PROXY v2

## 1. Ziel / Nicht-Ziele

**Ziel:** Frontend HTTP/2 (ALPN), outbound PROXY v2, inbound allowlist default off.

**Nicht-Ziele:** Blind X-Forwarded-For trust.

## 2. Defaults

- `proxy_protocol.outbound = "v2"`
- `inbound_enabled = false` (fail-closed if enabled without CIDRs)
- Accept path probes PROXY v1/v2; untrusted/disabled → connection drop (`accept_with_inbound_proxy`)

## 3. Testmatrix

| Art | Test |
|-----|------|
| Unit | PROXY v1/v2 byte layout |
| Integration | Mock-Seda trust check (Compose) |
| Negativ | spoof from untrusted IP → 403 at Mock-Seda |

## 4. Beispiel

Compose SeDat → mock-seda; see `deploy/mock-seda/server.py`.

## 5. Spec-Diff

`CONNECTION.md` trust boundary tests.

## 6. Risiken

Inbound PROXY parser on SeDat edge not fully wired (policy documented; default deny).
