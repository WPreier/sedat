# Phase 9 – Hardening & Ops (P09.1–P09.7)

Master plan: [ROADMAP_P09.md](../ROADMAP_P09.md).

## 1. Ziel / Nicht-Ziele

**Ziel:** Landlock/seccomp after drop, Prometheus via admin/loopback, Pebble CI issuance, H2 attack corpus, admin group ACL, PROXY-after-TLS mode, config-diff audit on reload.

**Nicht-Ziele:** Public metrics HTTP; mandatory sandbox on unsupported kernels; LE staging network in CI.

## 2. Defaults (fail-closed)

| Key | Default |
|-----|---------|
| `hardening.landlock` / `seccomp` | `auto` (skip if unsupported) |
| `server.admin_group` | unset → socket `0600` |
| `server.metrics_listen` | unset (off); if set → loopback only |
| `proxy_protocol.inbound_enabled` | `false` |
| `proxy_protocol.inbound_placement` | `before_tls` |
| Reload | previous active kept on error; audit log on success |

## 3. Testmatrix

| Art | Coverage |
|-----|----------|
| Unit | sandbox skip, security_diff, metrics format, admin mode, inbound placement validation |
| Integration | PROXY after TLS, H2 continuation corpus, admin metrics |
| CI | Pebble issuance job / script |
| Docker | `cargo test` via `deploy/Dockerfile.dev` |

## 4. Spec-Diff

See ROADMAP_P09 + updates to SECURITY / OPERATIONS / CONFIG / THREAT_MODEL / IDEAS.

## 5. Risiken

- Landlock ABI variance across kernels → `auto` must never break CI.
- Full ACME finalize needs reachable Pebble; offline tests keep self-signed path.
- PROXY-after-TLS changes accept ordering — default remains before_tls + inbound off.
