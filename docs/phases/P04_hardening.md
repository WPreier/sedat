# Phase 4 – Hardening & Limits

## 1. Ziel / Nicht-Ziele

**Ziel:** Privilege drop, limits, rate-limit, non-blocking logs, systemd/Docker harden.

**Nicht-Ziele:** Landlock/seccomp (IDEAS).

## 2. Defaults

- Token bucket per IP; connection cap; header/body caps
- Drop after bind when `server.user` set (Linux)
- Docker: `cap_drop: [ALL]`, `no-new-privileges`, read-only

## 3. Testmatrix

| Art | Test |
|-----|------|
| Unit | rate burst, connection guard, drop skip/unsupported |
| Example | `examples/hardening/*.py` |
| Platform | privilege drop skipped on Windows |

## 4. Beispiel

See `examples/hardening/README.md`.

## 5. Spec-Diff

Full threat model in `docs/THREAT_MODEL.md`; checklist in `SECURITY.md`; `OPERATIONS.md` systemd/Docker. Attack tests: `tests/attack_hygiene.rs`.

## 6. Risiken

systemd notify is best-effort without libsystemd.
