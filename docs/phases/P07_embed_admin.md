# Phase 7 – Embedded Docs & Admin

## 1. Ziel / Nicht-Ziele

**Ziel:** `/sedat` `/seda` embed; Unix admin socket (status/health/metrics/reload/cert).

**Nicht-Ziele:** Public HTTP admin or public `/metrics`/`/health` control plane.

## 2. Defaults

- `embedded_docs.enabled = true`
- Admin socket mode `0600`

## 3. Testmatrix

| Art | Test |
|-----|------|
| Unit | docs on/off |
| Manual | socat status/reload (Linux) |

## 4. Beispiel

```bash
curl -H 'Host: localhost' http://127.0.0.1:8080/sedat
echo status | socat - UNIX-CONNECT:./state/admin.sock
```

## 5. Spec-Diff

REQUIREMENTS embed items; OPERATIONS admin section.

## 6. Risiken

Admin socket unavailable on native Windows (documented).
