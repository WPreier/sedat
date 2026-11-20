# Phase 2 – HTTP/1.1 Proxy Core

## 1. Ziel / Nicht-Ziele

**Ziel:** Listener, routing, forward to mock upstream, embedded 404.

**Nicht-Ziele:** TLS, PROXY (still optional `off` for tests).

## 2. Defaults

- Unknown Host → 404 (embedded page)
- Header/body caps from `[limits]`
- Path traversal → 400

## 3. Testmatrix

| Art | Test |
|-----|------|
| Unit | router longest-prefix, unknown host |
| Integration | `tests/proxy_h1.rs` mock upstream |
| Negativ | traversal / absolute-URI mismatch |

## 4. Beispiel

See `examples/proxy_h1/`.

## 5. Spec-Diff

`ARCHITECTURE.md` module map; `CONNECTION.md` mock-seda note.

## 6. Risiken

Manual HTTP/1.1 upstream writer (MVP); upgrade to hyper client later if needed.
