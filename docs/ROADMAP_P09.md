# SeDat – Roadmap P09 (Post-MVP Hardening)

Phase **P09** closes residual security/ops gaps called out after P08 and in [IDEAS.md](IDEAS.md).
This document is the reviewable plan; detailed phase notes live under `docs/phases/P09_*.md`.

**Do not edit** the Cursor plan file `sedat_phasenplan_*.plan.md` — this repo roadmap is the source of truth for P09.

## Goals / Non-goals

**Goals**

1. Shrink RCE blast radius after privilege drop (Landlock + seccomp, Linux).
2. Prometheus-compatible metrics without a public metrics listener.
3. Reproducible ACME issuance in CI via Pebble (no LE staging network).
4. Negative HTTP/2 Continuations / HPACK-bomb corpus beyond hyper defaults.
5. Admin socket Group-ACL (`0660` + group) with secure defaults.
6. Documented & tested inbound PROXY-after-TLS (PP2 over TLS) mode; fail-closed defaults.
7. Config-diff audit on reload for trust-boundary / security-relevant keys.

**Non-goals**

- Public HTTP `/metrics` or `/health` control plane.
- Mandatory Landlock/seccomp on non-Linux or old kernels (graceful skip).
- Schema bump unless a breaking semantic change is required (P09 adds optional fields with defaults).

## Dependency order

```text
P09.5 Admin Group-ACL ──┐
P09.7 Config-Diff audit ┼─► early (config/admin surface)
P09.6 PROXY-after-TLS ──┘
         │
P09.2 Prometheus admin scrape (needs stable admin metrics)
         │
P09.1 Landlock/seccomp (after drop; needs state/admin paths known)
         │
P09.4 H2 attack corpus (independent tests)
P09.3 Pebble CI issuance (independent; needs ACME order_once completion)
```

Suggested implementation order: **5 → 7 → 6 → 2 → 1 → 4 → 3** (admin/config first, then sandbox, then corpora/CI).

---

## Phase breakdown (items 1–7)

### P09.1 – Landlock / seccomp after privilege drop

| | |
|--|--|
| **Depends on** | Privilege drop (`src/hardening`); known `state_dir`, cert paths, admin socket |
| **Config** | `[hardening] landlock = "auto"|"off"|"required"`, `seccomp = "auto"|"off"|"required"` (default `auto`) |
| **Behavior** | After successful/skipped drop: apply Landlock FS rules (RO config/certs where needed, RW `state_dir`); set `NO_NEW_PRIVS` + minimal seccomp if available. Unsupported kernel → log + continue when `auto`; hard-fail when `required`. Non-Linux → skip. |
| **Exit criteria** | Unit tests for skip/unsupported; Linux Docker path exercises `auto` without failing CI on missing Landlock; docs in SECURITY/OPERATIONS |
| **Tests** | `src/hardening` unit tests; optional Linux-only integration under Docker |

### P09.2 – Prometheus via Admin-Socket (loopback sidecar)

| | |
|--|--|
| **Depends on** | Admin `metrics` command |
| **Config** | `[server] metrics_listen` optional (`""` / unset = off). Bind **loopback only** (validation fail-closed for non-loopback). |
| **Behavior** | Admin `metrics` emits Prometheus text exposition. Optional tiny HTTP sidecar on loopback serves `GET /metrics` by formatting the same counters (no public bind). Script `scripts/prometheus_admin_scrape.sh` for socat-based scrape. |
| **Exit criteria** | Metrics parseable by Prometheus; public `/metrics` still absent; loopback sidecar optional |
| **Tests** | Admin metrics unit test; validation rejects non-loopback `metrics_listen`; attack_hygiene keeps “no public metrics” |

### P09.3 – Fully automated Pebble issuance in CI

| | |
|--|--|
| **Depends on** | ACME `order_once` completing DNS-01 with `instant-acme`; Compose `pebble` |
| **Behavior** | Complete order/challenge/finalize path; with `PEBBLE_VA_ALWAYS_VALID=1` file DNS + Pebble is enough. GitHub Actions job + `scripts/ci_pebble_issue.sh` / compose profile. |
| **Exit criteria** | CI job obtains a cert under `state/` without contacting LE; reproducible locally |
| **Tests** | CI workflow job `pebble-issue`; unit tests keep self-signed / fail-closed retention |

### P09.4 – HTTP/2 Continuations / HPACK-bomb corpus

| | |
|--|--|
| **Depends on** | HTTPS/h2 accept path |
| **Behavior** | Corpus of negative frames: CONTINUATION flood, oversized header block, HPACK bomb shapes. Expect connection close / bounded resource use (no panic/OOM in test harness). |
| **Exit criteria** | `tests/h2_attack_corpus.rs` (or equivalent) green under Docker `cargo test` |
| **Tests** | Integration against `serve_https` with self-signed ALPN h2 |

### P09.5 – Admin-Socket Group-ACL

| | |
|--|--|
| **Depends on** | Admin bind path |
| **Config** | `[server] admin_group` optional. No group → mode `0600` (default). Group set → `chown` group + mode `0660`. |
| **Exit criteria** | Documented; unit/integration checks mode bits on Unix |
| **Tests** | Unix permission assertions in admin tests |

### P09.6 – Inbound PROXY only after TLS (PP2 over TLS)

| | |
|--|--|
| **Depends on** | Inbound PROXY probe; TLS accept loop |
| **Config** | `[proxy_protocol] inbound_placement = "before_tls"|"after_tls"` (default `before_tls`). Still requires `inbound_enabled` + allowlist. When `after_tls`, plaintext listener never trusts PROXY; HTTPS probes PROXY **after** handshake on the decrypted stream. |
| **Exit criteria** | Docs + tests for after_tls accept and before_tls fail-closed defaults |
| **Tests** | Extended `tests/attack_hygiene.rs` / proxy_protocol tests |

### P09.7 – Config-Diff audit on reload

| | |
|--|--|
| **Depends on** | `try_reload` / admin `reload` |
| **Behavior** | Diff previous vs new config for trust-boundary keys (listen, PROXY inbound, ACME, admin socket/group, hardening, routes upstreams, limits caps). Emit structured audit log lines. Fail-closed reload unchanged. |
| **Exit criteria** | Reload logs/returns audit summary; bad reload still keeps active |
| **Tests** | Unit tests for `security_diff`; admin reload path |

---

## Extra ideas (proposed / not yet implemented)

These are **out of P09 scope** unless marked trivial and implemented later.

| # | Idea | Rationale |
|---|------|-----------|
| E1 | **mTLS to upstream Seda** | Closes private-net spoofing if an attacker reaches the upstream L3 segment. |
| E2 | **ACME ARI (Renewal Info)** | Reduces mass-renewal spikes; nicer ops when CA supports it. |
| E3 | **Per-route upstream allowlist (DNS/IP pin)** | Prevents config-reload SSRF if an editor is compromised. |
| E4 | **Admin socket capability tokens** | Defense-in-depth beyond FS ACL (e.g. first-line `AUTH <token>`). |
| E5 | **Structured audit log sink (JSONL file)** | Complements P09.7 for SIEM; rotate under `state_dir`. |
| E6 | **Runtime self-test endpoint (admin-only)** | `selftest` command: PROXY probe, TLS ALPN, limit counters — ops confidence after deploy. |
| E7 | **Seccomp profile library (generate + ship)** | Ship known-good profiles per release for `required` mode on hardened hosts. |
| E8 | **HTTP/3 amplification / QUIC storm corpus** | Mirror P09.4 for UDP when `http3` is on. |
| E9 | **Config signing (ed25519)** | Optional signature over active TOML so only signed configs activate. |

---

## Doc & test deliverables

- Update: `SECURITY.md`, `OPERATIONS.md`, `CONFIG.md`, `THREAT_MODEL.md`, `IDEAS.md`
- Phase notes: `docs/phases/P09_*.md` (this roadmap + per-item files as needed)
- Linux/Docker: `cargo test` (and CI Pebble job when feasible)

## Status

| Item | Status |
|------|--------|
| P09.1 Landlock/seccomp | **implemented** (`src/hardening`, `[hardening]`) |
| P09.2 Prometheus admin/sidecar | **implemented** (`src/admin`, `scripts/prometheus_admin_scrape.sh`) |
| P09.3 Pebble CI issuance | **implemented** (`order_once` DNS-01, CI job, compose `pebble-issue`) |
| P09.4 H2 Continuations corpus | **implemented** (`tests/h2_attack_corpus.rs`) |
| P09.5 Admin Group-ACL | **implemented** (`server.admin_group`, `0660`) |
| P09.6 PROXY after TLS | **implemented** (`inbound_placement`) |
| P09.7 Config-Diff audit | **implemented** (`config::security_diff`) |
