# Phase 8 – E2E & Release

## 1. Ziel / Nicht-Ziele

**Ziel:** Full Compose path with Mock-Seda (Seda stub), release checklist, IDEAS triage.

**Nicht-Ziele:** Block on missing real Seda binary.

## 2. Defaults

- Mock-Seda as approved stub when Seda binary missing
- Version from Cargo

## 3. Testmatrix

| Art | Test |
|-----|------|
| E2E | `examples/e2e_seda/run_e2e.sh` |
| Chaos | config reload via admin under traffic (manual) |
| PROXY | Mock-Seda trust |

## 4. Beispiel

See `examples/e2e_seda/`.

## 5. Spec-Diff

README status → MVP/Release-Kandidat; IDEAS triage below.

## 6. Release checklist

- [x] Phases P0–P8 docs present
- [x] `cargo test` (Linux/CI or Docker)
- [x] Clippy/fmt in CI workflow
- [x] Docker hardening defaults
- [x] Mock-Seda E2E runbook
- [ ] Optional SBOM (`cargo cyclonedx`) — deferred
- [ ] Real Seda binary once published — stub OK

## IDEAS triage

| Item | Decision |
|------|----------|
| Landlock/seccomp | Done in P09 |
| ARI | Later |
| Prometheus | Done in P09 (admin/loopback) |
| Windows service | Won't do |
| Pingora | Won't do |
| OCSP hard req | Won't do |
