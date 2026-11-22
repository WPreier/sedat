# P17.6 – Install / Update / Beispiel-Config Docs

| | |
|--|--|
| **Status** | **done** (v0.1.43) |
| **Scope** | Dokumentation only (kein Runtime-Verhalten) |

## Deliverables

- [docs/INSTALL.md](../INSTALL.md) – Linux-primär: Build, systemd, Privilege-Drop,
  State-Dirs, Firewall TCP/UDP 443, ACME staging, Verify (`selftest`/`health`/`ready`)
- [docs/UPDATE.md](../UPDATE.md) – git/binary Update, `--migrate-config`,
  Reload vs Restart / `restart_required`, Rollback
- [examples/config/full.example.toml](../../examples/config/full.example.toml) –
  annotiertes Schema-v1-Vollbeispiel (server, limits, logging/audit, routes, TLS/ACME
  DNS providers, proxy, embedded_docs, hardening, ban_share, experimental.h3)
- Cross-Links: README, CONFIG, OPERATIONS, DEV_SETUP, `examples/config/README.md`

## Notes

- Schema muss `src/config/schema.rs` entsprechen; keine erfundenen Keys.
- Nested `sedat/` / `.cursor/` nicht committen.
