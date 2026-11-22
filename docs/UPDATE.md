# SeDat – Update-Anleitung

Ziel: SeDat und die User-Config **fail-closed** aktualisieren, Drift erkennen,
Rollback kennen. Primär **Linux/systemd**. Verwandt: [INSTALL.md](INSTALL.md) ·
[CONFIG.md](CONFIG.md) · [CHANGELOG.md](../CHANGELOG.md) · [OPERATIONS.md](OPERATIONS.md).

## Vor dem Update

1. **Changelog lesen** — [CHANGELOG.md](../CHANGELOG.md) und ggf. Phase-Notes unter
   `docs/phases/` für Breaking/Restart-Only-Hinweise.
2. **Backup**

```bash
sudo cp -a /etc/sedat/sedat.toml /etc/sedat/sedat.toml.bak.$(date +%F)
sudo cp -a /var/lib/sedat /var/lib/sedat.bak.$(date +%F)
# laufendes Binary
sudo cp -a /usr/local/bin/sedat /usr/local/bin/sedat.bak.$(date +%F)
```

3. **Aktuelle Version notieren**

```bash
sedat --version
# oder
/usr/local/bin/sedat --version
```

## Variante A: aus Git / Quellcode

```bash
cd /path/to/sedat
git fetch origin
git checkout main
git pull --ff-only origin main
cargo test
cargo build --release
# optional HTTP/3:
# cargo build --release --features http3
```

Binary austauschen (Downtime kurz):

```bash
sudo systemctl stop sedat
sudo install -m 0755 target/release/sedat /usr/local/bin/sedat
sudo systemctl start sedat
systemctl status sedat --no-pager
```

Oder ohne Stop, wenn Unit `ExecStart` auf Symlink zeigt und Reload reicht —
bei Binary-Wechsel ist **Restart** üblich und klarer.

## Variante B: Release-Binary / Image

1. Artifact von Release/CI laden und Signatur/Checksum prüfen (falls vorhanden).
2. Wie oben: stop → install → start.
3. Docker: neues Tag bauen/pullen, Compose/Unit mit neuem Image neu starten;
   `state`-Volume behalten.

## Config-Migration

Schema ist aktuell **`schema_version = 1`**. Unbekannte Versionen starten
**nicht** (fail-closed).

```bash
# User-TOML durch Migrator (heute: Identity für v1; Fehler bei unbekannt)
sudo sedat --config /etc/sedat/sedat.toml --migrate-config
sudo sedat --config /etc/sedat/sedat.toml --validate
```

Danach entweder:

- **Reload** (live-sichere Keys), oder
- **Prozess-Restart** (Listen/Sandbox/Metrics/ACME-cold).

Siehe [CONFIG.md](CONFIG.md) „Schema version & migration“.

## Reload vs. Restart

| Aktion | Wann |
|--------|------|
| Admin `reload` / `SIGHUP` | Routes, Limits, Ban-Share, Audit, Token, static TLS, live ACME-Knobs |
| **Restart** (`systemctl restart sedat`) | `server.listen*`, Landlock/seccomp, `metrics_listen`, ACME enable-from-cold |

Nach Reload prüfen:

```bash
echo status | socat - UNIX-CONNECT:/run/sedat/admin.sock
echo ready  | socat - UNIX-CONNECT:/run/sedat/admin.sock
echo selftest | socat - UNIX-CONNECT:/run/sedat/admin.sock
```

- Enthält `status`/`reload` **`restart_required=…`** oder schlägt `ready` /
  Selftest-Check `restart_required` fehl → Config ist geladen, aber Boot-Knobs
  wirken erst nach **Prozess-Restart** (P15.3 / P17.1).
- Metrics: `sedat_restart_required{key="…"}` (P16.1).

Token nur rotieren:

```bash
printf 'AUTH %s\nreload-token\n' "$SEDAT_ADMIN_TOKEN" \
  | socat - UNIX-CONNECT:/run/sedat/admin.sock
```

## Checkliste nach Update

```text
[ ] sedat --version == erwartete Version
[ ] --validate OK
[ ] systemctl is-active sedat
[ ] health → OK healthy
[ ] ready → OK ready (kein restart_required-Drift)
[ ] selftest → OK (inkl. hardening_landlock/seccomp)
[ ] Smoke: HTTPS/Upstream erreichbar
[ ] bei ACME: cert / ACME-Status prüfen (admin `cert`)
[ ] Metrics/Audit (falls genutzt) schreiben weiter
```

## Rollback

1. Altes Binary zurück:

```bash
sudo systemctl stop sedat
sudo cp -a /usr/local/bin/sedat.bak.YYYY-MM-DD /usr/local/bin/sedat
sudo systemctl start sedat
```

2. Config/State nur bei Bedarf aus Backup zurück (Active-Copy unter `state_dir`
   wird beim nächsten erfolgreichen Load neu geschrieben).

3. Bei Git: `git checkout <alter-tag-oder-commit>` und erneut `cargo build --release`.

## Bekannte Stolpersteine

- **ACME cold → enabled**: Reload reicht nicht; Restart nötig.
- **Listen/Sandbox geändert + nur Reload**: `ready` failt absichtlich, bis Restart.
- **Ban-Share / Token-Quellen leer**: fail-closed (vorheriger Store/Token bleibt).
- **Feature `http3`**: Binary ohne Feature ignoriert `experimental.h3` sinnvoll —
  mit Feature bauen, wenn H3 gewünscht.

## Siehe auch

- [INSTALL.md](INSTALL.md) — Neuinstallation
- [OPERATIONS.md](OPERATIONS.md) — Alltag, Admin-Socket, Sizing
- [THREAT_MODEL.md](THREAT_MODEL.md) — Vertrauensgrenzen
