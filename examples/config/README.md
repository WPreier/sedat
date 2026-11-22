# Config-Beispiele

| Datei | Zweck |
|-------|--------|
| [good.toml](good.toml) | Minimales gültiges Dev-Beispiel (Tests / Quick start) |
| [full.example.toml](full.example.toml) | Kommentiertes Vollbeispiel aller wichtigen Sektionen |
| [bad_line_12.toml](bad_line_12.toml) | Absichtlich ungültig (Zeilenfehler-Demo) |

## Nutzung

```bash
# Kurz starten
cargo run -- --config examples/config/good.toml --listen 127.0.0.1:8080

# Vollbeispiel nur validieren (kein Daemon nötig)
cargo run -- --config examples/config/full.example.toml --validate
```

## Weiterlesen

- Schema & Lifecycle: [docs/CONFIG.md](../../docs/CONFIG.md)
- Installation: [docs/INSTALL.md](../../docs/INSTALL.md)
- Update / Reload / Rollback: [docs/UPDATE.md](../../docs/UPDATE.md)
- ACME Staging: [examples/acme_staging/](../acme_staging/)
