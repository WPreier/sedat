# SeDat

**SeDat** (türkisch: „der Rechtschaffene“) – minimaler, hoch sicherer Reverse-Proxy und Static-Content-Server in Rust.

Companion-Projekt: **[Seda](https://github.com/WPreier/seda)** (Proxy-Client für rein statische HTML-Seiten aus dem Speicher).

## Verbindung zu Seda

SeDat ist der vorgeschaltete Proxy. Seda ist der Backend-Client, der die statischen Seiten aus dem Speicher liefert.

```
Internet → SeDat (Proxy) → Seda (Static Memory Client)
```

Details: [docs/CONNECTION.md](docs/CONNECTION.md)

## Status

Spezifikationsphase. Vollständige Anforderungen für Code-Generierung vorhanden.

## Dokumentation

- [Requirements](docs/REQUIREMENTS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security](docs/SECURITY.md)
- [Operations](docs/OPERATIONS.md)
- [Config & Lifecycle](docs/CONFIG.md)
- [Connection to Seda](docs/CONNECTION.md)
- [Ideas](docs/IDEAS.md)
