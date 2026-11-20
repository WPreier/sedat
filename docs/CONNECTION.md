# Verbindung zwischen SeDat und Seda

## Rollen

| Komponente | Rolle | Repository |
|------------|------|------------|
| **SeDat** | Reverse-Proxy, TLS-Terminierung, ACME, Rate-Limiting, Routing | [sedat](https://github.com/WPreier/sedat) |
| **Seda** | Backend, liefert rein statische HTML-Seiten ausschließlich aus dem Speicher | [seda](https://github.com/WPreier/seda) |

## Kommunikationsfluss

```
Client
   ↓
SeDat (HTTPS, HTTP/1.1 + HTTP/2 + optional HTTP/3)
   ↓  PROXY Protocol v2 (empfohlen) oder HTTP
Seda (HTTP, Seiten aus Memory)
```

## Gemeinsame Prinzipien

- Identische Config-Philosophie (versteckte aktive Kopie, Fail-Closed mit Zeilennummer, `--resetconfig`)
- Gleiche Security-Anforderungen (Privilege Drop, Limits, non-blocking Logging)
- Beide Binaries können die Dokumentation des jeweils anderen einbetten
- `/sedat` und `/seda` liefern die eingebettete Dokumentation (konfigurierbar, Standard: aktiv)

## Empfohlene Betriebsart

- SeDat terminiert TLS und spricht Seda über **PROXY Protocol v2** auf localhost oder internem Netz an.
- Seda vertraut nur PROXY-Headern von SeDat (Trust-Allowlist / nur lokales Netz).
- **Inbound PROXY** auf SeDat: Standard **aus**; nur mit expliziter CIDR-Allowlist aktivieren.
- Seda darf nicht aus dem Internet erreichbar sein.
- **Request-ID:** SeDat setzt standardmäßig `x-request-id` als **HTTP-Header nach** dem PROXY-Framing (kein PROXY-TLV). Seda/Mock-Seda können den Header für Logs korrelieren; ungültige Client-Werte werden ersetzt.
- **Upstream HTTPS / mTLS (optional):** Standard bleibt `http://`. Bei `https://` spricht SeDat TLS zum Upstream (optional Client-Zertifikat via `upstream_mtls_*`). Outbound-PROXY wird auf HTTPS-Upstreams übersprungen (ClientHello zuerst). Details: [phases/P10_07_upstream_mtls.md](phases/P10_07_upstream_mtls.md).

## Trust-Boundary-Tests

- Mock-Seda akzeptiert PROXY nur von erlaubten Quell-IPs.
- Spoofing von Client-IPs über gefälschte PROXY-Frames von Fremd-IPs muss scheitern.

## Dev-Double

`deploy/mock-seda/` und Compose-Service `mock-seda` implementieren einen minimalen Upstream mit PROXY-Parser für CI/E2E, falls kein echtes Seda-Binary vorliegt.
