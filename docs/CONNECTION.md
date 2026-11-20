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
SeDat (HTTPS, HTTP/1.1 + HTTP/2 + HTTP/3)
   ↓  PROXY Protocol v1/v2 (empfohlen) oder HTTP
Seda (HTTP, Seiten aus Memory)
```

## Gemeinsame Prinzipien

- Identische Config-Philosophie (versteckte aktive Kopie, Fail-Closed mit Zeilennummer, `--resetconfig`)
- Gleiche Security-Anforderungen (Privilege Drop, Limits, non-blocking Logging)
- Beide Binaries enthalten die Dokumentation des jeweils anderen
- `/sedat` und `/seda` liefern die eingebettete Dokumentation (konfigurierbar, Standard: aktiv)

## Empfohlene Betriebsart

- SeDat terminiert TLS und spricht Seda über PROXY Protocol auf localhost oder internem Netz an.
- Seda vertraut nur den von SeDat gesetzten PROXY-Headern.
