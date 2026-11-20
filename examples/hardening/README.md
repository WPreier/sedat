# Phase 4 – Hardening attack scripts

These scripts verify SeDat returns expected status codes under abuse.
Run SeDat with a low `rate_limit_burst` for demos.

## Header flood (expect 431)

```bash
python header_flood.py http://127.0.0.1:8080/
```

## Slow read / Slowloris-ish (expect timeout / drop)

```bash
python slow_read.py 127.0.0.1 8080
```

## Rate limit burst (expect 429)

```bash
python rate_burst.py http://127.0.0.1:8080/ 50
```

Privilege-drop is Linux/WSL only; Windows host skips with a log warning.
