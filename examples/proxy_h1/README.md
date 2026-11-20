# Phase 2 – HTTP/1.1 proxy example

```bash
# Terminal A: mock upstream
python deploy/mock-seda/server.py
# or: docker compose -f docker-compose.dev.yml up mock-seda

# Terminal B:
cargo run -- --config examples/config/good.toml --listen 127.0.0.1:8080

# Terminal C:
curl -s -H 'Host: localhost' http://127.0.0.1:8080/
# expect: Mock-Seda HTML with client_ip=...
```

Unknown host:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: evil.test' http://127.0.0.1:8080/
# expect: 404
```
