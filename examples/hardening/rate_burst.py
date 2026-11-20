#!/usr/bin/env python3
import sys
import urllib.request

base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/"
n = int(sys.argv[2]) if len(sys.argv) > 2 else 50
codes = []
for _ in range(n):
    req = urllib.request.Request(base, headers={"Host": "localhost"})
    try:
        with urllib.request.urlopen(req, timeout=2) as r:
            codes.append(r.status)
    except urllib.error.HTTPError as e:
        codes.append(e.code)
    except Exception:
        codes.append(0)
print("codes:", sorted(set(codes)))
print("429 count:", codes.count(429))
