#!/usr/bin/env python3
import socket
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
s = socket.create_connection((host, port), timeout=30)
# Send request line very slowly
payload = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
for b in payload:
    s.sendall(bytes([b]))
    time.sleep(0.2)
s.settimeout(5)
try:
    print(s.recv(1024))
except Exception as e:
    print("expected slow/timeout behaviour:", e)
