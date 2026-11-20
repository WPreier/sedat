#!/usr/bin/env python3
import socket
import sys

url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/"
host = "127.0.0.1"
port = 8080
path = "/"
if "://" in url:
    _, rest = url.split("://", 1)
    hostport, _, path = rest.partition("/")
    path = "/" + path
    if ":" in hostport:
        host, port_s = hostport.split(":")
        port = int(port_s)
    else:
        host = hostport

s = socket.create_connection((host, port), timeout=5)
req = f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
for i in range(500):
    req += f"X-Flood-{i}: {'A' * 200}\r\n"
req += "\r\n"
s.sendall(req.encode())
print(s.recv(4096).decode(errors="replace").split("\r\n", 1)[0])
