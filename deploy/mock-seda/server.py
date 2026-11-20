#!/usr/bin/env python3
"""Minimal Mock-Seda: HTTP + PROXY v1/v2 parse with trust CIDR check."""
from __future__ import annotations

import ipaddress
import os
import socket
import struct
import threading

LISTEN = os.environ.get("LISTEN", "0.0.0.0:9080")
TRUST = [
    ipaddress.ip_network(c.strip())
    for c in os.environ.get(
        "TRUST_CIDRS", "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    ).split(",")
    if c.strip()
]
PROXY_SIG = b"\r\n\r\n\0\r\nQUIT\n"


def trusted(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    return any(ip in net for net in TRUST)


def read_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def parse_proxy(conn: socket.socket, peer: str) -> tuple[str | None, bytes]:
    """Return (client_ip, remainder_bytes). Rejects untrusted peers with PROXY."""
    peek = read_exact(conn, 16)
    if peek.startswith(b"PROXY "):
        if not trusted(peer):
            return None, b""
        rest = peek
        while b"\r\n" not in rest:
            rest += conn.recv(1)
        line, _, remainder = rest.partition(b"\r\n")
        parts = line.decode().split()
        # PROXY TCP4 cIP sIP cPort sPort
        return parts[2], remainder
    if peek.startswith(PROXY_SIG[:12]) or peek[:12] == PROXY_SIG:
        if not trusted(peer):
            return None, b""
        # ensure full 16-byte header start
        hdr = peek
        if len(hdr) < 16:
            hdr += read_exact(conn, 16 - len(hdr))
        ver_cmd = hdr[12]
        fam = hdr[13]
        (length,) = struct.unpack("!H", hdr[14:16])
        addr = read_exact(conn, length)
        if fam == 0x11 and length >= 12:  # IPv4
            cip = socket.inet_ntoa(addr[0:4])
            return cip, b""
        return peer, b""
    return peer, peek


def handle(conn: socket.socket, peer: str) -> None:
    try:
        client_ip, preamble = parse_proxy(conn, peer)
        if client_ip is None:
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nforbidden")
            return
        data = preamble + conn.recv(65535)
        if not data:
            return
        # Very small HTTP parse
        head, _, _ = data.partition(b"\r\n\r\n")
        req_line = head.split(b"\r\n", 1)[0].decode(errors="replace")
        body = (
            f"<html><body><h1>Mock-Seda</h1>"
            f"<p>client_ip={client_ip}</p>"
            f"<p>req={req_line}</p></body></html>"
        ).encode()
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + body
        )
        conn.sendall(resp)
    finally:
        conn.close()


def main() -> None:
    host, port_s = LISTEN.rsplit(":", 1)
    port = int(port_s)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(128)
    print(f"mock-seda listening on {LISTEN} trust={TRUST}", flush=True)
    while True:
        c, addr = srv.accept()
        threading.Thread(target=handle, args=(c, addr[0]), daemon=True).start()


if __name__ == "__main__":
    main()
