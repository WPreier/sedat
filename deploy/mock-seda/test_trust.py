#!/usr/bin/env python3
"""Unit checks for Mock-Seda PROXY trust policy (no network)."""
from __future__ import annotations

import ipaddress
import os
import sys

# Re-use server helpers by importing after path tweak
sys.path.insert(0, os.path.dirname(__file__))
import server  # noqa: E402


def test_trusted_defaults() -> None:
    assert server.trusted("127.0.0.1")
    assert server.trusted("10.1.2.3")
    assert not server.trusted("203.0.113.9")


def test_custom_trust_env(monkeypatch_env: None = None) -> None:
    # Inline: rebuild TRUST like server does
    trust = [
        ipaddress.ip_network(c.strip())
        for c in "192.0.2.0/24".split(",")
        if c.strip()
    ]

    def trusted(addr: str) -> bool:
        ip = ipaddress.ip_address(addr)
        return any(ip in net for net in trust)

    assert trusted("192.0.2.10")
    assert not trusted("127.0.0.1")


if __name__ == "__main__":
    test_trusted_defaults()
    test_custom_trust_env()
    print("mock-seda trust checks OK")
