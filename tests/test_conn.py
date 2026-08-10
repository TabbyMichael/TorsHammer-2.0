"""Tests for the connection factory (direct + SOCKS5 handshake)."""

from __future__ import annotations

import asyncio

from torshammer import conn
from torshammer.config import Config
from torshammer.proxies import Proxy


async def test_direct_connect(slow_server):
    cfg = Config(host="127.0.0.1", port=slow_server.port, connect_timeout=3)
    reader, writer = await conn.open_connection("127.0.0.1", slow_server.port, config=cfg)
    writer.write(b"hello")
    await writer.drain()
    await asyncio.sleep(0.05)
    writer.close()
    await writer.wait_closed()
    assert slow_server.bytes_received == 5


async def test_socks5_handshake(fake_socks5):
    proxy = Proxy("socks5", "127.0.0.1", fake_socks5.port)
    cfg = Config(host="example.com", port=80, connect_timeout=3)
    reader, writer = await conn.open_connection(
        "example.com", 80, config=cfg, proxy=proxy
    )
    # The fake proxy must have seen the CONNECT request.
    assert fake_socks5.targets[-1] == ("example.com", 80)
    # The tunnel now carries app data through the fake proxy.
    writer.write(b"ping")
    await writer.drain()
    await asyncio.sleep(0.05)
    writer.close()
    await writer.wait_closed()


async def test_socks5_domain_connect(fake_socks5):
    proxy = Proxy("socks5", "127.0.0.1", fake_socks5.port)
    cfg = Config(host="sub.example.net", port=443, connect_timeout=3)
    reader, writer = await conn.open_connection(
        "sub.example.net", 443, config=cfg, proxy=proxy
    )
    # Domain names must be sent to the proxy for remote resolution.
    assert fake_socks5.targets[-1] == ("sub.example.net", 443)
    writer.close()
    await writer.wait_closed()