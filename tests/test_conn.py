"""Tests for the connection factory (direct + SOCKS5 handshake)."""

from __future__ import annotations

import asyncio

from torshammer import conn
from torshammer.config import Config
from torshammer.proxies import Proxy


async def test_direct_connect(slow_server):
    cfg = Config(host="127.0.0.1", port=slow_server.port, connect_timeout=3)
    _reader, writer = await conn.open_connection("127.0.0.1", slow_server.port, config=cfg)
    writer.write(b"hello")
    await writer.drain()
    await asyncio.sleep(0.05)
    writer.close()
    await writer.wait_closed()
    assert slow_server.bytes_received == 5


async def test_socks5_handshake(fake_socks5):
    proxy = Proxy("socks5", "127.0.0.1", fake_socks5.port)
    cfg = Config(host="example.com", port=80, connect_timeout=3)
    _reader, writer = await conn.open_connection("example.com", 80, config=cfg, proxy=proxy)
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
    _reader, writer = await conn.open_connection("sub.example.net", 443, config=cfg, proxy=proxy)
    # Domain names must be sent to the proxy for remote resolution.
    assert fake_socks5.targets[-1] == ("sub.example.net", 443)
    writer.close()
    await writer.wait_closed()


async def test_socks4a_handshake(fake_socks4):
    proxy = Proxy("socks4", "127.0.0.1", fake_socks4.port)
    cfg = Config(host="example.com", port=80, connect_timeout=3)
    _reader, writer = await conn.open_connection("example.com", 80, config=cfg, proxy=proxy)
    # The fake SOCKS4a proxy must have seen the target hostname (remote DNS).
    assert fake_socks4.targets[-1] == ("example.com", 80)
    writer.write(b"ping")
    await writer.drain()
    await asyncio.sleep(0.05)
    writer.close()
    await writer.wait_closed()


async def test_socks4_ip_connect(fake_socks4):
    proxy = Proxy("socks4", "127.0.0.1", fake_socks4.port)
    cfg = Config(host="192.168.1.10", port=8080, connect_timeout=3)
    _reader, writer = await conn.open_connection("192.168.1.10", 8080, config=cfg, proxy=proxy)
    # For an IP literal the proxy must receive the dotted quad (no hostname).
    assert fake_socks4.targets[-1] == ("192.168.1.10", 8080)
    writer.close()
    await writer.wait_closed()


async def test_http_connect_handshake(fake_http_proxy):
    proxy = Proxy("http", "127.0.0.1", fake_http_proxy.port)
    cfg = Config(host="example.com", port=443, connect_timeout=3)
    _reader, writer = await conn.open_connection("example.com", 443, config=cfg, proxy=proxy)
    assert fake_http_proxy.targets[-1] == "example.com:443"
    writer.write(b"ping")
    await writer.drain()
    await asyncio.sleep(0.05)
    writer.close()
    await writer.wait_closed()


async def test_http_connect_with_auth(fake_http_proxy_auth):
    proxy = Proxy("http", "127.0.0.1", fake_http_proxy_auth.port, username="user", password="pass")
    cfg = Config(host="example.com", port=443, connect_timeout=3)
    _reader, writer = await conn.open_connection("example.com", 443, config=cfg, proxy=proxy)
    assert fake_http_proxy_auth.targets[-1] == "example.com:443"
    assert fake_http_proxy_auth.auth_headers[-1] != ""
    writer.close()
    await writer.wait_closed()


async def test_socks5_auth_handshake(fake_socks5_auth):
    proxy = Proxy("socks5", "127.0.0.1", fake_socks5_auth.port, username="user", password="pass")
    cfg = Config(host="example.com", port=80, connect_timeout=3)
    _reader, writer = await conn.open_connection("example.com", 80, config=cfg, proxy=proxy)
    assert fake_socks5_auth.targets[-1] == ("example.com", 80)
    writer.write(b"ping")
    await writer.drain()
    await asyncio.sleep(0.05)
    writer.close()
    await writer.wait_closed()


async def test_http_connect_failure_raises(fake_http_proxy_auth):
    """A non-200 CONNECT response (here: wrong Basic auth) must raise ProxyConnectError."""
    proxy = Proxy(
        "http", "127.0.0.1", fake_http_proxy_auth.port, username="wrong", password="wrong"
    )
    cfg = Config(host="example.com", port=443, connect_timeout=3)
    try:
        await conn.open_connection("example.com", 443, config=cfg, proxy=proxy)
        raise AssertionError("should have raised ProxyConnectError")
    except conn.ProxyConnectError:
        pass


async def test_tls_direct_connect_no_verify(tls_server):
    """Direct HTTPS connection with certificate verification disabled."""
    cfg = Config(
        host="localhost",
        port=tls_server.port,
        secure=True,
        ssl_verify=False,
        connect_timeout=3,
    )
    _reader, writer = await conn.open_connection("localhost", tls_server.port, config=cfg)
    writer.write(b"hello-tls")
    await writer.drain()
    await asyncio.sleep(0.2)
    assert tls_server.bytes_received == len(b"hello-tls")
    writer.close()
    await writer.wait_closed()


async def test_tls_verify_default_rejects_self_signed(tls_server):
    """Default certificate verification rejects a self-signed certificate."""
    import ssl

    cfg = Config(
        host="localhost",
        port=tls_server.port,
        secure=True,
        ssl_verify=True,  # default: verify certificates
        connect_timeout=3,
    )
    try:
        await conn.open_connection("localhost", tls_server.port, config=cfg)
        raise AssertionError("self-signed cert should have been rejected")
    except (ssl.SSLError, ssl.CertificateError, OSError):
        pass


async def test_tls_via_socks5_proxy(tls_server, relay_socks5):
    """HTTPS through a SOCKS5 proxy: CONNECT tunnel then TLS upgrade."""
    proxy = Proxy("socks5", "127.0.0.1", relay_socks5.port)
    cfg = Config(
        host="localhost",
        port=tls_server.port,
        secure=True,
        ssl_verify=False,
        connect_timeout=5,
    )
    _reader, writer = await conn.open_connection(
        "localhost", tls_server.port, config=cfg, proxy=proxy
    )
    # The proxy must have been asked to CONNECT to the TLS server.
    assert relay_socks5.targets[-1] == ("localhost", tls_server.port)
    # The TLS tunnel is now live end-to-end; data flows to the TLS server.
    writer.write(b"through-proxy")
    await writer.drain()
    await asyncio.sleep(0.3)
    assert tls_server.bytes_received == len(b"through-proxy")
    writer.close()
    await writer.wait_closed()
