"""Error-path coverage for the hand-rolled proxy handshakes in conn.py."""

from __future__ import annotations

import asyncio

import pytest

from torshammer.conn import ProxyConnectError, _connect_http, _connect_socks4, _connect_socks5
from torshammer.proxies import Proxy


class StubWriter:
    """Minimal StreamWriter stand-in that just records writes."""

    def __init__(self) -> None:
        self.sent = b""

    def write(self, data: bytes) -> None:
        self.sent += data

    async def drain(self) -> None:
        return None


def _reader(payload: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return reader


async def test_socks5_bad_version_rejected():
    proxy = Proxy("socks5", "p", 1080)
    with pytest.raises(ProxyConnectError, match="bad SOCKS5 version"):
        await _connect_socks5(_reader(b"\x04\x00"), StubWriter(), proxy, "h", 80)


async def test_socks5_auth_method_rejected():
    proxy = Proxy("socks5", "p", 1080, "u", "pw")
    # Server picks neither offered method (0x00 no-auth, 0x02 user/pass).
    with pytest.raises(ProxyConnectError, match="authentication methods"):
        await _connect_socks5(_reader(b"\x05\xff"), StubWriter(), proxy, "h", 80)


async def test_socks5_credentials_rejected():
    proxy = Proxy("socks5", "p", 1080, "u", "pw")
    # Method negotiation ok (chooses 0x02), then auth status != 0.
    with pytest.raises(ProxyConnectError, match="authentication failed"):
        await _connect_socks5(_reader(b"\x05\x02\x01\x01"), StubWriter(), proxy, "h", 80)


async def test_socks5_hostname_too_long():
    proxy = Proxy("socks5", "p", 1080)
    long_host = "x" * 300
    with pytest.raises(ProxyConnectError, match="hostname too long"):
        await _connect_socks5(_reader(b"\x05\x00"), StubWriter(), proxy, long_host, 80)


async def test_socks5_connect_reply_error():
    proxy = Proxy("socks5", "p", 1080)
    # Method ok, then reply version 5 rep=1 (general failure), minimal bound addr.
    payload = b"\x05\x00" + b"\x05\x01\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00"
    with pytest.raises(ProxyConnectError, match="reply 1"):
        await _connect_socks5(_reader(payload), StubWriter(), proxy, "127.0.0.1", 80)


async def test_socks4_failure_code():
    proxy = Proxy("socks4", "p", 1080)
    resp = b"\x00\x56" + b"\x00" * 6  # code 0x56 != 0x5A granted
    with pytest.raises(ProxyConnectError, match="code 86"):
        await _connect_socks4(_reader(resp), StubWriter(), proxy, "127.0.0.1", 80)


async def test_http_proxy_malformed_status():
    proxy = Proxy("http", "p", 8080)
    with pytest.raises(ProxyConnectError, match="malformed"):
        await _connect_http(_reader(b"GARBAGE-NOT-HTTP\r\n\r\n"), StubWriter(), proxy, "h", 80)


async def test_http_proxy_non_200():
    proxy = Proxy("http", "p", 8080)
    with pytest.raises(ProxyConnectError, match="returned 403"):
        await _connect_http(
            _reader(b"HTTP/1.1 403 Forbidden\r\n\r\n"), StubWriter(), proxy, "h", 80
        )


async def test_http_proxy_closed_mid_response():
    proxy = Proxy("http", "p", 8080)
    with pytest.raises(ProxyConnectError, match="closed during CONNECT"):
        await _connect_http(_reader(b""), StubWriter(), proxy, "h", 80)
