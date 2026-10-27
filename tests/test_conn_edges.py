"""Task 7 (conn half) - connection-factory edge branches.

These drive the small error/guard paths in :mod:`torshammer.conn` that the
proxy-fixture integration tests never reach: DNS resolution failure, the
socket-tuning guards when no raw socket is exposed, and the SOCKS5/HTTP
handshake decode arms (oversized credentials, IPv6 bound addresses and
oversized CONNECT responses) using purpose-built fake streams.
"""

from __future__ import annotations

import asyncio
from typing import cast

import pytest

from torshammer import conn
from torshammer.conn import (
    ProxyConnectError,
    _clear_addr_cache,
    _connect_http,
    _connect_socks5,
    _resolve_ips,
    _tune_socket,
    set_linger_off,
)
from torshammer.proxies import Proxy


class _Transport:
    def __init__(self, sock: object) -> None:
        self._sock = sock

    def get_extra_info(self, name: str, default: object = None) -> object:
        return self._sock if name == "socket" else default


class _Writer:
    def __init__(self, sock: object) -> None:
        self.transport = _Transport(sock)


class _RaisingSock:
    def setsockopt(self, *_a: object) -> None:
        raise OSError("setsockopt not permitted")


def _writer(sock: object) -> asyncio.StreamWriter:
    return cast(asyncio.StreamWriter, _Writer(sock))


# ---------------------------------------------------------------------------
# Address cache + resolution
# ---------------------------------------------------------------------------


def test_clear_addr_cache_empties_state() -> None:
    conn._ADDR_CACHE[("h", 1)] = ["1.2.3.4"]
    conn._ADDR_CURSOR[("h", 1)] = 5
    _clear_addr_cache()
    assert conn._ADDR_CACHE == {}
    assert conn._ADDR_CURSOR == {}


async def test_resolve_ips_raises_when_no_addresses() -> None:
    class _Loop:
        async def getaddrinfo(self, *_a: object, **_k: object) -> list[object]:
            return []

    _clear_addr_cache()
    with pytest.raises(OSError, match="could not resolve host"):
        await _resolve_ips(cast(asyncio.AbstractEventLoop, _Loop()), "nohost.invalid", 80)


# ---------------------------------------------------------------------------
# Socket tuning guards (sock is None / setsockopt raises)
# ---------------------------------------------------------------------------


def test_tune_socket_noop_without_raw_socket() -> None:
    _tune_socket(_writer(None))  # sock is None -> return early (L93-94)


def test_tune_socket_swallows_setsockopt_error() -> None:
    _tune_socket(_writer(_RaisingSock()))  # setsockopt OSError -> pass (L97-98)


def test_set_linger_off_noop_without_raw_socket() -> None:
    set_linger_off(_writer(None))  # L109-110


def test_set_linger_off_swallows_setsockopt_error() -> None:
    set_linger_off(_writer(_RaisingSock()))  # L113-114


# ---------------------------------------------------------------------------
# Fake stream readers for SOCKS5 / HTTP CONNECT handshake arms
# ---------------------------------------------------------------------------


class _Reader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    async def readexactly(self, n: int) -> bytes:
        chunk = self._data[self._pos : self._pos + n]
        self._pos += n
        if len(chunk) < n:
            raise asyncio.IncompleteReadError(chunk, None)
        return chunk

    async def read(self, n: int) -> bytes:
        chunk = self._data[self._pos : self._pos + n]
        self._pos += len(chunk)
        return chunk


class _Sink:
    def __init__(self) -> None:
        self.buf = bytearray()

    def write(self, data: bytes) -> None:
        self.buf += data

    async def drain(self) -> None:
        pass


def _sink() -> asyncio.StreamWriter:
    return cast(asyncio.StreamWriter, _Sink())


async def test_socks5_rejects_oversized_credentials() -> None:
    proxy = Proxy("socks5", "127.0.0.1", 1080, username="u" * 256, password="")
    reader = _Reader(b"\x05\x02")  # version 5, method 2 (user/pass)
    with pytest.raises(ProxyConnectError, match="credentials too long"):
        await _connect_socks5(reader, _sink(), proxy, "127.0.0.1", 80)


async def test_socks5_ipv6_target_and_ipv4_bound_address() -> None:
    proxy = Proxy("socks5", "127.0.0.1", 1080)  # no auth -> method 0
    # negotiate (5,0); reply ver=5 rep=0 rsv=0 satyp=1; 4 bound bytes; 2 port bytes
    reader = _Reader(b"\x05\x00" + b"\x05\x00\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x50")
    await _connect_socks5(reader, _sink(), proxy, "2001:db8::1", 80)  # IPv6 -> L200


async def test_socks5_consumes_ipv6_bound_address() -> None:
    proxy = Proxy("socks5", "127.0.0.1", 1080)
    reader = _Reader(b"\x05\x00" + b"\x05\x00\x00\x04" + b"\x00" * 16 + b"\x00\x50")
    await _connect_socks5(reader, _sink(), proxy, "127.0.0.1", 80)  # satyp 4 -> L216-217


async def test_socks5_consumes_hostname_bound_address() -> None:
    proxy = Proxy("socks5", "127.0.0.1", 1080)
    reader = _Reader(b"\x05\x00" + b"\x05\x00\x00\x03" + b"\x04" + b"abcd" + b"\x00\x50")
    await _connect_socks5(reader, _sink(), proxy, "localhost", 80)  # satyp 3 -> L218-220


async def test_http_connect_rejects_oversized_response() -> None:
    proxy = Proxy("http", "127.0.0.1", 3128)
    reader = _Reader(b"X" * 70000)  # never contains \r\n\r\n, exceeds 64 KiB cap
    with pytest.raises(ProxyConnectError, match="response too large"):
        await _connect_http(reader, _sink(), proxy, "example.com", 80)
