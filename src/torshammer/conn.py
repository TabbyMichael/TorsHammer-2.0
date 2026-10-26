"""Connection factory: plain HTTP, HTTPS with SNI, and proxied sockets.

Implements SOCKS5 (with optional username/password auth), SOCKS4a and HTTP
CONNECT with pure asyncio so there are no third-party dependencies.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import socket
import ssl
import struct

from .config import Config
from .proxies import Proxy


class ProxyConnectError(ConnectionError):
    """Raised when a proxy handshake fails."""


# Resolved-address cache: a target/proxy endpoint is looked up once, then every
# reconnect cycles across all addresses it resolves to. This removes the
# per-connection getaddrinfo syscall (a real bottleneck in reconnect-heavy modes
# such as http-pipelining/range-abuse) and spreads load across every backend IP
# of a round-robin/multi-A host so no single front-end is under-tested.
_ADDR_CACHE: dict[tuple[str, int], list[str]] = {}
_ADDR_CURSOR: dict[tuple[str, int], int] = {}


def _clear_addr_cache() -> None:
    """Drop cached DNS results (used by tests and after a target change)."""
    _ADDR_CACHE.clear()
    _ADDR_CURSOR.clear()


async def _resolve_ips(loop: asyncio.AbstractEventLoop, host: str, port: int) -> list[str]:
    """Return every IP ``host`` resolves to, resolved at most once per process."""
    key = (host, port)
    ips = _ADDR_CACHE.get(key)
    if ips is None:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        ips = [str(info[-1][0]) for info in infos]
        if not ips:
            raise OSError(f"could not resolve host {host!r}")
        _ADDR_CACHE[key] = ips
        _ADDR_CURSOR[key] = 0
    return ips


async def _connect_ips(
    loop: asyncio.AbstractEventLoop,
    host: str,
    port: int,
    *,
    ssl_ctx: ssl.SSLContext | None = None,
    sni: str | None = None,
    timeout: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to ``host`` using cached DNS, round-robining and falling back.

    Starts at the next cached IP (so load spreads across every backend address
    of a multi-A host) and tries each remaining IP until one connects, matching
    the address-fallback behavior of ``asyncio.open_connection`` while skipping
    the repeated network lookup.
    """
    key = (host, port)
    ips = await _resolve_ips(loop, host, port)
    start = _ADDR_CURSOR.get(key, 0)
    _ADDR_CURSOR[key] = start + 1
    last_error: BaseException | None = None
    for offset in range(len(ips)):
        ip = ips[(start + offset) % len(ips)]
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_ctx, server_hostname=sni),
                timeout,
            )
        except (TimeoutError, OSError) as exc:  # try the next address
            last_error = exc
            continue
        _tune_socket(writer)
        return reader, writer
    assert last_error is not None  # ips is non-empty, so we always set this
    raise last_error


def _tune_socket(writer: asyncio.StreamWriter) -> None:
    """Disable Nagle so byte-level dribbles are flushed immediately."""
    sock = writer.transport.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass


def set_linger_off(writer: asyncio.StreamWriter) -> None:
    """Arm SO_LINGER(0) so ``close`` sends RST and skips TIME_WAIT.

    Reconnect-heavy profiles otherwise exhaust ephemeral ports waiting on
    TIME_WAIT sockets; tearing down with RST keeps the port pool free. Safe for
    slow-request modes because the payload has already been handed to the peer.
    """
    sock = writer.transport.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass


async def open_connection(
    host: str,
    port: int,
    *,
    config: Config,
    proxy: Proxy | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a (reader, writer) stream to ``host:port``.

    When ``proxy`` is given the stream is first tunneled through the proxy;
    when the target is HTTPS the tunnel is upgraded to TLS (with SNI) after
    the proxy handshake. Direct connections use a cached, round-robined IP so
    the target is resolved at most once per process.
    """
    ctx = config.ssl_context()
    sni = host if config.secure else None
    loop = asyncio.get_running_loop()

    if proxy is None:
        return await _connect_ips(
            loop, host, port, ssl_ctx=ctx, sni=sni, timeout=config.connect_timeout
        )

    reader, writer = await _connect_ips(
        loop, proxy.host, proxy.port, timeout=config.connect_timeout
    )
    try:
        await asyncio.wait_for(
            _handshake(reader, writer, proxy, host, port), config.connect_timeout
        )
        if ctx is not None:
            # start_tls upgrades the existing transport in place.
            await asyncio.wait_for(
                writer.start_tls(ctx, server_hostname=sni), config.connect_timeout
            )
    except BaseException:
        writer.close()
        raise
    _tune_socket(writer)
    return reader, writer


async def _handshake(reader, writer, proxy, host, port) -> None:
    if proxy.scheme == "socks5":
        await _connect_socks5(reader, writer, proxy, host, port)
    elif proxy.scheme == "socks4":
        await _connect_socks4(reader, writer, proxy, host, port)
    else:  # http connect
        await _connect_http(reader, writer, proxy, host, port)


async def _connect_socks5(reader, writer, proxy, host, port) -> None:
    # --- method negotiation ---
    if proxy.username is None:
        writer.write(b"\x05\x01\x00")  # 1 method: no-auth
    else:
        writer.write(b"\x05\x02\x00\x02")  # 2 methods: no-auth, user/pass
    await writer.drain()

    ver, method = await reader.readexactly(2)
    if ver != 5:
        raise ProxyConnectError("bad SOCKS5 version")
    if method == 0:
        pass
    elif method == 2 and proxy.username is not None:
        user = proxy.username.encode()
        pwd = (proxy.password or "").encode()
        if len(user) > 255 or len(pwd) > 255:
            raise ProxyConnectError("SOCKS5 credentials too long")
        writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(pwd)]) + pwd)
        await writer.drain()
        ver2, status = await reader.readexactly(2)
        if ver2 != 1 or status != 0:
            raise ProxyConnectError("SOCKS5 authentication failed")
    else:
        raise ProxyConnectError("SOCKS5 rejected our authentication methods")

    # --- connection request ---
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            atyp, addr = b"\x01", ip.packed
        else:
            atyp, addr = b"\x04", ip.packed
    except ValueError:
        raw = host.encode()
        if len(raw) > 255:
            raise ProxyConnectError("hostname too long")
        atyp, addr = b"\x03", bytes([len(raw)]) + raw

    writer.write(b"\x05\x01\x00" + atyp + addr + struct.pack(">H", port))
    await writer.drain()

    ver, rep, _rsv, satyp = await reader.readexactly(4)
    if ver != 5 or rep != 0:
        raise ProxyConnectError(f"SOCKS5 connect failed (reply {rep})")
    # consume the bound address
    if satyp == 1:
        await reader.readexactly(4)
    elif satyp == 4:
        await reader.readexactly(16)
    elif satyp == 3:
        n = (await reader.readexactly(1))[0]
        await reader.readexactly(n)
    await reader.readexactly(2)  # bound port


async def _connect_socks4(reader, writer, proxy, host, port) -> None:
    userid = (proxy.username or "").encode() + b"\x00"
    try:
        ip = ipaddress.IPv4Address(host)
        req = b"\x04\x01" + struct.pack(">H", port) + ip.packed + userid
    except ValueError:
        # SOCKS4a: signal remote resolution with 0.0.0.1 and append hostname.
        req = (
            b"\x04\x01"
            + struct.pack(">H", port)
            + b"\x00\x00\x00\x01"
            + userid
            + host.encode()
            + b"\x00"
        )
    writer.write(req)
    await writer.drain()
    resp = await reader.readexactly(8)
    if resp[0] != 0 or resp[1] != 0x5A:
        raise ProxyConnectError(f"SOCKS4 connect failed (code {resp[1]})")


async def _connect_http(reader, writer, proxy, host, port) -> None:
    target = f"{host}:{port}"
    lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
    if proxy.username is not None:
        token = base64.b64encode(f"{proxy.username}:{proxy.password or ''}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
    await writer.drain()

    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = await reader.read(1024)
        if not chunk:
            raise ProxyConnectError("HTTP proxy closed during CONNECT")
        raw += chunk
        if len(raw) > 65536:
            raise ProxyConnectError("HTTP proxy response too large")

    status = raw.split(b"\r\n", 1)[0]
    parts = status.split(b" ")
    if len(parts) < 2 or not parts[1].isdigit():
        raise ProxyConnectError(f"malformed HTTP proxy response: {status!r}")
    if int(parts[1]) != 200:
        raise ProxyConnectError(f"HTTP proxy CONNECT returned {parts[1].decode()}")
