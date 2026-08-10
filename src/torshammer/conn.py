"""Connection factory: plain HTTP, HTTPS with SNI, and proxied sockets.

Implements SOCKS5 (with optional username/password auth), SOCKS4a and HTTP
CONNECT with pure asyncio so there are no third-party dependencies.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import ssl
import struct

from .config import Config
from .proxies import Proxy


class ProxyConnectError(ConnectionError):
    """Raised when a proxy handshake fails."""


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
    the proxy handshake.
    """
    ctx = config.ssl_context()
    sni = host if config.secure else None

    if proxy is None:
        return await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni),
            config.connect_timeout,
        )

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(proxy.host, proxy.port),
        config.connect_timeout,
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
        writer.write(b"\x05\x01\x00")            # 1 method: no-auth
    else:
        writer.write(b"\x05\x02\x00\x02")        # 2 methods: no-auth, user/pass
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
        writer.write(
            b"\x01" + bytes([len(user)]) + user + bytes([len(pwd)]) + pwd
        )
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
        token = base64.b64encode(
            f"{proxy.username}:{proxy.password or ''}".encode()
        ).decode()
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
