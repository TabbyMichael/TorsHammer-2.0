"""Shared pytest fixtures: a local "slow" server and a fake SOCKS5 proxy."""

from __future__ import annotations

import asyncio
import ssl

import pytest

# A self-signed certificate for CN=localhost (SAN: localhost, 127.0.0.1).
# Generated for tests only; expires 2036. Used by the TLS test server.
_TLS_CERT = """-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIUZ4Ix7T1BjH6blxhuGer4IjtJNjUwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgxMzA5NTYyM1oXDTM2MDgx
MDA5NTYyM1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAyZHa1UZYCmuvSfAdkaoa03e+qYPteKO7gBVeuZl9ftWt
u+2AoNOUPQ6PqdKUqwUPIi2xmNADXQi0VtzZLnTXrgRsFcL3DN8cflYYPb37Hkxa
Qs5fbrFqd1N0LJvlYZds2HE60EUOBb/G2QWvmM9J2xPMlhr/tknhL0u1r/YsvhGa
9+CuWW2IXnUQVbgNWrE1jdAVAcSauOjx9GluEB5J2Au9DRGKu4VgVKPoIUBILG6W
rIp0fJtJ4Diz9418Jk6XZgZCydL1BuPLytTdhO+wGqRNiV5PpZDkYvEtfh5yjikW
b+E8gBeuiAxnab+U8AJ7tAhcWyS1XaU7FjwcSsv3/QIDAQABo28wbTAdBgNVHQ4E
FgQUOKmN/n30Yylyl6KCSGbcIevJduEwHwYDVR0jBBgwFoAUOKmN/n30Yylyl6KC
SGbcIevJduEwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH
BH8AAAEwDQYJKoZIhvcNAQELBQADggEBACtP2WJ6fn6HAVG8OoCTkFLH0STXOql9
nz86fXV7xGG6AsMjM/yZMrdgbx0fIpBnK6txKjZlJzV9V9IP9ZfJCPQCiPTxQuZ+
O4/1Wklm3kdGueO8x5T4U4udMidSd7n3dHWydL2+NoC1buGW2ZhOXO0A3LOv8rAn
mIB4B+tVkkqhKSp5tCoF+4VLIatPkm8xCmZxMHLn+NEMmDFpOf5njcPu3YIGz6ar
HS8iPec8HdzMYTxhJXnCmGb+SOkyWrFssvLgkIFNSiEbnvbq4xz3cRetTEj7njEM
xFv4NDm70tk2VJ+2MWiiPtekBFiCfSqoAQ+8vMCsrqaxoAup2CiNTq8=
-----END CERTIFICATE-----"""

_TLS_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJkdrVRlgKa69J
8B2RqhrTd76pg+14o7uAFV65mX1+1a277YCg05Q9Do+p0pSrBQ8iLbGY0ANdCLRW
3NkudNeuBGwVwvcM3xx+Vhg9vfseTFpCzl9usWp3U3Qsm+Vhl2zYcTrQRQ4Fv8bZ
Ba+Yz0nbE8yWGv+2SeEvS7Wv9iy+EZr34K5ZbYhedRBVuA1asTWN0BUBxJq46PH0
aW4QHknYC70NEYq7hWBUo+ghQEgsbpasinR8m0ngOLP3jXwmTpdmBkLJ0vUG48vK
1N2E77AapE2JXk+lkORi8S1+HnKOKRZv4TyAF66IDGdpv5TwAnu0CFxbJLVdpTsW
PBxKy/f9AgMBAAECggEACrCA9el+lsLiL14b+1MVjBxgEJZN/CVWtrKrbNVOefDz
/zDXru+5f0lr5fokZzNj+5CHyA5T91WUVrzsiZGptHFImBjYSCb22F5Rd8jA7fjn
mn5eQj0HY9+ZnBoCXpwMqifLEitvVG+4qF6sUsK/bG5O3bD92ZluZzcxIe1Ary2g
ndMVTRwrEQsUEwggLxOOfbVHqV8ppX/0uArm+rbDyAF1F9Eh+nFMnUQWPNv2TzHB
J8gXewtLwT42JA0qE5wD+6/NkZFAy64yRaE8KRAd9WZgU+FTmCIREMipt/iksvit
4UbP1u/urVGZAF06DGr22cn929ZlVTyIb/lz3O3z0wKBgQD7gLwOQtfUgkedlgOK
81C36Xgs+Zcw/mlce8zBJ6yiLiqLnxZfFR2ok9Mnc+XxbyPakiO7AUBEjRh8uynN
6sLGuJa96AT3PfwxdyG2lYZJN2IeF6KIONIdB+BLEEZniv5GyP4slpYy9TClbxOX
O+iSfRc8eOn0Oe9oZ5hhYzSxcwKBgQDNLIyVwwWAzJaM2kf1L4atgB7LOGZZgv06
pn4IKYpB2QDlUflq9DRygmlyRY2qlor53POwAbmc8qK/Q4MDSbf3cZqXKK1e6Iqm
PFAPYR617Ak7Bs6QVMtcFUtn7NdeFzYXgk0omy/S6gNTWNPPUyptcyHpkru3xm6C
PyD2In6UzwKBgQDM2XpTE1bAnKzASmPwVWa1pdBgsZrYKSCgV6Xa3fnaz0eQGbAb
GhPiLyWZyOjN0fyeFtJLiyVRsKr1TW0rb7/eJJODcuw4haBYmfQ3x2ptUFL2t8GG
uuFJDBVAjq0JwUiDV0rP/oewUc2hset/DyjLyF+YvdOxPU8m9tpC2I8eyQKBgAZF
TUqqejmUhylo5ngc6r3Uw5wsbhxgP4MSYZm4Q0x96GQZ3EijjBLP348phwnmrfqz
AROpCdY9KDI2SwPHtgKvCy2BhcL30n0ALOY7bqfavfF65MdOgCShVfuoJnDuvq17
QwZxr8V/d3iNp3OXtB1CPpAX9vrH6sq6STScm0fLAoGAFesFxXLcoKEowNOdlNXo
2XPNMTHvkhWsNPYmCfQqU56hUwXrNO8zDTzdVABganIg6IbzETyvob4LO5+FfmxU
7j93uAkgAfXlYTpmRILdTW+mbv+uauAvEHevSutIGUg2aT2xtNETNkQklima+nFn
LhHLpWat9X5NzW/hUh2yq3Y=
-----END PRIVATE KEY-----"""


class TlsServer:
    """An asyncio TLS server backed by a self-signed certificate.

    Accepts TLS connections and reads incoming bytes (mirrors SlowServer
    but wrapped in TLS, so the client TLS/SNI code path can be exercised).
    """

    def __init__(self) -> None:
        self.bytes_received = 0
        self.connections = 0
        self.server: asyncio.AbstractServer | None = None

    async def _handle(self, reader, writer) -> None:
        self.connections += 1
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                self.bytes_received += len(data)
        finally:
            writer.close()

    async def start(self) -> TlsServer:
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fc:
            fc.write(_TLS_CERT)
            cert_path = fc.name
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fk:
            fk.write(_TLS_KEY)
            key_path = fk.name
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=ssl_ctx)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()


class SlowServer:
    """A server that accepts connections and reads but never responds.

    This models an Apache/IIS worker sitting on an incomplete request.
    Set ``respond_body`` to a bytes payload to exercise slow-read mode.
    """

    def __init__(self) -> None:
        self.bytes_received = 0
        self.connections = 0
        self.active = 0
        self.respond_body: bytes | None = None
        self.server: asyncio.AbstractServer | None = None

    async def _handle(self, reader, writer) -> None:
        self.connections += 1
        self.active += 1
        try:
            if self.respond_body:
                writer.write(self.respond_body)
                await writer.drain()
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                self.bytes_received += len(data)
        finally:
            self.active -= 1
            writer.close()

    async def start(self) -> SlowServer:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()


class FakeSocks5:
    """A SOCKS5 (no-auth) proxy used to validate our async client handshake."""

    def __init__(self) -> None:
        self.targets: list[tuple[str, int]] = []
        self.server: asyncio.AbstractServer | None = None

    async def _handle(self, reader, writer) -> None:
        try:
            _ver, nmethods = await reader.readexactly(2)
            await reader.readexactly(nmethods)
            writer.write(b"\x05\x00")  # no-auth selected
            await writer.drain()
            _v, _cmd, _rsv, atyp = await reader.readexactly(4)
            if atyp == 1:
                target = ".".join(str(b) for b in await reader.readexactly(4))
            elif atyp == 4:
                target = "::1"
            else:
                n = (await reader.readexactly(1))[0]
                target = (await reader.readexactly(n)).decode()
            port = int.from_bytes(await reader.readexactly(2), "big")
            self.targets.append((target, port))
            # success reply + a dummy bound address
            writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
            await writer.drain()
            while True:  # keep the tunnel open
                data = await reader.read(4096)
                if not data:
                    break
        finally:
            writer.close()

    async def start(self) -> FakeSocks5:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()


class FakeSocks4:
    """A minimal SOCKS4a proxy used to validate the async SOCKS4a client.

    Records requested targets and supports hostname (remote-DNS) CONNECTs
    via the ``0.0.0.1`` signalling convention.
    """

    def __init__(self) -> None:
        self.targets: list[tuple[str, int]] = []
        self.server: asyncio.AbstractServer | None = None

    async def _handle(self, reader, writer) -> None:
        try:
            _vn, _cd = await reader.readexactly(2)  # version, command
            port = int.from_bytes(await reader.readexactly(2), "big")
            dstip = await reader.readexactly(4)
            userid = bytearray()
            while True:
                b = await reader.readexactly(1)
                if b == b"\x00":
                    break
                userid += b
            # SOCKS4a: if DSTIP is 0.0.0.1 the real hostname follows.
            if dstip == b"\x00\x00\x00\x01":
                host = bytearray()
                while True:
                    b = await reader.readexactly(1)
                    if b == b"\x00":
                        break
                    host += b
                host = host.decode()
            else:
                host = ".".join(str(b) for b in dstip)
            self.targets.append((host, port))
            # Reply: VN(0), CD(90/granted), DSTPORT(0), DSTIP(0) = 8 bytes.
            writer.write(b"\x00\x5a\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            while True:
                data = await reader.read(4096)
                if not data:
                    break
        finally:
            writer.close()

    async def start(self) -> FakeSocks4:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()


class FakeHttpProxy:
    """A minimal HTTP CONNECT proxy for validating the CONNECT client path.

    Optionally requires Basic auth via ``require_auth``.
    """

    def __init__(self, require_auth: tuple[str, str] | None = None) -> None:
        self.require_auth = require_auth
        self.targets: list[str] = []  # authority hosts:port
        self.auth_headers: list[str] = []  # raw Proxy-Authorization header values
        self.server: asyncio.AbstractServer | None = None

    async def _handle(self, reader, writer) -> None:
        try:
            raw = b""
            while b"\r\n\r\n" not in raw:
                chunk = await reader.read(4096)
                if not chunk:
                    writer.close()
                    return
                raw += chunk
                if len(raw) > 65536:
                    writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    await writer.drain()
                    writer.close()
                    return
            head, _body, _ = raw.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            request_line = lines[0]
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            if self.require_auth:
                import base64

                expected = (
                    "Basic "
                    + base64.b64encode(
                        f"{self.require_auth[0]}:{self.require_auth[1]}".encode()
                    ).decode()
                )
                self.auth_headers.append(headers.get("proxy-authorization", ""))
                if headers.get("proxy-authorization") != expected:
                    writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                    await writer.drain()
                    writer.close()
                    return
            if request_line.startswith("CONNECT "):
                target = request_line.split(" ", 2)[1]
                self.targets.append(target)
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
            else:
                writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                await writer.drain()
            while True:
                data = await reader.read(4096)
                if not data:
                    break
        finally:
            writer.close()

    async def start(self) -> FakeHttpProxy:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()


class FakeSocks5Auth:
    """A SOCKS5 proxy that requires username/password authentication."""

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.targets: list[tuple[str, int]] = []
        self.server: asyncio.AbstractServer | None = None

    async def _handle(self, reader, writer) -> None:
        try:
            _ver, nmethods = await reader.readexactly(2)
            methods = await reader.readexactly(nmethods)
            if 0x02 not in methods:
                writer.write(b"\x05\xff")  # no acceptable method
                await writer.drain()
                writer.close()
                return
            writer.write(b"\x05\x02")  # select username/password
            await writer.drain()
            _ver, ulen = await reader.readexactly(2)
            user = (await reader.readexactly(ulen)).decode()
            plen = (await reader.readexactly(1))[0]
            pwd = (await reader.readexactly(plen)).decode()
            if user != self.username or pwd != self.password:
                writer.write(b"\x01\x01")  # auth failure
                await writer.drain()
                writer.close()
                return
            writer.write(b"\x01\x00")  # auth success
            await writer.drain()
            _v, _cmd, _rsv, atyp = await reader.readexactly(4)
            if atyp == 1:
                target = ".".join(str(b) for b in await reader.readexactly(4))
            elif atyp == 4:
                target = "::1"
            else:
                n = (await reader.readexactly(1))[0]
                target = (await reader.readexactly(n)).decode()
            port = int.from_bytes(await reader.readexactly(2), "big")
            self.targets.append((target, port))
            writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
            await writer.drain()
            # Relay app data bidirectionally so TLS-through-proxy works.
            try:
                target_reader, target_writer = await asyncio.open_connection(target, port)
            except OSError:
                writer.close()
                return
            await _relay(reader, writer, target_reader, target_writer)
        finally:
            writer.close()

    async def start(self) -> FakeSocks5Auth:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()


class RelaySocks5:
    """A SOCKS5 (no-auth) proxy that relays app data to the real target.

    Unlike ``FakeSocks5`` (which swallows tunnel traffic), this proxy opens a
    connection to the requested target and pipes bytes both ways, so a real
    TLS handshake can be carried through the tunnel in tests.
    """

    def __init__(self) -> None:
        self.targets: list[tuple[str, int]] = []
        self.server: asyncio.AbstractServer | None = None

    async def _handle(self, reader, writer) -> None:
        try:
            _ver, nmethods = await reader.readexactly(2)
            await reader.readexactly(nmethods)
            writer.write(b"\x05\x00")  # no-auth selected
            await writer.drain()
            _v, _cmd, _rsv, atyp = await reader.readexactly(4)
            if atyp == 1:
                target = ".".join(str(b) for b in await reader.readexactly(4))
            elif atyp == 4:
                target = "::1"
            else:
                n = (await reader.readexactly(1))[0]
                target = (await reader.readexactly(n)).decode()
            port = int.from_bytes(await reader.readexactly(2), "big")
            self.targets.append((target, port))
            writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50")
            await writer.drain()
            try:
                target_reader, target_writer = await asyncio.open_connection(target, port)
            except OSError:
                writer.close()
                return
            await _relay(reader, writer, target_reader, target_writer)
        finally:
            writer.close()

    async def start(self) -> RelaySocks5:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()


async def _relay(a_reader, a_writer, b_reader, b_writer) -> None:
    """Bidirectionally pipe bytes between two (reader, writer) stream pairs."""

    async def pump(src, dst):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                dst.close()
            except OSError:
                pass

    t1 = asyncio.ensure_future(pump(a_reader, b_writer))
    t2 = asyncio.ensure_future(pump(b_reader, a_writer))
    await asyncio.gather(t1, t2, return_exceptions=True)


@pytest.fixture
async def slow_server():
    srv = SlowServer()
    await srv.start()
    yield srv
    await srv.stop()


@pytest.fixture
async def fake_socks5():
    srv = FakeSocks5()
    await srv.start()
    yield srv
    await srv.stop()


@pytest.fixture
async def fake_socks4():
    srv = FakeSocks4()
    await srv.start()
    yield srv
    await srv.stop()


@pytest.fixture
async def fake_http_proxy():
    srv = FakeHttpProxy()
    await srv.start()
    yield srv
    await srv.stop()


@pytest.fixture
async def fake_http_proxy_auth():
    srv = FakeHttpProxy(require_auth=("user", "pass"))
    await srv.start()
    yield srv
    await srv.stop()


@pytest.fixture
async def fake_socks5_auth():
    srv = FakeSocks5Auth("user", "pass")
    await srv.start()
    yield srv
    await srv.stop()


@pytest.fixture
async def tls_server():
    srv = TlsServer()
    await srv.start()
    yield srv
    await srv.stop()


@pytest.fixture
async def relay_socks5():
    srv = RelaySocks5()
    await srv.start()
    yield srv
    await srv.stop()
