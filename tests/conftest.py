"""Shared pytest fixtures: a local "slow" server and a fake SOCKS5 proxy."""

from __future__ import annotations

import asyncio

import pytest


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
        except (asyncio.CancelledError, ConnectionError):
            raise
        finally:
            self.active -= 1
            writer.close()

    async def start(self) -> "SlowServer":
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
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
            raise
        finally:
            writer.close()

    async def start(self) -> "FakeSocks5":
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()


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