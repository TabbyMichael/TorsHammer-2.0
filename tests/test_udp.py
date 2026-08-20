"""Tests for the Python ``udp`` attack mode (real datagram traffic)."""

from __future__ import annotations

import asyncio

import pytest

from torshammer import udp
from torshammer.cli import _resolve_config, build_parser
from torshammer.config import Config
from torshammer.engine import AttackEngine
from torshammer.stats import Stats


class RecvProtocol(asyncio.DatagramProtocol):
    """Captures every datagram delivered to a test receiver socket."""

    def __init__(self) -> None:
        self.datagrams: list[bytes] = []
        self.bytes = 0

    def datagram_received(self, data: bytes, addr) -> None:
        self.datagrams.append(data)
        self.bytes += len(data)


@pytest.fixture
async def udp_receiver():
    """A real loopback UDP listener; yields ``(protocol, port)``."""
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        RecvProtocol, local_addr=("127.0.0.1", 0)
    )
    port = transport.get_extra_info("sockname")[1]
    try:
        yield protocol, port
    finally:
        transport.close()


def _cfg(port: int, **overrides) -> Config:
    defaults = {
        "host": "127.0.0.1",
        "port": port,
        "mode": "udp",
        "connect_timeout": 2,
        "delay_min": 0,
        "delay_max": 0.01,
        "base_post_length": 256,
        "path": "/",
        "quiet": True,
    }
    defaults.update(overrides)
    return Config(**defaults)


async def test_udp_engine_sends_real_datagrams(udp_receiver):
    protocol, port = udp_receiver
    cfg = _cfg(port, concurrency=4, duration=0.2)
    engine = AttackEngine(cfg, asyncio.Event())
    await engine.run()

    assert protocol.datagrams, "receiver should get real UDP datagrams"
    assert protocol.bytes > 0
    assert engine.stats.connections > 0
    assert engine.stats.bytes_sent > 0
    assert engine.stats.active == 0
    assert engine.stats.errors == 0


async def test_udp_open_drips_to_receiver(udp_receiver):
    protocol, port = udp_receiver
    stats = Stats()
    transport, _ = await udp.open_datagram("127.0.0.1", port, connect_timeout=2, stats=stats)
    stop = asyncio.Event()
    try:
        completed = await udp.drip(transport, _cfg(port, base_post_length=128), stats, stop)
    finally:
        transport.close()

    assert completed is True
    assert stats.bytes_sent > 0
    assert protocol.datagrams, "datagram drip never reached the receiver"


async def test_udp_drip_honors_pre_set_stop(udp_receiver):
    _protocol, port = udp_receiver
    stats = Stats()
    transport, _ = await udp.open_datagram("127.0.0.1", port, connect_timeout=2, stats=stats)
    stop = asyncio.Event()
    stop.set()
    try:
        completed = await udp.drip(transport, _cfg(port, base_post_length=128), stats, stop)
    finally:
        transport.close()

    assert completed is False
    assert stats.bytes_sent == 0


def test_udp_mode_is_a_selectable_cli_choice():
    args = build_parser().parse_args(["-m", "udp", "-u", "http://localhost"])
    cfg = _resolve_config(args)
    assert cfg.mode == "udp"
    assert cfg.port == 80


def test_udp_scheme_forces_udp_mode_and_default_port():
    args = build_parser().parse_args(["-u", "udp://example.com", "--allow-public-targets"])
    cfg = _resolve_config(args)
    assert cfg.mode == "udp"
    assert cfg.port == 53
