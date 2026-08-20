"""UDP attack profile: real datagram traffic to a target host:port.

This module gives the Python backend a ``udp`` mode that performs genuine
UDP I/O (unlike the TCP-based slow-request profiles). Each worker opens a
real connected UDP socket and slowly drips small, randomized datagrams toward
``host:port`` — a sustained, concurrency-aware datagram stream whose byte
counts feed the shared statistics.
"""

from __future__ import annotations

import asyncio
import random
import string

from .config import Config
from .stats import Stats

_ALNUM = string.ascii_letters + string.digits


class UdpProtocol(asyncio.DatagramProtocol):
    """Minimal datagram protocol; echoes/ICMP replies count as received bytes."""

    def __init__(self, stats: Stats) -> None:
        self._stats = stats

    def datagram_received(self, data: bytes, addr) -> None:
        self._stats.bytes_received += len(data)

    def error_received(self, exc: Exception) -> None:
        # ICMP port-unreachable / network errors surface here; ignore them so
        # the datagram loop keeps running (mirrors the fire-and-forget mode).
        pass


def _dribble(size: int) -> bytes:
    return "".join(random.choice(_ALNUM) for _ in range(size)).encode()


async def _halt(stop: asyncio.Event, config: Config) -> None:
    """Sleep a random delay, but wake early when ``stop`` is set."""
    try:
        await asyncio.wait_for(stop.wait(), timeout=config.random_delay())
    except TimeoutError:
        pass


async def open_datagram(
    host: str,
    port: int,
    *,
    connect_timeout: float,
    stats: Stats,
) -> tuple[asyncio.DatagramTransport, UdpProtocol]:
    """Open a connected UDP socket to ``host:port`` (no third-party deps).

    ``create_datagram_endpoint(..., remote_addr=...)`` yields a kernel-bound
    datagram transport whose ``sendto`` already targets the remote peer.
    """
    loop = asyncio.get_running_loop()
    return await asyncio.wait_for(
        loop.create_datagram_endpoint(lambda: UdpProtocol(stats), remote_addr=(host, port)),
        connect_timeout,
    )


async def drip(
    transport: asyncio.DatagramTransport,
    config: Config,
    stats: Stats,
    stop: asyncio.Event,
) -> bool:
    """Slowly send ``base_post_length`` bytes of datagrams to the target.

    Each datagram carries a random 1..32 byte payload, then the profile sleeps
    for a randomized delay before the next — mirroring the TCP ``chunked``
    mode's drip rhythm so the UDP traffic is *slow* rather than a burst.

    Returns ``True`` when the cycle completed, ``False`` if interrupted.
    """
    length = random.randint(max(1, config.base_post_length // 2), max(1, config.base_post_length))
    sent = 0
    while not stop.is_set() and sent < length:
        remaining = length - sent
        size = random.randint(1, min(32, remaining))
        payload = _dribble(size)
        try:
            transport.sendto(payload)
        except (OSError, ConnectionError, TimeoutError):
            return False
        stats.bytes_sent += size
        sent += size
        await _halt(stop, config)
    return not stop.is_set()
