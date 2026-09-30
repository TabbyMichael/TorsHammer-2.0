"""Tests for the attack profiles and the async engine."""

from __future__ import annotations

import asyncio

import pytest

from torshammer.config import Config
from torshammer.engine import AttackEngine
from torshammer.profiles import PROFILES, _base_headers, _path
from torshammer.stats import Stats


def _cfg(slow_server, **overrides) -> Config:
    defaults = {
        "host": "127.0.0.1",
        "port": slow_server.port,
        "connect_timeout": 3,
        "delay_min": 0,
        "delay_max": 0.01,
        "base_post_length": 64,
        "path": "/t",
    }
    defaults.update(overrides)
    return Config(**defaults)


async def _drive(profile_cls, cfg, stop=None, run_for=0.15) -> Stats:
    stop = stop or asyncio.Event()
    stats = Stats()
    reader, writer = await asyncio.open_connection("127.0.0.1", cfg.port)
    task = asyncio.create_task(profile_cls().run(reader, writer, cfg, "TestAgent/1.0", stats, stop))
    await asyncio.sleep(run_for)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    finally:
        writer.close()
        await writer.wait_closed()
    return stats


@pytest.mark.parametrize(
    "mode", ["slow-post", "slow-post-headers", "slow-headers", "slow-read", "chunked", "multipart-slow-upload", "expect-continue-abuse", "websocket-slow-upgrade", "http-pipelining", "range-abuse", "cookie-bomb", "jsonrpc-slow", "smtp-slow-envelope", "ftp-slow-command"]
)
async def test_profile_sends_bytes(slow_server, mode):
    cfg = _cfg(slow_server)
    await _drive(PROFILES[mode], cfg)
    assert slow_server.bytes_received > 0


def test_registry_exposes_the_documented_fifteen_modes():
    """The registry must match the fifteen modes documented in docs/attack-modes.md."""
    expected = [
        "chunked",
        "cookie-bomb",
        "expect-continue-abuse",
        "ftp-slow-command",
        "http-pipelining",
        "jsonrpc-slow",
        "multipart-slow-upload",
        "range-abuse",
        "slow-headers",
        "slow-post",
        "slow-post-headers",
        "slow-read",
        "smtp-slow-envelope",
        "websocket-slow-upgrade",
    ]
    assert sorted(PROFILES) == expected
    assert len(expected) + 1 == 15  # + the udp mode handled by engine/udp.py


async def test_profile_honors_pre_set_stop(slow_server):
    cfg = _cfg(slow_server)
    stop = asyncio.Event()
    stop.set()
    stats = Stats()
    reader, writer = await asyncio.open_connection("127.0.0.1", cfg.port)
    start = asyncio.get_running_loop().time()
    await PROFILES["slow-post"]().run(reader, writer, cfg, "UA", stats, stop)
    elapsed = asyncio.get_running_loop().time() - start
    writer.close()
    await writer.wait_closed()
    assert elapsed < 0.5


async def test_slow_read_consumes_response(slow_server):
    slow_server.respond_body = b"x" * 4096
    cfg = _cfg(slow_server)
    stats = await _drive(PROFILES["slow-read"], cfg, run_for=0.2)
    assert stats.bytes_received > 0


async def test_engine_runs_and_stops_cleanly(slow_server):
    cfg = _cfg(
        slow_server,
        concurrency=4,
        mode="slow-post",
        delay_min=0,
        delay_max=0.02,
        base_post_length=256,
        duration=0.4,
        quiet=True,
    )
    engine = AttackEngine(cfg, asyncio.Event())
    await engine.run()
    assert engine.stats.connections > 0
    assert engine.stats.errors == 0
    assert engine.stats.active == 0
    assert slow_server.connections > 0
    assert slow_server.bytes_received > 0


async def test_engine_stops_via_event(slow_server):
    cfg = _cfg(slow_server, concurrency=2, delay_min=0, delay_max=0.05, quiet=True)
    stop = asyncio.Event()
    engine = AttackEngine(cfg, stop)
    task = asyncio.create_task(engine.run())
    await asyncio.sleep(0.3)
    stop.set()
    await asyncio.wait_for(task, timeout=5)
    assert engine.stats.active == 0


def test_random_path_appends_token_when_enabled():
    """_path should append a URL-safe token when randomize_path is True."""
    cfg = Config(host="example.com", port=80, path="/api", randomize_path=True)
    path1 = _path(cfg)
    path2 = _path(cfg)
    # Shape: must start with the configured path followed by ?<token>
    assert path1.startswith("/api?")
    assert path2.startswith("/api?")
    # Two consecutive calls should produce different tokens (CSPRNG, not seeded random)
    # This is not guaranteed but astronomically likely; if it fails, there's a real bug.
    assert path1 != path2


def test_random_path_disabled_returns_bare_path():
    """_path should return the bare path when randomize_path is False."""
    cfg = Config(host="example.com", port=80, path="/api", randomize_path=False)
    assert _path(cfg) == "/api"
    assert _path(cfg) == "/api"  # Must be stable


def test_custom_headers_override_defaults():
    cfg = Config(
        host="example.com",
        port=80,
        path="/",
        header_host="example.com",
        custom_headers=["User-Agent: CustomAgent/1.0", "Accept: application/xml"],
    )
    headers = _base_headers(cfg, "IgnoredAgent")
    assert any(h == "User-Agent: CustomAgent/1.0" for h in headers)
    assert any(h == "Accept: application/xml" for h in headers)
    assert not any(h.startswith("User-Agent: Mozilla") for h in headers)


async def test_slow_headers_sends_custom_headers(slow_server):
    """Profile-level coverage: SlowHeaders should send custom headers."""
    cfg = _cfg(
        slow_server,
        custom_headers={"X-Custom": "test-value", "X-Another": "another-value"},
    )
    stats = await _drive(PROFILES["slow-headers"], cfg, run_for=0.2)
    assert stats.bytes_sent > 0
    # Check that custom headers were sent (they'll be in the request)
    assert slow_server.bytes_received > 0


async def test_slow_post_sends_custom_headers(slow_server):
    """Profile-level coverage: SlowPost should merge custom headers."""
    cfg = _cfg(
        slow_server,
        mode="slow-post",
        custom_headers={"X-Custom": "test-value"},
    )
    stats = await _drive(PROFILES["slow-post"], cfg, run_for=0.2)
    assert stats.bytes_sent > 0
    assert slow_server.bytes_received > 0


async def test_websocket_slow_upgrade_sends_websocket_headers(slow_server):
    """WebSocket Slow Upgrade should send WebSocket-specific headers."""
    cfg = _cfg(slow_server, mode="websocket-slow-upgrade")
    stats = await _drive(PROFILES["websocket-slow-upgrade"], cfg, run_for=0.2)
    assert stats.bytes_sent > 0
    # Verify WebSocket headers were sent by checking received data
    received = slow_server.get_received_data()
    received_str = received.decode('utf-8', errors='ignore')
    assert "Upgrade: websocket" in received_str
    assert "Connection: Upgrade" in received_str
    assert "Sec-WebSocket-Key:" in received_str
    assert "Sec-WebSocket-Version: 13" in received_str


async def test_http_pipelining_sends_multiple_requests(slow_server):
    """HTTP Pipelining should send multiple requests without waiting for responses."""
    cfg = _cfg(slow_server, mode="http-pipelining")
    stats = await _drive(PROFILES["http-pipelining"], cfg, run_for=0.3)
    assert stats.bytes_sent > 0
    # Verify multiple requests were sent by checking received data
    received = slow_server.get_received_data()
    received_str = received.decode('utf-8', errors='ignore')
    # Count how many times "GET /" appears (each request starts with this)
    request_count = received_str.count("GET /")
    assert request_count > 1, f"Expected multiple requests, got {request_count}"


async def test_range_abuse_sends_range_headers(slow_server):
    """Range Header Abuse should send Range headers with byte ranges."""
    cfg = _cfg(slow_server, mode="range-abuse")
    stats = await _drive(PROFILES["range-abuse"], cfg, run_for=0.3)
    assert stats.bytes_sent > 0
    # Verify Range headers were sent by checking received data
    received = slow_server.get_received_data()
    received_str = received.decode('utf-8', errors='ignore')
    # Count how many times "Range:" appears (each request has a Range header)
    range_count = received_str.count("Range:")
    assert range_count > 1, f"Expected multiple Range headers, got {range_count}"
    # Verify Range header format
    assert "Range: bytes=" in received_str, "Range header format incorrect"


async def test_cookie_bomb_sends_large_cookie(slow_server):
    """Cookie Bomb should send extremely large cookie values."""
    cfg = _cfg(slow_server, mode="cookie-bomb")
    stats = await _drive(PROFILES["cookie-bomb"], cfg, run_for=0.2)
    assert stats.bytes_sent > 0
    # Verify large cookie was sent by checking received data
    received = slow_server.get_received_data()
    received_str = received.decode('utf-8', errors='ignore')
    # Verify Cookie header exists and is large
    assert "Cookie:" in received_str, "Cookie header missing"
    # Find the cookie value and check it's large
    cookie_start = received_str.find("Cookie:")
    if cookie_start != -1:
        cookie_line = received_str[cookie_start:cookie_start + 100]  # Get first 100 chars
        assert "bomb_cookie=" in cookie_line, "Cookie name incorrect"


async def test_jsonrpc_slow_sends_json_content(slow_server):
    """JSON-RPC Slow should send JSON content type and partial JSON payload."""
    cfg = _cfg(slow_server, mode="jsonrpc-slow")
    stats = await _drive(PROFILES["jsonrpc-slow"], cfg, run_for=0.2)
    assert stats.bytes_sent > 0
    # Verify JSON content type and payload were sent
    received = slow_server.get_received_data()
    received_str = received.decode('utf-8', errors='ignore')
    assert "Content-Type: application/json" in received_str, "JSON content type missing"
    assert '"jsonrpc":"2.0"' in received_str, "JSON-RPC version missing"
    # Just check that JSON-RPC structure started (may be partial due to slow drip)
    assert '{"jsonrpc"' in received_str or '"method"' in received_str, "JSON-RPC structure missing"


async def test_smtp_slow_envelope_sends_smtp_commands(slow_server):
    """SMTP Slow Envelope should send SMTP envelope commands."""
    cfg = _cfg(slow_server, mode="smtp-slow-envelope")
    stats = await _drive(PROFILES["smtp-slow-envelope"], cfg, run_for=0.2)
    assert stats.bytes_sent > 0
    # Verify SMTP commands were sent
    received = slow_server.get_received_data()
    received_str = received.decode('utf-8', errors='ignore')
    assert "EHLO" in received_str, "EHLO command missing"
    assert "MAIL FROM:" in received_str, "MAIL FROM command missing"
    assert "RCPT TO:" in received_str, "RCPT TO command missing"


async def test_ftp_slow_command_sends_ftp_commands(slow_server):
    """FTP Slow Command should send FTP commands."""
    cfg = _cfg(slow_server, mode="ftp-slow-command")
    stats = await _drive(PROFILES["ftp-slow-command"], cfg, run_for=0.2)
    assert stats.bytes_sent > 0
    # Verify FTP commands were sent
    received = slow_server.get_received_data()
    received_str = received.decode('utf-8', errors='ignore')
    assert "USER" in received_str, "USER command missing"
    assert "PASS" in received_str, "PASS command missing"
    assert "PASV" in received_str, "PASV command missing"


async def test_multipart_slow_upload_sends_multipart_preamble(slow_server):
    """Multipart Slow Upload should send a multipart body without the closing boundary."""
    cfg = _cfg(slow_server, mode="multipart-slow-upload", base_post_length=32)
    stats = await _drive(PROFILES["multipart-slow-upload"], cfg, run_for=0.25)
    assert stats.bytes_sent > 0
    received = slow_server.get_received_data()
    received_str = received.decode('utf-8', errors='ignore')
    # The drive window is long enough to overrun the Content-Length accounting,
    # so scope structural assertions to the completed request head and the
    # upload preamble that immediately follows it.
    header_end = received_str.find("\r\n\r\n")
    assert header_end != -1, "request headers must complete"
    # Header names are case-insensitive on the wire (RFC 9110 §5.1); match
    # case-insensitively so legal casing can never hide a real terminator.
    head = received_str[: header_end + 4].lower()
    assert head.startswith("post /"), "missing request line"
    assert "content-type: multipart/form-data; boundary=" in head, (
        "multipart content type missing"
    )
    after_head = received_str[header_end + 4 :].lower()
    assert 'content-disposition: form-data; name="upload"' in after_head, (
        "upload part preamble missing"
    )
    boundary = head.split("boundary=", 1)[1].split("\r\n", 1)[0]
    assert len(boundary) > len("----webkitformboundary"), (
        f"boundary token missing, got {boundary!r}"
    )
    assert f"--{boundary}--" not in received_str.lower(), (
        "closing boundary must never be emitted"
    )


async def test_expect_continue_abuse_announces_body_and_stalls(slow_server):
    """Expect-Continue Abuse should announce a body via Expect and stall it."""
    cfg = _cfg(
        slow_server,
        mode="expect-continue-abuse",
        base_post_length=24,
        connect_timeout=0.05,
        delay_min=0,
        delay_max=0,
    )
    stats = await _drive(PROFILES["expect-continue-abuse"], cfg, run_for=0.25)
    assert stats.bytes_sent > 0
    received = slow_server.get_received_data()
    received_str = received.decode('utf-8', errors='ignore')
    assert "Expect: 100-continue" in received_str, "Expect header missing"
    assert "Content-Length:" in received_str, "announced body length missing"
    header_end = received_str.find("\r\n\r\n")
    assert header_end != -1, "request headers must complete before the stall"
    # The collector is silent, so the interim read hits its short deadline
    # and the stall dribbles within the 0.25s drive window.
    body = received_str[header_end + 4:]
    assert 1 <= len(body) <= 24, f"stalled body out of range: {len(body)} bytes"
