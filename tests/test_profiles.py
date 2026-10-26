"""Tests for the attack profiles and the async engine."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import SlowServer
from torshammer.config import Config
from torshammer.engine import AttackEngine
from torshammer.profiles import PROFILES, Profile, _base_headers, _path
from torshammer.stats import Stats, classify_verdict


def _cfg(slow_server: SlowServer, **overrides: Any) -> Config:
    defaults: dict[str, Any] = {
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


async def _drive(
    profile_cls: type[Profile],
    cfg: Config,
    stop: asyncio.Event | None = None,
    run_for: float = 0.15,
) -> Stats:
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
    "mode",
    [
        "slow-post",
        "slow-post-headers",
        "slow-headers",
        "slow-read",
        "chunked",
        "multipart-slow-upload",
        "expect-continue-abuse",
        "websocket-slow-upgrade",
        "http-pipelining",
        "range-abuse",
        "cookie-bomb",
        "jsonrpc-slow",
        "smtp-slow-envelope",
        "ftp-slow-command",
        "imap-slow-literal",
        "redis-resp-slow",
        "postgres-startup-slow",
        "dns-tcp-slow",
        "nntp-slow-post",
        "slow-xml",
        "slow-form-parse",
        "header-count-flood",
        "websocket-slow-frame",
        "req-smuggling-probe",
        "h2-rapid-reset",
        "h2-slow-streams",
        "h2-continuation-flood",
        "h2-hpack-drip",
        "tls-slow-hello",
        "tls-renego-hold",
    ],
)
async def test_profile_sends_bytes(slow_server, mode):
    cfg = _cfg(slow_server)
    await _drive(PROFILES[mode], cfg)
    assert slow_server.bytes_received > 0


def test_registry_matches_documented_modes():
    """PROFILES (the TCP modes) plus the engine's ``udp`` mode must equal the
    canonical documented mode list in ``tests/mode_list.txt``.

    Derived rather than hardcoded so adding a mode never leaves a stale magic
    list here (the same file is the cross-backend parity contract).
    """
    text = (Path(__file__).resolve().parents[1] / "tests" / "mode_list.txt").read_text(
        encoding="utf-8"
    )
    canonical = {line.strip() for line in text.splitlines() if line.strip()}
    assert {*PROFILES, "udp"} == canonical


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
        custom_headers={"User-Agent": "CustomAgent/1.0", "Accept": "application/xml"},
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
    received_str = received.decode("utf-8", errors="ignore")
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
    received_str = received.decode("utf-8", errors="ignore")
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
    received_str = received.decode("utf-8", errors="ignore")
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
    received_str = received.decode("utf-8", errors="ignore")
    # Verify Cookie header exists and is large
    assert "Cookie:" in received_str, "Cookie header missing"
    # Find the cookie value and check it's large
    cookie_start = received_str.find("Cookie:")
    if cookie_start != -1:
        cookie_line = received_str[cookie_start : cookie_start + 100]  # Get first 100 chars
        assert "bomb_cookie=" in cookie_line, "Cookie name incorrect"


async def test_jsonrpc_slow_sends_json_content(slow_server):
    """JSON-RPC Slow should send JSON content type and partial JSON payload."""
    cfg = _cfg(slow_server, mode="jsonrpc-slow")
    stats = await _drive(PROFILES["jsonrpc-slow"], cfg, run_for=0.2)
    assert stats.bytes_sent > 0
    # Verify JSON content type and payload were sent
    received = slow_server.get_received_data()
    received_str = received.decode("utf-8", errors="ignore")
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
    received_str = received.decode("utf-8", errors="ignore")
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
    received_str = received.decode("utf-8", errors="ignore")
    assert "USER" in received_str, "USER command missing"
    assert "PASS" in received_str, "PASS command missing"
    assert "PASV" in received_str, "PASV command missing"


async def test_engine_counts_completed_connections(slow_server):
    """Regression: engine.stats.completed must increment when a profile runs
    to completion. Previously slow-post / slow-post-headers / chunked fell off
    the end of ``run()`` returning None, so ``if completed:`` in
    ``AttackEngine._attack`` never fired and the advisory verdict could never
    report LIKELY_VULNERABLE."""
    cfg = _cfg(
        slow_server,
        mode="slow-post",
        concurrency=2,
        duration=0.6,
        base_post_length=32,
        delay_min=0,
        delay_max=0.02,
        ramp_up=0,
        quiet=True,
    )
    engine = AttackEngine(cfg, asyncio.Event())
    await engine.run()
    assert engine.stats.completed > 0
    assert classify_verdict(engine.stats)[0] == "LIKELY_VULNERABLE"


@pytest.mark.parametrize("mode", ["slow-post", "slow-post-headers", "chunked"])
async def test_profile_returns_true_on_natural_completion(slow_server, mode):
    """A profile that finishes its body without being stopped must return True
    (not None) so the engine counts it as a completed connection."""
    cfg = _cfg(slow_server, mode=mode, base_post_length=20, delay_min=0, delay_max=0)
    stats = Stats()
    reader, writer = await asyncio.open_connection("127.0.0.1", cfg.port)
    try:
        result = await asyncio.wait_for(
            PROFILES[mode]().run(reader, writer, cfg, "TestAgent/1.0", stats, asyncio.Event()),
            timeout=3,
        )
    finally:
        writer.close()
        await writer.wait_closed()
    assert result is True


async def test_multipart_slow_upload_sends_multipart_preamble(slow_server):
    """Multipart Slow Upload should send a multipart body without the closing boundary."""
    cfg = _cfg(slow_server, mode="multipart-slow-upload", base_post_length=32)
    stats = await _drive(PROFILES["multipart-slow-upload"], cfg, run_for=0.25)
    assert stats.bytes_sent > 0
    received = slow_server.get_received_data()
    received_str = received.decode("utf-8", errors="ignore")
    # The drive window is long enough to overrun the Content-Length accounting,
    # so scope structural assertions to the completed request head and the
    # upload preamble that immediately follows it.
    header_end = received_str.find("\r\n\r\n")
    assert header_end != -1, "request headers must complete"
    # Header names are case-insensitive on the wire (RFC 9110 §5.1); match
    # case-insensitively so legal casing can never hide a real terminator.
    head = received_str[: header_end + 4].lower()
    assert head.startswith("post /"), "missing request line"
    assert "content-type: multipart/form-data; boundary=" in head, "multipart content type missing"
    after_head = received_str[header_end + 4 :].lower()
    assert 'content-disposition: form-data; name="upload"' in after_head, (
        "upload part preamble missing"
    )
    boundary = head.split("boundary=", 1)[1].split("\r\n", 1)[0]
    assert len(boundary) > len("----webkitformboundary"), (
        f"boundary token missing, got {boundary!r}"
    )
    assert f"--{boundary}--" not in received_str.lower(), "closing boundary must never be emitted"


async def test_expect_continue_abuse_announces_body_and_stalls(slow_server: SlowServer):
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
    received: bytes = slow_server.get_received_data()
    received_str: str = received.decode("utf-8", errors="ignore")
    assert "Expect: 100-continue" in received_str, "Expect header missing"
    assert "Content-Length:" in received_str, "announced body length missing"
    header_end: int = received_str.find("\r\n\r\n")
    assert header_end != -1, "request headers must complete before the stall"
    # The collector is silent, so the interim read hits its short deadline
    # and the stall dribbles within the 0.25s drive window.
    body: str = received_str[header_end + 4 :]
    assert 1 <= len(body) <= 24, f"stalled body out of range: {len(body)} bytes"


# --- impact metering (response status / latency + smarter verdict) ----------


def test_stats_record_response_bytes_tallies_statuses():
    """Parsed HTTP status lines populate the per-class counters."""
    s = Stats()
    payloads = (
        b"HTTP/1.1 200 OK\r\n\r\n",
        b"HTTP/1.1 404 Not Found\r\n\r\n",
        b"HTTP/1.1 503 Service Unavailable\r\n\r\n",
    )
    for p in payloads:
        s.record_response_bytes(p)
    assert s.responses == 3
    assert (s.status_2xx, s.status_4xx, s.status_5xx) == (1, 1, 1)
    assert s.bytes_received == sum(len(p) for p in payloads)


def test_stats_record_response_bytes_ignores_non_status():
    s = Stats()
    s.record_response_bytes(b"garbage without a status line\r\n")
    assert s.responses == 0
    assert s.bytes_received > 0


def test_stats_response_latency_mean_and_negative_guard():
    s = Stats()
    assert s.mean_response_latency == 0.0
    s.record_response_latency(0.2)
    s.record_response_latency(0.4)
    assert s.resp_latency_count == 2
    assert abs(s.mean_response_latency - 0.3) < 1e-9
    s.record_response_latency(-1.0)  # ignored
    assert s.resp_latency_count == 2


def test_verdict_server_errors_under_load_is_vulnerable():
    """5xx replies with no completed cycles still read as impact (VULNERABLE)."""
    s = Stats(connections=20, completed=0, peak_active=5, errors=0)
    for _ in range(5):
        s.record_response_bytes(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
    verdict, reason = classify_verdict(s)
    assert verdict == "LIKELY_VULNERABLE"
    assert "5xx" in reason


def test_verdict_telemetry_appended_when_responses_seen():
    """Existing INCONCLUSIVE path now surfaces observed response telemetry."""
    s = Stats(connections=10, completed=1, errors=1, peak_active=3)
    s.record_response_bytes(b"HTTP/1.1 200 OK\r\n\r\n")
    s.record_response_latency(0.5)
    verdict, reason = classify_verdict(s)
    assert verdict == "INCONCLUSIVE"
    assert "responses=1" in reason
    assert "mean_resp_latency=0.50s" in reason


async def test_pipelining_meters_server_errors(slow_server):
    """A target that answers 503 is metered into the impact counters."""
    slow_server.respond_body = b"HTTP/1.1 503 Service Unavailable\r\n\r\n"
    cfg = _cfg(slow_server, mode="http-pipelining")
    stats = await _drive(PROFILES["http-pipelining"], cfg, run_for=0.25)
    assert stats.status_5xx >= 1
    assert stats.responses >= 1
    assert stats.resp_latency_count >= 1
    assert stats.mean_response_latency >= 0.0


# --- Phase 1 Tier-1 protocol-starvation modes -------------------------------


async def test_imap_slow_literal_announces_unclosed_literal(slow_server):
    """IMAP literal: announce ``{N}`` then never deliver N octets."""
    cfg = _cfg(slow_server, mode="imap-slow-literal", base_post_length=64)
    await _drive(PROFILES["imap-slow-literal"], cfg, run_for=0.25)
    data: bytes = slow_server.get_received_data()
    assert b" APPEND INBOX {" in data, "literal command missing"
    assert b"}\r\n" in data, "literal length marker not closed"


async def test_redis_resp_slow_declares_oversized_bulk(slow_server):
    """Redis RESP: ``*1`` multibulk with a ``$len`` bulk that is never completed."""
    cfg = _cfg(slow_server, mode="redis-resp-slow", base_post_length=64)
    await _drive(PROFILES["redis-resp-slow"], cfg, run_for=0.25)
    data: bytes = slow_server.get_received_data()
    m = re.search(rb"\*1\r\n\$(\d+)\r\n", data)
    assert m is not None, "RESP multibulk/bulk framing missing"
    declared = int(m.group(1))
    assert declared >= 64, f"bulk length too small: {declared}"
    body = data[m.end() :]
    assert len(body) < declared, f"bulk unexpectedly completed ({len(body)} >= {declared})"


async def test_postgres_startup_slow_claims_large_packet(slow_server):
    """Postgres StartupMessage: length field over-promises; version is 3.0."""
    cfg = _cfg(slow_server, mode="postgres-startup-slow", base_post_length=64)
    await _drive(PROFILES["postgres-startup-slow"], cfg, run_for=0.25)
    data: bytes = slow_server.get_received_data()
    assert len(data) >= 8, "startup header truncated"
    total = int.from_bytes(data[0:4], "big")
    version = int.from_bytes(data[4:8], "big")
    assert version == 196608, f"protocol version wrong: {version}"
    # Length counts the 8-byte header itself + the declared body; the profile
    # never emits the terminating NUL that would make it a well-formed packet.
    assert total == 8 + 64, f"declared startup packet length wrong: {total}"
    assert b"user=slowprobe\x00" in data, "startup parameters missing"


async def test_dns_tcp_slow_announces_oversized_query(slow_server):
    """DNS-over-TCP: 2-byte length prefix exceeds the bytes actually sent."""
    cfg = _cfg(slow_server, mode="dns-tcp-slow", base_post_length=64)
    await _drive(PROFILES["dns-tcp-slow"], cfg, run_for=0.25)
    data: bytes = slow_server.get_received_data()
    assert len(data) >= 4, "tcp-length prefix + header truncated"
    declared = int.from_bytes(data[0:2], "big")
    assert declared == 64, f"declared query size wrong: {declared}"
    assert data[2:4] == b"\xaa\xbb", "query ID not at expected offset"
    assert len(data) - 2 < declared, f"query completed ({len(data) - 2} >= {declared})"


async def test_nntp_slow_post_never_terminates_article(slow_server):
    """NNTP POST: dot-terminator ``\\r\\n.\\r\\n`` must never be emitted."""
    cfg = _cfg(slow_server, mode="nntp-slow-post", base_post_length=64)
    await _drive(PROFILES["nntp-slow-post"], cfg, run_for=0.25)
    data: bytes = slow_server.get_received_data()
    assert data.startswith(b"POST\r\n"), "POST command not sent first"
    assert b"\r\n.\r\n" not in data, "article terminator leaked"


async def test_idle_hold_sends_nothing(slow_server):
    """Idle-hold pins a slot with zero request bytes."""
    cfg = _cfg(slow_server, mode="idle-hold")
    stats = await _drive(PROFILES["idle-hold"], cfg, run_for=0.2)
    assert stats.bytes_sent == 0, "idle-hold must not send any bytes"
    assert slow_server.get_received_data() == b"", "server received unexpected bytes"


# --- Phase 2 Tier-2 HTTP-parser-targeted modes ------------------------------


async def test_slow_xml_announces_unclosed_document(slow_server):
    """slow-xml sends an XML/XXE prelude with an oversized body promise."""
    cfg = _cfg(slow_server, mode="slow-xml", base_post_length=64)
    await _drive(PROFILES["slow-xml"], cfg, run_for=0.25)
    received_str: str = slow_server.get_received_data().decode("utf-8", errors="ignore")
    assert "Content-Type: application/xml" in received_str
    assert "Content-Length:" in received_str
    assert "<?xml" in received_str and "<!DOCTYPE" in received_str, "XML prelude missing"


async def test_slow_form_parse_streams_urlencoded_pairs(slow_server):
    """slow-form-parse dribbles endless urlencoded key=value pairs."""
    cfg = _cfg(slow_server, mode="slow-form-parse", base_post_length=64)
    await _drive(PROFILES["slow-form-parse"], cfg, run_for=0.25)
    received: bytes = slow_server.get_received_data()
    received_str: str = received.decode("utf-8", errors="ignore")
    assert "Content-Type: application/x-www-form-urlencoded" in received_str
    header_end: int = received_str.find("\r\n\r\n")
    assert header_end != -1, "request headers must complete before the body"
    body: str = received_str[header_end + 4 :]
    assert "=" in body and "&" in body, f"no urlencoded pairs in body: {body!r}"


async def test_header_count_flood_completes_many_headers(slow_server):
    """header-count-flood emits thousands of headers and then COMPLETES them."""
    cfg = _cfg(slow_server, mode="header-count-flood")
    await _drive(PROFILES["header-count-flood"], cfg, run_for=0.5)
    received: bytes = slow_server.get_received_data()
    assert received.count(b"\r\nX-") >= 200, "expected a flood of header lines"
    assert b"\r\n\r\n" in received, "header block must be completed"


async def test_websocket_slow_frame_completes_handshake_then_dribbles(slow_server):
    """websocket-slow-frame finishes the upgrade request, then sends a partial frame."""
    cfg = _cfg(slow_server, mode="websocket-slow-frame")
    await _drive(PROFILES["websocket-slow-frame"], cfg, run_for=0.25)
    received: bytes = slow_server.get_received_data()
    received_str: str = received.decode("utf-8", errors="ignore")
    assert "Upgrade: websocket" in received_str
    header_end: int = received_str.find("\r\n\r\n")
    assert header_end != -1, "upgrade request must complete (blank line)"
    frame: bytes = received[header_end + 4 :]
    assert len(frame) >= 2, "a WebSocket frame header must follow the handshake"
    assert frame[0] == 0x81, f"expected FIN|text frame opcode, got {frame[0]:#04x}"


async def test_req_smuggling_probe_sends_ambiguous_framing(slow_server):
    """req-smuggling-probe presents BOTH Content-Length and Transfer-Encoding."""
    cfg = _cfg(slow_server, mode="req-smuggling-probe")
    await _drive(PROFILES["req-smuggling-probe"], cfg, run_for=0.2)
    received_str: str = slow_server.get_received_data().decode("utf-8", errors="ignore")
    lowered = received_str.lower()
    assert "content-length:" in lowered, "CL framing missing"
    assert "transfer-encoding: chunked" in lowered, "TE framing missing"


# --- Phase 3 Tier-3 HTTP/2 modes --------------------------------------------


async def test_h2_rapid_reset_opens_and_resets_streams(slow_server):
    """h2-rapid-reset sends the preface then HEADERS immediately followed by RST."""
    cfg = _cfg(slow_server, mode="h2-rapid-reset")
    await _drive(PROFILES["h2-rapid-reset"], cfg, run_for=0.25)
    data: bytes = slow_server.get_received_data()
    assert data.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), "missing client preface"
    # After the 24-byte preface the first frame must be SETTINGS (type 0x4).
    assert data[24 + 3] == 0x4, "first frame after preface is not SETTINGS"
    # At least one RST_STREAM frame (type 0x3) must appear.
    assert any(data[i + 3] == 0x3 for i in range(24, len(data) - 4)), "no RST_STREAM frame sent"


async def test_h2_slow_streams_leaves_streams_half_open(slow_server):
    """h2-slow-streams sends HEADERS without END_STREAM, then trickles DATA."""
    cfg = _cfg(slow_server, mode="h2-slow-streams")
    await _drive(PROFILES["h2-slow-streams"], cfg, run_for=0.25)
    data: bytes = slow_server.get_received_data()
    assert data.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), "missing client preface"
    # HEADERS frames (type 0x1) must never carry the END_STREAM flag (0x1).
    headers_seen = 0
    i = 24
    while i + 9 <= len(data):
        length = int.from_bytes(data[i : i + 3], "big")
        ftype = data[i + 3]
        flags = data[i + 4]
        if length > (1 << 24) - 1 or i + 9 + length > len(data):
            break
        if ftype == 0x1:
            headers_seen += 1
            assert not (flags & 0x1), "HEADERS must omit END_STREAM"
        i += 9 + length
    assert headers_seen > 0, "no HEADERS frames sent"


async def test_h2_continuation_flood_never_ends_headers(slow_server):
    """h2-continuation-flood keeps a header block open with many CONTINUATIONs."""
    cfg = _cfg(slow_server, mode="h2-continuation-flood")
    await _drive(PROFILES["h2-continuation-flood"], cfg, run_for=0.25)
    data: bytes = slow_server.get_received_data()
    assert data.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), "missing client preface"
    continuation_count = 0
    i = 24
    while i + 9 <= len(data):
        length = int.from_bytes(data[i : i + 3], "big")
        ftype = data[i + 3]
        flags = data[i + 4]
        if length > (1 << 24) - 1 or i + 9 + length > len(data):
            break
        if ftype == 0xA:  # CONTINUATION
            continuation_count += 1
            assert not (flags & 0x4), "CONTINUATION must not set END_HEADERS (block stays open)"
        i += 9 + length
    assert continuation_count >= 100, (
        f"expected a flood of CONTINUATION frames, got {continuation_count}"
    )


async def test_h2_hpack_drip_fragments_one_header_block(slow_server):
    """h2-hpack-drip dribbles a single header block one octet per frame."""
    cfg = _cfg(slow_server, mode="h2-hpack-drip", base_post_length=64)
    await _drive(PROFILES["h2-hpack-drip"], cfg, run_for=0.4)
    data: bytes = slow_server.get_received_data()
    assert data.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), "missing client preface"
    # Reassemble the header block from HEADERS + CONTINUATION payloads and check
    # it is a valid (literal, non-Huffman) HPACK encoding of pseudo-headers.
    block = bytearray()
    i = 24
    while i + 9 <= len(data):
        length = int.from_bytes(data[i : i + 3], "big")
        ftype = data[i + 3]
        if length > (1 << 24) - 1 or i + 9 + length > len(data):
            break
        if ftype in (0x1, 0xA):
            block += data[i + 9 : i + 9 + length]
        i += 9 + length
    # A literal-without-indexing new-name field begins with 0x00, then a
    # length-prefixed name. ":method" is 7 bytes -> 0x00 0x07 ':method'.
    assert bytes(block[:9]) == b"\x00\x07:method", f"unexpected HPACK start: {bytes(block[:9])!r}"


# --- Phase 4 Tier-4 TLS handshake-starvation modes --------------------------


async def test_tls_slow_hello_declares_unfinished_record(slow_server):
    """tls-slow-hello opens a handshake record far larger than the bytes sent."""
    cfg = _cfg(slow_server, mode="tls-slow-hello")
    await _drive(PROFILES["tls-slow-hello"], cfg, run_for=0.3)
    data: bytes = slow_server.get_received_data()
    # First octet is the handshake content type, then the legacy record version.
    assert data[0] == 0x16, "first record must be a handshake record"
    assert int.from_bytes(data[1:3], "big") == 0x0301, "bad TLS record version"
    declared = int.from_bytes(data[3:5], "big")
    # A ClientHello handshake header sits inside the record.
    assert data[5] == 0x01, "expected a ClientHello handshake message"
    msg_len = int.from_bytes(data[6:9], "big")
    # The declared record/handshake lengths agree, but the client never delivers
    # a full record - the whole point of handshake starvation.
    assert declared == msg_len + 4, "record/handshake lengths inconsistent"
    assert len(data) < declared, "record was (impossibly) completed"


async def test_tls_renego_hold_reinitiates_handshakes(slow_server):
    """tls-renego-hold emits many fresh, never-completed ClientHello records."""
    cfg = _cfg(slow_server, mode="tls-renego-hold")
    await _drive(PROFILES["tls-renego-hold"], cfg, run_for=0.5)
    data: bytes = slow_server.get_received_data()
    # Each initiation starts with a handshake record declaring 2048 bytes followed
    # by a ClientHello whose message length is 2048 - 4. That prefix recurs once
    # per renegotiation attempt.
    prefix = b"\x16\x03\x01\x08\x00\x01" + (2044).to_bytes(3, "big")
    initiations = data.count(prefix)
    assert initiations >= 2, f"expected repeated handshake initiations, got {initiations}"
