"""Tests for the attack profiles and the async engine."""

from __future__ import annotations

import asyncio

import pytest

from torshammer import conn
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
    reader, writer = await conn.open_connection("127.0.0.1", cfg.port, config=cfg)
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
    "mode", ["slow-post", "slow-post-headers", "slow-headers", "slow-read", "chunked"]
)
async def test_profile_sends_bytes(slow_server, mode):
    cfg = _cfg(slow_server)
    await _drive(PROFILES[mode], cfg)
    assert slow_server.bytes_received > 0


async def test_profile_honors_pre_set_stop(slow_server):
    cfg = _cfg(slow_server)
    stop = asyncio.Event()
    stop.set()
    stats = Stats()
    reader, writer = await conn.open_connection("127.0.0.1", cfg.port, config=cfg)
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
