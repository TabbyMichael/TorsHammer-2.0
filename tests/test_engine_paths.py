"""Engine lifecycle coverage: ramp-up, circuit breaker, proxies, UDP and reporter.

``test_profiles.py`` only exercises the happy TCP path with ``quiet=True``, so
the engine's ramp-up staggering, verbose/circuit-breaker logging, proxy
success/failure accounting, the whole ``_udp_worker`` branch and the JSON
reporter line were all still cold. These tests drive ``AttackEngine`` directly.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from torshammer import engine as engine_mod
from torshammer import udp
from torshammer.config import Config
from torshammer.engine import AttackEngine
from torshammer.proxies import Proxy


def _cfg(port: int, **overrides: object) -> Config:
    defaults: dict[str, object] = {
        "host": "127.0.0.1",
        "port": port,
        "concurrency": 2,
        "mode": "slow-post",
        "delay_min": 0,
        "delay_max": 0.01,
        "base_post_length": 32,
        "connect_timeout": 3,
        "quiet": True,
    }
    defaults.update(overrides)
    return Config(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Ramp-up staggering (engine.run L35-43)
# ---------------------------------------------------------------------------


async def test_ramp_up_starts_workers_gradually(slow_server):
    cfg = _cfg(slow_server.port, concurrency=4, ramp_up=8, duration=0.5, quiet=True)
    eng = AttackEngine(cfg, asyncio.Event())
    await eng.run()
    assert eng.stats.connections > 0


async def test_ramp_up_breaks_when_stopped_midway(slow_server):
    """Stop firing between staggered starts exercises the ramp-up ``break`` (L39-40)."""
    stop = asyncio.Event()
    cfg = _cfg(slow_server.port, concurrency=8, ramp_up=2, duration=0, quiet=True)
    eng = AttackEngine(cfg, stop)
    run_task = asyncio.create_task(eng.run())
    await asyncio.sleep(0.05)  # let the first worker + first ramp sleep elapse
    stop.set()
    await asyncio.wait_for(run_task, timeout=5)


# ---------------------------------------------------------------------------
# Verbose worker logging + TCP circuit breaker (L85-93, L122-129)
# ---------------------------------------------------------------------------


async def test_tcp_circuit_breaker_verbose_logging(capsys):
    """Unreachable target with verbose logging drives the breaker + error prints."""
    cfg = _cfg(
        0,
        host="192.0.2.1",  # TEST-NET-1, always fails to connect
        concurrency=1,
        mode="slow-post",
        connect_timeout=0.2,
        max_errors=2,
        verbose=1,
        duration=0,
        quiet=False,
    )
    eng = AttackEngine(cfg, asyncio.Event())
    await eng.run()
    assert eng.stats.errors >= 2
    assert eng.stats.circuit_breaker is True
    err = capsys.readouterr().out
    assert "Circuit breaker" in err
    assert "consecutive errors" in err


# ---------------------------------------------------------------------------
# Proxy success / failure accounting (L112-113, L133-134) and pool starvation
# ---------------------------------------------------------------------------


async def test_proxy_success_recorded(fake_socks5, slow_server):
    """A reachable SOCKS5 proxy yields a success record (engine L112-113)."""
    proxy = Proxy("socks5", "127.0.0.1", fake_socks5.port)
    cfg = _cfg(
        slow_server.port,
        concurrency=1,
        mode="slow-post",
        proxies=[proxy],
        duration=0.3,
    )
    eng = AttackEngine(cfg, asyncio.Event())
    await eng.run()
    assert proxy.failures == 0  # record_success keeps it clean
    assert eng.stats.connections > 0


async def test_proxy_failure_recorded(slow_server):
    """A dead proxy endpoint drives the failure/deprioritize path (L133-134)."""
    dead = Proxy("socks5", "127.0.0.1", 1, failure_threshold=1)  # connect refused
    cfg = _cfg(
        slow_server.port,
        concurrency=1,
        mode="slow-post",
        proxies=[dead],
        connect_timeout=0.2,
        duration=0.3,
    )
    eng = AttackEngine(cfg, asyncio.Event())
    await eng.run()
    assert dead.failures >= 1
    assert eng.stats.errors >= 1


async def test_pool_starvation_waits_and_retries(slow_server, monkeypatch):
    """A pool that hands out ``None`` exercises the sleep-and-retry branch (L96-98)."""

    class _EmptyPool:
        def __init__(self) -> None:
            self.calls = 0

        def next(self) -> Proxy | None:
            self.calls += 1
            return None

        def record_success(self, proxy: Proxy) -> None:
            pass

        def record_failure(self, proxy: Proxy) -> None:
            pass

    sleeps: list[float] = []
    real_sleep = asyncio.sleep

    async def spy_sleep(delay: float, *a: object, **k: object) -> None:
        sleeps.append(delay)
        await real_sleep(0)

    monkeypatch.setattr(engine_mod.asyncio, "sleep", spy_sleep)
    cfg = _cfg(
        slow_server.port,
        concurrency=1,
        mode="slow-post",
        proxies=[Proxy("socks5", "h", 1)],
        duration=0.05,
    )
    eng = AttackEngine(cfg, asyncio.Event())
    pool = _EmptyPool()
    eng._pool = pool  # type: ignore[assignment]
    await eng.run()
    assert pool.calls > 0
    assert 1.0 in sleeps


# ---------------------------------------------------------------------------
# Writer close-on-error swallow (L140-148)
# ---------------------------------------------------------------------------


async def test_writer_close_oserror_swallowed(slow_server, monkeypatch):
    """An OSError while tearing down a finished connection is swallowed (L146-147)."""

    def _boom(writer: object) -> None:
        raise OSError("linger failed")

    monkeypatch.setattr(engine_mod.conn, "set_linger_off", _boom)
    cfg = _cfg(slow_server.port, concurrency=1, mode="idle-hold", duration=0.2)
    eng = AttackEngine(cfg, asyncio.Event())
    await eng.run()
    assert eng.stats.active == 0


# ---------------------------------------------------------------------------
# Grace-period cancel of a stuck worker (L61-64, L120-121)
# ---------------------------------------------------------------------------


async def test_grace_period_cancels_stuck_worker(flaky_server, monkeypatch):
    """A worker blocked in the SOCKS handshake is cancelled at the grace timeout."""
    # slow_server-like target that accepts but never answers the SOCKS reply, so
    # open_connection() blocks in ``readexactly`` until it is cancelled.
    hang = Proxy("socks5", "127.0.0.1", flaky_server.port)
    cfg = _cfg(
        flaky_server.port,
        concurrency=1,
        mode="slow-post",
        proxies=[hang],
        connect_timeout=30,  # never self-times-out; relies on the cancel below
        duration=0.1,
    )
    # Shrink the grace window so the test stays fast but still exercises cancel().
    eng = AttackEngine(cfg, asyncio.Event())
    run_task = asyncio.create_task(eng.run())
    await asyncio.sleep(0.2)  # worker is now stuck mid-handshake
    # run() is waiting in ``asyncio.wait(workers, timeout=2.0)``; let it fire.
    await asyncio.wait_for(run_task, timeout=10)
    assert eng.stats.active == 0


# ---------------------------------------------------------------------------
# UDP worker (L150-208)
# ---------------------------------------------------------------------------


async def test_udp_worker_sends_and_completes():
    """A live datagram receiver lets the UDP worker connect, drip and complete."""
    received: list[bytes] = []

    class _Sink(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr) -> None:
            received.append(data)

    loop = asyncio.get_running_loop()
    transport, _proto = await loop.create_datagram_endpoint(_Sink, local_addr=("127.0.0.1", 0))
    port = transport.get_extra_info("socket").getsockname()[1]
    try:
        cfg = _cfg(
            port,
            host="127.0.0.1",
            concurrency=1,
            mode="udp",
            base_post_length=16,
            delay_min=0,
            delay_max=0,
            duration=0.3,
        )
        eng = AttackEngine(cfg, asyncio.Event())
        await eng.run()
        assert eng.stats.connections > 0
        assert eng.stats.completed >= 1
        assert eng.stats.bytes_sent > 0
        assert received, "target received no datagrams"
    finally:
        transport.close()


async def test_udp_worker_backoff_and_breaker(capsys, monkeypatch):
    """A connect failure drives the UDP error/backoff branch and the breaker."""

    async def _raise(*a: object, **k: object):
        raise ConnectionRefusedError("no route")

    monkeypatch.setattr(udp, "open_datagram", _raise)
    cfg = _cfg(
        0,
        host="127.0.0.1",
        concurrency=1,
        mode="udp",
        max_errors=2,
        connect_timeout=0.2,
        verbose=1,
        duration=0,
        quiet=False,
    )
    eng = AttackEngine(cfg, asyncio.Event())
    # Keep the injected backoff from slowing the test.
    real_sleep = asyncio.sleep

    async def fast_sleep(delay: float, *a: object, **k: object) -> None:
        await real_sleep(0)

    monkeypatch.setattr(engine_mod.asyncio, "sleep", fast_sleep)
    await eng.run()
    assert eng.stats.errors >= 2
    assert eng.stats.circuit_breaker is True
    out = capsys.readouterr().out
    assert "Circuit breaker" in out


async def test_udp_transport_close_error(monkeypatch):
    """An OSError on ``transport.close()`` is swallowed (L203-206)."""

    class _BadCloseTransport:
        def sendto(self, _data: bytes) -> None:
            return None

        def close(self) -> None:
            raise OSError("already closed")

    async def _fake_open(*a: object, **k: object):
        return _BadCloseTransport(), None

    monkeypatch.setattr(udp, "open_datagram", _fake_open)
    cfg = _cfg(
        0,
        host="127.0.0.1",
        concurrency=1,
        mode="udp",
        base_post_length=8,
        delay_min=0,
        delay_max=0,
        duration=0.1,
    )
    eng = AttackEngine(cfg, asyncio.Event())
    await eng.run()
    assert eng.stats.connections > 0
    assert eng.stats.active == 0  # decremented even though close() raised


async def test_udp_worker_reraises_cancellation(monkeypatch):
    """A UDP worker cancelled mid-connect re-raises CancelledError (L188-189)."""
    started = asyncio.Event()

    async def _hang(*_a: object, **_k: object):
        started.set()
        await asyncio.Event().wait()  # block until cancelled

    monkeypatch.setattr(udp, "open_datagram", _hang)
    cfg = _cfg(0, host="127.0.0.1", concurrency=1, mode="udp")
    eng = AttackEngine(cfg, asyncio.Event())
    task = asyncio.create_task(eng._udp_worker(0))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


# ---------------------------------------------------------------------------
# JSON reporter (L249-250)
# ---------------------------------------------------------------------------


async def test_json_reporter_emits_payload(slow_server, capsys):
    cfg = _cfg(
        slow_server.port,
        concurrency=2,
        mode="slow-post",
        json_output=True,
        quiet=False,
        stats_interval=0.05,
        duration=0.2,
    )
    eng = AttackEngine(cfg, asyncio.Event())
    await eng.run()
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    payload = json.loads(lines[-1])
    assert {"connections", "peak_active", "bytes_sent", "verdict"} <= set(payload)
