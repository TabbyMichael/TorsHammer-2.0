"""Table-driven coverage for the attack profiles.

``test_profiles.py`` drives every TCP mode with ``task.cancel()``, so a profile
loop is only ever *interrupted* - it never runs its natural exit paths. The
bulk of ``profiles.py``'s uncovered lines are exactly those exits:

* the trailing ``return not stop.is_set()`` after a ``while not stop`` loop, and
* the early ``return False`` guards that fire when ``stop`` is set during a
  finite preamble loop (SMTP/FTP command list, WebSocket header loop, multipart
  header lines, the ``_announce_then_dribble`` protocol profiles, ...).

This module closes those with three coordinated mechanisms, plus direct unit
tests for the small helper branches that no socket scenario reaches reliably:

1. a **graceful-stop pass**: run each profile, then *set* the stop flag and
   await the task to completion (never cancel), exercising the post-loop returns
   and the infinite dribble loops (multipart boundary chunks, JSON-RPC's second
   loop, header-count completion).
2. a **pre-set-stop pass**: enter every profile with ``stop`` already set,
   exercising the early ``return False`` exits and the ``_announce_then_dribble``
   short-circuits in one shot.
3. **flaky-server passes** against a target that hangs up mid-stream: a clean
   close gives ``reader.read() -> b""`` (slow-read's EOF break), a hard RST gives
   ``ConnectionResetError`` inside the response drain.
"""

from __future__ import annotations

import asyncio
from typing import Any, cast
from unittest.mock import MagicMock

import pytest

from torshammer import profiles
from torshammer.config import Config
from torshammer.profiles import (
    PROFILES,
    Profile,
    _announce_then_dribble,
    _base_headers,
    _random_header_name,
    _read_available,
    _write,
)
from torshammer.settings import all_modes
from torshammer.stats import Stats

_TCP_MODES = sorted(set(all_modes()) - {"udp"})

# Modes whose interesting inner loops need many dribbles to complete within the
# graceful window; give them a longer run time.
_LONGER: dict[str, float] = {
    "header-count-flood": 0.5,
    "multipart-slow-upload": 0.35,
    "jsonrpc-slow": 0.2,
}


def _cfg(port: int, **overrides: Any) -> Config:
    defaults: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": port,
        "connect_timeout": 0.05,
        "delay_min": 0,
        "delay_max": 0,
        "base_post_length": 32,
        "path": "/t",
        "randomize_path": False,
    }
    defaults.update(overrides)
    return Config(**defaults)


async def _run_to_completion(
    profile_cls: type[Profile],
    cfg: Config,
    *,
    pre_set: bool,
    run_for: float,
) -> tuple[Stats, bool]:
    """Run ``profile_cls`` against ``cfg.port`` and return it by *setting* stop.

    The task is awaited (not cancelled), so the profile reaches its own return
    statement. Connection errors are tolerated: a flaky target legitimately makes
    the dribble loop raise.
    """
    stop = asyncio.Event()
    if pre_set:
        stop.set()
    stats = Stats()
    reader, writer = await asyncio.open_connection("127.0.0.1", cfg.port)
    task = asyncio.create_task(profile_cls().run(reader, writer, cfg, "UA/1.0", stats, stop))
    try:
        if not pre_set:
            await asyncio.sleep(run_for)
            stop.set()
        result = await asyncio.wait_for(task, timeout=5)
    except (ConnectionError, OSError):
        result = False
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass
    return stats, result


# --- mechanism 1: graceful stop drives the post-loop returns ----------------


@pytest.mark.parametrize("mode", _TCP_MODES)
async def test_profile_graceful_stop_returns(slow_server, mode):
    cfg = _cfg(slow_server.port)
    stats, result = await _run_to_completion(
        PROFILES[mode], cfg, pre_set=False, run_for=_LONGER.get(mode, 0.08)
    )
    # Exiting via stop must yield a boolean (never None -> the engine's
    # "completed" accounting depends on it).
    assert result in (True, False)
    assert stats.bytes_sent >= 0


@pytest.mark.parametrize("mode", ["slow-post", "chunked", "http-pipelining"])
async def test_body_profiles_send_bytes_on_graceful_stop(slow_server, mode):
    cfg = _cfg(slow_server.port, base_post_length=16)
    stats, _ = await _run_to_completion(PROFILES[mode], cfg, pre_set=False, run_for=0.1)
    assert stats.bytes_sent > 0


# --- mechanism 2: pre-set stop drives the early return-False exits ----------


@pytest.mark.parametrize("mode", _TCP_MODES)
async def test_profile_pre_set_stop_exits_early(slow_server, mode):
    cfg = _cfg(slow_server.port)
    _, result = await _run_to_completion(PROFILES[mode], cfg, pre_set=True, run_for=0.0)
    assert result in (True, False)


# --- mechanism 3: flaky target drives the read / connection-lost branches ---


async def test_slow_read_breaks_on_server_close(flaky_server):
    """A clean hang-up makes ``reader.read()`` return EOF -> the EOF break."""
    cfg = _cfg(flaky_server.port)
    _stats, result = await _run_to_completion(
        PROFILES["slow-read"], cfg, pre_set=False, run_for=0.3
    )
    assert result in (True, False)


@pytest.mark.parametrize(
    "mode",
    [
        "http-pipelining",
        "range-abuse",
        "h2-rapid-reset",
        "h2-continuation-flood",
        "tls-renego-hold",
    ],
)
async def test_drain_profiles_survive_hard_reset(reset_server, mode):
    """A mid-stream RST exercises the ``_read_available`` connection-reset path."""
    cfg = _cfg(reset_server.port)
    await _run_to_completion(PROFILES[mode], cfg, pre_set=False, run_for=0.2)


# --- direct helper / branch coverage ----------------------------------------


async def test_write_timeout_raises_connectionerror():
    """``_write`` converts a drain stall into ConnectionError (L176-177)."""

    class _StallingWriter:
        def write(self, data: bytes) -> None:
            pass

        async def drain(self) -> None:
            await asyncio.sleep(10)

    cfg = _cfg(0, connect_timeout=0.01)  # drain timeout = connect_timeout * 2
    with pytest.raises(ConnectionError, match="write drain timed out"):
        await _write(cast(asyncio.StreamWriter, _StallingWriter()), b"x", Stats(), cfg)


async def test_read_available_returns_buffered_bytes():
    class _ReadyReader:
        async def read(self, _n: int) -> bytes:
            return b"payload"

    assert await _read_available(cast(asyncio.StreamReader, _ReadyReader())) == b"payload"


async def test_read_available_swallows_oserror():
    class _ResetReader:
        async def read(self, _n: int) -> bytes:
            raise ConnectionResetError("reset by peer")

    assert await _read_available(cast(asyncio.StreamReader, _ResetReader())) == b""


async def test_read_available_cancels_a_pending_read():
    class _IdleReader:
        async def read(self, _n: int) -> bytes:
            await asyncio.Event().wait()  # never completes
            return b""

    assert await _read_available(cast(asyncio.StreamReader, _IdleReader())) == b""


async def test_drain_responses_records_latency():
    class _ReadyReader:
        async def read(self, _n: int) -> bytes:
            return b"HTTP/1.1 503 Service Unavailable\r\n\r\n"

    stats = Stats()
    await profiles._drain_responses(cast(asyncio.StreamReader, _ReadyReader()), stats, sent_at=0.0)
    assert stats.responses == 1
    assert stats.status_5xx == 1
    assert stats.resp_latency_count == 1


def test_random_header_name_is_used() -> None:
    # L93-96 helper is referenced by parity tests; assert it round-trips the name.
    assert _random_header_name("X-Trace-Id").lower() == "x-trace-id"


def test_base_headers_skips_protected_custom_names() -> None:
    """Custom ``Host``/``Connection`` are structural and must not override (L150)."""
    cfg = Config(
        host="example.com",
        port=80,
        header_host="example.com",
        custom_headers={"Host": "evil.example", "Connection": "close", "X-Keep": "1"},
    )
    headers = _base_headers(cfg, "Agent/1.0")
    assert "Host: evil.example" not in headers
    assert "Connection: close" not in headers
    assert any(h == "Host: example.com" for h in headers)
    assert "X-Keep: 1" in headers


@pytest.mark.parametrize("mode", ["slow-post", "chunked"])
async def test_custom_body_branch_is_taken(slow_server, mode):
    """The ``config.custom_body`` branch (L284-286 / L385-387) replaces the RNG body."""
    cfg = _cfg(slow_server.port, custom_body=b"fixed-body-payload")
    stats, result = await _run_to_completion(PROFILES[mode], cfg, pre_set=True, run_for=0.0)
    assert result is False  # pre-set stop -> returns before dribbling the body
    assert stats.bytes_sent > 0  # request headers (with the framing) were written
    received = slow_server.get_received_data().decode("latin-1")
    if mode == "slow-post":
        # slow-post announces the fixed body length via Content-Length.
        assert "Content-Length: 18" in received
    else:
        # chunked frames the body with Transfer-Encoding instead.
        assert "Transfer-Encoding: chunked" in received


async def test_expect_continue_records_interim_response(slow_server):
    """A responding target yields a non-empty interim -> L713-715 + return False."""
    slow_server.respond_body = b"HTTP/1.1 100 continue\r\n\r\n"
    cfg = _cfg(slow_server.port, mode="expect-continue-abuse")
    stats, _result = await _run_to_completion(
        PROFILES["expect-continue-abuse"], cfg, pre_set=False, run_for=0.15
    )
    assert stats.bytes_received > 0


async def test_announce_then_dribble_returns_false_when_stopped():
    """Directly drive the shared protocol-starvation helper's stopped short-circuit."""
    stop = asyncio.Event()

    class _CountingWriter:
        def __init__(self) -> None:
            self.writes = 0

        def write(self, _data: bytes) -> None:
            self.writes += 1
            if self.writes > 1:  # after the announce, stop the dribble loop
                stop.set()

        async def drain(self) -> None:
            pass

    cfg = _cfg(0)
    completed = await _announce_then_dribble(
        cast(asyncio.StreamWriter, _CountingWriter()), Stats(), cfg, stop, b"ANNOUNCE\r\n", count=10
    )
    assert completed is False  # stop fired mid-announce


async def test_multipart_returns_false_before_body():
    """Cover multipart's ``return False`` blank-line guard (L651-652) deterministically.

    The header-line loop completes (stop clear), then ``stop`` is set exactly
    after the terminating blank line is written, so the second guard fires.
    """
    stop = asyncio.Event()

    class _BlankLineWriter:
        def write(self, data: bytes) -> None:
            if data == b"\r\n":  # the blank line that ends the header block
                stop.set()

        async def drain(self) -> None:
            pass

    cfg = _cfg(0)
    reader = cast(asyncio.StreamReader, MagicMock())
    result = await PROFILES["multipart-slow-upload"]().run(
        reader, cast(asyncio.StreamWriter, _BlankLineWriter()), cfg, "UA", Stats(), stop
    )
    assert result is False


async def test_tls_renego_returns_false_mid_dribble():
    """Cover tls-renego-hold's inner 8-dribble ``return False`` guard (L1136-1137).

    The outer ``while`` and the ClientHello write happen with ``stop`` clear; the
    guard trips on the second dribble write, so the profile returns from inside
    the ``for _ in range(8)`` loop rather than completing a renegotiation round.
    """
    stop = asyncio.Event()

    class _StopAfterAnnounce:
        def __init__(self) -> None:
            self.writes = 0

        def write(self, _data: bytes) -> None:
            self.writes += 1
            if self.writes >= 2:  # announce (#1) sent; first dribble arms the stop
                stop.set()

        async def drain(self) -> None:
            pass

    cfg = _cfg(0)
    reader = cast(asyncio.StreamReader, MagicMock())
    result = await PROFILES["tls-renego-hold"]().run(
        reader, cast(asyncio.StreamWriter, _StopAfterAnnounce()), cfg, "UA", Stats(), stop
    )
    assert result is False
