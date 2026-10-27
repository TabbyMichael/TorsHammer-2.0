"""Task 7 (cluster half) - RPC handler arms and a real ``run_worker``/``run_master``.

The existing ``test_cluster.py`` covers the happy paths but never executes
``run_worker`` (it is patched out by the CLI test) nor several error arms in
``handle_client`` / ``_handle_start`` / ``_send_command``. This file drives those
for real, using purpose-built fake streams and an actual worker RPC server on a
loopback/ephemeral port.
"""

from __future__ import annotations

import asyncio
import json
import signal
import socket

import pytest

from tests.conftest import SlowServer
from torshammer import cluster
from torshammer.cluster import (
    MasterController,
    WorkerNode,
    _config_to_payload,
    run_master,
    run_worker,
)
from torshammer.config import Config


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _local_config(slow_server: SlowServer, **overrides: object) -> Config:
    defaults: dict[str, object] = {
        "host": "127.0.0.1",
        "port": slow_server.port,
        "mode": "slow-post",
        "concurrency": 2,
        "duration": 0.0,
        "base_post_length": 64,
        "delay_min": 0.0,
        "delay_max": 0.01,
        "connect_timeout": 3,
        "quiet": True,
    }
    defaults.update(overrides)
    return Config(**defaults)  # type: ignore[arg-type]


class _ClientReader:
    def __init__(self, lines: list[bytes] | None = None, exc: BaseException | None = None) -> None:
        self._lines = list(lines or [])
        self._exc = exc

    async def readline(self) -> bytes:
        if self._exc is not None:
            raise self._exc
        return self._lines.pop(0) if self._lines else b""


class _ClientWriter:
    def __init__(self) -> None:
        self.data = bytearray()
        self.closed = False

    def write(self, blob: bytes) -> None:
        self.data += blob

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass


# ---------------------------------------------------------------------------
# _config_to_payload: skip non-JSON-safe values (L53-54)
# ---------------------------------------------------------------------------


def test_payload_skips_non_json_safe_field() -> None:
    cfg = Config(host="127.0.0.1", port=8080, mode="slow-post", concurrency=1)
    non_json_field = "method"
    setattr(cfg, non_json_field, object())  # not JSON-serializable
    payload = _config_to_payload(cfg)
    assert "method" not in payload
    assert payload["host"] == "127.0.0.1"


# ---------------------------------------------------------------------------
# _handle_start error arms (L117, L120-121)
# ---------------------------------------------------------------------------


async def test_handle_start_requires_dict_config() -> None:
    node = WorkerNode()
    res = await node._handle_start({"task_id": "t", "config": "not-a-dict"})
    assert res["status"] == "error"
    assert "config payload" in res["message"]


async def test_handle_start_rejects_invalid_config() -> None:
    node = WorkerNode()
    res = await node._handle_start(
        {"task_id": "t", "config": {"host": "127.0.0.1", "port": 80, "stats_interval": 0}}
    )
    assert res["status"] == "error"
    assert "invalid config" in res["message"]


# ---------------------------------------------------------------------------
# handle_client arms (L157, L159-164, L181-184)
# ---------------------------------------------------------------------------


async def test_handle_client_empty_line_returns() -> None:
    node = WorkerNode()
    writer = _ClientWriter()
    await node.handle_client(_ClientReader([b""]), writer)  # type: ignore[arg-type]
    assert writer.data == b""
    assert writer.closed


async def test_handle_client_invalid_json() -> None:
    node = WorkerNode()
    writer = _ClientWriter()
    await node.handle_client(_ClientReader([b"{not json\n"]), writer)  # type: ignore[arg-type]
    assert b"invalid json" in writer.data


async def test_handle_client_read_error_is_swallowed() -> None:
    node = WorkerNode()
    writer = _ClientWriter()
    reader = _ClientReader(exc=ConnectionError("peer reset"))
    await node.handle_client(reader, writer)  # type: ignore[arg-type]
    assert writer.closed  # no reply, but connection closed in finally


async def test_handle_client_status_action() -> None:
    node = WorkerNode()
    writer = _ClientWriter()
    req = json.dumps({"action": "status"}).encode() + b"\n"
    await node.handle_client(_ClientReader([req]), writer)  # type: ignore[arg-type]
    reply = json.loads(writer.data.decode())
    assert reply["role"] == "worker"


async def test_handle_client_unknown_action() -> None:
    node = WorkerNode()
    writer = _ClientWriter()
    req = json.dumps({"action": "bogus"}).encode() + b"\n"
    await node.handle_client(_ClientReader([req]), writer)  # type: ignore[arg-type]
    assert b"unknown action" in writer.data


# ---------------------------------------------------------------------------
# _send_command arms (L229-230, L243-244, L249)
# ---------------------------------------------------------------------------


async def test_send_command_rejects_bad_endpoint() -> None:
    controller = MasterController(workers=[])
    res = await controller._send_command("badhost", {"action": "ping"})
    assert res["status"] == "error"
    assert "invalid worker endpoint" in res["message"]


async def test_send_command_reports_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _ClientReader(exc=ConnectionError("broken pipe"))
    writer = _ClientWriter()

    async def _fake_open(_host: str, _port: int) -> tuple[object, object]:
        return reader, writer

    monkeypatch.setattr(cluster.asyncio, "open_connection", _fake_open)
    controller = MasterController(workers=[])
    res = await controller._send_command("127.0.0.1:1", {"action": "ping"})
    assert res["status"] == "error"
    assert "broken pipe" in res["message"]


async def test_send_command_reports_no_response(monkeypatch: pytest.MonkeyPatch) -> None:
    reader = _ClientReader([b""])  # server closes without a reply line
    writer = _ClientWriter()

    async def _fake_open(_host: str, _port: int) -> tuple[object, object]:
        return reader, writer

    monkeypatch.setattr(cluster.asyncio, "open_connection", _fake_open)
    controller = MasterController(workers=[])
    res = await controller._send_command("127.0.0.1:1", {"action": "ping"})
    assert res == {"status": "error", "message": "no response"}


# ---------------------------------------------------------------------------
# _install_stop_handler happy registration (L277-280)
# ---------------------------------------------------------------------------


async def test_install_stop_handler_registers_signals() -> None:
    stop = asyncio.Event()
    cluster._install_stop_handler(stop)
    loop = asyncio.get_running_loop()
    # Registered cleanly on POSIX; tear down so no handler leaks past the test.
    assert loop.remove_signal_handler(signal.SIGINT)
    assert loop.remove_signal_handler(signal.SIGTERM)


# ---------------------------------------------------------------------------
# run_worker: real serve + non-loopback warning + graceful stop (L287-303)
# ---------------------------------------------------------------------------


async def test_run_worker_serves_and_stops(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    port = _free_port()
    captured: dict[str, asyncio.Event] = {}

    def _capture(stop: asyncio.Event) -> None:
        captured["stop"] = stop

    monkeypatch.setattr(cluster, "_install_stop_handler", _capture)

    task = asyncio.create_task(run_worker(f"0.0.0.0:{port}", ""))

    reader = writer = None
    for _ in range(200):
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            break
        except OSError:
            await asyncio.sleep(0.01)
    assert reader is not None and writer is not None, "worker never started listening"

    writer.write(json.dumps({"action": "ping"}).encode() + b"\n")
    await writer.drain()
    reply = json.loads((await reader.readline()).decode())
    assert reply["status"] == "ok"
    writer.close()

    captured["stop"].set()
    assert await task == 0
    assert "non-loopback address" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# run_master: duration==0 branch (L326-328) and failed-start report (L321)
# ---------------------------------------------------------------------------


async def test_run_master_zero_duration_waits_then_stops(
    monkeypatch: pytest.MonkeyPatch, slow_server: SlowServer
) -> None:
    worker = WorkerNode(host="127.0.0.1", port=0)
    await worker.start()
    assert worker.server is not None
    addr = f"127.0.0.1:{worker.server.sockets[0].getsockname()[1]}"  # type: ignore[union-attr]
    # Unblocks the duration==0 stop.wait() deterministically.
    monkeypatch.setattr(cluster, "_install_stop_handler", lambda stop: stop.set())

    cfg = _local_config(slow_server, duration=0)
    assert await run_master(cfg, [addr], secret="") == 0
    await worker.stop()


async def test_run_master_reports_failed_start(slow_server: SlowServer) -> None:
    worker = WorkerNode(host="127.0.0.1", port=0)
    await worker.start()
    assert worker.server is not None
    addr = f"127.0.0.1:{worker.server.sockets[0].getsockname()[1]}"  # type: ignore[union-attr]

    # A public target is refused locally by the worker -> master prints the error.
    cfg = Config(host="example.com", port=80, mode="slow-post", concurrency=1, duration=0.05)
    assert await run_master(cfg, [addr], secret="") == 0
    await worker.stop()
