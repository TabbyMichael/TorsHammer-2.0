"""Unit tests for the distributed master/worker cluster module."""

from __future__ import annotations

import asyncio

import pytest

from tests.conftest import SlowServer
from torshammer.cluster import (
    MasterController,
    WorkerNode,
    _config_from_payload,
    _config_to_payload,
    parse_host_port,
    run_master,
)
from torshammer.config import Config


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


@pytest.mark.asyncio
async def test_worker_node_ping_and_auth():
    worker = WorkerNode(host="127.0.0.1", port=0, secret="supersecret")
    await worker.start()
    assert worker.server is not None
    port = worker.server.sockets[0].getsockname()[1]

    master = MasterController(workers=[f"127.0.0.1:{port}"], secret="supersecret")
    assert (await master.ping_all())[f"127.0.0.1:{port}"] is True

    unauth = MasterController(workers=[f"127.0.0.1:{port}"], secret="wrongsecret")
    assert (await unauth.ping_all())[f"127.0.0.1:{port}"] is False

    await worker.stop()


@pytest.mark.asyncio
async def test_broadcast_start_actually_launches_attack_and_stop_removes_it(
    slow_server: SlowServer,
):
    """A start command must spawn a real engine (hitting the target) and stop
    must tear it down — not merely return a 'scheduled' stub."""
    worker = WorkerNode(host="127.0.0.1", port=0)
    await worker.start()
    port = worker.server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    addr = f"127.0.0.1:{port}"
    master = MasterController(workers=[addr])

    start = await master.broadcast_start("task-1", _local_config(slow_server))
    assert start[addr]["status"] == "ok"
    assert "task-1" in worker.active_tasks

    # Let the launched engine connect to prove an attack is genuinely running.
    await asyncio.sleep(0.2)
    assert slow_server.connections > 0

    stop = await master.broadcast_stop("task-1")
    assert stop[addr]["status"] == "ok"
    await asyncio.sleep(0.05)
    assert "task-1" not in worker.active_tasks

    await worker.stop()


@pytest.mark.asyncio
async def test_worker_refuses_unauthorized_public_target(slow_server: SlowServer):
    """Defense-in-depth: a worker must refuse a public target even if a (rogue)
    master asks for it, applying the same default-deny policy locally."""
    worker = WorkerNode(host="127.0.0.1", port=0)
    await worker.start()
    port = worker.server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    addr = f"127.0.0.1:{port}"
    master = MasterController(workers=[addr])

    public = Config(host="example.com", port=80, mode="slow-post", concurrency=2)
    start = await master.broadcast_start("bad-task", public)
    assert start[addr]["status"] == "error"
    assert "refused" in start[addr]["message"]
    assert "bad-task" not in worker.active_tasks

    await worker.stop()


@pytest.mark.asyncio
async def test_duplicate_task_id_is_rejected(slow_server: SlowServer):
    worker = WorkerNode(host="127.0.0.1", port=0)
    await worker.start()
    port = worker.server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    addr = f"127.0.0.1:{port}"
    master = MasterController(workers=[addr])

    cfg = _local_config(slow_server)
    assert (await master.broadcast_start("dup", cfg))[addr]["status"] == "ok"
    second = await master.broadcast_start("dup", cfg)
    assert second[addr]["status"] == "error"
    assert "already running" in second[addr]["message"]

    await worker.stop()


@pytest.mark.asyncio
async def test_master_controller_unreachable_worker():
    master = MasterController(workers=["127.0.0.1:59999"], secret="pass")
    assert (await master.ping_all())["127.0.0.1:59999"] is False


def test_parse_host_port_variants():
    assert parse_host_port("127.0.0.1:9000") == ("127.0.0.1", 9000)
    assert parse_host_port("[::1]:8080") == ("[::1]", 8080)
    with pytest.raises(ValueError):
        parse_host_port("nocolon")


def test_config_payload_roundtrip_drops_nondistributable_fields():
    cfg = Config(
        host="127.0.0.1",
        port=8080,
        mode="chunked",
        concurrency=10,
        allowed_targets={"b.com", "a.com"},
    )
    payload = _config_to_payload(cfg)
    # allowed_targets becomes a JSON-safe sorted list; wire-only fields dropped.
    assert payload["allowed_targets"] == ["a.com", "b.com"]
    assert "proxies" not in payload
    assert "custom_body" not in payload
    rebuilt = _config_from_payload(payload)
    assert rebuilt.host == "127.0.0.1"
    assert rebuilt.concurrency == 10
    assert rebuilt.allowed_targets == {"a.com", "b.com"}


@pytest.mark.asyncio
async def test_run_master_orchestrates_start_hold_stop(slow_server: SlowServer):
    """run_master pings, broadcasts start, holds for the duration, then stops."""
    worker = WorkerNode(host="127.0.0.1", port=0)
    await worker.start()
    port = worker.server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    addr = f"127.0.0.1:{port}"

    cfg = _local_config(slow_server, duration=0.2)
    rc = await run_master(cfg, [addr], secret="")
    assert rc == 0
    assert slow_server.connections > 0

    await worker.stop()


@pytest.mark.asyncio
async def test_run_master_aborts_when_no_workers_reachable():
    cfg = Config(host="127.0.0.1", port=9, mode="slow-post", concurrency=1, duration=0.1)
    assert await run_master(cfg, ["127.0.0.1:59998"], secret="") == 1
