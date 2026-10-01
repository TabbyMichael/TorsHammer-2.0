"""Unit tests for distributed node cluster controller and worker RPC nodes."""

from __future__ import annotations

import pytest

from torshammer.cluster import MasterController, WorkerNode


@pytest.mark.asyncio
async def test_worker_node_ping_and_auth():
    worker = WorkerNode(host="127.0.0.1", port=0, secret="supersecret")
    await worker.start()
    assert worker.server is not None
    port = worker.server.sockets[0].getsockname()[1]

    # Authorized master
    master = MasterController(workers=[f"127.0.0.1:{port}"], secret="supersecret")
    pings = await master.ping_all()
    assert pings[f"127.0.0.1:{port}"] is True

    # Unauthorized master
    unauth_master = MasterController(workers=[f"127.0.0.1:{port}"], secret="wrongsecret")
    unauth_pings = await unauth_master.ping_all()
    assert unauth_pings[f"127.0.0.1:{port}"] is False

    await worker.stop()


@pytest.mark.asyncio
async def test_master_broadcast_start_stop():
    worker = WorkerNode(host="127.0.0.1", port=0, secret="clusterpass")
    await worker.start()
    assert worker.server is not None
    port = worker.server.sockets[0].getsockname()[1]

    master = MasterController(workers=[f"127.0.0.1:{port}"], secret="clusterpass")
    
    start_res = await master.broadcast_start("task-101", "http://127.0.0.1:8080", concurrency=100)
    assert start_res[f"127.0.0.1:{port}"]["status"] == "ok"

    stop_res = await master.broadcast_stop("task-101")
    assert stop_res[f"127.0.0.1:{port}"]["status"] == "ok"

    await worker.stop()


@pytest.mark.asyncio
async def test_master_controller_unreachable_worker():
    master = MasterController(workers=["127.0.0.1:59999"], secret="pass")
    res = await master.ping_all()
    assert res["127.0.0.1:59999"] is False
