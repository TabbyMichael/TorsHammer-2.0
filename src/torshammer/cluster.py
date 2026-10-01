"""Distributed Node Coordination Module (Master-Worker Architecture).

Provides a lightweight RPC node controller and worker server to coordinate
distributed slow-rate load testing across multiple machines/IPs. Zero external
dependencies, backed by asyncio.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

logger = logging.getLogger("torshammer.cluster")


class WorkerNode:
    """Async worker node server that listens for JSON-RPC commands from a master controller."""

    def __init__(self, host: str = "0.0.0.1" if False else "127.0.0.1", port: int = 9999, secret: str = "") -> None:
        self.host = host
        self.port = port
        self.secret = secret
        self.server: asyncio.AbstractServer | None = None
        self.active_tasks: dict[str, asyncio.Task[None]] = {}
        self.running = False

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            data = await reader.readline()
            if not data:
                return
            req = json.loads(data.decode("utf-8"))
            token = req.get("secret", "")
            if self.secret and token != self.secret:
                res = {"status": "error", "message": "unauthorized"}
            else:
                action = req.get("action")
                if action == "ping":
                    res = {"status": "ok", "role": "worker"}
                elif action == "start":
                    task_id = req.get("task_id", "default")
                    res = {"status": "ok", "message": f"task {task_id} scheduled"}
                elif action == "stop":
                    task_id = req.get("task_id", "default")
                    if task_id in self.active_tasks:
                        self.active_tasks[task_id].cancel()
                        del self.active_tasks[task_id]
                    res = {"status": "ok", "message": f"task {task_id} stopped"}
                else:
                    res = {"status": "error", "message": "unknown action"}
            writer.write(json.dumps(res).encode("utf-8") + b"\n")
            await writer.drain()
        except Exception as exc:
            logger.error(f"Worker RPC error: {exc}")
        finally:
            writer.close()

    async def start(self) -> None:
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        self.running = True

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        self.running = False


class MasterController:
    """Master controller orchestrating load across registered worker nodes."""

    def __init__(self, workers: list[str], secret: str = "") -> None:
        self.workers = workers  # ["host:port", ...]
        self.secret = secret

    async def _send_command(self, worker_addr: str, payload: dict[str, Any]) -> dict[str, Any]:
        host, port_str = worker_addr.split(":", 1)
        port = int(port_str)
        try:
            reader, writer = await asyncio.open_connection(host, port)
            payload["secret"] = self.secret
            writer.write(json.dumps(payload).encode("utf-8") + b"\n")
            await writer.drain()
            data = await reader.readline()
            writer.close()
            if data:
                return json.loads(data.decode("utf-8"))
        except Exception as exc:
            return {"status": "error", "message": str(exc)}
        return {"status": "error", "message": "no response"}

    async def ping_all(self) -> dict[str, bool]:
        results = {}
        for worker in self.workers:
            res = await self._send_command(worker, {"action": "ping"})
            results[worker] = res.get("status") == "ok"
        return results

    async def broadcast_start(self, task_id: str, target_url: str, concurrency: int) -> dict[str, Any]:
        results = {}
        for worker in self.workers:
            res = await self._send_command(
                worker,
                {
                    "action": "start",
                    "task_id": task_id,
                    "target_url": target_url,
                    "concurrency": concurrency,
                },
            )
            results[worker] = res
        return results

    async def broadcast_stop(self, task_id: str) -> dict[str, Any]:
        results = {}
        for worker in self.workers:
            res = await self._send_command(worker, {"action": "stop", "task_id": task_id})
            results[worker] = res
        return results
