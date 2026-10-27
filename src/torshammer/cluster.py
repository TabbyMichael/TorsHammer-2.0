"""Distributed Node Coordination Module (Master-Worker Architecture).

Provides a lightweight JSON-RPC worker server and a master controller that
coordinate distributed slow-rate load testing across multiple machines/IPs.
Zero external dependencies, backed by asyncio.

A :class:`WorkerNode` genuinely launches an :class:`~torshammer.engine.AttackEngine`
per ``start`` command (tracked by ``task_id`` so it can be stopped), and
re-applies the default-deny target policy locally — a rogue or misconfigured
master cannot coerce a worker into hammering an unauthorized public host.
:class:`MasterController` serializes a resolved :class:`~torshammer.config.Config`
to each registered worker, holds for the configured duration, then stops them.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
from contextlib import suppress
from dataclasses import fields
from typing import Any

from .config import Config
from .engine import AttackEngine
from .target import _check_target_policy

logger = logging.getLogger("torshammer.cluster")

# Fields that are not JSON-safe or must not cross the wire to a worker
# (proxies carry credentials, custom_body is bytes, the SSL context is cached
# per-process and rebuilt locally).
_NON_DISTRIBUTABLE = {"proxies", "custom_body", "_cached_ssl_context"}

_CONFIG_FIELD_NAMES: frozenset[str] = frozenset(f.name for f in fields(Config) if f.init)


def _config_to_payload(config: Config) -> dict[str, Any]:
    """Reduce a :class:`Config` to a JSON-safe dict for distribution."""
    payload: dict[str, Any] = {}
    for field in fields(Config):
        if not field.init or field.name in _NON_DISTRIBUTABLE:
            continue
        value = getattr(config, field.name)
        if field.name == "allowed_targets":
            payload[field.name] = sorted(value)
            continue
        try:
            json.dumps(value)
        except (TypeError, ValueError):
            continue
        payload[field.name] = value
    return payload


def _config_from_payload(payload: dict[str, Any]) -> Config:
    """Rebuild a :class:`Config` from a distributed payload, ignoring unknown keys."""
    data = {key: value for key, value in payload.items() if key in _CONFIG_FIELD_NAMES}
    if isinstance(data.get("allowed_targets"), list):
        data["allowed_targets"] = set(data["allowed_targets"])
    return Config(**data)


def parse_host_port(addr: str) -> tuple[str, int]:
    """Split a ``host:port`` endpoint string (IPv6 should be bracketed)."""
    host, _, port_str = addr.rpartition(":")
    if not host or not port_str:
        raise ValueError(f"invalid worker endpoint {addr!r}; expected host:port")
    return host, int(port_str)


def load_workers_file(path: str) -> list[str]:
    """Read one ``host:port`` endpoint per line, skipping blanks and comments."""
    with open(path, encoding="utf-8") as handle:
        return [line.strip() for line in handle if line.strip() and not line.startswith("#")]


class WorkerNode:
    """Async worker node that listens for JSON-RPC commands from a master."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9999, secret: str = "") -> None:
        self.host = host
        self.port = port
        self.secret = secret
        self.server: asyncio.AbstractServer | None = None
        self.active_tasks: dict[str, asyncio.Task[None]] = {}
        self._stops: dict[str, asyncio.Event] = {}
        self.running = False

    async def _launch(self, task_id: str, config: Config) -> None:
        """Run an engine to completion (or until stopped/cancelled)."""
        stop = asyncio.Event()
        self._stops[task_id] = stop
        engine = AttackEngine(config, stop)
        try:
            await engine.run()
            logger.info(
                "worker task %s finished (connections=%s)", task_id, engine.stats.connections
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover  # noqa: BLE001
            logger.error("worker task %s failed: %s", task_id, exc)
        finally:
            self._stops.pop(task_id, None)
            self.active_tasks.pop(task_id, None)

    async def _handle_start(self, req: dict[str, Any]) -> dict[str, Any]:
        task_id = str(req.get("task_id", "default"))
        if task_id in self.active_tasks:
            return {"status": "error", "message": f"task {task_id} already running"}
        payload = req.get("config")
        if not isinstance(payload, dict):
            return {"status": "error", "message": "start requires a config payload"}
        try:
            config = _config_from_payload(payload)
        except (TypeError, ValueError) as exc:
            return {"status": "error", "message": f"invalid config: {exc}"}
        # Defense-in-depth: re-apply the operator's authorization locally so a
        # rogue master cannot coerce this node into an unauthorized public target.
        try:
            _check_target_policy(
                config.host,
                allow_public_targets=config.allow_public_targets,
                allowlist=config.allowed_targets,
            )
        except SystemExit as exc:
            return {"status": "error", "message": f"target refused: {exc}"}
        self.active_tasks[task_id] = asyncio.create_task(self._launch(task_id, config))
        return {
            "status": "ok",
            "message": f"task {task_id} started",
            "concurrency": config.concurrency,
            "mode": config.mode,
        }

    async def _handle_stop(self, req: dict[str, Any]) -> dict[str, Any]:
        task_id = str(req.get("task_id", "default"))
        if task_id not in self.active_tasks:
            return {"status": "error", "message": f"no such task {task_id}"}
        stop = self._stops.get(task_id)
        if stop is not None:
            stop.set()
        self.active_tasks[task_id].cancel()
        return {"status": "ok", "message": f"task {task_id} stopped"}

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            try:
                data = await reader.readline()
                if not data:
                    return
                req = json.loads(data.decode("utf-8"))
            except json.JSONDecodeError:
                await self._reply(writer, {"status": "error", "message": "invalid json"})
                return
            except (OSError, ConnectionError) as exc:
                logger.error("Worker RPC read error: %s", exc)
                return

            if self.secret and req.get("secret", "") != self.secret:
                await self._reply(writer, {"status": "error", "message": "unauthorized"})
                return

            action = req.get("action")
            if action == "ping":
                res: dict[str, Any] = {
                    "status": "ok",
                    "role": "worker",
                    "tasks": len(self.active_tasks),
                }
            elif action == "start":
                res = await self._handle_start(req)
            elif action == "stop":
                res = await self._handle_stop(req)
            elif action == "status":
                res = {"status": "ok", "role": "worker", "tasks": sorted(self.active_tasks)}
            else:
                res = {"status": "error", "message": "unknown action"}
            await self._reply(writer, res)
        finally:
            # Always close the connection or `server.wait_closed()` in stop()
            # blocks forever on the lingering handler.
            writer.close()

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, payload: dict[str, Any]) -> None:
        with suppress(OSError, ConnectionError):
            writer.write(json.dumps(payload).encode("utf-8") + b"\n")
            await writer.drain()

    async def start(self) -> None:
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        self.running = True

    async def stop(self) -> None:
        """Cancel every running attack, then close the RPC listener."""
        for stop in list(self._stops.values()):
            stop.set()
        tasks = list(self.active_tasks.values())
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.active_tasks.clear()
        self._stops.clear()
        if self.server is not None:
            self.server.close()
            with suppress(OSError, ConnectionError):
                await self.server.wait_closed()
        self.running = False


class MasterController:
    """Master controller orchestrating load across registered worker nodes."""

    def __init__(self, workers: list[str], secret: str = "") -> None:
        self.workers = workers  # ["host:port", ...]
        self.secret = secret

    async def _send_command(self, worker_addr: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            host, port = parse_host_port(worker_addr)
        except ValueError as exc:
            return {"status": "error", "message": str(exc)}
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except (OSError, ConnectionError) as exc:
            return {"status": "error", "message": str(exc)}
        try:
            message = dict(payload)
            message["secret"] = self.secret
            writer.write(json.dumps(message).encode("utf-8") + b"\n")
            await writer.drain()
            data = await reader.readline()
            if data:
                return dict(json.loads(data.decode("utf-8")))
        except (OSError, ConnectionError, json.JSONDecodeError) as exc:
            return {"status": "error", "message": str(exc)}
        finally:
            writer.close()
            with suppress(OSError, ConnectionError):
                await writer.wait_closed()
        return {"status": "error", "message": "no response"}

    async def ping_all(self) -> dict[str, bool]:
        results: dict[str, bool] = {}
        for worker in self.workers:
            res = await self._send_command(worker, {"action": "ping"})
            results[worker] = res.get("status") == "ok"
        return results

    async def broadcast_start(self, task_id: str, config: Config) -> dict[str, Any]:
        payload = _config_to_payload(config)
        results: dict[str, Any] = {}
        for worker in self.workers:
            results[worker] = await self._send_command(
                worker, {"action": "start", "task_id": task_id, "config": payload}
            )
        return results

    async def broadcast_stop(self, task_id: str) -> dict[str, Any]:
        results: dict[str, Any] = {}
        for worker in self.workers:
            results[worker] = await self._send_command(
                worker, {"action": "stop", "task_id": task_id}
            )
        return results


def _install_stop_handler(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (
            NotImplementedError,
            RuntimeError,
        ):  # pragma: no cover - Windows has no POSIX signal handlers
            pass  # e.g. Windows: Ctrl-C raises KeyboardInterrupt instead


async def run_worker(bind: str, secret: str) -> int:
    """Serve a :class:`WorkerNode` until SIGINT/SIGTERM. Returns the exit code."""
    host, port = parse_host_port(bind)
    if host not in {"127.0.0.1", "::1", "localhost"} and not secret:
        print(
            "[warn] worker RPC is bound to a non-loopback address without a shared secret; "
            "any host that can reach it may issue commands. Set --cluster-secret.",
            file=sys.stderr,
        )
    node = WorkerNode(host=host, port=port, secret=secret)
    await node.start()
    print(f"[cluster] worker listening on {host}:{port} (pid {os.getpid()})", file=sys.stderr)
    stop = asyncio.Event()
    _install_stop_handler(stop)
    try:
        await stop.wait()
    finally:
        await node.stop()
    return 0


async def run_master(config: Config, workers: list[str], secret: str, task_id: str = "task") -> int:
    """Broadcast the resolved attack to workers, hold for the duration, then stop."""
    controller = MasterController(workers=workers, secret=secret)
    pings = await controller.ping_all()
    reachable = [worker for worker, ok in pings.items() if ok]
    if not reachable:
        print("[cluster] no reachable workers; aborting.", file=sys.stderr)
        return 1
    print(
        f"[cluster] {len(reachable)}/{len(workers)} workers reachable; broadcasting start",
        file=sys.stderr,
    )
    start_results = await controller.broadcast_start(task_id, config)
    for worker, res in start_results.items():
        if isinstance(res, dict) and res.get("status") != "ok":
            print(f"[cluster] {worker}: {res.get('message')}", file=sys.stderr)

    if config.duration > 0:
        await asyncio.sleep(config.duration)
    else:
        stop = asyncio.Event()
        _install_stop_handler(stop)
        await stop.wait()

    await controller.broadcast_stop(task_id)
    print("[cluster] broadcast stop complete", file=sys.stderr)
    return 0
