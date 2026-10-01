#!/usr/bin/env python3
"""Opt-in soak / sustained-load check for TorsHammer 2.0.

Runs the real CLI against a local asyncio sink at high concurrency for a
sustained period and asserts:

1. the process exits 0 within the expected window (no hung sockets blocking
   shutdown),
2. at least one connection was actually opened,
3. ``peak_active <= concurrency`` (the engine never over-subscribes sockets),
4. the reported ``active`` count tracks ``connections`` (no runaway growth:
   ``active`` must not exceed the concurrency cap).

Note: the final JSON line is emitted before worker teardown, so ``active``
there is intentionally non-zero; clean shutdown is proven by the process
exiting on its own plus (1)-(4).

Skips cleanly (exit 0 with a notice) when the requested concurrency exceeds the
runner's descriptor budget, so it can be wired into a nightly job without
flaking on small runners.

Usage:
    python scripts/soak.py --concurrency 2000 --duration 120
    SOAK_CONCURRENCY=200 SOAK_DURATION=10 python scripts/soak.py

Env overrides: SOAK_CONCURRENCY, SOAK_DURATION, SOAK_MODE.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import resource
import subprocess
import sys
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


class Sink:
    """Minimal asyncio TCP sink that accepts and holds connections."""

    def __init__(self) -> None:
        self.server: asyncio.AbstractServer | None = None
        self.port: int = 0
        self.connections: int = 0

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
            except OSError:
                pass

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()


def _soft_fd_limit() -> int:
    soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    return int(soft) if soft != resource.RLIM_INFINITY else 1 << 20


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TorsHammer soak / shutdown-leak check")
    parser.add_argument(
        "--concurrency",
        type=int,
        default=int(os.environ.get("SOAK_CONCURRENCY", "500")),
        help="Concurrent connections (env SOAK_CONCURRENCY)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=float(os.environ.get("SOAK_DURATION", "30")),
        help="Attack duration in seconds (env SOAK_DURATION)",
    )
    parser.add_argument(
        "--mode", default=os.environ.get("SOAK_MODE", "slow-headers"), help="Attack mode"
    )
    parser.add_argument("--stats-interval", type=float, default=1.0)
    args = parser.parse_args(argv)

    if args.concurrency > int(_soft_fd_limit() * 0.8):
        print(
            f"SKIP: concurrency {args.concurrency} exceeds 80% of RLIMIT_NOFILE "
            f"({_soft_fd_limit()}); raise 'ulimit -n' on the runner first"
        )
        return 0

    holder: dict[str, object] = {}

    async def scenario() -> None:
        sink = Sink()
        await sink.start()
        url = f"http://127.0.0.1:{sink.port}"
        cmd = [
            sys.executable,
            "-m",
            "torshammer",
            "-u",
            url,
            "-c",
            str(args.concurrency),
            "-d",
            str(args.duration),
            "-m",
            args.mode,
            "--stats-interval",
            str(args.stats_interval),
            "--json",
        ]

        proc_holder: dict[str, subprocess.CompletedProcess[str]] = {}

        def run() -> None:
            proc_holder["proc"] = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                cwd=REPO_ROOT,
                timeout=args.duration + 120,
            )

        thread = threading.Thread(target=run)
        thread.start()
        while thread.is_alive():
            await asyncio.sleep(0.5)

        holder["proc"] = proc_holder.get("proc")
        holder["sink_conns"] = sink.connections
        await sink.stop()

    asyncio.run(scenario())

    proc = holder.get("proc")
    if proc is None:
        print("FAIL: soak run did not complete")
        return 1

    lines = [line for line in proc.stdout.splitlines() if line.strip().startswith("{")]
    if not lines:
        print("FAIL: no JSON stats produced")
        print(proc.stdout[-2000:])
        print(proc.stderr[-2000:])
        return 1

    final = json.loads(lines[-1])
    print(
        f"connections={final['connections']} peak_active={final['peak_active']} "
        f"errors={final['errors']} active_at_end={final['active']} "
        f"sink_conns={holder.get('sink_conns')}"
    )

    failures: list[str] = []
    if proc.returncode != 0:
        failures.append(f"exit code {proc.returncode}")
    if int(final["connections"]) <= 0:
        failures.append("no connections were opened")
    if int(final["peak_active"]) <= 0:
        failures.append("peak_active was 0 (no concurrent connections held)")
    if int(final["peak_active"]) > args.concurrency:
        failures.append(f"peak_active={final['peak_active']} exceeds -c {args.concurrency}")
    if int(final["active"]) > args.concurrency:
        failures.append(
            f"active={final['active']} exceeds -c {args.concurrency} (sockets accumulating)"
        )

    if failures:
        print("FAIL: " + "; ".join(failures))
        print(proc.stderr[-2000:])
        return 1
    print("OK: soak passed (sustained load, clean process exit, no over-subscription)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
