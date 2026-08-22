"""End-to-end smoke tests for the real CLI entry point.

These tests execute ``torshammer.cli.main`` exactly as an operator would,
against live local fixtures.  They exist because the entry point once
regressed into an unrunnable state (syntax error / missing helper /
NameError in ``main``) without any test noticing: every other suite tested
individual components but never the actual command.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import threading
from pathlib import Path

import pytest

from tests.conftest import SlowServer
from torshammer.cli import main


def _free_port() -> int:
    """Grab an ephemeral port and immediately release it (small TOCTOU risk OK)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_main_end_to_end_against_local_server():
    """main() must complete successfully against a live local target."""
    holder: dict = {}
    started = threading.Event()

    async def scenario():
        srv = SlowServer()
        await srv.start()
        holder["port"] = srv.port
        started.set()

        def run_cli():
            holder["rc"] = main(["-u", f"http://127.0.0.1:{holder['port']}", "-c", "2", "-d", "1"])

        thread = threading.Thread(target=run_cli)
        thread.start()

        # Let the run finish (duration 1s + teardown margin), then reap it.
        deadline = asyncio.get_running_loop().time() + 15
        while thread.is_alive():
            if asyncio.get_running_loop().time() > deadline:
                raise TimeoutError("CLI run did not finish within 15s")
            await asyncio.sleep(0.05)

        holder["connections_seen"] = srv.connections
        await srv.stop()

    asyncio.run(scenario())

    assert holder.get("rc") == 0, f"expected exit code 0, got {holder.get('rc')}"
    assert holder.get("connections_seen", 0) > 0, "server never saw a connection"


def test_main_circuit_breaker_exit_code():
    """Unreachable target + --max-errors must produce exit code 1 (CI hook)."""
    dead_port = _free_port()
    rc = main(
        [
            "-u",
            f"http://127.0.0.1:{dead_port}",
            "-c",
            "2",
            "-d",
            "5",
            "--max-errors",
            "1",
        ]
    )
    assert rc == 1, "circuit breaker path should exit non-zero"


def test_main_udp_mode_smoke():
    """udp:// scheme must force udp mode and run cleanly end-to-end."""
    port = _free_port()
    rc = main(["-u", f"udp://127.0.0.1:{port}", "-c", "2", "-d", "0.5"])
    assert rc == 0


def test_main_fail_on_zero_exit_code():
    """--fail-on-zero against an unreachable target must exit non-zero."""
    dead_port = _free_port()
    rc = main(
        [
            "-u",
            f"http://127.0.0.1:{dead_port}",
            "-c",
            "1",
            "-d",
            "0.3",
            "--connect-timeout",
            "0.2",
            "--fail-on-zero",
        ]
    )
    assert rc == 1


def test_rust_backend_parity_smoke():
    """The Rust backend must open real connections against the same fixture.

    Mirrors the Python e2e test above so both backends are held to the same
    behavioural contract. Skipped automatically when the Rust binary has not
    been built (``cargo build`` in rust/).
    """
    repo = Path(__file__).resolve().parents[1]
    candidates = [
        repo / "rust" / "target" / "release" / "torshammer-rust",
        repo / "rust" / "target" / "debug" / "torshammer-rust",
    ]
    binary = next((p for p in candidates if p.exists() and os.access(p, os.X_OK)), None)
    if binary is None:
        pytest.skip("rust backend not built (cargo build --manifest-path rust/Cargo.toml)")

    holder: dict = {}

    async def scenario():
        srv = SlowServer()
        await srv.start()
        url = f"http://127.0.0.1:{srv.port}"

        def run_rust():
            return subprocess.run(
                [str(binary), "-u", url, "-c", "2", "-d", "0.5"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )

        proc = await asyncio.to_thread(run_rust)
        holder["rc"] = proc.returncode
        holder["stdout"] = proc.stdout
        holder["stderr"] = proc.stderr
        holder["connections_seen"] = srv.connections
        await srv.stop()

    asyncio.run(scenario())

    assert holder["rc"] == 0, (
        f"rust backend exited {holder['rc']}\nstdout={holder['stdout']}\nstderr={holder['stderr']}"
    )
    assert holder["connections_seen"] > 0, "rust backend never opened a connection"
