"""Task 6 - CLI orchestration glue and the ``python -m`` entry point.

These tests drive the branches in :func:`torshammer.cli.main` and its helpers
that the happy-path end-to-end suite never reaches: banner fallback, file
descriptor limit adjustment, ``--config-file`` layering, dry-run/master/rust
dispatch, ``KeyboardInterrupt`` and the ``--fail-under`` tripwire. They also
cover ``torshammer.__main__`` in-process (a subprocess would not register with
pytest-cov).
"""

from __future__ import annotations

import asyncio
import resource
import runpy
import threading
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import SlowServer
from torshammer import cli
from torshammer.cli import _check_fd_limits, _load_banner, main

# ---------------------------------------------------------------------------
# __main__.py entry point (executed in-process so coverage records it)
# ---------------------------------------------------------------------------


def test_module_entry_point_forwards_main_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    """``python -m torshammer`` raises SystemExit(main()) - covered via runpy."""
    monkeypatch.setattr(cli, "main", lambda *a, **k: 7)
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("torshammer", run_name="__main__")
    assert excinfo.value.code == 7


# ---------------------------------------------------------------------------
# _load_banner fallback (cli.py 41-42)
# ---------------------------------------------------------------------------


def test_load_banner_falls_back_when_resource_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(_pkg: str) -> Any:
        raise OSError("banner.txt not packaged")

    monkeypatch.setattr(cli.resources, "files", _boom)
    banner = _load_banner()
    assert "{VER}" in banner and "TorsHammer" in banner


# ---------------------------------------------------------------------------
# _check_fd_limits branches (cli.py 344, 355-357, 374-376)
# ---------------------------------------------------------------------------


def test_check_fd_limits_raises_toward_infinity_hard_cap(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """soft < desired and hard == RLIM_INFINITY -> target = desired (L344)."""
    if not cli.HAS_RESOURCE:  # pragma: no cover - POSIX-only gate
        pytest.skip("resource module unavailable")
    monkeypatch.setattr(resource, "getrlimit", lambda _which: (10, resource.RLIM_INFINITY))
    set_calls: list[tuple[int, int]] = []
    monkeypatch.setattr(resource, "setrlimit", lambda _which, lim: set_calls.append(lim))
    _check_fd_limits(100)
    assert set_calls == [(164, resource.RLIM_INFINITY)]
    assert "raised file-descriptor soft limit to 164" in capsys.readouterr().err


def test_check_fd_limits_swallows_setrlimit_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A root-only hard limit makes setrlimit raise -> warn path (L355-357)."""
    if not cli.HAS_RESOURCE:  # pragma: no cover - POSIX-only gate
        pytest.skip("resource module unavailable")

    def _raise(_which: int, _lim: tuple[int, int]) -> None:
        raise OSError("operation not permitted")

    monkeypatch.setattr(resource, "getrlimit", lambda _which: (10, resource.RLIM_INFINITY))
    monkeypatch.setattr(resource, "setrlimit", _raise)
    _check_fd_limits(100)
    err = capsys.readouterr().err
    assert "exceeds 80%" in err


def test_check_fd_limits_swallows_getrlimit_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """getrlimit failing outright is tolerated (L374-376)."""
    if not cli.HAS_RESOURCE:  # pragma: no cover - POSIX-only gate
        pytest.skip("resource module unavailable")

    def _raise(_which: int) -> tuple[int, int]:
        raise ValueError("getrlimit unsupported")

    monkeypatch.setattr(resource, "getrlimit", _raise)
    _check_fd_limits(100)  # no exception should escape


# ---------------------------------------------------------------------------
# main() layered --config-file (cli.py 416) and dry-run/master/rust paths
# ---------------------------------------------------------------------------


def test_main_uses_explicit_config_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    toml = tmp_path / "torshammer.toml"
    toml.write_text("[tool.torshammer]\nconcurrency = 42\n")
    rc = main(
        [
            "-u",
            "http://localhost:8080",
            "--config-file",
            str(toml),
            "--dry-run",
        ]
    )
    assert rc == 0
    assert "dry-run" in capsys.readouterr().out


def test_main_dry_run_announces_rust_backend(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Keep this independent of whether a `torshammer-rust` binary happens to be
    # built in the environment (CI's python matrix jobs never build the Rust
    # backend). The real lookup and its no-binary fallback branch are covered in
    # test_cli_units / test_dispatch_edges; here we only need `--backend rust`
    # to resolve to rust so the dry-run announce fires.
    monkeypatch.setattr(
        "torshammer.dispatch._find_rust_binary",
        lambda *a, **k: "/repo/rust/target/debug/torshammer-rust",
    )
    rc = main(["-u", "http://localhost:8080", "--backend", "rust", "--dry-run"])
    assert rc == 0
    assert "rust backend selected" in capsys.readouterr().err


def test_main_dispatches_to_rust(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def _fake_forward(config: Any, args: Any) -> int:
        seen["backend"] = config.backend
        return 5

    monkeypatch.setattr(cli, "_forward_to_rust", _fake_forward)
    # Force the rust resolution regardless of build state; otherwise a missing
    # binary makes the CLI fall back to the python engine and launch a real
    # attack against the target at the default (run-until-interrupted) duration.
    monkeypatch.setattr(
        "torshammer.dispatch._find_rust_binary",
        lambda *a, **k: "/repo/rust/target/debug/torshammer-rust",
    )
    rc = main(["-u", "http://localhost:8080", "--backend", "rust"])
    assert rc == 5
    assert seen["backend"] == "rust"


def test_main_master_requires_readable_workers_file(tmp_path: Path) -> None:
    missing = tmp_path / "nope.txt"
    rc = main(["-u", "http://localhost:8080", "--master", "--cluster-workers", str(missing)])
    assert rc == 2


def test_main_master_rejects_empty_workers_file(tmp_path: Path) -> None:
    empty = tmp_path / "workers.txt"
    empty.write_text("# only a comment\n\n")
    rc = main(["-u", "http://localhost:8080", "--master", "--cluster-workers", str(empty)])
    assert rc == 2


# ---------------------------------------------------------------------------
# main() interruption + fail-under tripwire (cli.py 491-493, 502-506)
# ---------------------------------------------------------------------------


def test_main_returns_130_on_keyboard_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*_a: Any, **_k: Any) -> Any:
        for arg in _a:
            if asyncio.iscoroutine(arg):
                arg.close()
        raise KeyboardInterrupt

    monkeypatch.setattr(cli.asyncio, "run", _raise)
    rc = main(["-u", "http://localhost:8080"])
    assert rc == 130


def test_main_fail_under_tripwire_returns_1() -> None:
    """A live target with an unreachable threshold exits 1 via the tripwire."""
    holder: dict[str, Any] = {}
    started = threading.Event()

    async def scenario() -> None:
        srv = SlowServer()
        await srv.start()

        def run_cli() -> None:
            holder["rc"] = main(
                [
                    "-u",
                    f"http://127.0.0.1:{srv.port}",
                    "-c",
                    "1",
                    "-d",
                    "0.3",
                    "--fail-under",
                    "100000",
                ]
            )

        thread = threading.Thread(target=run_cli)
        thread.start()
        started.set()
        deadline = asyncio.get_running_loop().time() + 15
        while thread.is_alive():
            if asyncio.get_running_loop().time() > deadline:
                raise TimeoutError("CLI did not finish within 15s")
            await asyncio.sleep(0.05)
        await srv.stop()

    asyncio.run(scenario())
    assert holder.get("rc") == 1
