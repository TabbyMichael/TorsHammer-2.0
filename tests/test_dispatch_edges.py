"""Task 7 (dispatch half) - Rust binary discovery and Windows launch errors.

Covers the :func:`torshammer.dispatch._find_rust_binary` discovery arms
(``TORSHAMMER_RUST_BIN`` hit, the repo-relative ``rust/target/{release,debug}``
dev-build scan, and the ``None`` fall-through when nothing is found) and the
Windows ``os.name == "nt"`` spawn path whose ``subprocess.run`` raises
``OSError``. The POSIX ``return 0`` after ``os.execv`` is excluded in
Task 8 (execv never returns on success).
"""

from __future__ import annotations

import argparse
import subprocess
import sys

import pytest

from torshammer import dispatch
from torshammer.config import Config


def _no_blocker_config() -> Config:
    return Config(host="127.0.0.1", port=80, mode="slow-post", concurrency=1)


def _args(**overrides: object) -> argparse.Namespace:
    base: dict[str, object] = {
        "path": None,
        "body_file": None,
        "allowlist_file": None,
        "url": None,
        "user_agents": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_find_rust_binary_prefers_env_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TORSHAMMER_RUST_BIN", sys.executable)
    assert dispatch._find_rust_binary() == sys.executable


def test_find_rust_binary_returns_none_when_nothing_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TORSHAMMER_RUST_BIN", raising=False)
    monkeypatch.setattr(dispatch.shutil, "which", lambda _name: None)
    monkeypatch.setattr(dispatch.os.path, "isfile", lambda _p: False)
    assert dispatch._find_rust_binary() is None


def test_find_rust_binary_discovers_repo_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The repo-relative dev-build scan (dispatch.py 40-44) is covered deterministically.

    We fake the filesystem so ``rust/target/{release,debug}/torshammer-rust``
    looks present and executable, rather than depending on an actual ``cargo
    build`` artifact existing in CI's Rust-binary-free python jobs.
    """
    monkeypatch.delenv("TORSHAMMER_RUST_BIN", raising=False)
    monkeypatch.setattr(dispatch.shutil, "which", lambda _name: None)
    monkeypatch.setattr(dispatch.os.path, "isfile", lambda _p: True)
    monkeypatch.setattr(dispatch.os, "access", lambda _p, _mode: True)
    found = dispatch._find_rust_binary()
    assert found is not None
    assert found.endswith("rust/target/release/torshammer-rust")


def test_forward_to_rust_windows_spawn_error_returns_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dispatch.os, "name", "nt")
    monkeypatch.setattr(dispatch, "_find_rust_binary", lambda *a, **k: "/fake/torshammer-rust")

    def _boom(*_a: object, **_k: object) -> object:
        raise OSError("cannot spawn")

    monkeypatch.setattr(subprocess, "run", _boom)
    rc = dispatch._forward_to_rust(_no_blocker_config(), _args())
    assert rc == 1
