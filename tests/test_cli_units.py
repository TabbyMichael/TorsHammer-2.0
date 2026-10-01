"""Unit tests for CLI helpers: policy, parsing, backend dispatch, fd limits."""

from __future__ import annotations

import argparse
import stat
from pathlib import Path
from typing import Any

import pytest

from torshammer import cli, dispatch
from torshammer.cli import (
    _check_fd_limits,
    _check_target_policy,
    _forward_to_rust,
    _is_private_or_local_target,
    _load_allowlist,
    _load_custom_body,
    _parse_custom_headers,
    _resolve_backend,
    build_parser,
)
from torshammer.config import Config
from torshammer.useragents import load_user_agents

# ---------------------------------------------------------------------------
# Target policy
# ---------------------------------------------------------------------------


def test_is_private_or_local_target():
    assert _is_private_or_local_target("localhost")
    assert _is_private_or_local_target("myhost.localhost")
    assert _is_private_or_local_target("127.0.0.1")
    assert _is_private_or_local_target("10.0.0.1")
    assert _is_private_or_local_target("192.168.1.1")
    assert _is_private_or_local_target("::1")
    assert not _is_private_or_local_target("example.com")
    assert not _is_private_or_local_target("93.184.216.34")


def test_check_target_policy_public_refused_by_default():
    with pytest.raises(SystemExit):
        _check_target_policy("example.com", allow_public_targets=False, allowlist=set())


def test_check_target_policy_allow_public_flag():
    _check_target_policy("example.com", allow_public_targets=True, allowlist=set())


def test_check_target_policy_allowlist_entry():
    _check_target_policy("example.com", allow_public_targets=False, allowlist={"example.com"})


def test_load_allowlist(tmp_path: Path):
    path = tmp_path / "allow.txt"
    path.write_text("# comment\n\nExample.COM\n10.0.0.1\n")
    assert _load_allowlist(str(path)) == {"example.com", "10.0.0.1"}


# ---------------------------------------------------------------------------
# Header / body parsing
# ---------------------------------------------------------------------------


def test_parse_custom_headers_colon_only():
    out = _parse_custom_headers(["X-A: 1", "X-B: 2"])
    assert out == ["X-A: 1", "X-B: 2"]


def test_parse_custom_headers_rejects_equals_form():
    """The legacy ``Name=value`` form is rejected (colon-only contract)."""
    with pytest.raises(SystemExit):
        _parse_custom_headers(["X-B=2"])


def test_parse_custom_headers_rejects_crlf():
    """CR/LF content is rejected to prevent header injection."""
    with pytest.raises(SystemExit):
        _parse_custom_headers(["X-A: a\r\nInjected: b"])
    with pytest.raises(SystemExit):
        _parse_custom_headers(["X-A: a\nb"])


def test_parse_custom_headers_rejects_invalid():
    with pytest.raises(SystemExit):
        _parse_custom_headers(["no-separator"])


def test_load_custom_body(tmp_path: Path):
    body = tmp_path / "body.bin"
    body.write_bytes(b"PAYLOAD")
    assert _load_custom_body(str(body)) == b"PAYLOAD"
    assert _load_custom_body(None) is None
    with pytest.raises(SystemExit):
        _load_custom_body(str(tmp_path / "missing.bin"))


# ---------------------------------------------------------------------------
# User agents
# ---------------------------------------------------------------------------


def test_load_user_agents_default_when_no_path():
    assert len(load_user_agents(None)) >= 1


def test_load_user_agents_from_file(tmp_path: Path):
    path = tmp_path / "ua.txt"
    path.write_text("# bot list\nMyAgent/1.0\n\n")
    assert load_user_agents(str(path)) == ["MyAgent/1.0"]


def test_load_user_agents_empty_file_falls_back(tmp_path: Path):
    path = tmp_path / "ua.txt"
    path.write_text("# only comments\n")
    assert len(load_user_agents(str(path))) >= 1


def test_load_user_agents_missing_file_exits(tmp_path: Path):
    with pytest.raises(SystemExit):
        load_user_agents(str(tmp_path / "missing.txt"))


# ---------------------------------------------------------------------------
# FD limits
# ---------------------------------------------------------------------------


def test_check_fd_limits_warns_but_does_not_raise(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    import resource

    def fake_getrlimit(res: int) -> tuple[int, int]:
        return (10, 100)  # soft=10 forces the warning branch at any concurrency

    monkeypatch.setattr(resource, "getrlimit", fake_getrlimit)
    _check_fd_limits(256)  # must warn, never raise
    assert "[warn]" in capsys.readouterr().err


def test_check_fd_limits_silent_when_under_limit(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    import resource

    def fake_getrlimit(res: int) -> tuple[int, int]:
        return (100000, 200000)

    monkeypatch.setattr(resource, "getrlimit", fake_getrlimit)
    _check_fd_limits(256)
    assert "[warn]" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Backend resolution / Rust dispatch
# ---------------------------------------------------------------------------


def test_resolve_backend_python_short_circuits():
    assert _resolve_backend("python") == "python"


def test_resolve_backend_rust_falls_back_without_binary(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    monkeypatch.delenv("TORSHAMMER_RUST_BIN", raising=False)

    def no_which(name: str) -> None:
        return None

    monkeypatch.setattr(dispatch.shutil, "which", no_which)
    # The repo-relative dev build must be neutralised too: on a machine where
    # `cargo build` has run, rust/target/{release,debug}/torshammer-rust exists.
    monkeypatch.setattr(dispatch, "_find_rust_binary", lambda: None)
    assert _resolve_backend("rust") == "python"
    assert "[warn]" in capsys.readouterr().err


def test_resolve_backend_rust_keeps_rust_when_dev_build_exists(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    """A locally built binary (repo layout) counts as available, without a warning."""
    monkeypatch.setattr(
        dispatch, "_find_rust_binary", lambda: "/repo/rust/target/release/torshammer-rust"
    )
    assert _resolve_backend("rust") == "rust"
    assert capsys.readouterr().err == ""


def _rust_config(**overrides: Any) -> Config:
    defaults: dict[str, Any] = {
        "host": "example.com",
        "port": 80,
        "header_host": "example.com",
        "backend": "rust",
    }
    defaults.update(overrides)
    return Config(**defaults)


def test_forward_to_rust_missing_binary_exit_127(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(dispatch, "_find_rust_binary", lambda: None)
    args = build_parser().parse_args(["-u", "http://example.com", "--backend", "rust"])
    assert _forward_to_rust(_rust_config(), args) == 127


def test_forward_to_rust_rejects_https(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    fake_bin = tmp_path / "torshammer-rust"
    fake_bin.write_text("#!/bin/sh\n")
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(dispatch, "_find_rust_binary", lambda: str(fake_bin))
    args = build_parser().parse_args(["-u", "https://example.com", "--backend", "rust"])
    assert _forward_to_rust(_rust_config(secure=True), args) == 1


def test_forward_to_rust_exec_failure_exit_1(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    fake_bin = tmp_path / "torshammer-rust"
    fake_bin.write_text("#!/bin/sh\n")
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(cli, "_find_rust_binary", lambda: str(fake_bin))

    def broken_execv(binary: str, argv: list[str]) -> None:
        raise OSError("no exec for you")

    monkeypatch.setattr(dispatch.os, "execv", broken_execv)
    args = build_parser().parse_args(["-u", "http://example.com", "--backend", "rust"])
    assert _forward_to_rust(_rust_config(), args) == 1


def _rust_bin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> str:
    fake_bin = tmp_path / "torshammer-rust"
    fake_bin.write_text("#!/bin/sh\n")
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(dispatch, "_find_rust_binary", lambda: str(fake_bin))
    return str(fake_bin)


def test_forward_to_rust_rejects_proxies_fail_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """Proxy/Tor flags must exit non-zero, never be silently ignored."""
    _rust_bin(monkeypatch, tmp_path)
    args = build_parser().parse_args(
        [
            "-u",
            "http://example.com",
            "--backend",
            "rust",
            "--proxy",
            "socks5://127.0.0.1:9050",
            "--allow-public-targets",
        ]
    )
    from torshammer.cli import _resolve_config

    assert _forward_to_rust(_resolve_config(args), args) == 1


def test_forward_to_rust_rejects_ssl_no_verify(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    _rust_bin(monkeypatch, tmp_path)
    args = build_parser().parse_args(
        [
            "-u",
            "http://example.com",
            "--backend",
            "rust",
            "--ssl-no-verify",
            "--allow-public-targets",
        ]
    )
    from torshammer.cli import _resolve_config

    assert _forward_to_rust(_resolve_config(args), args) == 1


def test_forward_to_rust_rejects_user_agents_and_ramp_up(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    _rust_bin(monkeypatch, tmp_path)
    from torshammer.cli import _resolve_config as _rc

    ua_file = tmp_path / "ua.txt"
    ua_file.write_text("CustomAgent/1.0\n")
    ua_args = build_parser().parse_args(
        [
            "-u",
            "http://example.com",
            "--backend",
            "rust",
            "--user-agents",
            str(ua_file),
            "--allow-public-targets",
        ]
    )
    assert _forward_to_rust(_rc(ua_args), ua_args) == 1

    args = build_parser().parse_args(
        ["-u", "http://example.com", "--backend", "rust", "--allow-public-targets"]
    )
    assert _forward_to_rust(_rust_config(ramp_up=5), args) == 1


def test_forward_to_rust_forwards_headers_and_body(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Mappable flags must survive the exec boundary as --header/--body-file."""
    captured: dict[str, list[str]] = {}
    _rust_bin(monkeypatch, tmp_path)
    body = tmp_path / "body.bin"
    body.write_bytes(b"PAYLOAD")

    def fake_execv(binary: str, argv: list[str]) -> None:
        captured["argv"] = argv
        raise OSError("stop here")

    monkeypatch.setattr(dispatch.os, "execv", fake_execv)
    args = build_parser().parse_args(
        [
            "-u",
            "http://example.com",
            "--backend",
            "rust",
            "--header",
            "X-A: 1",
            "--body-file",
            str(body),
            "--allow-public-targets",
        ]
    )
    from torshammer.cli import _resolve_config

    assert _forward_to_rust(_resolve_config(args), args) == 1
    argv = captured["argv"]
    idx = argv.index("--header")
    assert argv[idx + 1] == "X-A: 1"
    assert "--body-file" in argv


def test_forward_to_rust_windows_uses_subprocess(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """On Windows there is no execv; the backend is spawned and mirrored."""
    import subprocess

    binary = _rust_bin(monkeypatch, tmp_path)
    monkeypatch.setattr(dispatch.os, "name", "nt")

    def fake_run(cmd: list[str], check: bool = False):  # type: ignore[no-untyped-def]
        assert cmd[0] == binary
        assert "--backend" in cmd and "rust" in cmd

        class Done:
            returncode = 42

        return Done()

    monkeypatch.setattr(subprocess, "run", fake_run)
    args = build_parser().parse_args(["-u", "http://example.com", "--backend", "rust"])
    assert _forward_to_rust(_rust_config(), args) == 42


def test_forward_to_rust_rejects_udp_target_without_udp_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """Defense-in-depth: a udp:// target with a non-udp Config fails closed.

    The CLI itself always sets ``mode=udp`` for ``udp://`` URLs (see
    ``tests/test_udp.py``), so this branch is only reachable for programmatic
    callers passing a mismatched Config — which is exactly why it must not
    exec.
    """
    _rust_bin(monkeypatch, tmp_path)

    def fake_execv(binary: str, argv: list[str]) -> None:
        raise AssertionError("must fail closed before exec")

    monkeypatch.setattr(dispatch.os, "execv", fake_execv)
    args = build_parser().parse_args(
        ["-u", "udp://127.0.0.1:53", "--backend", "rust", "--allow-public-targets"]
    )
    assert _forward_to_rust(_rust_config(mode="slow-post"), args) == 1
    assert "requires -m udp" in capsys.readouterr().err


def test_forward_to_rust_udp_mode_accepted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """With `-m udp` the same udp:// target dispatches, keeping the udp scheme."""
    captured: dict[str, list[str]] = {}
    _rust_bin(monkeypatch, tmp_path)

    def fake_execv(binary: str, argv: list[str]) -> None:
        captured["argv"] = argv
        raise OSError("stop here")

    monkeypatch.setattr(dispatch.os, "execv", fake_execv)
    args = build_parser().parse_args(
        ["-u", "udp://127.0.0.1:53", "-m", "udp", "--backend", "rust", "--allow-public-targets"]
    )
    from torshammer.cli import _resolve_config

    assert _forward_to_rust(_resolve_config(args), args) == 1
    target = captured["argv"][captured["argv"].index("--target") + 1]
    assert target.startswith("udp://"), target
    assert "-m" in captured["argv"]
    assert captured["argv"][captured["argv"].index("-m") + 1] == "udp"


def test_forward_to_rust_warns_on_path_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    """--path is dropped at the exec boundary, but must warn, not fail silently.

    ``_resolve_config`` copies ``args.path`` into ``config.path``, so the CLI
    can never trip this guard; it exists for programmatic callers whose Config
    carries a different path than the args being forwarded.
    """
    _rust_bin(monkeypatch, tmp_path)

    def fake_execv(binary: str, argv: list[str]) -> None:
        raise OSError("x")

    monkeypatch.setattr(dispatch.os, "execv", fake_execv)
    args = build_parser().parse_args(
        ["-u", "http://example.com/", "--path", "/override", "--backend", "rust"]
    )
    _forward_to_rust(_rust_config(path="/from-config"), args)
    assert "ignoring --path override" in capsys.readouterr().err


def test_forward_to_rust_forwards_optional_flags(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """Every mapped optional flag survives the exec boundary."""
    captured: dict[str, list[str]] = {}
    _rust_bin(monkeypatch, tmp_path)

    def fake_execv(binary: str, argv: list[str]) -> None:
        captured["argv"] = argv
        raise OSError("stop here")

    monkeypatch.setattr(dispatch.os, "execv", fake_execv)
    args = build_parser().parse_args(
        [
            "-u",
            "http://example.com",
            "--backend",
            "rust",
            "--method",
            "PUT",
            "--no-random-path",
            "--json",
            "--quiet",
            "-v",
            "--fail-under",
            "25",
            "--fail-on-zero",
            "--allow-public-targets",
        ]
    )
    from torshammer.cli import _resolve_config

    assert _forward_to_rust(_resolve_config(args), args) == 1
    argv = captured["argv"]
    assert argv[argv.index("--method") + 1] == "PUT"
    assert "--no-random-path" in argv
    assert "--json" in argv
    assert "--quiet" in argv
    assert "-v" in argv
    assert argv[argv.index("--fail-under") + 1] == "25"
    assert "--fail-on-zero" in argv


def test_cli_import_without_resource_module(monkeypatch: pytest.MonkeyPatch):
    """Windows has no `resource` module; import + fd check must degrade."""
    import torshammer.cli as cli_mod

    monkeypatch.setattr(cli_mod, "resource", None)
    monkeypatch.setattr(cli_mod, "HAS_RESOURCE", False)
    cli_mod._check_fd_limits(100000)  # must no-op, never raise


# ---------------------------------------------------------------------------
# Proxy building
# ---------------------------------------------------------------------------


def test_build_proxies_from_proxy_list_skips_invalid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    from torshammer.cli import _build_proxies

    path = tmp_path / "proxies.txt"
    path.write_text("# comment\nsocks5://10.0.0.1:1080\nnot-a-scheme!://x\n")
    args = argparse.Namespace(
        url=None,
        target=None,
        ssl=False,
        proxy=None,
        proxy_env=None,
        proxy_list=str(path),
        tor=False,
    )
    proxies = _build_proxies(args)
    assert proxies is not None and len(proxies) == 1
    assert proxies[0].host == "10.0.0.1"


def test_build_proxies_missing_env_var_exits():
    from torshammer.cli import _build_proxies

    args = argparse.Namespace(
        url=None,
        target=None,
        ssl=False,
        proxy=None,
        proxy_env="DEFINITELY_NOT_SET_VAR_XYZ",
        proxy_list=None,
        tor=False,
    )
    with pytest.raises(SystemExit):
        _build_proxies(args)


def test_build_proxies_tor_flag_prepends():
    from torshammer.cli import _build_proxies

    args = argparse.Namespace(
        url=None,
        target=None,
        ssl=False,
        proxy=None,
        proxy_env=None,
        proxy_list=None,
        tor=True,
    )
    proxies = _build_proxies(args)
    assert proxies is not None
    assert proxies[0].scheme == "socks5" and proxies[0].port == 9050


def test_build_proxies_none_when_empty():
    from torshammer.cli import _build_proxies

    args = argparse.Namespace(
        url=None,
        target=None,
        ssl=False,
        proxy=None,
        proxy_env=None,
        proxy_list=None,
        tor=False,
    )
    assert _build_proxies(args) is None


def test_pytest_dependency_warning_guidance():
    """Verify pyproject.toml provides clear test dependencies in optional-dependencies.dev."""
    import tomllib

    pyproject_path = Path(__file__).resolve().parents[1] / "pyproject.toml"
    assert pyproject_path.exists()
    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    dev_deps = data["project"]["optional-dependencies"]["dev"]
    assert any("pytest-cov" in dep for dep in dev_deps)
    assert any("pytest-asyncio" in dep for dep in dev_deps)

