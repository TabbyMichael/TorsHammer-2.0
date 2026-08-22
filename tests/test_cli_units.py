"""Unit tests for CLI helpers: policy, parsing, backend dispatch, fd limits."""

from __future__ import annotations

import argparse
import stat

import pytest

from torshammer import cli
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


def test_load_allowlist(tmp_path):
    path = tmp_path / "allow.txt"
    path.write_text("# comment\n\nExample.COM\n10.0.0.1\n")
    assert _load_allowlist(str(path)) == {"example.com", "10.0.0.1"}


# ---------------------------------------------------------------------------
# Header / body parsing
# ---------------------------------------------------------------------------


def test_parse_custom_headers_colon_and_equals():
    out = _parse_custom_headers(["X-A: 1", "X-B=2"])
    assert out == ["X-A: 1", "X-B: 2"]


def test_parse_custom_headers_rejects_invalid():
    with pytest.raises(SystemExit):
        _parse_custom_headers(["no-separator"])


def test_load_custom_body(tmp_path):
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


def test_load_user_agents_from_file(tmp_path):
    path = tmp_path / "ua.txt"
    path.write_text("# bot list\nMyAgent/1.0\n\n")
    assert load_user_agents(str(path)) == ["MyAgent/1.0"]


def test_load_user_agents_empty_file_falls_back(tmp_path):
    path = tmp_path / "ua.txt"
    path.write_text("# only comments\n")
    assert len(load_user_agents(str(path))) >= 1


def test_load_user_agents_missing_file_exits(tmp_path):
    with pytest.raises(SystemExit):
        load_user_agents(str(tmp_path / "missing.txt"))


# ---------------------------------------------------------------------------
# FD limits
# ---------------------------------------------------------------------------


def test_check_fd_limits_warns_but_does_not_raise(monkeypatch, capsys):
    import resource

    def fake_getrlimit(res):
        return (10, 100)  # soft=10 forces the warning branch at any concurrency

    monkeypatch.setattr(resource, "getrlimit", fake_getrlimit)
    _check_fd_limits(256)  # must warn, never raise
    assert "[warn]" in capsys.readouterr().err


def test_check_fd_limits_silent_when_under_limit(monkeypatch, capsys):
    import resource

    monkeypatch.setattr(resource, "getrlimit", lambda res: (100000, 200000))
    _check_fd_limits(256)
    assert "[warn]" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Backend resolution / Rust dispatch
# ---------------------------------------------------------------------------


def test_resolve_backend_python_short_circuits():
    assert _resolve_backend("python") == "python"


def test_resolve_backend_rust_falls_back_without_binary(monkeypatch, capsys):
    monkeypatch.delenv("TORSHAMMER_RUST_BIN", raising=False)
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    assert _resolve_backend("rust") == "python"
    assert "[warn]" in capsys.readouterr().err


def _rust_config(**overrides) -> Config:
    defaults: dict = {
        "host": "example.com",
        "port": 80,
        "header_host": "example.com",
        "backend": "rust",
    }
    defaults.update(overrides)
    return Config(**defaults)


def test_forward_to_rust_missing_binary_exit_127(monkeypatch):
    monkeypatch.setattr(cli, "_find_rust_binary", lambda: None)
    args = build_parser().parse_args(["-u", "http://example.com", "--backend", "rust"])
    assert _forward_to_rust(_rust_config(), args) == 127


def test_forward_to_rust_rejects_https(monkeypatch, tmp_path):
    fake_bin = tmp_path / "torshammer-rust"
    fake_bin.write_text("#!/bin/sh\n")
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(cli, "_find_rust_binary", lambda: str(fake_bin))
    args = build_parser().parse_args(["-u", "https://example.com", "--backend", "rust"])
    assert _forward_to_rust(_rust_config(secure=True), args) == 1


def test_forward_to_rust_exec_failure_exit_1(monkeypatch, tmp_path):
    fake_bin = tmp_path / "torshammer-rust"
    fake_bin.write_text("#!/bin/sh\n")
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setattr(cli, "_find_rust_binary", lambda: str(fake_bin))

    def broken_execv(binary, argv):
        raise OSError("no exec for you")

    monkeypatch.setattr(cli.os, "execv", broken_execv)
    args = build_parser().parse_args(["-u", "http://example.com", "--backend", "rust"])
    assert _forward_to_rust(_rust_config(), args) == 1


# ---------------------------------------------------------------------------
# Proxy building
# ---------------------------------------------------------------------------


def test_build_proxies_from_proxy_list_skips_invalid(tmp_path, capsys):
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
