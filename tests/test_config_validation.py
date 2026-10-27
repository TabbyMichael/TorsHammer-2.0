"""Direct unit tests for :mod:`torshammer.config`: validation and layering.

These exercise the ``Config.__post_init__`` rejection matrix, the TOML
discovery helpers, and the env/file coercion fall-throughs in isolation,
without going through the CLI parser.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest

from torshammer.config import (
    Config,
    _apply_bool,
    _apply_scalar,
    _coerce,
    _was_explicit,
    load_toml_file,
)

BASE = {"host": "example.com", "port": 80}


# ---------------------------------------------------------------------------
# __post_init__ rejection matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"stats_interval": 0}, "stats_interval must be greater than 0"),
        ({"stats_interval": -1.0}, "stats_interval must be greater than 0"),
        ({"delay_min": -0.1}, "delay_min must be non-negative"),
        ({"delay_max": -0.1}, "delay_max must be non-negative"),
        ({"delay_min": 5.0, "delay_max": 1.0}, "delay_max must be greater"),
        ({"concurrency": 0}, "concurrency must be at least 1"),
        ({"concurrency": -5}, "concurrency must be at least 1"),
        ({"base_post_length": 0}, "base_post_length must be at least 1"),
        ({"connect_timeout": 0}, "connect_timeout must be greater than 0"),
        ({"connect_timeout": -1.0}, "connect_timeout must be greater than 0"),
        ({"duration": -0.5}, "duration must be non-negative"),
        ({"max_errors": -1}, "max_errors must be non-negative"),
        ({"ramp_up": -1}, "ramp_up must be non-negative"),
        ({"fail_under": -1}, "fail_under must be non-negative"),
    ],
)
def test_invalid_values_are_rejected(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        Config(**BASE, **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"stats_interval": 0.5},
        {"delay_min": 0.0, "delay_max": 0.0},
        {"concurrency": 1},
        {"base_post_length": 1},
        {"connect_timeout": 0.1},
        {"duration": 0.0},
        {"max_errors": 0},
        {"ramp_up": 0},
        {"fail_under": 0},
    ],
)
def test_boundary_values_are_accepted(kwargs: dict[str, Any]) -> None:
    config = Config(**BASE, **kwargs)  # type: ignore[arg-type]
    for name, value in kwargs.items():
        assert getattr(config, name) == value


def test_custom_headers_none_is_tolerated() -> None:
    """Legacy untyped call sites may pass ``custom_headers=None``."""
    config = Config(**BASE, custom_headers=None)  # type: ignore[arg-type]
    assert config.custom_headers == {}


# ---------------------------------------------------------------------------
# TOML discovery and loading
# ---------------------------------------------------------------------------


def test_load_toml_file_discovers_torshammer_toml(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """With no explicit path, a ``torshammer.toml`` in the cwd is picked up."""
    (tmp_path / "torshammer.toml").write_text(
        'concurrency = 12\nmode = "slow-read"\n', encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    assert load_toml_file(None) == {"concurrency": 12, "mode": "slow-read"}


def test_load_toml_file_prefers_torshammer_toml_over_pyproject(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "torshammer.toml").write_text("concurrency = 7\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[tool.torshammer]\nconcurrency = 99\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    assert load_toml_file(None) == {"concurrency": 7}


def test_load_toml_file_returns_empty_when_no_candidate_exists(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    assert load_toml_file(None) == {}


def test_load_toml_file_swallows_oserror(tmp_path: Path) -> None:
    """An unreadable/missing path degrades to empty settings, not a crash."""
    assert load_toml_file(tmp_path / "does-not-exist.toml") == {}


def test_load_toml_file_swallows_decode_error(tmp_path: Path) -> None:
    bad = tmp_path / "broken.toml"
    bad.write_text("this is = not = valid toml\n", encoding="utf-8")
    assert load_toml_file(bad) == {}


def test_load_toml_file_reads_tool_section_from_pyproject(tmp_path: Path) -> None:
    project = tmp_path / "pyproject.toml"
    project.write_text("[tool.torshammer]\nconcurrency = 33\nquiet = true\n", encoding="utf-8")
    assert load_toml_file(project) == {"concurrency": 33, "quiet": True}


def test_load_toml_file_pyproject_without_section_returns_empty(tmp_path: Path) -> None:
    project = tmp_path / "pyproject.toml"
    project.write_text("[tool.other]\nx = 1\n", encoding="utf-8")
    assert load_toml_file(project) == {}


def test_load_toml_file_pyproject_with_non_table_tool(tmp_path: Path) -> None:
    """``tool`` bound to a scalar is not a table: treated as absent."""
    project = tmp_path / "pyproject.toml"
    project.write_text("tool = 5\n", encoding="utf-8")
    assert load_toml_file(project) == {}


def test_load_toml_file_non_dict_payload_returns_empty(tmp_path: Path) -> None:
    """A plain (non-pyproject) TOML file always yields a dict; guard holds."""
    plain = tmp_path / "torshammer.toml"
    plain.write_text("[a.b]\nx = 1\n", encoding="utf-8")
    assert load_toml_file(plain) == {"a": {"b": {"x": 1}}}


def test_load_toml_file_on_a_directory(tmp_path: Path) -> None:
    """Passing a directory hits the OSError branch instead of tracebacking."""
    assert load_toml_file(tmp_path) == {}


# ---------------------------------------------------------------------------
# Layered-setting primitives
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "raw", "expected"),
    [("int", "12", 12), ("float", "1.5", 1.5), ("str", "slow-post", "slow-post")],
)
def test_coerce(kind: str, raw: str, expected: object) -> None:
    assert _coerce(kind, raw) == expected


def test_was_explicit_without_defaults_never_claims_explicit() -> None:
    args = argparse.Namespace(concurrency=99)
    assert _was_explicit(args, "concurrency", None) is False
    assert _was_explicit(args, "concurrency", {}) is False
    assert _was_explicit(args, "concurrency", {"mode": "x"}) is False


def test_was_explicit_detects_a_changed_default() -> None:
    args = argparse.Namespace(concurrency=99)
    assert _was_explicit(args, "concurrency", {"concurrency": 256}) is True
    assert _was_explicit(args, "concurrency", {"concurrency": 99}) is False


def test_apply_scalar_env_coercion_failure_falls_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """A garbage env value is ignored rather than crashing the run."""
    monkeypatch.setenv("TORSHAMMER_CONCURRENCY", "not-a-number")
    args = argparse.Namespace(concurrency=256)
    _apply_scalar(args, "concurrency", "int", {}, None)
    assert args.concurrency == 256


def test_apply_scalar_env_value_is_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TORSHAMMER_CONCURRENCY", "42")
    args = argparse.Namespace(concurrency=256)
    _apply_scalar(args, "concurrency", "int", {}, None)
    assert args.concurrency == 42


def test_apply_scalar_file_value_coercion_failure_is_ignored() -> None:
    args = argparse.Namespace(concurrency=256)
    _apply_scalar(args, "concurrency", "int", {"concurrency": "abc"}, None)
    assert args.concurrency == 256


def test_apply_scalar_file_value_is_applied() -> None:
    args = argparse.Namespace(mode="slow-post")
    _apply_scalar(args, "mode", "str", {"mode": "slow-read"}, None)
    assert args.mode == "slow-read"


def test_apply_scalar_explicit_cli_flag_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TORSHAMMER_CONCURRENCY", "42")
    args = argparse.Namespace(concurrency=7)
    _apply_scalar(args, "concurrency", "int", {"concurrency": 11}, {"concurrency": 256})
    assert args.concurrency == 7


def test_apply_bool_cli_flag_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    """An already-set flag short-circuits before env/file are consulted."""
    monkeypatch.setenv("TORSHAMMER_QUIET", "false")
    args = argparse.Namespace(quiet=True)
    _apply_bool(args, "quiet", {"quiet": True})
    assert args.quiet is True


@pytest.mark.parametrize("raw", ["1", "TRUE", "yes", "on", " true "])
def test_apply_bool_env_truthy_values(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv("TORSHAMMER_QUIET", raw)
    args = argparse.Namespace(quiet=False)
    _apply_bool(args, "quiet", {})
    assert args.quiet is True


def test_apply_bool_env_falsy_value_falls_back_to_file(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TORSHAMMER_QUIET", "0")
    args = argparse.Namespace(quiet=False)
    _apply_bool(args, "quiet", {"quiet": True})
    assert args.quiet is True


def test_apply_bool_env_absent_and_file_false_keeps_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TORSHAMMER_QUIET", raising=False)
    args = argparse.Namespace(quiet=False)
    _apply_bool(args, "quiet", {"quiet": False})
    assert args.quiet is False


def test_apply_bool_missing_attribute_is_tolerated(monkeypatch: pytest.MonkeyPatch) -> None:
    """Namespaces lacking the flag (e.g. partial test doubles) do not raise."""
    monkeypatch.delenv("TORSHAMMER_JSON_OUTPUT", raising=False)
    args = argparse.Namespace()
    _apply_bool(args, "json_output", {"json_output": True})
    assert args.json_output is True


# ---------------------------------------------------------------------------
# Derived properties used by the engine and connection factory
# ---------------------------------------------------------------------------


def test_server_hostname_tracks_secure_flag() -> None:
    assert Config(**BASE, secure=True).server_hostname == "example.com"
    assert Config(**BASE, secure=False).server_hostname is None


def test_ssl_context_is_cached_per_config() -> None:
    config = Config(**BASE, secure=True)
    first = config.ssl_context()
    assert first is not None
    assert config.ssl_context() is first


def test_insecure_ssl_context_disables_verification() -> None:
    import ssl as ssl_module

    config = Config(**BASE, secure=True, ssl_verify=False)
    context = config.ssl_context()
    assert context is not None
    assert context.check_hostname is False
    assert context.verify_mode is ssl_module.CERT_NONE


def test_ssl_context_is_none_for_plain_http() -> None:
    assert Config(**BASE).ssl_context() is None


def test_random_delay_stays_within_bounds() -> None:
    config = Config(**BASE, delay_min=0.5, delay_max=1.5)
    samples = {config.random_delay() for _ in range(200)}
    assert all(0.5 <= value <= 1.5 for value in samples)


def test_random_delay_collapses_when_bounds_equal() -> None:
    config = Config(**BASE, delay_min=0.25, delay_max=0.25)
    assert config.random_delay() == 0.25
