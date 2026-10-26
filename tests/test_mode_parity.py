"""Cross-backend parity + registry-derivation guards (Phase 0 foundation).

These tests are the mechanical enforcement of the two standing rules:

1. Every attack mode exists in BOTH the Python and Rust backends.
2. The mode list is *derived* from the single-source-of-truth registries, never
   hardcoded in the CLI, help text or argument validation.

``tests/mode_list.txt`` is the canonical contract; the Python ``PROFILES``
registry and the Rust ``TCP_MODES`` dispatch table are each parsed and asserted
to match it exactly.
"""

from __future__ import annotations

import re
from pathlib import Path

from torshammer.cli import build_parser
from torshammer.profiles import PROFILES
from torshammer.settings import all_modes

REPO_ROOT = Path(__file__).resolve().parents[1]
MODE_LIST = REPO_ROOT / "tests" / "mode_list.txt"
RUST_PROFILES = REPO_ROOT / "rust" / "src" / "engine" / "profiles.rs"
ATTACK_MODES_DOC = REPO_ROOT / "docs" / "attack-modes.md"


def _canonical_modes() -> set[str]:
    lines = MODE_LIST.read_text(encoding="utf-8").splitlines()
    return {line.strip() for line in lines if line.strip() and not line.startswith("#")}


def _rust_tcp_mode_names() -> set[str]:
    """Extract the mode names from the Rust ``TCP_MODES`` dispatch table."""
    text = RUST_PROFILES.read_text(encoding="utf-8")
    start = text.index("TCP_MODES: &[(&str, Handler)] = &[")
    end = text.index("];", start)
    block = text[start:end]
    return set(re.findall(r"\(\s*\"([a-z0-9\-]+)\"\s*,", block))


def test_python_registry_matches_mode_list() -> None:
    assert {*PROFILES, "udp"} == _canonical_modes()


def test_rust_dispatch_table_matches_mode_list() -> None:
    # The Rust table holds the TCP profiles; `udp` is added by `mode_names()`.
    assert _rust_tcp_mode_names() | {"udp"} == _canonical_modes()


def test_cli_choices_are_derived_not_hardcoded() -> None:
    parser = build_parser()
    action = next(a for a in parser._actions if a.dest == "mode")
    assert sorted(action.choices or []) == all_modes()
    assert set(action.choices or []) == _canonical_modes()


def test_unknown_mode_injected_via_settings_is_rejected() -> None:
    # Closes the torshammer.toml / TORSHAMMER_MODE bypass: argparse choices only
    # guard CLI flags, so the runtime guard in _resolve_config must catch a bogus
    # mode that arrived via layered settings.
    import argparse

    from torshammer.settings import _resolve_config

    args = argparse.Namespace(
        url="http://localhost",
        target=None,
        host=None,
        port=None,
        ssl=None,
        path=None,
        allowlist_file=None,
        allow_public_targets=False,
        concurrency=1,
        mode="not-a-real-mode",
        backend="python",
        post_length=4096,
        delay_min=0.1,
        delay_max=3.0,
        duration=0.0,
        connect_timeout=15.0,
        ssl_no_verify=False,
        max_errors=0,
        ramp_up=0,
        no_random_path=False,
        proxy=None,
        proxy_env=None,
        proxy_list=None,
        tor=False,
        rotate_proxies=False,
        user_agents=None,
        header=None,
        header_file=None,
        body_file=None,
        fail_under=0,
        fail_on_zero=False,
        stats_interval=1.0,
        json_output=False,
        quiet=False,
        verbose=0,
        method=None,
    )
    try:
        _resolve_config(args)
        raise AssertionError("expected unknown mode to be rejected")
    except ValueError as exc:
        assert "not-a-real-mode" in str(exc)


def test_docs_document_every_mode() -> None:
    doc = ATTACK_MODES_DOC.read_text(encoding="utf-8")
    missing = [mode for mode in _canonical_modes() if mode not in doc]
    assert not missing, f"modes missing from docs/attack-modes.md: {missing}"
