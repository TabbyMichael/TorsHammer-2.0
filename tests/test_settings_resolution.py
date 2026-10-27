"""Tests for :mod:`torshammer.settings`: CLI namespace to validated Config.

Covers the target-parsing rejections, the proxy environment fallback and its
credential redaction, and the ``--header-file`` reader - the resolution paths
that ``torshammer.toml`` / env injection can reach but the flag parser cannot.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from torshammer.cli import build_parser
from torshammer.settings import (
    _build_custom_headers,
    _build_proxies,
    _parse_custom_headers,
    _resolve_config,
)

# Proxy environment variables consulted by the fallback path; cleared for every
# test so a developer's shell configuration cannot leak into assertions.
_PROXY_ENV_VARS = (
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
)


@pytest.fixture(autouse=True)
def _clean_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _PROXY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def _args(**overrides: object) -> argparse.Namespace:
    """A parsed namespace for a loopback target with individual overrides."""
    args = build_parser().parse_args(["-u", "http://127.0.0.1"])
    for name, value in overrides.items():
        setattr(args, name, value)
    return args


def _proxy_ns(**overrides: object) -> argparse.Namespace:
    base: dict[str, object] = {
        "url": None,
        "target": None,
        "ssl": False,
        "proxy": None,
        "proxy_env": None,
        "proxy_list": None,
        "tor": False,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


# ---------------------------------------------------------------------------
# Header syntax
# ---------------------------------------------------------------------------


def test_header_with_empty_name_is_rejected() -> None:
    with pytest.raises(SystemExit, match="invalid header name"):
        _parse_custom_headers([": just-a-value"])


def test_crlf_in_value_is_rejected() -> None:
    with pytest.raises(SystemExit, match="CR/LF not allowed"):
        _parse_custom_headers(["X-Ok: a\r\nInjected: yes"])


# ---------------------------------------------------------------------------
# Target resolution rejections
# ---------------------------------------------------------------------------


def test_unsupported_url_scheme_exits() -> None:
    with pytest.raises(SystemExit, match="unsupported URL scheme"):
        _resolve_config(_args(url="ftp://127.0.0.1", allow_public_targets=True))


def test_url_without_hostname_exits() -> None:
    with pytest.raises(SystemExit, match="no hostname"):
        _resolve_config(_args(url="http://"))


def test_missing_target_exits() -> None:
    with pytest.raises(SystemExit, match="a target is required"):
        _resolve_config(_args(url=None, target=None, host=None))


def test_unreadable_allowlist_file_exits() -> None:
    with pytest.raises(SystemExit, match="cannot read allowlist file"):
        _resolve_config(_args(allowlist_file="/nonexistent/dir/allowlist.txt"))


def test_unreadable_proxy_list_exits() -> None:
    with pytest.raises(SystemExit, match="cannot read proxy list"):
        _resolve_config(_args(proxy_list="/nonexistent/dir/proxies.txt"))


def test_unknown_mode_from_layered_settings_is_rejected() -> None:
    """A bogus mode injected via env/TOML fails here, not as an engine KeyError."""
    with pytest.raises(ValueError, match="unknown attack mode"):
        _resolve_config(_args(mode="not-a-real-mode"))


# ---------------------------------------------------------------------------
# Legacy --host/--port/--ssl shape
# ---------------------------------------------------------------------------


def test_legacy_host_with_ssl_derives_https_default_port() -> None:
    config = _resolve_config(_args(url=None, target=None, host="10.0.0.5", ssl=True, port=None))
    assert config.host == "10.0.0.5"
    assert config.secure is True
    assert config.port == 443
    assert config.header_host == "10.0.0.5"


def test_legacy_host_plain_defaults_to_port_80() -> None:
    config = _resolve_config(_args(url=None, target=None, host="10.0.0.5", ssl=False, port=None))
    assert config.secure is False
    assert config.port == 80
    assert config.header_host == "10.0.0.5"


def test_legacy_host_with_explicit_port_kept_in_header() -> None:
    config = _resolve_config(_args(url=None, target=None, host="10.0.0.5", ssl=False, port=8080))
    assert config.port == 8080
    assert config.header_host == "10.0.0.5:8080"


def test_ipv6_host_is_bracketed_for_the_header() -> None:
    config = _resolve_config(_args(url=None, target=None, host="::1", ssl=False, port=8080))
    assert config.header_host == "[::1]:8080"


def test_url_port_wins_over_legacy_port_flag() -> None:
    config = _resolve_config(_args(url="http://127.0.0.1:8080", port=9999))
    assert config.port == 9999


def test_path_override_beats_url_path() -> None:
    config = _resolve_config(_args(url="http://127.0.0.1/original", path="/override"))
    assert config.path == "/override"


def test_query_string_is_preserved_in_path() -> None:
    config = _resolve_config(_args(url="http://127.0.0.1/a?b=c"))
    assert config.path == "/a?b=c"


# ---------------------------------------------------------------------------
# Proxy environment fallback
# ---------------------------------------------------------------------------


def test_proxy_env_none_when_nothing_configured() -> None:
    assert _build_proxies(_proxy_ns()) is None


def test_https_target_prefers_https_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://plain-proxy:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://secure-proxy:8080")
    proxies = _build_proxies(_proxy_ns(ssl=None, url="https://example.com"))
    assert proxies is not None
    assert [p.host for p in proxies] == ["secure-proxy"]


def test_proxy_scheme_inference_defaults_to_http(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://plain-proxy:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://secure-proxy:8080")
    # ssl=None and no URL at all: the fall-through assumes plain HTTP.
    proxies = _build_proxies(_proxy_ns(ssl=None, url=None, target=None))
    assert proxies is not None
    assert [p.host for p in proxies] == ["plain-proxy"]


def test_https_url_scheme_detected_from_target_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://secure-proxy:8080")
    proxies = _build_proxies(_proxy_ns(ssl=None, target="https://example.com"))
    assert proxies is not None
    assert [p.host for p in proxies] == ["secure-proxy"]


def test_explicit_ssl_flag_overrides_url_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://plain-proxy:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://secure-proxy:8080")
    proxies = _build_proxies(_proxy_ns(ssl=False, url="https://example.com"))
    assert proxies is not None
    assert [p.host for p in proxies] == ["plain-proxy"]


def test_all_proxy_applies_to_plain_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALL_PROXY", "socks5://any-proxy:1080")
    proxies = _build_proxies(_proxy_ns())
    assert proxies is not None
    assert proxies[0].host == "any-proxy" and proxies[0].port == 1080


def test_invalid_env_proxy_is_reported_with_credentials_redacted(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A broken env proxy warns without leaking its password."""
    monkeypatch.setenv("HTTP_PROXY", "socks5://user:sup3rs3cret@")
    assert _build_proxies(_proxy_ns()) is None
    err = capsys.readouterr().err
    assert "ignoring invalid proxy from environment" in err
    assert "sup3rs3cret" not in err
    assert "***" in err


def test_proxy_flag_and_env_and_tor_accumulate(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_PROXY", "http://env-proxy:8080")
    proxies = _build_proxies(
        _proxy_ns(proxy="socks5://flag-proxy:1080", proxy_env="MY_PROXY", tor=True)
    )
    assert proxies is not None
    # --tor is inserted first so circuits lead the list.
    assert [(p.scheme, p.host) for p in proxies] == [
        ("socks5", "127.0.0.1"),
        ("socks5", "flag-proxy"),
        ("http", "env-proxy"),
    ]


def test_proxy_list_comments_and_blank_lines_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "proxies.txt"
    path.write_text("# rotate me\n\n  \nsocks5://10.0.0.1:1080\nhttp://10.0.0.2:3128\n")
    proxies = _build_proxies(_proxy_ns(proxy_list=str(path)))
    assert proxies is not None
    assert [(p.host, p.port) for p in proxies] == [("10.0.0.1", 1080), ("10.0.0.2", 3128)]


# ---------------------------------------------------------------------------
# --header / --header-file
# ---------------------------------------------------------------------------


def test_header_file_is_parsed_ignoring_comments(tmp_path: Path) -> None:
    path = tmp_path / "headers.txt"
    path.write_text(
        "# sent on every request\n"
        "\n"
        "X-Test: one\n"
        "X-Multi:  spaced  value  \n"
        "# X-Skipped: nope\n"
        "X-Second: two\n",
        encoding="utf-8",
    )
    args = _args(header=None, header_file=str(path))
    headers = _build_custom_headers(args)
    assert headers == {"X-Test": "one", "X-Multi": "spaced  value", "X-Second": "two"}


def test_header_and_header_file_combine(tmp_path: Path) -> None:
    path = tmp_path / "headers.txt"
    path.write_text("From-File: yes\n", encoding="utf-8")
    args = _args(header=["From-Flag: yes"], header_file=str(path))
    assert _build_custom_headers(args) == {"From-Flag": "yes", "From-File": "yes"}


def test_file_last_wins_for_duplicate_names(tmp_path: Path) -> None:
    path = tmp_path / "headers.txt"
    path.write_text("X-Dup: from-file\n", encoding="utf-8")
    args = _args(header=["X-Dup: from-flag"], header_file=str(path))
    assert _build_custom_headers(args) == {"X-Dup": "from-file"}


def test_unreadable_header_file_exits() -> None:
    args = _args(header=None, header_file="/nonexistent/dir/headers.txt")
    with pytest.raises(SystemExit, match="cannot read header file"):
        _build_custom_headers(args)


def test_missing_body_file_exits() -> None:
    from torshammer.settings import _load_custom_body

    with pytest.raises(SystemExit, match="cannot read body file"):
        _load_custom_body("/nonexistent/dir/body.bin")
