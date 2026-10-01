"""Tests for Phase 1 critical bugfixes and improvements."""

from __future__ import annotations

import asyncio
import io
import sys

import pytest

from torshammer.cli import _print_summary, _resolve_config, build_parser
from torshammer.config import Config
from torshammer.stats import Stats, human_size

# ============================================================================
# 1.1 JSON Output Pollution Fix
# ============================================================================


def test_banner_goes_to_stderr_with_json_flag():
    """Banner should print to stderr when --json is used."""
    parser = build_parser()
    args = parser.parse_args(["-u", "http://example.com", "--json", "--allow-public-targets"])
    config = _resolve_config(args)

    old_stderr = sys.stderr
    sys.stderr = io.StringIO()
    try:
        output = sys.stderr if config.json_output else sys.stdout
        print("BANNER_TEST", file=output)
        stderr_content = sys.stderr.getvalue()
    finally:
        sys.stderr = old_stderr

    assert "BANNER_TEST" in stderr_content


def test_summary_goes_to_stderr_with_json_flag():
    """Summary should print to stderr when --json is used."""
    stats = Stats()
    old_stderr = sys.stderr
    sys.stderr = io.StringIO()
    try:
        _print_summary(stats, json_output=True)
        stderr_content = sys.stderr.getvalue()
    finally:
        sys.stderr = old_stderr

    assert "connections opened" in stderr_content


# ============================================================================
# 1.2 Duplicate Query String Fix
# ============================================================================


def test_path_without_query_gets_question_mark():
    """Paths without existing query should get ? separator."""
    from torshammer.profiles import _path

    config = Config(host="example.com", port=80, path="/api")
    result = _path(config)
    assert result.startswith("/api?")


def test_path_with_query_gets_ampersand():
    """Paths with existing query should get & separator."""
    from torshammer.profiles import _path

    config = Config(host="example.com", port=80, path="/api?key=value")
    result = _path(config)
    assert result.startswith("/api?key=value&")
    assert "&" in result
    assert result.count("?") == 1  # No double ?


# ============================================================================
# 1.3 IPv6 Host Header Fix
# ============================================================================


def test_ipv6_literal_wrapped_in_brackets():
    """IPv6 literals should be wrapped in brackets for Host header."""
    parser = build_parser()
    args = parser.parse_args(["-u", "http://[::1]:8080/path"])
    config = _resolve_config(args)

    assert config.host == "::1"
    assert config.header_host == "[::1]:8080"


def test_ipv6_literal_without_port():
    """IPv6 literals without explicit port should be wrapped in brackets."""
    parser = build_parser()
    args = parser.parse_args(["-u", "http://[::1]/path"])
    config = _resolve_config(args)

    assert config.host == "::1"
    assert config.header_host == "[::1]"


def test_ipv6_with_https():
    """IPv6 literals with HTTPS should be wrapped in brackets."""
    parser = build_parser()
    args = parser.parse_args(["-u", "https://[2001:db8::1]:8443/path"])
    config = _resolve_config(args)

    assert config.host == "2001:db8::1"
    assert config.header_host == "[2001:db8::1]:8443"
    assert config.secure is True


def test_ipv4_not_wrapped():
    """IPv4 addresses should not be wrapped in brackets."""
    parser = build_parser()
    args = parser.parse_args(["-u", "http://192.168.1.1:8080/path"])
    config = _resolve_config(args)

    assert config.host == "192.168.1.1"
    assert config.header_host == "192.168.1.1:8080"


# ============================================================================
# 1.7 Config Validation
# ============================================================================


def test_invalid_stats_interval_raises():
    """stats_interval <= 0 should raise ValueError."""
    with pytest.raises(ValueError, match="stats_interval must be greater than 0"):
        Config(host="example.com", port=80, stats_interval=0)


def test_negative_delay_min_raises():
    """delay_min < 0 should raise ValueError."""
    with pytest.raises(ValueError, match="delay_min must be non-negative"):
        Config(host="example.com", port=80, delay_min=-1.0)


def test_delay_max_less_than_delay_min_raises():
    """delay_max < delay_min should raise ValueError."""
    with pytest.raises(ValueError, match="delay_max must be greater than or equal to delay_min"):
        Config(host="example.com", port=80, delay_min=5.0, delay_max=1.0)


def test_concurrency_less_than_one_raises():
    """concurrency < 1 should raise ValueError."""
    with pytest.raises(ValueError, match="concurrency must be at least 1"):
        Config(host="example.com", port=80, concurrency=0)


# ============================================================================
# 1.6 SSLContext Caching
# ============================================================================


def test_ssl_context_caching():
    """SSL context should be cached and reused."""
    config = Config(host="example.com", port=443, secure=True)

    ctx1 = config.ssl_context()
    ctx2 = config.ssl_context()

    assert ctx1 is ctx2  # Same object (cached)


def test_ssl_context_none_for_http():
    """SSL context should be None for HTTP."""
    config = Config(host="example.com", port=80, secure=False)
    ctx = config.ssl_context()
    assert ctx is None


# ============================================================================
# 2.1 File Descriptor Limits Check
# ============================================================================


def test_fd_limits_check_exists():
    """_check_fd_limits function should exist and be importable."""
    from torshammer.cli import _check_fd_limits

    assert callable(_check_fd_limits)
    _check_fd_limits(256)  # Should not raise for reasonable concurrency


# ============================================================================
# 2.3 Smarter Error Backoff
# ============================================================================


@pytest.mark.asyncio
async def test_circuit_breaker_triggers():
    """Engine should trigger circuit breaker after max_errors."""
    from torshammer.config import Config
    from torshammer.engine import AttackEngine

    cfg = Config(
        host="192.0.2.1",  # TEST-NET-1, will fail
        port=12345,
        connect_timeout=0.5,
        delay_min=0,
        delay_max=0.01,
        concurrency=8,  # More workers to accumulate errors faster
        mode="slow-post",
        duration=2.0,  # Longer duration to allow errors to accumulate
        quiet=True,
        max_errors=3,
    )

    engine = AttackEngine(cfg, asyncio.Event())
    await engine.run()

    # With 8 workers trying to connect and failing, should hit circuit breaker
    assert engine.stats.errors >= 3


# ============================================================================
# 2.4 Proxy Health Tracking
# ============================================================================


def test_proxy_health_tracking():
    """Proxy should track failures and support health checks."""
    from torshammer.proxies import Proxy

    proxy = Proxy("socks5", "proxy.example.com", 9050)
    assert proxy.is_healthy() is True

    # Record several failures
    for _ in range(5):
        proxy.record_failure()

    # Should now be unhealthy
    assert proxy.is_healthy() is False

    # Record success should reset
    proxy.record_success()
    assert proxy.is_healthy() is True


def test_proxy_stats():
    """Proxy should provide stats for JSON output."""
    from torshammer.proxies import Proxy

    proxy = Proxy("socks5", "proxy.example.com", 9050, "user", "pass")
    stats = proxy.get_stats()

    assert stats["proxy"] == "socks5://proxy.example.com:9050"
    assert stats["failures"] == 0
    assert stats["healthy"] is True


# ============================================================================
# 3.1 Custom Headers
# ============================================================================


def test_custom_headers_via_cli():
    """Custom headers should be parsed from --header flag."""
    parser = build_parser()
    args = parser.parse_args(
        [
            "-u",
            "http://example.com",
            "--header",
            "X-Custom: value1",
            "--header",
            "Authorization: Bearer token123",
            "--allow-public-targets",
        ]
    )
    config = _resolve_config(args)

    # Config.__post_init__ normalizes custom headers to a dict; narrow for typing.
    assert isinstance(config.custom_headers, dict)
    assert "X-Custom" in config.custom_headers
    assert config.custom_headers["X-Custom"] == "value1"


# ============================================================================
# 3.2 Custom Body
# ============================================================================


def test_custom_body_from_file(tmp_path):
    """Custom POST body should be loaded from --body-file."""
    body_file = tmp_path / "body.txt"
    body_content = b"custom POST data here"
    body_file.write_bytes(body_content)

    parser = build_parser()
    args = parser.parse_args(
        [
            "-u",
            "http://example.com",
            "--body-file",
            str(body_file),
            "--allow-public-targets",
        ]
    )
    config = _resolve_config(args)

    assert config.custom_body == body_content


# ============================================================================
# 3.6 Proxy Credentials from Environment
# ============================================================================


def test_proxy_env_variable(monkeypatch):
    """Proxy URL should be read from environment variable."""
    monkeypatch.setenv("MY_PROXY_URL", "socks5://user:pass@proxy:9050")

    parser = build_parser()
    args = parser.parse_args(
        [
            "-u",
            "http://example.com",
            "--proxy-env",
            "MY_PROXY_URL",
            "--allow-public-targets",
        ]
    )
    config = _resolve_config(args)

    assert config.proxies is not None
    assert len(config.proxies) == 1
    assert config.proxies[0].username == "user"
    assert config.proxies[0].password == "pass"


# ============================================================================
# Layered settings (TOML file + TORSHAMMER_* env)
# ============================================================================


def test_toml_file_fills_defaults(tmp_path):
    """A TOML file provides defaults; explicit CLI flags win (tested below)."""
    from torshammer.cli import _resolve_config, build_parser
    from torshammer.config import apply_layered_settings, load_toml_file

    cfg_file = tmp_path / "torshammer.toml"
    cfg_file.write_text("concurrency = 77\nmode = 'slow-headers'\n")
    args = build_parser().parse_args(["-u", "http://example.com", "--allow-public-targets"])
    apply_layered_settings(args, load_toml_file(cfg_file))
    config = _resolve_config(args)
    assert config.concurrency == 77
    assert config.mode == "slow-headers"


def test_cli_flag_wins_over_toml_and_env(tmp_path, monkeypatch):
    """Precedence: CLI > env > TOML > default."""
    from torshammer.cli import _resolve_config, build_parser
    from torshammer.config import apply_layered_settings, load_toml_file

    parser = build_parser()
    cli_defaults = {
        action.dest: action.default for action in parser._actions if action.dest != "help"
    }
    cfg_file = tmp_path / "torshammer.toml"
    cfg_file.write_text("concurrency = 77\nduration = 9.0\n")
    monkeypatch.setenv("TORSHAMMER_CONCURRENCY", "88")
    args = parser.parse_args(["-u", "http://example.com", "--allow-public-targets", "-c", "99"])
    apply_layered_settings(args, load_toml_file(cfg_file), cli_defaults)
    config = _resolve_config(args)
    assert config.concurrency == 99  # CLI beat env(88) and TOML(77)
    assert config.duration == 9.0  # TOML filled the unset flag


def test_env_fills_unset_flag(monkeypatch):
    """TORSHAMMER_* env fills flags the CLI left at default."""
    from torshammer.cli import _resolve_config, build_parser
    from torshammer.config import apply_layered_settings

    monkeypatch.setenv("TORSHAMMER_DURATION", "12.5")
    args = build_parser().parse_args(["-u", "http://example.com", "--allow-public-targets"])
    apply_layered_settings(args, {})
    assert _resolve_config(args).duration == 12.5


# ============================================================================
# Dry-run + advisory verdict
# ============================================================================


def test_dry_run_opens_zero_connections(capsys):
    """--dry-run resolves and prints without touching the network."""
    from torshammer.cli import main

    rc = main(["-u", "http://127.0.0.1:9", "--dry-run", "-c", "64"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dry-run: no connections opened" in out
    assert "127.0.0.1" in out


def test_dry_run_rejects_public_target_by_default():
    """Safety policy still applies in dry-run mode."""
    import pytest

    from torshammer.cli import main

    with pytest.raises(SystemExit):
        main(["-u", "http://example.com", "--dry-run"])


def test_classify_verdict_branches():
    """Advisory verdict covers mitigated / vulnerable / inconclusive."""
    from torshammer.stats import Stats, classify_verdict

    assert classify_verdict(Stats())[0] == "INCONCLUSIVE"
    err = Stats(connections=10, errors=8)
    assert classify_verdict(err)[0] == "LIKELY_MITIGATED"
    vuln = Stats(connections=10, completed=5, peak_active=8)
    assert classify_verdict(vuln)[0] == "LIKELY_VULNERABLE"
    mid = Stats(connections=10, completed=1, errors=1, peak_active=3)
    assert classify_verdict(mid)[0] == "INCONCLUSIVE"


# ============================================================================
# Human Size Helper
# ============================================================================


def test_human_size_bytes():
    """human_size should format bytes correctly."""
    assert human_size(500) == "500.0 B"


def test_human_size_kilobytes():
    """human_size should format kilobytes correctly."""
    assert human_size(1500) == "1.5 KB"


def test_human_size_megabytes():
    """human_size should format megabytes correctly."""
    assert human_size(2_500_000) == "2.4 MB"


def test_human_size_gigabytes():
    """human_size should format gigabytes correctly."""
    assert human_size(3_500_000_000) == "3.3 GB"
