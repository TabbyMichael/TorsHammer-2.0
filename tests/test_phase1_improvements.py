"""Tests for Phase 1 critical bugfixes and improvements."""

from __future__ import annotations

import asyncio
import io
import sys

import pytest

from torshammer.cli import _resolve_config, _print_summary, build_parser
from torshammer.config import Config
from torshammer.stats import Stats, human_size


# ============================================================================
# 1.1 JSON Output Pollution Fix
# ============================================================================


def test_banner_goes_to_stderr_with_json_flag():
    """Banner should print to stderr when --json is used."""
    parser = build_parser()
    args = parser.parse_args(["-u", "http://example.com", "--json"])
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
    args = parser.parse_args([
        "-u", "http://example.com",
        "--header", "X-Custom: value1",
        "--header", "Authorization: Bearer token123"
    ])
    config = _resolve_config(args)
    
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
    args = parser.parse_args([
        "-u", "http://example.com",
        "--body-file", str(body_file)
    ])
    config = _resolve_config(args)
    
    assert config.custom_body == body_content


# ============================================================================
# 3.6 Proxy Credentials from Environment
# ============================================================================


def test_proxy_env_variable(monkeypatch):
    """Proxy URL should be read from environment variable."""
    monkeypatch.setenv("MY_PROXY_URL", "socks5://user:pass@proxy:9050")
    
    parser = build_parser()
    args = parser.parse_args([
        "-u", "http://example.com",
        "--proxy-env", "MY_PROXY_URL"
    ])
    config = _resolve_config(args)
    
    assert config.proxies is not None
    assert len(config.proxies) == 1
    assert config.proxies[0].username == "user"
    assert config.proxies[0].password == "pass"


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
