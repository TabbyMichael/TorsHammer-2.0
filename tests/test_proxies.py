"""Tests for proxy parsing and rotation."""

from __future__ import annotations

import pytest

from torshammer.proxies import Proxy, ProxyPool


def test_parse_socks5_with_credentials():
    proxy = Proxy.from_url("socks5://user:pa:ss@1.2.3.4:9050")
    assert proxy.scheme == "socks5"
    assert proxy.host == "1.2.3.4"
    assert proxy.port == 9050
    assert proxy.username == "user"
    assert proxy.password == "pa:ss"


def test_parse_default_scheme_and_port():
    proxy = Proxy.from_url("127.0.0.1:9050")
    assert (proxy.scheme, proxy.host, proxy.port) == ("socks5", "127.0.0.1", 9050)


def test_parse_socks4_and_http_defaults():
    assert (
        Proxy.from_url("socks4://x.y:9999").scheme,
        Proxy.from_url("socks4://x.y:9999").port,
    ) == ("socks4", 9999)
    http = Proxy.from_url("http://proxy.local")
    assert (http.scheme, http.port) == ("http", 8080)


def test_parse_https_is_treated_as_connect():
    assert Proxy.from_url("https://p:8443").scheme == "http"


def test_invalid_scheme_rejected():
    with pytest.raises(ValueError):
        Proxy.from_url("gopher://host:1")


def test_pool_round_robin():
    proxies = [Proxy("socks5", "a", 1), Proxy("socks5", "b", 2), Proxy("socks5", "c", 3)]
    pool = ProxyPool(proxies, rotate=False)
    assert pool.next().host == "a"
    assert pool.next().host == "b"
    assert pool.next().host == "c"
    assert pool.next().host == "a"


def test_pool_empty_returns_none():
    assert ProxyPool([]).next() is None


def test_unhealthy_proxy_is_skipped_until_recovery():
    """Deprioritized proxies stay in the pool and recover after cooldown.

    Tests the unified health model: a proxy that exceeds failure_threshold is
    skipped in favour of healthy proxies, but is NEVER removed (so it can recover
    after recovery_time seconds).  We inject tiny thresholds so the test runs fast.
    """
    a = Proxy("socks5", "a", 1, failure_threshold=2, recovery_time=0.05)
    b = Proxy("socks5", "b", 2, failure_threshold=2, recovery_time=0.05)
    pool = ProxyPool([a, b], rotate=False)

    # Both healthy initially — pool size unchanged throughout
    assert len(pool) == 2
    assert pool.next().host == "a"

    # Exhaust proxy a's threshold
    pool.record_failure(a)
    pool.record_failure(a)
    assert not a.is_healthy()

    # Pool should prefer b while a is deprioritized
    assert pool.next().host == "b"
    assert pool.next().host == "b"

    # Pool still contains both (no removal)
    assert len(pool) == 2

    # After the recovery window, a should be healthy again
    import time

    time.sleep(0.06)  # > recovery_time=0.05
    assert a.is_healthy()
    # Round-robin should now include a again
    seen = {pool.next().host for _ in range(4)}
    assert "a" in seen


def test_round_robin_does_not_hang():
    """next() with healthy proxies in round-robin must return promptly — regression
    guard against the former len(list(infinite_cycle)) hang."""
    proxies = [Proxy("socks5", str(i), i) for i in range(5)]
    pool = ProxyPool(proxies, rotate=False)
    # Call next() many times quickly; if this hangs the test suite will time out
    results = [pool.next().host for _ in range(15)]
    assert results[:5] == [str(i) for i in range(5)]
    assert results[5:10] == results[:5]  # second cycle
