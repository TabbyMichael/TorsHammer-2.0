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
    assert (Proxy.from_url("socks4://x.y:9999").scheme, Proxy.from_url("socks4://x.y:9999").port) == ("socks4", 9999)
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


def test_proxy_pool_removes_failed_proxy():
    proxies = [Proxy("socks5", "a", 1), Proxy("socks5", "b", 2)]
    pool = ProxyPool(proxies, rotate=False, max_failures=2)
    proxy = pool.next()
    assert proxy.host == "a"
    pool.report_failure(proxy)
    assert len(pool) == 2
    pool.report_failure(proxy)
    assert len(pool) == 1
    assert pool.next().host == "b"
