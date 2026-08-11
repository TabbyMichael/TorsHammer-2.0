"""Proxy parsing and rotation.

Only pure-Python, fully async proxies are supported so the tool stays a
zero-dependency, single-file-per-module utility.  ``ProxyPool`` hands out
either a round-robin or a random proxy for every new connection.
"""

from __future__ import annotations

import itertools
import random
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

_SUPPORTED = {"socks5", "socks4", "http", "https"}
_DEFAULT_PORTS = {"socks5": 1080, "socks4": 1080, "http": 8080}


@dataclass
class Proxy:
    """A single configured proxy endpoint."""

    scheme: str  # socks5 | socks4 | http
    host: str
    port: int
    username: str | None = None
    password: str | None = None

    @classmethod
    def from_url(cls, url: str) -> Proxy:
        """Build a Proxy from a URL such as ``socks5://user:pass@host:port``.

        ``socks5://127.0.0.1:9050`` (Tor's default) is the common case.
        """
        if "://" not in url:
            url = "socks5://" + url
        parsed = urlparse(url)
        scheme = (parsed.scheme or "socks5").lower()
        if scheme not in _SUPPORTED:
            raise ValueError(f"unsupported proxy scheme: {parsed.scheme!r}")
        # An HTTPS forward proxy still speaks HTTP CONNECT for tunnelling.
        if scheme == "https":
            scheme = "http"
        host = parsed.hostname or ""
        if not host:
            raise ValueError(f"proxy URL has no host: {url!r}")
        port = parsed.port or _DEFAULT_PORTS[scheme]
        username = password = None
        if parsed.username:
            username = unquote(parsed.username)
            password = unquote(parsed.password) if parsed.password else ""
        return cls(scheme, host, port, username, password)

    def __str__(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


class ProxyPool:
    """Hands out proxies for each connection.

    ``rotate`` selects a random proxy per connection (useful to spread
    connections across Tor circuits / a proxy list); otherwise proxies are
    returned round-robin.
    """

    def __init__(self, proxies: list[Proxy] | None, rotate: bool = False, max_failures: int = 3):
        self._proxies = proxies or []
        self._failures = [0] * len(self._proxies)
        self._cycle = itertools.cycle(self._proxies) if self._proxies else None
        self._rotate = rotate
        self._max_failures = max_failures

    def _reset_cycle(self) -> None:
        self._cycle = itertools.cycle(self._proxies) if self._proxies else None

    def next(self) -> Proxy | None:
        if not self._proxies:
            return None
        if self._rotate and len(self._proxies) > 1:
            return random.choice(self._proxies)
        if self._cycle is None:
            self._reset_cycle()
        assert self._cycle is not None
        return next(self._cycle)

    def report_failure(self, proxy: Proxy) -> None:
        try:
            idx = self._proxies.index(proxy)
        except ValueError:
            return
        self._failures[idx] += 1
        if self._failures[idx] >= self._max_failures:
            del self._proxies[idx]
            del self._failures[idx]
            self._reset_cycle()

    def __len__(self) -> int:
        return len(self._proxies)
