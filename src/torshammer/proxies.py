"""Proxy parsing and rotation.

Only pure-Python, fully async proxies are supported so the tool stays a
zero-dependency, single-file-per-module utility.  ``ProxyPool`` hands out
either a round-robin or a random proxy for every new connection.
"""

from __future__ import annotations

import itertools
import random
import time
from dataclasses import dataclass, field
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
    # Health tuning (instance-level so tests and callers can inject values).
    failure_threshold: int = 5  # temporarily deprioritize after N consecutive failures
    recovery_time: float = 300.0  # seconds to wait before considering a proxy recovered
    # Health tracking fields
    failures: int = field(default=0, init=False, repr=False)
    last_failure: float = field(default=0.0, init=False, repr=False)
    last_success: float = field(default=0.0, init=False, repr=False)

    def record_success(self) -> None:
        """Record a successful connection through this proxy."""
        self.failures = 0
        self.last_success = time.monotonic()

    def record_failure(self) -> None:
        """Record a failed connection through this proxy."""
        self.failures += 1
        self.last_failure = time.monotonic()

    def is_healthy(self) -> bool:
        """Check if proxy is considered healthy (not temporarily deprioritized)."""
        if self.failures < self.failure_threshold:
            return True
        # Allow recovery after cooldown period
        return (time.monotonic() - self.last_failure) > self.recovery_time

    def get_stats(self) -> dict:
        """Get proxy statistics for JSON output."""
        return {
            "proxy": str(self),
            "failures": self.failures,
            "last_success": self.last_success,
            "last_failure": self.last_failure,
            "healthy": self.is_healthy(),
        }

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
    returned round-robin. Unhealthy proxies are temporarily deprioritized;
    they are never removed so they can recover after their cooldown period.
    """

    def __init__(self, proxies: list[Proxy] | None, rotate: bool = False):
        self._proxies = proxies or []
        self._rotate = rotate
        self._cycle: itertools.cycle | None = None
        # The set of proxies the current round-robin cycle was built from
        # (stable object-identity key), so we rebuild the cycle only when the
        # healthy pool actually changes membership.
        self._cycle_key: tuple[int, ...] | None = None

    def next(self) -> Proxy | None:
        if not self._proxies:
            return None

        healthy = [p for p in self._proxies if p.is_healthy()]
        # Prefer healthy proxies; fall back to all so a fully-deprioritized
        # pool keeps retrying (rather than starving the attack).
        available = healthy if healthy else self._proxies

        if self._rotate:
            return random.choice(available) if available else None

        key = tuple(id(p) for p in available)
        if self._cycle is None or self._cycle_key != key:
            self._cycle = itertools.cycle(available) if available else None
            self._cycle_key = key
        return next(self._cycle) if self._cycle else None

    def record_success(self, proxy: Proxy) -> None:
        """Record successful connection through proxy."""
        proxy.record_success()

    def record_failure(self, proxy: Proxy) -> None:
        """Record failed connection through proxy (deprioritize, don't remove)."""
        proxy.record_failure()

    def get_all_stats(self) -> list[dict]:
        """Get statistics for all proxies."""
        return [p.get_stats() for p in self._proxies]

    def __len__(self) -> int:
        return len(self._proxies)
