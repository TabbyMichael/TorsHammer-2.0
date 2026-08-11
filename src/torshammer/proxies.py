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

    scheme: str            # socks5 | socks4 | http
    host: str
    port: int
    username: str | None = None
    password: str | None = None
    # Health tracking fields
    failures: int = field(default=0, init=False, repr=False)
    last_failure: float = field(default=0.0, init=False, repr=False)
    last_success: float = field(default=0.0, init=False, repr=False)

    FAILURE_THRESHOLD = 5  # Temporarily deprioritize after N failures
    RECOVERY_TIME = 300.0  # 5 minutes before considering recovery

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
        if self.failures < self.FAILURE_THRESHOLD:
            return True
        # Allow recovery after cooldown period
        return (time.monotonic() - self.last_failure) > self.RECOVERY_TIME

    def get_stats(self) -> dict:
        """Get proxy statistics for JSON output."""
        return {
            "proxy": str(self),
            "failures": self.failures,
            "last_success": self.last_success,
            "last_failure": self.last_failure,
            "healthy": self.is_healthy()
        }

    @classmethod
    def from_url(cls, url: str) -> "Proxy":
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
    returned round-robin. Unhealthy proxies are temporarily deprioritized.
    """

    def __init__(self, proxies: list[Proxy] | None, rotate: bool = False):
        self._proxies = proxies or []
        self._cycle = itertools.cycle(self._proxies)
        self._rotate = rotate

    def next(self) -> Proxy | None:
        if not self._proxies:
            return None

        # Get healthy proxies
        healthy_proxies = [p for p in self._proxies if p.is_healthy()]

        # If no healthy proxies, fall back to all proxies
        available = healthy_proxies if healthy_proxies else self._proxies

        if self._rotate and len(available) > 1:
            return random.choice(available)

        # For round-robin, cycle through healthy proxies first
        if healthy_proxies:
            # Reset cycle to healthy proxies if it was set to all
            if not hasattr(self, '_healthy_cycle') or len(list(self._healthy_cycle)) != len(healthy_proxies):
                self._healthy_cycle = itertools.cycle(healthy_proxies)
            return next(self._healthy_cycle)
        else:
            return next(self._cycle)

    def record_success(self, proxy: Proxy) -> None:
        """Record successful connection through proxy."""
        proxy.record_success()

    def record_failure(self, proxy: Proxy) -> None:
        """Record failed connection through proxy."""
        proxy.record_failure()

    def get_all_stats(self) -> list[dict]:
        """Get statistics for all proxies."""
        return [p.get_stats() for p in self._proxies]

    def __len__(self) -> int:
        return len(self._proxies)
