"""Runtime configuration model for the engine and attack profiles."""

from __future__ import annotations

import random
import ssl
from dataclasses import dataclass, field

from .proxies import Proxy


@dataclass
class Config:
    """Shared runtime configuration."""

    host: str
    port: int
    secure: bool = False
    path: str = "/"
    header_host: str = ""  # value of the Host: header (may include port)

    concurrency: int = 256
    mode: str = "slow-post"
    backend: str = "python"
    base_post_length: int = 4096  # baseline Content-Length for slow-post

    delay_min: float = 0.1
    delay_max: float = 3.0
    duration: float = 0.0  # seconds; 0 == unlimited
    connect_timeout: float = 15.0
    ssl_verify: bool = True
    max_errors: int = 0             # circuit breaker: exit after N consecutive errors
    ramp_up: int = 0               # stagger worker starts (N per second, 0 = immediate)

    proxies: list[Proxy] | None = None
    rotate_proxies: bool = False
    proxy_max_failures: int = 3
    allow_public_targets: bool = False
    allowed_targets: set[str] = field(default_factory=set)

    user_agents: list[str] = field(default_factory=list)
    custom_headers: dict[str, str] = field(default_factory=dict)
    custom_body: bytes | None = None  # Custom POST body content
    fail_under: int = 0  # Exit with error if peak active connections < N
    fail_on_zero: bool = False  # Exit with error if zero connections opened
    stats_interval: float = 1.0
    json_output: bool = False
    quiet: bool = False
    verbose: int = 0

    # Cached SSL context to avoid recreating for each connection
    _cached_ssl_context: ssl.SSLContext | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate configuration parameters after initialization."""
        # Validate timing parameters
        if self.stats_interval <= 0:
            raise ValueError("stats_interval must be greater than 0")
        if self.delay_min < 0:
            raise ValueError("delay_min must be non-negative")
        if self.delay_max < 0:
            raise ValueError("delay_max must be non-negative")
        if self.delay_max < self.delay_min:
            raise ValueError("delay_max must be greater than or equal to delay_min")

        # Validate concurrency
        if self.concurrency < 1:
            raise ValueError("concurrency must be at least 1")

        # Validate post length
        if self.base_post_length < 1:
            raise ValueError("base_post_length must be at least 1")

        # Validate timeout
        if self.connect_timeout <= 0:
            raise ValueError("connect_timeout must be greater than 0")

        # Validate duration
        if self.duration < 0:
            raise ValueError("duration must be non-negative")

        # Validate max_errors
        if self.max_errors < 0:
            raise ValueError("max_errors must be non-negative")

        # Validate ramp_up
        if self.ramp_up < 0:
            raise ValueError("ramp_up must be non-negative")

        # Validate fail_under
        if self.fail_under is not None and self.fail_under < 0:
            raise ValueError("fail_under must be non-negative")

    @property
    def server_hostname(self) -> str | None:
        """SNI host used for TLS; None for plain HTTP."""
        return self.host if self.secure else None

    def random_delay(self) -> float:
        lo = min(self.delay_min, self.delay_max)
        hi = max(self.delay_min, self.delay_max)
        return random.uniform(lo, hi)

    def validate(self) -> None:
        if self.concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if self.delay_min < 0 or self.delay_max < 0:
            raise ValueError("delay values must be non-negative")
        if self.delay_min > self.delay_max:
            raise ValueError("delay-min cannot be greater than delay-max")
        if self.duration < 0:
            raise ValueError("duration must be non-negative")
        if self.connect_timeout <= 0:
            raise ValueError("connect-timeout must be positive")
        if self.base_post_length < 1:
            raise ValueError("post-length must be at least 1")
        if self.proxy_max_failures < 1:
            raise ValueError("proxy-max-failures must be at least 1")
        if self.stats_interval <= 0:
            raise ValueError("stats-interval must be positive")

    def ssl_context(self) -> ssl.SSLContext | None:
        """Return a cached TLS context for HTTPS targets, else None."""
        if not self.secure:
            return None
        if self._cached_ssl_context is None:
            if self.ssl_verify:
                self._cached_ssl_context = ssl.create_default_context()
            else:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                self._cached_ssl_context = ctx
        return self._cached_ssl_context
