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

    proxies: list[Proxy] | None = None
    rotate_proxies: bool = False
    proxy_max_failures: int = 3
    allow_public_targets: bool = False
    allowed_targets: set[str] = field(default_factory=set)

    user_agents: list[str] = field(default_factory=list)
    custom_headers: list[str] = field(default_factory=list)
    method: str | None = None
    randomize_path: bool = True
    seed: int | None = None

    stats_interval: float = 1.0
    json_output: bool = False
    quiet: bool = False
    verbose: int = 0

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
        """Return a TLS context for HTTPS targets, else None."""
        if not self.secure:
            return None
        if self.ssl_verify:
            return ssl.create_default_context()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
