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
    header_host: str = ""            # value of the Host: header (may include port)

    concurrency: int = 256
    mode: str = "slow-post"
    base_post_length: int = 4096     # baseline Content-Length for slow-post

    delay_min: float = 0.1
    delay_max: float = 3.0
    duration: float = 0.0            # seconds; 0 == unlimited
    connect_timeout: float = 15.0
    ssl_verify: bool = True

    proxies: list[Proxy] | None = None
    rotate_proxies: bool = False

    user_agents: list[str] = field(default_factory=list)
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
