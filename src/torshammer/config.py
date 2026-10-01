"""Runtime configuration model for the engine and attack profiles."""

from __future__ import annotations

import os
import random
import ssl
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

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
    method: str | None = None  # Override HTTP method per profile (None = profile default)
    backend: str = "python"
    base_post_length: int = 4096  # baseline Content-Length for slow-post
    randomize_path: bool = True  # Append a random token to every request path

    delay_min: float = 0.1
    delay_max: float = 3.0
    duration: float = 0.0  # seconds; 0 == unlimited
    connect_timeout: float = 15.0
    ssl_verify: bool = True
    max_errors: int = 0  # circuit breaker: exit after N consecutive errors
    ramp_up: int = 0  # stagger worker starts (N per second, 0 = immediate)

    proxies: list[Proxy] | None = None
    rotate_proxies: bool = False
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
    _cached_ssl_context: ssl.SSLContext | None = field(
        default=None, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        """Validate configuration parameters after initialization."""
        # Defensive runtime tolerance for legacy callers passing None
        # (type is dict[str, str]; untyped call sites may still pass None).
        if getattr(self, "custom_headers", None) is None:  # pyright: ignore[reportUnnecessaryComparison]
            self.custom_headers = {}

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
        if self.fail_under < 0:
            raise ValueError("fail_under must be non-negative")

    @property
    def server_hostname(self) -> str | None:
        """SNI host used for TLS; None for plain HTTP."""
        return self.host if self.secure else None

    def random_delay(self) -> float:
        lo = min(self.delay_min, self.delay_max)
        hi = max(self.delay_min, self.delay_max)
        return random.uniform(lo, hi)

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


# ---------------------------------------------------------------------------
# Layered settings: CLI > TORSHAMMER_* env > torshammer.toml file > defaults.
# TOML-only on purpose (stdlib tomllib, zero runtime dependencies).
# ---------------------------------------------------------------------------

# CLI flag name -> (TOML key, value kind); env var is TORSHAMMER_<UPPER NAME>.
_SETTINGS_MAP: tuple[tuple[str, str], ...] = (
    ("concurrency", "int"),
    ("mode", "str"),
    ("delay_min", "float"),
    ("delay_max", "float"),
    ("duration", "float"),
    ("connect_timeout", "float"),
    ("post_length", "int"),
    ("stats_interval", "float"),
    ("max_errors", "int"),
    ("ramp_up", "int"),
    ("fail_under", "int"),
)

_BOOL_FLAGS: tuple[str, ...] = (
    "ssl_no_verify",  # inverted -> Config.ssl_verify
    "no_random_path",
    "rotate_proxies",
    "json_output",
    "quiet",
    "fail_on_zero",
    "allow_public_targets",
)


def _coerce(kind: str, raw: str) -> int | float | str:
    if kind == "int":
        return int(raw)
    if kind == "float":
        return float(raw)
    return raw


def load_toml_file(path: str | Path | None) -> dict[str, object]:
    """Load a ``torshammer.toml`` file (empty dict when absent/unreadable)."""
    if path is None:
        for candidate in ("torshammer.toml", "pyproject.toml"):
            if Path(candidate).is_file():
                path = candidate
                break
    if path is None:
        return {}
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    if str(path).endswith("pyproject.toml"):
        tool = data.get("tool")
        if isinstance(tool, dict):
            section = tool.get("torshammer")
            return section if isinstance(section, dict) else {}
        return {}
    return data if isinstance(data, dict) else {}


def apply_layered_settings(
    args: object,
    file_data: dict[str, object] | None = None,
    defaults: dict[str, object] | None = None,
) -> None:
    """Fill unset CLI defaults from env, then TOML file (mutates ``args``).

    Precedence: explicit CLI flag > ``TORSHAMMER_*`` env > TOML table >
    argparse default. ``defaults`` maps flag name -> argparse default so an
    explicitly-passed flag (value != default) is never overwritten; when
    omitted, scalar current values are compared against the file value only
    via env-first ordering and a CLI-sentinel cannot be derived. Callers that
    need strict CLI-wins (``cli.main``) pass the parser defaults; tests may
    pass ``{}`` for env/TOML-fill semantics.
    """
    data = file_data if file_data is not None else load_toml_file(None)

    for cli_name, kind in _SETTINGS_MAP:
        _apply_scalar(args, cli_name, kind, data, defaults)
    for cli_name in _BOOL_FLAGS:
        _apply_bool(args, cli_name, data)


def _was_explicit(args: object, name: str, defaults: dict[str, object] | None) -> bool:
    if defaults is None or name not in defaults:
        return False
    return getattr(args, name, None) != defaults.get(name)


def _apply_scalar(
    args: object,
    name: str,
    kind: str,
    data: dict[str, object],
    defaults: dict[str, object] | None = None,
) -> None:
    if _was_explicit(args, name, defaults):
        return  # explicit CLI flag always wins
    env_val = os.environ.get(f"TORSHAMMER_{name.upper()}")
    if env_val is not None:
        try:
            setattr(args, name, _coerce(kind, env_val))
            return
        except (ValueError, TypeError):
            pass
    if name in data and isinstance(data[name], (int, float, str)):
        try:
            setattr(args, name, _coerce(kind, str(data[name])))
        except (ValueError, TypeError):
            pass


def _apply_bool(args: object, name: str, data: dict[str, object]) -> None:
    if getattr(args, name, False):
        return  # explicit CLI flag wins
    env_val = os.environ.get(f"TORSHAMMER_{name.upper()}")
    if env_val is not None and env_val.strip().lower() in {"1", "true", "yes", "on"}:
        setattr(args, name, True)
        return
    if data.get(name) is True:
        setattr(args, name, True)
