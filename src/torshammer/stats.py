"""Aggregate counters and helpers shared by the engine and profiles."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


def human_size(n: float) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024:
            return f"{round(value, 1)} {unit}"
        value /= 1024.0
    return f"{round(value, 1)} TB"


@dataclass
class Stats:
    """Aggregate counters. Updated from the single event loop."""

    connections: int = 0
    active: int = 0
    peak_active: int = 0
    completed: int = 0
    errors: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    start: float = field(default_factory=time.monotonic)
    circuit_breaker: bool = False  # True if circuit breaker was triggered
