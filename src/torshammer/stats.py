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


def classify_verdict(stats: Stats) -> tuple[str, str]:
    """Classify a run as an advisory mitigation verdict (never an exit code).

    Heuristic, documented limits: a high error/reset share suggests the
    target (or its WAF/timeouts) is shedding slow connections (MITIGATED);
    sustained open connections with completed slow cycles suggests workers
    stayed pinned (VULNERABLE); anything else is INCONCLUSIVE.
    """
    total = stats.connections
    if total <= 0:
        return ("INCONCLUSIVE", "no connections opened; nothing to classify")
    error_share = stats.errors / total
    completed_share = stats.completed / total if total else 0.0
    if error_share >= 0.5:
        return (
            "LIKELY_MITIGATED",
            (
                f"{stats.errors}/{total} connections errored "
                "(target shed slow connections; check timeouts/WAF)"
            ),
        )
    if stats.peak_active > 0 and completed_share >= 0.2:
        return (
            "LIKELY_VULNERABLE",
            (
                f"{stats.completed}/{total} slow cycles completed with "
                f"peak_active={stats.peak_active} (workers stayed pinned)"
            ),
        )
    return (
        "INCONCLUSIVE",
        (
            f"errors={stats.errors} completed={stats.completed} "
            f"peak_active={stats.peak_active}; rerun longer for a clearer signal"
        ),
    )
