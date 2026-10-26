"""Aggregate counters and helpers shared by the engine and profiles."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

# Best-effort scan of an HTTP response status line out of whatever peer bytes a
# profile happens to read. Deliberately tolerant of chunk boundaries: a status
# line that is split across reads simply is not tallied (advisory-only).
_STATUS_LINE = re.compile(rb"HTTP/\d(?:\.\d)?[ \t]+(\d{3})")


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

    # --- impact metering (advisory): what the target actually answered with ---
    responses: int = 0  # HTTP status lines observed in peer bytes
    status_2xx: int = 0
    status_3xx: int = 0
    status_4xx: int = 0
    status_5xx: int = 0
    status_other: int = 0
    resp_latency_count: int = 0  # number of response-latency samples
    resp_latency_total: float = 0.0  # sum of seconds request->response

    def record_response_bytes(self, data: bytes) -> None:
        """Account for ``data`` received from the peer and tally any status codes.

        Replaces the old bare ``bytes_received += len(data)`` so profile reads
        also feed the advisory impact verdict with server-error / latency signal.
        """
        self.bytes_received += len(data)
        for match in _STATUS_LINE.finditer(data):
            self.responses += 1
            self._tally_status(int(match.group(1)))

    def _tally_status(self, code: int) -> None:
        if 200 <= code < 300:
            self.status_2xx += 1
        elif 300 <= code < 400:
            self.status_3xx += 1
        elif 400 <= code < 500:
            self.status_4xx += 1
        elif 500 <= code < 600:
            self.status_5xx += 1
        else:
            self.status_other += 1

    def record_response_latency(self, seconds: float) -> None:
        """Record one request->response latency sample (ignored if negative)."""
        if seconds < 0:
            return
        self.resp_latency_count += 1
        self.resp_latency_total += seconds

    @property
    def mean_response_latency(self) -> float:
        if self.resp_latency_count <= 0:
            return 0.0
        return self.resp_latency_total / self.resp_latency_count


def _response_telemetry(stats: Stats) -> str:
    """Render an ``; ...`` telemetry suffix, or ``""`` when nothing was read."""
    if stats.responses == 0 and stats.resp_latency_count == 0:
        return ""
    parts: list[str] = []
    if stats.responses:
        parts.append(
            f"responses={stats.responses} "
            f"(2xx={stats.status_2xx} 3xx={stats.status_3xx} "
            f"4xx={stats.status_4xx} 5xx={stats.status_5xx})"
        )
    if stats.resp_latency_count:
        parts.append(f"mean_resp_latency={stats.mean_response_latency:.2f}s")
    return "; " + ", ".join(parts)


def classify_verdict(stats: Stats) -> tuple[str, str]:
    """Classify a run as an advisory mitigation verdict (never an exit code).

    Heuristic, documented limits: a high error/reset share suggests the
    target (or its WAF/timeouts) is shedding slow connections (MITIGATED);
    sustained open connections with completed slow cycles suggests workers
    stayed pinned (VULNERABLE); the target returning server errors (5xx) under
    load is direct evidence its backend is degrading (VULNERABLE); anything
    else is INCONCLUSIVE. Observed response status mix and mean response
    latency are appended to every reason as operator-facing impact telemetry.
    """
    total = stats.connections
    if total <= 0:
        return ("INCONCLUSIVE", "no connections opened; nothing to classify")
    error_share = stats.errors / total
    completed_share = stats.completed / total if total else 0.0
    telemetry = _response_telemetry(stats)
    if error_share >= 0.5:
        return (
            "LIKELY_MITIGATED",
            (
                f"{stats.errors}/{total} connections errored "
                "(target shed slow connections; check timeouts/WAF)" + telemetry
            ),
        )
    if stats.peak_active > 0 and completed_share >= 0.2:
        return (
            "LIKELY_VULNERABLE",
            (
                f"{stats.completed}/{total} slow cycles completed with "
                f"peak_active={stats.peak_active} (workers stayed pinned)" + telemetry
            ),
        )
    # No completed cycles, but the target is itself erroring under load: server
    # 5xx replies are concrete impact even when our connections never finish.
    if stats.status_5xx >= max(2, total // 10):
        return (
            "LIKELY_VULNERABLE",
            (
                f"{stats.status_5xx} server errors (5xx) returned under load "
                "(backend degrading while workers held open)" + telemetry
            ),
        )
    return (
        "INCONCLUSIVE",
        (
            f"errors={stats.errors} completed={stats.completed} "
            f"peak_active={stats.peak_active}; rerun longer for a clearer signal" + telemetry
        ),
    )
