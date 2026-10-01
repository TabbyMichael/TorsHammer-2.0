"""Final summary and dry-run reporting (stdout/stderr contract)."""

from __future__ import annotations

import sys
import time

from .config import Config
from .stats import Stats, classify_verdict, human_size


def _print_summary(stats: Stats, json_output: bool = False) -> None:
    """Print the final summary.

    When ``json_output`` is set, the summary is written to stderr so it does
    not pollute the newline-delimited JSON stream on stdout. An advisory
    mitigation verdict (never an exit code) is included; see
    :func:`stats.classify_verdict` for heuristic limits.
    """
    stream = sys.stderr if json_output else sys.stdout
    uptime = time.monotonic() - stats.start
    verdict, reason = classify_verdict(stats)
    print(file=stream)
    print("  connections opened :", stats.connections, file=stream)
    print("  peak concurrent    :", stats.peak_active, file=stream)
    print("  completed cycles   :", stats.completed, file=stream)
    print("  errors             :", stats.errors, file=stream)
    print("  bytes sent         :", human_size(stats.bytes_sent), file=stream)
    print("  bytes received     :", human_size(stats.bytes_received), file=stream)
    print("  elapsed            :", f"{int(uptime // 60)}:{int(uptime % 60):02d}", file=stream)
    print(f"  verdict            : {verdict} — {reason}", file=stream)


def _print_dry_run(config: Config) -> None:
    """Print the resolved target/config without opening any connections."""
    from .profiles import PROFILES

    scheme = "udp" if config.mode == "udp" else ("https" if config.secure else "http")
    print("dry-run: no connections opened")
    print(f"  target     : {scheme}://{config.host}:{config.port}{config.path}")
    print(f"  backend    : {config.backend}")
    print(f"  mode       : {config.mode}")
    print(f"  method     : {config.method or '(profile default)'}")
    print(f"  concurrency: {config.concurrency}")
    print(f"  duration   : {config.duration}")
    print(f"  tls_verify : {config.ssl_verify} (SNI: {config.server_hostname or 'n/a'})")
    print(f"  proxies    : {len(config.proxies or [])}")
    print(f"  headers    : {len(config.custom_headers)} custom")
    if config.mode != "udp" and config.mode in PROFILES:
        print(f"  profile    : {PROFILES[config.mode].__name__}")
