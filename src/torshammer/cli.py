"""Command line interface and orchestration.

The banner, argument parser, orchestration loop and process entry point live
here; target policy, CLI-to-Config resolution, Rust dispatch and reporting are
implemented in :mod:`torshammer.target`, :mod:`torshammer.settings`,
:mod:`torshammer.dispatch` and :mod:`torshammer.summary` and re-exported below
so existing ``from torshammer.cli import ...`` imports keep working.
"""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys
from importlib import resources
from typing import Final

try:
    import resource
except ImportError:  # Windows / platforms without POSIX resource module
    resource = None  # type: ignore[assignment]

HAS_RESOURCE = resource is not None and hasattr(resource, "RLIMIT_NOFILE")

from . import __version__
from .config import Config
from .engine import AttackEngine
from .profiles import PROFILES


def _load_banner() -> str:
    """Load the shared ASCII banner shipped as package data.

    Falls back to a compact banner when the packaged resource cannot be read.
    Both templates use the same placeholders, so the substitution performed by
    :func:`main` works whichever one is in play.
    """
    try:
        return (resources.files("torshammer") / "banner.txt").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return (
            "  TorsHammer {VER} - slow-requests DoS/Vulnerability testing tool\n\n"
            "Target  : {TARGET}\n"
            "Backend : {BACKEND}\n"
            "Mode    : {MODE}\n"
            "Conns   : {CONCURRENCY}\n\n"
        )


BANNER: Final[str] = _load_banner()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="torshammer",
        description=f"Tor's Hammer {__version__} - slow-requests DoS/Vulnerability testing tool.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    target = parser.add_argument_group("target")
    target.add_argument("-u", "--url", help="Target URL, e.g. https://example.com/api/")
    target.add_argument("-t", "--target", dest="target", help="Alias for --url (legacy flag)")
    target.add_argument("--host", help="Target hostname/IP (alternative to --url)")
    target.add_argument("-p", "--port", type=int, help="Remote port (default 80 or 443)")
    target.add_argument("--ssl", action="store_true", help="Use TLS (implied by an https:// URL)")
    target.add_argument(
        "--ssl-no-verify", action="store_true", help="Do not verify TLS certificates"
    )
    target.add_argument(
        "--backend",
        choices=["python", "rust"],
        default="python",
        help=(
            "Select the runtime backend. 'python' is the reference asyncio engine "
            "(full flag support). 'rust' execs the high-performance backend and "
            "only supports the mapped flags; incompatible flags "
            "(proxies/Tor, TLS verify bypass, HTTPS targets) exit non-zero "
            "instead of being silently ignored."
        ),
    )
    target.add_argument(
        "--allow-public-targets",
        action="store_true",
        help="Allow public internet targets; by default only loopback/private targets are permitted.",
    )
    target.add_argument(
        "--allowlist-file",
        metavar="FILE",
        help="File with one hostname/IP per line that is allowed to be targeted.",
    )

    attack = parser.add_argument_group("attack")
    attack.add_argument("-m", "--mode", choices=sorted(PROFILES) + ["udp"], default="slow-post")
    attack.add_argument(
        "--method",
        metavar="VERB",
        help="Override HTTP method (default depends on mode: POST for slow-post/chunked, GET otherwise)",
    )
    attack.add_argument(
        "--path",
        metavar="PATH",
        help="Override the request path (default: path from --url, or '/')",
    )
    attack.add_argument(
        "--no-random-path",
        action="store_true",
        default=False,
        help="Disable per-request random token appended to the path",
    )
    attack.add_argument(
        "-c",
        "--concurrency",
        "--threads",
        "-r",
        dest="concurrency",
        type=int,
        default=256,
        help="Number of concurrent connections",
    )
    attack.add_argument("-dl", "--delay-min", type=float, default=0.1, metavar="SEC")
    attack.add_argument("-dh", "--delay-max", type=float, default=3.0, metavar="SEC")
    attack.add_argument(
        "-d",
        "--duration",
        type=float,
        default=0.0,
        help="Stop after N seconds (0 = unlimited)",
    )
    attack.add_argument(
        "--post-length",
        type=int,
        default=4096,
        help="Baseline Content-Length for slow-post / chunked modes",
    )
    attack.add_argument("--connect-timeout", type=float, default=15.0, metavar="SEC")
    attack.add_argument(
        "--max-errors",
        type=int,
        default=0,
        help="Exit after N consecutive errors (0 = disabled, for CI integration)",
    )
    attack.add_argument(
        "--ramp-up",
        type=int,
        default=0,
        help="Stagger worker starts (N workers per second, 0 = start all immediately)",
    )

    proxy_group = parser.add_argument_group("proxy / Tor")
    proxy_group.add_argument(
        "--tor", action="store_true", help="Route via Tor SOCKS5 at 127.0.0.1:9050"
    )
    proxy_group.add_argument("--proxy", help="Proxy URL, e.g. socks5://user:pass@host:9050")
    proxy_group.add_argument(
        "--proxy-list", metavar="FILE", help="File with one proxy URL per line"
    )
    proxy_group.add_argument(
        "--proxy-env", metavar="VAR", help="Read proxy URL from environment variable"
    )
    proxy_group.add_argument(
        "--rotate-proxies", action="store_true", help="Pick a random proxy per connection"
    )

    output = parser.add_argument_group("output")
    output.add_argument("--stats-interval", type=float, default=1.0, metavar="SEC")
    output.add_argument(
        "--json", action="store_true", dest="json_output", help="Emit newline-delimited JSON stats"
    )
    output.add_argument("-q", "--quiet", action="store_true", help="Suppress the live status line")
    output.add_argument(
        "-v", "--verbose", action="count", default=0, help="Print per-error details"
    )
    output.add_argument(
        "--user-agents", metavar="FILE", help="File with one User-Agent string per line"
    )

    custom = parser.add_argument_group("customization")
    custom.add_argument(
        "--header",
        action="append",
        metavar="NAME:VALUE",
        help="Add custom HTTP header (can be repeated)",
    )
    custom.add_argument(
        "--header-file",
        metavar="FILE",
        help="Load custom headers from file (one 'Name: Value' per line)",
    )
    custom.add_argument(
        "--body-file",
        metavar="FILE",
        help="Load custom POST body from file (for slow-post/chunked modes)",
    )
    custom.add_argument(
        "--config-file",
        dest="config_file",
        metavar="FILE",
        help="Load defaults from a TOML file (CLI flags and TORSHAMMER_* env win)",
    )

    automation = parser.add_argument_group("automation")
    automation.add_argument(
        "--fail-under", type=int, metavar="N", help="Exit with error if peak active connections < N"
    )
    automation.add_argument(
        "--fail-on-zero",
        action="store_true",
        help="Exit with error if zero connections were opened",
    )
    automation.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve and print the target/config without opening any connections",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


# ---------------------------------------------------------------------------
# Re-exports: implementations live in target/settings/dispatch/summary; the
# `cli` names remain import-compatible for tests and downstream users.
# ---------------------------------------------------------------------------
__all__ = [
    "_build_custom_headers",
    "_build_proxies",
    "_check_fd_limits",
    "_check_target_policy",
    "_find_rust_binary",
    "_forward_to_rust",
    "_is_private_or_local_target",
    "_load_allowlist",
    "_load_custom_body",
    "_parse_custom_headers",
    "_print_dry_run",
    "_print_summary",
    "_resolve_backend",
    "_resolve_config",
    "build_parser",
    "main",
]

from .dispatch import _find_rust_binary, _forward_to_rust, _resolve_backend
from .settings import (
    _build_custom_headers,
    _build_proxies,
    _load_custom_body,
    _parse_custom_headers,
    _resolve_config,
)
from .summary import _print_dry_run, _print_summary
from .target import (
    _check_target_policy,
    _is_private_or_local_target,
    _load_allowlist,
)


async def _run(config: Config) -> AttackEngine:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass  # e.g. Windows: Ctrl-C raises KeyboardInterrupt instead

    engine = AttackEngine(config, stop)
    try:
        await engine.run()
    finally:
        _print_summary(engine.stats, json_output=config.json_output)
    return engine


def _check_fd_limits(concurrency: int) -> None:
    """Check file descriptor limits and warn if concurrency might exceed them."""
    if not HAS_RESOURCE or resource is None:
        return  # Windows or systems without resource module

    try:
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        # Use 80% of soft limit as safe threshold
        safe_limit = int(soft_limit * 0.8)

        if concurrency > safe_limit:
            print(
                f"[warn] Requested concurrency ({concurrency}) exceeds 80% of "
                f"file descriptor limit ({soft_limit}).",
                file=sys.stderr,
            )
            print("[warn] This may cause 'Too many open files' errors.", file=sys.stderr)
            print(
                f"[warn] Consider: 'ulimit -n {hard_limit}' to increase the limit.", file=sys.stderr
            )
            print(f"[warn] Or reduce concurrency with -c {safe_limit}", file=sys.stderr)
    except (ValueError, OSError):
        # getrlimit can fail on some systems, just skip the check
        pass


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Layered settings (TOML-only, zero-dep): CLI > TORSHAMMER_* env >
    # torshammer.toml / [tool.torshammer] in pyproject.toml > defaults.
    # Controlled by --config-file; auto-discovery only when the flag is absent
    # is intentionally OFF so runs stay reproducible by default.
    from .config import apply_layered_settings, load_toml_file

    cfg_file = getattr(args, "config_file", None)
    cli_defaults = {
        action.dest: action.default
        for action in parser._actions
        if action.dest not in {"help", "version"}
    }
    if cfg_file:
        apply_layered_settings(args, load_toml_file(cfg_file), cli_defaults)
    else:
        apply_layered_settings(args, {}, cli_defaults)
    try:
        config = _resolve_config(args)
    except ValueError as exc:
        # Config validation errors are user errors, not crashes: report them
        # on stderr with a clean message and exit code 2 (argparse convention).
        print(f"error: invalid option: {exc}", file=sys.stderr)
        return 2

    if getattr(args, "dry_run", False):
        if config.backend == "rust":
            print("dry-run: rust backend selected; no dispatch performed", file=sys.stderr)
        _print_dry_run(config)
        return 0

    # Dispatch to the Rust backend before any Python engine work: on POSIX this
    # replaces the process image; on Windows it spawns and mirrors the code.
    if config.backend == "rust":
        return _forward_to_rust(config, args)

    # Check file descriptor limits before starting
    _check_fd_limits(config.concurrency)

    scheme = "https" if config.secure else "http"
    # Route the banner to stderr in JSON mode so stdout stays a clean JSON stream.
    banner_stream = sys.stderr if config.json_output else sys.stdout
    print(
        BANNER.format(
            VER=__version__,
            TARGET=f"{scheme}://{config.host}:{config.port}{config.path}",
            BACKEND=config.backend,
            MODE=config.mode,
            CONCURRENCY=config.concurrency,
        ),
        file=banner_stream,
    )

    try:
        engine = asyncio.run(_run(config))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130

    # Exit with non-zero if circuit breaker was triggered
    if engine.stats.circuit_breaker:
        print("\nCircuit breaker triggered: too many consecutive errors.", file=sys.stderr)
        return 1

    # Exit with error if fail_under condition not met
    if config.fail_under > 0 and engine.stats.peak_active < config.fail_under:
        print(
            f"\nAutomation failure: peak active connections ({engine.stats.peak_active}) below threshold ({config.fail_under})",
            file=sys.stderr,
        )
        return 1

    # Exit with error if fail_on_zero and no connections opened
    if config.fail_on_zero and engine.stats.connections == 0:
        print("\nAutomation failure: zero connections opened", file=sys.stderr)
        return 1

    return 0
