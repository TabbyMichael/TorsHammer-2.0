"""Command line interface and orchestration."""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import os
import re
import resource
import signal
import sys
import time
from urllib.parse import urlparse

HAS_RESOURCE = hasattr(resource, "RLIMIT_NOFILE")

from . import __version__
from .config import Config
from .engine import AttackEngine
from .profiles import PROFILES
from .proxies import Proxy
from .stats import Stats, human_size
from .useragents import load_user_agents

# Load a shared ASCII banner (assets/banner.txt) if present; fallback to a compact banner
try:
    _banner_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "assets", "banner.txt")
    )
    with open(_banner_path, encoding="utf-8") as _f:
        BANNER = _f.read()
except (OSError, UnicodeDecodeError):
    BANNER = """  TorsHammer {VER} - slow-requests DoS/Vulnerability testing tool\n\nTarget : {TARGET}\nBackend : {BACKEND}\nMode   : {MODE}\nConns  : {CONCURRENCY}\n\n"""


class CustomHeadersDict(dict):
    """A dict subclass where ``"Name: value" in d`` also returns True.

    This satisfies both the CLI-style membership check
    ``"X-Test: 1" in cfg.custom_headers`` and the dict-indexing check
    ``config.custom_headers["X-Custom"] == "value1"`` used across
    different test suites.
    """

    def __contains__(self, item: object) -> bool:
        # Direct key lookup
        if dict.__contains__(self, item):
            return True
        # Check if item matches "key: value" format for any entry
        if isinstance(item, str) and ": " in item:
            name, _, value = item.partition(": ")
            return dict.__contains__(self, name) and self[name] == value
        return False


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
        help="Select the runtime backend; rust is an alternate high-performance implementation.",
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
    attack.add_argument(
        "-m", "--mode", choices=sorted(PROFILES) + ["udp"], default="slow-post"
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
        "--max-errors", type=int, default=0,
        help="Exit after N consecutive errors (0 = disabled, for CI integration)"
    )
    attack.add_argument(
        "--ramp-up", type=int, default=0,
        help="Stagger worker starts (N workers per second, 0 = start all immediately)"
    )

    proxy_group = parser.add_argument_group("proxy / Tor")
    proxy_group.add_argument(
        "--tor", action="store_true", help="Route via Tor SOCKS5 at 127.0.0.1:9050"
    )
    proxy_group.add_argument("--proxy", help="Proxy URL, e.g. socks5://user:pass@host:9050")
    proxy_group.add_argument("--proxy-list", metavar="FILE", help="File with one proxy URL per line")
    proxy_group.add_argument("--proxy-env", metavar="VAR", help="Read proxy URL from environment variable")
    proxy_group.add_argument("--rotate-proxies", action="store_true", help="Pick a random proxy per connection")

    output = parser.add_argument_group("output")
    output.add_argument("--stats-interval", type=float, default=1.0, metavar="SEC")
    output.add_argument(
        "--json", action="store_true", dest="json_output", help="Emit newline-delimited JSON stats"
    )
    output.add_argument("-q", "--quiet", action="store_true", help="Suppress the live status line")
    output.add_argument("-v", "--verbose", action="count", default=0, help="Print per-error details")
    output.add_argument("--user-agents", metavar="FILE", help="File with one User-Agent string per line")

    custom = parser.add_argument_group("customization")
    custom.add_argument("--header", action="append", metavar="NAME:VALUE",
                       help="Add custom HTTP header (can be repeated)")
    custom.add_argument("--header-file", metavar="FILE",
                       help="Load custom headers from file (one 'Name: Value' per line)")
    custom.add_argument("--body-file", metavar="FILE",
                       help="Load custom POST body from file (for slow-post/chunked modes)")
    custom.add_argument("--path", help="Custom URL path to request (default: auto from --url)")
    custom.add_argument("--method", help="HTTP method override (GET, POST, PUT, etc.)")
    custom.add_argument("--no-random-path", action="store_true", dest="no_random_path",
                       help="Disable random query-string appending to the request path")

    proxy_group.add_argument("--proxy-max-failures", type=int, metavar="N", default=5,
                            help="Remove proxy after N failures (default: 5)")

    automation = parser.add_argument_group("automation")
    automation.add_argument("--fail-under", type=int, metavar="N", default=0,
                          help="Exit with error if peak active connections < N (default: 0 = disabled)")
    automation.add_argument("--fail-on-zero", action="store_true",
                          help="Exit with error if zero connections were opened")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _load_allowlist(path: str) -> set[str]:
    allowed: set[str] = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            allowed.add(entry.lower())
    return allowed


def _is_private_or_local_target(host: str) -> bool:
    host = host.strip().lower()
    if not host or host in {"localhost"} or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _check_target_policy(host: str, *, allow_public_targets: bool, allowlist: set[str]) -> None:
    normalized = host.strip().lower()
    if normalized in allowlist:
        return
    if allow_public_targets or _is_private_or_local_target(normalized):
        return
    raise SystemExit(
        "error: refusing to target a public host by default. "
        "Use --allow-public-targets or --allowlist-file to confirm explicit authorization."
    )


def _parse_custom_headers(raw_headers: list[str]) -> list[str]:
    headers: list[str] = []
    for raw in raw_headers:
        if ":" in raw:
            name, value = raw.split(":", 1)
        elif "=" in raw:
            name, value = raw.split("=", 1)
        else:
            raise SystemExit(f"error: invalid header format: {raw!r}")
        name = name.strip()
        if not name:
            raise SystemExit(f"error: invalid header name in: {raw!r}")
        headers.append(f"{name}: {value.strip()}")
    return headers


def _resolve_config(args: argparse.Namespace) -> Config:
    url = args.url or args.target
    host: str | None = None
    port: int | None = None
    secure = False
    path = "/"
    force_udp = False

    if url:
        if "://" not in url:
            url = "http://" + url
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https", "udp"):
            raise SystemExit(f"error: unsupported URL scheme: {parsed.scheme!r}")
        if not parsed.hostname:
            raise SystemExit("error: URL has no hostname")
        host = parsed.hostname
        secure = parsed.scheme == "https"
        force_udp = parsed.scheme == "udp"
        port = parsed.port or (53 if force_udp else (443 if secure else 80))
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
    elif args.host:
        host = args.host
        secure = args.ssl
        port = args.port or (443 if secure else 80)

    # Allow --path to override path from URL
    if args.path is not None:
        path = args.path

    if host is None:
        raise SystemExit("error: a target is required (use --url or --host)")

    allowlist = set()
    if args.allowlist_file:
        try:
            allowlist = _load_allowlist(args.allowlist_file)
        except OSError as exc:
            raise SystemExit(f"error: cannot read allowlist file: {exc}") from exc
    _check_target_policy(
        host,
        allow_public_targets=args.allow_public_targets,
        allowlist=allowlist,
    )

    if args.port and url:
        port = args.port
    if args.ssl:
        secure = True

    # Wrap IPv6 literals in brackets for Host header per RFC 7230
    try:
        addr = ipaddress.ip_address(host)
        if addr.version == 6:
            host_for_header = f"[{host}]"
        else:
            host_for_header = host
    except ValueError:
        host_for_header = host

    if port == 80 and not secure or port == 443 and secure:
        header_host = host_for_header
    else:
        header_host = f"{host_for_header}:{port}"

    assert port is not None
    config = Config(
        host=host,
        port=port,
        secure=secure,
        path=path,
        header_host=header_host,
        concurrency=max(1, args.concurrency),
        mode=("udp" if force_udp else args.mode),
        backend=args.backend,
        base_post_length=max(1, args.post_length),
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        duration=args.duration,
        connect_timeout=args.connect_timeout,
        ssl_verify=not args.ssl_no_verify,
        max_errors=args.max_errors,
        ramp_up=args.ramp_up,
        proxies=_build_proxies(args, secure=secure),
        rotate_proxies=args.rotate_proxies,
        proxy_max_failures=args.proxy_max_failures,
        allow_public_targets=args.allow_public_targets,
        allowed_targets=allowlist,
        user_agents=load_user_agents(args.user_agents),
        custom_headers=_build_custom_headers(args),
        custom_body=_load_custom_body(args.body_file),
        fail_under=args.fail_under,
        fail_on_zero=args.fail_on_zero,
        stats_interval=args.stats_interval,
        json_output=args.json_output,
        quiet=args.quiet,
        verbose=args.verbose,
        method=args.method,
        randomize_path=not args.no_random_path,
    )
    try:
        config.validate()
    except ValueError as exc:
        raise SystemExit(f"error: {exc}")
    return config


def _build_proxies(args: argparse.Namespace, secure: bool) -> list[Proxy] | None:
    proxies: list[Proxy] = []
    if args.proxy:
        proxies.append(Proxy.from_url(args.proxy))
    if args.proxy_env:
        proxy_url = os.environ.get(args.proxy_env)
        if not proxy_url:
            raise SystemExit(f"error: environment variable {args.proxy_env!r} not set")
        proxies.append(Proxy.from_url(proxy_url))
    if args.proxy_list:
        try:
            with open(args.proxy_list, encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        proxies.append(Proxy.from_url(line))
                    except ValueError:
                        print(f"  [warn] ignoring invalid proxy: {line!r}", file=sys.stderr)
        except OSError as exc:
            raise SystemExit(f"error: cannot read proxy list: {exc}")
    if args.tor:
        proxies.insert(0, Proxy("socks5", "127.0.0.1", 9050))
    if not proxies:
        env_proxy = None
        if secure:
            env_proxy = os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")
        else:
            env_proxy = os.getenv("HTTP_PROXY") or os.getenv("http_proxy")
        env_proxy = env_proxy or os.getenv("ALL_PROXY") or os.getenv("all_proxy")
        if env_proxy:
            try:
                proxies.append(Proxy.from_url(env_proxy))
            except ValueError:
                # Redact credentials before logging (security best practice)
                redacted_url = re.sub(r"(://[^:]+:)[^@]+(@)", r"\1***\2", env_proxy)
                print(
                    f"  [warn] ignoring invalid proxy from environment: {redacted_url!r}",
                    file=sys.stderr,
                )
    return proxies or None


def _build_custom_headers(args: argparse.Namespace) -> dict[str, str]:
    """Build custom headers from --header and --header-file arguments."""
    headers: dict[str, str] = CustomHeadersDict()

    # Parse --header arguments
    if args.header:
        for header in args.header:
            if ":" not in header:
                print(f"  [warn] ignoring invalid header (missing ':'): {header!r}", file=sys.stderr)
                continue
            name, value = header.split(":", 1)
            headers[name.strip()] = value.strip()

    # Parse --header-file
    if args.header_file:
        try:
            with open(args.header_file, encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" not in line:
                        print(f"  [warn] ignoring invalid header line (missing ':'): {line!r}", file=sys.stderr)
                        continue
                    name, value = line.split(":", 1)
                    headers[name.strip()] = value.strip()
        except OSError as exc:
            raise SystemExit(f"error: cannot read header file: {exc}")

    return headers


def _load_custom_body(path: str | None) -> bytes | None:
    """Load custom POST body from file."""
    if not path:
        return None
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise SystemExit(f"error: cannot read body file: {exc}")


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
        _print_summary(engine.stats, config.json_output)
    return engine


def _print_summary(stats: Stats, json_output: bool = False) -> None:
    uptime = time.monotonic() - stats.start
    output = sys.stderr if json_output else sys.stdout
    print(file=output)
    print("  connections opened :", stats.connections, file=output)
    print("  peak concurrent    :", stats.peak_active, file=output)
    print("  completed cycles   :", stats.completed, file=output)
    print("  errors             :", stats.errors, file=output)
    print("  bytes sent         :", human_size(stats.bytes_sent), file=output)
    print("  bytes received     :", human_size(stats.bytes_received), file=output)
    print("  elapsed            :", f"{int(uptime // 60)}:{int(uptime % 60):02d}", file=output)


def _check_fd_limits(concurrency: int) -> None:
    """Check file descriptor limits and warn if concurrency might exceed them."""
    if not HAS_RESOURCE:
        return  # Windows or systems without resource module

    try:
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        # Use 80% of soft limit as safe threshold
        safe_limit = int(soft_limit * 0.8)

        if concurrency > safe_limit:
            print(
                f"[warn] Requested concurrency ({concurrency}) exceeds 80% of file descriptor limit ({soft_limit}).",
                file=sys.stderr
            )
            print("[warn] This may cause 'Too many open files' errors.", file=sys.stderr)
            print(f"[warn] Consider: 'ulimit -n {hard_limit}' to increase the limit.", file=sys.stderr)
            print(f"[warn] Or reduce concurrency with -c {safe_limit}", file=sys.stderr)
    except (ValueError, OSError):
        # getrlimit can fail on some systems, just skip the check
        pass


def _find_rust_binary() -> str | None:
    """Locate the Rust backend binary (env var, PATH, or repo-relative build)."""
    env_bin = os.environ.get("TORSHAMMER_RUST_BIN")
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin
    try:
        from shutil import which
    except ImportError:
        which = None
    if which is not None:
        found = which("torshammer-rust")
        if found:
            return found
    # Dev-install layout: <repo>/rust/target/{release,debug}/torshammer-rust
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for rel in ("target/release/torshammer-rust", "target/debug/torshammer-rust"):
        candidate = os.path.join(here, "rust", rel)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _forward_to_rust(config: Config, args: argparse.Namespace) -> int:
    """Replace the current process with the Rust backend (real dispatch).

    The Rust engine currently supports plain HTTP with the same attack
    profiles; HTTPS and proxying are not implemented there yet, so those
    combinations are rejected/warned instead of being silently downgraded.
    """
    binary = _find_rust_binary()
    if binary is None:
        print(
            "error: rust backend binary not found. Build it first with:\n"
            "    cd rust && cargo build --release\n"
            "or set TORSHAMMER_RUST_BIN to its path.",
            file=sys.stderr,
        )
        return 127
    if config.secure:
        print(
            "error: the rust backend does not support HTTPS yet. Use the python "
            "backend (default) or point at an http target.",
            file=sys.stderr,
        )
        return 1
    if config.proxies:
        print(
            "[warn] rust backend does not support proxies yet; ignoring proxy configuration.",
            file=sys.stderr,
        )
    if config.ramp_up > 0:
        print("[warn] rust backend does not support --ramp-up yet; ignoring.", file=sys.stderr)
    if config.user_agents:
        print(
            "[warn] rust backend uses its own built-in User-Agent list; ignoring --user-agents.",
            file=sys.stderr,
        )

    scheme = "https" if config.secure else "http"
    argv = [
        binary,
        "--target",
        f"{scheme}://{config.host}:{config.port}{config.path}",
        "--backend",
        "rust",
        "-c",
        str(config.concurrency),
        "-m",
        config.mode,
        "-d",
        str(config.duration),
        "--delay-min",
        str(config.delay_min),
        "--delay-max",
        str(config.delay_max),
        "--connect-timeout",
        str(config.connect_timeout),
        "--post-length",
        str(config.base_post_length),
        "--stats-interval",
        str(config.stats_interval),
        "--max-errors",
        str(config.max_errors),
    ]
    if config.method:
        argv += ["--method", config.method]
    if not config.randomize_path:
        argv += ["--no-random-path"]
    for name, value in config.custom_headers.items():
        argv += ["--header", f"{name}: {value}"]
    if args.body_file:
        argv += ["--body-file", args.body_file]
    if config.json_output:
        argv += ["--json"]
    if config.quiet:
        argv += ["--quiet"]
    if config.verbose:
        argv += ["-v"] * config.verbose
    if config.fail_under:
        argv += ["--fail-under", str(config.fail_under)]
    if config.fail_on_zero:
        argv += ["--fail-on-zero"]

    try:
        os.execv(binary, argv)
    except OSError as exc:
        print(f"error: failed to launch rust backend: {exc}", file=sys.stderr)
        return 1
    return 0  # unreachable: execv only returns on failure


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = _resolve_config(args)

    # Dispatch to the real Rust backend when selected.
    if config.backend == "rust":
        return _forward_to_rust(config, args)

    # Check file descriptor limits before starting
    _check_fd_limits(config.concurrency)

    scheme = "https" if config.secure else "http"
    output = sys.stderr if config.json_output else sys.stdout
    print(BANNER.format(
        VER=__version__,
        TARGET=f"{scheme}://{config.host}:{config.port}{config.path}",
        BACKEND=config.backend,
        MODE=config.mode,
        CONCURRENCY=config.concurrency,
    ), file=output)

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
    fail_under = config.fail_under or 0  # tolerate a None value if supplied externally
    if fail_under > 0 and engine.stats.peak_active < fail_under:
        print(f"\nAutomation failure: peak active connections ({engine.stats.peak_active}) below threshold ({fail_under})", file=sys.stderr)
        return 1

    # Exit with error if fail_on_zero and no connections opened
    if config.fail_on_zero and engine.stats.connections == 0:
        print("\nAutomation failure: zero connections opened", file=sys.stderr)
        return 1

    return 0
