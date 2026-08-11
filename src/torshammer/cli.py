"""Command line interface and orchestration."""

from __future__ import annotations

import argparse
import asyncio
import os
import random
import re
import signal
import sys
import time
from urllib.parse import urlparse

from . import __version__
from .config import Config
from .engine import AttackEngine
from .profiles import PROFILES
from .proxies import Proxy
from .stats import Stats, human_size
from .useragents import load_user_agents

BANNER = """\
/*  Tor's Hammer {ver}
 *  Slow-requests DoS/Vulnerability testing tool (asyncio rewrite)
 *  Target: {target}   Mode: {mode}   Connections: {concurrency}
 *
 *  LEGAL: You may only use this against systems you own or are
 *  explicitly authorized to test. Unauthorized denial-of-service
 *  activity is illegal in most jurisdictions.
 */"""


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

    attack = parser.add_argument_group("attack")
    attack.add_argument("-m", "--mode", choices=sorted(PROFILES), default="slow-post")
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
        "--method",
        choices=["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        help="HTTP method to use for requests",
    )
    attack.add_argument("--path", help="Request path to use instead of the URL path")
    attack.add_argument(
        "--no-random-path",
        action="store_true",
        help="Preserve the configured request path without adding a random query string",
    )
    attack.add_argument(
        "--header",
        action="append",
        dest="headers",
        metavar="HEADER",
        default=[],
        help="Custom header to include in requests, e.g. 'X-Api-Key: abc'",
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
        "--rotate-proxies", action="store_true", help="Pick a random proxy per connection"
    )
    proxy_group.add_argument(
        "--proxy-max-failures",
        type=int,
        default=3,
        help="Remove a proxy from the pool after this many failures",
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
        "--seed",
        type=int,
        help="Seed the random number generator for reproducible request patterns",
    )
    output.add_argument(
        "--user-agents", metavar="FILE", help="File with one User-Agent string per line"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


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

    if url:
        if "://" not in url:
            url = "http://" + url
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise SystemExit(f"error: unsupported URL scheme: {parsed.scheme!r}")
        if not parsed.hostname:
            raise SystemExit("error: URL has no hostname")
        host = parsed.hostname
        secure = parsed.scheme == "https"
        port = parsed.port or (443 if secure else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
    elif args.host:
        host = args.host
        secure = args.ssl
        port = args.port or (443 if secure else 80)

    if host is None:
        raise SystemExit("error: a target is required (use --url or --host)")

    if args.port and url:
        port = args.port
    if args.ssl:
        secure = True

    if args.path:
        path = args.path if args.path.startswith("/") else "/" + args.path

    if (port == 80 and not secure) or (port == 443 and secure):
        header_host = host
    else:
        header_host = f"{host}:{port}"

    assert port is not None
    config = Config(
        host=host,
        port=port,
        secure=secure,
        path=path,
        header_host=header_host,
        concurrency=max(1, args.concurrency),
        mode=args.mode,
        base_post_length=max(1, args.post_length),
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        duration=args.duration,
        connect_timeout=args.connect_timeout,
        ssl_verify=not args.ssl_no_verify,
        proxies=_build_proxies(args, secure),
        rotate_proxies=args.rotate_proxies,
        proxy_max_failures=args.proxy_max_failures,
        user_agents=load_user_agents(args.user_agents),
        custom_headers=_parse_custom_headers(args.headers),
        method=args.method,
        randomize_path=not args.no_random_path,
        seed=args.seed,
        stats_interval=args.stats_interval,
        json_output=args.json_output,
        quiet=args.quiet,
        verbose=args.verbose,
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
                redacted_url = re.sub(r'(://[^:]+:)[^@]+(@)', r'\1***\2', env_proxy)
                print(
                    f"  [warn] ignoring invalid proxy from environment: {redacted_url!r}",
                    file=sys.stderr,
                )
    return proxies or None


async def _run(config: Config) -> None:
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
        _print_summary(engine.stats)


def _print_summary(stats: Stats) -> None:
    uptime = time.monotonic() - stats.start
    print()
    print("  connections opened :", stats.connections)
    print("  peak concurrent    :", stats.peak_active)
    print("  completed cycles   :", stats.completed)
    print("  errors             :", stats.errors)
    print("  bytes sent         :", human_size(stats.bytes_sent))
    print("  bytes received     :", human_size(stats.bytes_received))
    print("  elapsed            :", f"{int(uptime // 60)}:{int(uptime % 60):02d}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = _resolve_config(args)
    if config.seed is not None:
        random.seed(config.seed)

    scheme = "https" if config.secure else "http"
    print(
        BANNER.format(
            ver=__version__,
            target=f"{scheme}://{config.host}:{config.port}{config.path}",
            mode=config.mode,
            concurrency=config.concurrency,
        )
    )

    try:
        asyncio.run(_run(config))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    return 0
