"""CLI-to-Config resolution: target parsing, headers, bodies, proxies.

Single source of truth for how ``argparse.Namespace`` becomes a validated
:class:`torshammer.config.Config`. The custom-header parser is fail-closed:
``:`` is the only separator and CR/LF content exits (header-injection guard).
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
from urllib.parse import urlparse

from .config import Config
from .dispatch import _resolve_backend
from .proxies import Proxy
from .target import _check_target_policy, _load_allowlist
from .useragents import load_user_agents


def _parse_custom_headers(raw_headers: list[str]) -> list[str]:
    """Normalize ``Name: value`` header strings (fail-closed strict parser).

    Single source of truth for custom-header syntax: ``:`` is the only
    accepted separator (the legacy ``Name=value`` form is rejected), and any
    CR/LF content (header-injection) exits with an error.
    """

    def _check_crlf(raw: str) -> None:
        if "\r" in raw or "\n" in raw:
            raise SystemExit(f"error: invalid header (CR/LF not allowed): {raw!r}")

    headers: list[str] = []
    for raw in raw_headers:
        _check_crlf(raw)
        if ":" not in raw:
            raise SystemExit(f"error: invalid header format: {raw!r}")
        name, value = raw.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            raise SystemExit(f"error: invalid header name in: {raw!r}")
        _check_crlf(name)
        _check_crlf(value)
        headers.append(f"{name}: {value}")
    return headers


def _resolve_config(args: argparse.Namespace) -> Config:
    # The namespace attributes are ``Any`` (argparse creates them dynamically),
    # so bind them to explicitly typed locals; everything downstream is then
    # type-checked instead of degrading to "partially unknown".
    url: str | None = args.url or args.target
    host: str | None = None
    port: int | None = None
    secure: bool = False
    path: str = "/"
    force_udp = False

    if url:
        if "://" not in url:
            url = f"http://{url}"
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
            path = f"{path}?{parsed.query}"
    elif args.host:
        host = args.host
        secure = args.ssl
        port = args.port or (443 if secure else 80)

    # Allow --path to override path from URL
    if args.path is not None:
        path = args.path

    if host is None:
        raise SystemExit("error: a target is required (use --url or --host)")

    allowlist: set[str] = set()
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
        mode="udp" if force_udp else args.mode,
        backend=_resolve_backend(args.backend),
        base_post_length=max(1, args.post_length),
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        duration=args.duration,
        connect_timeout=args.connect_timeout,
        ssl_verify=not args.ssl_no_verify,
        max_errors=args.max_errors,
        ramp_up=args.ramp_up,
        randomize_path=not args.no_random_path,
        proxies=_build_proxies(args),
        rotate_proxies=args.rotate_proxies,
        allow_public_targets=args.allow_public_targets,
        allowed_targets=allowlist,
        user_agents=load_user_agents(args.user_agents),
        custom_headers=_build_custom_headers(args),
        custom_body=_load_custom_body(args.body_file),
        fail_under=args.fail_under or 0,
        fail_on_zero=args.fail_on_zero,
        stats_interval=args.stats_interval,
        json_output=args.json_output,
        quiet=args.quiet,
        verbose=args.verbose,
        method=args.method,
    )
    # Validation is enforced by Config.__post_init__; errors surface as ValueError
    # from the constructor above and will propagate as-is to the caller.
    return config


def _build_proxies(args: argparse.Namespace) -> list[Proxy] | None:
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
        # Infer the scheme to select the right environment variable
        _url = args.url or args.target
        # Only derive _secure from URL scheme when --ssl was not explicitly provided
        if args.ssl is not None:
            _secure = args.ssl
        elif _url and "://" in _url:
            _secure = _url.split("://", 1)[0].lower() == "https"
        else:
            _secure = False
        if _secure:
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
    """Build custom headers from --header and --header-file arguments.

    Fail-closed: malformed entries and CR/LF content exit via
    :func:`_parse_custom_headers` instead of being silently skipped.
    """
    raw: list[str] = []

    # Parse --header arguments
    if args.header:
        raw.extend(args.header)

    # Parse --header-file
    if args.header_file:
        try:
            with open(args.header_file, encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    raw.append(line)
        except OSError as exc:
            raise SystemExit(f"error: cannot read header file: {exc}")

    headers: dict[str, str] = {}
    for entry in _parse_custom_headers(raw):
        name, _, value = entry.partition(":")
        headers[name.strip()] = value.strip()
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
