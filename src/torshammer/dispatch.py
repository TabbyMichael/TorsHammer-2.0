"""Rust backend discovery and fail-closed dispatch.

``main()`` calls :func:`_forward_to_rust` when ``--backend rust`` is selected:
on POSIX the process image is replaced via ``os.execv``; on Windows the binary
is spawned with ``subprocess.run`` and its exit code mirrored. Flags the Rust
engine cannot honor exit non-zero with an explanation instead of being
silently downgraded (a quiet downgrade would be a security bug — e.g.
believing traffic is anonymized when it is not).
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys

from .config import Config


def _find_rust_binary(*, include_repo_build: bool = True) -> str | None:
    """Locate the Rust backend binary (env var, PATH, and optionally repo build).

    ``include_repo_build`` controls whether a repository-local
    ``rust/target/{release,debug}/torshammer-rust`` development build counts as
    "available". It is ``True`` for an explicit ``--backend rust`` (a developer
    who just ran ``cargo build`` gets their build used) and ``False`` for the
    ``auto`` resolver, so merely building the engine for development never
    silently changes what a normal run dispatches to.
    """
    env_bin = os.environ.get("TORSHAMMER_RUST_BIN")
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin
    found = shutil.which("torshammer-rust")
    if found:
        return found
    if not include_repo_build:
        return None
    # Dev-install layout: <repo>/rust/target/{release,debug}/torshammer-rust
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for rel in ("target/release/torshammer-rust", "target/debug/torshammer-rust"):
        candidate = os.path.join(here, "rust", rel)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _resolve_backend(requested: str) -> str:
    """Resolve the runtime backend, warning and falling back to Python if rust is unavailable.

    If the user explicitly selects ``--backend rust`` we look for the
    ``torshammer-rust`` binary through :func:`_find_rust_binary` — that is, the
    ``TORSHAMMER_RUST_BIN`` environment variable, then ``PATH``, then the
    repo-relative ``rust/target/{release,debug}`` build produced by
    ``cargo build``. When no binary exists we log a clear warning to stderr and
    fall back to the Python reference engine so the run can proceed.
    """
    if requested == "python":
        return "python"
    if requested == "auto":
        # The concrete choice needs the full Config (feature set in use), so it
        # is deferred to :func:`_resolve_auto_backend`, called from ``main()``.
        return "auto"
    if _find_rust_binary() is not None:
        return "rust"
    print(
        "  [warn] --backend rust requested but no 'torshammer-rust' binary was"
        " found (PATH, TORSHAMMER_RUST_BIN or rust/target/{release,debug})."
        " Falling back to the python reference engine.",
        file=sys.stderr,
    )
    return "python"


def _rust_blockers(config: Config, args: argparse.Namespace) -> list[str]:
    """Return reasons this run cannot be honored by the Rust backend (empty == OK).

    Single source of truth shared by the fail-closed explicit ``--backend rust``
    path (:func:`_forward_to_rust`) and the ``auto`` resolver
    (:func:`_resolve_auto_backend`), so the two can never drift on which features
    the Rust engine lacks.
    """
    blockers: list[str] = []
    if config.secure:
        blockers.append(
            "the rust backend does not support HTTPS yet. Use the python backend "
            "(default) or point at an http target."
        )
    if config.proxies:
        blockers.append(
            "--backend rust does not support proxies/Tor; use --backend python instead."
        )
    if not config.ssl_verify:
        blockers.append(
            "--backend rust does not support --ssl-no-verify; use --backend python instead."
        )
    if getattr(args, "user_agents", None):
        blockers.append(
            "--backend rust does not support --user-agents; use --backend python instead."
        )
    if config.ramp_up:
        blockers.append("--backend rust does not support --ramp-up; use --backend python instead.")
    url = getattr(args, "url", None)
    if url and str(url).lower().startswith("udp://") and config.mode != "udp":
        blockers.append("--backend rust requires -m udp for udp:// targets.")
    return blockers


def _resolve_auto_backend(config: Config, args: argparse.Namespace) -> str:
    """Resolve ``--backend auto`` to a concrete engine.

    Prefers the Rust engine only when a *properly installed* binary (``PATH`` or
    ``TORSHAMMER_RUST_BIN``, never a repository-local dev build) exists **and**
    the run uses no feature the Rust engine lacks; otherwise it falls back to the
    Python reference engine. This is what makes a normal run "just work" without
    ever silently dropping a requested capability.
    """
    if _find_rust_binary(include_repo_build=False) is None:
        return "python"
    if _rust_blockers(config, args):
        return "python"
    return "rust"


def _forward_to_rust(config: Config, args: argparse.Namespace) -> int:
    """Replace the current process with the Rust backend (real dispatch).

    Fail-closed: flags the Rust engine cannot honor (proxies/Tor, TLS verify
    bypass, HTTPS targets, custom UA lists, ramp-up) exit non-zero instead of
    being silently downgraded — a quiet downgrade here would be a security
    bug (e.g. believing traffic is anonymized when it is not).
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
    # Fail closed on any feature the Rust engine cannot honor: a quiet downgrade
    # would be a security bug (e.g. traffic believed anonymised when it is not).
    blockers = _rust_blockers(config, args)
    if blockers:
        print(f"error: {blockers[0]}", file=sys.stderr)
        return 1
    if args.path and args.path != config.path:
        print(
            "  [warn] rust backend derives the path from the target URL; ignoring --path override.",
            file=sys.stderr,
        )

    # Preserve the udp scheme: Rust already parses `udp://` (url.rs) and keys
    # the datagram engine off `-m udp`, but rewriting the target to http://
    # would silently change meaning if dispatch ever started keying off scheme.
    if config.mode == "udp":
        scheme = "udp"
    else:
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
    # The Rust engine now enforces the same default-deny target policy as the
    # Python wrapper; forward the operator's explicit authorization so a
    # sanctioned public-target run is not refused by the backend.
    if config.allow_public_targets:
        argv += ["--allow-public-targets"]
    if args.allowlist_file:
        argv += ["--allowlist-file", args.allowlist_file]

    if os.name == "nt":
        # os.execv has no Windows equivalent that replaces the process image;
        # spawn the backend and mirror its exit code instead.
        import subprocess

        try:
            completed = subprocess.run([binary, *argv[1:]], check=False)
        except OSError as exc:
            print(f"error: failed to launch rust backend: {exc}", file=sys.stderr)
            return 1
        return completed.returncode
    try:
        os.execv(binary, argv)
    except OSError as exc:
        print(f"error: failed to launch rust backend: {exc}", file=sys.stderr)
        return 1
    return 0  # unreachable on POSIX: execv only returns on failure
