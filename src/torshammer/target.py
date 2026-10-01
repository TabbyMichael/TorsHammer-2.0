"""Target authorization policy: allowlist loading and default-deny checks.

The tool refuses to target public hosts unless the operator opts in with
``--allow-public-targets`` or lists the host in ``--allowlist-file``. The
check is hostname-based (see ``docs/security.md`` for the DNS-rebinding
TOCTOU limitation).
"""

from __future__ import annotations

import ipaddress


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
