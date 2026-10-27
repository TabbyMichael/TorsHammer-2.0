#!/usr/bin/env python3
"""Enforce 100% Rust line coverage from a cargo-llvm-cov ``lcov.info`` file.

Why not ``cargo llvm-cov --fail-under-lines 100``?

``--fail-under-lines`` reads the ``llvm-cov report`` line model, which on
cargo-llvm-cov 0.9.1 / LLVM 21 spuriously attributes about a dozen
already-executed continuation / closing-brace lines in ``engine/mod.rs`` and
``main.rs`` as *uncovered*, even though ``llvm-cov show`` and the ``lcov``
export (both produced from the identical merged profile) report **0**
uncovered statement lines for those files. No test can cover an already-run
line and no code restructure removes the artifact, so gating on ``report``
would pin the build at 99.79% forever.

The ``lcov`` model, by contrast, counts every real source statement and marks
each with a hit count. Gating on it (fail if ANY crate source line has a 0
hit count) is the honest 100%-lines check. See
``docs/testing.md`` -> "Rust backend coverage" for the full rationale and the
exclusion register.

Exit codes: 0 = every crate source line covered; 1 = uncovered lines found (or
no in-scope files, to avoid a vacuous pass); 2 = bad usage.
"""

from __future__ import annotations

import sys


def _is_crate_src(sf: str) -> bool:
    """True for files under this crate's ``src/`` (exclude toolchain/deps)."""
    if "/library/" in sf or "/registry/" in sf or "/rustup/" in sf:
        return False
    return "/src/" in sf


def _gate(path: str) -> int:
    cur: str | None = None
    in_scope = False
    per_file: dict[str, list[int]] = {}
    uncovered: list[str] = []

    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line.startswith("SF:"):
                cur = line[3:]
                in_scope = _is_crate_src(cur)
                if in_scope:
                    per_file.setdefault(cur, [0, 0])
            elif line.startswith("DA:") and in_scope and cur is not None:
                parts = line[3:].split(",")
                if len(parts) < 2:
                    continue
                lineno = parts[0]
                try:
                    count = int(parts[1])
                except ValueError:
                    continue
                rec = per_file[cur]
                rec[0] += 1
                if count > 0:
                    rec[1] += 1
                else:
                    uncovered.append(f"{cur}:{lineno}")

    if not per_file:
        sys.stderr.write("no rust/src files found in lcov - refusing to pass vacuously\n")
        return 1

    if uncovered:
        sys.stderr.write(f"FAIL: {len(uncovered)} uncovered rust/src line(s):\n")
        for item in uncovered:
            sys.stderr.write(f"  {item}\n")
        return 1

    total_found = sum(v[0] for v in per_file.values())
    total_hit = sum(v[1] for v in per_file.values())
    pct = (100.0 * total_hit / total_found) if total_found else 100.0
    print(
        f"PASS rust/src: {total_hit}/{total_found} lines covered "
        f"({pct:.2f}%) across {len(per_file)} files"
    )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        sys.stderr.write("usage: rust_cov_gate.py <lcov.info>\n")
        return 2
    return _gate(argv[0])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
