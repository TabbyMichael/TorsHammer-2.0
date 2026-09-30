"""Tests for the shared startup banner artwork.

`assets/banner.txt` at the repository root is the single source of truth for
the banner: the Python package ships a copy as
`src/torshammer/banner.txt` (package data must live inside the package) and the
Rust engine embeds the same file at compile time
(`rust/src/cli/banner.rs` -> `include_str!("../../../assets/banner.txt")`).
These tests fail if the two copies ever drift apart or if the placeholders the
CLI substitutes are renamed.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CANONICAL_BANNER = REPO_ROOT / "assets" / "banner.txt"
PACKAGED_BANNER = REPO_ROOT / "src" / "torshammer" / "banner.txt"
RUST_BANNER_SOURCE = REPO_ROOT / "rust" / "src" / "cli" / "banner.rs"

# Placeholders substituted by ``cli.main`` via ``str.format``.
PLACEHOLDERS = ("{VER}", "{TARGET}", "{BACKEND}", "{MODE}", "{CONCURRENCY}")


def _art_rows(text: str) -> list[str]:
    """Return the artwork rows that precede the first blank line."""
    rows: list[str] = []
    for line in text.split("\n"):
        if line == "":
            break
        rows.append(line)
    return rows


def test_packaged_banner_matches_canonical_asset() -> None:
    """`src/torshammer/banner.txt` must be byte-identical to the shared asset."""
    assert CANONICAL_BANNER.is_file(), "assets/banner.txt is the source of truth"
    assert PACKAGED_BANNER.read_bytes() == CANONICAL_BANNER.read_bytes()


def test_rust_engine_embeds_the_canonical_asset() -> None:
    """The Rust banner must embed `assets/banner.txt`, not a private copy."""
    source = RUST_BANNER_SOURCE.read_text(encoding="utf-8")
    assert 'include_str!("../../../assets/banner.txt")' in source


def test_placeholders_are_exactly_the_ones_the_cli_substitutes() -> None:
    """Only the placeholders `cli.main` passes to `str.format` may appear."""
    text = CANONICAL_BANNER.read_text(encoding="utf-8")
    assert set(re.findall(r"\{[A-Z_]+\}", text)) == set(PLACEHOLDERS)


def test_artwork_is_six_uniformly_padded_rows() -> None:
    """Trailing spaces in the artwork are meaningful: rows must line up."""
    rows = _art_rows(CANONICAL_BANNER.read_text(encoding="utf-8"))
    assert len(rows) == 6, "the shared wordmark is six rows tall"
    widths = sorted({len(row) for row in rows})
    assert len(widths) == 1, f"artwork rows are not aligned: {widths}"
    assert "█" in rows[0] and "╗" in rows[0], "block-drawing wordmark expected"


def test_cli_banner_renders_artwork_and_run_config() -> None:
    """The packaged banner formats cleanly into the documented layout."""
    from torshammer.cli import BANNER

    rendered = BANNER.format(
        VER="2.0.0",
        TARGET="http://127.0.0.1:8080/",
        BACKEND="python",
        MODE="slow-post",
        CONCURRENCY=256,
    )
    assert "█" in rendered, "artwork must be rendered"
    assert "TorsHammer 2.0.0" in rendered
    assert "Security Testing & Vulnerability Assessment Framework" in rendered
    assert "Target  : http://127.0.0.1:8080/" in rendered
    assert "Backend : python" in rendered
    assert "Mode    : slow-post" in rendered
    assert "Conns   : 256" in rendered


def test_resource_fallback_banner_is_substitutable() -> None:
    """The fallback used when package data is missing must accept the same keys."""
    source = (REPO_ROOT / "src" / "torshammer" / "cli.py").read_text(encoding="utf-8")
    _, _, tail = source.partition("except (OSError, UnicodeDecodeError):")
    fallback = tail.split("class CustomHeadersDict", 1)[0]
    assert set(re.findall(r"\{[A-Z_]+\}", fallback)) == set(PLACEHOLDERS)
