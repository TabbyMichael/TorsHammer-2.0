"""Allow running the tool as ``python -m torshammer``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
