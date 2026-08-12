# Development Guide

## Overview

This guide covers the development workflow for contributing to Torshammer 2.0, including repository structure, coding standards, testing, and build processes.

## Repository Structure

```
torshammer/
├── src/
│   └── torshammer/
│       ├── __init__.py          # Package initialization, version
│       ├── __main__.py          # Python module entry point
│       ├── cli.py               # CLI argument parsing and orchestration
│       ├── config.py            # Configuration dataclass
│       ├── engine.py            # Async attack engine
│       ├── profiles.py          # Attack profiles
│       ├── conn.py              # Connection factory
│       ├── proxies.py           # Proxy parsing and rotation
│       ├── useragents.py        # User-Agent management
│       ├── stats.py             # Statistics aggregation
│       └── py.typed             # Type hints marker
├── tests/
│   ├── conftest.py              # Shared test fixtures
│   ├── test_cli.py              # CLI tests
│   ├── test_conn.py             # Connection tests
│   ├── test_profiles.py         # Profile tests
│   └── test_proxies.py          # Proxy tests
├── examples/
│   ├── proxies.txt              # Example proxy list
│   └── user-agents.txt          # Example User-Agent list
├── legacy/                      # Original 2011 code (reference only)
├── docs/                        # Documentation
├── pyproject.toml               # Project configuration
├── LICENSE                      # GPL-2.0-or-later
└── README.md                    # Project README
```

## Development Environment Setup

### Prerequisites

- Python 3.11 or higher
- Git (for version control)
- Virtual environment tool (venv)

### Initial Setup

```bash
# Clone repository (if using git)
git clone <repository-url>
cd torshammer

# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate  # Windows

# Install development dependencies
pip install -e ".[dev]"
```

### Verify Setup

```bash
# Check version
torshammer --version

# Run tests
pytest

# Check CLI help
torshammer --help
```

## Coding Standards

### Python Version

- **Minimum:** Python 3.11
- **Target:** Python 3.11+

### Type Hints

Type hints are required for all public functions and methods:

```python
from __future__ annotations

def example_function(param: str) -> int:
    return len(param)
```

### Code Style

Torshammer uses `ruff` for linting and formatting. Configuration in `pyproject.toml`:

```toml
[tool.ruff]
line-length = 100
target-version = "py311"
```

#### Running Ruff

```bash
# Install ruff
pip install ruff

# Check for issues
ruff check src/

# Auto-fix issues
ruff check --fix src/

# Format code
ruff format src/
```

### Import Style

- Use `from __future__ import annotations` at top of files
- Group imports: standard library, third-party, local
- Use absolute imports for local modules

```python
from __future__ import annotations

import asyncio
import ssl

from .config import Config
from .proxies import Proxy
```

### Naming Conventions

- **Modules:** `lowercase_with_underscores.py`
- **Classes:** `PascalCase`
- **Functions/Methods:** `lowercase_with_underscores`
- **Constants:** `UPPER_CASE`
- **Private:** `_leading_underscore`

### Docstrings

Use Google-style docstrings for public functions and classes:

```python
def open_connection(
    host: str,
    port: int,
    *,
    config: Config,
    proxy: Proxy | None = None,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a (reader, writer) stream to ``host:port``.

    When ``proxy`` is given the stream is first tunneled through the proxy;
    when the target is HTTPS the tunnel is upgraded to TLS (with SNI) after
    the proxy handshake.

    Args:
        host: Target hostname or IP address.
        port: Target port number.
        config: Configuration object.
        proxy: Optional proxy endpoint.

    Returns:
        Tuple of (reader, writer) streams.

    Raises:
        ConnectionError: If connection fails.
        asyncio.TimeoutError: If connection times out.
    """
```

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_cli.py

# Run specific test
pytest tests/test_cli.py::test_parse_https_url

# Run with coverage
pytest --cov=torshammer --cov-report=html
```

### Writing Tests

1. **Add test to appropriate file** based on functionality
2. **Use existing fixtures** (`slow_server`, `fake_socks5`)
3. **Make tests async** if testing async code
4. **Follow naming convention** `test_<description>`

**Example:**

```python
# tests/test_cli.py


def test_new_option():
    """Test new CLI option."""
    args = build_parser().parse_args(["-u", "http://example.com", "--new-option"])
    cfg = _resolve_config(args)
    assert cfg.new_option == expected_value
```

### Test Fixtures

#### SlowServer

Simulates a slow web server:

```python
async def test_with_slow_server(slow_server):
    cfg = Config(host="127.0.0.1", port=slow_server.port)
    # Test against slow_server
```

#### FakeSocks5

Simulates a SOCKS5 proxy:

```python
async def test_with_fake_proxy(fake_socks5):
    proxy = Proxy("socks5", "127.0.0.1", fake_socks5.port)
    # Test against fake_socks5
```

## Adding Features

### Adding a New Attack Profile

1. **Create profile class** in `profiles.py`:

```python
class NewMode(Profile):
    name = "new-mode"

    async def run(self, reader, writer, config, ua, stats, stop):
        # Implement attack logic
        while not stop.is_set():
            # Send data slowly
            await _write(writer, b"data", stats)
            await _halt(stop, config)
```

2. **Add to PROFILES dictionary**:

```python
PROFILES: dict[str, type[Profile]] = {
    SlowPost.name: SlowPost,
    SlowHeaders.name: SlowHeaders,
    SlowRead.name: SlowRead,
    Chunked.name: Chunked,
    NewMode.name: NewMode,  # Add here
}
```

3. **Update CLI choices** in `cli.py`:

```python
attack.add_argument("-m", "--mode", choices=sorted(PROFILES), default="slow-post")
```

4. **Add tests** in `test_profiles.py`:

```python
async def test_new_mode(slow_server):
    cfg = _cfg(slow_server)
    await _drive(PROFILES["new-mode"], cfg)
    assert slow_server.bytes_received > 0
```

### Adding a New Proxy Type

1. **Add handshake function** in `conn.py`:

```python
async def _connect_newproxy(reader, writer, proxy, host, port) -> None:
    # Implement handshake
    pass
```

2. **Add to _handshake** in `conn.py`:

```python
async def _handshake(reader, writer, proxy, host, port) -> None:
    if proxy.scheme == "socks5":
        await _connect_socks5(reader, writer, proxy, host, port)
    elif proxy.scheme == "newproxy":
        await _connect_newproxy(reader, writer, proxy, host, port)
    # ...
```

3. **Add scheme** in `proxies.py`:

```python
_SUPPORTED = {"socks5", "socks4", "http", "newproxy"}
_DEFAULT_PORTS = {"socks5": 1080, "socks4": 1080, "http": 8080, "newproxy": 9999}
```

4. **Add tests** in `test_conn.py` and `test_proxies.py`

### Adding a New CLI Option

1. **Add argument** in `cli.py`:

```python
attack.add_argument("--new-option", type=int, default=42, help="New option description")
```

2. **Add to Config** in `config.py`:

```python
@dataclass
class Config:
    # ... existing fields ...
    new_option: int = 42
```

3. **Update _resolve_config** in `cli.py`:

```python
return Config(
    # ... existing fields ...
    new_option=args.new_option,
)
```

4. **Add tests** in `test_cli.py`:

```python
def test_new_option():
    args = build_parser().parse_args(["-u", "http://example.com", "--new-option", "100"])
    cfg = _resolve_config(args)
    assert cfg.new_option == 100
```

## Build Process

### Building for Distribution

```bash
# Build source distribution
python -m build

# Build wheel
python -m build --wheel

# Output in dist/
```

### Installation from Source

```bash
# Install from local directory
pip install -e .

# Install from sdist
pip install dist/torshammer-2.0.0.tar.gz

# Install from wheel
pip install dist/torshammer-2.0.0-py3-none-any.whl
```

## Versioning

Version is defined in `src/torshammer/__init__.py`:

```python
__version__ = "2.0.0"
```

And in `pyproject.toml`:

```toml
[project]
version = "2.0.0"
```

**Update both when changing version.**

## Debugging

### Running with Debugger

```bash
# Run with pdb
python -m pdb -m torshammer -u http://localhost:8080

# Or use IDE debugger (VS Code, PyCharm, etc.)
```

### Debugging Async Code

```python
import asyncio

# Enable debug mode
asyncio.run(main(), debug=True)
```

### Logging

Add temporary logging for debugging:

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
logger.debug("Debug message")
```

## Performance Profiling

### Profiling with cProfile

```bash
python -m cProfile -o profile.stats -m torshammer -u http://localhost:8080
python -m pstats profile.stats
```

### Profiling Memory

```bash
pip install memory_profiler
python -m memory_profiler -m torshammer -u http://localhost:8080
```

## Continuous Integration

Torshammer uses [Woodpecker CI](https://woodpecker-ci.org/), configured in
[`.woodpecker.yml`](../.woodpecker.yml). The pipeline validates both the Python and
Rust backends across Python 3.11 / 3.12 / 3.13 and Rust 1.75 on every push and pull
request to `main` / `develop`.

### What CI runs

- **Python (`python:3.11-slim`, `python:3.12-slim`, `python:3.13-slim`)**
  1. `pip install -u pip`
  2. `pip install -e ".[dev]"` (editable install — note the `.` before `[dev]`)
  3. `pytest`
  4. `pip install ruff mypy`
  5. `ruff check .`
  6. `ruff format --check .`
  7. `mypy src/`

- **Rust lint (`rust:1.75`)**
  1. `rustup component add rustfmt` / `rustup component add clippy`
  2. `cargo fmt --manifest-path rust/Cargo.toml -- --check`
  3. `cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings`

- **Rust build+test (`rust:1.75`)**
  1. `cargo build --manifest-path rust/Cargo.toml`
  2. `cargo test --manifest-path rust/Cargo.toml`

> The Rust lint step pins the `rust:1.75` toolchain. Do **not** use
> `--toolchain stable` when adding components — that channel is not installed in the
> pinned image, so `cargo fmt` and `cargo clippy` would be unavailable.

### Running CI locally with Docker

To reproduce the pipeline locally, run any step with the matching image and mount:

```bash
# Python (any minor version)
docker run --rm -v "$PWD:/workspace" -w /workspace python:3.12-slim \
  sh -c 'pip install -e ".[dev]" && pytest && pip install ruff mypy && \
         ruff check . && ruff format --check . && mypy src/'

# Rust lint + build
docker run --rm -v "$PWD:/workspace" -w /workspace rust:1.75 \
  sh -c 'rustup component add rustfmt clippy && \
         cargo fmt --manifest-path rust/Cargo.toml -- --check && \
         cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings && \
         cargo build --manifest-path rust/Cargo.toml && \
         cargo test --manifest-path rust/Cargo.toml'
```

See [Testing Guide](testing.md#continuous-integration) for the full step table and
linting notes.

## Documentation

### Updating Documentation

Documentation is in the `docs/` directory:

- `architecture.md` - Architecture details
- `installation.md` - Installation instructions
- `cli.md` - CLI reference
- `configuration.md` - Configuration guide
- `security.md` - Security documentation
- `attack-modes.md` - Attack mode details
- `proxy-support.md` - Proxy documentation
- `output-formats.md` - Output format documentation
- `testing.md` - Testing guide
- `troubleshooting.md` - Troubleshooting guide
- `development.md` - This file

### Building Documentation

Currently, documentation is plain Markdown. To add static site generation:

```bash
# Install MkDocs
pip install mkdocs

# Build
mkdocs build

# Serve
mkdocs serve
```

## Security Considerations for Developers

### Credential Handling

- Never commit credentials to version control
- Use environment variables for sensitive data
- Document security implications of changes

### Code Review

- Review all changes for security implications
- Pay special attention to:
  - Input validation
  - Output encoding
  - Credential handling
  - Resource cleanup

### Testing Security

- Test with various malicious inputs
- Test resource limits
- Test error conditions
- Test with untrusted proxies

## Release Process

### Pre-Release Checklist

- [ ] All tests passing
- [ ] Documentation updated
- [ ] Version number updated
- [ ] CHANGELOG.md updated
- [ ] No sensitive data in code
- [ ] Code reviewed
- [ ] Tested on target platforms

### Release Steps

1. Update version in `__init__.py` and `pyproject.toml`
2. Update CHANGELOG.md
3. Commit changes
4. Create git tag
5. Build distributions
6. Upload to PyPI (if applicable)

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.

## Resources

- [Python 3.11 Documentation](https://docs.python.org/3.11/)
- [asyncio Documentation](https://docs.python.org/3.11/library/asyncio.html)
- [pytest Documentation](https://docs.pytest.org/)
- [ruff Documentation](https://docs.astral.sh/ruff/)

## See Also

- [Architecture Documentation](architecture.md) - Understanding the codebase
- [Testing Guide](testing.md) - Test suite details
- [CONTRIBUTING.md](../CONTRIBUTING.md) - Contribution guidelines
