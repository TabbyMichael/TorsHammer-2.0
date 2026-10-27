# Testing Guide

## Overview

Torshammer 2.0 includes a comprehensive test suite built with pytest. The tests use custom fixtures to simulate slow servers and SOCKS5 proxies, enabling safe, isolated testing without external dependencies.

## Test Framework

### Framework: pytest

Torshammer uses pytest as its test framework with pytest-asyncio for async test support.

**Dependencies:**
```toml
[project.optional-dependencies]
dev = ["pytest>=8", "pytest-asyncio>=0.23"]
```

### Configuration

Test configuration in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
```

## Installing Test Dependencies

```bash
# Install development dependencies
pip install -e ".[dev]"
```

## Running Tests

### Run All Tests

```bash
pytest
```

### Run with Verbose Output

```bash
pytest -v
```

### Run Specific Test File

```bash
pytest tests/test_cli.py
```

### Run Specific Test

```bash
pytest tests/test_cli.py::test_parse_https_url
```

### Run with Coverage

```bash
pytest --cov=src/torshammer --cov-report=html
```

**Note:** Coverage is enabled automatically — `pytest-cov` is part of the `dev`
extra (`pip install -e ".[dev]"`) and `pyproject.toml` wires
`addopts = "--cov=src/torshammer --cov-report=term-missing --cov-fail-under=100"`,
so a plain `pytest` run already measures coverage and **fails below 100%**.
See [Coverage policy](#coverage-policy) below.

## Test Structure

```
tests/
├── conftest.py          # Shared fixtures
├── test_banner.py       # Shared banner artwork tests
├── test_cli.py          # CLI argument parsing tests
├── test_conn.py         # Connection factory tests
├── test_profiles.py     # Attack profile tests
└── test_proxies.py      # Proxy parsing tests
```

## Test Fixtures

### SlowServer Fixture

**Purpose:** Simulates a web server that accepts connections but never responds (or responds slowly).

**Location:** `tests/conftest.py`

**Behavior:**
- Accepts TCP connections
- Reads data from clients
- Never sends responses (unless configured)
- Keeps connections open

**Configuration:**
- `respond_body`: Optional bytes to send (for slow-read mode testing)
- `bytes_received`: Tracks total bytes received
- `connections`: Tracks total connections
- `active`: Tracks currently active connections

**Usage:**
```python
async def test_something(slow_server):
    cfg = Config(host="127.0.0.1", port=slow_server.port)
    # Test against slow_server
```

### FakeSocks5 Fixture

**Purpose:** Simulates a SOCKS5 proxy for testing proxy handshakes.

**Location:** `tests/conftest.py`

**Behavior:**
- Implements SOCKS5 no-auth handshake
- Records connection targets
- Maintains tunnel until client closes
- Returns success response

**Configuration:**
- `targets`: List of (host, port) tuples requested by clients

**Usage:**
```python
async def test_socks5_handshake(fake_socks5):
    proxy = Proxy("socks5", "127.0.0.1", fake_socks5.port)
    # Test against fake_socks5
```

### FlakyServer Fixture

**Purpose:** Exercises the per-profile error/dribble arms. Unlike `SlowServer`
(a connection lives forever), `flaky_server` accepts a connection, reads up to a
configurable byte budget, then **hard-closes mid-stream**. Every TCP profile's
`except (ConnectionError, OSError)` reconnect/dribble branch fires against it,
which is what drives profile error-path coverage in
`tests/test_profiles_coverage.py`.

**Location:** `tests/conftest.py`

**Usage:**
```python
async def test_profile_survives_midstream_close(flaky_server):
    cfg = _cfg(flaky_server, mode="slow-post", ...)
    stats = await _drive(PROFILES["slow-post"], cfg, run_for=0.2)
    assert stats.bytes_sent > 0
```

## Test Files

### test_cli.py

**Purpose:** Test CLI argument parsing and configuration resolution.

**Tests:**
- `test_parse_https_url` - HTTPS URL parsing
- `test_parse_http_url_with_custom_port` - HTTP with custom port
- `test_legacy_host_flags` - Legacy flag compatibility
- `test_tor_flag_adds_socks5_proxy` - Tor flag behavior
- `test_ssl_no_verify` - SSL verification bypass
- `test_mode_choice_validation` - Mode validation

**Example:**
```python
def test_parse_https_url():
    args = build_parser().parse_args(["-u", "https://example.com/api?x=1", "-c", "512"])
    cfg = _resolve_config(args)
    assert cfg.host == "example.com"
    assert cfg.port == 443
    assert cfg.secure is True
```

### test_banner.py

**Purpose:** Guard the shared startup banner artwork.

`assets/banner.txt` at the repository root is the single source of truth. The Python package ships a
byte-identical copy as `src/torshammer/banner.txt` (package data must live inside the package) and
the Rust engine embeds the canonical file at compile time (`rust/src/cli/banner.rs` →
`include_str!("../../../assets/banner.txt")`). These tests fail if the copies ever drift apart, if
the six artwork rows stop lining up, or if the placeholders the CLI substitutes are renamed.

**Tests:**
- `test_packaged_banner_matches_canonical_asset` - `src/torshammer/banner.txt` is byte-equal to `assets/banner.txt`
- `test_rust_engine_embeds_the_canonical_asset` - the Rust banner uses `include_str!` on the shared asset
- `test_placeholders_are_exactly_the_ones_the_cli_substitutes` - only `{VER}`, `{TARGET}`, `{BACKEND}`, `{MODE}`, `{CONCURRENCY}` appear
- `test_artwork_is_six_uniformly_padded_rows` - the wordmark keeps six equally wide rows
- `test_cli_banner_renders_artwork_and_run_config` - formatting produces the documented layout
- `test_resource_fallback_banner_is_substitutable` - the missing-package-data fallback still formats

### test_conn.py

**Purpose:** Test connection factory (direct and proxied connections).

**Tests:**
- `test_direct_connect` - Direct TCP connection
- `test_socks5_handshake` - SOCKS5 proxy handshake
- `test_socks5_domain_connect` - SOCKS5 with domain name

**Example:**
```python
async def test_direct_connect(slow_server):
    cfg = Config(host="127.0.0.1", port=slow_server.port, connect_timeout=3)
    reader, writer = await conn.open_connection("127.0.0.1", slow_server.port, config=cfg)
    writer.write(b"hello")
    await writer.drain()
    writer.close()
    await writer.wait_closed()
    assert slow_server.bytes_received == 5
```

### test_profiles.py

**Purpose:** Test attack profiles and engine integration.

The `tests/test_profiles.py` suite drives every profile in the `PROFILES` registry (fourteen TCP
profiles), checking each one sends the protocol-specific bytes it is supposed to and honours a
pre-set stop event. The `udp` mode is covered separately by `tests/test_udp.py` (real datagrams
against a loopback receiver).

**Tests:**
- `test_profile_sends_bytes` - Parameterised across the TCP profiles: every profile sends data
- `test_registry_matches_documented_modes` - Registry matches the canonical `tests/mode_list.txt`
- `test_profile_honors_pre_set_stop` - Profiles respect stop signal
- `test_slow_read_consumes_response` - Slow-read mode
- `test_engine_runs_and_stops_cleanly` - Engine lifecycle
- `test_engine_stops_via_event` - Event-based stopping
- `test_websocket_slow_upgrade_sends_websocket_headers` - WebSocket upgrade headers present
- `test_http_pipelining_sends_multiple_requests` - Multiple pipelined requests on one connection
- `test_range_abuse_sends_range_headers` - Randomized `Range:` headers
- `test_cookie_bomb_sends_large_cookie` - Oversized `Cookie` header
- `test_jsonrpc_slow_sends_json_content` - JSON-RPC payload bytes
- `test_smtp_slow_envelope_sends_smtp_commands` - SMTP envelope commands
- `test_ftp_slow_command_sends_ftp_commands` - FTP commands
- `test_multipart_slow_upload_sends_multipart_preamble` - Multipart framing, no closing boundary
- `test_expect_continue_abuse_announces_body_and_stalls` - `Expect:` announced body, stalled

**Example:**
```python
async def test_engine_runs_and_stops_cleanly(slow_server):
    cfg = _cfg(
        slow_server,
        concurrency=4,
        mode="slow-post",
        delay_min=0,
        delay_max=0.02,
        base_post_length=256,
        duration=0.4,
        quiet=True,
    )
    engine = AttackEngine(cfg, asyncio.Event())
    await engine.run()
    assert engine.stats.connections > 0
    assert engine.stats.errors == 0
    assert engine.stats.active == 0
```

### test_proxies.py

**Purpose:** Test proxy parsing and rotation.

**Tests:**
- `test_parse_socks5_with_credentials` - SOCKS5 with auth
- `test_parse_default_scheme_and_port` - Default values
- `test_parse_socks4_and_http_defaults` - SOCKS4/HTTP defaults
- `test_parse_https_is_treated_as_connect` - HTTPS → HTTP
- `test_invalid_scheme_rejected` - Scheme validation
- `test_pool_round_robin` - Round-robin selection
- `test_pool_empty_returns_none` - Empty pool handling

**Example:**
```python
def test_parse_socks5_with_credentials():
    proxy = Proxy.from_url("socks5://user:pa:ss@1.2.3.4:9050")
    assert proxy.scheme == "socks5"
    assert proxy.host == "1.2.3.4"
    assert proxy.port == 9050
    assert proxy.username == "user"
    assert proxy.password == "pa:ss"
```

## Writing Tests

### Adding a New Test

1. **Choose appropriate test file** based on what you're testing
2. **Use existing fixtures** (`slow_server`, `fake_socks5`) when applicable
3. **Follow naming convention** `test_<description>`
4. **Make tests async** if they use async/await
5. **Use pytest assertions** (`assert`)

### Example: New Connection Test

```python
# tests/test_conn.py


async def test_connection_timeout(slow_server):
    """Test that connection timeout is enforced."""
    cfg = Config(
        host="127.0.0.1",
        port=slow_server.port,
        connect_timeout=0.001,  # Very short timeout
    )
    with pytest.raises((asyncio.TimeoutError, ConnectionError)):
        await asyncio.sleep(0.1)  # Ensure timeout
        await conn.open_connection("127.0.0.1", slow_server.port, config=cfg)
```

### Example: New Profile Test

```python
# tests/test_profiles.py


@pytest.mark.parametrize("mode", sorted(PROFILES))
async def test_profile_respects_config(slow_server, mode):
    """Test that profiles respect configuration parameters."""
    cfg = _cfg(slow_server, delay_min=0.5, delay_max=0.5)
    stats = await _drive(PROFILES[mode], cfg, run_for=0.3)
    # With 0.5s delay and 0.3s runtime, should send limited data
    assert stats.bytes_sent < 1000
```

The real suite lists the modes explicitly (including `"slow-post-headers"` and every
protocol-specific mode) so a newly added profile cannot silently lose coverage; keep that list in
sync when you add a mode to `PROFILES`.

## Test Best Practices

### Isolation

Each test should be independent:
- Don't rely on test execution order
- Clean up resources in `finally` blocks
- Use fixtures for shared setup

### Async Tests

- Use `async def` for async tests
- Use `pytest.mark.asyncio` if needed (not required with `asyncio_mode = "auto"`)
- Handle async exceptions properly

### Assertions

- Use specific assertions for clarity
- Test both success and failure cases
- Assert on important state, not implementation details

### Fixtures

- Use fixtures for shared test infrastructure
- Keep fixtures simple and focused
- Document fixture behavior

## Continuous Integration

This project uses **GitHub Actions** for continuous integration.

**Workflow location:** `.github/workflows/ci.yml`

The GitHub Actions workflow runs automatically on:
- Push to the `main` branch
- Pull requests targeting the `main` branch

**Workflow configuration:**

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ['3.11', '3.12', '3.13']

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"

      - name: Run tests
        run: |
          pytest

      - name: Run ruff check
        run: |
          pip install ruff
          ruff check .

      - name: Run ruff format check
        run: |
          ruff format --check .

      - name: Run mypy
        run: |
          pip install mypy
          mypy src/
```

**Note:** CI workflows live in `.github/workflows/` (`ci.yml`, `release.yml`,
`soak.yml`).

## Soak Testing (opt-in)

Sustained high-concurrency behaviour is covered by an opt-in script rather
than the merge gate:

```bash
# Local run (defaults: -c 500, 30s, slow-headers)
python scripts/soak.py
python scripts/soak.py --concurrency 2000 --duration 120
SOAK_CONCURRENCY=200 SOAK_DURATION=10 python scripts/soak.py
```

It starts a local asyncio sink, runs the real CLI against it, and asserts a
clean process exit with no socket over-subscription (`peak_active`/`active`
must not exceed `-c`, and `connections > 0`). The script self-skips (exit 0)
when the requested concurrency exceeds 80% of the runner's `RLIMIT_NOFILE`,
so it is safe to schedule nightly — `.github/workflows/soak.yml` does exactly
that, plus a manual `workflow_dispatch` trigger.

## Test Coverage

Coverage is measured and **enforced on every `pytest` run**. `pyproject.toml`
sets `addopts = "--cov=src/torshammer --cov-report=term-missing
--cov-fail-under=100"`, so the suite exits non-zero if line coverage drops below
100%. `pytest-cov` ships with the `dev` extra, so no separate install is needed:

```bash
# Install the development extras (pytest, pytest-asyncio, pytest-cov, mypy)
pip install -e ".[dev]"

# Coverage runs automatically with the suite and fails below 100%
pytest

# Opt into an HTML report as well
pytest --cov-report=html
open htmlcov/index.html      # macOS
xdg-open htmlcov/index.html  # Linux
```

When working on a single module you can raise the bar or silence it for a local
run with `pytest -o addopts=""` (skips the coverage gate) — but CI always
enforces it.

## Coverage policy

The Python backend holds a **100% line-coverage** target on `src/torshammer`.
Every line is either executed by the suite or carries a written, auditable
justification. Two families of tests do most of the structural work:

- **Mode-parametrized profile harness** (`tests/test_profiles_coverage.py`):
  a single `@pytest.mark.parametrize` pass runs every TCP profile in
  `settings.all_modes()` against the live `slow_server` fixture (success path)
  and again against the `flaky_server` fixture (error/dribble path). Adding a
  new mode automatically inherits coverage of the send/loop/except arms, so a
  new profile cannot silently ship untested.
- **Real end-to-end CLI + cluster tests** (`tests/test_main_e2e.py`,
  `tests/test_cluster_edges.py`): these drive `torshammer.cli.main` and
  `cluster.run_worker` for real rather than patching them out, so the entry
  point, the RPC handler arms and the master/worker orchestration are genuinely
  exercised.

### Coverage exclusions

Genuinely non-executable code is excluded with an inline
`# pragma: no cover - <reason>` marker rather than being faked. Every exclusion
is listed here so both backends stay auditable in one place.

Python (`src/torshammer`):

| Location | Lines | Reason |
|---|---|---|
| `cli.py` | `import resource` fallback | POSIX-only module; dead on the Windows interpreters this branch exists for |
| `cluster.py` | `_install_stop_handler` `except` | `add_signal_handler` raises `NotImplementedError`/`RuntimeError` only on Windows |
| `dispatch.py` | `return 0` after `os.execv` | on POSIX `execv` only returns on failure; the failure path is covered by a test |
| `profiles.py` | H2 stream-id wraparound | reaching it needs ~2^31 streams in one run - a defensive overflow guard, not a reachable state |

Rust (`rust/src`) exclusions are registered under [Coverage exclusions -
Rust](#coverage-exclusions---rust) below.

### Rust backend coverage

The Rust engine is measured with [`cargo-llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov)
and held to **100% lines** on `rust/src`. Run it with the rustup toolchain on
`PATH` to avoid the distro-toolchain corrupt-metadata (E0786) failure:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cd rust
cargo llvm-cov --all-targets --summary-only
cargo llvm-cov --all-targets --show-missing-lines   # per-file uncovered lines
cargo llvm-cov --all-targets --lcov --output-path target/llvm-cov/lcov.info
```

#### Enforcing the gate (why not `--fail-under-lines 100`)

`make rust-cov` (and both CI configs) enforce the Rust line target with an
**lcov-based zero-uncovered-line assertion** rather than
`cargo llvm-cov --fail-under-lines 100`. The reason is a version-specific
accounting quirk, verified against cargo-llvm-cov 0.9.1 / LLVM 21 on this tree:

- The `lcov` export and `llvm-cov show` report **0** uncovered statement lines
  for every file in `rust/src` (all executable lines are hit; functions are
  100%; e.g. `engine/mod.rs` = 531 `DA:` records, **0** with a `0` count).
- `llvm-cov report` — the metric `--fail-under-lines` reads — *additionally*
  attributes **12** already-executed continuation / closing-brace lines
  (`engine/mod.rs` 10, `main.rs` 2) as uncovered. Those lines are not even
  statements in the `lcov`/`show` line model, so **no test can cover them and no
  code restructure removes them** (verified: inlining generic bounds, hoisting
  multi-line calls, and toggling the `#[cfg(not(coverage))]` monitor poll all
  leave the count at 12; `--show-missing-lines` cannot enumerate them).

This is a discrepancy internal to the toolchain (`show`/`lcov` agree at 100%,
`report` lags at 99.79%), not a real gap in the suite. cargo-llvm-cov 0.9.1
provides **no per-line/per-region exclude selector** — only whole-file
`--ignore-filename-regex` and package-level `--exclude` — so the phantom lines
cannot be excluded at line granularity without dropping ~1,280 genuinely covered
lines from the two modules. Enforcing on the `lcov` model (the one that correctly
counts every real statement) is therefore the honest gate. A `--fail-under-lines
99` report tripwire is kept alongside it so a real regression (not the fixed 12
phantoms) still fails CI.

#### Coverage exclusions - Rust

Platform-gated code that is simply not compiled on the measurement host never
appears in the report (no marker needed) — e.g. the `#[cfg(not(unix))]` module in
`engine/signals.rs` (L39) and the `#[cfg(unix)]` install path (L16).

`#[cfg]`-independent, non-test-reachable regions are dropped from the
instrumented build with `#[cfg(not(coverage))]` (cargo-llvm-cov injects
`--cfg coverage`, so these compile out only under coverage yet stay live in
production). `#![allow(unexpected_cfgs)]` in `main.rs` keeps `clippy -D warnings`
clean about that external cfg. Registered sites:

| File | Site | Reason |
|---|---|---|
| `engine/mod.rs` | monitor-loop mid-poll `shutdown_requested()` check | responsiveness-only Ctrl-C checkpoint; firing it needs a signal to land inside a 100ms window a bounded test cannot schedule. Interval-granular shutdown is covered by the post-loop check. |
| `engine/profiles.rs` (L1023) | H2 `stream_id > 0x7FFF_FFF0` recycle | needs ~2^31 RST frames in one run — a defensive overflow guard, unreachable in the test budget |
| `engine/profiles.rs` (L1233, L1316, L1323) | narrow `should_stop()` early-exits | the surrounding loop/write-abort path already drives the stop route; these micro-exits can't be scheduled deterministically |
| `engine/profiles.rs` (L1293) | `Expect`-header defensive filter | forces a state the harness can't produce (custom `Expect` header colliding with the built one) |
| `main.rs` (L501) | `process::exit(run())` in `fn main()` | would terminate the test runner; `main()` is exercised by the black-box `rust/tests/cli.rs` harness (`CARGO_BIN_EXE_…`), not in-process unit coverage |

Additionally, the 12 `report`-model phantom lines (`engine/mod.rs` ×10,
`main.rs` ×2) described above are accepted as a toolchain artifact and are the
reason the gate is enforced on the `lcov` line model rather than `--fail-under-lines 100`.


## Troubleshooting Tests

### Tests Hang

**Problem:** Tests hang indefinitely

**Causes:**
- Async deadlock
- Missing cleanup
- Fixture not tearing down

**Solutions:**
- Add timeouts to async operations
- Ensure resources are closed in `finally` blocks
- Check fixture teardown

### Fixture Not Found

**Problem:** `pytest` can't find fixture

**Causes:**
- Fixture not in `conftest.py`
- Fixture name typo
- Wrong scope

**Solutions:**
- Define fixture in `conftest.py`
- Check fixture name spelling
- Ensure fixture is in correct directory

### Async Tests Not Running

**Problem:** Async tests not collected or run

**Causes:**
- Missing `pytest-asyncio`
- Wrong `asyncio_mode`
- Not using `async def`

**Solutions:**
- Install `pytest-asyncio>=0.23`
- Check `asyncio_mode = "auto"` in config
- Use `async def` for async tests

### Port Already in Use

**Problem:** Tests fail with "Address already in use"

**Causes:**
- Previous test didn't clean up
- Fixture port conflict
- Another process using port

**Solutions:**
- Ensure fixtures close servers properly
- Use port 0 for automatic port selection
- Kill processes using the port

## Running Tests in Development

### Watch Mode

For continuous testing during development:

```bash
# Install pytest-watch
pip install pytest-watch

# Run tests on file changes
ptw
```

### Debug Mode

To debug a failing test:

```bash
# Run with pdb on failure
pytest --pdb

# Run specific test in debugger
pytest tests/test_cli.py::test_parse_https_url --pdb
```

### Verbosity

For detailed test output:

```bash
pytest -vv --tb=long
```

## Test Data

### Example Files

The project includes example files for testing:

- `examples/proxies.txt` - Example proxy list format
- `examples/user-agents.txt` - Example User-Agent format

These can be used in tests or for manual testing.

## See Also

- [Development Guide](development.md) - Development setup and workflow
- [Architecture Documentation](architecture.md) - Understanding the codebase
- [CLI Reference](cli.md) - CLI option testing
