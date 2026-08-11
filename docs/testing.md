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
pytest --cov=torshammer --cov-report=html
```

**Note:** Coverage reporting requires `pytest-cov` (not currently in dependencies).

## Test Structure

```
tests/
├── conftest.py          # Shared fixtures
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

**Tests:**
- `test_profile_sends_bytes` - All profiles send data
- `test_profile_honors_pre_set_stop` - Profiles respect stop signal
- `test_slow_read_consumes_response` - Slow-read mode
- `test_engine_runs_and_stops_cleanly` - Engine lifecycle
- `test_engine_stops_via_event` - Event-based stopping

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


@pytest.mark.parametrize("mode", ["slow-post", "slow-headers", "slow-read", "chunked"])
async def test_profile_respects_config(slow_server, mode):
    """Test that profiles respect configuration parameters."""
    cfg = _cfg(slow_server, delay_min=0.5, delay_max=0.5)
    stats = await _drive(PROFILES[mode], cfg, run_for=0.3)
    # With 0.5s delay and 0.3s runtime, should send limited data
    assert stats.bytes_sent < 1000
```

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

**Note:** This project does not currently have CI/CD configuration.

To add CI, consider:

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -e ".[dev]"
      - run: pytest
```

## Test Coverage

To check test coverage:

```bash
# Install coverage tool
pip install pytest-cov

# Run tests with coverage
pytest --cov=torshammer --cov-report=html

# View report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

**Note:** Coverage is not currently enforced or tracked.

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
