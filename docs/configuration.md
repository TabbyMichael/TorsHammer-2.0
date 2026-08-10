# Configuration Guide

## Overview

Torshammer 2.0 uses a centralized configuration dataclass (`Config`) that aggregates all runtime parameters. Configuration is primarily set via command-line arguments, but can also be programmatically constructed for testing and integration.

## Configuration Sources

### Primary: Command-Line Arguments

All configuration is set via CLI arguments. See [CLI Reference](cli.md) for complete option list.

### Secondary: Programmatic Construction

For testing and integration, the `Config` dataclass can be instantiated directly:

```python
from torshammer.config import Config

config = Config(
    host="example.com",
    port=80,
    concurrency=256,
    mode="slow-post",
)
```

### No Environment Variables

Torshammer 2.0 does **not** use environment variables for configuration. All settings must be specified via CLI arguments or programmatic construction.

## Config Dataclass

### Location

`src/torshammer/config.py`

### Fields

#### Target Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | `str` | *required* | Target hostname or IP address |
| `port` | `int` | *derived* | Target port (80 for HTTP, 443 for HTTPS) |
| `secure` | `bool` | `False` | Use HTTPS/TLS |
| `path` | `str` | `"/"` | HTTP path (including query string) |
| `header_host` | `str` | *derived* | Host header value (may include port) |

**Example:**
```python
config = Config(
    host="api.example.com",
    port=443,
    secure=True,
    path="/v1/endpoint",
    header_host="api.example.com",
)
```

#### Attack Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `concurrency` | `int` | `256` | Number of concurrent connections |
| `mode` | `str` | `"slow-post"` | Attack mode (`slow-post`, `slow-headers`, `slow-read`, `chunked`) |
| `base_post_length` | `int` | `4096` | Baseline Content-Length for post modes |
| `delay_min` | `float` | `0.1` | Minimum dribble delay (seconds) |
| `delay_max` | `float` | `3.0` | Maximum dribble delay (seconds) |
| `duration` | `float` | `0.0` | Auto-stop after N seconds (0 = unlimited) |

**Example:**
```python
config = Config(
    host="example.com",
    port=80,
    concurrency=512,
    mode="slow-headers",
    base_post_length=8192,
    delay_min=0.05,
    delay_max=1.0,
    duration=60.0,
)
```

#### Network Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `connect_timeout` | `float` | `15.0` | Connection timeout (seconds) |
| `ssl_verify` | `bool` | `True` | Verify TLS certificates |

**Example:**
```python
config = Config(
    host="example.com",
    port=443,
    secure=True,
    connect_timeout=30.0,
    ssl_verify=False,  # For self-signed certificates
)
```

#### Proxy Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `proxies` | `list[Proxy] \| None` | `None` | List of proxy endpoints |
| `rotate_proxies` | `bool` | `False` | Random proxy per connection |

**Example:**
```python
from torshammer.proxies import Proxy

config = Config(
    host="example.com",
    port=80,
    proxies=[
        Proxy("socks5", "127.0.0.1", 9050),
        Proxy("http", "proxy.example.com", 8080),
    ],
    rotate_proxies=True,
)
```

#### Output Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `user_agents` | `list[str]` | *internal list* | User-Agent strings to rotate |
| `stats_interval` | `float` | `1.0` | Statistics update interval (seconds) |
| `json_output` | `bool` | `False` | Emit JSON instead of terminal output |
| `quiet` | `bool` | `False` | Suppress terminal output |
| `verbose` | `int` | `0` | Verbosity level (0-2) |

**Example:**
```python
config = Config(
    host="example.com",
    port=80,
    user_agents=["CustomAgent/1.0"],
    stats_interval=5.0,
    json_output=True,
    quiet=True,
    verbose=1,
)
```

## Properties

### `server_hostname`

**Returns:** `str | None`

**Description:** Returns the SNI hostname for TLS connections, or `None` for plain HTTP.

**Example:**
```python
config = Config(host="example.com", port=443, secure=True)
assert config.server_hostname == "example.com"

config = Config(host="example.com", port=80, secure=False)
assert config.server_hostname is None
```

### Methods

### `random_delay()`

**Returns:** `float`

**Description:** Returns a random delay between `delay_min` and `delay_max`.

**Example:**
```python
config = Config(delay_min=0.1, delay_max=1.0)
delay = config.random_delay()  # Returns float between 0.1 and 1.0
```

### `ssl_context()`

**Returns:** `ssl.SSLContext | None`

**Description:** Creates and returns an SSL context for HTTPS targets. Returns `None` for HTTP targets.

**Behavior:**
- If `secure=False`: Returns `None`
- If `secure=True` and `ssl_verify=True`: Returns default SSL context with verification
- If `secure=True` and `ssl_verify=False`: Returns SSL context with verification disabled

**Example:**
```python
config = Config(host="example.com", port=443, secure=True, ssl_verify=True)
ctx = config.ssl_context()  # SSLContext with verification

config = Config(host="example.com", port=443, secure=True, ssl_verify=False)
ctx = config.ssl_context()  # SSLContext without verification
```

## Proxy Configuration

### Proxy Dataclass

**Location:** `src/torshammer/proxies.py`

**Fields:**
- `scheme` (`str`) - Proxy scheme: `socks5`, `socks4`, or `http`
- `host` (`str`) - Proxy hostname or IP
- `port` (`int`) - Proxy port
- `username` (`str | None`) - Optional username for authentication
- `password` (`str | None`) - Optional password for authentication

### Creating Proxies

#### From URL (Recommended)

```python
from torshammer.proxies import Proxy

# SOCKS5 (Tor default)
proxy = Proxy.from_url("socks5://127.0.0.1:9050")

# SOCKS5 with authentication
proxy = Proxy.from_url("socks5://user:pass@127.0.0.1:9050")

# HTTP CONNECT
proxy = Proxy.from_url("http://proxy.example.com:8080")

# HTTP CONNECT with authentication
proxy = Proxy.from_url("http://user:pass@proxy.example.com:8080")

# SOCKS4a
proxy = Proxy.from_url("socks4://127.0.0.1:1080")

# Default scheme (socks5) and port (9050)
proxy = Proxy.from_url("127.0.0.1:9050")
```

#### Direct Construction

```python
from torshammer.proxies import Proxy

proxy = Proxy(
    scheme="socks5",
    host="127.0.0.1",
    port=9050,
    username="user",
    password="pass",
)
```

### Proxy Pool

**Location:** `src/torshammer/proxies.py`

**Purpose:** Manages proxy selection strategy (round-robin or random rotation).

**Parameters:**
- `proxies` (`list[Proxy] | None`) - List of proxies
- `rotate` (`bool`) - If `True`, select random proxy per connection; if `False`, use round-robin

**Example:**
```python
from torshammer.proxies import Proxy, ProxyPool

proxies = [
    Proxy.from_url("socks5://proxy1.example.com:9050"),
    Proxy.from_url("socks5://proxy2.example.com:9050"),
    Proxy.from_url("http://proxy3.example.com:8080"),
]

# Round-robin selection
pool = ProxyPool(proxies, rotate=False)
assert pool.next().host == "proxy1.example.com"
assert pool.next().host == "proxy2.example.com"
assert pool.next().host == "proxy3.example.com"
assert pool.next().host == "proxy1.example.com"  # Cycles back

# Random selection
pool = ProxyPool(proxies, rotate=True)
proxy = pool.next()  # Random proxy from list
```

## User-Agent Configuration

### Default User-Agents

Torshammer includes a built-in list of modern User-Agent strings:

- Chrome (Windows, macOS, Linux)
- Firefox (Windows, Linux)
- Safari (macOS, iOS)
- Edge (Windows)
- Mobile browsers (Android, iOS)
- Googlebot

**Location:** `src/torshammer/useragents.py`

### Loading Custom User-Agents

```python
from torshammer.useragents import load_user_agents

# Load from file
user_agents = load_user_agents("user-agents.txt")

# Returns default list if file not provided
user_agents = load_user_agents(None)
```

**File Format:**
```
# Comments start with #
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...
```

**Behavior:**
- Blank lines are ignored
- Lines starting with `#` are treated as comments
- Falls back to default list if file is empty or not provided

## Configuration Examples

### Basic HTTP Test

```python
from torshammer.config import Config

config = Config(
    host="localhost",
    port=8080,
    secure=False,
    concurrency=256,
    mode="slow-post",
)
```

### HTTPS with Custom Timing

```python
from torshammer.config import Config

config = Config(
    host="api.example.com",
    port=443,
    secure=True,
    path="/v1/endpoint",
    concurrency=512,
    mode="slow-headers",
    delay_min=0.05,
    delay_max=1.0,
    duration=60.0,
)
```

### Through Tor

```python
from torshammer.config import Config
from torshammer.proxies import Proxy

config = Config(
    host="example.com",
    port=80,
    proxies=[Proxy("socks5", "127.0.0.1", 9050)],
)
```

### Through Proxy List with Rotation

```python
from torshammer.config import Config
from torshammer.proxies import Proxy, ProxyPool

proxies = [
    Proxy.from_url("socks5://proxy1.example.com:9050"),
    Proxy.from_url("socks5://proxy2.example.com:9050"),
    Proxy.from_url("http://proxy3.example.com:8080"),
]

config = Config(
    host="example.com",
    port=80,
    proxies=proxies,
    rotate_proxies=True,
)
```

### JSON Output for Monitoring

```python
from torshammer.config import Config

config = Config(
    host="example.com",
    port=80,
    json_output=True,
    quiet=True,
    stats_interval=5.0,
)
```

### Custom User-Agents

```python
from torshammer.config import Config
from torshammer.useragents import load_user_agents

config = Config(
    host="example.com",
    port=80,
    user_agents=load_user_agents("custom-uas.txt"),
)
```

### Self-Signed Certificate (Test Environment)

```python
from torshammer.config import Config

config = Config(
    host="self-signed.local",
    port=443,
    secure=True,
    ssl_verify=False,  # Only for test environments!
)
```

## Configuration Validation

The configuration is validated during construction in the CLI:

- **URL scheme:** Must be `http` or `https`
- **Hostname:** Required for URL-based targets
- **Port:** Must be valid integer (1-65535)
- **Concurrency:** Minimum 1 (enforced)
- **Mode:** Must be one of: `slow-post`, `slow-headers`, `slow-read`, `chunked`
- **Proxy scheme:** Must be one of: `socks5`, `socks4`, `http`

## Security Considerations

### Proxy Credentials

Proxy credentials are passed in URLs and stored in memory:

```python
# Credentials in URL (memory only)
proxy = Proxy.from_url("socks5://user:pass@host:9050")
```

**Recommendations:**
- Do not commit proxy URLs with credentials to version control
- Use environment variables for sensitive credentials in production
- Credentials are not logged or persisted

### TLS Verification

Disabling TLS verification is dangerous:

```python
config = Config(
    host="example.com",
    port=443,
    secure=True,
    ssl_verify=False,  # ⚠️ Security risk
)
```

**Recommendations:**
- Only disable verification in controlled test environments
- Use proper certificate authorities in production
- Self-signed certificates should be added to system trust store

### No Environment Variables

Torshammer does not use environment variables for configuration. This prevents:

- Accidental credential exposure via process environment
- Configuration drift between environments
- Secret leakage in process listings

All configuration must be explicitly provided via CLI or programmatic construction.

## Configuration Best Practices

### For Testing

```python
# Conservative settings for initial testing
config = Config(
    host="test.local",
    port=8080,
    concurrency=64,  # Start low
    duration=30,     # Time-limited
    delay_min=0.1,
    delay_max=1.0,
)
```

### For Production Assessment

```python
# Higher concurrency with monitoring
config = Config(
    host="target.example.com",
    port=443,
    secure=True,
    concurrency=512,
    json_output=True,  # For monitoring
    stats_interval=5.0,
    verbose=1,  # Error details
)
```

### For Anonymized Testing

```python
# Use Tor with rotation
config = Config(
    host="example.com",
    port=80,
    proxies=[Proxy("socks5", "127.0.0.1", 9050)],
    rotate_proxies=True,  # If using proxy list
)
```

## See Also

- [CLI Reference](cli.md) - Command-line option mapping
- [Proxy Support](proxy-support.md) - Detailed proxy configuration
- [Architecture Documentation](architecture.md) - How configuration flows through the system
