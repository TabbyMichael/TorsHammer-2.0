# Proxy Support Documentation

## Overview

Torshammer 2.0 supports multiple proxy protocols for traffic anonymization and distribution: SOCKS5, SOCKS4a, and HTTP CONNECT. This enables testing through Tor networks, corporate proxies, or distributed proxy pools.

## Supported Proxy Types

| Protocol | Scheme | Authentication | TLS Support | DNS Resolution |
|----------|--------|----------------|-------------|----------------|
| SOCKS5 | `socks5://` | Username/password | Yes (via CONNECT) | Remote or local |
| SOCKS4a | `socks4://` | Username only | No | Remote |
| HTTP CONNECT | `http://` | Basic auth | Yes (via CONNECT) | Local |

## Configuration

### Single Proxy

Use the `--proxy` flag:

```bash
torshammer -u http://example.com --proxy socks5://127.0.0.1:9050
```

### Proxy List

Use the `--proxy-list` flag with a file containing one proxy URL per line:

```bash
torshammer -u http://example.com --proxy-list proxies.txt
```

**File Format (`proxies.txt`):**
```
# Comments start with #
socks5://127.0.0.1:9050
http://proxy.example.com:8080
socks5://user:pass@10.0.0.1:1080
```

### Proxy Rotation

Use `--rotate-proxies` to select a random proxy for each connection:

```bash
torshammer -u http://example.com --proxy-list proxies.txt --rotate-proxies
```

**Without rotation:** Proxies used in round-robin order
**With rotation:** Random proxy selected per connection

### Tor Integration

Use the `--tor` flag for quick Tor setup:

```bash
torshammer -u http://example.com --tor
```

This is equivalent to:
```bash
torshammer -u http://example.com --proxy socks5://127.0.0.1:9050
```

**Requirements:** Tor must be running on `127.0.0.1:9050`. See [Installation Guide](installation.md#tor-installation-optional).

## Proxy URL Syntax

### SOCKS5

**Basic:**
```
socks5://host:port
socks5://127.0.0.1:9050
```

**With Authentication:**
```
socks5://username:password@host:port
socks5://user:pass@127.0.0.1:9050
```

**Default Port:** 1080 (if not specified)

### SOCKS4a

**Basic:**
```
socks4://host:port
socks4://127.0.0.1:1080
```

**With Username:**
```
socks4://username@host:port
socks4://user@127.0.0.1:1080
```

**Default Port:** 1080 (if not specified)

**Note:** SOCKS4a supports remote DNS resolution (the proxy resolves hostnames).

### HTTP CONNECT

**Basic:**
```
http://host:port
http://proxy.example.com:8080
```

**With Authentication:**
```
http://username:password@host:port
http://user:pass@proxy.example.com:8080
```

**Default Port:** 8080 (if not specified)

**Note:** HTTPS proxies are treated as HTTP CONNECT (the `https://` scheme is converted to `http://`).

### Short Form

If you omit the scheme, it defaults to `socks5`:

```
127.0.0.1:9050  # Equivalent to socks5://127.0.0.1:9050
```

## Proxy Authentication

### SOCKS5 Authentication

SOCKS5 supports username/password authentication:

```bash
torshammer -u http://example.com --proxy socks5://user:pass@proxy:9050
```

**Authentication Flow:**
1. Client sends supported authentication methods
2. Server selects method (no-auth or username/password)
3. If username/password selected, client sends credentials
4. Server validates and responds

**Limitations:**
- Username max 255 characters
- Password max 255 characters
- Credentials sent in clear (use with TLS proxy)

### SOCKS4 Authentication

SOCKS4 supports username only (no password):

```bash
torshammer -u http://example.com --proxy socks4://user@proxy:1080
```

**Note:** SOCKS4 authentication is not standardized and may not be supported by all proxies.

### HTTP CONNECT Authentication

HTTP CONNECT uses Basic authentication:

```bash
torshammer -u http://example.com --proxy http://user:pass@proxy:8080
```

**Authentication Flow:**
1. Client sends `CONNECT target:port HTTP/1.1`
2. Client includes `Proxy-Authorization: Basic <base64>`
3. Server validates and responds with `200 Connection Established`

**Note:** Credentials are base64-encoded (not encrypted). Use with HTTPS proxy or trusted network.

## TLS with Proxies

### HTTPS Targets

When targeting HTTPS through a proxy:

1. Client connects to proxy
2. Client performs proxy handshake (SOCKS5/HTTP CONNECT)
3. Client upgrades connection to TLS via `start_tls()`
4. Client performs TLS handshake with target
5. Encrypted data flows through proxy tunnel

**SNI Support:** The target hostname is sent via SNI during TLS handshake.

### Proxy TLS

Torshammer does **not** support TLS to the proxy itself. It assumes:

- SOCKS5 proxies are on trusted networks or use other encryption
- HTTP proxies are on trusted networks or use HTTPS (which is treated as HTTP CONNECT)

**Recommendation:** Use Tor for end-to-end encryption.

## Tor Integration

### Basic Tor Usage

```bash
# Start Tor
sudo systemctl start tor  # Linux
brew services start tor   # macOS

# Run Torshammer through Tor
torshammer -u http://example.com --tor
```

### Tor Verification

Verify Tor is working:

```bash
# Test Tor connection
curl --socks5 127.0.0.1:9050 https://check.torproject.org

# Should show Tor exit node information
```

### Tor with Multiple Circuits

Use proxy rotation to distribute across multiple Tor circuits:

```bash
# Requires multiple Tor instances or Tor with multiple circuits
torshammer -u http://example.com --proxy-list tor-proxies.txt --rotate-proxies
```

**Note:** Standard Tor on `127.0.0.1:9050` uses a single circuit. To use multiple circuits, you need multiple Tor instances on different ports.

### Tor Configuration

**Tor Configuration (`/etc/tor/torrc`):**

```
SocksPort 9050
ControlPort 9051
```

**Multiple Tor Instances:**

```
# Instance 1
SocksPort 9050
ControlPort 9051
DataDirectory /var/lib/tor1

# Instance 2
SocksPort 9051
ControlPort 9052
DataDirectory /var/lib/tor2
```

## Proxy Pool Management

### Round-Robin Selection

Default behavior when using proxy list:

```bash
torshammer -u http://example.com --proxy-list proxies.txt
```

**Behavior:**
- Connection 1: proxy1
- Connection 2: proxy2
- Connection 3: proxy3
- Connection 4: proxy1 (cycles back)

### Random Selection

With `--rotate-proxies`:

```bash
torshammer -u http://example.com --proxy-list proxies.txt --rotate-proxies
```

**Behavior:**
- Connection 1: random proxy from list
- Connection 2: random proxy from list
- Connection 3: random proxy from list

**Use Cases:**
- Distributing load across multiple Tor circuits
- Avoiding single proxy rate limits
- Geolocation distribution

### Proxy Pool Example

```python
from torshammer.proxies import Proxy, ProxyPool

proxies = [
    Proxy.from_url("socks5://proxy1.example.com:9050"),
    Proxy.from_url("socks5://proxy2.example.com:9050"),
    Proxy.from_url("http://proxy3.example.com:8080"),
]

# Round-robin
pool = ProxyPool(proxies, rotate=False)

# Random
pool = ProxyPool(proxies, rotate=True)
```

## Troubleshooting Proxies

### Connection Refused

**Error:** `ConnectionRefusedError: [Errno 111] Connection refused`

**Causes:**
- Proxy not running
- Wrong proxy port
- Firewall blocking connection

**Solutions:**
```bash
# Check if proxy is running
netstat -an | grep 9050  # Linux
lsof -i :9050           # macOS

# Test proxy with curl
curl --proxy socks5://127.0.0.1:9050 http://example.com
```

### Authentication Failed

**Error:** `ProxyConnectError: SOCKS5 authentication failed`

**Causes:**
- Wrong username/password
- Proxy doesn't support authentication
- Proxy requires different method

**Solutions:**
- Verify credentials
- Check proxy documentation
- Try without authentication

### Timeout

**Error:** `TimeoutError: Connection timeout`

**Causes:**
- Proxy too slow
- Network issues
- Proxy overloaded

**Solutions:**
- Increase `--connect-timeout`
- Try different proxy
- Check network connectivity

### Proxy Rejects Connection

**Error:** `ProxyConnectError: SOCKS5 connect failed (reply 5)`

**Causes:**
- Proxy拒绝连接 (SOCKS5 reply 5)
- Target blocked by proxy
- Proxy ACL restrictions

**Solutions:**
- Check proxy ACL rules
- Verify target is allowed
- Try different target

### DNS Resolution Issues

**Error:** Proxy can't resolve hostname

**Causes:**
- SOCKS4 without remote DNS
- Proxy DNS issues

**Solutions:**
- Use SOCKS5 (supports remote DNS)
- Use IP address instead of hostname
- Check proxy DNS configuration

## Security Considerations

### Credential Exposure

Proxy credentials are passed in URLs:

```bash
torshammer -u http://example.com --proxy socks5://user:pass@proxy:9050
```

**Risks:**
- Process listing may show credentials
- Shell history may store credentials
- Logs may capture credentials

**Mitigations:**
- Use environment variables (not supported by Torshammer yet)
- Clear shell history: `history -c`
- Use read-only credentials when possible

### Proxy Trust

When using a proxy, the proxy operator can see:
- Target hostnames/IPs
- Traffic patterns
- Timing information
- (Potentially) Content if not using TLS

**Recommendations:**
- Use Tor for strong privacy
- Use trusted proxy operators
- Use HTTPS targets when possible
- Assume proxy traffic is observable

### Proxy Logging

Proxies may log:
- Connection timestamps
- Source IPs
- Target hosts
- Authentication attempts
- Traffic volume

**Recommendations:**
- Review proxy logging policies
- Use proxies with no-logging policies
- Assume logs may be retained

## Performance Considerations

### Proxy Overhead

Proxies add latency:
- Connection setup: Additional RTT
- Data transfer: Additional hop
- TLS: Additional handshake

**Impact:** Slower connection establishment, slightly reduced throughput.

### Proxy Capacity

Proxies have limits:
- Maximum concurrent connections
- Bandwidth limits
- CPU limits

**Symptoms of Overload:**
- Increased timeouts
- Connection failures
- Slow performance

**Solutions:**
- Use multiple proxies
- Reduce concurrency per proxy
- Monitor proxy performance

### Proxy Rotation Overhead

Random proxy selection adds overhead:
- Need to maintain proxy pool
- Potential connection reuse issues

**Recommendation:** Use round-robin for consistent performance, random for distribution.

## Example Configurations

### Corporate Proxy

```bash
torshammer -u http://internal-server \
  --proxy http://proxy.corp.com:8080 \
  --proxy-list corp-proxies.txt \
  --rotate-proxies
```

### Tor Anonymization

```bash
torshammer -u http://example.com --tor
```

### Distributed Testing

```bash
torshammer -u http://example.com \
  --proxy-list distributed-proxies.txt \
  --rotate-proxies \
  -c 512
```

### Multi-Region Testing

```bash
# proxies.txt contains proxies from different regions
torshammer -u http://example.com \
  --proxy-list regional-proxies.txt \
  --rotate-proxies
```

## Proxy File Examples

### Example: `proxies.txt`

```
# Tor instances
socks5://127.0.0.1:9050
socks5://127.0.0.1:9051
socks5://127.0.0.1:9052

# HTTP proxies
http://proxy1.example.com:8080
http://proxy2.example.com:8080

# SOCKS5 with authentication
socks5://user1:pass1@proxy3.example.com:9050
socks5://user2:pass2@proxy4.example.com:9050
```

### Example: `tor-proxies.txt`

```
# Multiple Tor instances on different ports
socks5://127.0.0.1:9050
socks5://127.0.0.1:9051
socks5://127.0.0.1:9052
socks5://127.0.0.1:9053
```

## See Also

- [Configuration Guide](configuration.md) - Proxy configuration details
- [CLI Reference](cli.md) - Proxy command-line options
- [Security Documentation](security.md) - Proxy security considerations
- [Architecture Documentation](architecture.md) - Proxy implementation details
