# Tor's Hammer 2.0

![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-GPL--2.0--or--later-green)

Modern slow-requests **vulnerability testing** tool, rewritten from the
classic 2011 Tor's Hammer on **Python 3.11+ / asyncio** with zero runtime
dependencies.

> **⚠️ LEGAL NOTICE — READ CAREFULLY**
>
> This tool sends long-lived, slow HTTP requests designed to exhaust the
> worker threads/processes of an unprotected web server (a denial-of-service
> condition). Use it **only against systems you own or are explicitly authorized
> to test**. Unauthorized use is illegal in most jurisdictions. You are
> responsible for complying with the law.
>
> **Authorized use cases:**
> - Systems you own
> - Systems with explicit written authorization
> - Local lab environments
> - Staging environments
> - CTF/security-training environments
> - Defensive security assessments

## Why a rewrite?

What changed vs. the 2011 `legacy/` code:

| 2011 original | 2.0 rewrite |
|---|---|
| Python 2 (never imports on Py3) | Python 3.11+ stdlib only |
| 1 OS thread per socket (≤ ~2k sockets) | asyncio: tens of thousands of sockets |
| HTTP port 80 only | HTTP + **HTTPS/TLS with SNI** |
| Fixed request fingerprint | Randomized headers/UA/path/timing per connection |
| `send()` partial writes, magic `errno` checks | buffered `writer.write`/`drain`, typed exceptions |
| Broken thread shutdown (`join()` list bug) | `asyncio.Event` stop flag + SIGINT/SIGTERM cleanup |
| Bundled SocksiPy (broken SOCKS5 auth) | Built-in async SOCKS5/SOCKS4a/HTTP CONNECT |
| Single Tor endpoint | Proxy list + rotation |
| No coverage of modern mitigations | 32 vectors (slowloris, protocol-starvation, HTTP/2, TLS handshake) |
| No stats, no duration control | Live stats line, JSON output, `--duration` |

## Features

- **Zero runtime dependencies** - Python 3.11+ standard library only
- **Thirty-two attack modes** - 7 classic TCP slow-request modes (`slow-post`, `slow-post-headers`,
  `slow-headers`, `slow-read`, `chunked`, `multipart-slow-upload`, `expect-continue-abuse`), a real
  `udp` flood, 7 protocol-specific modes (`websocket-slow-upgrade`, `http-pipelining`,
  `range-abuse`, `cookie-bomb`, `jsonrpc-slow`, `smtp-slow-envelope`, `ftp-slow-command`), 6
  protocol-starvation modes (`imap-slow-literal`, `redis-resp-slow`, `postgres-startup-slow`,
  `dns-tcp-slow`, `nntp-slow-post`, `idle-hold`), 5 HTTP-parser / framing-abuse modes
  (`slow-xml`, `slow-form-parse`, `header-count-flood`, `websocket-slow-frame`, `req-smuggling-probe`),
  4 HTTP/2 framing / HPACK-abuse modes (`h2-rapid-reset`, `h2-slow-streams`,
  `h2-continuation-flood`, `h2-hpack-drip`) and 2 TLS-handshake starvation modes
  (`tls-slow-hello`, `tls-renego-hold`)
- **Two interchangeable backends** - identical 32-mode set in the Python and Rust engines.
  By default `--backend auto` transparently uses the Rust engine only when it is *installed*
  (on `PATH`/`TORSHAMMER_RUST_BIN`) **and** the run is fully Rust-compatible; otherwise it
  runs the Python engine, so ordinary use never changes behaviour. The Rust engine covers
  plain HTTP and UDP with fail-closed dispatch (`os.execv` on POSIX, spawned subprocess on
  Windows). HTTPS/TLS, proxies, and `--ramp-up` remain Python-only: an explicit
  `--backend rust` with such flags exits non-zero with an explanation instead of silently
  downgrading, and `auto` quietly falls back to Python.
- **Asyncio-powered** - Tens of thousands of concurrent connections
- **HTTPS/TLS support** - With SNI (Server Name Indication)
- **Proxy support** - SOCKS5, SOCKS4a, HTTP CONNECT (including Tor)
- **Proxy rotation** - Distribute connections across multiple proxies
- **Request randomization** - Headers, User-Agent, path, timing per connection
- **Live statistics** - Real-time terminal stats or JSON output
- **Clean shutdown** - SIGINT/SIGTERM handling with graceful worker cleanup
- **Cross-platform** - Linux, macOS, Windows

## Requirements

- **Python 3.11 or higher**
- Network access to target
- (Optional) Tor running on `127.0.0.1:9050` for `--tor` flag
- (Optional) Proxy servers for anonymization

## Installation

Torshammer ships as a pure-Python package (the `torshammer` command, **zero
runtime dependencies**) with an optional high-performance Rust backend. Pick the
path that suits you.

### 1. Download the source

```bash
git clone https://github.com/TabbyMichael/TorsHammer-2.0.git
cd TorsHammer-2.0
```

### 2. Install the Python CLI

**Recommended — isolated install with `pipx`** (no venv to babysit; puts
`torshammer` on your PATH):

```bash
pipx install .
# manage it later: pipx upgrade torshammer  |  pipx uninstall torshammer
```

**Or a virtual environment** (Linux / macOS):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .            # use ".[dev]" to also pull pytest, mypy and ruff
```

**Windows (CMD / PowerShell):**

```cmd
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

No `pipx` and don't want a venv? Run `python -m pip install --user .`, or skip
installing entirely and invoke it straight from the checkout with
`python -m torshammer`.

### 3. Build the Rust backend (optional)

Only needed for extreme concurrency on plain-HTTP/UDP targets. With the default
`--backend auto` it is picked up **automatically** once installed on your `PATH`
(or via `TORSHAMMER_RUST_BIN`) and the run is Rust-compatible — otherwise the
Python engine is used. It is **never installed by default**, and the Python
engine already covers all 32 modes and every flag.

```bash
cd rust && cargo build --release
# binary: rust/target/release/torshammer-rust
# auto-discovered next to the checkout, or set TORSHAMMER_RUST_BIN=/abs/path
```

### Windows-Specific Considerations

**High Concurrency on Windows:**
- Windows uses the ProactorEventLoop by default, which handles high concurrency well
- The older SelectorEventLoop had limitations (~512 sockets), but ProactorEventLoop does not
- If you encounter issues, you may need to adjust your event loop policy
- File descriptor limits are different on Windows; the tool will warn if concurrency is too high

**Performance Tips:**
- Start with lower concurrency (e.g., `-c 128`) and increase gradually
- Monitor system resources during high-concurrency tests
- Use `--duration` for time-limited tests to avoid uncontrolled resource usage

## Quick Start

The tool needs exactly one thing — a target URL you are authorized to test:

```bash
torshammer -u http://localhost:8080            # slow-post, 256 connections, until Ctrl-C
```

Run it bare (`torshammer`, no target) and it prints this same copy-pasteable
quickstart instead of a cryptic error. Backend selection is automatic
(`--backend auto`): the Rust engine is used when it's installed and the run is
compatible, otherwise Python — you rarely need to think about it.

1. **Preview first** — resolves and prints the effective config but opens
   **zero** connections:

   ```bash
   torshammer -u http://localhost:8080 --dry-run
   ```

2. **Run a bounded test** and watch the live stats line:

   ```bash
   torshammer -u http://localhost:8080 -c 128 -d 30
   ```

   ```
   thm | conns=128 open=128 done=12 err=0 | sent 45.2 KB @ 12.3 KB/s | recv 0.0 B | 0:15
   ```

3. **Stop anytime** with `Ctrl-C` — workers shut down gracefully and a final
   summary (including an advisory mitigation verdict) is printed.

> **Running it other ways:** `python -m torshammer ...` (straight from the
> checkout) and `pipx run` behave identically to the installed `torshammer`
> command — same flags, same output.

> **Safety guardrail:** by default only loopback/private hosts are permitted.
> Targeting a public host requires an explicit `--allow-public-targets` (or the
> host listed in `--allowlist-file`) so you can't accidentally test a third-party
> system.

## Usage

```bash
torshammer -u http://example.com                  # classic slow POST, 256 conns
torshammer -u https://login.example.net/api -m slow-headers -c 512 --ssl-no-verify
torshammer -u http://10.0.0.5 --tor               # anonymize via Tor (127.0.0.1:9050)
torshammer -u http://example.com --proxy-list proxies.txt --rotate-proxies
torshammer -u http://example.com -m slow-read -d 300 --json > stats.log
torshammer -u http://example.com/wp-admin/media-new.php -m multipart-slow-upload -c 128 -d 60
torshammer -u http://example.com -m expect-continue-abuse -c 128 -d 60
```

Protocol-specific modes target the service that speaks the matching protocol:

```bash
torshammer -u http://example.com -m websocket-slow-upgrade   # incomplete WS handshakes
torshammer -u http://example.com -m http-pipelining          # 50 pipelined requests/conn
torshammer -u http://example.com/big.bin -m range-abuse      # 100 Range requests/conn
torshammer -u http://example.com -m cookie-bomb              # ~10 KB cookie per request
torshammer -u http://example.com/rpc -m jsonrpc-slow         # dribbled JSON-RPC payload
torshammer -u http://mail.example.com:25 -m smtp-slow-envelope
torshammer -u http://ftp.example.com:21 -m ftp-slow-command
torshammer -u udp://dns.example.com:53 -m udp                # real UDP datagram flood
```

See [Attack Modes](docs/attack-modes.md) for the mechanism and countermeasures of each mode.

The original flags still work: `-t <host> -r <threads> -p <port> -T`.

By default the tool refuses to target public internet hosts unless the operator explicitly opts in with `--allow-public-targets` or a `--allowlist-file`. This is a built-in safety guardrail meant to reduce accidental misuse against third-party systems.

### Options

| Flag | Meaning | Default |
|---|---|---|
| `-u, --url` | Target URL (`http://`, `https://` or `udp://`) | required |
| `-c, --concurrency` | Concurrent sockets | 256 |
| `-m, --mode` | Attack mode — any of the 32 listed under [Features](#features) and detailed in [Attack Modes](docs/attack-modes.md) | `slow-post` |
| `-dl / -dh` | Min/max dribble delay (s) | 0.1 / 3.0 |
| `-d, --duration` | Auto-stop after N s (0 = until Ctrl-C) | 0 |
| `--post-length` | Baseline `Content-Length` for slow-post/slow-post-headers/chunked (byte budget for `udp`) | 4096 |
| `--tor` | Proxy through `127.0.0.1:9050` | off |
| `--proxy` / `--proxy-list` | Single proxy URL / file of proxy URLs | none |
| `--rotate-proxies` | Random proxy per connection | off |
| `--ssl-no-verify` | Skip TLS certificate validation | off |
| `--backend` | Runtime backend: `auto` (use Rust when installed + compatible, else Python) \| `python` \| `rust` | `auto` |
| `--allow-public-targets` | Permit public internet targets (explicit authorization required) | off |
| `--allowlist-file` | File of allowed hostnames / IPs; entries are always permitted | none |
| `--json` | Newline-delimited JSON stats | off |
| `-q / -v` | Quiet / verbose | - |

`examples/proxies.txt` and `examples/user-agents.txt` show the expected
file formats.

## Observability

### Terminal Output

```
thm | conns=512 open=512 done=3 err=7 | sent 1.4 MB @ 45.2 KB/s | recv 0.0 B | 1:05
```

**Fields:**
- `conns` - Total connections opened
- `open` - Currently active connections
- `done` - Completed attack cycles
- `err` - Connection errors
- `sent` - Total bytes sent
- `@ KB/s` - Current send rate
- `recv` - Total bytes received
- `MM:SS` - Elapsed time

### JSON Output

```bash
torshammer -u http://example.com --json > stats.log
```

Emits one newline-delimited JSON object per interval:

```json
{"connections":512,"active":512,"peak_active":512,"completed":3,"errors":7,"bytes_sent":1474560,"bytes_received":0,"sent_bytes_per_sec":45200,"uptime":65.0}
```

## Architecture

```
┌─────────────┐
│     CLI     │  (argparse, signal handling)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Config    │  (dataclass, validation)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ AttackEngine│  (asyncio worker pool)
└──────┬──────┘
       │
       ├─────────────────────────────────┐
       │                                 │
       ▼                                 ▼
┌─────────────┐                   ┌─────────────┐
│   Profiles  │                   │  ProxyPool  │
│ (32 modes)  │                   │ (rotation)  │
└──────┬──────┘                   └──────┬──────┘
       │                                 │
       ▼                                 ▼
┌─────────────┐                   ┌─────────────┐
│  Connection │◄──────────────────│   Proxy     │
│   Factory   │                   │   (SOCKS5/  │
└──────┬──────┘                   │   SOCKS4/   │
       │                          │   HTTP)     │
       │                          └─────────────┘
       ▼
┌─────────────┐
│   Target    │
│ (HTTP/HTTPS)│
└─────────────┘

(UDP mode sends datagrams directly through `udp.py` instead of the Connection Factory.)
```

**Modules:**
- `cli.py` - Argument parsing, orchestration, signal handling
- `config.py` - Configuration dataclass with validation + layered TOML/env settings
- `engine.py` - Async attack engine with worker pool
- `profiles.py` - Thirty-one TCP attack profiles (7 classic slow modes + 7 protocol-specific modes + 6 protocol-starvation modes + 5 HTTP-parser/framing modes + 4 HTTP/2 framing/HPACK modes + 2 TLS-handshake starvation modes); plus `udp` = 32 modes total
- `h2.py` - Dependency-free HTTP/2 frame + HPACK builders for the Tier-3 modes
- `tls.py` - Dependency-free TLS record + ClientHello builders for the Tier-4 handshake-starvation modes
- `udp.py` - UDP datagram flood mode
- `conn.py` - Connection factory (plain, TLS, SOCKS5, SOCKS4a, HTTP CONNECT)
- `proxies.py` - Proxy parsing and rotation
- `useragents.py` - User-Agent list and file loader
- `stats.py` - Statistics aggregation and formatting

## Security Considerations

### Authorization Required

This tool is designed for **authorized security testing only**. You must have:
- Ownership of the target system, OR
- Explicit written authorization from the system owner

### Intended Use Cases

- **Vulnerability assessment** - Test web server resilience to slow-requests attacks
- **Mitigation validation** - Verify that defenses (WAF, rate limiting, timeouts) are effective
- **Security research** - Study slow-requests attack vectors in controlled environments
- **Educational purposes** - Learn about DoS vulnerabilities in lab settings

### Limitations

- Does not bypass authentication mechanisms
- Does not exploit application-layer vulnerabilities
- Does not include persistence mechanisms
- Does not steal credentials or data
- Relies on HTTP protocol compliance

### Privacy

- Supports Tor anonymization via `--tor` flag
- Supports proxy rotation via `--proxy-list` and `--rotate-proxies`
- Does not log sensitive data
- Proxy credentials are passed in URLs (use environment variables for sensitive credentials)

## Documentation

- [Architecture Documentation](docs/architecture.md) - Detailed architecture and data flow
- [Installation Guide](docs/installation.md) - Platform-specific installation instructions
- [CLI Reference](docs/cli.md) - Complete command-line interface documentation
- [Configuration Guide](docs/configuration.md) - Configuration options and examples
- [Attack Modes](docs/attack-modes.md) - Detailed explanation of each attack vector
- [Proxy Support](docs/proxy-support.md) - Proxy configuration and Tor integration
- [Output Formats](docs/output-formats.md) - Terminal and JSON output documentation
- [Security Documentation](docs/security.md) - Security model and threat analysis
- [Testing Guide](docs/testing.md) - Running and extending the test suite
- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions
- [Development Guide](docs/development.md) - Contributor guide and code style

## Testing

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_cli.py
```

The test suite includes:
- Local test server (`SlowServer` fixture)
- Fake SOCKS5 proxy (`FakeSocks5` fixture)
- CLI argument parsing tests
- Connection factory tests
- Attack profile tests
- Engine integration tests

## Troubleshooting

**Connection timeout errors:**
- Check network connectivity to target
- Verify target is accepting connections
- Increase `--connect-timeout` if needed
- Check firewall rules

**Proxy handshake failures:**
- Verify proxy is running and accessible
- Check proxy credentials (if using authentication)
- Test proxy with `curl --proxy` first
- Check proxy scheme (socks5://, socks4://, http://)

**TLS certificate errors:**
- Use `--ssl-no-verify` for self-signed certificates (in test environments only)
- Verify target certificate chain
- Check system certificate store

For more troubleshooting information, see [docs/troubleshooting.md](docs/troubleshooting.md).

## Development

The root `Makefile` wraps every common workflow (`make` lists them):

```bash
make dev      # editable install with pytest, mypy and ruff
make test     # pytest with the coverage gate
make lint     # ruff check + format --check
make type     # mypy
make check    # all Python + Rust gates (what CI runs)
```

Or do it manually:

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Check CLI help
python -m torshammer --help

# Run with verbose output
torshammer -u http://localhost:8080 -v
```

See [docs/development.md](docs/development.md) for:
- Repository structure
- Adding new attack profiles
- Code style (ruff configuration)
- Type hints
- Testing guidelines

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Code style requirements
- Testing requirements
- Pull request process
- Security-sensitive changes

## License

GPL-2.0-or-later - See [LICENSE](LICENSE) for details.

## Acknowledgements

The original Tor's Hammer by e.c. / SourceForge project, and SocksiPy by
Dan Haim that shipped with it.
