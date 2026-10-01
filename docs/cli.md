# CLI Reference

## Overview

Torshammer 2.0 provides a single command-line interface with multiple options for configuring attack parameters, proxy settings, and output formats.

## Command Syntax

```bash
torshammer [OPTIONS]
```

## Entry Points

The tool can be invoked in three ways:

```bash
# Via installed script
torshammer [OPTIONS]

# Via Python module
python -m torshammer [OPTIONS]

# Direct execution (if in source directory)
python src/torshammer/cli.py [OPTIONS]
```

## Options

### Target Options

#### `-u, --url <URL>`

**Required:** Yes (alternative to `--host`)

**Description:** Target URL including scheme (`http://` or `https://`)

**Examples:**
```bash
torshammer -u http://example.com
torshammer -u https://api.example.net/v1/endpoint
torshammer -u http://10.0.0.5:8080/login
```

**Behavior:**
- If scheme is omitted, defaults to `http://`
- Supports query parameters: `http://example.com/api?key=value`
- Path defaults to `/` if not specified
- Port defaults to 80 (HTTP) or 443 (HTTPS)

#### `-t, --target <HOST>`

**Required:** Yes (alternative to `--url`)

**Description:** Legacy alias for `--url`. Accepts hostname or IP address.

**Examples:**
```bash
torshammer -t example.com
torshammer -t 192.168.1.100
```

**Note:** This is a legacy flag from the original Tor's Hammer. `--url` is preferred.

#### `--host <HOST>`

**Required:** Yes (alternative to `--url`)

**Description:** Target hostname or IP address. Use with `--port` and optionally `--ssl`.

**Examples:**
```bash
torshammer --host example.com --port 80
torshammer --host 10.0.0.5 --port 443 --ssl
```

**Behavior:**
- Must be used with `--port`
- Use `--ssl` flag for HTTPS
- Path defaults to `/`

#### `-p, --port <PORT>`

**Required:** No

**Description:** Target port number.

**Default:** 80 (HTTP) or 443 (HTTPS) when using `--url`

**Examples:**
```bash
torshammer -u http://example.com -p 8080
torshammer --host example.com --port 8443 --ssl
```

#### `--ssl`

**Required:** No

**Description:** Enable TLS/SSL. Implied when using `https://` scheme.

**Default:** Off

**Examples:**
```bash
torshammer --host example.com --port 443 --ssl
torshammer -u http://example.com --ssl  # Upgrades to HTTPS
```

#### `--ssl-no-verify`

**Required:** No

**Description:** Skip TLS certificate verification. **Use only in test environments.**

**Default:** Off

**Security Warning:** Disabling certificate verification exposes you to man-in-the-middle attacks. Only use this in controlled lab environments.

**Examples:**
```bash
torshammer -u https://self-signed.example.com --ssl-no-verify
```

### Attack Options

#### `-m, --mode <MODE>`

**Required:** No

**Description:** Attack mode to use.

**Default:** `slow-post`

**Choices - Classic TCP slow-request modes:**

- `slow-post` - Classic Tor's Hammer: complete headers with a large `Content-Length`, dribble the body
- `slow-post-headers` - Leak the request line and every header one line at a time, then dribble the body
- `slow-headers` - Slowloris: send the request line and headers, never finish them
- `slow-read` - Slow-read: send a complete request, read the response 8 bytes at a time
- `chunked` - Chunked encoding: `Transfer-Encoding: chunked` body in tiny chunks, never the 0-chunk
- `multipart-slow-upload` - Multipart upload with the closing boundary withheld, MIME parts dribbled
- `expect-continue-abuse` - `Expect: 100-continue` headers, body stalled after the interim response

**Choices - UDP mode (also selected automatically by a `udp://` target):**

- `udp` - Real UDP datagram flood with randomized 1-32 byte payloads

**Choices - Advanced protocol-specific modes:**

- `websocket-slow-upgrade` - Send WebSocket upgrade headers one at a time, never complete the handshake
- `http-pipelining` - Pipeline up to 50 HTTP requests per connection without reading responses
- `range-abuse` - Send up to 100 randomized `Range:` requests per connection
- `cookie-bomb` - Send a ~10 KB random `Cookie` header and hold the connection
- `jsonrpc-slow` - Slowly dribble a JSON-RPC payload with an overstated `Content-Length`
- `smtp-slow-envelope` - Slowly drip SMTP envelope commands (`EHLO`/`MAIL FROM`/`RCPT TO`), never `DATA`
- `ftp-slow-command` - Slowly drip FTP commands (`USER`/`PASS`/`PASV`), never transfer data

**Examples:**
```bash
torshammer -u http://example.com -m slow-headers
torshammer -u http://example.com -m slow-post-headers
torshammer -u http://example.com -m slow-read
torshammer -u http://example.com -m chunked
torshammer -u http://example.com -m multipart-slow-upload
torshammer -u http://example.com -m expect-continue-abuse
torshammer -u http://example.com -m websocket-slow-upgrade
torshammer -u http://example.com -m http-pipelining
torshammer -u http://example.com/large.bin -m range-abuse
torshammer -u http://example.com -m cookie-bomb
torshammer -u http://example.com/rpc -m jsonrpc-slow
torshammer -u http://example.com:25 -m smtp-slow-envelope
torshammer -u http://example.com:21 -m ftp-slow-command
torshammer -u udp://example.com:53 -m udp
```

**Note:** The Python CLI derives the choice list from the profile registry, so every mode above is
accepted by both backends (`--backend python` and `--backend rust`). Protocol-specific modes require
a target service that speaks the matching protocol.

**See:** [Attack Modes Documentation](attack-modes.md) for detailed explanations.

#### `-c, --concurrency, --threads, -r <NUMBER>`

**Required:** No

**Description:** Number of concurrent connections.

**Default:** 256

**Examples:**
```bash
torshammer -u http://example.com -c 512
torshammer -u http://example.com --threads 128
torshammer -u http://example.com -r 64  # Legacy flag
```

**Note:** Higher concurrency requires higher file descriptor limits. See [Installation Guide](installation.md#file-descriptor-limits).

#### `-dl, --delay-min <SECONDS>`

**Required:** No

**Description:** Minimum dribble delay between data sends.

**Default:** 0.1

**Examples:**
```bash
torshammer -u http://example.com -dl 0.05
torshammer -u http://example.com --delay-min 0.5
```

#### `-dh, --delay-max <SECONDS>`

**Required:** No

**Description:** Maximum dribble delay between data sends.

**Default:** 3.0

**Examples:**
```bash
torshammer -u http://example.com -dh 5.0
torshammer -u http://example.com --delay-max 10.0
```

**Behavior:** Actual delay is randomly chosen between `delay-min` and `delay-max` for each send.

#### `-d, --duration <SECONDS>`

**Required:** No

**Description:** Auto-stop after N seconds. Use 0 for unlimited (manual stop with Ctrl-C).

**Default:** 0 (unlimited)

**Examples:**
```bash
torshammer -u http://example.com -d 60  # Stop after 60 seconds
torshammer -u http://example.com --duration 300  # Stop after 5 minutes
torshammer -u http://example.com -d 0  # Run until Ctrl-C (default)
```

#### `--post-length <BYTES>`

**Required:** No

**Description:** Baseline `Content-Length` for `slow-post`, `slow-post-headers` and `chunked` modes
(and the baseline byte budget for the `udp` flood).

**Default:** 4096

**Examples:**
```bash
torshammer -u http://example.com --post-length 8192
torshammer -u http://example.com --post-length 2048
```

**Behavior:** Actual length is randomized between `post-length/2` and `post-length`.

#### `--connect-timeout <SECONDS>`

**Required:** No

**Description:** Connection timeout in seconds.

**Default:** 15.0

**Examples:**
```bash
torshammer -u http://example.com --connect-timeout 30
torshammer -u http://example.com --connect-timeout 5
```

### Proxy Options

#### `--tor`

**Required:** No

**Description:** Route traffic through Tor SOCKS5 proxy at `127.0.0.1:9050`.

**Default:** Off

**Examples:**
```bash
torshammer -u http://example.com --tor
```

**Requirements:** Tor must be running on `127.0.0.1:9050`. See [Installation Guide](installation.md#tor-installation-optional).

#### `--proxy <URL>`

**Required:** No

**Description:** Single proxy URL.

**Default:** None

**Supported Schemes:**
- `socks5://[user:pass@]host:port`
- `socks4://[user@]host:port`
- `http://[user:pass@]host:port`
- `https://[user:pass@]host:port` (treated as HTTP CONNECT)

**Examples:**
```bash
torshammer -u http://example.com --proxy socks5://127.0.0.1:9050
torshammer -u http://example.com --proxy http://proxy.example.com:8080
torshammer -u http://example.com --proxy socks5://user:pass@10.0.0.1:1080
```

**See:** [Proxy Support Documentation](proxy-support.md) for details.

#### `--proxy-list <FILE>`

**Required:** No

**Description:** File containing one proxy URL per line.

**Default:** None

**File Format:**
```
# Comments start with #
socks5://127.0.0.1:9050
http://proxy1.example.com:8080
socks5://user:pass@10.0.0.1:1080
```

**Examples:**
```bash
torshammer -u http://example.com --proxy-list proxies.txt
```

**See:** `examples/proxies.txt` for example format.

#### `--rotate-proxies`

**Required:** No

**Description:** Pick a random proxy for each connection instead of round-robin.

**Default:** Off

**Examples:**
```bash
torshammer -u http://example.com --proxy-list proxies.txt --rotate-proxies
```

**Behavior:**
- Without this flag: proxies are used in round-robin order
- With this flag: random proxy selected per connection
- Useful for distributing across Tor circuits

### Output Options

#### `--stats-interval <SECONDS>`

**Required:** No

**Description:** Interval between statistics updates.

**Default:** 1.0

**Examples:**
```bash
torshammer -u http://example.com --stats-interval 5.0
torshammer -u http://example.com --stats-interval 0.5
```

#### `--json`

**Required:** No

**Description:** Emit newline-delimited JSON statistics instead of terminal output.

**Default:** Off

**Examples:**
```bash
torshammer -u http://example.com --json > stats.log
torshammer -u http://example.com --json | jq .
```

**Output Format:**
```json
{"connections":512,"active":512,"peak_active":512,"completed":3,"errors":7,"bytes_sent":1474560,"bytes_received":0,"sent_bytes_per_sec":45200,"uptime":65.0}
```

**See:** [Output Formats Documentation](output-formats.md) for schema details.

#### `-q, --quiet`

**Required:** No

**Description:** Suppress live status line. Useful with `--json`.

**Default:** Off

**Examples:**
```bash
torshammer -u http://example.com --json --quiet
```

#### `-v, --verbose`

**Required:** No

**Description:** Print per-error details. Can be specified multiple times for increased verbosity.

**Default:** 0 (off)

**Examples:**
```bash
torshammer -u http://example.com -v
torshammer -u http://example.com -vv
```

**Behavior:**
- `-v`: Print error type and message
- `-vv`: More detailed error information (if implemented)

#### `--user-agents <FILE>`

**Required:** No

**Description:** File containing one User-Agent string per line.

**Default:** Internal modern browser list

**File Format:**
```
# Comments start with #
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...
Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...
```

**Examples:**
```bash
torshammer -u http://example.com --user-agents user-agents.txt
```

**See:** `examples/user-agents.txt` for example format.

### Help Options

#### `--version`

**Required:** No

**Description:** Display version information and exit.

**Examples:**
```bash
torshammer --version
```

**Output:**
```
torshammer 2.0.0
```

#### `-h, --help`

**Required:** No

**Description:** Display help message and exit.

**Examples:**
```bash
torshammer --help
torshammer -h
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 130 | Interrupted (Ctrl-C) |
| 1 | Configuration error (invalid arguments) |
| 2 | Network/connection error |

## Examples

### Basic Usage

```bash
# Test with default settings (256 connections, slow-post mode)
torshammer -u http://localhost:8080
```

### High Concurrency

```bash
# Use 512 connections
torshammer -u http://localhost:8080 -c 512
```

### HTTPS Target

```bash
# Test HTTPS endpoint
torshammer -u https://api.example.com/v1/endpoint
```

### Slowloris Attack

```bash
# Use slow-headers mode (slowloris)
torshammer -u http://localhost:8080 -m slow-headers
```

### With Tor

```bash
# Anonymize through Tor
torshammer -u http://example.com --tor
```

### With Proxy List

```bash
# Rotate through multiple proxies
torshammer -u http://example.com --proxy-list proxies.txt --rotate-proxies
```

### JSON Output

```bash
# Export statistics to JSON file
torshammer -u http://localhost:8080 --json > stats.log
```

### Time-Limited Test

```bash
# Run for exactly 60 seconds
torshammer -u http://localhost:8080 -d 60
```

### Verbose Mode

```bash
# Show error details
torshammer -u http://localhost:8080 -v
```

### Custom Timing

```bash
# Faster dribble (0.05-1.0 seconds)
torshammer -u http://localhost:8080 -dl 0.05 -dh 1.0
```

### Self-Signed Certificate

```bash
# Ignore certificate verification (test environment only)
torshammer -u https://self-signed.local --ssl-no-verify
```

## Legacy Compatibility

The original Tor's Hammer flags are still supported:

| Original Flag | Modern Equivalent |
|---------------|-------------------|
| `-t <host>` | `-u http://<host>` or `--host <host>` |
| `-r <threads>` | `-c <concurrency>` or `--threads` |
| `-p <port>` | `-p <port>` (unchanged) |
| `-T` | `--tor` |

**Example:**
```bash
# Original syntax
./torshammer.py -t 192.168.1.100 -r 256 -p 80 -T

# Modern equivalent
torshammer -u http://192.168.1.100 -c 256 --tor
```

## Common Patterns

### Testing Web Server Resilience

```bash
# Start with low concurrency, increase gradually
torshammer -u http://test.local -c 64 -d 30
torshammer -u http://test.local -c 128 -d 30
torshammer -u http://test.local -c 256 -d 30
```

### Comparing Attack Modes

```bash
# Test each mode against the same target
torshammer -u http://test.local -m slow-post -d 30 --json > slow-post.json
torshammer -u http://test.local -m slow-post-headers -d 30 --json > slow-post-headers.json
torshammer -u http://test.local -m slow-headers -d 30 --json > slow-headers.json
torshammer -u http://test.local -m slow-read -d 30 --json > slow-read.json
torshammer -u http://test.local -m chunked -d 30 --json > chunked.json
torshammer -u http://test.local -m multipart-slow-upload -d 30 --json > multipart.json
torshammer -u http://test.local -m expect-continue-abuse -d 30 --json > expect-continue.json
torshammer -u http://test.local -m websocket-slow-upgrade -d 30 --json > websocket.json
torshammer -u http://test.local -m http-pipelining -d 30 --json > pipelining.json
torshammer -u http://test.local -m range-abuse -d 30 --json > range.json
torshammer -u http://test.local -m cookie-bomb -d 30 --json > cookie.json
torshammer -u http://test.local -m jsonrpc-slow -d 30 --json > jsonrpc.json
torshammer -u http://test.local:25 -m smtp-slow-envelope -d 30 --json > smtp.json
torshammer -u http://test.local:21 -m ftp-slow-command -d 30 --json > ftp.json
torshammer -u udp://test.local:53 -m udp -d 30 --json > udp.json
```

### Distributed Testing with Proxies

```bash
# Use multiple proxies to distribute load
torshammer -u http://test.local --proxy-list proxies.txt --rotate-proxies -c 512
```

### Continuous Monitoring

```bash
# Run with JSON output and monitor in real-time
torshammer -u http://test.local --json | jq --unbuffered '{conns, active, errors, sent_bytes_per_sec}'
```

## Error Messages

### Configuration Errors

```
error: unsupported URL scheme: 'ftp'
```
**Cause:** Invalid URL scheme. Supported schemes are `http://`, `https://` and `udp://`.

```
error: URL has no hostname
```
**Cause:** Invalid URL format.

```
error: a target is required (use --url or --host)
```
**Cause:** No target specified.

### Network Errors

```
[w0] ConnectionRefusedError: [Errno 111] Connection refused
```
**Cause:** Target is not accepting connections.

```
[w0] TimeoutError: Connection timeout
```
**Cause:** Connection timed out. Increase `--connect-timeout`.

### Proxy Errors

```
error: cannot read proxy list: [Errno 2] No such file or directory
```
**Cause:** Proxy list file not found.

```
[w0] ProxyConnectError: SOCKS5 connect failed (reply 5)
```
**Cause:** Proxy rejected connection or authentication failed.

## Safety & Layered Settings

### `--dry-run`

Resolve and print the target/configuration **without opening a single
connection**. Exits `0`. The default-deny public-target policy still applies
in dry-run mode, so a typo cannot be "safely" inspected for a public host
without `--allow-public-targets`.

```bash
torshammer -u https://example.com/api --dry-run --allow-public-targets
```

### `--config-file` and `TORSHAMMER_*` environment variables

Defaults can be layered (TOML-only, zero runtime dependencies — stdlib
`tomllib`):

```
explicit CLI flag  >  TORSHAMMER_* env var  >  --config-file TOML  >  argparse default
```

```bash
# torshammer.toml
concurrency = 512
mode = "slow-headers"
duration = 60

torshammer -u http://127.0.0.1:8080 --config-file torshammer.toml
TORSHAMMER_DURATION=10 torshammer -u http://127.0.0.1:8080   # env wins over TOML
```

Supported keys: `concurrency`, `mode`, `delay_min`, `delay_max`, `duration`,
`connect_timeout`, `post_length`, `stats_interval`, `max_errors`, `ramp_up`,
`fail_under` plus boolean `ssl_no_verify`, `no_random_path`,
`rotate_proxies`, `json_output`, `quiet`, `fail_on_zero`,
`allow_public_targets`. A `[tool.torshammer]` table in `pyproject.toml` is
also accepted when passed to `--config-file`.

### Advisory mitigation verdict

The final summary and every JSON stats line include an **advisory-only**
`verdict` (`LIKELY_VULNERABLE` / `LIKELY_MITIGATED` / `INCONCLUSIVE`) with a
reason. It is a heuristic signal for operators — it never influences exit
codes. See `torshammer.stats.classify_verdict` for the exact thresholds.

### `--backend rust` fail-closed behaviour

When `--backend rust` is selected, flags the Rust engine cannot honor
(`--proxy*`, `--tor`, `--proxy-env`, `--ssl-no-verify`, `--user-agents`,
`--ramp-up`, HTTPS targets, `udp://` without `-m udp`) cause a **non-zero
exit with an explanation** instead of a silent downgrade. Build the binary
first (`cd rust && cargo build --release`) or set `TORSHAMMER_RUST_BIN`.

## See Also

- [Architecture Documentation](architecture.md) - How the CLI connects to the engine
- [Configuration Guide](configuration.md) - Configuration dataclass details
- [Attack Modes](attack-modes.md) - Attack mode explanations
- [Output Formats](output-formats.md) - Output format details
