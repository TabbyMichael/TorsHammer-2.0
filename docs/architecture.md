# Architecture Documentation

## Overview

Torshammer 2.0 is built on Python's asyncio framework, enabling it to manage tens of thousands of concurrent connections with a single event loop. The architecture follows a modular design with clear separation of concerns.

## System Architecture

```mermaid
flowchart TD
    CLI[CLI<br/>cli.py] --> Config[Config<br/>config.py]
    Config --> Engine[AttackEngine<br/>engine.py]
    Engine --> Profiles[Profiles<br/>profiles.py]
    Engine --> Udp[UDP Flood<br/>udp.py]
    Engine --> ProxyPool[ProxyPool<br/>proxies.py]
    Profiles --> Connection[Connection Factory<br/>conn.py]
    ProxyPool --> Connection
    Connection --> Target[Target Server<br/>HTTP/HTTPS]
    Udp --> UdpTarget[Target Server<br/>UDP]
    Engine --> Stats[Stats<br/>stats.py]
    Engine --> Reporter[Reporter<br/>engine.py:_report]
    
    subgraph "Configuration"
        Config
    end
    
    subgraph "Attack Engine"
        Engine
        Stats
        Reporter
    end
    
    subgraph "Attack Profiles"
        Profiles
        Udp
    end
    
    subgraph "Network Layer"
        ProxyPool
        Connection
    end
```

## Module Responsibilities

### `cli.py` - Command Line Interface

**Responsibilities:**
- Argument parsing using `argparse`
- Orchestration of attack engine
- Signal handling (SIGINT, SIGTERM)
- Re-exports of the split helper modules (import-compatible surface)

**Key Functions:**
- `build_parser()` - Constructs argument parser with all options
- `main()` - Process entry point (layered settings, dispatch, run, exit codes)
- `_check_fd_limits()` - Warns when `-c` exceeds the descriptor budget

### `target.py` - Target Authorization Policy

- `_load_allowlist()` - Reads `--allowlist-file` (one host per line, `#` comments)
- `_is_private_or_local_target()` - Loopback/private/link-local/reserved detection
- `_check_target_policy()` - Default-deny public targets

**Security note:** the policy is hostname-based and evaluated once at startup;
see `docs/security.md` for the DNS-rebinding (TOCTOU) limitation.

### `settings.py` - CLI-to-Config Resolution

- `_resolve_config()` - Builds the validated `Config` from the parsed CLI
- `_build_proxies()` - `--proxy`, `--proxy-env`, `--proxy-list`, `--tor`, env fallback
- `_parse_custom_headers()` / `_build_custom_headers()` - Fail-closed header parsing
  (`:` separator only; CR/LF rejected to prevent header injection)
- `_load_custom_body()` - `--body-file`

### `dispatch.py` - Backend Selection and Rust Dispatch

- `_find_rust_binary()` - `TORSHAMMER_RUST_BIN`, `PATH`, then repo-relative build
- `_resolve_backend()` - Warns and falls back to Python when Rust is unavailable
- `_forward_to_rust()` - Fail-closed `execv` dispatch (POSIX) / `subprocess` (Windows)

### `summary.py` - Reporting

- `_print_summary()` - Final counters plus the advisory mitigation verdict
  (stdout, or stderr in `--json` mode)
- `_print_dry_run()` - `--dry-run` target/config preview (no sockets opened)

### `config.py` - Configuration Model

**Responsibilities:**
- Centralized configuration dataclass
- Default value management
- SSL context creation
- Random delay generation
- SNI hostname resolution

**Key Class:**
- `Config` - Dataclass containing all runtime configuration

**Properties:**
- `server_hostname` - Returns SNI hostname for TLS or None for HTTP
- `ssl_context()` - Creates SSL context with or without verification

**Security Considerations:**
- Supports TLS certificate verification bypass (for testing only)
- Does not log sensitive configuration values
- Proxy credentials stored in memory only

### `engine.py` - Attack Engine

**Responsibilities:**
- Manages asyncio worker pool
- Coordinates attack profiles
- Handles statistics collection
- Implements graceful shutdown
- Manages proxy rotation

**Key Class:**
- `AttackEngine` - Main orchestrator

**Methods:**
- `run()` - Main async method that spawns workers and reporter
- `_worker()` - Individual worker that runs attack profiles
- `_report()` - Periodic statistics reporter

**Worker Lifecycle:**
1. Acquire proxy (if configured)
2. Select User-Agent
3. Open connection via Connection Factory
4. Run attack profile
5. Handle errors with backoff
6. Close connection
7. Repeat until stop signal

**Security Considerations:**
- Implements connection backoff on errors
- Respects stop signal for graceful shutdown
- Does not persist sensitive data

### `profiles.py` - Attack Profiles

**Responsibilities:**
- Implements fourteen TCP attack vectors (fifteen including the `udp` mode in `udp.py`)
- Randomizes request characteristics
- Manages slow data transmission
- Evades simple fingerprinting

**Attack Profiles:**

#### `SlowPost` (Classic Tor's Hammer)
- Sends POST with large Content-Length
- Dribbles body one byte at a time
- Keeps connection open indefinitely

#### `SlowPostHeaders`
- Sends the request line and each header line separately
- Completes headers, then dribbles the body byte by byte

#### `SlowHeaders` (Slowloris)
- Sends GET request line
- Never sends terminating blank line
- Continues adding headers slowly

#### `SlowRead` (Slow-Bytes)
- Sends complete request
- Reads response in tiny chunks
- Pauses between reads

#### `Chunked`
- Sends POST with Transfer-Encoding: chunked
- Dribbles small chunks
- Never sends terminating 0-chunk

#### `MultipartSlowUpload`
- Sends POST with `Content-Type: multipart/form-data` and a random boundary
- Dribbles MIME-part content one byte at a time
- Never emits the closing boundary; strips any programmed `Expect:` header

#### `ExpectContinueAbuse`
- Sends complete headers with `Content-Length` and `Expect: 100-continue`
- Consumes the interim response with a read deadline, then stalls the body
- A caller-supplied `Expect:` header replaces the default (no duplicates)

#### `WebSocketSlowUpgrade`
- Sends a WebSocket upgrade request with `Sec-WebSocket-Key`/`Version`/`Protocol`
- Leaks each header line with delays
- Never sends the terminating blank line, then keeps the connection alive with random headers

#### `HttpPipelining`
- Sends up to 50 complete HTTP requests per connection without reading responses
- Holds the connection open between requests

#### `RangeHeaderAbuse`
- Sends up to 100 GET requests per connection, each with a distinct random `Range: bytes=start-end`
- Targets file-handle and range-parsing limits

#### `CookieBomb`
- Sends a ~10 KB random `Cookie` header
- Keeps the connection open with occasional extra data

#### `JsonRpcSlow`
- POSTs a partial JSON-RPC document (`{"jsonrpc":"2.0",...`) with an overstated `Content-Length`
- Dribbles the payload one character at a time and never completes the JSON

#### `SmtpSlowEnvelope`
- Drips `EHLO`, `MAIL FROM` and `RCPT TO` commands slowly
- Never sends `DATA`, leaving the mail envelope incomplete

#### `FtpSlowCommand`
- Drips `USER`, `PASS` and `PASV` commands slowly
- Never completes a data transfer

**Randomization Techniques:**
- Random User-Agent per connection
- Random Accept header
- Random X-Forwarded-For header
- Random X-Trace-Id header
- Random query parameters
- Random timing delays
- Randomly generated header names (generation-based modes)
- Random ranges and cookie payloads (targeted modes)

**Security Considerations:**
- Uses cryptographically secure random for tokens
- Does not include exploit payloads
- Relies on HTTP protocol compliance

### `udp.py` - UDP Flood

**Responsibilities:**
- Implements the `udp` attack mode
- Sends real UDP datagrams via `asyncio.DatagramProtocol`
- Randomizes payload content, size and inter-datagram delay

**Key Definitions:**
- `UdpProtocol` - `asyncio.DatagramProtocol` implementation (datagram replies are discarded)
- `open_datagram()` - Opens a datagram endpoint for the target host/port
- `drip()` - Sends randomized 1-32 byte datagrams with delays until stopped

**Security Considerations:**
- Requires the same explicit authorization as TCP modes
- Sends no protocol-specific exploits, only randomized datagrams

### `conn.py` - Connection Factory

**Responsibilities:**
- Opens plain HTTP connections
- Opens HTTPS/TLS connections with SNI
- Implements SOCKS5 handshake with authentication
- Implements SOCKS4a handshake
- Implements HTTP CONNECT tunneling
- Handles TLS upgrade after proxy handshake

**Key Function:**
- `open_connection()` - Unified connection factory

**Proxy Handshakes:**
- `_connect_socks5()` - SOCKS5 with optional username/password
- `_connect_socks4()` - SOCKS4a with remote DNS resolution
- `_connect_http()` - HTTP CONNECT with Basic authentication

**Security Considerations:**
- Validates proxy responses
- Implements timeout handling
- Supports TLS certificate verification
- Does not log proxy credentials

### `proxies.py` - Proxy Management

**Responsibilities:**
- Parses proxy URLs
- Manages proxy rotation
- Implements round-robin selection
- Implements random selection

**Key Classes:**
- `Proxy` - Single proxy endpoint configuration
- `ProxyPool` - Proxy selection strategy

**Supported Schemes:**
- `socks5://` - SOCKS5 with optional authentication
- `socks4://` - SOCKS4a with remote DNS
- `http://` - HTTP CONNECT tunneling
- `https://` - Treated as HTTP CONNECT

**Security Considerations:**
- URL-encoded credentials are decoded
- Credentials stored in memory only
- No credential persistence

### `useragents.py` - User-Agent Management

**Responsibilities:**
- Provides default User-Agent list
- Loads custom User-Agent from file
- Handles comments and blank lines

**Key Function:**
- `load_user_agents()` - Loads from file or returns defaults

**Default User-Agents:**
- Modern browsers (Chrome, Firefox, Safari, Edge)
- Mobile browsers (iOS, Android)
- Googlebot
- Multiple versions for fingerprinting evasion

**Security Considerations:**
- Does not validate User-Agent strings
- Falls back to defaults if file is empty

### `stats.py` - Statistics

**Responsibilities:**
- Aggregates connection statistics
- Formats byte sizes for human readability
- Tracks timing information

**Key Class:**
- `Stats` - Thread-safe statistics container

**Fields:**
- `connections` - Total connections opened
- `active` - Currently active connections
- `peak_active` - Peak concurrent connections
- `completed` - Completed attack cycles
- `errors` - Connection errors
- `bytes_sent` - Total bytes sent
- `bytes_received` - Total bytes received
- `start` - Start timestamp

**Security Considerations:**
- No sensitive data in statistics
- Updated from single event loop (thread-safe)

## Data Flow

```mermaid
sequenceDiagram
    participant CLI
    participant Config
    participant Engine
    participant Worker
    participant Profile
    participant Connection
    participant Proxy
    participant Target

    CLI->>Config: Parse arguments
    Config->>Config: Validate and resolve
    CLI->>Engine: Create with Config
    Engine->>Engine: Spawn N workers
    loop Worker Loop
        Worker->>Proxy: Get proxy (if configured)
        Worker->>Connection: Open connection
        Connection->>Proxy: Handshake (if proxy)
        Proxy->>Target: Establish tunnel
        Connection->>Target: TLS handshake (if HTTPS)
        Worker->>Profile: Run attack profile
        Profile->>Target: Send slow data
        Profile->>Profile: Randomize timing
        Worker->>Engine: Update stats
        Worker->>Connection: Close connection
    end
    Engine->>Engine: Report statistics
    CLI->>Engine: Stop signal (Ctrl-C)
    Engine->>Worker: Notify stop
    Worker->>Profile: Stop attack
    Engine->>CLI: Summary statistics
```

## Asyncio Event Loop

The attack engine uses a single asyncio event loop to manage all workers:

1. **Worker Spawning** - Creates N async tasks (one per concurrency level)
2. **Worker Execution** - Each worker runs independently in the event loop
3. **Statistics Reporting** - Separate async task reports periodically
4. **Signal Handling** - SIGINT/SIGTERM sets stop event
5. **Graceful Shutdown** - Workers observe stop event and exit cleanly

**Benefits:**
- Single event loop handles thousands of connections
- No thread synchronization issues
- Efficient I/O multiplexing
- Clean shutdown handling

## Worker Pool Design

Each worker is an independent async task that:

1. **Acquires Resources** - Gets proxy and User-Agent
2. **Opens Connection** - Via connection factory
3. **Runs Profile** - Executes attack profile until stop signal
4. **Handles Errors** - Implements backoff on failures
5. **Cleans Up** - Closes connection and updates stats
6. **Repeats** - Loops until stop signal

**Error Handling:**
- Connection errors trigger backoff (0.3s sleep)
- Continuous failure loops are detected and throttled
- Statistics track error counts
- Verbose mode logs error details

## Memory Management

- **No connection pooling** - Each connection is closed after use
- **No data persistence** - Statistics only in memory
- **No logging** - No file I/O during operation
- **Graceful cleanup** - All connections closed on shutdown

## Concurrency Model

- **Single-process** - No multiprocessing
- **Single event loop** - All I/O in one loop
- **Cooperative multitasking** - Workers yield via async/await
- **No shared state** - Statistics updated atomically
- **No locks needed** - Single-threaded event loop

## Extension Points

To add a new attack profile:

1. Create a new class inheriting from `Profile` in `profiles.py`
2. Implement the `run()` method
3. Add to the `PROFILES` dictionary (**the CLI `-m/--mode` choices are derived from this
   dictionary**, so no `cli.py` change is needed)
4. Mirror the profile in `rust/src/engine/profiles.rs` (`run_profile()` match arm)
5. Add the mode to `MODES` in `rust/src/main.rs` (the Rust CLI validates against it and `--help`
   renders it) and to the `-m` help string in `rust/src/cli/help.rs`
6. Add tests to `tests/test_profiles.py` and the Rust `mod tests` block

To add a new UDP-based mode:

1. Extend `udp.py` (or add a module) with the datagram logic
2. Route it from `engine.py` the same way `--mode udp` is routed
3. Add the mode name to the CLI choices list in `cli.py`

To add a new proxy type:

1. Add handshake function in `conn.py`
2. Add scheme to `_SUPPORTED` in `proxies.py`
3. Add default port to `_DEFAULT_PORTS` in `proxies.py`
4. Update `_handshake()` in `conn.py`

## Performance Characteristics

- **Scalability** - Limited by file descriptor limits, not threads
- **Memory** - O(concurrency) memory footprint
- **CPU** - Low CPU usage (I/O bound)
- **Network** - Generates low-bandwidth, long-lived connections

## Security Architecture

- **No privilege escalation** - Runs as normal user
- **No persistence** - No files written during operation
- **No data exfiltration** - Only statistics collected
- **No credential theft** - Does not handle target credentials
- **Proxy support** - Can anonymize traffic
