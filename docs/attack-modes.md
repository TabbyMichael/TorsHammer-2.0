# Attack Modes Documentation

## Overview

Torshammer 2.0 implements **thirty-two** distinct attack vectors designed to exhaust server resources through different protocol manipulation techniques. These include:

- **7 classic TCP slow-request modes** (HTTP slow attacks, all original responses to slowloris-era mitigations)
- **1 UDP flood mode** (datagram-based flooding)
- **7 advanced protocol-specific modes** (WebSocket, HTTP pipelining, application-layer, email/FTP)
- **6 protocol-starvation modes** (IMAP, Redis, Postgres, DNS-over-TCP, NNTP, idle-connection hold)
- **5 HTTP-parser / framing-abuse modes** (XML & form-parse starvation, header-count flood, slow WebSocket frame, request-smuggling probe)
- **4 HTTP/2 framing / HPACK-abuse modes** (rapid reset, half-open slow streams, continuation flood, HPACK drip)
- **2 TLS-handshake starvation modes** (starved ClientHello record, (re)handshake-initiation churn)

Each mode targets different server components and uses different attack vectors for comprehensive security testing.

All thirty-two modes are implemented in **both** backends (Python `src/torshammer/profiles.py` +
`src/torshammer/udp.py` + `src/torshammer/h2.py` + `src/torshammer/tls.py`, Rust `rust/src/engine/profiles.rs` +
`rust/src/engine/udp.rs` + `rust/src/engine/h2.rs` + `rust/src/engine/tls.rs`) and are
selectable through the same `-m` / `--mode` CLI flag.

## Attack Modes Summary

### Classic TCP Slow-Request Modes

| Mode | Also Known As | Mechanism | Primary Target |
|------|---------------|-----------|-----------------|
| `slow-post` | Slow POST, Tor's Hammer | Large Content-Length, dribble body | Worker threads/processes |
| `slow-post-headers` | Slow POST headers | Headers leaked one line at a time, then dribble body | Worker threads/processes |
| `slow-headers` | Slowloris | Never finish headers | Worker threads/processes |
| `slow-read` | Slow-read, Slow-bytes | Read response slowly | Server socket buffers |
| `chunked` | Chunked encoding | Never send terminating chunk | Worker threads/processes |
| `multipart-slow-upload` | Slow multipart upload | MIME parts dribbled, closing boundary withheld | Upload parsers/temp-file handling |
| `expect-continue-abuse` | Expect stall, 100-continue abuse | Headers + Expect, body stalled after interim response | Interim-response state/workers |

### UDP Flood Mode

| Mode | Mechanism | Primary Target |
|------|-----------|-----------------|
| `udp` | Real UDP datagram flood | Network bandwidth, UDP service availability |

### Advanced Protocol-Specific Modes

| Mode | Protocol | Mechanism | Primary Target |
|------|----------|-----------|-----------------|
| `websocket-slow-upgrade` | WebSocket | Slowly send upgrade headers | WebSocket connection limits |
| `http-pipelining` | HTTP/1.1 | Multiple requests without responses | Request buffer limits |
| `range-abuse` | HTTP/1.1 | Many byte range requests | File handle limits |
| `cookie-bomb` | HTTP/1.1 | Extremely large cookies | Cookie parsing memory |
| `jsonrpc-slow` | JSON-RPC | Slowly send JSON payload | JSON parser buffers |
| `smtp-slow-envelope` | SMTP | Slowly send envelope commands | SMTP connection limits |
| `ftp-slow-command` | FTP | Slowly send FTP commands | FTP connection limits |

### Protocol-Starvation Modes

These announce a protocol length/framing element the server then blocks waiting to
read in full, and never complete it — pinning a request handler with only a handful
of bytes on the wire.

| Mode | Protocol | Mechanism | Primary Target |
|------|----------|-----------|-----------------|
| `imap-slow-literal` | IMAP4rev1 | `{N}` literal announced, literal bytes never delivered | Mailbox/IMAP worker slots |
| `redis-resp-slow` | Redis RESP | `*1` multibulk with an oversized `$len` bulk, never closed | Redis read handler/clients limit |
| `postgres-startup-slow` | PostgreSQL | StartupMessage length over-promised, terminator withheld | Forked per-connection backend |
| `dns-tcp-slow` | DNS-over-TCP | 2-byte length prefix exceeds bytes actually sent | Resolver TCP query handler |
| `nntp-slow-post` | NNTP | `POST` accepted, article dot-terminator never sent | Reader/NNTP process slots |
| `idle-hold` | (any TCP) | Open the socket and send zero bytes forever | Connection/idle-slot limits |

### HTTP-Parser / Framing-Abuse Modes

These complete (or nearly complete) the request but abuse how the server *parses*
it — over-promising a document/body the parser keeps buffering, exceeding header
*counts* rather than header size, stalling a post-handshake WebSocket frame, or
making a front-end and back-end disagree on message framing.

| Mode | Mechanism | Primary Target |
|------|-----------|-----------------|
| `slow-xml` | Unclosed XML/`DOCTYPE` prolog + oversized `Content-Length`, body dribbled forever | XML/SOAP parsers, entity-expansion handling |
| `slow-form-parse` | Huge urlencoded `Content-Length`, endless `key=value&` pairs trickle in | Framework body-parsers that pre-allocate per `Content-Length` |
| `header-count-flood` | ~2000 tiny headers, then the request is *completed* | Per-header bookkeeping that caps bytes but not count |
| `websocket-slow-frame` | Finish the upgrade, then stream a frame whose declared length never fills | Post-handshake WebSocket frame readers |
| `req-smuggling-probe` | Ambiguous `Content-Length` **and** `Transfer-Encoding: chunked` | Front-end/back-end framing disagreement (request smuggling) |

### HTTP/2 Framing / HPACK-Abuse Modes

These speak real HTTP/2 (the connection preface, `SETTINGS`, and hand-built frames
via `h2.py`/`h2.rs` — no HTTP/2 crates) and abuse the multiplexing, frame-reassembly
and HPACK layers rather than the HTTP/1.x text parser.

| Mode | Mechanism | Primary Target |
|------|-----------|-----------------|
| `h2-rapid-reset` | On one connection, open a rapid run of streams and `RST_STREAM` each immediately after its `HEADERS` (CVE-2023-44487 class) | Per-stream alloc/teardown + concurrency-accounting in HTTP/2 servers |
| `h2-slow-streams` | Open many streams whose `HEADERS` omit `END_STREAM`, then dribble a byte of `DATA` forever without closing any | Half-open per-stream flow-control / buffer state |
| `h2-continuation-flood` | Start a header block then keep it open with an unbounded run of `CONTINUATION` frames that never set `END_HEADERS` | Frame-reassembly buffering + per-frame accounting |
| `h2-hpack-drip` | Feed one valid HPACK block a single octet per frame (`HEADERS` + `CONTINUATION`) with random delays, closing `END_HEADERS` only at the end | HTTP/2 analogue of slowloris: stalled header-block reassembly |

### TLS-Handshake Starvation Modes

These speak real TLS records (a hand-built `ClientHello` via `tls.py`/`tls.rs` — no TLS
crates, no key exchange, the socket is left raw) and target the server's *handshake*
reassembly path rather than the HTTP layer: an oversized record length is announced and
never filled, so the handshake worker/connection slot stays pinned at near-zero bandwidth.
Point them at a TLS listener over a plain `http://host:port` target so the raw handshake
bytes reach the port unwrapped.

| Mode | Mechanism | Primary Target |
|------|-----------|-----------------|
| `tls-slow-hello` | Announce a handshake record declaring the max record length, open a `ClientHello` inside it, then dribble a few bytes and never complete the record | Handshake reassembly buffer / connection slots |
| `tls-renego-hold` | Repeatedly emit a fresh (partial) `ClientHello` record to churn (re)handshake initiation without ever completing one | Renegotiation/handshake state re-allocation |

## Mode Selection

Use the `-m` or `--mode` flag:

```bash
# Classic TCP modes
torshammer -u http://example.com -m slow-post
torshammer -u http://example.com -m slow-post-headers
torshammer -u http://example.com -m slow-headers
torshammer -u http://example.com -m slow-read
torshammer -u http://example.com -m chunked
torshammer -u http://example.com -m multipart-slow-upload
torshammer -u http://example.com -m expect-continue-abuse

# UDP mode
torshammer -u udp://example.com:53 -m udp

# Advanced protocol-specific modes
torshammer -u http://example.com -m websocket-slow-upgrade
torshammer -u http://example.com -m http-pipelining
torshammer -u http://example.com -m range-abuse
torshammer -u http://example.com -m cookie-bomb
torshammer -u http://example.com -m jsonrpc-slow
torshammer -u http://example.com:25 -m smtp-slow-envelope
torshammer -u http://example.com:21 -m ftp-slow-command

# Protocol-starvation modes (target port must speak the matching protocol)
torshammer -u http://example.com:143 -m imap-slow-literal
torshammer -u http://example.com:6379 -m redis-resp-slow
torshammer -u http://example.com:5432 -m postgres-startup-slow
torshammer -u http://example.com:53 -m dns-tcp-slow
torshammer -u http://example.com:119 -m nntp-slow-post
torshammer -u http://example.com -m idle-hold

# HTTP-parser / framing-abuse modes
torshammer -u http://example.com -m slow-xml
torshammer -u http://example.com -m slow-form-parse
torshammer -u http://example.com -m header-count-flood
torshammer -u http://example.com -m websocket-slow-frame
torshammer -u http://example.com -m req-smuggling-probe

# HTTP/2 framing / HPACK-abuse modes (target must serve HTTP/2; use --backend rust or
# a build with h2c support, or front the target with an HTTP/2 cleartext listener)
torshammer -u http://example.com -m h2-rapid-reset
torshammer -u http://example.com -m h2-slow-streams
torshammer -u http://example.com -m h2-continuation-flood
torshammer -u http://example.com -m h2-hpack-drip

# TLS-handshake starvation modes (point at a TLS listener over a raw http:// target so
# the hand-built ClientHello bytes reach the port unwrapped)
torshammer -u http://example.com:443 -m tls-slow-hello
torshammer -u http://example.com:443 -m tls-renego-hold
```

## Slow POST Mode

### Also Known As

- Classic Tor's Hammer
- Slow POST
- Apache Killer (historical)

### Mechanism

1. Send HTTP POST request with large `Content-Length` header
2. Send complete HTTP headers
3. Send request body one byte at a time
4. Keep connection open indefinitely

### Request Structure

```http
POST /?random_token HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 4096

X
```

Then dribble remaining bytes one at a time with random delays.

### How It Works

The server reads the `Content-Length: 4096` header and allocates a buffer for 4096 bytes. It then waits for the body to arrive. Since the client sends only one byte at a time with long delays, the server keeps the connection open and the worker thread busy waiting for data that never arrives quickly.

### Target Systems

Most effective against:
- Apache (older versions)
- IIS (older versions)
- Servers with fixed thread pools
- Servers with long request timeouts

### Less Effective Against

- Nginx (event-driven architecture)
- Servers with aggressive timeouts
- Servers with worker thread limits
- Servers with rate limiting

### Configuration Options

Relevant options for slow-post mode:

- `--post-length` - Baseline Content-Length (default: 4096)
- `-dl` / `-dh` - Min/max dribble delay (default: 0.1/3.0 seconds)

### Example

```bash
torshammer -u http://example.com -m slow-post --post-length 8192 -dl 0.05 -dh 1.0
```

### Countermeasures

Server-side defenses:
- Reduce request timeout
- Limit maximum request size
- Implement rate limiting per IP
- Use event-driven architecture
- Monitor connection duration

## Slow POST Headers Mode

### Also Known As

- Slow POST headers
- Header-dribbling POST

### Mechanism

1. Send the HTTP POST request line on its own
2. Send each header line separately with a random delay
3. Complete the headers with the terminating blank line
4. Dribble the request body one byte at a time

### Request Structure

```http
POST /?random_token HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 2687

X
```

Each header line is flushed individually before the blank line and body dribble begin.

### How It Works

This mode combines the slowloris header trick with the classic slow POST body trick. The request
line and *every* header (including the randomized `Host`, `User-Agent`, `Accept` and custom headers)
is written one line at a time, each followed by a randomized delay, then the request is completed and
the body is dribbled byte by byte until the randomized `Content-Length` is reached. Servers that
validate the request line early but still hold the connection until the body arrives are tied up just
as effectively as with `slow-post`, while header-based IDS signatures see a different traffic shape.

Unlike `slow-post`, this mode always generates its body from the `--post-length` range and does not
use `--body-file`.

### Target Systems

Most effective against:
- Apache and IIS (thread/process per connection models)
- Servers with header timeout separate from body timeout
- Servers with long keep-alive/read timeouts

### Less Effective Against

- Nginx and other event-driven servers
- Servers with aggregate request time limits
- Servers with per-connection byte-rate limits

### Configuration Options

Relevant options for slow-post-headers mode:

- `--post-length` - Baseline Content-Length, randomized to `post-length/2` .. `post-length` (default: 4096)
- `-dl` / `-dh` - Min/max delay between header lines and body bytes (default: 0.1/3.0 seconds)
- `--header` / `--method` - Custom headers and HTTP method for the request

### Example

```bash
torshammer -u http://example.com -m slow-post-headers --post-length 4096 -c 256 -d 60
```

### Countermeasures

Server-side defenses:
- Reduce header read timeout independently of the body timeout
- Enforce a maximum total time per request
- Limit header count and total header size
- Use an event-driven architecture with request budgets

## Slow Headers Mode (Slowloris)

### Also Known As

- Slowloris
- Slow headers

### Mechanism

1. Send HTTP GET request line
2. Send partial headers (Host, User-Agent, etc.)
3. Never send terminating blank line (`\r\n\r\n`)
4. Continue sending headers slowly

### Request Structure

```http
GET /?random_token HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...
X-Random-Header-1: value
X-Random-Header-2: value
```

Headers continue indefinitely without the terminating blank line.

### How It Works

The HTTP/1.1 specification requires the request to end with a blank line. The server reads headers line by line, waiting for the blank line to signal the end of headers. Since the client never sends the blank line, the server keeps the connection open waiting for more headers.

### Target Systems

Most effective against:
- Apache (all versions)
- IIS (some versions)
- Servers with thread-based architectures
- Servers with long header timeouts

### Less Effective Against

- Nginx (has slowloris protection)
- Servers with header size limits
- Servers with aggressive timeouts
- Servers with connection limits per IP

### Configuration Options

Relevant options for slow-headers mode:

- `-dl` / `-dh` - Min/max delay between headers (default: 0.1/3.0 seconds)

### Example

```bash
torshammer -u http://example.com -m slow-headers -dl 0.1 -dh 2.0
```

### Countermeasures

Server-side defenses:
- Reduce header timeout
- Limit maximum header size
- Limit headers per request
- Implement slowloris protection (Nginx has this built-in)
- Limit connections per IP

## Slow Read Mode

### Also Known As

- Slow read
- Slow bytes
- Slow response

### Mechanism

1. Send complete HTTP GET request
2. Read response in tiny chunks (8 bytes at a time)
3. Pause between reads
4. Keep connection open while reading slowly

### Request Structure

```http
GET /?random_token HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...
Accept: text/html,...

(complete request with terminating blank line)
```

Then read response 8 bytes at a time with delays.

### How It Works

The server sends the complete response, but the client reads it very slowly (8 bytes at a time with delays). This keeps the server's socket buffer full and the connection open, preventing the server from closing the connection and freeing resources.

### Target Systems

Most effective against:
- Servers with large socket buffers
- Servers that keep connections open after response
- Servers with limited socket buffer space
- Servers with slow client timeout

### Less Effective Against

- Servers with small socket buffers
- Servers that close connections immediately
- Servers with aggressive read timeouts
- Servers with connection limits

### Configuration Options

Relevant options for slow-read mode:

- `-dl` / `-dh` - Min/max delay between reads (default: 0.1/3.0 seconds)
- `--connect-timeout` - Read timeout (default: 15.0 seconds)

### Example

```bash
torshammer -u http://example.com -m slow-read -dl 0.05 -dh 1.0 --connect-timeout 30
```

### Countermeasures

Server-side defenses:
- Reduce socket buffer size
- Close connections immediately after response
- Implement aggressive read timeouts
- Limit connection duration
- Monitor for slow-reading clients

## Chunked Mode

### Also Known As

- Chunked encoding attack
- Slow chunked

### Mechanism

1. Send HTTP POST request with `Transfer-Encoding: chunked`
2. Send data in small chunks
3. Never send terminating `0\r\n\r\n` chunk
4. Keep connection open indefinitely

### Request Structure

```http
POST /?random_token HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...
Transfer-Encoding: chunked
Content-Type: application/x-www-form-urlencoded

4\r\n
data\r\n
3\r\n
abc\r\n
```

Chunks continue without the terminating `0\r\n\r\n`.

### How It Works

HTTP/1.1 chunked encoding requires the client to send a `0\r\n\r\n` chunk to signal the end of the body. The server waits for this terminating chunk before considering the request complete. Since the client never sends it, the server keeps the connection open waiting.

### Target Systems

Most effective against:
- Servers supporting HTTP/1.1 chunked encoding
- Servers with long chunked encoding timeouts
- Servers with thread-based architectures
- Servers that wait for complete request bodies

### Less Effective Against

- Servers that disable chunked encoding
- Servers with aggressive chunked timeouts
- Servers with strict request validation
- Servers that reject malformed chunked data

### Configuration Options

Relevant options for chunked mode:

- `--post-length` - Baseline total size (default: 4096)
- `-dl` / `-dh` - Min/max delay between chunks (default: 0.1/3.0 seconds)

### Example

```bash
torshammer -u http://example.com -m chunked --post-length 8192 -dl 0.1 -dh 2.0
```

### Countermeasures

Server-side defenses:
- Disable chunked encoding support
- Reduce chunked encoding timeout
- Limit maximum chunked request size
- Validate chunked encoding strictly
- Implement time limits per request

## Multipart Slow Upload Mode

### Also Known As

- Slow multipart upload
- R-U-Dead-Yet variant (multipart framing)

### Mechanism

1. Send HTTP POST with `Content-Type: multipart/form-data` and a random boundary
2. Emit the request line and every header line separately with delays
3. Send a realistic file-upload preamble (`Content-Disposition`, filename, `Content-Type`)
4. Dribble MIME-part content one byte at a time forever
5. Never emit the closing boundary (`--<boundary>--`)

### Request Structure

```http
POST /?random_token HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryAb12Cd34Ef56Gh78Ij90Kl
Content-Length: 4096

------WebKitFormBoundaryAb12Cd34Ef56Gh78Ij90Kl
Content-Disposition: form-data; name="upload"; filename="a1B2c3D4e5.bin"
Content-Type: application/octet-stream

X
```

Body bytes dribble one at a time; fresh non-final boundaries (`field<N>` parts) are emitted
periodically so multipart parsers keep scanning and buffering without ever seeing the upload end.

### How It Works

Opaque-body attacks (`slow-post`, `chunked`) only pin the request-body reader. Multipart uploads
additionally engage the MIME parser: boundary scanning, per-part buffering, and — on real upload
endpoints — temp-file creation. The announced `Content-Length` is a fixed budget but the closing
boundary never arrives, so neither the parser nor the worker can consider the upload complete.

### Target Systems

Most effective against:
- File/media upload endpoints (WordPress media library, CMS attachment handlers)
- Frameworks buffering multipart bodies in memory or temp files (PHP, Django, Rails)
- Servers with long request-body timeouts and generous upload size limits

### Less Effective Against

- Servers that reject `multipart/form-data` on non-upload routes
- Servers with small aggregate `LimitRequestBody` / client-body limits
- Servers with aggressive body timeouts

### Configuration Options

Relevant options for multipart-slow-upload mode:

- `--post-length` - Baseline body accounting (default: 4096); the dribble itself is unbounded,
  the closing boundary is what never arrives
- `-dl` / `-dh` - Min/max delay between header lines and body bytes (default: 0.1/3.0 seconds)
- `--header` / `--method` / `--body-file` - Custom headers, method; a custom `Expect:` header is
  stripped (it would turn the upload into an expect/continue transaction), and `--body-file`
  does not change the multipart framing

### Example

```bash
torshammer -u http://example.com/wp-admin/media-new.php -m multipart-slow-upload -c 128 -d 60
```

### Countermeasures

Server-side defenses:
- Cap `multipart` part counts and per-part/total sizes independently of `Content-Length`
- Stream uploads to disk with strict quotas instead of buffering in memory
- Enforce per-request body time budgets, not just byte limits
- Reject oversized `Content-Type: multipart/*` on routes that never accept files

## Expect-Continue Abuse Mode

### Also Known As

- Expect stall
- 100-continue abuse

### Mechanism

1. Send complete headers with `Content-Length` **and** `Expect: 100-continue`
2. Wait for the interim server response (`100 Continue`, or a final rejection)
3. Dribble the announced body one byte at a time with random delays
4. Hold the socket open even after the announced byte count is exhausted

### Request Structure

```http
POST /?random_token HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...
Content-Type: application/x-www-form-urlencoded
Content-Length: 2687
Expect: 100-continue

X
```

The headers complete (unlike slowloris), the server decides on the interim response, and then
the promised body arrives at a trickle.

### How It Works

`Expect: 100-continue` exists so a server can reject an upload *before* reading it — but many
stacks allocate the request context, upload buffer, or PHP worker the moment they emit
`100 Continue`. The attack completes the exact handshake those code paths expect, then never
delivers the body at a useful rate. Any state allocated on the interim decision stays pinned
for the life of the connection, which, unlike plain `slow-post`, specifically exercises the
interim-response state machine.

A caller-supplied `Expect:` header (via `--header`) replaces the default instead of duplicating
it, in both backends.

### Target Systems

Most effective against:
- Apache + mod_php / PHP-FPM upload paths (the WordPress media flow)
- Reverse proxies that forward `100 Continue` and buffer the body (nginx `proxy_request_buffering`)
- Frameworks allocating upload state on the interim response

### Less Effective Against

- Servers that ignore `Expect:` entirely
- Servers that immediately finalize with `417 Expectation Failed` or `4xx` and close
- Servers with short body-phase timeouts regardless of interim handling

### Configuration Options

Relevant options for expect-continue-abuse mode:

- `--post-length` - Announced body range `post-length/2` .. `post-length` (default: 4096)
- `-dl` / `-dh` - Min/max delay between body bytes (default: 0.1/3.0 seconds)
- `--connect-timeout` - Interim-response read deadline (default: 15.0 seconds)

### Example

```bash
torshammer -u http://example.com -m expect-continue-abuse --post-length 8192 -c 256 -d 60
```

### Countermeasures

Server-side defenses:
- Do not allocate upload buffers until the first body bytes arrive
- Apply the same body timeout after `100 Continue` as for any other body
- Reject `Expect:` on routes that never need it
- Limit concurrent in-flight `100-continue` transactions per worker/IP

## UDP Flood Mode

### Mechanism

1. Send real UDP datagrams to target:port
2. Send randomized 1-32 byte payloads
3. Flood with controlled timing between datagrams
4. Maintain connection without completion

### Datagram Structure

```
UDP packet to target:port
Random payload: 1-32 bytes of alphanumeric data
Random delay between datagrams
```

### How It Works

The UDP flood mode sends actual UDP datagrams (not simulated traffic) to the target. Each datagram contains a random payload and is sent with controlled timing. This floods the target's UDP service with genuine network traffic, potentially exhausting network bandwidth or UDP service capacity.

### Target Systems

Most effective against:
- DNS servers
- UDP-based services
- Network appliances
- Gaming servers
- VoIP services

### Less Effective Against

- Services with rate limiting
- Services with firewall protection
- Services with DDoS mitigation
- Services with limited bandwidth

### Configuration Options

Relevant options for UDP mode:

- `-dl` / `-dh` - Min/max delay between datagrams (default: 0.1/3.0 seconds)
- `--post-length` - Baseline byte budget; each cycle sends `post-length/2` .. `post-length` bytes
  split into random 1-32 byte datagrams (default: 4096)

### Example

```bash
torshammer -u udp://8.8.8.8:53 -m udp -c 100 -d 30
```

### Countermeasures

Server-side defenses:
- Implement rate limiting per IP
- Use firewall rules to block excessive UDP traffic
- Implement DDoS protection
- Monitor for unusual traffic patterns
- Limit datagram processing rate

## WebSocket Slow Upgrade Mode

### Mechanism

1. Send HTTP GET request with WebSocket upgrade headers
2. Slowly send WebSocket-specific headers one by one
3. Never send terminating blank line to complete upgrade
4. Continue sending random headers to keep connection alive

### Request Structure

```http
GET /?random_token HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: chat
X-Random-Header: value
```

Headers continue indefinitely without the terminating blank line.

### How It Works

WebSocket upgrade requires the client to send specific headers and then complete the handshake. The server allocates resources for the WebSocket connection and waits for the handshake to complete. Since the client never sends the terminating blank line, the server keeps the connection open waiting for the upgrade to complete.

### Target Systems

Most effective against:
- WebSocket servers
- Real-time communication servers
- Chat applications
- Gaming servers with WebSocket support
- Notification services

### Less Effective Against

- Servers without WebSocket support
- Servers with aggressive header timeouts
- Servers with connection limits per IP
- Servers that reject incomplete upgrades

### Configuration Options

Relevant options for WebSocket slow upgrade mode:

- `-dl` / `-dh` - Min/max delay between headers (default: 0.1/3.0 seconds)

### Example

```bash
torshammer -u http://websocket-server -m websocket-slow-upgrade -c 128 -d 30
```

### Countermeasures

Server-side defenses:
- Reduce WebSocket handshake timeout
- Limit connections per IP
- Implement WebSocket-specific rate limiting
- Validate WebSocket headers early
- Monitor for incomplete handshake attempts

## HTTP Pipelining Mode

### Mechanism

1. Send multiple HTTP requests on same connection
2. Do not wait for responses between requests
3. Send up to 50 requests per connection
4. Hold the connection open with small random delays between requests

### Request Structure

```http
GET /?random_token HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...

GET /?random_token HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...

(repeated up to 50 times)
```

Multiple requests sent without waiting for responses.

### How It Works

HTTP/1.1 pipelining allows multiple requests to be sent on a single connection without waiting for responses. The server processes requests sequentially but must maintain state for all pipelined requests. By sending many requests without waiting, the client can exhaust the server's request buffer limits.

### Target Systems

Most effective against:
- HTTP/1.1 servers supporting pipelining
- Servers with large request buffers
- Servers that process requests sequentially
- Servers with limited request queue capacity

### Less Effective Against

- Servers that disable pipelining
- HTTP/2 servers (different multiplexing mechanism)
- Servers with small request buffers
- Servers with aggressive timeouts

### Configuration Options

Relevant options for HTTP pipelining mode:

- `-dl` / `-dh` - Min/max delay between requests (default: 0.1/3.0 seconds)

### Example

```bash
torshammer -u http://example.com -m http-pipelining -c 64 -d 30
```

### Countermeasures

Server-side defenses:
- Disable HTTP pipelining
- Limit requests per connection
- Reduce request buffer size
- Implement aggressive timeouts
- Monitor for pipelining abuse

## Range Header Abuse Mode

### Mechanism

1. Send multiple HTTP GET requests with Range headers
2. Each request requests different byte ranges
3. Send up to 100 range requests per connection
4. Target file handles through many range requests

### Request Structure

```http
GET /?random_token HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...
Range: bytes=12345-13345

GET /?random_token HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...
Range: bytes=54321-54345

(repeated up to 100 times)
```

Each request has a different random byte range.

### How It Works

HTTP Range requests allow clients to request specific byte ranges of a file. Servers must open file handles and maintain state for each range request. By sending many range requests with different byte ranges, the client can exhaust the server's file handle limits and memory.

### Target Systems

Most effective against:
- Servers serving large files
- Apache with Range header support (CVE-2011-3192 vulnerable)
- IIS with Range header support
- File servers
- Media streaming servers

### Less Effective Against

- Servers that disable Range support
- Servers with Range request limits
- Servers with strict validation
- Servers serving small files

### Configuration Options

Relevant options for Range header abuse mode:

- `-dl` / `-dh` - Min/max delay between requests (default: 0.1/3.0 seconds)

### Example

```bash
torshammer -u http://example.com/large-file.zip -m range-abuse -c 64 -d 30
```

### Countermeasures

Server-side defenses:
- Limit Range requests per connection
- Limit total Range requests per IP
- Validate Range header values strictly
- Implement request counting
- Monitor for Range header abuse

## Cookie Bomb Mode

### Mechanism

1. Send HTTP request with extremely large Cookie header
2. Cookie value is 10KB+ of random data
3. Keep connection alive with periodic keep-alive
4. Exhaust cookie parsing memory

### Request Structure

```http
GET /?random_token HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...
Cookie: bomb_cookie=<10KB of random data>
```

Cookie header contains very large value.

### How It Works

HTTP cookies are parsed by web servers to maintain session state. The server allocates memory to parse and store cookie values. By sending an extremely large cookie (10KB+), the client can exhaust the server's cookie parsing memory and cause memory exhaustion or slow parsing.

### Target Systems

Most effective against:
- Servers with large cookie parsing buffers
- Servers that store cookies in memory
- Session-based applications
- Web applications with extensive cookie usage

### Less Effective Against

- Servers with cookie size limits
- Servers that reject large cookies
- Servers with strict validation
- Servers that don't use cookies

### Configuration Options

Relevant options for Cookie bomb mode:

- `-dl` / `-dh` - Min/max delay for keep-alive (default: 0.1/3.0 seconds)

### Example

```bash
torshammer -u http://example.com -m cookie-bomb -c 64 -d 30
```

### Countermeasures

Server-side defenses:
- Limit maximum cookie size
- Reject oversized cookies
- Validate cookie format strictly
- Monitor for large cookie requests
- Implement cookie memory limits

## JSON-RPC Slow Mode

### Mechanism

1. Send HTTP POST request with JSON-RPC payload
2. Slowly send JSON payload character by character
3. Claim larger Content-Length than actual payload
4. Never complete JSON structure

### Request Structure

```http
POST /?random_token HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 ...
Content-Type: application/json
Content-Length: 1050

{"jsonrpc":"2.0","method":"slow_method","params":[
```

JSON payload sent character by character without completion.

### How It Works

JSON-RPC is a remote procedure call protocol using JSON. The server parses the JSON payload to extract method names and parameters. By slowly sending the JSON character by character and claiming a larger Content-Length, the client can keep the JSON parser busy waiting for data that never arrives quickly.

### Target Systems

Most effective against:
- JSON-RPC API servers
- WebSocket endpoints using JSON-RPC
- REST APIs with JSON bodies
- Microservices with JSON parsing

### Less Effective Against

- Servers with JSON size limits
- Servers with aggressive timeouts
- Servers that validate JSON structure
- Servers that reject incomplete JSON

### Configuration Options

Relevant options for JSON-RPC slow mode:

- `-dl` / `-dh` - Min/max delay between characters (default: 0.1/3.0 seconds)

### Example

```bash
torshammer -u http://api.example.com -m jsonrpc-slow -c 64 -d 30
```

### Countermeasures

Server-side defenses:
- Limit JSON payload size
- Validate JSON structure early
- Implement aggressive timeouts
- Reject incomplete JSON
- Monitor for slow JSON parsing

## SMTP Slow Envelope Mode

### Mechanism

1. Send SMTP envelope commands slowly
2. Send EHLO, MAIL FROM, RCPT TO commands
3. Never send DATA command to complete envelope
4. Continue sending incomplete RCPT TO commands

### Command Structure

```
EHLO example.com
MAIL FROM: <slow-test@example.com>
RCPT TO: <recipient@example.com>
RCPT TO: <another@example.com>
...
```

Commands sent without completing envelope.

### How It Works

SMTP servers process email envelopes through command sequences. The server allocates resources for each envelope stage and waits for the next command. By slowly sending envelope commands and never completing with DATA, the client can exhaust SMTP connection limits and keep connections open.

### Target Systems

Most effective against:
- SMTP mail servers
- Email gateway servers
- MTA (Mail Transfer Agent) servers
- Spam filtering systems

### Less Effective Against

- Servers with command rate limits
- Servers with aggressive timeouts
- Servers that reject incomplete envelopes
- Servers with connection limits

### Configuration Options

Relevant options for SMTP slow envelope mode:

- `-dl` / `-dh` - Min/max delay between commands (default: 0.1/3.0 seconds)

### Example

```bash
torshammer -u http://smtp-server:25 -m smtp-slow-envelope -c 64 -d 30
```

### Countermeasures

Server-side defenses:
- Limit commands per connection
- Implement aggressive timeouts
- Reject incomplete envelopes
- Monitor for slow command sequences
- Limit connections per IP

## FTP Slow Command Mode

### Mechanism

1. Send FTP commands slowly
2. Send USER, PASS, PASV commands
3. Never complete data transfer
4. Continue sending PASV commands

### Command Structure

```
USER anonymous
PASS test@example.com
PASV
PASV
...
```

Commands sent without completing data transfer.

### How It Works

FTP servers process commands in sequence to establish connections and data transfers. The server allocates resources for each command stage and waits for the next command. By slowly sending commands and never completing data transfer, the client can exhaust FTP connection limits.

### Target Systems

Most effective against:
- FTP servers
- File transfer servers
- Anonymous FTP services
- Legacy FTP implementations

### Less Effective Against

- Servers with command rate limits
- Servers with aggressive timeouts
- Servers that reject incomplete sequences
- Servers with connection limits

### Configuration Options

Relevant options for FTP slow command mode:

- `-dl` / `-dh` - Min/max delay between commands (default: 0.1/3.0 seconds)

### Example

```bash
torshammer -u http://ftp-server:21 -m ftp-slow-command -c 64 -d 30
```

### Countermeasures

Server-side defenses:
- Limit commands per connection
- Implement aggressive timeouts
- Reject incomplete sequences
- Monitor for slow command sequences
- Limit connections per IP

## IMAP Slow Literal Mode

### Mechanism

1. Send `<TAG> APPEND INBOX {N}\r\n` announcing an IMAP literal of `N` octets
2. A conforming server replies `+ ` and blocks until it has read exactly `N` bytes
3. Drip a handful of literal bytes, then never deliver the rest
4. Hold the connection open indefinitely

### How It Works

The `{N}` literal tells the IMAP server that `N` opaque bytes follow. The server
sizes its APPEND buffer and parks the mailbox worker inside its literal read.
Because the promised bytes never arrive, that worker (and the mailbox it holds)
stays pinned. `N` is randomized within the `--post-length` range and the tag is a
random 4-character literal so connections do not share a fingerprint.

### Target Systems

- IMAP4rev1 servers (Dovecot, Courier, Microsoft Exchange)
- Servers that allocate a worker/mailbox lock per in-flight command

### Example

```bash
torshammer -u http://mail-server:143 -m imap-slow-literal -c 64 -d 60
```

### Countermeasures

- Enforce an literal-arrival timeout, not just a command timeout
- Cap concurrent incomplete APPEND literals per IP

## Redis RESP Slow Mode

### Mechanism

1. Send a one-element multibulk frame `*1\r\n` followed by `$<len>\r\n`
2. Redis reads `len` to size a bulk argument and waits for exactly `len` bytes + CRLF
3. Emit a few bulk bytes, then stall with the terminating CRLF withheld

### How It Works

RESP bulk strings are length-prefixed; Redis commits a client read handler to
buffering `len` bytes before it can dispatch the command. Declaring an oversized
`$len` and never finishing it pins that client slot. The `maxclients` limit turns
a handful of stalled connections into a denial of new clients.

### Target Systems

- Redis and RESP-speaking servers/caches

### Example

```bash
torshammer -u http://redis-host:6379 -m redis-resp-slow -c 128 -d 60
```

### Countermeasures

- Apply a per-client input buffer/idle timeout (`client-output-buffer-limit`, idle timeout)
- Cap and reclaim stalled clients well below `maxclients`

## Postgres Startup Slow Mode

### Mechanism

1. Send a StartupMessage: Int32 length (counting itself) + Int32 version `196608` (3.0)
2. Follow with `user=...\0database=...\0` parameters but claim a larger length than sent
3. Never emit the terminating NUL that closes the packet

### How It Works

PostgreSQL reads the 4-byte length, then `secure_read`s exactly that many octets
before it will begin authentication. The backend process forked for the connection
blocks in that read, tying up a process slot and the associated memory for the whole
declared length that never lands.

### Target Systems

- PostgreSQL and other servers using a length-prefixed startup handshake

### Example

```bash
torshammer -u http://db-host:5432 -m postgres-startup-slow -c 64 -d 60
```

### Countermeasures

- Enforce a startup-packet timeout (`authentication_timeout` covers auth, not the length read)
- Front with a connection proxy that validates the framing before forking a backend

## DNS TCP Slow Mode

### Mechanism

1. Send the 2-byte big-endian TCP length prefix declaring a large DNS message
2. Emit the 12-byte query header (ID `0xAABB`, `RD`, `QDCOUNT=1`) plus a couple of bytes
3. Never complete the declared message

### How It Works

DNS-over-TCP (RFC 1035 §4.2.2) prefixes each message with its octet length. The
resolver allocates a receive buffer of that size and blocks until the whole query
arrives. Over-promising the length and under-delivering pins the TCP query handler.

### Target Systems

- Recursive/authoritative DNS servers with TCP support (BIND, Unbound, PowerDNS)

### Example

```bash
torshammer -u http://dns-host:53 -m dns-tcp-slow -c 64 -d 60
```

### Countermeasures

- Cap advertised TCP message sizes and apply a per-connection message timeout
- Limit concurrent inbound TCP queries per source

## NNTP Slow Post Mode

### Mechanism

1. Send `POST\r\n`; a server replies `340` and begins reading an article
2. Drip header/body lines slowly (`X-<rand>: <rand>\r\n`)
3. Never emit the terminating `\r\n.\r\n` dot-line

### How It Works

NNTP marks the end of a posted article with a line containing only a single `.`.
The reader process holds the article buffer and its slot open until that terminator
appears. Withholding it parks the process mid-transfer.

### Target Systems

- NNTP news servers (INN, DS, DNews)

### Example

```bash
torshammer -u http://nntp-host:119 -m nntp-slow-post -c 64 -d 60
```

### Countermeasures

- Apply an article-transfer timeout that starts at `340`, not at first byte
- Limit concurrent unfinished POSTs per peer

## Idle Hold Mode

### Mechanism

1. Open a TCP connection to the target
2. Send **zero** bytes
3. Hold the socket open until the run is stopped

### How It Works

Many servers cap concurrent connections (or idle worker slots) and only start a
timeout/reaper once request bytes arrive. A silent, fully-open socket consumes a
connection slot and file descriptor with no request to fingerprint, parse, or
rate-limit. At scale this exhausts the accept backlog / connection table.

### Target Systems

- Thread- or process-per-connection servers with a bounded connection pool
- Services that only arm their idle timeout after the first request line

### Configuration Options

- `-dl` / `-dh` - Min/max keep-alive interval (the socket is held with sleeps, never written to)

### Example

```bash
torshammer -u http://example.com -m idle-hold -c 256 -d 120
```

### Countermeasures

- Arm an accept-before-first-byte timeout on every connection
- Enforce per-IP connection limits and a bounded backlog

## Slow XML Mode

### Also Known As

- XML parser starvation
- Billion-laughs / XXE-shaped slow body

### Mechanism

1. Send a POST with `Content-Type: application/xml` and an oversized `Content-Length`
   (a multiple of the `--post-length` range)
2. Emit an **unclosed** document prolog: `<?xml ...?><!DOCTYPE bomb [ <!ENTITY a "`
3. Dribble body bytes one at a time, never closing the entity, DTD, or document

### How It Works

XML/SOAP stacks frequently buffer the whole document before handing it to a
DOM/expat parser and pre-expand entity declarations while doing so. By announcing
a large `Content-Length` and starting a `DOCTYPE`/entity that never terminates, the
parser stays in its accumulate-and-validate stage, holding both the request buffer
and (on pre-loading parsers) entity-expansion work. Unlike `slow-post` this targets
the *XML* decoding path rather than the opaque body reader.

### Target Systems

- SOAP/XML-RPC endpoints and gateways
- Stacks that parse the full document before processing (Java `DocumentBuilder`,
  libxml2-backed PHP, .NET `XmlDocument`) before entity-expansion limits engage

### Example

```bash
torshammer -u http://example.com/soap -m slow-xml --post-length 16384 -c 128 -d 60
```

### Countermeasures

- Disable DTD/entity processing (or apply strict `XMLSecurityManager` / entity limits)
- Stream-parse with hard byte budgets instead of buffering to `Content-Length`
- Cap `Content-Length` and apply a body-read timeout

## Slow Form Parse Mode

### Mechanism

1. Send a POST with `Content-Type: application/x-www-form-urlencoded` and a very
   large `Content-Length`
2. Emit an endless trickle of `key=value&` pairs (fresh random names per pair)
3. Never fill the announced byte count, so the parse never finalizes

### How It Works

Many frameworks allocate their form-decoding buffer and per-field storage from the
announced `Content-Length` up front, then split on `&`/`=`, URL-decode and validate
each field as it arrives. Because the declared length is far larger than what is
slowly delivered, the parser keeps a live, partially-parsed field map for the life
of the connection — tying up the worker and the request-scoped memory.

### Target Systems

- Form handlers in PHP, Django, Rails, Spring (parameter-binding stages)
- Servers that pre-allocate parse state from `Content-Length`

### Example

```bash
torshammer -u http://example.com/submit -m slow-form-parse --post-length 32768 -c 128 -d 60
```

### Countermeasures

- Do not pre-allocate from `Content-Length`; grow buffers incrementally with a cap
- Bound the number of accepted form fields and total decoded size
- Apply an aggregate request time budget

## Header Count Flood Mode

### Mechanism

1. Send the request line and `Host:`
2. Emit ~2000 tiny `X-<rand>: <rand>` headers, pausing every 64 lines
3. **Complete** the header block with the terminating blank line, then hold the socket

### How It Works

Servers commonly cap total header *size* (which `slow-headers`/slowloris stays under)
but place a much higher — or no — limit on header *count*. Each header still costs a
list node, a hash-map entry and a lowercase/copy pass in the request object. Emitting
thousands of minimal headers per connection multiplies that per-header cost, and
because the request is actually completed this exercises a different code path than
slowloris: post-parse handler work rather than a stuck header reader.

### Target Systems

- Servers/proxies that cap header bytes but not header entries
- Frameworks building large case-insensitive header maps per request

### Example

```bash
torshammer -u http://example.com -m header-count-flood -c 128 -d 60
```

### Countermeasures

- Enforce a maximum header **count** per request, not only a maximum header size
- Reject requests exceeding the limit early (before building the full header table)

## WebSocket Slow Frame Mode

### Mechanism

1. Send a **complete** WebSocket upgrade request (proper `Sec-WebSocket-Key`, blank line)
2. After the handshake, emit a binary frame header advertising a large masked payload
   length (`FIN`+`0x81`, extended length `4096`, 4 mask bytes)
3. Dribble payload bytes one at a time so the declared frame length is never satisfied

### How It Works

This is the post-handshake counterpart to `websocket-slow-upgrade`. That mode stalls
the HTTP header parser; this one gets the upgrade accepted and then pins the *frame
reader*: the server allocates an unmasking buffer sized from the frame's declared
length and blocks until every payload byte arrives. Because the socket is already a
WebSocket, HTTP-layer slowloris mitigations do not apply.

### Target Systems

- WebSocket servers that buffer a full frame before dispatch
- Real-time/chat/game/notification backends past the handshake

### Example

```bash
torshammer -u http://chat-server -m websocket-slow-frame -c 128 -d 60
```

### Countermeasures

- Cap maximum frame size and apply a per-frame assembly timeout
- Bound concurrent half-received frames per connection/IP

## Request Smuggling Probe Mode

### Mechanism

1. Send a POST carrying **both** `Content-Length: 6` and `Transfer-Encoding: chunked`
2. Follow with a body that is a valid final chunk (`0\r\n\r\n`) *and* a trailing
   `GET /smuggled HTTP/1.1` request line
3. Hold the socket open so the differential framing handling is observable

### How It Works

When a front-end and back-end disagree about whether `Content-Length` or
`Transfer-Encoding` wins, the two requests they each see desynchronize — the
signature of HTTP request smuggling (CL.TE). This mode sends the classic ambiguous
CL.TE probe once and holds the connection so a test harness can observe whether a
server/proxy accepts, rejects, or desynchronizes on the framing conflict. It is a
*detection probe* for authorized testing, not an exploit payload.

Framing headers the profile emits cannot be overridden by `--header`: any
caller-supplied `Content-Length`, `Transfer-Encoding`, `Expect` or `Te` is stripped
before the probe's own framing headers are added (in both backends), so the
ambiguous request is always well-formed.

### Target Systems

- HTTP front-ends / reverse proxies / WAFs in front of a distinct back-end parser

### Example

```bash
torshammer -u http://example.com -m req-smuggling-probe -c 32 -d 30
```

### Countermeasures

- Normalize/reject requests bearing both `Content-Length` and `Transfer-Encoding`
- Ensure front-end and back-end use the same framing rules and HTTP stack

## HTTP/2 Rapid Reset Mode

### Also Known As

- HTTP/2 Rapid Reset (CVE-2023-44487 class)

### Mechanism

1. Send the HTTP/2 client preface + `SETTINGS` and a `SETTINGS` ACK
2. On that single connection, emit a burst of `HEADERS` frames (each a complete,
   self-contained request with `END_HEADERS | END_STREAM`) on fresh odd stream ids
3. Immediately follow each `HEADERS` with a `RST_STREAM` (`NO_ERROR`)
4. Loop forever, wrapping the stream id before the reserved boundary

### How It Works

Opening a stream makes the server allocate per-stream state (a request context,
flow-control window, header table entry); a `RST_STREAM` tells it to tear that
state down out of band. Because the reset arrives before the request could ever
be served, the server does the expensive alloc/dealloc work repeatedly at
near-zero bandwidth — the exact asymmetry the 2023 rapid-reset wave exploited.
Frames and HPACK blocks are hand-built in `h2.py`/`h2.rs`, so no HTTP/2 library
or prior negotiation is required.

### Target Systems

- HTTP/2 servers that count concurrent streams but do not rate-limit resets
- Reverse proxies / load balancers multiplexing many back-end streams per connection

### Example

```bash
torshammer -u http://example.com -m h2-rapid-reset -c 4 -d 60
```

### Countermeasures

- Limit the number of RST_STREAM frames per unit time / per connection (the fix
  shipped for CVE-2023-44487)
- Cap concurrent streams and account reset-heavy streams against stream budgets

## HTTP/2 Slow Streams Mode

### Mechanism

1. Send the HTTP/2 preface + `SETTINGS`/ACK
2. Open 32 streams whose `HEADERS` set `END_HEADERS` but **not** `END_STREAM`
   (each announces a `POST` that still owes a body)
3. Round-robin a single byte of `DATA` onto each stream forever, never closing one

### How It Works

An HTTP/2 server that accepts a request without `END_STREAM` keeps the stream
half-open: its flow-control window, receive buffer and per-stream bookkeeping
stay live until the body completes or a timeout fires. By spreading a trickle of
`DATA` across many such streams on one connection, the client pins a large amount
of server-side per-stream state at a token-byte-per-second rate — the HTTP/2
equivalent of holding many body-phase slow requests open at once.

### Target Systems

- HTTP/2 servers with generous per-connection stream limits and long body timeouts

### Example

```bash
torshammer -u http://example.com -m h2-slow-streams -c 8 -d 120
```

### Countermeasures

- Bound concurrent half-open streams per connection and per IP
- Apply a per-stream inactivity/idle timeout, not just a whole-connection one

## HTTP/2 Continuation Flood Mode

### Mechanism

1. Send the HTTP/2 preface + `SETTINGS`/ACK
2. Open a header block with a `HEADERS` frame whose `END_HEADERS` is clear
3. Keep the block open with an unbounded run of `CONTINUATION` frames (batches of
   256), **never** setting `END_HEADERS`

### How It Works

RFC 7540 requires `CONTINUATION` frames to immediately follow a `HEADERS` (or
prior `CONTINUATION`) frame whose `END_HEADERS` is clear, so the server cannot
process anything else until the block closes. It must buffer the ever-growing
reassembled header block while counting an ever-growing number of frames. The
block is never completed, so reassembly state accumulates without bound until a
framing/header-count limit trips — exercising a different path than the header
*bytes* cap that `slow-headers` stays under.

### Target Systems

- HTTP/2 implementations that cap header size but not frame count or reassembly depth

### Example

```bash
torshammer -u http://example.com -m h2-continuation-flood -c 4 -d 60
```

### Countermeasures

- Enforce a maximum number of `CONTINUATION` frames / reassembled block size
- Apply a header-block reassembly timeout

## HTTP/2 HPACK Drip Mode

### Mechanism

1. Send the HTTP/2 preface + `SETTINGS`/ACK
2. Build one valid HPACK header block (literal-without-indexing fields, no dynamic
   table), then emit only its **first octet** in the `HEADERS` frame
3. Feed the remaining octets one at a time via `CONTINUATION` frames, each after a
   random delay, setting `END_HEADERS` only on the final byte
4. Hold the connection open afterwards (the completed `POST` still owes a body)

### How It Works

This is the HTTP/2 analogue of a slowloris header drip, done at the framing/HPACK
layer. HPACK blocks may be fragmented across `HEADERS` + `CONTINUATION` frames, so
a server must reassemble the whole block before it can decode the headers. Sending
one octet per frame with delays keeps that reassembly buffer and the stream pinned
for as long as the server tolerates an incomplete header block. The blocks use only
`0x00`-prefixed literal fields (never Huffman, never the dynamic table), so the
stream is valid HPACK and no prior encoder state is assumed.

### Target Systems

- HTTP/2 servers with long header-block reassembly timeouts

### Example

```bash
torshammer -u http://example.com -m h2-hpack-drip -dl 0.5 -dh 5.0 -c 64 -d 120
```

### Countermeasures

- Bound the time an incomplete header block may stay half-received
- Limit concurrent streams with open (unclosed) header blocks

## Randomization Techniques

All HTTP-based attack modes (`slow-post`, `slow-post-headers`, `slow-headers`, `slow-read`,
`chunked`, `multipart-slow-upload`, `expect-continue-abuse`, `websocket-slow-upgrade`,
`http-pipelining`, `range-abuse`, `cookie-bomb`, `jsonrpc-slow`) share the same randomization
layer, so requests never look like a fixed fingerprint. The multipart boundary, upload filename,
and non-final part names are freshly random per connection, and the protocol-specific modes
randomize what they can: `udp` uses random 1-32 byte payloads with random delays,
`range-abuse` randomizes the byte range per request, `cookie-bomb` randomizes the cookie value,
and `smtp-slow-envelope` / `ftp-slow-command` randomize their timing (their command syntax is
fixed by the respective RFC).

### Request Randomization

**Random Query Parameters:**
```http
GET /?aB3xY9z HTTP/1.1
```
Each connection gets a cryptographically random query parameter.

**Random Headers:**
```http
X-Forwarded-For: 192.168.1.100
X-Trace-Id: a1b2c3d4e5f6
```
Random X-Forwarded-For and X-Trace-Id headers added randomly. `Referer`, `Cache-Control`, `DNT`
and `TE` are also emitted probabilistically, and every header name emitted by `slow-headers`,
`slow-post-headers` and `websocket-slow-upgrade` is freshly generated.

**User-Agent Rotation:**
Each connection selects a random User-Agent from the provided list.

### Timing Randomization

**Random Delays:**
Actual delay between sends is randomly chosen between `delay-min` and `delay-max`:
```python
delay = random.uniform(delay_min, delay_max)
```

This prevents timing-based detection.

### Size Randomization

**Random Content-Length:**
Actual body size is randomized:
```python
length = random.randint(base_post_length // 2, base_post_length)
```

This prevents size-based detection.

## Choosing the Right Mode

### For Testing Apache

**Most Effective:** Slow headers (slowloris)

```bash
torshammer -u http://apache-server -m slow-headers
```

### For Testing IIS

**Most Effective:** Slow POST

```bash
torshammer -u http://iis-server -m slow-post
```

### For Testing Nginx

**Note:** Nginx has built-in slowloris protection. Try slow-read mode:

```bash
torshammer -u http://nginx-server -m slow-read
```

### For Testing WebSocket Servers

**Most Effective:** WebSocket slow upgrade

```bash
torshammer -u http://chat-server -m websocket-slow-upgrade -c 128 -d 60
```

### For Testing Web/JSON APIs

**Most Effective:** `jsonrpc-slow` for JSON-RPC endpoints, `slow-post` or `chunked` for REST endpoints

```bash
torshammer -u http://api-server/rpc -m jsonrpc-slow -c 128 -d 60
torshammer -u http://api-server/v1/items -m slow-post --post-length 16384 -c 128 -d 60
```

### For Testing File Uploads

**Most Effective:** `multipart-slow-upload` against the upload route, `expect-continue-abuse` when the
stack honors `Expect: 100-continue` (the WordPress media flow is the textbook case)

```bash
torshammer -u http://wp-server/wp-admin/media-new.php -m multipart-slow-upload -c 128 -d 60
torshammer -u http://wp-server/wp-admin/media-new.php -m expect-continue-abuse -c 128 -d 60
```

### For Testing File, Media and CDN Servers

**Most Effective:** `range-abuse` (servers honoring `Range`), `http-pipelining` (pipelining-friendly servers)

```bash
torshammer -u http://cdn-server/large-file.bin -m range-abuse -c 64 -d 60
```

### For Testing Mail Servers

**Most Effective:** SMTP slow envelope (ports 25 / 587)

```bash
torshammer -u http://mail-server:25 -m smtp-slow-envelope -c 64 -d 60
```

### For Testing FTP Servers

**Most Effective:** FTP slow command (port 21)

```bash
torshammer -u http://ftp-server:21 -m ftp-slow-command -c 64 -d 60
```

### For Testing UDP Services

**Most Effective:** UDP flood (DNS on 53, game and VoIP services)

```bash
torshammer -u udp://dns-server:53 -m udp -c 100 -d 60
```

### For Testing Modern Servers

**Try all modes:**

```bash
for mode in slow-post slow-post-headers slow-headers slow-read chunked \
            multipart-slow-upload expect-continue-abuse \
            websocket-slow-upgrade http-pipelining range-abuse cookie-bomb \
            jsonrpc-slow smtp-slow-envelope ftp-slow-command \
            imap-slow-literal redis-resp-slow postgres-startup-slow \
            dns-tcp-slow nntp-slow-post idle-hold \
            slow-xml slow-form-parse header-count-flood \
            websocket-slow-frame req-smuggling-probe \
            h2-rapid-reset h2-slow-streams h2-continuation-flood h2-hpack-drip \
            tls-slow-hello tls-renego-hold; do
  torshammer -u http://server -m "$mode" -d 30 --json > "$mode.json"
done
```

Compare results to see which mode is most effective. Protocol-specific modes (`smtp-slow-envelope`,
`ftp-slow-command`, `udp`) need a target service that speaks the matching protocol — pointing them at
an HTTP listener only tests the HTTP listener's tolerance of foreign bytes. The `h2-*` modes need an
HTTP/2 target and the `tls-*` modes need a TLS listener (point them at it over a raw `http://host:port`
target so the hand-built handshake bytes reach the port unwrapped).

### Backend Support

Every mode is available from both backends; pass `--backend python` or `--backend rust` to the unified
CLI. Both backends ship the same random header set - the only difference is that the Rust engine
randomizes from its built-in User-Agent pool instead of a `--user-agents` file.

| Mode | Python | Rust |
|------|--------|------|
| `slow-post` | ✅ | ✅ |
| `slow-post-headers` | ✅ | ✅ |
| `slow-headers` | ✅ | ✅ |
| `slow-read` | ✅ | ✅ |
| `chunked` | ✅ | ✅ |
| `multipart-slow-upload` | ✅ | ✅ |
| `expect-continue-abuse` | ✅ | ✅ |
| `websocket-slow-upgrade` | ✅ | ✅ |
| `http-pipelining` | ✅ | ✅ |
| `range-abuse` | ✅ | ✅ |
| `cookie-bomb` | ✅ | ✅ |
| `jsonrpc-slow` | ✅ | ✅ |
| `smtp-slow-envelope` | ✅ | ✅ |
| `ftp-slow-command` | ✅ | ✅ |
| `imap-slow-literal` | ✅ | ✅ |
| `redis-resp-slow` | ✅ | ✅ |
| `postgres-startup-slow` | ✅ | ✅ |
| `dns-tcp-slow` | ✅ | ✅ |
| `nntp-slow-post` | ✅ | ✅ |
| `idle-hold` | ✅ | ✅ |
| `slow-xml` | ✅ | ✅ |
| `slow-form-parse` | ✅ | ✅ |
| `header-count-flood` | ✅ | ✅ |
| `websocket-slow-frame` | ✅ | ✅ |
| `req-smuggling-probe` | ✅ | ✅ |
| `h2-rapid-reset` | ✅ | ✅ |
| `h2-slow-streams` | ✅ | ✅ |
| `h2-continuation-flood` | ✅ | ✅ |
| `h2-hpack-drip` | ✅ | ✅ |
| `tls-slow-hello` | ✅ | ✅ |
| `tls-renego-hold` | ✅ | ✅ |
| `udp` | ✅ | ✅ |

## Mode Comparison

| Mode | Transport / Protocol | Completes Request | Reads Response | Bandwidth | Detection Difficulty |
|------|----------------------|-------------------|----------------|-----------|----------------------|
| `slow-post` | HTTP/1.1 POST | No (body dribbled) | No | Very low | Medium |
| `slow-post-headers` | HTTP/1.1 POST | No (body dribbled) | No | Very low | Medium |
| `slow-headers` | HTTP/1.1 GET | No (headers never end) | No | Very low | High |
| `slow-read` | HTTP/1.1 GET | Yes | Yes (8 bytes at a time) | Low | Low |
| `chunked` | HTTP/1.1 chunked | No (no 0-chunk) | No | Very low | Medium |
| `multipart-slow-upload` | HTTP/1.1 multipart POST | No (no closing boundary) | No | Very low | High |
| `expect-continue-abuse` | HTTP/1.1 POST + `Expect` | No (body stalled) | Interim only | Very low | High |
| `websocket-slow-upgrade` | HTTP/1.1 → WebSocket upgrade | No (no blank line) | No | Very low | High |
| `http-pipelining` | HTTP/1.1 | 50 requests per connection | No | Low | Low |
| `range-abuse` | HTTP/1.1 `Range` | 100 requests per connection | No | Low | Low |
| `cookie-bomb` | HTTP/1.1 | Yes | No | Medium (10 KB header) | Low |
| `jsonrpc-slow` | HTTP/1.1 + JSON-RPC | No (claimed length never filled) | No | Very low | High |
| `smtp-slow-envelope` | SMTP | No (no `DATA`) | No | Very low | Medium |
| `ftp-slow-command` | FTP | No (no data transfer) | No | Very low | Medium |
| `imap-slow-literal` | IMAP4rev1 | No (literal never delivered) | No | Very low | High |
| `redis-resp-slow` | Redis RESP | No (bulk never closed) | No | Very low | High |
| `postgres-startup-slow` | PostgreSQL | No (startup packet never terminated) | No | Very low | High |
| `dns-tcp-slow` | DNS-over-TCP | No (query never completed) | No | Very low | High |
| `nntp-slow-post` | NNTP | No (dot-terminator withheld) | No | Very low | High |
| `idle-hold` | any TCP | No (zero bytes sent) | No | None | High |
| `slow-xml` | HTTP/1.1 XML POST | No (document never closes) | No | Very low | High |
| `slow-form-parse` | HTTP/1.1 urlencoded POST | No (length never filled) | No | Very low | High |
| `header-count-flood` | HTTP/1.1 GET | Yes (~2000 headers) | No | Low | Medium |
| `websocket-slow-frame` | HTTP/1.1 → WebSocket frames | Handshake yes; frame no | No | Very low | High |
| `req-smuggling-probe` | HTTP/1.1 CL.TE | Yes (ambiguous framing) | No | Very low | Medium |
| `h2-rapid-reset` | HTTP/2 (h2c) | Yes (HEADERS) then RST per stream | No | Very low | Medium |
| `h2-slow-streams` | HTTP/2 (h2c) | No (streams half-open) | No | Very low | High |
| `h2-continuation-flood` | HTTP/2 (h2c) | No (header block never closes) | No | Very low | High |
| `h2-hpack-drip` | HTTP/2 (h2c) | No (HPACK block dribbled a byte/frame) | No | Very low | High |
| `tls-slow-hello` | TLS handshake record | No (record never completed) | No | Very low | High |
| `tls-renego-hold` | TLS handshake records | No (ClientHello records never completed) | No | Very low | High |
| `udp` | UDP datagrams | N/A (stateless) | No | High (flood) | Low |

## Testing Methodology

### 1. Baseline Test

Start with conservative settings:

```bash
torshammer -u http://test-server -c 64 -d 30
```

### 2. Monitor Server

Watch server metrics:
- Active connections
- Response time
- Error rate
- Resource utilization

### 3. Increase Gradually

If server handles baseline, increase concurrency:

```bash
torshammer -u http://test-server -c 128 -d 30
torshammer -u http://test-server -c 256 -d 30
```

### 4. Try Different Modes

Test each mode to find the most effective:

```bash
torshammer -u http://test-server -m slow-headers -c 128 -d 30
torshammer -u http://test-server -m slow-read -c 128 -d 30
torshammer -u http://test-server -m slow-post-headers -c 128 -d 30
torshammer -u http://test-server -m multipart-slow-upload -c 128 -d 30
torshammer -u http://test-server -m expect-continue-abuse -c 128 -d 30
torshammer -u http://test-server -m http-pipelining -c 128 -d 30
torshammer -u http://test-server -m websocket-slow-upgrade -c 128 -d 30
torshammer -u http://test-server -m range-abuse -c 64 -d 30
```

Protocol-specific modes need a matching service on the target port:

```bash
torshammer -u http://test-server -m jsonrpc-slow -c 128 -d 30     # JSON-RPC endpoint
torshammer -u http://test-server:25 -m smtp-slow-envelope -c 64 -d 30
torshammer -u http://test-server:21 -m ftp-slow-command -c 64 -d 30
torshammer -u udp://test-server:53 -m udp -c 100 -d 30
```

Repeat with `--backend rust` to compare backends; the traffic patterns are equivalent.

### 5. Document Results

Record:
- Concurrency level where issues appear
- Which mode is most effective
- Server behavior (timeouts, errors, etc.)
- Mitigation effectiveness

## Troubleshooting Attack Modes

### No Impact on Server

**Possible Causes:**
- Server has mitigations in place
- Concurrency too low
- Network latency too high
- Wrong mode for server type

**Solutions:**
- Increase concurrency (`-c`)
- Try different modes
- Reduce delays (`-dl`, `-dh`)
- Check server logs

### Connections Close Immediately

**Possible Causes:**
- Server has aggressive timeouts
- Server rejects requests
- Network issues
- WAF/IDS interference

**Solutions:**
- Reduce delays (`-dl`, `-dh`)
- Check server logs
- Verify network connectivity
- Try different mode

### High Error Rate

**Possible Causes:**
- Server rate limiting
- Connection limits
- Network issues
- Proxy issues

**Solutions:**
- Reduce concurrency
- Use proxy rotation
- Check network connectivity
- Verify proxy configuration

## Security Considerations

### Authorization Required

All attack modes require explicit authorization to use against target systems.

### Defensive Use Only

These modes are designed for:
- Testing server resilience
- Validating mitigations
- Security research
- Educational purposes

### Not for Exploitation

Do not use for:
- Unauthorized denial-of-service attacks
- Disrupting production systems
- Causing harm to third parties

## See Also

- [Security Documentation](security.md) - Authorization requirements
- [CLI Reference](cli.md) - Command-line options
- [Configuration Guide](configuration.md) - Mode configuration
- [Architecture Documentation](architecture.md) - Profile implementation
