# Attack Modes Documentation

## Overview

Torshammer 2.0 implements four distinct slow-requests attack vectors, each designed to exhaust web server resources through different protocol manipulation techniques.

## Attack Modes Summary

| Mode | Also Known As | Mechanism | Primary Target |
|------|---------------|-----------|-----------------|
| `slow-post` | Slow POST, Tor's Hammer | Large Content-Length, dribble body | Worker threads/processes |
| `slow-headers` | Slowloris | Never finish headers | Worker threads/processes |
| `slow-read` | Slow-read, Slow-bytes | Read response slowly | Server socket buffers |
| `chunked` | Chunked encoding | Never send terminating chunk | Worker threads/processes |

## Mode Selection

Use the `-m` or `--mode` flag:

```bash
torshammer -u http://example.com -m slow-post
torshammer -u http://example.com -m slow-headers
torshammer -u http://example.com -m slow-read
torshammer -u http://example.com -m chunked
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

## Randomization Techniques

All attack modes implement randomization to evade simple fingerprinting:

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
Random X-Forwarded-For and X-Trace-Id headers added randomly.

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

### For Testing Modern Servers

**Try all modes:**

```bash
torshammer -u http://server -m slow-post -d 30 --json > slow-post.json
torshammer -u http://server -m slow-headers -d 30 --json > slow-headers.json
torshammer -u http://server -m slow-read -d 30 --json > slow-read.json
torshammer -u http://server -m chunked -d 30 --json > chunked.json
```

Compare results to see which mode is most effective.

## Mode Comparison

| Characteristic | Slow POST | Slow Headers | Slow Read | Chunked |
|----------------|-----------|--------------|-----------|---------|
| HTTP Method | POST | GET | GET | POST |
| Completes Headers | Yes | No | Yes | Yes |
| Completes Body | No | N/A | N/A | No |
| Reads Response | No | No | Yes (slowly) | No |
| Bandwidth Usage | Very low | Very low | Low | Very low |
| Server State | Waiting for body | Waiting for headers | Sending response | Waiting for chunks |
| Detection Difficulty | Medium | High | Low | Medium |

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
```

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
