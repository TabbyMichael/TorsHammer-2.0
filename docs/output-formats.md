# Output Formats Documentation

## Overview

Torshammer 2.0 provides two output formats for monitoring attack progress: a terminal-based live status line and newline-delimited JSON for programmatic consumption.

## Terminal Output

### Default Format

The default output is a live-updating status line:

```
thm | conns=512 open=512 done=3 err=7 | sent 1.4 MB @ 45.2 KB/s | recv 0.0 B | 1:05
```

### Field Descriptions

| Field | Description | Example |
|-------|-------------|---------|
| `thm` | Tool identifier (Tor's Hammer) | `thm` |
| `conns` | Total connections opened | `512` |
| `open` | Currently active connections | `512` |
| `done` | Completed attack cycles | `3` |
| `err` | Connection errors | `7` |
| `sent` | Total bytes sent | `1.4 MB` |
| `@ KB/s` | Current send rate | `45.2 KB/s` |
| `recv` | Total bytes received | `0.0 B` |
| `MM:SS` | Elapsed time (minutes:seconds) | `1:05` |

### Update Interval

Terminal output updates every `--stats-interval` seconds (default: 1.0 second).

### Suppressing Terminal Output

Use the `-q` or `--quiet` flag to suppress terminal output:

```bash
torshammer -u http://example.com --quiet
```

This is useful when using JSON output or when redirecting to a file.

### Summary Output

When the tool stops (Ctrl-C or duration limit), a summary is printed:

```
  connections opened : 512
  peak concurrent    : 512
  completed cycles   : 3
  errors             : 7
  bytes sent         : 1.4 MB
  bytes received     : 0.0 B
  elapsed            : 1:05
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 130 | Interrupted (Ctrl-C) |
| 1 | Configuration error |
| 2 | Network error |

## JSON Output

### Enabling JSON Output

Use the `--json` flag to enable newline-delimited JSON output:

```bash
torshammer -u http://example.com --json
```

### JSON Schema

Each line is a JSON object with the following schema:

```json
{
  "connections": 512,
  "active": 512,
  "peak_active": 512,
  "completed": 3,
  "errors": 7,
  "bytes_sent": 1474560,
  "bytes_received": 0,
  "sent_bytes_per_sec": 45200.0,
  "uptime": 65.0
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `connections` | integer | Total connections opened |
| `active` | integer | Currently active connections |
| `peak_active` | integer | Peak concurrent connections |
| `completed` | integer | Completed attack cycles |
| `errors` | integer | Connection errors |
| `bytes_sent` | integer | Total bytes sent |
| `bytes_received` | integer | Total bytes received |
| `sent_bytes_per_sec` | float | Current send rate (bytes/second) |
| `uptime` | float | Elapsed time in seconds |

### Update Interval

JSON output is emitted every `--stats-interval` seconds (default: 1.0 second).

### Example Usage

#### Direct Output

```bash
torshammer -u http://example.com --json
```

Output:
```json
{"connections":256,"active":256,"peak_active":256,"completed":0,"errors":0,"bytes_sent":1024,"bytes_received":0,"sent_bytes_per_sec":1024.0,"uptime":1.0}
{"connections":256,"active":256,"peak_active":256,"completed":1,"errors":0,"bytes_sent":2048,"bytes_received":0,"sent_bytes_per_sec":1024.0,"uptime":2.0}
```

#### Redirect to File

```bash
torshammer -u http://example.com --json > stats.log
```

#### Pipe to jq

```bash
torshammer -u http://example.com --json | jq '{conns, active, errors, sent_bytes_per_sec}'
```

#### Real-time Monitoring

```bash
torshammer -u http://example.com --json | jq --unbuffered '{conns, active, errors, rate: .sent_bytes_per_sec}'
```

#### Quiet Mode

Use `--quiet` with `--json` to suppress any non-JSON output:

```bash
torshammer -u http://example.com --json --quiet > stats.log
```

## Statistics Collection

### Data Source

Statistics are collected by the `Stats` dataclass in `src/torshammer/stats.py`:

```python
@dataclass
class Stats:
    connections: int = 0
    active: int = 0
    peak_active: int = 0
    completed: int = 0
    errors: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    start: float = field(default_factory=time.monotonic)
```

### Thread Safety

Statistics are updated from a single asyncio event loop, so no locking is required.

### Rate Calculation

Send rate is calculated as:

```python
sent_rate = (stats.bytes_sent - last_sent) / dt
```

Where:
- `stats.bytes_sent` is current total bytes sent
- `last_sent` is bytes sent at previous interval
- `dt` is time elapsed since previous interval

## Output Comparison

| Characteristic | Terminal | JSON |
|----------------|----------|------|
| Human-readable | Yes | No (requires jq or similar) |
| Machine-readable | No | Yes |
| Real-time updates | Yes (in-place) | Yes (new lines) |
| File redirection | Possible | Easy |
| Programmatic parsing | Difficult | Easy |
| Bandwidth | Low | Low |
| Overhead | Minimal | Minimal |

## Usage Examples

### Terminal Monitoring

```bash
# Watch live statistics
torshammer -u http://example.com
```

### JSON Logging

```bash
# Log to file for later analysis
torshammer -u http://example.com --json > test-$(date +%Y%m%d-%H%M%S).json
```

### Real-time Filtering

```bash
# Monitor specific fields
torshammer -u http://example.com --json | jq --unbuffered '.active'
```

### Rate Monitoring

```bash
# Monitor send rate
torshammer -u http://example.com --json | jq --unbuffered '.sent_bytes_per_sec'
```

### Error Monitoring

```bash
# Alert on errors
torshammer -u http://example.com --json | jq --unbuffered 'select(.errors > 0)'
```

### Graphite/StatsD Integration

```bash
# Send to Graphite
torshammer -u http://example.com --json | while read line; do
  echo "$line" | jq -r '"torshammer.conns \(.connections) ' + $(date +%s)"
  echo "$line" | jq -r '"torshammer.active \(.active) ' + $(date +%s)"
  echo "$line" | jq -r '"torshammer.errors \(.errors) ' + $(date +%s)"
done | nc graphite.example.com 2003
```

### Prometheus Integration

```bash
# Use with prometheus-node-exporter textfile collector
torshammer -u http://example.com --json | while read line; do
  echo "$line" | jq -r '
    "# HELP torshammer_connections Total connections opened",
    "# TYPE torshammer_connections counter",
    "torshammer_connections \(.connections)",
    "# HELP torshammer_active Currently active connections",
    "# TYPE torshammer_active gauge",
    "torshammer_active \(.active)",
    "# HELP torshammer_errors Connection errors",
    "# TYPE torshammer_errors counter",
    "torshammer_errors \(.errors)"
  '
done > /var/lib/node_exporter/textfile_collector/torshammer.prom
```

## Troubleshooting Output

### No Output

**Problem:** No statistics appearing

**Causes:**
- `--quiet` flag set
- Output redirected to file
- Statistics interval too long

**Solutions:**
- Remove `--quiet` flag
- Check output destination
- Reduce `--stats-interval`

### JSON Not Valid

**Problem:** JSON output not parseable

**Causes:**
- Mixed with terminal output
- Corrupted due to signal handling

**Solutions:**
- Use `--quiet` with `--json`
- Ensure clean shutdown

### Rate Shows Zero

**Problem:** `sent_bytes_per_sec` is 0

**Causes:**
- No data sent yet
- Network issues
- Target not responding

**Solutions:**
- Wait a few intervals
- Check network connectivity
- Verify target is reachable

### Peak Active Lower Than Concurrency

**Problem:** `peak_active` < `concurrency`

**Causes:**
- Connection errors
- Slow connection establishment
- Network latency

**Solutions:**
- Check error count
- Increase `--connect-timeout`
- Verify network connectivity

## Output Analysis

### Calculating Throughput

From JSON output:

```bash
# Average send rate over time
torshammer -u http://example.com --json | jq -s '
  add / length | .sent_bytes_per_sec
'
```

### Error Rate Calculation

```bash
# Error rate as percentage
torshammer -u http://example.com --json | jq -s '
  (.[length-1].errors / .[length-1].connections * 100)
'
```

### Connection Success Rate

```bash
# Successful connections percentage
torshammer -u http://example.com --json | jq -s '
  (.[length-1].completed / .[length-1].connections * 100)
'
```

## Best Practices

### For Human Monitoring

Use terminal output for real-time monitoring:

```bash
torshammer -u http://example.com
```

### For Automated Analysis

Use JSON output for logging and analysis:

```bash
torshammer -u http://example.com --json --quiet > stats.log
```

### For Integration

Use JSON with programmatic parsing:

```bash
torshammer -u http://example.com --json | jq ...
```

### For Long-Running Tests

Use JSON with timestamps (add externally):

```bash
torshammer -u http://example.com --json | while read line; do
  echo "$(date -Iseconds) $line"
done > stats.log
```

## See Also

- [CLI Reference](cli.md) - Output-related command-line options
- [Configuration Guide](configuration.md) - Statistics configuration
- [Architecture Documentation](architecture.md) - Statistics implementation
