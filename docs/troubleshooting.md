# Troubleshooting Guide

## Overview

This guide covers common issues encountered when installing, configuring, and running Torshammer 2.0, along with their solutions.

## Installation Issues

### Python Version Too Old

**Error:**
```
Python 3.11 or higher is required
```

**Cause:** Torshammer requires Python 3.11+ for asyncio features and type hints.

**Solution:**
```bash
# Check Python version
python --version

# Install Python 3.11+ (Linux)
sudo apt install python3.11  # Debian/Ubuntu
sudo dnf install python3.11  # Fedora/RHEL

# Install Python 3.11+ (macOS)
brew install python@3.11

# Install Python 3.11+ (Windows)
# Download from https://www.python.org/downloads/
```

### Permission Denied

**Error:**
```
Permission denied: '.venv'
```

**Cause:** Insufficient permissions to create virtual environment in current directory.

**Solution:**
```bash
# Use user-writable directory
python3.11 -m venv ~/.venv-torshammer
source ~/.venv-torshammer/bin/activate
pip install -e /path/to/torshammer
```

### pip Not Found

**Error:**
```
pip: command not found
```

**Cause:** pip not installed or not in PATH.

**Solution:**
```bash
# Install pip (Linux)
sudo apt install python3-pip  # Debian/Ubuntu
sudo dnf install python3-pip  # Fedora/RHEL

# Install pip (macOS)
brew install python  # Includes pip

# Install pip (Windows)
# Ensure "Add Python to PATH" during installation
python -m ensurepip --upgrade
```

### SSL Certificate Issues

**Error:**
```
SSL: CERTIFICATE_VERIFY_FAILED
```

**Cause:** pip cannot verify SSL certificates.

**Solution:**
```bash
# Update system certificates (Linux)
sudo apt install ca-certificates  # Debian/Ubuntu
sudo dnf install ca-certificates  # Fedora/RHEL

# Temporary workaround (not recommended)
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org -e .
```

## Configuration Issues

### No Target Specified

**Error:**
```
error: a target is required (use --url or --host)
```

**Cause:** No target URL or host specified.

**Solution:**
```bash
# Specify target with URL
torshammer -u http://example.com

# Specify target with host and port
torshammer --host example.com --port 80
```

### Invalid URL Scheme

**Error:**
```
error: unsupported URL scheme: 'ftp'
```

**Cause:** URL uses unsupported scheme (only http/https supported).

**Solution:**
```bash
# Use http
torshammer -u http://example.com

# Use https
torshammer -u https://example.com
```

### Invalid Mode

**Error:**
```
error: argument -m/--mode: invalid choice: 'invalid' (choose from 'slow-post', 'slow-headers', 'slow-read', 'chunked')
```

**Cause:** Invalid attack mode specified.

**Solution:**
```bash
# Use valid mode
torshammer -u http://example.com -m slow-post
torshammer -u http://example.com -m slow-headers
torshammer -u http://example.com -m slow-read
torshammer -u http://example.com -m chunked
```

### Proxy List Not Found

**Error:**
```
error: cannot read proxy list: [Errno 2] No such file or directory: 'proxies.txt'
```

**Cause:** Proxy list file does not exist.

**Solution:**
```bash
# Create proxy list file
cat > proxies.txt << EOF
socks5://127.0.0.1:9050
http://proxy.example.com:8080
EOF

# Or use example file
torshammer -u http://example.com --proxy-list examples/proxies.txt
```

### User-Agent File Not Found

**Error:**
```
[Errno 2] No such file or directory: 'user-agents.txt'
```

**Cause:** User-Agent file does not exist.

**Solution:**
```bash
# Create user-agent file
cat > user-agents.txt << EOF
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...
EOF

# Or omit flag to use defaults
torshammer -u http://example.com
```

## Network Issues

### Connection Refused

**Error:**
```
[w0] ConnectionRefusedError: [Errno 111] Connection refused
```

**Cause:** Target is not accepting connections or wrong port.

**Solution:**
```bash
# Verify target is reachable
curl http://example.com
telnet example.com 80

# Check correct port
torshammer -u http://example.com:8080

# Check firewall
sudo iptables -L  # Linux
```

### Connection Timeout

**Error:**
```
[w0] TimeoutError: Connection timeout
```

**Cause:** Connection timeout too short or network issues.

**Solution:**
```bash
# Increase timeout
torshammer -u http://example.com --connect-timeout 30

# Check network connectivity
ping example.com
traceroute example.com

# Check DNS
nslookup example.com
```

### Name Resolution Failed

**Error:**
```
[w0] OSError: [Errno -2] Name or service not known
```

**Cause:** DNS resolution failure.

**Solution:**
```bash
# Check DNS
nslookup example.com
dig example.com

# Use IP address instead
torshammer -u http://10.0.0.1

# Check /etc/resolv.conf
cat /etc/resolv.conf
```

### Too Many Open Files

**Error:**
```
OSError: [Errno 24] Too many open files
```

**Cause:** File descriptor limit too low for concurrency level.

**Solution:**
```bash
# Check current limit
ulimit -n

# Increase limit (temporary)
ulimit -n 65536

# Increase limit (permanent)
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Reduce concurrency
torshammer -u http://example.com -c 128
```

## Proxy Issues

### Proxy Connection Refused

**Error:**
```
[w0] ConnectionRefusedError: [Errno 111] Connection refused
```

**Cause:** Proxy not running or wrong port.

**Solution:**
```bash
# Check if proxy is running
netstat -an | grep 9050  # Linux
lsof -i :9050           # macOS

# Test proxy with curl
curl --proxy socks5://127.0.0.1:9050 http://example.com

# Check proxy configuration
torshammer -u http://example.com --proxy socks5://127.0.0.1:9050
```

### Proxy Authentication Failed

**Error:**
```
[w0] ProxyConnectError: SOCKS5 authentication failed
```

**Cause:** Wrong proxy credentials or authentication not supported.

**Solution:**
```bash
# Verify credentials
torshammer -u http://example.com --proxy socks5://user:pass@proxy:9050

# Try without authentication
torshammer -u http://example.com --proxy socks5://proxy:9050

# Check proxy documentation for auth requirements
```

### Proxy Handshake Failed

**Error:**
```
[w0] ProxyConnectError: SOCKS5 connect failed (reply 5)
```

**Cause:** Proxy rejected connection (ACL restrictions, target blocked).

**Solution:**
```bash
# Check proxy ACL rules
# Verify target is allowed by proxy
# Try different target
torshammer -u http://allowed.example.com --proxy socks5://proxy:9050
```

### Tor Not Running

**Error:**
```
[w0] ConnectionRefusedError: [Errno 111] Connection refused
```

**Cause:** Tor not running on 127.0.0.1:9050.

**Solution:**
```bash
# Start Tor
sudo systemctl start tor  # Linux
brew services start tor   # macOS

# Verify Tor is running
netstat -an | grep 9050
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

## TLS/SSL Issues

### Certificate Verification Failed

**Error:**
```
[w0] ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED]
```

**Cause:** TLS certificate verification failed (self-signed, expired, etc.).

**Solution:**
```bash
# For test environments only, disable verification
torshammer -u https://self-signed.example.com --ssl-no-verify

# For production, add certificate to trust store
# (platform-specific)
```

### SNI Error

**Error:**
```
[w0] ssl.SSLError: [SSL: TLSV1_ALERT_INTERNAL_ERROR]
```

**Cause:** Server does not support SNI or has SNI misconfiguration.

**Solution:**
```bash
# This is typically a server-side issue
# Verify server supports SNI
# Try different target
```

## Performance Issues

### Low Connection Rate

**Problem:** Connections established slowly.

**Causes:**
- Network latency
- Proxy overhead
- Target response time

**Solutions:**
```bash
# Reduce delays for faster testing
torshammer -u http://example.com -dl 0.01 -dh 0.1

# Check network latency
ping example.com

# Use direct connection (no proxy)
torshammer -u http://example.com  # Without --proxy
```

### High Error Rate

**Problem:** Many connection errors.

**Causes:**
- Target rate limiting
- Network issues
- Proxy issues
- Concurrency too high

**Solutions:**
```bash
# Reduce concurrency
torshammer -u http://example.com -c 128

# Increase connection timeout
torshammer -u http://example.com --connect-timeout 30

# Check error details with verbose mode
torshammer -u http://example.com -v

# Try without proxy
torshammer -u http://example.com
```

### No Impact on Target

**Problem:** Target not affected despite high concurrency.

**Causes:**
- Target has mitigations
- Wrong attack mode
- Concurrency too low
- Network issues

**Solutions:**
```bash
# Try different attack modes
torshammer -u http://example.com -m slow-headers
torshammer -u http://example.com -m slow-read

# Increase concurrency
torshammer -u http://example.com -c 512

# Reduce delays
torshammer -u http://example.com -dl 0.05 -dh 0.5

# Monitor target metrics
# Check if target has rate limiting/WAF
```

## Output Issues

### No Statistics Displayed

**Problem:** No statistics appearing in terminal.

**Causes:**
- `--quiet` flag set
- Output redirected
- Statistics interval too long

**Solutions:**
```bash
# Remove quiet flag
torshammer -u http://example.com

# Check output destination
torshammer -u http://example.com  # Not redirected

# Reduce stats interval
torshammer -u http://example.com --stats-interval 0.5
```

### JSON Not Parseable

**Problem:** JSON output cannot be parsed.

**Causes:**
- Mixed with terminal output
- Corrupted due to signal

**Solutions:**
```bash
# Use quiet mode with JSON
torshammer -u http://example.com --json --quiet

# Ensure clean shutdown (Ctrl-C, not kill)
```

## Platform-Specific Issues

### Windows

#### PowerShell Execution Policy

**Error:**
```
running scripts is disabled on this system
```

**Solution:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### Path Too Long

**Error:**
```
path too long
```

**Solution:**
```cmd
# Install in shorter path
cd C:\dev
git clone https://github.com/...
```

### Linux

#### No Python 3.11 in Repository

**Problem:** System repositories don't have Python 3.11.

**Solution:**
```bash
# Use deadsnakes PPA (Ubuntu)
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.11

# Or compile from source
wget https://www.python.org/ftp/python/3.11.0/Python-3.11.0.tgz
tar xzf Python-3.11.0.tgz
cd Python-3.11.0
./configure
make
sudo make install
```

### macOS

#### Xcode Command Line Tools

**Error:**
```
xcrun: error: invalid active developer path
```

**Solution:**
```bash
xcode-select --install
```

#### Homebrew Python

**Problem:** Multiple Python versions installed.

**Solution:**
```bash
# Use specific Python version
python3.11 -m venv .venv

# Or unlink other versions
brew unlink python@3.10
```

## Debugging

### Enable Verbose Mode

```bash
torshammer -u http://example.com -v
```

Shows error details and connection information.

### Enable JSON Output

```bash
torshammer -u http://example.com --json
```

Provides structured output for debugging.

### Test with Low Concurrency

```bash
torshammer -u http://example.com -c 1 -d 5
```

Single connection for easier debugging.

### Test Against Local Server

```bash
# Start simple HTTP server
python -m http.server 8080

# Test against it
torshammer -u http://localhost:8080 -c 10
```

## Getting Help

### Check Logs

```bash
# Redirect output to file
torshammer -u http://example.com --json > debug.log 2>&1

# Check for error patterns
grep -i error debug.log
```

### Verify Installation

```bash
# Check version
torshammer --version

# Check help
torshammer --help

# Verify module imports
python -c "from torshammer import __version__; print(__version__)"
```

### Test Network

```bash
# Basic connectivity
ping example.com

# HTTP connectivity
curl -v http://example.com

# HTTPS connectivity
curl -v https://example.com

# Proxy connectivity
curl --proxy socks5://127.0.0.1:9050 http://example.com
```

## Common Mistakes

### Using Real Targets Without Authorization

**Mistake:** Testing against production systems without permission.

**Correction:** Only test against systems you own or have explicit authorization to test.

### Ignoring Legal Notice

**Mistake:** Not reading or understanding the legal notice.

**Correction:** Always read and understand the legal notice before use.

### Using Production Tor for Testing

**Mistake:** Using shared Tor exit nodes for testing (can abuse Tor network).

**Correction:** Use private Tor instances or controlled proxy networks.

### Not Monitoring Target

**Mistake:** Running tests without monitoring target health.

**Correction:** Always monitor target during testing and stop if issues occur.

### Leaving Tests Running

**Mistake:** Forgetting to stop tests, causing extended impact.

**Correction:** Use `--duration` flag or set reminders to stop tests.

## See Also

- [Installation Guide](installation.md) - Installation troubleshooting
- [CLI Reference](cli.md) - Command-line option issues
- [Security Documentation](security.md) - Legal and authorization issues
- [Proxy Support](proxy-support.md) - Proxy-specific issues
