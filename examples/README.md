# Tor's Hammer 2.0 Examples

This directory contains example configurations, scripts, and resources to help you get started with Tor's Hammer 2.0 for authorized security testing.

## ⚠️ Legal Notice

**IMPORTANT:** Only use these examples against systems you own or have explicit written authorization to test. Unauthorized denial-of-service testing is illegal in most jurisdictions.

## Files Overview

### Configuration Files

#### `proxies.txt`
Example proxy configurations showing how to format proxy lists for use with `--proxy-list` and `--rotate-proxies`.

**Supported proxy types:**
- SOCKS5: `socks5://[user:pass@]host:port`
- SOCKS4a: `socks4://[user@]host:port`
- HTTP CONNECT: `http://[user:pass@]host:port`

**Usage:**
```bash
torshammer -u http://example.com --proxy-list proxies.txt --rotate-proxies
```

#### `user-agents.txt`
Example User-Agent strings for various browsers and operating systems. Use these to make your testing traffic appear more realistic.

**Usage:**
```bash
torshammer -u http://example.com --user-agents user-agents.txt
```

### Example Scripts

All example scripts are executable bash scripts. Run them with:
```bash
./script_name.sh
```

#### `basic_usage.sh`
Demonstrates the simplest use case: testing a target with default settings.

**What it shows:**
- Basic slow-post attack
- Default 256 concurrent connections
- Unlimited duration (stop with Ctrl-C)

**When to use:** First-time users getting familiar with the tool

#### `all_attack_modes.sh`
Tests a target using all four available attack modes to identify which is most effective.

**What it shows:**
- slow-post mode
- slow-headers mode
- slow-read mode
- chunked mode

**When to use:** Security assessment to identify vulnerable attack vectors

#### `tor_anonymization.sh`
Demonstrates how to route traffic through Tor for anonymity.

**What it shows:**
- Basic Tor routing via `--tor` flag
- Custom proxy configuration

**When to use:** When you need to maintain anonymity during authorized testing

#### `proxy_rotation.sh`
Shows how to use multiple proxies with rotation for better connection distribution.

**What it shows:**
- Loading proxies from a file
- Random proxy selection per connection
- Higher concurrency with multiple proxies

**When to use:** Distributing load across multiple proxy servers

#### `https_testing.sh`
Demonstrates HTTPS/TLS testing with proper certificate handling.

**What it shows:**
- Basic HTTPS testing with certificate verification
- Testing with self-signed certificates (`--ssl-no-verify`)
- Custom User-Agent strings

**When to use:** Testing HTTPS endpoints and TLS configurations

#### `json_output.sh`
Shows how to capture detailed statistics in JSON format for analysis.

**What it shows:**
- JSON output instead of terminal display
- Redirecting output to a file
- Example JSON structure

**When to use:** Automated testing, logging, or statistical analysis

#### `advanced_config.sh`
Demonstrates advanced configuration options for fine-tuning behavior.

**What it shows:**
- Custom timing delays (`-dl`, `-dh`)
- Custom POST length (`--post-length`)
- Higher concurrency settings
- Connection timeout configuration
- Combined advanced options

**When to use:** Fine-tuning the tool for specific targets or requirements

## Quick Start Guide

### 1. Basic Testing
```bash
# Replace with your authorized target
./basic_usage.sh
```

### 2. Test All Attack Modes
```bash
# Identify which mode is most effective against your target
./all_attack_modes.sh
```

### 3. Use with Proxies
```bash
# Edit proxies.txt with your proxy servers first
./proxy_rotation.sh
```

### 4. HTTPS Testing
```bash
# Test HTTPS endpoints with proper TLS handling
./https_testing.sh
```

### 5. Capture Statistics
```bash
# Save detailed statistics for analysis
./json_output.sh
```

## Common Use Cases

### Security Assessment
Test your own systems for slow-requests vulnerabilities:
```bash
torshammer -u http://your-server.com -m slow-headers -c 512 -d 60
```

### Mitigation Validation
Verify that your defenses (WAF, rate limiting, timeouts) are effective:
```bash
torshammer -u http://your-server.com --proxy-list proxies.txt --rotate-proxies
```

### Load Testing
Test server capacity under slow-requests conditions:
```bash
torshammer -u http://your-server.com -c 1024 -d 300 --json > load_test_results.json
```

### Anonymized Testing
Route traffic through Tor for privacy:
```bash
torshammer -u http://target.com --tor
```

## Customization Tips

### Adjusting Concurrency
- Start with `-c 128` for initial testing
- Increase to `-c 512` or `-c 1024` for powerful targets
- Monitor error rates to find optimal concurrency

### Timing Delays
- Default: 0.1s to 3.0s (`-dl 0.1 -dh 3.0`)
- Slower: `-dl 0.5 -dh 5.0` (more effective against some servers)
- Faster: `-dl 0.05 -dh 1.0` (for high-bandwidth targets)

### Duration Control
- Manual stop: omit `-d` flag (default)
- Timed test: `-d 60` for 60 seconds
- Long running: `-d 3600` for 1 hour

## Safety Guidelines

1. **Always get authorization** before testing any system
2. **Start with low concurrency** and increase gradually
3. **Monitor the target** during testing to avoid unintended outages
4. **Use appropriate duration** limits for automated testing
5. **Test in staging** before production environments
6. **Document your findings** for security reports

## Troubleshooting

### Connection Errors
- Reduce concurrency with `-c`
- Check network connectivity to target
- Verify proxy servers are accessible

### Timeout Issues
- Increase connection timeout: `--connect-timeout 30`
- Check if target is rate-limiting your IP
- Try different attack modes

### Permission Errors
- Ensure scripts are executable: `chmod +x *.sh`
- Check file permissions for proxy/user-agent files
- Verify torshammer is installed: `pip install -e .`

## Additional Resources

- Main README: `../README.md`
- Tool documentation: `torshammer --help`
- Legal guidelines: See main README legal notice

## Contributing Examples

Have a useful example? Feel free to:
1. Create a new script following the existing pattern
2. Add detailed comments explaining the use case
3. Include safety warnings where appropriate
4. Update this README with your new example

Remember: All examples should demonstrate authorized, defensive security testing only.
