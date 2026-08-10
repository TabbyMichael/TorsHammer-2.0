# Security Documentation

## Legal and Authorization Requirements

### ⚠️ Critical Legal Notice

**Torshammer 2.0 is a security testing tool designed for authorized vulnerability assessment only.**

**You must have explicit authorization before using this tool against any system.**

### Authorized Use Cases

You may only use Torshammer 2.0 against:

- **Systems you own** - Personal or organizational systems where you have ownership rights
- **Systems with explicit written authorization** - Written permission from the system owner
- **Local lab environments** - Isolated test networks you control
- **Staging environments** - Pre-production environments you manage
- **CTF/security-training environments** - Educational capture-the-flag competitions
- **Defensive security assessments** - Authorized penetration testing and red teaming

### Unauthorized Use is Illegal

Using this tool without authorization may constitute:

- **Unauthorized access** under computer crime laws (e.g., CFAA in the US)
- **Denial of service attacks** under cybercrime laws
- **Network abuse** violating terms of service
- **Civil liability** for damages caused

**You are solely responsible for complying with applicable laws and regulations.**

## What the Tool Does

### Purpose

Torshammer 2.0 tests web server resilience to slow-requests attacks by:

- Opening long-lived HTTP/HTTPS connections
- Sending data at very slow rates
- Keeping connections open indefinitely
- Exhausting server worker threads/processes

### Attack Vectors

The tool implements four slow-requests attack vectors:

1. **Slow POST** - Sends headers with large Content-Length, dribbles body one byte at a time
2. **Slow Headers (Slowloris)** - Never finishes sending request headers
3. **Slow Read** - Sends complete request, reads response in tiny chunks
4. **Chunked** - Sends POST with chunked encoding, never sends terminating chunk

**See:** [Attack Modes Documentation](attack-modes.md) for detailed explanations.

### What the Tool Does NOT Do

Torshammer 2.0 does **not**:

- Exploit application-layer vulnerabilities (SQL injection, XSS, etc.)
- Bypass authentication mechanisms
- Steal credentials or data
- Install persistence mechanisms
- Perform lateral movement
- Include exploit payloads
- Elevate privileges
- Access unauthorized resources

## Security Model

### Authorization

**Requirement:** Users must have explicit authorization to test target systems.

**Verification:** The tool does not verify authorization. Users are responsible for obtaining and documenting authorization.

**Recommendation:** Maintain written authorization records for all testing activities.

### Privileges

**Required Privileges:** Normal user privileges

**No special privileges required:**
- No root/administrator access needed
- No elevated capabilities needed
- No special system permissions needed

**Network Access:** Requires outbound network connectivity to target

### Credentials

#### Proxy Credentials

**Storage:** In-memory only (Proxy dataclass)

**Transmission:** Sent to proxy servers during handshake

**Logging:** Not logged

**Persistence:** Not persisted to disk

**Format:** URL-encoded in proxy URLs

**Example:**
```bash
torshammer -u http://example.com --proxy socks5://user:pass@proxy:9050
```

**Security Recommendations:**
- Do not commit proxy URLs with credentials to version control
- Use environment variables for sensitive credentials
- Rotate credentials regularly
- Use proxy authentication only over secure channels

#### Target Credentials

**Torshammer does not handle target credentials.** The tool does not:

- Accept username/password for target authentication
- Handle API keys or tokens
- Manage session cookies
- Store any target authentication material

If you need to test authenticated endpoints, the target must:

- Accept unauthenticated requests to the test endpoint, OR
- Use authentication that doesn't require credential handling by Torshammer

### Sensitive Data

#### Data Handled

Torshammer handles the following data:

- **Target URLs** - Hostnames, IP addresses, ports, paths
- **Proxy URLs** - Proxy endpoints and optional credentials
- **User-Agent strings** - Browser identification strings
- **HTTP headers** - Standard HTTP headers for requests
- **Random tokens** - Cryptographically random strings for fingerprinting evasion

#### Data Not Handled

Torshammer does **not** handle:

- Passwords
- API keys
- Session tokens
- Cookies
- Personal data
- Financial data
- Health data
- Any other sensitive user data

#### Data in Transit

- **TLS/SSL:** Supported for HTTPS targets with SNI
- **Proxy Encryption:** Depends on proxy type (Tor provides encryption, HTTP proxies may not)
- **Recommendation:** Use Tor or encrypted proxies for sensitive testing

### Logging

#### What is Logged

**Statistics:** Connection counts, byte counts, error counts, timing

**Verbose Mode:** Error types and messages when `-v` flag is used

**What is NOT Logged:**
- Proxy credentials
- Request bodies
- Response bodies
- Authentication tokens
- Any sensitive data

#### Log Locations

**Standard Output:** Statistics and verbose errors go to stdout/stderr

**JSON Output:** If `--json` flag is used, statistics are emitted as JSON to stdout

**No File Logging:** Torshammer does not write log files to disk

**Recommendation:** Redirect output to secure files if persistence is needed:

```bash
torshammer -u http://example.com --json > /secure/path/stats.log
```

### Data Retention

#### Runtime Data

**In-Memory Only:** All data is stored in memory during execution

**Cleared on Exit:** All data is cleared when the process exits

**No Persistence:** No data is written to disk during operation

#### Statistics

**Lifetime:** Statistics exist only during process execution

**Export:** Statistics can be exported via JSON output for external storage

**Recommendation:** If you need to retain statistics, redirect JSON output to a secure location.

#### Temporary Files

**No Temporary Files:** Torshammer does not create temporary files

**No Cache:** No caching mechanisms

**No Artifacts:** No artifacts left on disk after execution

## Threat Model

### Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| Proxy credentials | Authentication for proxy servers | High |
| Target URLs | Systems being tested | Medium |
| Test results | Statistics and error information | Low |
| Network traffic | HTTP/HTTPS requests to targets | Low |

### Threat Actors

| Actor | Capability | Motivation |
|-------|------------|------------|
| Network eavesdropper | Can sniff network traffic | Data theft |
| Proxy operator | Can see traffic through proxy | Traffic analysis |
| System administrator | Can see process/memory | Credential exposure |
| Malicious insider | Has access to testing environment | Sabotage |

### Attack Surfaces

| Surface | Threat | Impact | Mitigation |
|---------|--------|--------|------------|
| Proxy credentials in URLs | Process listing exposure | Medium | Use environment variables |
| Network traffic | Eavesdropping | Low | Use Tor/encrypted proxies |
| Process memory | Memory dump | Medium | Credentials in memory only |
| Output redirection | File permissions | Low | Secure file permissions |

### Trust Boundaries

```
┌─────────────────────────────────────────┐
│         User Environment                │
│  (CLI args, environment variables)      │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│         Torshammer Process              │
│  (In-memory configuration, statistics)   │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│         Network Layer                   │
│  (Proxy servers, target systems)        │
└─────────────────────────────────────────┘
```

**Trust Assumptions:**
- User environment is trusted
- Local system is not compromised
- Proxy servers are trusted (or traffic is encrypted)
- Target systems are authorized for testing

### Potential Abuse

| Abuse Scenario | Likelihood | Impact | Mitigation |
|----------------|------------|--------|------------|
| Unauthorized DoS attacks | High | High | Legal notice, authorization documentation |
| Proxy credential theft | Low | Medium | Secure credential handling |
| Traffic analysis | Medium | Low | Use Tor/encrypted proxies |
| Process memory inspection | Low | Medium | In-memory only, no persistence |

## Security Best Practices

### Before Testing

1. **Obtain Authorization**
   - Get written permission from system owner
   - Document scope and duration of testing
   - Define escalation procedures

2. **Environment Isolation**
   - Use isolated test networks when possible
   - Avoid testing production systems during peak hours
   - Have rollback procedures ready

3. **Credential Management**
   - Use environment variables for sensitive credentials
   - Rotate credentials before and after testing
   - Do not commit credentials to version control

### During Testing

1. **Monitoring**
   - Monitor target system health during testing
   - Have incident response procedures ready
   - Stop immediately if unexpected issues occur

2. **Rate Limiting**
   - Start with low concurrency
   - Gradually increase to understand impact
   - Use time-limited tests (`--duration`)

3. **Observability**
   - Use JSON output for monitoring (`--json`)
   - Capture statistics for analysis
   - Monitor error rates

### After Testing

1. **Cleanup**
   - Stop all test instances
   - Review statistics for anomalies
   - Clean up any redirected output files

2. **Documentation**
   - Document test results
   - Note any issues discovered
   - Report findings to system owner

3. **Credential Rotation**
   - Rotate proxy credentials if used
   - Revoke any temporary access granted

## Limitations and Assumptions

### Network Assumptions

- **Reliable Network:** Assumes network connectivity to target
- **No Firewall Interference:** Assumes ports are not blocked
- **No IDS/IPS:** Assumes no intrusion detection/prevention interference

### Target Assumptions

- **HTTP Compliance:** Assumes target follows HTTP specification
- **No Rate Limiting:** Assumes target does not rate-limit connections
- **No WAF:** Assumes no web application firewall interference

### Proxy Assumptions

- **Proxy Availability:** Assumes proxy servers are reachable
- **Proxy Capacity:** Assumes proxies can handle connection load
- **Proxy Trust:** Assumes proxy operators are trusted

## Defensive Measures

### For System Administrators

If you're concerned about slow-requests attacks, consider:

1. **Rate Limiting**
   - Limit connections per IP
   - Limit connection duration
   - Limit request size

2. **Timeout Configuration**
   - Set aggressive read timeouts
   - Set aggressive connection timeouts
   - Set maximum header size

3. **Worker Pool Sizing**
   - Increase worker thread/process pool
   - Use event-driven architectures
   - Implement connection limits

4. **Monitoring**
   - Monitor connection counts per IP
   - Monitor connection duration
   - Alert on anomalous patterns

5. **WAF/IDS**
   - Deploy web application firewalls
   - Use intrusion detection systems
   - Implement signature-based detection

### Testing Your Defenses

Use Torshammer 2.0 to **validate** your defenses:

```bash
# Test with low concurrency first
torshammer -u http://your-server -c 64 -d 30

# Monitor your server's response
# If server remains responsive, defenses are working

# Gradually increase to find breaking point
torshammer -u http://your-server -c 128 -d 30
torshammer -u http://your-server -c 256 -d 30
```

## Responsible Disclosure

If you discover vulnerabilities using Torshammer 2.0:

1. **Stop Testing** - Immediately cease testing
2. **Document Findings** - Record what was discovered
3. **Report Responsibly** - Report to system owner
4. **Allow Remediation** - Give time for fixes
5. **Coordinate Disclosure** - Coordinate public disclosure

## Security Policy

For vulnerability reporting or security questions, see [SECURITY.md](../SECURITY.md).

## References

- [OWASP Slowloris](https://owasp.org/www-community/attacks/Slowloris)
- [CWE-770: Allocation of Resources Without Limits](https://cwe.mitre.org/data/definitions/770.html)
- [Slow HTTP Attacks](https://www.qualys.com/blog/research/slow-http-attacks/)

## See Also

- [Attack Modes Documentation](attack-modes.md) - Detailed attack vector explanations
- [Proxy Support Documentation](proxy-support.md) - Proxy security considerations
- [Architecture Documentation](architecture.md) - Security architecture details
