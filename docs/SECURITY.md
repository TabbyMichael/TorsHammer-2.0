# Security Policy

## Supported Versions

Currently supported versions:

| Version | Supported Until |
|---------|----------------|
| 2.0.0   | TBD            |

Legacy versions (1.x) are not supported.

## Reporting Vulnerabilities

### How to Report

If you discover a security vulnerability in Torshammer 2.0, please report it responsibly.

**Note:** This project does not currently have a designated security contact. Please use the following placeholder:

```
[SECURITY CONTACT]
```

**For Maintainers:** Replace `[SECURITY CONTACT]` with an actual security contact method (e.g., security@ email address, GitHub security advisory, etc.).

### What to Report

Report vulnerabilities that could:

- Allow unauthorized access to systems
- Expose sensitive information
- Allow privilege escalation
- Bypass security controls
- Cause denial of service (beyond intended functionality)

### What NOT to Report

Do not report:

- Intended functionality (slow-requests attacks are the purpose)
- Issues requiring physical access
- Issues in third-party dependencies
- Issues in legacy code (1.x)
- General security best practices

### Report Format

Include the following information in your report:

1. **Description:** Clear description of the vulnerability
2. **Impact:** Potential impact of the vulnerability
3. **Reproduction:** Steps to reproduce the issue
4. **Proof of Concept:** Working example (if applicable)
5. **Affected Versions:** Which versions are affected
6. **Proposed Fix:** Suggested remediation (if known)

### Responsible Disclosure

We follow responsible disclosure:

1. **Acknowledgment:** We will acknowledge receipt within 7 days
2. **Assessment:** We will assess the vulnerability within 14 days
3. **Remediation:** We will aim to fix within 30 days
4. **Disclosure:** Public disclosure after fix is released

**Timeline may vary based on severity and complexity.**

## Security-Sensitive Issues

### Authorization Requirements

Torshammer 2.0 is designed for authorized security testing only. Users must:

- Own the target system, OR
- Have explicit written authorization from the system owner

**Unauthorized use is illegal in most jurisdictions.**

### Tool Limitations

Torshammer 2.0 does NOT:

- Exploit application-layer vulnerabilities
- Bypass authentication mechanisms
- Steal credentials or data
- Install persistence mechanisms
- Perform lateral movement
- Include exploit payloads

### Credential Handling

The tool handles credentials only for:

- **Proxy authentication** - Passed in URLs, stored in memory only
- **No target credentials** - Tool does not handle target authentication

**Credentials are never logged or persisted.**

### Data Handling

The tool handles:

- Target URLs (hostnames, IPs, ports, paths)
- Proxy URLs (endpoints and optional credentials)
- User-Agent strings
- HTTP headers
- Random tokens for fingerprinting evasion

The tool does NOT handle:

- Passwords
- API keys
- Session tokens
- Personal data
- Financial data
- Health data

### Network Security

- **TLS Support:** HTTPS with SNI for secure connections
- **Proxy Encryption:** Depends on proxy type (Tor provides encryption)
- **Recommendation:** Use Tor or encrypted proxies for sensitive testing

## Security Best Practices for Users

### Before Testing

1. **Obtain Authorization**
   - Get written permission from system owner
   - Document scope and duration
   - Define escalation procedures

2. **Environment Isolation**
   - Use isolated test networks
   - Avoid production during peak hours
   - Have rollback procedures ready

3. **Credential Management**
   - Use environment variables for sensitive credentials
   - Rotate credentials before and after testing
   - Do not commit credentials to version control

### During Testing

1. **Monitoring**
   - Monitor target system health
   - Have incident response procedures ready
   - Stop immediately if unexpected issues occur

2. **Rate Limiting**
   - Start with low concurrency
   - Gradually increase to understand impact
   - Use time-limited tests

3. **Observability**
   - Use JSON output for monitoring
   - Capture statistics for analysis
   - Monitor error rates

### After Testing

1. **Cleanup**
   - Stop all test instances
   - Review statistics for anomalies
   - Clean up output files

2. **Documentation**
   - Document test results
   - Note any issues discovered
   - Report findings to system owner

3. **Credential Rotation**
   - Rotate proxy credentials if used
   - Revoke any temporary access

## Security Architecture

See [Security Documentation](docs/security.md) for detailed security model, threat analysis, and defensive measures.

## Dependencies

Torshammer 2.0 has **zero runtime dependencies** - it uses only Python 3.11+ standard library.

**No third-party security vulnerabilities in runtime dependencies.**

Development dependencies:
- `pytest>=8` - Test framework
- `pytest-asyncio>=0.23` - Async test support

**Version status has not been independently verified.**

## Security Testing

The project includes:

- Unit tests for all components
- Integration tests with local server
- Proxy handshake tests
- Attack profile tests

Run tests:

```bash
pip install -e ".[dev]"
pytest
```

## Known Security Considerations

### Proxy Credentials in URLs

Proxy credentials are passed in URLs and may be visible in:

- Process listings
- Shell history
- Logs (if output is redirected)

**Mitigation:** Use environment variables (not yet supported), clear shell history, use read-only credentials.

### TLS Verification Bypass

The `--ssl-no-verify` flag disables certificate verification.

**Risk:** Man-in-the-middle attacks.

**Mitigation:** Only use in controlled test environments, never in production.

### No Rate Limiting

The tool does not implement rate limiting.

**Risk:** Can generate high connection rates.

**Mitigation:** User must control concurrency and timing.

### No Authentication Validation

The tool does not validate authorization.

**Risk:** Unauthorized use possible.

**Mitigation:** Legal notice, user responsibility, documentation.

## Security Advisories

### Past Advisories

None (initial release).

### Advisories Process

When a vulnerability is reported and fixed:

1. Assess severity (Critical, High, Medium, Low)
2. Develop fix
3. Test fix thoroughly
4. Release new version
5. Publish advisory
6. Update documentation

## Contact

For security questions or vulnerability reports:

```
[SECURITY CONTACT]
```

**For Maintainers:** Replace with actual contact information.

## See Also

- [Security Documentation](docs/security.md) - Detailed security analysis
- [Architecture Documentation](docs/architecture.md) - Security architecture
- [Troubleshooting](docs/troubleshooting.md) - Security-related issues
