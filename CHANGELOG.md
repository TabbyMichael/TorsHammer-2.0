# Changelog

All notable changes to Torshammer 2.0 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Fixed Woodpecker CI Python steps: `pip install -e ".[dev]"` (previously written as
  `pip install -e "[dev]"` without the project directory, which is not a valid
  editable requirement and failed to install).
- Fixed the Rust lint step targeting a non-existent `stable` toolchain in the pinned
  `rust:1.75` image — components are now added to the default `1.75.0` toolchain so
  `cargo fmt` and `cargo clippy` actually run.
- Fixed `clippy::single_char_pattern` lint errors in the Rust CLI tests by using
  `char` literals (e.g. `contains('\u{2026}')`, `starts_with('1')`).

## [2.0.0] - 2026-08-10

### Added

- Complete rewrite from Python 2 to Python 3.11+
- Asyncio-based architecture for handling tens of thousands of connections
- HTTPS/TLS support with SNI (Server Name Indication)
- Four attack modes: slow-post, slow-headers, slow-read, chunked
- Built-in async SOCKS5/SOCKS4a/HTTP CONNECT proxy support
- Proxy list support with rotation
- Live statistics with terminal output
- JSON output format for programmatic consumption
- Time-limited testing with `--duration` flag
- Request randomization (headers, User-Agent, path, timing)
- Connection timeout configuration
- Configurable dribble delays
- Comprehensive test suite with pytest
- Integration tests with local server and fake SOCKS5 proxy
- Type hints throughout codebase
- Zero runtime dependencies (Python stdlib only)
- Graceful shutdown on SIGINT/SIGTERM
- SSL certificate verification bypass for test environments
- User-Agent customization via file
- Peak concurrent connection tracking
- Error backoff to prevent tight failure loops

### Changed

- **Breaking:** Python 2 support removed (requires Python 3.11+)
- **Breaking:** Module structure reorganized (src/torshammer/)
- **Breaking:** Entry point changed to `torshammer` command
- Thread-based architecture replaced with asyncio
- Fixed request fingerprint replaced with per-connection randomization
- Bundled SocksiPy replaced with built-in async proxy implementation
- Single Tor endpoint replaced with proxy list support
- HTTP port 80 only replaced with HTTP/HTTPS support
- No statistics replaced with live stats and JSON output
- No duration control replaced with `--duration` flag
- Thread shutdown replaced with asyncio.Event-based stopping

### Fixed

- Broken thread shutdown from original implementation
- SOCKS5 authentication issues from original SocksiPy
- Connection handling and cleanup issues
- Signal handling for graceful shutdown

### Removed

- Python 2 compatibility code
- Bundled SocksiPy library
- Thread-based worker pool
- Legacy build scripts

### Security

- Added legal notice with authorization requirements
- Documented security model and threat analysis
- Added SECURITY.md for vulnerability reporting
- Added security documentation
- Credential handling clarified (memory only, no persistence)
- TLS verification controls documented

### Documentation

- Added comprehensive README with quick start
- Added architecture documentation with Mermaid diagrams
- Added installation guide for multiple platforms
- Added complete CLI reference
- Added configuration guide
- Added security documentation
- Added attack modes documentation
- Added proxy support documentation
- Added output formats documentation
- Added testing guide
- Added troubleshooting guide
- Added development guide
- Added CONTRIBUTING.md
- Added SECURITY.md
- Added CHANGELOG.md

### Testing

- Added pytest test suite
- Added SlowServer fixture for testing
- Added FakeSocks5 fixture for testing
- Added CLI argument parsing tests
- Added connection factory tests
- Added attack profile tests
- Added proxy parsing tests
- Added engine integration tests

### Development

- Added pyproject.toml for modern Python packaging
- Added ruff configuration for code style
- Added type hints marker (py.typed)
- Added development dependencies (pytest, pytest-asyncio)
- Added example files (proxies.txt, user-agents.txt)

## [1.x] - Legacy

Legacy version (2011) kept in `legacy/` directory for reference only.

### Features (1.x)

- Python 2 implementation
- Thread-based worker pool
- HTTP port 80 only
- SOCKS5 support via bundled SocksiPy
- Single Tor endpoint support
- Slow POST attack mode only
- Basic statistics

### Known Issues (1.x)

- Broken thread shutdown
- SOCKS5 authentication broken
- No HTTPS support
- Limited scalability (thread-based)
- No statistics or duration control
- Fixed request fingerprint

## Future Releases

### Planned Features

- [ ] Environment variable support for configuration
- [ ] Additional proxy protocols
- [ ] Enhanced statistics and reporting
- [ ] Configuration file support
- [ ] More aggressive randomization options
- [ ] Additional attack profiles
- [ ] Performance profiling tools
- [ ] Integration with monitoring systems

### Planned Improvements

- [ ] Enhanced error handling and recovery
- [ ] Better proxy health checking
- [ ] Connection pooling optimization
- [ ] Memory usage optimization
- [ ] Additional platform testing
- [ ] CI/CD pipeline
- [ ] Automated security scanning
- [ ] Performance benchmarking

## Version Scheme

- **Major version (X.0.0):** Breaking changes, major features
- **Minor version (0.X.0):** New features, backward-compatible
- **Patch version (0.0.X):** Bug fixes, backward-compatible

## Support

For information on supported versions, see [SECURITY.md](SECURITY.md).

## Links

- [Repository](https://github.com/yourusername/torshammer)
- [Documentation](docs/)
- [Security Policy](SECURITY.md)
- [Contributing Guide](CONTRIBUTING.md)

[2.0.0]: https://github.com/yourusername/torshammer/releases/tag/v2.0.0
