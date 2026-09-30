# Changelog

All notable changes to Torshammer 2.0 will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Seven new attack modes**, implemented in both backends with identical CLI surface
  (`-m/--mode`), timing behaviour and test coverage:
  - `websocket-slow-upgrade` - leaks WebSocket upgrade headers and never completes the handshake
  - `http-pipelining` - pipelines up to 50 requests per connection without reading responses
  - `range-abuse` - sends up to 100 randomized `Range: bytes=start-end` requests per connection
  - `cookie-bomb` - sends a ~10 KB random `Cookie` header and holds the connection open
  - `jsonrpc-slow` - dribbles an incomplete JSON-RPC document with an overstated `Content-Length`
  - `smtp-slow-envelope` - drips SMTP envelope commands and never sends `DATA`
  - `ftp-slow-command` - drips FTP commands and never completes a data transfer
- **Two new classic TCP slow-request modes**, implemented in both backends with identical CLI
  surface (`-m/--mode`), timing behaviour and test coverage:
  - `multipart-slow-upload` - multipart/form-data upload with the closing boundary withheld,
    MIME parts dribbled slowly
  - `expect-continue-abuse` - `Expect: 100-continue` headers, body stalled after the interim response
- Rust backend: `base64` dependency for generating `Sec-WebSocket-Key` values, and the Rust CLI now
  accepts all fifteen modes (the `MODES` array in `rust/src/main.rs` covers every profile plus `udp`).
- Python tests for every new mode in `tests/test_profiles.py`, plus registry/CLI coherence tests
  (`test_registry_exposes_the_documented_fifteen_modes`,
  `test_every_registered_mode_is_accepted_by_the_cli`,
  `test_rust_cli_mode_list_matches_python_registry`).
- Rust unit tests for every new profile and for the mode registry/help output
  (`mode_registry_is_unique_and_complete`, `parse_args_accepts_advanced_mode`,
  `help_lists_every_attack_mode`).
- Documentation overhaul for the expanded mode set: `docs/attack-modes.md` now documents all
  fifteen modes (mechanism, request/command structure, target systems, configuration, examples,
  countermeasures), gains new `multipart-slow-upload` and `expect-continue-abuse` sections, a
  per-mode comparison table and a backend support matrix. `README.md`, `HOW_TO_RUN.md`,
  `docs/cli.md`, `docs/configuration.md`, `docs/architecture.md`, `docs/security.md`,
  `docs/testing.md`, `docs/troubleshooting.md` and the `examples/` scripts were updated to match.
- End-to-end CLI smoke tests (`tests/test_main_e2e.py`) exercising the real
  `main()` entry point against a live local server, including circuit-breaker,
  `--fail-on-zero`, and UDP exit-code paths.
- Rust↔Python backend parity smoke test (auto-skips when the Rust binary is
  not built).
- Unit tests for CLI helpers (target policy, allowlist, proxy building, fd
  limits, Rust dispatch) and for SOCKS4a/SOCKS5/HTTP-CONNECT handshake error
  branches.
- Coverage enforcement: `pytest-cov` with an 85% floor wired into pytest and
  both CI pipelines; syntax gate (`compileall`) in CI; Forgejo release pipeline
  on tags; container image (`Dockerfile`, non-root).
- **Shared startup banner.** `assets/banner.txt` is now the single source of
  truth for the wordmark: the Rust engine embeds it at compile time
  (`include_str!` in `rust/src/cli/banner.rs`) and the Python package ships the
  same bytes as package data (`src/torshammer/banner.txt`), so both runtimes
  print a byte-for-byte identical banner. The Rust banner was rebuilt around
  the template (artwork, `TorsHammer {VER}`, description, then
  `Target`/`Backend`/`Mode`/`Conns`) instead of its previous private wordmark
  and `Engine`/`Version`/`Platform` fields.
- `tests/test_banner.py` guards the shared artwork: byte-equality between the
  canonical asset and the packaged copy, `include_str!` usage in the Rust
  engine, placeholder names, uniform row padding and the rendered layout.

### Fixed

- **Critical:** `src/torshammer/cli.py` no longer fails to compile (duplicate
  `randomize_path=` keyword argument) or crash at startup (missing
  `_check_fd_limits`, undefined banner output stream, orphaned statement).
- `_run()` now returns the engine so circuit-breaker / fail-under /
  fail-on-zero exit codes work again.
- `udp://` target scheme forces UDP mode with default port 53 as documented.
- Custom headers passed via `--header` now correctly override defaults such as
  `User-Agent` and `Accept` without duplicating header lines.
- Rust backend passes `cargo fmt --check` and `cargo clippy -D warnings`; CI
  lint steps are no longer allowed to silently pass (`|| true` removed).
- Banner is shipped as package data and loaded via `importlib.resources`, so
  installed wheels show the correct banner.
- The compact fallback banner (used only when the packaged `banner.txt` cannot
  be read) used lowercase placeholders and therefore raised `KeyError` under
  `str.format`; it now uses the same `{VER}`/`{TARGET}`/`{BACKEND}`/`{MODE}`/
  `{CONCURRENCY}` names as the real banner.
- `--backend rust` no longer silently runs the Python engine. It logs a warning
  to stderr and falls back to Python when the `torshammer-rust` binary is not
  on PATH, keeping stdout clean.
- The Rust CLI used to reject the seven protocol-specific modes
  (`unknown attack mode: ...`) even though the Rust engine implemented them. The
  accepted list is now the single `MODES` constant in `rust/src/main.rs`, is
  reused by `--help`, and is covered by a Python↔Rust parity test.
- In JSON mode (`--json`), the startup banner and final summary are written to
  stderr so stdout remains a clean newline-delimited JSON stream in both
  backends. The Rust engine previously did the opposite (JSON on stderr, banner
  on stdout), so `torshammer --backend rust --json | jq` saw no data.
- `--backend rust` now finds a locally built engine. The fallback check only
  looked at `PATH`, so the documented `cd rust && cargo build --release` flow
  printed "binary not found on PATH" and silently ran the Python engine even
  though `rust/target/{release,debug}/torshammer-rust` existed. Backend
  resolution now uses the same lookup as the dispatcher (`TORSHAMMER_RUST_BIN`,
  `PATH`, then the repo-relative build).
- Dribble writes in attack profiles apply `config.connect_timeout * 2` as a
  `writer.drain()` timeout, preventing a worker from hanging forever if a
  target stops reading.
- Removed a duplicated `## Usage` heading in README.md.
- Fixed the Woodpecker CI install step (invalid bare editable requirement).
- Fixed the Rust lint step targeting a non-existent `stable` toolchain in the
  pinned `rust:1.75` image — components are now added to the default toolchain
  so `cargo fmt` and `cargo clippy` actually run.
- Fixed `clippy::single_char_pattern` lint errors in the Rust CLI tests.

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

- [Repository](https://github.com/TabbyMichael/TorsHammer-2.0)
- [Documentation](docs/)
- [Security Policy](docs/security.md)
- [Contributing Guide](CONTRIBUTING.md)

[2.0.0]: https://github.com/TabbyMichael/TorsHammer-2.0/releases/tag/v2.0.0
