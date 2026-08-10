"""Tor's Hammer 2.0 - modern slow-requests vulnerability testing tool.

A modern, Python 3 rewrite of the classic Tor's Hammer slow-POST DoS
*tester* that:

* runs on asyncio (thousands of sockets instead of one OS thread each),
* speaks both plain HTTP and HTTPS/TLS with SNI,
* supports multiple attack modes (slow POST, slow headers / slowloris,
  slow read, chunked),
* rotates SOCKS4/SOCKS5/HTTP proxies (including Tor on 127.0.0.1:9050),
* randomizes each connection's request profile to defeat simple
  fingerprinting,
* emits live statistics and optional JSON logs,
* shuts down cleanly on Ctrl-C / SIGTERM.
"""

__version__ = "2.0.0"

__all__ = ["__version__"]
