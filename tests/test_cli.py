"""Tests for CLI argument parsing and target resolution."""

from __future__ import annotations

from torshammer.cli import _resolve_config, build_parser


def test_parse_https_url():
    args = build_parser().parse_args(["-u", "https://example.com/api?x=1", "-c", "512"])
    cfg = _resolve_config(args)
    assert cfg.host == "example.com"
    assert cfg.port == 443
    assert cfg.secure is True
    assert cfg.path == "/api?x=1"
    assert cfg.concurrency == 512
    assert cfg.header_host == "example.com"


def test_parse_http_url_with_custom_port():
    args = build_parser().parse_args(["--url", "http://example.com:8080/", "-r", "128"])
    cfg = _resolve_config(args)
    assert (cfg.host, cfg.port, cfg.concurrency) == ("example.com", 8080, 128)
    assert cfg.secure is False
    assert cfg.header_host == "example.com:8080"


def test_legacy_host_flags():
    args = build_parser().parse_args(["-t", "10.0.0.1", "-p", "443", "--ssl"])
    cfg = _resolve_config(args)
    assert (cfg.host, cfg.port, cfg.secure, cfg.header_host) == ("10.0.0.1", 443, True, "10.0.0.1")


def test_tor_flag_adds_socks5_proxy():
    args = build_parser().parse_args(["--url", "http://x.com", "--tor"])
    cfg = _resolve_config(args)
    assert cfg.proxies is not None
    assert (cfg.proxies[0].scheme, cfg.proxies[0].host, cfg.proxies[0].port) == ("socks5", "127.0.0.1", 9050)


def test_ssl_no_verify():
    args = build_parser().parse_args(["-u", "https://x.com", "--ssl-no-verify"])
    cfg = _resolve_config(args)
    assert cfg.ssl_verify is False


def test_mode_choice_validation():
    parser = build_parser()
    try:
        parser.parse_args(["--url", "http://x.com", "-m", "bogus"])
        raise AssertionError("should have failed")
    except SystemExit:
        pass