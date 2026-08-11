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
    assert (cfg.proxies[0].scheme, cfg.proxies[0].host, cfg.proxies[0].port) == (
        "socks5",
        "127.0.0.1",
        9050,
    )


def test_proxy_env_fallback(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.example:8080")
    args = build_parser().parse_args(["--url", "http://x.com"])
    cfg = _resolve_config(args)
    assert cfg.proxies is not None
    assert cfg.proxies[0].scheme == "http"
    assert cfg.proxies[0].host == "proxy.example"
    assert cfg.proxies[0].port == 8080


def test_parse_custom_headers_and_method():
    args = build_parser().parse_args(
        [
            "--url",
            "http://example.com",
            "--path",
            "/custom",
            "--method",
            "PUT",
            "--header",
            "X-Test: 1",
            "--header",
            "User-Agent: CustomAgent/1.0",
        ]
    )
    cfg = _resolve_config(args)
    assert cfg.method == "PUT"
    assert cfg.path == "/custom"
    assert "X-Test: 1" in cfg.custom_headers
    assert "User-Agent: CustomAgent/1.0" in cfg.custom_headers


def test_no_random_path():
    args = build_parser().parse_args(["--url", "http://example.com/api", "--no-random-path"])
    cfg = _resolve_config(args)
    assert cfg.randomize_path is False
    assert cfg.path == "/api"


def test_invalid_header_format_raises():
    parser = build_parser()
    args = parser.parse_args(["--url", "http://example.com", "--header", "BadHeader"])
    try:
        _resolve_config(args)
        raise AssertionError("should have failed")
    except SystemExit:
        pass


def test_negative_delay_validation():
    parser = build_parser()
    args = parser.parse_args(["--url", "http://example.com", "-dl", "1.0", "-dh", "0.1"])
    try:
        _resolve_config(args)
        raise AssertionError("should have failed")
    except SystemExit:
        pass


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
