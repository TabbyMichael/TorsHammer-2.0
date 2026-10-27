"""Focused unit tests for isolated branches in the leaf modules.

Companion to :mod:`tests.test_config_validation`: these drive the
size/limit guards, status tallies, and small helpers that the profile-level
integration tests never reach, without needing a socket.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.metadata
from typing import cast

import pytest

import torshammer
from torshammer import h2, tls, udp
from torshammer.config import Config
from torshammer.proxies import Proxy, ProxyPool
from torshammer.stats import Stats, human_size
from torshammer.summary import _print_summary

# ---------------------------------------------------------------------------
# stats: size formatting and status tallying
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "0.0 B"),
        (512, "512.0 B"),
        (1023, "1023.0 B"),
        (1024, "1.0 KB"),
        (1536, "1.5 KB"),
        (1024**2, "1.0 MB"),
        (1024**3, "1.0 GB"),
        (1024**4, "1.0 TB"),
        (5 * 1024**4, "5.0 TB"),
    ],
)
def test_human_size_units(value: int, expected: str) -> None:
    assert human_size(value) == expected


def test_human_size_reaches_the_tb_return() -> None:
    """Values past GB fall out of the unit loop into the TB branch."""
    assert human_size(1024**5) == "1024.0 TB"


@pytest.mark.parametrize(
    ("status_line", "bucket", "count"),
    [
        (b"HTTP/1.1 200 OK\r\n", "status_2xx", 1),
        (b"HTTP/1.1 301 Moved\r\n", "status_3xx", 1),
        (b"HTTP/1.1 302 Found\r\n", "status_3xx", 1),
        (b"HTTP/1.1 404 Not Found\r\n", "status_4xx", 1),
        (b"HTTP/1.0 503 Slow Down\r\n", "status_5xx", 1),
        (b"HTTP/1.1 100 Continue\r\n", "status_other", 1),
        (b"HTTP/1.1 999 Weird\r\n", "status_other", 1),
    ],
)
def test_record_response_bytes_tallies_every_class(
    status_line: bytes, bucket: str, count: int
) -> None:
    stats = Stats()
    stats.record_response_bytes(status_line)
    assert stats.responses == count
    assert getattr(stats, bucket) == count
    assert stats.bytes_received == len(status_line)


def test_record_response_bytes_ignores_non_status_payload() -> None:
    stats = Stats()
    payload = b"\x00\x01not-an-http-response"
    stats.record_response_bytes(payload)
    assert stats.responses == 0
    assert stats.bytes_received == len(payload)


def test_multiple_status_lines_in_one_read() -> None:
    stats = Stats()
    stats.record_response_bytes(b"HTTP/1.1 200 OK\r\nHTTP/1.1 500 Oops\r\n")
    assert stats.responses == 2
    assert stats.status_2xx == 1
    assert stats.status_5xx == 1


def test_latency_ignores_negative_samples() -> None:
    stats = Stats()
    stats.record_response_latency(-1.0)
    assert stats.resp_latency_count == 0
    assert stats.resp_latency_total == 0.0
    assert stats.mean_response_latency == 0.0


def test_latency_averages_positive_samples() -> None:
    stats = Stats()
    stats.record_response_latency(0.0)
    stats.record_response_latency(1.0)
    assert stats.resp_latency_count == 2
    assert stats.mean_response_latency == 0.5


# ---------------------------------------------------------------------------
# summary: the responses/latency block only prints when telemetry exists
# ---------------------------------------------------------------------------


def test_print_summary_includes_response_telemetry(capsys: pytest.CaptureFixture[str]) -> None:
    stats = Stats()
    stats.connections = 4
    stats.peak_active = 4
    stats.record_response_bytes(b"HTTP/1.1 200 OK\r\n")
    stats.record_response_bytes(b"HTTP/1.1 503 Slow Down\r\n")
    stats.record_response_latency(0.2)

    _print_summary(stats)

    out = capsys.readouterr().out
    assert "server responses" in out
    assert "2xx=1" in out
    assert "5xx=1" in out
    assert "mean resp latency" in out
    assert "verdict" in out


def test_print_summary_omits_response_block_without_reads(
    capsys: pytest.CaptureFixture[str],
) -> None:
    stats = Stats()
    stats.connections = 1
    _print_summary(stats)
    out = capsys.readouterr().out
    assert "server responses" not in out
    assert "mean resp latency" not in out


def test_print_summary_routes_to_stderr_for_json(capsys: pytest.CaptureFixture[str]) -> None:
    stats = Stats(connections=1, responses=1)
    stats.record_response_bytes(b"HTTP/1.1 302 Found\r\n")
    _print_summary(stats, json_output=True)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "server responses" in captured.err


# ---------------------------------------------------------------------------
# proxies: rotation, health pass-through, and stats reporting
# ---------------------------------------------------------------------------


def test_pool_rotation_returns_a_proxy_from_the_healthy_set() -> None:
    pool = ProxyPool([Proxy("socks5", "127.0.0.1", 1080)], rotate=True)
    picked = pool.next()
    assert picked is not None
    assert picked.host == "127.0.0.1"


def test_pool_rotation_yields_multiple_proxies() -> None:
    proxies = [Proxy("socks5", f"10.0.0.{i}", 1080) for i in range(4)]
    pool = ProxyPool(proxies, rotate=True)
    seen = {id(pool.next()) for _ in range(200)}
    assert len(seen) > 1, "rotation should spread across the pool"


def test_pool_record_failure_and_recovery(capsys: pytest.CaptureFixture[str]) -> None:
    proxy = Proxy("socks5", "127.0.0.1", 1080, failure_threshold=1)
    pool = ProxyPool([proxy])

    pool.record_failure(proxy)
    assert proxy.failures == 1
    assert proxy.is_healthy() is False
    # A fully-deprioritized pool still hands out its only proxy (warn, no starvation).
    assert pool.next() is proxy
    assert "all 1 proxies deprioritized" in capsys.readouterr().err

    pool.record_success(proxy)
    assert proxy.failures == 0
    assert proxy.is_healthy() is True


def test_pool_stats_report_every_member() -> None:
    proxies = [Proxy("socks5", "127.0.0.1", 1080), Proxy("http", "10.0.0.1", 8080)]
    pool = ProxyPool(proxies)
    pool.record_success(proxies[0])
    stats = pool.get_all_stats()
    assert len(stats) == 2
    assert {row["proxy"] for row in stats} == {str(p) for p in proxies}
    assert stats[0]["healthy"] is True
    assert "last_success" in stats[0]


def test_pool_summary_counts_healthy_members() -> None:
    proxies = [Proxy("socks5", f"10.0.0.{i}", 1080, failure_threshold=1) for i in range(3)]
    pool = ProxyPool(proxies)
    pool.record_failure(proxies[0])
    assert pool.stats_summary() == {"healthy": 2, "total": 3}


def test_proxy_health_recovers_after_cooldown() -> None:
    proxy = Proxy("socks5", "127.0.0.1", 1080, failure_threshold=1, recovery_time=-1.0)
    proxy.record_failure()
    assert proxy.failures == 1
    # Cooldown already elapsed, so the failure no longer deprioritizes it.
    assert proxy.is_healthy() is True


# ---------------------------------------------------------------------------
# tls: oversize guards
# ---------------------------------------------------------------------------


def test_record_rejects_payload_above_16_bit_field() -> None:
    with pytest.raises(ValueError, match="record payload too large"):
        tls.record(tls.CONTENT_HANDSHAKE, b"\x00" * (0xFFFF + 1))


def test_record_header_rejects_negative_length() -> None:
    with pytest.raises(ValueError, match="16-bit field"):
        tls.record_header(tls.CONTENT_HANDSHAKE, tls.SSL31, -1)


def test_handshake_rejects_body_above_24_bit_field() -> None:
    class _Oversized:
        """Claims a length past the 24-bit field without allocating 16 MB."""

        def __len__(self) -> int:
            return 0xFFFFFF + 1

    with pytest.raises(ValueError, match="24-bit length field"):
        tls.handshake(tls.HS_CLIENT_HELLO, cast(bytes, _Oversized()))


def test_client_hello_accepts_explicit_suites_and_session_id() -> None:
    body = tls.client_hello_body(
        bytes(range(32)), session_id=b"\xaa\xbb", cipher_suites=(0x1301,), version=tls.SSL31
    )
    assert body[34] == 2  # session id length
    assert body[35:37] == b"\xaa\xbb"
    assert int.from_bytes(body[37:39], "big") == 2  # one suite


# ---------------------------------------------------------------------------
# h2: integer coding and the frame builders profiles never call directly
# ---------------------------------------------------------------------------


def test_hpack_int_rejects_negative_values() -> None:
    with pytest.raises(ValueError, match="HPACK integers are unsigned"):
        h2._hpack_int(-1, 7)


def test_headers_frame_end_stream_flag() -> None:
    block = b"\x82\x84"
    plain = h2.headers(1, block)
    assert plain[0:3] == b"\x00\x00\x02"
    assert plain[5:9] == (1).to_bytes(4, "big")
    assert not plain[4] & h2.END_STREAM

    ending = h2.headers(1, block, end_stream=True)
    assert ending[4] & h2.END_STREAM
    assert not ending[4] & h2.END_HEADERS


def test_goaway_frame_payload() -> None:
    raw = h2.goaway(last_stream_id=3, error=h2.PROTOCOL_ERROR)
    assert int.from_bytes(raw[0:3], "big") == 8  # 4-octet last-stream-id + 4-octet error
    assert raw[3] == h2.GOAWAY
    assert raw[4] == 0  # GOAWAY carries no flags
    assert int.from_bytes(raw[5:9], "big") == 0  # always on the connection (stream 0)
    assert len(raw) == 9 + 8
    payload = raw[9:]
    assert int.from_bytes(payload[0:4], "big") == 3
    assert int.from_bytes(payload[4:8], "big") == h2.PROTOCOL_ERROR


def test_goaway_masks_reserved_high_bit() -> None:
    raw = h2.goaway(last_stream_id=0xFFFFFFFF, error=h2.NO_ERROR)
    payload = raw[9:]
    assert int.from_bytes(payload[0:4], "big") == 0x7FFFFFFF


def test_frame_rejects_oversize_payload() -> None:
    with pytest.raises(ValueError):
        h2.frame(1, h2.DATA, 0, b"\x00" * ((1 << 24) + 1))


# ---------------------------------------------------------------------------
# __init__: version resolution and its metadata-missing fallback
# ---------------------------------------------------------------------------


def test_package_version_fallbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    real_version = importlib.metadata.version

    try:
        monkeypatch.setattr(importlib.metadata, "version", lambda name: "9.9.9-test")
        importlib.reload(torshammer)
        assert torshammer.__version__ == "9.9.9-test"

        def raiser(name: str) -> str:
            raise importlib.metadata.PackageNotFoundError(name)

        monkeypatch.setattr(importlib.metadata, "version", raiser)
        importlib.reload(torshammer)
        assert torshammer.__version__ == "2.0.0"
    finally:
        monkeypatch.setattr(importlib.metadata, "version", real_version)
        importlib.reload(torshammer)

    assert torshammer.__version__ == importlib.metadata.version("torshammer")


# ---------------------------------------------------------------------------
# udp: inbound datagrams and send failures
# ---------------------------------------------------------------------------


def test_udp_protocol_counts_inbound_bytes() -> None:
    stats = Stats()
    protocol = udp.UdpProtocol(stats)
    protocol.datagram_received(b"echo-me", ("127.0.0.1", 53))
    assert stats.bytes_received == len(b"echo-me")


def test_udp_protocol_tolerates_transport_errors() -> None:
    """ICMP port-unreachable must not abort the drip loop."""
    protocol = udp.UdpProtocol(Stats())
    protocol.error_received(ConnectionResetError("icmp port unreachable"))


class _BrokenTransport:
    """A datagram transport whose send always fails like a closed socket."""

    def sendto(self, data: bytes) -> None:
        raise OSError("sendto on closed transport")


async def test_udp_drip_reports_incomplete_cycle_on_send_error() -> None:
    stats = Stats()
    config = Config(
        host="127.0.0.1", port=53, mode="udp", base_post_length=64, delay_min=0, delay_max=0
    )
    broken = cast(udp.asyncio.DatagramTransport, _BrokenTransport())
    completed = await udp.drip(broken, config, stats, asyncio.Event())
    assert completed is False
    assert stats.bytes_sent == 0


def test_dribble_payload_shape() -> None:
    payload = udp._dribble(16)
    assert len(payload) == 16
    assert payload.isalnum()
