"""Unit tests for the dependency-free HTTP/2 frame + HPACK builders.

These cover the shared ``torshammer.h2`` serializer independently of the
attack profiles, so a wire-format regression is caught at the source rather
than only through the profile-level behavioral tests.
"""

from __future__ import annotations

from torshammer import h2


def test_preface_is_the_literal_magic_string() -> None:
    assert h2.PREFACE == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    assert len(h2.PREFACE) == 24


def test_frame_header_layout() -> None:
    payload = b"abcde"
    raw = h2.frame(7, h2.DATA, 0x1, payload)
    assert len(raw) == 9 + len(payload)
    assert int.from_bytes(raw[0:3], "big") == len(payload)
    assert raw[3] == h2.DATA
    assert raw[4] == 0x1
    assert int.from_bytes(raw[5:9], "big") == 7
    assert raw[9:] == payload


def test_frame_clears_reserved_stream_bit() -> None:
    raw = h2.frame(0xFFFFFFFF, h2.HEADERS, 0, b"")
    assert int.from_bytes(raw[5:9], "big") == 0x7FFFFFFF


def test_frame_rejects_oversized_payload() -> None:
    # A 24-bit length field cannot describe more than 2**24 - 1 octets.
    class _Big(bytes):
        def __len__(self) -> int:  # pragma: no cover - only used to trip the guard
            return (1 << 24) + 1

    import pytest

    with pytest.raises(ValueError):
        h2.frame(1, h2.DATA, 0, _Big(b""))  # type: ignore[arg-type]


def test_hpack_int_single_and_multibyte() -> None:
    # Value below the prefix max is a single octet.
    assert h2._hpack_int(10, 5) == bytes([10])
    # Value exactly at the prefix max spills into a zero continuation octet.
    assert h2._hpack_int(31, 5) == bytes([31, 0])
    # Value 300 with the 7-bit string-length prefix encodes over three octets.
    assert h2._hpack_int(300, 7) == bytes([127, 0x80 | (300 - 127), 1])


def test_hpack_int_roundtrips_large_lengths() -> None:
    for value in (0, 1, 126, 127, 128, 200, 1000):
        encoded = h2._hpack_int(value, 7)
        # Decode using the same prefix width.
        max_prefix = (1 << 7) - 1
        if encoded[0] < max_prefix:
            assert encoded[0] == value
            continue
        assert encoded[0] == max_prefix
        result = 0
        shift = 0
        for byte in encoded[1:]:
            result |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                break
        assert max_prefix + result == value


def test_header_field_is_literal_without_indexing() -> None:
    block = h2.header_field(":method", "GET")
    assert block[0] == 0x00  # literal, new name, no indexing
    # ":method" is 7 chars (H bit clear), then "GET" is 3.
    assert block == b"\x00\x07:method\x03GET"


def test_request_block_orders_pseudo_headers_first() -> None:
    block = h2.request_block("POST", "/x", "example.com")
    assert block.startswith(b"\x00\x07:method\x04POST")
    for name in (b":method", b":path", b":scheme", b":authority"):
        assert name in block


def test_settings_and_ack_frames() -> None:
    s = h2.settings()
    assert s[3] == h2.SETTINGS
    assert int.from_bytes(s[0:3], "big") == 0
    ack = h2.settings_ack()
    assert ack[3] == h2.SETTINGS
    assert ack[4] & h2.ACK


def test_continuation_sets_end_headers_flag() -> None:
    cont = h2.continuation(3, b"\x00", end_headers=True)
    assert cont[3] == h2.CONTINUATION
    assert cont[4] & h2.END_HEADERS
    plain = h2.continuation(3, b"\x00", end_headers=False)
    assert not (plain[4] & h2.END_HEADERS)


def test_rst_stream_carries_error_code() -> None:
    rst = h2.rst_stream(5, h2.NO_ERROR)
    assert rst[3] == h2.RST_STREAM
    assert int.from_bytes(rst[5:9], "big") == 5
    assert rst[9:] == (0).to_bytes(4, "big")
