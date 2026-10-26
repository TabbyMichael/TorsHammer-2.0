"""Unit tests for the dependency-free TLS record + handshake builders.

These cover the shared ``torshammer.tls`` serializer independently of the attack
profiles, so a wire-format regression is caught at the source rather than only
through the profile-level behavioral tests.
"""

from __future__ import annotations

import pytest

from torshammer import tls


def test_record_header_layout() -> None:
    raw = tls.record_header(tls.CONTENT_HANDSHAKE, tls.SSL31, 300)
    assert len(raw) == 5
    assert raw[0] == tls.CONTENT_HANDSHAKE
    assert int.from_bytes(raw[1:3], "big") == tls.SSL31
    assert int.from_bytes(raw[3:5], "big") == 300


def test_record_header_rejects_oversize_length() -> None:
    with pytest.raises(ValueError):
        tls.record_header(tls.CONTENT_HANDSHAKE, tls.SSL31, 0x10000)


def test_record_matches_payload_length() -> None:
    payload = b"\x01\x02\x03\x04\x05"
    raw = tls.record(tls.CONTENT_APPLICATION_DATA, payload)
    assert raw[:5] == tls.record_header(tls.CONTENT_APPLICATION_DATA, tls.SSL31, len(payload))
    assert raw[5:] == payload


def test_handshake_header_type_and_24bit_length() -> None:
    body = b"abc"
    raw = tls.handshake(tls.HS_CLIENT_HELLO, body)
    assert raw[0] == tls.HS_CLIENT_HELLO
    assert int.from_bytes(raw[1:4], "big") == len(body)
    assert raw[4:] == body


def test_client_hello_body_structure() -> None:
    rand = bytes(range(32))
    body = tls.client_hello_body(rand)
    # version (2) + random (32) at the front.
    assert int.from_bytes(body[0:2], "big") == tls.TLS12
    assert body[2:34] == rand
    # session id length octet then suites: 5 suites -> 10 bytes, 2-byte length.
    assert body[34] == 0  # empty session id
    suite_len = int.from_bytes(body[35:37], "big")
    assert suite_len == 10
    suites_end = 37 + suite_len
    assert body[suites_end] == 1  # one compression method
    assert body[suites_end + 1] == 0x00  # NULL compression
    assert len(body) == suites_end + 2


def test_client_hello_body_requires_32_byte_random() -> None:
    with pytest.raises(ValueError):
        tls.client_hello_body(b"short")


def test_client_hello_is_a_handshake_message() -> None:
    msg = tls.client_hello(bytes(32))
    assert msg[0] == tls.HS_CLIENT_HELLO
    declared = int.from_bytes(msg[1:4], "big")
    assert declared == len(msg) - 4


def test_starved_client_hello_under_delivers() -> None:
    rand = bytes(32)
    raw = tls.starved_client_hello(rand)
    # A handshake record header declaring the full max record length.
    assert raw[0] == tls.CONTENT_HANDSHAKE
    assert int.from_bytes(raw[1:3], "big") == tls.SSL31
    declared = int.from_bytes(raw[3:5], "big")
    assert declared == tls.MAX_RECORD
    # Inside it, a ClientHello whose handshake length agrees with the record.
    assert raw[5] == tls.HS_CLIENT_HELLO
    msg_len = int.from_bytes(raw[6:9], "big")
    assert msg_len == declared - 4
    # We only ever emit the 5-byte record header + 4-byte handshake header + the
    # requested 8 body octets - vastly fewer than the record promises.
    assert len(raw) == 5 + 4 + 8
    assert len(raw) < declared
