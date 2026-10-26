"""Minimal, dependency-free HTTP/2 frame + HPACK builders.

This module exists so the Tier-3 HTTP/2 attack profiles can emit *real*
HTTP/2 wire bytes with no third-party crates/modules: just the standard
library. It is a serializer only - there is no connection state machine,
no flow-control accounting and no response parsing - which is exactly what
the slow-connection / frame-abuse profiles need. The companion Rust module
is ``rust/src/engine/h2.rs``; the two are kept byte-for-byte equivalent and
share ``tests/mode_list.txt`` as the parity contract.

Frame layout (RFC 7540 section 4.1)::

    +---24---+---8---+---8---+------31 (R) +----+
    | Length | Type  | Flags |  Stream ID  |
    +----------------------------------------+
    |                   Payload ...          |

We encode headers with HPACK (RFC 7541) using only "Literal Header Field -
without Indexing - New Name" (first octet ``0x00``), never Huffman and never
touching the dynamic table. That is a fully valid HPACK block on its own: the
peer indexes what it likes, we simply re-send the names. It keeps the encoder
tiny and side-effect free, which matters because these profiles build many
independent header blocks per connection.
"""

from __future__ import annotations

# The client connection preface (RFC 7540 3.5), sent verbatim before any frame.
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Frame types (RFC 7540 6).
DATA = 0x0
HEADERS = 0x1
RST_STREAM = 0x3
SETTINGS = 0x4
PING = 0x6
GOAWAY = 0x7
WINDOW_UPDATE = 0x8
CONTINUATION = 0xA

# Frame flags.
END_STREAM = 0x1
ACK = 0x1  # only meaningful for SETTINGS/PING
END_HEADERS = 0x4

# RST_STREAM error codes (RFC 7540 7).
NO_ERROR = 0x0
PROTOCOL_ERROR = 0x1
INTERNAL_ERROR = 0x2
FLOW_CONTROL_ERROR = 0x3
CANCEL = 0x8

# Largest frame payload we ever emit; keeps the 24-bit length field simple.
_MAX_FRAME = (1 << 24) - 1


def _hpack_int(value: int, prefix_bits: int) -> bytes:
    """HPACK integer coding (RFC 7541 5.1) into ``prefix_bits`` low bits.

    The unused high bits of the first octet are left clear (they carry the
    representation/flag selector, which the caller sets separately).
    """
    if value < 0:
        raise ValueError("HPACK integers are unsigned")
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([value])
    out = bytearray([max_prefix])
    value -= max_prefix
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _hpack_str(raw: bytes) -> bytes:
    """Literal (non-Huffman) HPACK string: H=0 length octet(s) + bytes."""
    return _hpack_int(len(raw), 7) + raw


def header_field(name: str, value: str) -> bytes:
    """Encode one header as HPACK literal-without-indexing / new-name.

    First octet ``0x00`` selects that representation with a 4-bit index prefix
    set to 0 (new name); the name and value follow as plain length-prefixed
    strings. This never mutates the dynamic table, so blocks can be built in
    any order without shared state.
    """
    return b"\x00" + _hpack_str(name.encode("latin-1")) + _hpack_str(value.encode("latin-1"))


def request_block(
    method: str,
    path: str,
    authority: str,
    scheme: str = "http",
    extra: dict[str, str] | None = None,
) -> bytes:
    """A complete HPACK header block for a single HTTP/2 request.

    Pseudo-headers come first (RFC 7540 8.1.2.1), then any caller extras.
    """
    block = bytearray()
    block += header_field(":method", method)
    block += header_field(":path", path)
    block += header_field(":scheme", scheme)
    block += header_field(":authority", authority)
    if extra:
        for name, value in extra.items():
            block += header_field(name, value)
    return bytes(block)


def frame(stream_id: int, ftype: int, flags: int, payload: bytes) -> bytes:
    """Serialize one HTTP/2 frame (9-octet header + payload)."""
    length = len(payload)
    if length > _MAX_FRAME:
        raise ValueError("frame payload exceeds the 24-bit length field")
    header = (
        length.to_bytes(3, "big")
        + bytes([ftype & 0xFF, flags & 0xFF])
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
    )
    return header + payload


def settings(payload: bytes = b"") -> bytes:
    """A SETTINGS frame on connection stream 0 (empty == defaults)."""
    return frame(0, SETTINGS, 0, payload)


def settings_ack() -> bytes:
    """A SETTINGS frame with the ACK flag - a valid handshake courtesy."""
    return frame(0, SETTINGS, ACK, b"")


def headers(stream_id: int, block_fragment: bytes, *, end_stream: bool = False) -> bytes:
    """A HEADERS frame carrying ``block_fragment``.

    ``END_HEADERS`` is deliberately NOT set here so the block can be continued
    with CONTINUATION frames; the continuation builders below set the final
    flag.
    """
    flags = END_STREAM if end_stream else 0
    return frame(stream_id, HEADERS, flags, block_fragment)


def continuation(stream_id: int, block_fragment: bytes, *, end_headers: bool = False) -> bytes:
    """A CONTINUATION frame extending the header block started by HEADERS."""
    flags = END_HEADERS if end_headers else 0
    return frame(stream_id, CONTINUATION, flags, block_fragment)


def data(stream_id: int, payload: bytes, *, end_stream: bool = False) -> bytes:
    """A DATA frame on ``stream_id``."""
    flags = END_STREAM if end_stream else 0
    return frame(stream_id, DATA, flags, payload)


def rst_stream(stream_id: int, error: int = NO_ERROR) -> bytes:
    """A RST_STREAM frame (4-octet error code payload)."""
    return frame(stream_id, RST_STREAM, 0, error.to_bytes(4, "big"))


def goaway(last_stream_id: int = 0, error: int = NO_ERROR) -> bytes:
    """A GOAWAY frame closing the connection from the client side."""
    payload = (last_stream_id & 0x7FFFFFFF).to_bytes(4, "big") + error.to_bytes(4, "big")
    return frame(0, GOAWAY, 0, payload)
