//! Minimal, dependency-free HTTP/2 frame + HPACK builders.
//!
//! This module is the Rust mirror of `src/torshammer/h2.py`: it exists so the
//! Tier-3 HTTP/2 attack profiles emit *real* HTTP/2 wire bytes with nothing but
//! the standard library. It is a serializer only - no connection state machine,
//! no flow-control accounting, no response parsing - which is exactly what the
//! slow-connection / frame-abuse profiles need.
//!
//! Frame layout (RFC 7540 §4.1): a 24-bit length, an 8-bit type, an 8-bit
//! flags octet, a 31-bit stream id (top "R" bit reserved), then the payload.
//!
//! Headers are encoded with HPACK (RFC 7541) using only the "Literal Header
//! Field without Indexing, New Name" form (first octet `0x00`) - never Huffman
//! and never touching the dynamic table. That is a fully valid HPACK block: the
//! peer indexes what it likes, we simply re-send the names, so blocks can be
//! built in any order without shared state.

/// The client connection preface (RFC 7540 §3.5), sent verbatim first.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// Frame types (RFC 7540 §6).
pub const DATA: u8 = 0x0;
pub const HEADERS: u8 = 0x1;
#[allow(dead_code)]
pub const RST_STREAM: u8 = 0x3;
pub const SETTINGS: u8 = 0x4;
#[allow(dead_code)]
pub const PING: u8 = 0x6;
#[allow(dead_code)]
pub const GOAWAY: u8 = 0x7;
#[allow(dead_code)]
pub const WINDOW_UPDATE: u8 = 0x8;
pub const CONTINUATION: u8 = 0xA;

// Frame flags.
pub const END_STREAM: u8 = 0x1;
pub const ACK: u8 = 0x1; // only meaningful for SETTINGS/PING
pub const END_HEADERS: u8 = 0x4;

// RST_STREAM / GOAWAY error codes (RFC 7540 §7).
pub const NO_ERROR: u32 = 0x0;
#[allow(dead_code)]
pub const PROTOCOL_ERROR: u32 = 0x1;
#[allow(dead_code)]
pub const INTERNAL_ERROR: u32 = 0x2;
#[allow(dead_code)]
pub const FLOW_CONTROL_ERROR: u32 = 0x3;
#[allow(dead_code)]
pub const CANCEL: u32 = 0x8;

/// HPACK integer coding (RFC 7541 §5.1) into `prefix_bits` low bits. Unused
/// high bits of the first octet stay clear (the caller's representation
/// selector owns them).
fn hpack_int(value: usize, prefix_bits: u32) -> Vec<u8> {
    let max_prefix = ((1u32 << prefix_bits) - 1) as usize;
    let mut out = Vec::new();
    if value < max_prefix {
        out.push(value as u8);
        return out;
    }
    out.push(max_prefix as u8);
    let mut v = value - max_prefix;
    while v >= 128 {
        out.push(((v as u8) & 0x7F) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
    out
}

/// Literal (non-Huffman) HPACK string: H=0 length octet(s) + bytes.
fn hpack_str(raw: &[u8]) -> Vec<u8> {
    let mut out = hpack_int(raw.len(), 7);
    out.extend_from_slice(raw);
    out
}

/// Encode one header as HPACK literal-without-indexing / new-name (0x00).
pub fn header_field(name: &str, value: &str) -> Vec<u8> {
    let mut out = vec![0x00];
    out.extend_from_slice(&hpack_str(name.as_bytes()));
    out.extend_from_slice(&hpack_str(value.as_bytes()));
    out
}

/// A complete HPACK header block for a single request (pseudo-headers first).
pub fn request_block(
    method: &str,
    path: &str,
    authority: &str,
    scheme: &str,
    extra: &[(&str, &str)],
) -> Vec<u8> {
    let mut block = Vec::new();
    block.extend_from_slice(&header_field(":method", method));
    block.extend_from_slice(&header_field(":path", path));
    block.extend_from_slice(&header_field(":scheme", scheme));
    block.extend_from_slice(&header_field(":authority", authority));
    for (name, value) in extra {
        block.extend_from_slice(&header_field(name, value));
    }
    block
}

/// Serialize one HTTP/2 frame (9-octet header + payload). The 24-bit length is
/// taken from the last three bytes of a big-endian `u32` (payload must be under
/// 2^24 octets, which every builder here satisfies).
pub fn frame(stream_id: u32, ftype: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let length = payload.len() as u32;
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&length.to_be_bytes()[1..]);
    out.push(ftype);
    out.push(flags);
    out.extend_from_slice(&(stream_id & 0x7FFF_FFFF).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A SETTINGS frame on connection stream 0 (empty == defaults).
pub fn settings() -> Vec<u8> {
    frame(0, SETTINGS, 0, &[])
}

/// A SETTINGS frame with the ACK flag.
pub fn settings_ack() -> Vec<u8> {
    frame(0, SETTINGS, ACK, &[])
}

/// A HEADERS frame; `END_HEADERS` is deliberately clear so the block can be
/// continued with CONTINUATION frames. Retained for parity with the Python
/// builder even though the current profiles emit `frame(.., HEADERS, ..)`
/// directly for complete blocks.
#[allow(dead_code)]
pub fn headers(stream_id: u32, block_fragment: &[u8], end_stream: bool) -> Vec<u8> {
    let flags = if end_stream { END_STREAM } else { 0 };
    frame(stream_id, HEADERS, flags, block_fragment)
}

/// A CONTINUATION frame extending an open header block.
pub fn continuation(stream_id: u32, block_fragment: &[u8], end_headers: bool) -> Vec<u8> {
    let flags = if end_headers { END_HEADERS } else { 0 };
    frame(stream_id, CONTINUATION, flags, block_fragment)
}

/// A DATA frame on `stream_id`.
pub fn data(stream_id: u32, payload: &[u8], end_stream: bool) -> Vec<u8> {
    let flags = if end_stream { END_STREAM } else { 0 };
    frame(stream_id, DATA, flags, payload)
}

/// A RST_STREAM frame (4-octet error code payload).
pub fn rst_stream(stream_id: u32, error: u32) -> Vec<u8> {
    frame(stream_id, RST_STREAM, 0, &error.to_be_bytes())
}

/// A GOAWAY frame closing the connection from the client side. Retained for
/// parity with the Python builder; the drip-style profiles simply drop the
/// socket rather than sending a polite GOAWAY.
#[allow(dead_code)]
pub fn goaway(last_stream_id: u32, error: u32) -> Vec<u8> {
    let mut payload = (last_stream_id & 0x7FFF_FFFF).to_be_bytes().to_vec();
    payload.extend_from_slice(&error.to_be_bytes());
    frame(0, GOAWAY, 0, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be24(raw: &[u8]) -> usize {
        ((raw[0] as usize) << 16) | ((raw[1] as usize) << 8) | raw[2] as usize
    }

    #[test]
    fn preface_is_the_literal_magic_string() {
        assert_eq!(PREFACE, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        assert_eq!(PREFACE.len(), 24);
    }

    #[test]
    fn frame_header_layout() {
        let payload = b"abcde";
        let raw = frame(7, DATA, 0x1, payload);
        assert_eq!(raw.len(), 9 + payload.len());
        assert_eq!(be24(&raw[0..3]), payload.len());
        assert_eq!(raw[3], DATA);
        assert_eq!(raw[4], 0x1);
        assert_eq!(u32::from_be_bytes(raw[5..9].try_into().unwrap()), 7);
        assert_eq!(&raw[9..], payload);
    }

    #[test]
    fn frame_clears_reserved_stream_bit() {
        let raw = frame(0xFFFF_FFFF, HEADERS, 0, b"");
        assert_eq!(
            u32::from_be_bytes(raw[5..9].try_into().unwrap()),
            0x7FFF_FFFF
        );
    }

    #[test]
    fn hpack_int_single_and_multibyte() {
        assert_eq!(hpack_int(10, 5), vec![10]);
        assert_eq!(hpack_int(31, 5), vec![31, 0]);
        assert_eq!(hpack_int(300, 7), vec![127, 0x80 | 45, 1]);
    }

    #[test]
    fn hpack_int_roundtrips_large_lengths() {
        for value in [0usize, 1, 126, 127, 128, 200, 1000] {
            let encoded = hpack_int(value, 7);
            let max_prefix = 127usize;
            if encoded[0] < max_prefix as u8 {
                assert_eq!(encoded[0] as usize, value);
                continue;
            }
            assert_eq!(encoded[0], max_prefix as u8);
            let mut result = 0usize;
            let mut shift = 0;
            for &byte in &encoded[1..] {
                result |= ((byte & 0x7F) as usize) << shift;
                shift += 7;
                if byte & 0x80 == 0 {
                    break;
                }
            }
            assert_eq!(max_prefix + result, value);
        }
    }

    #[test]
    fn header_field_is_literal_without_indexing() {
        let block = header_field(":method", "GET");
        assert_eq!(block[0], 0x00);
        assert_eq!(block, b"\x00\x07:method\x03GET");
    }

    #[test]
    fn request_block_orders_pseudo_headers_first() {
        let block = request_block("POST", "/x", "example.com", "http", &[]);
        assert!(block.starts_with(b"\x00\x07:method\x04POST"));
        for name in [b":method".as_slice(), b":path", b":scheme", b":authority"] {
            assert!(block.windows(name.len()).any(|w| w == name));
        }
    }

    #[test]
    fn settings_and_ack_frames() {
        let s = settings();
        assert_eq!(s[3], SETTINGS);
        assert_eq!(be24(&s[0..3]), 0);
        let ack = settings_ack();
        assert_eq!(ack[3], SETTINGS);
        assert_ne!(ack[4] & ACK, 0);
    }

    #[test]
    fn continuation_sets_end_headers_flag() {
        let cont = continuation(3, b"\x00", true);
        assert_eq!(cont[3], CONTINUATION);
        assert_ne!(cont[4] & END_HEADERS, 0);
        let plain = continuation(3, b"\x00", false);
        assert_eq!(plain[4] & END_HEADERS, 0);
    }

    #[test]
    fn rst_stream_carries_error_code() {
        let rst = rst_stream(5, NO_ERROR);
        assert_eq!(rst[3], RST_STREAM);
        assert_eq!(u32::from_be_bytes(rst[5..9].try_into().unwrap()), 5);
        assert_eq!(&rst[9..], &0u32.to_be_bytes());
    }

    #[test]
    fn headers_frame_sets_end_stream_flag_when_requested() {
        let with_es = headers(3, b"\x00\x01\x02", true);
        assert_eq!(with_es[3], HEADERS);
        assert_ne!(with_es[4] & END_STREAM, 0);
        assert_eq!(u32::from_be_bytes(with_es[5..9].try_into().unwrap()), 3);
        assert_eq!(&with_es[9..], b"\x00\x01\x02");
        let without_es = headers(3, b"\x00", false);
        assert_eq!(without_es[4] & END_STREAM, 0);
    }

    #[test]
    fn goaway_frame_encodes_last_stream_and_error() {
        let ga = goaway(7, PROTOCOL_ERROR);
        assert_eq!(ga[3], GOAWAY);
        assert_eq!(u32::from_be_bytes(ga[5..9].try_into().unwrap()), 0); // conn stream
        assert_eq!(&ga[9..13], &7u32.to_be_bytes()); // last stream id
        assert_eq!(&ga[13..], &PROTOCOL_ERROR.to_be_bytes());
    }
}
