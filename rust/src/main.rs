//! TorsHammer CLI entry point.
//!
//! `main.rs` parses command-line options, decides between the
//! version/help/run actions, and delegates presentation to the `cli` module
//! while the real slow-request attack logic lives in the `engine` module.

mod cli;
mod engine;
mod target_policy;

use cli::banner::{self, BannerMeta};
use cli::help;
use cli::output::Output;
use cli::progress::{self, human_elapsed, progress_line, Spinner, StepStatus, Symbols};
use cli::table::Table;
use cli::theme::{self, Theme};
use engine::stats::{classify_verdict, human_size, Snapshot};
use engine::{url, EngineConfig, Monitor};
use std::process;

/// Canonical program name used across the CLI surface.
pub const PROGRAM: &str = "TorsHammer";
/// One-line tool description.
pub const DESCRIPTION: &str = "Security Testing & Vulnerability Assessment Framework";
/// The version is sourced once from Cargo.toml (`CARGO_PKG_VERSION`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Attack modes accepted by the CLI.
///
/// Sourced from the engine's single profile registry
/// (`engine::profiles::TCP_MODES`) plus the `udp` datagram mode, so `--help`,
/// argument validation and the cross-backend parity tests never drift.
pub fn all_modes() -> Vec<&'static str> {
    engine::profiles::mode_names()
}

/// Parsed runtime configuration for a scan invocation.
#[derive(Debug, Clone, PartialEq)]
struct Config {
    target: String,
    backend: String,
    color: bool,
    unicode: bool,
    verbosity: i32,
    // --- attack engine settings ---
    concurrency: usize,
    mode: String,
    duration: f64,
    delay_min: f64,
    delay_max: f64,
    connect_timeout: f64,
    post_length: usize,
    method: Option<String>,
    path: Option<String>,
    no_random_path: bool,
    custom_headers: Vec<String>,
    body_file: Option<String>,
    json: bool,
    stats_interval: f64,
    max_errors: usize,
    fail_under: usize,
    fail_on_zero: bool,
    allow_public_targets: bool,
    allowlist_file: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            target: String::new(),
            backend: "rust".to_string(),
            color: false,
            unicode: true,
            verbosity: 0,
            concurrency: 256,
            mode: "slow-post".to_string(),
            duration: 0.0,
            delay_min: 0.1,
            delay_max: 3.0,
            connect_timeout: 15.0,
            post_length: 4096,
            method: None,
            path: None,
            no_random_path: false,
            custom_headers: Vec::new(),
            body_file: None,
            json: false,
            stats_interval: 1.0,
            max_errors: 0,
            fail_under: 0,
            fail_on_zero: false,
            allow_public_targets: false,
            allowlist_file: None,
        }
    }
}

/// The action a given invocation maps to.
#[derive(Debug, PartialEq)]
enum Action {
    Run(Box<Config>),
    Help,
    Version,
}

/// Parse command-line arguments (excluding the program name).
fn parse_args<I, T>(iter: I) -> Result<Action, String>
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
{
    let args: Vec<String> = iter.into_iter().map(|a| a.as_ref().to_string()).collect();

    let mut cfg = Config {
        color: theme::color_enabled(false),
        unicode: theme::unicode_enabled(false),
        ..Config::default()
    };
    let mut show_help = false;
    let mut show_version = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--target" | "-t" | "--url" | "-u" => cfg.target = take_value(&args, &mut i, arg)?,
            "--backend" => cfg.backend = take_value(&args, &mut i, arg)?,
            "-c" | "--concurrency" => {
                cfg.concurrency = parse_usize(take_value(&args, &mut i, arg)?, arg)?
            }
            "-m" | "--mode" => cfg.mode = take_value(&args, &mut i, arg)?,
            "-d" | "--duration" => cfg.duration = parse_f64(take_value(&args, &mut i, arg)?, arg)?,
            "--delay-min" => cfg.delay_min = parse_f64(take_value(&args, &mut i, arg)?, arg)?,
            "--delay-max" => cfg.delay_max = parse_f64(take_value(&args, &mut i, arg)?, arg)?,
            "--connect-timeout" => {
                cfg.connect_timeout = parse_f64(take_value(&args, &mut i, arg)?, arg)?
            }
            "--post-length" => cfg.post_length = parse_usize(take_value(&args, &mut i, arg)?, arg)?,
            "--method" => cfg.method = Some(take_value(&args, &mut i, arg)?),
            "--path" => cfg.path = Some(take_value(&args, &mut i, arg)?),
            "--header" => cfg.custom_headers.push(take_value(&args, &mut i, arg)?),
            "--body-file" => cfg.body_file = Some(take_value(&args, &mut i, arg)?),
            "--stats-interval" => {
                cfg.stats_interval = parse_f64(take_value(&args, &mut i, arg)?, arg)?
            }
            "--max-errors" => cfg.max_errors = parse_usize(take_value(&args, &mut i, arg)?, arg)?,
            "--fail-under" => cfg.fail_under = parse_usize(take_value(&args, &mut i, arg)?, arg)?,
            "--no-random-path" => cfg.no_random_path = true,
            "--fail-on-zero" => cfg.fail_on_zero = true,
            "--allow-public-targets" => cfg.allow_public_targets = true,
            "--allowlist-file" => cfg.allowlist_file = Some(take_value(&args, &mut i, arg)?),
            "--json" => cfg.json = true,
            "--no-color" => cfg.color = false,
            "--no-unicode" | "--ascii" => cfg.unicode = false,
            "--debug" | "-v" => cfg.verbosity = 1,
            "--quiet" | "-q" => cfg.verbosity = -1,
            "--help" | "-h" => show_help = true,
            "--version" | "-V" => show_version = true,
            _ if arg.starts_with('-') => return Err(format!("unknown option: {arg}")),
            _ => cfg.target = arg.to_string(),
        }
        i += 1;
    }

    if show_version {
        return Ok(Action::Version);
    }
    if show_help || args.is_empty() {
        return Ok(Action::Help);
    }
    if cfg.target.is_empty() {
        return Err("a target is required; use --target or --url".to_string());
    }
    Ok(Action::Run(Box::new(cfg)))
}

/// Consume the value that follows a value-taking flag.
fn take_value(args: &[String], index: &mut usize, flag: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn parse_usize(raw: String, flag: &str) -> Result<usize, String> {
    raw.parse::<usize>()
        .map_err(|_| format!("invalid numeric value for {flag}: {raw}"))
}

fn parse_f64(raw: String, flag: &str) -> Result<f64, String> {
    raw.parse::<f64>()
        .map_err(|_| format!("invalid numeric value for {flag}: {raw}"))
}

/// Split `"Name: value"` strings into `(name, value)` pairs.
fn parse_headers(raw: &[String]) -> Vec<(String, String)> {
    raw.iter()
        .filter_map(|h| {
            h.split_once(':')
                .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

/// `TorsHammer <version>` — the canonical `--version` line.
pub fn version_line() -> String {
    format!("{PROGRAM} {VERSION}")
}

/// Human-facing live/summary renderer for the non-JSON output path.
///
/// Composes the reusable [`cli::progress`] building blocks (spinner, status
/// symbols, elapsed timer, progress bar) for the live line and the
/// [`cli::table`] renderer for the final summary. This is the presentation
/// hook the engine calls via [`Monitor`]; it keeps all formatting/IO out of the
/// engine itself.
struct TtyMonitor {
    duration: f64,
    unicode: bool,
    quiet: bool,
    symbols: Symbols,
    spinner: Spinner,
    elapsed: progress::Elapsed,
}

impl TtyMonitor {
    fn new(duration: f64, unicode: bool, quiet: bool) -> Self {
        Self {
            duration,
            unicode,
            quiet,
            symbols: if unicode {
                Symbols::unicode()
            } else {
                Symbols::ascii()
            },
            spinner: Spinner::new(unicode),
            elapsed: progress::Elapsed::start(),
        }
    }
}

impl Monitor for TtyMonitor {
    fn tick(&mut self, snap: &Snapshot, uptime: f64, sent_rate: f64, recv_rate: f64) {
        use std::io::Write;
        let frame = self.spinner.tick();
        let status = StepStatus::Running.line(self.symbols, "attack");
        let bar = if self.duration > 0.0 {
            format!(
                " {}",
                progress_line((uptime / self.duration) as f32, 20, self.unicode)
            )
        } else {
            String::new()
        };
        let line = format!(
            "\r{frame} {status} | conns={} active={} done={} err={} | sent {} @{}/s | recv {} @{}/s | {}{bar}",
            snap.connections,
            snap.active,
            snap.completed,
            snap.errors,
            human_size(snap.bytes_sent as f64),
            human_size(sent_rate),
            human_size(snap.bytes_received as f64),
            human_size(recv_rate),
            self.elapsed.as_display(),
        );
        print!("{line:<140}");
        let _ = std::io::stdout().flush();
    }

    fn finish(&mut self, snap: &Snapshot, uptime: f64) {
        if !self.quiet {
            println!();
        }
        let status = if snap.errors > 0 {
            StepStatus::Failed.line(self.symbols, "scan finished with errors")
        } else {
            StepStatus::Done.line(self.symbols, "scan finished")
        };
        let mut table = Table::new(["METRIC", "VALUE"]).with_unicode(self.unicode);
        table.add_row([
            "connections opened".to_string(),
            snap.connections.to_string(),
        ]);
        table.add_row(["peak concurrent".to_string(), snap.peak_active.to_string()]);
        table.add_row(["completed cycles".to_string(), snap.completed.to_string()]);
        table.add_row(["errors".to_string(), snap.errors.to_string()]);
        table.add_row(["bytes sent".to_string(), human_size(snap.bytes_sent as f64)]);
        table.add_row([
            "bytes received".to_string(),
            human_size(snap.bytes_received as f64),
        ]);
        if snap.responses > 0 || snap.resp_latency_count > 0 {
            table.add_row([
                "server responses".to_string(),
                format!(
                    "{} (2xx={} 3xx={} 4xx={} 5xx={})",
                    snap.responses,
                    snap.status_2xx,
                    snap.status_3xx,
                    snap.status_4xx,
                    snap.status_5xx
                ),
            ]);
        }
        if snap.resp_latency_count > 0 {
            table.add_row([
                "mean resp latency".to_string(),
                format!("{:.2}s", snap.mean_response_latency()),
            ]);
        }
        table.add_row(["elapsed".to_string(), human_elapsed(uptime as u64)]);
        let (verdict, reason) = classify_verdict(snap);
        table.add_row(["verdict".to_string(), verdict]);
        table.add_row(["verdict reason".to_string(), reason]);
        println!("{status}");
        println!("{}", table.render(80));
    }
}

/// Render the banner, build the engine config, and run the attack.
fn run_scan(cfg: &Config) -> i32 {
    // In JSON mode stdout must stay a clean newline-delimited JSON stream, so
    // every human-readable line (banner, status messages) is routed to stderr
    // instead. Mirrors the Python engine's behaviour.
    let mut output = if cfg.json {
        Output::with_writers(
            cfg.color,
            cfg.verbosity,
            Box::new(std::io::stderr()),
            Box::new(std::io::stderr()),
        )
    } else {
        Output::new(cfg.color, cfg.verbosity)
    };
    let theme: Theme = if cfg.color {
        Theme::default()
    } else {
        Theme::plain()
    };

    let meta = BannerMeta {
        version: VERSION,
        description: DESCRIPTION,
        target: &cfg.target,
        backend: &cfg.backend,
        mode: &cfg.mode,
        concurrency: cfg.concurrency,
    };

    let _ = output.raw(&banner::render(&theme, &meta, cfg.color));
    let _ = output.info("Initializing TorsHammer CLI...");

    let target = match url::parse(&cfg.target) {
        Ok(target) => target,
        Err(err) => {
            let _ = output.error(&err);
            let _ = output.raw(help::error_hint());
            return 2;
        }
    };

    if target.scheme == "https" {
        let _ = output.error(
            "https is not yet supported by the Rust engine; use the python backend \
             (--backend python) or point at an http target.",
        );
        return 2;
    }

    let modes = all_modes();
    if !modes.contains(&cfg.mode.as_str()) {
        let _ = output.error(&format!(
            "unknown attack mode: {} (choose {})",
            cfg.mode,
            modes.join(", ")
        ));
        return 2;
    }

    // Default-deny public targets, mirroring the Python wrapper so running the
    // `torshammer-rust` binary directly cannot bypass the authorization guard.
    let allowlist = match &cfg.allowlist_file {
        Some(path) => match target_policy::load_allowlist(path) {
            Ok(set) => set,
            Err(err) => {
                let _ = output.error(&err);
                let _ = output.raw(help::error_hint());
                return 2;
            }
        },
        None => std::collections::HashSet::new(),
    };
    if let Err(err) = target_policy::check(&target.host, cfg.allow_public_targets, &allowlist) {
        let _ = output.error(&err);
        let _ = output.raw(help::error_hint());
        return 2;
    }

    let path = cfg.path.clone().unwrap_or_else(|| target.path.clone());
    let custom_body = match &cfg.body_file {
        Some(file) => match std::fs::read(file) {
            Ok(bytes) => {
                let _ = output.info(&format!(
                    "Loaded custom body from {file} ({} bytes)",
                    bytes.len()
                ));
                Some(bytes)
            }
            Err(err) => {
                let _ = output.error(&format!("cannot read body file {file}: {err}"));
                return 2;
            }
        },
        None => None,
    };

    let engine_cfg = EngineConfig {
        host: target.host.clone(),
        port: target.port,
        path,
        header_host: target.header_host.clone(),
        secure: target.scheme == "https",
        mode: cfg.mode.clone(),
        concurrency: cfg.concurrency.max(1),
        duration: cfg.duration.max(0.0),
        delay_min: cfg.delay_min,
        delay_max: cfg.delay_max,
        connect_timeout: cfg.connect_timeout,
        base_post_length: cfg.post_length.max(1),
        randomize_path: !cfg.no_random_path,
        method: cfg.method.clone(),
        custom_headers: parse_headers(&cfg.custom_headers),
        custom_body,
        json: cfg.json,
        stats_interval: cfg.stats_interval,
        quiet: cfg.verbosity < 0,
        verbose: cfg.verbosity > 0,
        max_errors: cfg.max_errors,
        fail_under: cfg.fail_under,
        fail_on_zero: cfg.fail_on_zero,
    };

    let _ = output.success("Rust engine initialized");
    let _ = output.info(&format!(
        "target={} mode={} concurrency={}",
        target.header_host, engine_cfg.mode, engine_cfg.concurrency
    ));
    // In JSON mode the engine writes newline-delimited JSON to stdout and never
    // invokes the monitor, so this human renderer is only exercised on the
    // non-JSON path (matching the Python backend's stream contract).
    let mut monitor = TtyMonitor::new(cfg.duration, cfg.unicode, cfg.verbosity < 0);
    engine::run(engine_cfg, &mut monitor)
}

/// Top-level dispatch. Returns the process exit code.
pub fn run() -> i32 {
    match parse_args(std::env::args().skip(1)) {
        Ok(Action::Version) => {
            println!("{}", version_line());
            0
        }
        Ok(Action::Help) => {
            let color = theme::color_enabled(false);
            let theme: Theme = if color {
                Theme::default()
            } else {
                Theme::plain()
            };
            let _ = Output::new(color, 0).raw(&help::render(
                PROGRAM,
                VERSION,
                &theme,
                color,
                &all_modes(),
            ));
            0
        }
        Ok(Action::Run(cfg)) => run_scan(&cfg),
        Err(err) => {
            let color = theme::color_enabled(false);
            let mut output = Output::new(color, 0);
            let _ = output.error(&err);
            let _ = output.raw(help::error_hint());
            2
        }
    }
}

fn main() {
    process::exit(run());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comes_from_cargo_package_metadata() {
        assert!(!VERSION.is_empty());
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert!(version_line().starts_with("TorsHammer "));
        assert!(version_line().contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn mode_registry_is_unique_and_complete() {
        let modes = all_modes();
        assert_eq!(modes.len(), 32, "thirty-two modes are documented");
        let mut sorted = modes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), modes.len(), "duplicate attack mode in list");
        for mode in [
            "slow-post",
            "slow-post-headers",
            "slow-headers",
            "slow-read",
            "chunked",
            "multipart-slow-upload",
            "expect-continue-abuse",
            "websocket-slow-upgrade",
            "http-pipelining",
            "range-abuse",
            "cookie-bomb",
            "jsonrpc-slow",
            "smtp-slow-envelope",
            "ftp-slow-command",
            "imap-slow-literal",
            "redis-resp-slow",
            "postgres-startup-slow",
            "dns-tcp-slow",
            "nntp-slow-post",
            "idle-hold",
            "slow-xml",
            "slow-form-parse",
            "header-count-flood",
            "websocket-slow-frame",
            "req-smuggling-probe",
            "h2-rapid-reset",
            "h2-slow-streams",
            "h2-continuation-flood",
            "h2-hpack-drip",
            "tls-slow-hello",
            "tls-renego-hold",
            "udp",
        ] {
            assert!(modes.contains(&mode), "missing mode {mode}");
        }
    }

    #[test]
    fn parse_args_accepts_advanced_mode() {
        let args = ["-u", "http://example.com", "-m", "websocket-slow-upgrade"];
        match parse_args(args).expect("should parse") {
            Action::Run(cfg) => assert_eq!(cfg.mode, "websocket-slow-upgrade"),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_with_target_and_backend() {
        let args = ["--target", "http://127.0.0.1:8080", "--backend", "rust"];
        match parse_args(args).expect("should parse") {
            Action::Run(cfg) => {
                assert_eq!(cfg.target, "http://127.0.0.1:8080");
                assert_eq!(cfg.backend, "rust");
            }
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_short_flags() {
        let args = ["-u", "http://example.com"];
        match parse_args(args).expect("should parse") {
            Action::Run(cfg) => assert_eq!(cfg.target, "http://example.com"),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_positional_target() {
        let args = ["http://localhost"];
        match parse_args(args).expect("should parse") {
            Action::Run(cfg) => assert_eq!(cfg.target, "http://localhost"),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_allow_public_targets_flag() {
        let args = ["--target", "http://example.com", "--allow-public-targets"];
        match parse_args(args).expect("should parse") {
            Action::Run(cfg) => assert!(cfg.allow_public_targets),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_allowlist_file_flag() {
        let args = [
            "--target",
            "http://example.com",
            "--allowlist-file",
            "hosts.txt",
        ];
        match parse_args(args).expect("should parse") {
            Action::Run(cfg) => assert_eq!(cfg.allowlist_file.as_deref(), Some("hosts.txt")),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn run_scan_refuses_public_target_without_opt_in() {
        // Default-deny must abort with a usage error (2) before any worker
        // connects; 8.8.8.8 is a genuinely public address.
        let cfg = Config {
            target: "http://8.8.8.8".to_string(),
            ..Config::default()
        };
        assert_eq!(run_scan(&cfg), 2);
    }

    #[test]
    fn parse_args_no_arguments_yields_help() {
        let empty: [&str; 0] = [];
        assert_eq!(parse_args(empty).expect("should parse"), Action::Help);
    }

    #[test]
    fn parse_args_version_flag() {
        let args = ["--version"];
        assert_eq!(parse_args(args).expect("should parse"), Action::Version);
        let args = ["-V"];
        assert_eq!(parse_args(args).expect("should parse"), Action::Version);
    }

    #[test]
    fn parse_args_help_flag() {
        let args = ["--help"];
        assert_eq!(parse_args(args).expect("should parse"), Action::Help);
        let args = ["-h"];
        assert_eq!(parse_args(args).expect("should parse"), Action::Help);
    }

    #[test]
    fn parse_args_no_color_flag() {
        let args = ["--target", "http://x", "--no-color"];
        match parse_args(args).expect("should parse") {
            Action::Run(cfg) => assert!(!cfg.color),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_verbosity_flags() {
        let args = ["--target", "http://x", "--debug"];
        match parse_args(args).expect("should parse") {
            Action::Run(cfg) => assert_eq!(cfg.verbosity, 1),
            other => panic!("expected Run, got {other:?}"),
        }
        let args = ["--target", "http://x", "--quiet"];
        match parse_args(args).expect("should parse") {
            Action::Run(cfg) => assert_eq!(cfg.verbosity, -1),
            other => panic!("expected Run, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_errors() {
        let args = ["--backend"];
        assert!(parse_args(args).is_err());
        let args = ["--bogus"];
        assert!(parse_args(args).is_err());
    }

    #[test]
    fn tty_monitor_renders_live_and_summary_without_panic() {
        let snap = Snapshot {
            connections: 4,
            active: 2,
            peak_active: 3,
            completed: 1,
            errors: 0,
            bytes_sent: 2048,
            bytes_received: 512,
            ..Snapshot::default()
        };
        // Exercises the progress (spinner/symbols/bar) and table renderers on
        // the live tick and the final summary path.
        let mut monitor = TtyMonitor::new(2.0, false, false);
        monitor.tick(&snap, 0.5, 1024.0, 256.0);
        monitor.finish(&snap, 1.5);
    }

    #[test]
    fn summary_table_lists_metrics_and_elapsed() {
        let mut table = Table::new(["METRIC", "VALUE"]).with_unicode(false);
        table.add_row(["connections opened".to_string(), "4".to_string()]);
        table.add_row(["elapsed".to_string(), human_elapsed(90)]);
        let out = table.render(80);
        assert!(out.contains("connections opened"));
        assert!(out.contains("1:30"));
    }
}
