//! TorsHammer CLI entry point.
//!
//! `main.rs` parses command-line options, decides between the
//! version/help/run actions, and delegates presentation to the `cli` module
//! while the real slow-request attack logic lives in the `engine` module.

mod cli;
mod engine;

use cli::banner::{self, BannerMeta};
use cli::help;
use cli::output::Output;
use cli::theme::{self, Theme};
use engine::{url, EngineConfig};
use std::process;

/// Canonical program name used across the CLI surface.
pub const PROGRAM: &str = "TorsHammer";
/// One-line tool description.
pub const DESCRIPTION: &str = "Security Testing & Vulnerability Assessment Framework";
/// The version is sourced once from Cargo.toml (`CARGO_PKG_VERSION`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Platform label like `linux-x86_64`.
fn platform_label() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
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
        }
    }
}

/// The action a given invocation maps to.
#[derive(Debug, PartialEq)]
enum Action {
    Run(Config),
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

    let mut cfg = Config::default();
    cfg.color = theme::color_enabled(false);
    cfg.unicode = theme::unicode_enabled(false);
    let mut show_help = false;
    let mut show_version = false;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        match arg {
            "--target" | "-t" | "--url" | "-u" => cfg.target = take_value(&args, &mut i, arg)?,
            "--backend" => cfg.backend = take_value(&args, &mut i, arg)?,
            "-c" | "--concurrency" => cfg.concurrency = parse_usize(take_value(&args, &mut i, arg)?, arg)?,
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
    Ok(Action::Run(cfg))
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

/// Render the banner, build the engine config, and run the attack.
fn run_scan(cfg: &Config) -> i32 {
    let mut output = Output::new(cfg.color, cfg.verbosity);
    let theme: Theme = if cfg.color {
        Theme::default()
    } else {
        Theme::plain()
    };

    let meta = BannerMeta {
        version: VERSION,
        description: DESCRIPTION,
        engine: "Rust",
        platform: &platform_label(),
        target: &cfg.target,
        backend: &cfg.backend,
        config_path: None,
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

    const MODES: [&str; 6] = [
        "slow-post",
        "slow-post-headers",
        "slow-headers",
        "slow-read",
        "chunked",
        "udp",
    ];
    if !MODES.contains(&cfg.mode.as_str()) {
        let _ = output.error(&format!(
            "unknown attack mode: {} (choose slow-post, slow-post-headers, slow-headers, slow-read, chunked, udp)",
            cfg.mode
        ));
        return 2;
    }

    let path = cfg.path.clone().unwrap_or_else(|| target.path.clone());
    let custom_body = match &cfg.body_file {
        Some(file) => match std::fs::read(file) {
            Ok(bytes) => {
                let _ = output.info(&format!("Loaded custom body from {file} ({} bytes)", bytes.len()));
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
    engine::run(engine_cfg)
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
            let _ = Output::new(color, 0).raw(&help::render(PROGRAM, VERSION, &theme, color));
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
    fn platform_label_is_os_arch() {
        let label = platform_label();
        assert!(label.contains(std::env::consts::OS));
        assert!(label.contains(std::env::consts::ARCH));
    }
}
