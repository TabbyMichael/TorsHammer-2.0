//! TorsHammer CLI entry point.
//!
//! `main.rs` is deliberately thin: it parses command-line options, decides
//! between the version/help/run actions, and delegates all presentation to
//! the `cli` module. There is no scanning logic here — the engine is expected
//! to produce structured results that this layer renders.

mod cli;

use cli::banner::{self, BannerMeta};
use cli::help;
use cli::output::Output;
use cli::progress::{progress_line, Elapsed, Spinner, StepStatus, Symbols};
use cli::table::Table;
use cli::theme::{self, Theme};
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
#[derive(Debug, PartialEq, Eq)]
struct Config {
    target: String,
    backend: String,
    color: bool,
    unicode: bool,
    verbosity: i32,
}

/// The action a given invocation maps to.
#[derive(Debug, PartialEq, Eq)]
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

    let mut target: Option<String> = None;
    let mut backend = "rust".to_string();
    let mut color = theme::color_enabled(false);
    let mut unicode = theme::unicode_enabled(false);
    let mut verbosity = 0i32;
    let mut show_help = false;
    let mut show_version = false;

    let mut i = 0;
    let mut need_value: Option<&'static str> = None;
    while i < args.len() {
        let arg = args[i].as_str();
        if let Some(flag) = need_value.take() {
            match flag {
                "--target" => target = Some(arg.to_string()),
                "--backend" => backend = arg.to_string(),
                _ => unreachable!("unknown value flag"),
            }
            i += 1;
            continue;
        }
        match arg {
            "--target" | "-t" | "--url" | "-u" => need_value = Some("--target"),
            "--backend" => need_value = Some("--backend"),
            "--no-color" => color = false,
            "--no-unicode" | "--ascii" => unicode = false,
            "--debug" | "-v" => verbosity = 1,
            "--quiet" | "-q" => verbosity = -1,
            "--help" | "-h" => show_help = true,
            "--version" | "-V" => show_version = true,
            _ if arg.starts_with('-') => return Err(format!("unknown option: {arg}")),
            _ => target = Some(arg.to_string()),
        }
        i += 1;
    }
    if let Some(flag) = need_value {
        return Err(format!("missing value for {flag}"));
    }

    if show_version {
        return Ok(Action::Version);
    }
    if show_help || args.is_empty() {
        return Ok(Action::Help);
    }
    let target = target.ok_or_else(|| "a target is required; use --target or --url".to_string())?;
    Ok(Action::Run(Config {
        target,
        backend,
        color,
        unicode,
        verbosity,
    }))
}

/// `TorsHammer <version>` — the canonical `--version` line.
pub fn version_line() -> String {
    format!("{PROGRAM} {VERSION}")
}

/// Render and run a scan session. The Rust engine is a scaffold, so this
/// prints the branded header and a readiness summary only.
fn run_scan(cfg: &Config) -> i32 {
    let mut output = Output::new(cfg.color, cfg.verbosity);
    let theme: Theme = if cfg.color {
        Theme::default()
    } else {
        Theme::plain()
    };
    let symbols = if cfg.unicode {
        Symbols::unicode()
    } else {
        Symbols::ascii()
    };
    let elapsed = Elapsed::start();

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

    // Step lifecycle: pending -> running -> done.
    let _ = output.raw(&StepStatus::Pending.line(symbols, "Initializing scanner"));
    let _ = output.raw(&StepStatus::Running.line(symbols, "Preparing target"));
    let _ = output.raw(&StepStatus::Done.line(symbols, "Target ready"));

    let _ = output.success("CLI layer initialized (Rust backend)");
    let _ = output.warning("Rust engine not yet implemented; branded scaffold only");

    // Spinner + progress bar demo of the reusable status components.
    let mut spinner = Spinner::new(cfg.unicode);
    let _ = output.raw(&format!("[{}] Scanning...", spinner.tick()));
    let _ = output.raw(&format!("[{}] finished", spinner.done_symbol()));
    let _ = output.raw(&progress_line(0.42, 20, cfg.unicode));

    let _ = output.debug(&format!(
        "color={} unicode={} verbosity={}",
        cfg.color, cfg.unicode, cfg.verbosity
    ));

    // Structured demo output: the CLI renders engine data, it never scans.
    let mut table = Table::new(["PORT", "STATE", "SERVICE"]).with_unicode(cfg.unicode);
    table.add_row(["22", "OPEN", "SSH"]);
    table.add_row(["80", "OPEN", "HTTP"]);
    table.add_row(["443", "OPEN", "HTTPS"]);
    let _ = output.raw("");
    let _ = output.result("Demo results (engine pending):");
    let _ = output.raw("");
    let _ = output.raw(&table.render(80));
    let _ = output.raw("");

    let _ = output.info(&format!(
        "Platform {} | Backend {} | Elapsed {} ({}s)",
        platform_label(),
        cfg.backend,
        elapsed.as_display(),
        elapsed.as_secs()
    ));
    0
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
