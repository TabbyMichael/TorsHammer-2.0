//! Professional `--help` output for the TorsHammer CLI.
//!
//! The help text is structured into clearly distinguished sections
//! (Usage, Commands, Options, Examples, Configuration) and rendered through
//! the active theme. Only flags that actually exist are documented — no
//! invented subcommands.

use crate::cli::theme::Theme;

/// Render the full help page.
pub fn render(program: &str, version: &str, theme: &Theme, color: bool) -> String {
    let mut out = String::new();
    let header = format!(
        "{program} v{version} \u{2014} Security Testing & Vulnerability Assessment Framework"
    );
    out.push_str(&theme.title.paint(&header, color));
    out.push('\n');
    out.push('\n');
    out.push_str(&theme.subtitle.paint("Usage", color));
    out.push('\n');
    out.push_str("  torshammer [OPTIONS] --target <URL>\n");
    out.push_str("  torshammer --help | --version\n");
    out.push('\n');

    out.push_str(&theme.subtitle.paint("Commands", color));
    out.push('\n');
    out.push_str("  help       Show this help message (alias: -h)\n");
    out.push_str("  version    Print the version and exit (alias: -V)\n");
    out.push('\n');

    out.push_str(&theme.subtitle.paint("Options", color));
    out.push('\n');
    let options: &[(&str, &str)] = &[
        ("-t, --target <URL>", "Target URL or host to test"),
        ("-u, --url <URL>", "Alias for --target"),
        (
            "--backend <NAME>",
            "Runtime backend: python | rust [default: rust]",
        ),
        ("-c, --concurrency <N>", "Concurrent connections [default: 256]"),
        (
            "-m, --mode <NAME>",
            "Attack profile: slow-post | slow-post-headers | slow-headers | slow-read | chunked | udp",
        ),
        ("-d, --duration <SECS>", "Attack duration in seconds (0 = unlimited)"),
        ("--delay-min <SECS>", "Minimum byte-dribble delay [default: 0.1]"),
        ("--delay-max <SECS>", "Maximum byte-dribble delay [default: 3.0]"),
        ("--connect-timeout <SECS>", "Connection timeout [default: 15]"),
        ("--post-length <N>", "Baseline slow-post content length [default: 4096]"),
        ("--method <VERB>", "Override the HTTP method (GET, POST, PUT, ...)"),
        ("--path <PATH>", "Override the request path [default: from target]"),
        ("--no-random-path", "Do not append a random query token"),
        ("--header <NAME:VALUE>", "Add a custom header (repeatable)"),
        ("--body-file <FILE>", "Custom POST body for slow-post/chunked modes"),
        ("--json", "Emit JSON stats lines (to stderr)"),
        ("--stats-interval <SECS>", "Stats reporting interval [default: 1.0]"),
        ("--max-errors <N>", "Circuit-breaker: exit after N consecutive errors"),
        ("--fail-under <N>", "Exit non-zero if peak active connections < N"),
        ("--fail-on-zero", "Exit non-zero if no connections were opened"),
        ("--no-color", "Disable colored output"),
        ("--no-unicode", "Use ASCII symbols instead of Unicode"),
        ("--debug", "Enable debug output"),
        ("--quiet", "Only show warnings and errors"),
        ("-h, --help", "Print help and exit"),
        ("-V, --version", "Print version and exit"),
    ];
    for (flag, help) in options {
        out.push_str(&format!("  {flag:<28}{help}\n"));
    }
    out.push('\n');

    out.push_str(&theme.subtitle.paint("Examples", color));
    out.push('\n');
    out.push_str("  torshammer --target http://localhost --backend rust\n");
    out.push_str("  torshammer -u http://localhost -c 512 -m slow-headers -d 30\n");
    out.push_str("  torshammer --url http://example.com/api/ --no-color --method PUT\n");
    out.push('\n');

    out.push_str(&theme.subtitle.paint("Configuration", color));
    out.push('\n');
    out.push_str("  Color follows the terminal; NO_COLOR is honored and --no-color\n");
    out.push_str("  forces plain output. Unicode symbols degrade to ASCII with\n");
    out.push_str("  --no-unicode.\n");
    out.push('\n');

    out.push_str(&theme.muted.paint(
        "Authorized security testing only. See README.md and SECURITY.md.",
        color,
    ));
    out.push('\n');
    out
}

/// The concise usage block printed next to parse errors.
pub fn error_hint() -> &'static str {
    "Try 'torshammer --help' for more information."
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_lists_sections_and_existing_flags() {
        let theme = Theme::plain();
        let out = render("TorsHammer", "2.0.0", &theme, false);
        for section in ["Usage", "Commands", "Options", "Examples", "Configuration"] {
            assert!(out.contains(section), "missing section {section}");
        }
        for flag in ["--target", "--backend", "--no-color", "--version", "--help"] {
            assert!(out.contains(flag), "missing flag {flag}");
        }
        assert!(!out.contains("scan"), "no invented subcommands");
    }

    #[test]
    fn help_honors_plain_theme() {
        let out = render("TorsHammer", "2.0.0", &Theme::plain(), false);
        assert!(!out.contains("\x1b["));
    }
}
