//! Semantic output system for TorsHammer.
//!
//! Replaces ad-hoc `println!` / `eprintln!` with a small abstraction that
//! guarantees consistent, aligned labels ([INFO], [SUCCESS], ...) and routes
//! the right streams. Business logic produces messages; this module decides
//! exactly how they are formatted, styled, and emitted.

use crate::cli::theme::{Style, Theme};
use std::io::Write;

/// Semantic message levels understood by the output system.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    Info,
    Success,
    Warning,
    Error,
    Debug,
    Result,
}

impl Level {
    /// The textual label used in output, e.g. `INFO` for [`Level::Info`].
    pub fn label(self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Success => "SUCCESS",
            Level::Warning => "WARNING",
            Level::Error => "ERROR",
            Level::Debug => "DEBUG",
            Level::Result => "RESULT",
        }
    }

    /// The style assigned to this level by the active theme.
    fn style(self, theme: &Theme) -> Style {
        match self {
            Level::Info => theme.info,
            Level::Success => theme.success,
            Level::Warning => theme.warning,
            Level::Error => theme.error,
            Level::Debug => theme.muted,
            Level::Result => theme.result,
        }
    }

    /// Whether this level is shown at a given verbosity.
    ///
    /// * Warnings and errors are always shown.
    /// * Results and success are always shown.
    /// * Info is hidden under `--quiet`.
    /// * Debug is only shown with `--debug`.
    fn shown_at(self, verbosity: i32) -> bool {
        match self {
            Level::Warning | Level::Error | Level::Result | Level::Success => true,
            Level::Info => verbosity >= 0,
            Level::Debug => verbosity >= 1,
        }
    }

    /// Right-aligned label rendered at a fixed width so messages line up.
    ///
    /// `[SUCCESS]` / `[WARNING]` are the widest labels (9 columns); every
    /// other label is padded to the same 11-column slot, matching the
    /// familiar `[INFO]     ...` / `[SUCCESS]  ...` alignment.
    fn tag(self) -> String {
        let tag = format!("[{}]", self.label());
        format!("{tag:<11}")
    }
}

/// The presentation channel for emitting styled, labeled messages.
///
/// [`Output`] owns the streams it writes to, an active [`Theme`], and a
/// verbosity level. Use one instance per run and reuse it for every message
/// so formatting stays consistent across the whole application.
pub struct Output {
    color: bool,
    theme: Theme,
    verbosity: i32,
    out: Box<dyn Write>,
    err: Box<dyn Write>,
}

impl Output {
    /// Create an output channel bound to the real stdout/stderr.
    pub fn new(color: bool, verbosity: i32) -> Self {
        Self::with_writers(
            color,
            verbosity,
            Box::new(std::io::stdout()),
            Box::new(std::io::stderr()),
        )
    }

    /// Create an output channel over arbitrary writers (useful in tests).
    pub fn with_writers(
        color: bool,
        verbosity: i32,
        out: Box<dyn Write>,
        err: Box<dyn Write>,
    ) -> Self {
        Self {
            color,
            theme: if color {
                Theme::default()
            } else {
                Theme::plain()
            },
            verbosity,
            out,
            err,
        }
    }

    /// Emit a message at the given level, respecting verbosity and stream.
    fn emit(&mut self, level: Level, msg: &str) -> std::io::Result<()> {
        if !level.shown_at(self.verbosity) {
            return Ok(());
        }
        let tag = level.style(&self.theme).paint(&level.tag(), self.color);
        let line = format!("{tag}{msg}\n");
        match level {
            Level::Warning | Level::Error => {
                self.err.write_all(line.as_bytes())?;
                self.err.flush()
            }
            _ => {
                self.out.write_all(line.as_bytes())?;
                self.out.flush()
            }
        }
    }

    /// An informational message.
    pub fn info(&mut self, msg: &str) -> std::io::Result<()> {
        self.emit(Level::Info, msg)
    }

    /// A successful operation.
    pub fn success(&mut self, msg: &str) -> std::io::Result<()> {
        self.emit(Level::Success, msg)
    }

    /// A non-fatal warning.
    pub fn warning(&mut self, msg: &str) -> std::io::Result<()> {
        self.emit(Level::Warning, msg)
    }

    /// A fatal error (also routed to stderr).
    pub fn error(&mut self, msg: &str) -> std::io::Result<()> {
        self.emit(Level::Error, msg)
    }

    /// A debug-only message (shown only with `--debug`).
    pub fn debug(&mut self, msg: &str) -> std::io::Result<()> {
        self.emit(Level::Debug, msg)
    }

    /// A significant result / finding.
    pub fn result(&mut self, msg: &str) -> std::io::Result<()> {
        self.emit(Level::Result, msg)
    }

    /// Write a raw line to stdout with no label or styling.
    pub fn raw(&mut self, msg: &str) -> std::io::Result<()> {
        self.out.write_all(msg.as_bytes())?;
        self.out.write_all(b"\n")?;
        self.out.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Shared capture buffer shared with the writer under test.
    type Shared = Arc<Mutex<Vec<u8>>>;

    #[derive(Clone, Default)]
    struct Buffer(Shared);

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture(color: bool, verbosity: i32) -> (Output, Shared, Shared) {
        let out = Buffer::default();
        let err = Buffer::default();
        let out_shared = out.0.clone();
        let err_shared = err.0.clone();
        let output = Output::with_writers(color, verbosity, Box::new(out), Box::new(err));
        (output, out_shared, err_shared)
    }

    #[test]
    fn labels_are_right_aligned() {
        assert_eq!(Level::Info.tag(), "[INFO]     ");
        assert_eq!(Level::Success.tag(), "[SUCCESS]  ");
        assert_eq!(Level::Warning.tag(), "[WARNING]  ");
        assert_eq!(Level::Error.tag(), "[ERROR]    ");
        assert_eq!(Level::Debug.tag(), "[DEBUG]    ");
        assert_eq!(Level::Result.tag(), "[RESULT]   ");
    }

    #[test]
    fn verbosity_hides_info_and_debug() {
        assert!(Level::Info.shown_at(0));
        assert!(!Level::Info.shown_at(-1));
        assert!(!Level::Debug.shown_at(0));
        assert!(Level::Debug.shown_at(1));
        assert!(Level::Warning.shown_at(-1));
        assert!(Level::Error.shown_at(-1));
        assert!(Level::Result.shown_at(-1));
    }

    #[test]
    fn messages_are_emitted_to_stdout_with_label() {
        let (mut output, out, _err) = capture(false, 0);
        output.info("Initializing TorsHammer...").unwrap();
        let text = String::from_utf8(out.lock().unwrap().clone()).unwrap();
        assert_eq!(text, "[INFO]     Initializing TorsHammer...\n");
    }

    #[test]
    fn errors_are_emitted_to_stderr() {
        let (mut output, _out, err) = capture(false, 0);
        output.error("Target configuration is invalid").unwrap();
        let text = String::from_utf8(err.lock().unwrap().clone()).unwrap();
        assert_eq!(text, "[ERROR]    Target configuration is invalid\n");
    }

    #[test]
    fn quiet_hides_info_but_keeps_warnings() {
        let (mut output, out, err) = capture(false, -1);
        output.info("hidden").unwrap();
        output.warning("shown").unwrap();
        assert!(out.lock().unwrap().is_empty());
        assert_eq!(
            String::from_utf8(err.lock().unwrap().clone()).unwrap(),
            "[WARNING]  shown\n"
        );
    }

    #[test]
    fn debug_only_shown_when_verbose() {
        let (mut output, out, _err) = capture(false, 0);
        output.debug("no").unwrap();
        assert!(out.lock().unwrap().is_empty());
        let (mut output, out, _err) = capture(false, 1);
        output.debug("yes").unwrap();
        assert_eq!(
            String::from_utf8(out.lock().unwrap().clone()).unwrap(),
            "[DEBUG]    yes\n"
        );
    }

    #[test]
    fn color_emits_escape_codes_and_plain_does_not() {
        let (mut output, out, _err) = capture(true, 0);
        output.result("found").unwrap();
        let text = String::from_utf8(out.lock().unwrap().clone()).unwrap();
        assert!(text.contains("\x1b["));

        let (mut output, out, _err) = capture(false, 0);
        output.result("found").unwrap();
        let text = String::from_utf8(out.lock().unwrap().clone()).unwrap();
        assert!(!text.contains("\x1b["));
    }
}
