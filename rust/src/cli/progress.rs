//! Reusable progress and status components for long-running operations.
//!
//! Provides lightweight, stream-friendly building blocks: step status states
//! (`[+]` / `[*]` / `[\u2713]` / `[\u2717]`), a small spinner, an elapsed-time
//! timer, plus Unicode-aware symbol selection with an ASCII fallback so the
//! interface stays readable in redirected and non-UTF-8 terminals.

use std::time::Instant;

/// Symbol sets used by the status renderer.
///
/// The Unicode set is the default; callers building for legacy or redirected
/// terminals pick the ASCII set instead. Symbols are intentionally optional.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Symbols {
    pending: &'static str,
    running: &'static str,
    done: &'static str,
    failed: &'static str,
}

impl Symbols {
    /// Unicode glyphs: `[+]`, `[*]`, `[\u2713]`, `[\u2717]`.
    pub const fn unicode() -> Self {
        Self {
            pending: "\u{2795}",
            running: "\u{2756}",
            done: "\u{2713}",
            failed: "\u{2717}",
        }
    }

    /// Plain ASCII fallback: `[+]`, `[>]`, `[OK]`, `[ERR]`.
    pub const fn ascii() -> Self {
        Self {
            pending: "+",
            running: ">",
            done: "OK",
            failed: "ERR",
        }
    }

    /// The current line for a pending step.
    pub fn pending_line(self, label: &str) -> String {
        format!("[{}] {label}", self.pending)
    }

    /// The current line for a running step.
    pub fn running_line(self, label: &str) -> String {
        format!("[{}] {label}...", self.running)
    }

    /// The final line for a completed step.
    pub fn done_line(self, label: &str) -> String {
        format!("[{}] {label}", self.done)
    }

    /// The final line for a failed step.
    pub fn failed_line(self, label: &str) -> String {
        format!("[{}] {label}", self.failed)
    }
}

/// The lifecycle state of a single task/step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepStatus {
    Pending,
    Running,
    Done,
    /// Reserved for failure lifecycle states; not produced by the scaffold.
    #[allow(dead_code)]
    Failed,
}

impl StepStatus {
    /// Render this status with the given symbols and label.
    pub fn line(self, symbols: Symbols, label: &str) -> String {
        match self {
            StepStatus::Pending => symbols.pending_line(label),
            StepStatus::Running => symbols.running_line(label),
            StepStatus::Done => symbols.done_line(label),
            StepStatus::Failed => symbols.failed_line(label),
        }
    }
}

/// A minimal non-clear-line spinner for single-line status updates.
///
/// Instead of redrawing rows (which floods redirected output), [`Spinner`]
/// yields frame characters that callers compose into one line. Frames are
/// swapped client-side by re-emitting/replacing a single status row only when
/// the underlying terminal supports it; when output is redirected the caller
/// is expected to print one line per phase instead.
pub struct Spinner {
    frames: &'static [char],
    idx: usize,
    unicode: bool,
}

impl Spinner {
    /// Create a spinner using either Unicode or ASCII frames.
    pub fn new(unicode: bool) -> Self {
        Self {
            frames: if unicode {
                &['\u{25d0}', '\u{25d3}', '\u{25d1}', '\u{25d2}']
            } else {
                &['|', '/', '-', '\\']
            },
            idx: 0,
            unicode,
        }
    }

    /// Advance and return the current frame character.
    pub fn tick(&mut self) -> char {
        let frame = self.frames[self.idx];
        self.idx = (self.idx + 1) % self.frames.len();
        frame
    }

    /// The ordinary `[OK]`/`[ERR]` completion glyph.
    pub fn done_symbol(&self) -> &'static str {
        if self.unicode {
            "\u{2713}"
        } else {
            "OK"
        }
    }
}

/// Measures and formats elapsed time.
#[derive(Clone, Copy, Debug)]
pub struct Elapsed {
    started: Instant,
}

impl Elapsed {
    /// Start timing.
    pub fn start() -> Self {
        Self {
            started: Instant::now(),
        }
    }

    /// Seconds elapsed since start, exposed for tests and reports.
    pub fn as_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// Human-readable `MM:SS` (or `H:MM:SS` when >= 1 hour) elapsed time.
    pub fn as_display(&self) -> String {
        human_elapsed(self.started.elapsed().as_secs())
    }
}

/// Format a number of seconds as `MM:SS` or `H:MM:SS` (>= 1 hour).
pub fn human_elapsed(total: u64) -> String {
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes}:{seconds:02}")
    }
}

/// Render a simple ASCII/Unicode progress bar on a single line.
///
/// Useful when progress must be visible in pipes/logs: each call returns one
/// line (no carriage-return redraw). `width` caps the bar in columns.
pub fn progress_line(filled: f32, width: usize, unicode: bool) -> String {
    let width = width.max(1);
    let filled = filled.clamp(0.0, 1.0);
    let complete = (filled * width as f32).round() as usize;
    let (block, empty) = if unicode {
        ("\u{2588}", "\u{2591}")
    } else {
        ("#", "-")
    };
    let bar: String = (0..width)
        .map(|i| if i < complete { block } else { empty })
        .collect();
    format!("[{bar}] {:>3}%", (filled * 100.0) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_symbols_fallback() {
        let s = Symbols::ascii();
        assert_eq!(
            s.done_line("Loaded configuration"),
            "[OK] Loaded configuration"
        );
        assert_eq!(s.failed_line("Target invalid"), "[ERR] Target invalid");
        assert_eq!(s.pending_line("x"), "[+] x");
        assert_eq!(s.running_line("y"), "[>] y...");
    }

    #[test]
    fn unicode_symbols() {
        let s = Symbols::unicode();
        assert_eq!(s.done_line("Scan completed"), "[\u{2713}] Scan completed");
        assert_eq!(
            s.failed_line("Connection lost"),
            "[\u{2717}] Connection lost"
        );
        assert_eq!(s.running_line("Scan"), "[\u{2756}] Scan...");
    }

    #[test]
    fn step_status_lines() {
        let s = Symbols::ascii();
        assert_eq!(StepStatus::Done.line(s, "x"), "[OK] x");
        assert_eq!(StepStatus::Failed.line(s, "x"), "[ERR] x");
        assert_eq!(StepStatus::Running.line(s, "x"), "[>] x...");
        assert_eq!(StepStatus::Pending.line(s, "x"), "[+] x");
    }

    #[test]
    fn spinner_ticks_cycle() {
        let mut sp = Spinner::new(false);
        let first = sp.tick();
        let second = sp.tick();
        assert_ne!(first, second);
        assert!(sp.done_symbol() == "OK");
    }

    #[test]
    fn elapsed_formatting_is_deterministic() {
        // `as_secs` is exercised by the run path; here we pin the formatter.
        assert_eq!(human_elapsed(65), "1:05");
        assert_eq!(human_elapsed(3661), "1:01:01");
        assert_eq!(human_elapsed(59), "0:59");
        assert_eq!(human_elapsed(0), "0:00");
    }

    #[test]
    fn progress_line_bounds() {
        assert_eq!(progress_line(0.0, 5, false), "[-----]   0%");
        assert_eq!(progress_line(1.0, 5, false), "[#####] 100%");
        let half = progress_line(0.5, 4, false);
        assert!(half.starts_with('['));
        assert!(half.ends_with('%'));
    }
}
