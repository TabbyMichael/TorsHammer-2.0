//! Centralized terminal theme for TorsHammer.
//!
//! All color/style decisions for the CLI presentation layer live here.
//! Command logic never hard-codes escape sequences; it asks the [`Theme`]
//! for the appropriate [`Style`] and paints through it. Disabling color is
//! a single switch: build a theme with [`Theme::plain()`] (or pass
//! `color = false` to any [`Style::paint`] call) and every renderer
//! degrades to plain text automatically.

use std::io::IsTerminal;

/// The small set of ANSI attributes the presentation layer uses.
///
/// Kept deliberately small: the goal is professional, restrained coloring,
/// not rainbow output.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Color {
    Bold,
    Dim,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
}

impl Color {
    /// The SGR escape code for this color/attribute.
    fn code(self) -> &'static str {
        match self {
            Color::Bold => "\x1b[1m",
            Color::Dim => "\x1b[2m",
            Color::Red => "\x1b[31m",
            Color::Green => "\x1b[32m",
            Color::Yellow => "\x1b[33m",
            Color::Blue => "\x1b[34m",
            Color::Magenta => "\x1b[35m",
            Color::Cyan => "\x1b[36m",
        }
    }

    /// The ANSI reset sequence.
    const RESET: &'static str = "\x1b[0m";
}

/// A composable set of attributes applied to a run of text.
#[derive(Clone, Copy, Debug)]
pub struct Style {
    fg: Option<Color>,
    bold: bool,
    dim: bool,
}

impl Style {
    /// A neutral style that renders plain text.
    pub const fn new() -> Self {
        Self {
            fg: None,
            bold: false,
            dim: false,
        }
    }

    /// A style with a single foreground color.
    pub const fn colored(color: Color) -> Self {
        Self {
            fg: Some(color),
            bold: false,
            dim: false,
        }
    }

    /// Mark the style as bold.
    pub const fn bold(mut self) -> Self {
        self.bold = true;
        self
    }

    /// Mark the style as dimmed (muted).
    pub const fn dim(mut self) -> Self {
        self.dim = true;
        self
    }

    /// Apply this style to `text`.
    ///
    /// When `enabled` is `false` — or the style carries no attributes — the
    /// text is returned verbatim, so callers can degrade gracefully in
    /// non-TTY, CI, or `--no-color` environments.
    pub fn paint(self, text: &str, enabled: bool) -> String {
        if !enabled || (self.fg.is_none() && !self.bold && !self.dim) {
            return text.to_string();
        }
        let mut prefix = String::new();
        if self.bold {
            prefix.push_str(Color::Bold.code());
        }
        if self.dim {
            prefix.push_str(Color::Dim.code());
        }
        if let Some(fg) = self.fg {
            prefix.push_str(fg.code());
        }
        format!("{prefix}{text}{}", Color::RESET)
    }
}

impl Default for Style {
    fn default() -> Self {
        Self::new()
    }
}
/// The semantic roles available to the presentation layer.
#[derive(Clone, Copy, Debug)]
pub struct Theme {
    /// Large logotype / banner artwork.
    pub banner: Style,
    /// Short program title (e.g. "TorsHammer v2.0.0").
    pub title: Style,
    /// One-line description under the title.
    pub subtitle: Style,
    /// Informational messages.
    pub info: Style,
    /// Successful operations.
    pub success: Style,
    /// Non-fatal problems.
    pub warning: Style,
    /// Fatal problems / errors.
    pub error: Style,
    /// Significant findings (e.g. scan results).
    pub result: Style,
    /// De-emphasized helper text.
    pub muted: Style,
    /// Emphasis for values inside otherwise plain lines.
    pub highlight: Style,
}

impl Theme {
    /// The default ANSI theme.
    ///
    /// Colors are used sparingly: one color family per semantic role.
    pub fn default() -> Self {
        Self {
            banner: Style::colored(Color::Cyan).bold(),
            title: Style::colored(Color::Cyan).bold(),
            subtitle: Style::new().dim(),
            info: Style::colored(Color::Blue),
            success: Style::colored(Color::Green),
            warning: Style::colored(Color::Yellow),
            error: Style::colored(Color::Red),
            result: Style::colored(Color::Cyan).bold(),
            muted: Style::new().dim(),
            highlight: Style::colored(Color::Magenta),
        }
    }

    /// A theme that renders plain, uncolored text.
    ///
    /// Used when color is disabled, stdout is redirected, or `NO_COLOR` /
    /// `TERM=dumb` is in effect. The presentation layer remains fully
    /// functional: only the styling is stripped.
    pub fn plain() -> Self {
        Self {
            banner: Style::new(),
            title: Style::new(),
            subtitle: Style::new(),
            info: Style::new(),
            success: Style::new(),
            warning: Style::new(),
            error: Style::new(),
            result: Style::new(),
            muted: Style::new(),
            highlight: Style::new(),
        }
    }
}

/// Heuristic for whether ANSI color should be used by default.
///
/// Honors the industry-standard `NO_COLOR` convention and `TERM=dumb`,
/// and refuses to colorize when the stream is not an interactive terminal.
/// Callers may still override the result with an explicit `--no-color` flag.
pub fn color_enabled(no_color_flag: bool) -> bool {
    if no_color_flag {
        return false;
    }
    if std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    if matches!(std::env::var("TERM").as_deref(), Ok("dumb") | Err(_)) {
        return false;
    }
    std::io::stdout().is_terminal()
}

/// Heuristic for whether Unicode symbols should be used by default.
///
/// Falls back to plain ASCII when the terminal reports a legacy encoding
/// or when `LANG` does not advertise UTF-8 support.
pub fn unicode_enabled(no_unicode_flag: bool) -> bool {
    if no_unicode_flag {
        return false;
    }
    if matches!(std::env::var("TERM").as_deref(), Ok("dumb") | Err(_)) {
        return false;
    }
    match std::env::var("LANG") {
        Ok(lang) => lang.to_ascii_uppercase().contains("UTF-8") || lang.contains("utf8"),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_style_does_not_emit_escape_codes() {
        let style = Style::colored(Color::Red).bold();
        assert_eq!(style.paint("hello", false), "hello");
    }

    #[test]
    fn colored_style_wraps_with_escape_codes() {
        let style = Style::colored(Color::Red);
        assert_eq!(style.paint("x", true), "\x1b[31mx\x1b[0m");
    }

    #[test]
    fn default_theme_has_styles() {
        let theme = Theme::default();
        let painted = theme.success.paint("ok", true);
        assert!(painted.contains("\x1b["));
    }

    #[test]
    fn plain_theme_renders_every_role_without_color() {
        let theme = Theme::plain();
        assert_eq!(theme.info.paint("a", true), "a");
        assert_eq!(theme.error.paint("b", true), "b");
        assert_eq!(theme.banner.paint("c", true), "c");
        assert_eq!(theme.result.paint("d", true), "d");
    }

    #[test]
    fn no_color_env_disables_color() {
        assert!(!color_enabled(true));
        std::env::set_var("NO_COLOR", "1");
        assert!(!color_enabled(false));
        std::env::remove_var("NO_COLOR");
    }

    #[test]
    fn unicode_flag_disables_unicode() {
        assert!(!unicode_enabled(true));
    }
}
