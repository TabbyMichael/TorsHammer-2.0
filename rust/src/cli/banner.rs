//! TorsHammer startup banner and branding header.
//!
//! The logotype is an original, compact block-letter wordmark composed from a
//! small glyph font. It is assembled programmatically so every row lines up
//! exactly, and it is rendered through the active [`Theme`] so `--no-color`
//! degrades it to plain text automatically. Version text always comes from
//! the caller (which sources it from `CARGO_PKG_VERSION`), never duplicated
//! here.

use crate::cli::theme::Theme;

/// One letter of the block-letter font: exactly 5 rows of 6 columns.
struct Letter {
    rows: [&'static str; 5],
}

const LETTER_T: Letter = Letter {
    rows: ["######", "  #   ", "  #   ", "  #   ", "  #   "],
};
const LETTER_O: Letter = Letter {
    rows: [" #### ", "#    #", "#    #", "#    #", " #### "],
};
const LETTER_R: Letter = Letter {
    rows: ["####  ", "#   # ", "####  ", "# #   ", "#  #  "],
};
const LETTER_S: Letter = Letter {
    rows: [" #### ", "#     ", " #### ", "     #", "####  "],
};
const LETTER_H: Letter = Letter {
    rows: ["#    #", "#    #", "######", "#    #", "#    #"],
};
const LETTER_A: Letter = Letter {
    rows: [" #### ", "#    #", "######", "#    #", "#    #"],
};
const LETTER_M: Letter = Letter {
    rows: ["#    #", "##  ##", "# ## #", "#    #", "#    #"],
};
const LETTER_E: Letter = Letter {
    rows: ["##### ", "#     ", "####  ", "#     ", "##### "],
};

fn letter_for(c: char) -> Option<&'static Letter> {
    match c {
        'T' => Some(&LETTER_T),
        'O' => Some(&LETTER_O),
        'R' => Some(&LETTER_R),
        'S' => Some(&LETTER_S),
        'H' => Some(&LETTER_H),
        'A' => Some(&LETTER_A),
        'M' => Some(&LETTER_M),
        'E' => Some(&LETTER_E),
        _ => None,
    }
}

/// Compose the original "TORSHAMMER" logotype from the block-letter font.
///
/// Each letter occupies the same 6x5 cell, so rows align by construction and
/// the banner renders identically on every terminal.
pub fn logotype() -> String {
    let word = "TORSHAMMER";
    let mut lines = vec![String::new(); 5];
    for c in word.chars() {
        if let Some(letter) = letter_for(c) {
            for (line, row) in lines.iter_mut().zip(letter.rows.iter()) {
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(row);
            }
        }
    }
    lines.join("\n")
}

/// Metadata displayed below the logotype in the startup banner.
pub struct BannerMeta<'a> {
    /// Program version (e.g. "2.0.0").
    pub version: &'a str,
    /// One-line description of the tool.
    pub description: &'a str,
    /// Runtime/engine label, e.g. "Rust".
    pub engine: &'a str,
    /// Platform label, e.g. "linux-x86_64".
    pub platform: &'a str,
    /// Target host/URL being tested.
    pub target: &'a str,
    /// Backend flavor, e.g. "rust".
    pub backend: &'a str,
    /// Optional configuration path; omitted from the header when `None`.
    pub config_path: Option<&'a str>,
}

/// Render a right-padded `label : value` header field.
fn field(theme: &Theme, label: &str, value: &str, color: bool) -> String {
    // `Configuration` is the longest label; pad everything to its width.
    format!("{label:<13} : {}", theme.highlight.paint(value, color))
}

/// Render the complete startup banner as a string.
pub fn render(theme: &Theme, meta: &BannerMeta, color: bool) -> String {
    let mut out = String::new();
    out.push_str(&theme.banner.paint(&logotype(), color));
    out.push('\n');
    out.push('\n');
    out.push_str(
        &theme
            .title
            .paint(&format!("TorsHammer v{}", meta.version), color),
    );
    out.push('\n');
    out.push_str(&theme.subtitle.paint(meta.description, color));
    out.push('\n');
    out.push('\n');
    out.push_str(&field(theme, "Engine", meta.engine, color));
    out.push('\n');
    out.push_str(&field(theme, "Version", meta.version, color));
    out.push('\n');
    out.push_str(&field(theme, "Platform", meta.platform, color));
    out.push('\n');
    out.push_str(&field(theme, "Target", meta.target, color));
    out.push('\n');
    out.push_str(&field(theme, "Backend", meta.backend, color));
    if let Some(path) = meta.config_path {
        out.push('\n');
        out.push_str(&field(theme, "Configuration", path, color));
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> BannerMeta<'static> {
        BannerMeta {
            version: "2.0.0",
            description: "Security Testing & Vulnerability Assessment Framework",
            engine: "Rust",
            platform: "linux-x86_64",
            target: "http://localhost",
            backend: "rust",
            config_path: None,
        }
    }

    #[test]
    fn logotype_has_five_aligned_rows() {
        let logo = logotype();
        let lines: Vec<&str> = logo.lines().collect();
        assert_eq!(lines.len(), 5);
        let widths: Vec<usize> = lines.iter().map(|l| l.chars().count()).collect();
        let first = widths[0];
        assert!(
            widths.iter().all(|w| *w == first),
            "logo rows are not aligned: {widths:?}"
        );
        assert_eq!(first, 69);
    }

    #[test]
    fn banner_contains_version_and_description() {
        let out = render(&Theme::plain(), &meta(), false);
        assert!(out.contains("TorsHammer v2.0.0"));
        assert!(out.contains("Security Testing"));
        assert!(out.contains("linux-x86_64"));
        assert!(out.contains("http://localhost"));
    }

    #[test]
    fn banner_respects_plain_theme() {
        let out = render(&Theme::plain(), &meta(), false);
        assert!(!out.contains("\x1b["));
    }

    #[test]
    fn banner_color_uses_escape_codes() {
        let out = render(&Theme::default(), &meta(), true);
        assert!(out.contains("\x1b["));
    }

    #[test]
    fn optional_config_path_is_only_shown_when_present() {
        let plain = render(&Theme::plain(), &meta(), false);
        assert!(!plain.contains("Configuration"));
        let mut m = meta();
        m.config_path = Some("~/.torshammer/config.toml");
        let with = render(&Theme::plain(), &m, false);
        assert!(with.contains("Configuration"));
        assert!(with.contains("~/.torshammer/config.toml"));
    }

    #[test]
    fn field_pads_labels_to_common_width() {
        let out = field(&Theme::plain(), "Engine", "Rust", false);
        assert!(out.starts_with("Engine        : Rust"));
    }
}
