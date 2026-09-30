//! TorsHammer startup banner and branding header.
//!
//! The banner is the shared template in `assets/banner.txt` at the repository
//! root — the single source of truth for every runtime. The Python package
//! ships the same bytes as `src/torshammer/banner.txt`, and
//! `tests/test_banner.py` fails if the two copies ever drift apart.
//!
//! The template is embedded at compile time and rendered through the active
//! [`Theme`], so `--no-color` degrades it to plain text automatically. Its
//! `{VER}` / `{TARGET}` / `{BACKEND}` / `{MODE}` / `{CONCURRENCY}` placeholders
//! are filled from the running scan, so the Rust and Python engines print
//! byte-for-byte identical banners apart from the values themselves.

use crate::cli::theme::Theme;

/// The shared banner template, embedded at compile time.
///
/// The path is relative to this file and resolves to the repository-root
/// `assets/banner.txt`, so the Rust and Python runtimes always render exactly
/// the same banner. Building the crate therefore requires a full checkout;
/// CI builds with `--manifest-path rust/Cargo.toml` from the root.
const BANNER_TEMPLATE: &str = include_str!("../../../assets/banner.txt");

/// The artwork rows as written in the asset, before any padding.
fn art_rows() -> Vec<&'static str> {
    BANNER_TEMPLATE
        .lines()
        .take_while(|line| !line.is_empty())
        .collect()
}

/// Compose the logotype from the shared artwork.
///
/// Every row is right-padded to the widest row, so the artwork keeps a single
/// uniform width even when an editor strips trailing whitespace from the asset
/// file. Rows therefore align by construction.
pub fn logotype() -> String {
    let rows = art_rows();
    let width = rows
        .iter()
        .map(|row| row.chars().count())
        .max()
        .unwrap_or(0);
    rows.iter()
        .map(|row| format!("{row}{}", " ".repeat(width - row.chars().count())))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Metadata displayed below the logotype in the startup banner.
pub struct BannerMeta<'a> {
    /// Program version (e.g. "2.0.0").
    pub version: &'a str,
    /// One-line description of the tool.
    pub description: &'a str,
    /// Target host/URL being tested.
    pub target: &'a str,
    /// Backend flavor, e.g. "rust".
    pub backend: &'a str,
    /// Attack mode in use, e.g. "slow-post".
    pub mode: &'a str,
    /// Requested concurrent connections.
    pub concurrency: usize,
}

/// Render a `label : value` line using the shared template's 8-column layout
/// (`Target  : ...`, `Backend : ...`, `Mode    : ...`, `Conns   : ...`), so the
/// Rust banner lines up with the Python one and with `assets/banner.txt`.
fn field(theme: &Theme, label: &str, value: &str, color: bool) -> String {
    format!("{label:<8}: {}", theme.highlight.paint(value, color))
}

/// Render the complete startup banner as a string.
///
/// Mirrors the shared template exactly — artwork, `TorsHammer {VER}`,
/// description, then the `Target`/`Backend`/`Mode`/`Conns` block — so the Rust
/// and Python engines produce identical banners.
pub fn render(theme: &Theme, meta: &BannerMeta, color: bool) -> String {
    let mut out = String::new();
    out.push_str(&theme.banner.paint(&logotype(), color));
    out.push_str("\n\n");
    out.push_str(
        &theme
            .title
            .paint(&format!("TorsHammer {}", meta.version), color),
    );
    out.push('\n');
    out.push_str(&theme.subtitle.paint(meta.description, color));
    out.push_str("\n\n");
    out.push_str(&field(theme, "Target", meta.target, color));
    out.push('\n');
    out.push_str(&field(theme, "Backend", meta.backend, color));
    out.push('\n');
    out.push_str(&field(theme, "Mode", meta.mode, color));
    out.push('\n');
    out.push_str(&field(theme, "Conns", &meta.concurrency.to_string(), color));
    out.push_str("\n\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> BannerMeta<'static> {
        BannerMeta {
            version: "2.0.0",
            description: "Security Testing & Vulnerability Assessment Framework",
            target: "http://localhost",
            backend: "rust",
            mode: "slow-post",
            concurrency: 256,
        }
    }

    #[test]
    fn logotype_comes_from_the_shared_asset() {
        let source = art_rows();
        assert_eq!(source.len(), 6, "the shared artwork is six rows tall");
        let logo = logotype();
        let lines: Vec<&str> = logo.lines().collect();
        assert_eq!(lines.len(), source.len());
        for (padded, raw) in lines.iter().zip(source.iter()) {
            // Only trailing whitespace may differ: content must match the asset.
            assert!(
                padded.starts_with(raw),
                "row drifted: {padded:?} vs {raw:?}"
            );
            assert_eq!(
                padded.trim_end().chars().count(),
                raw.trim_end().chars().count()
            );
        }
        assert!(lines[0].contains('\u{2588}'), "block glyph expected");
    }

    #[test]
    fn logotype_rows_are_aligned() {
        let logo = logotype();
        let widths: Vec<usize> = logo.lines().map(|l| l.chars().count()).collect();
        let first = widths[0];
        assert!(
            widths.iter().all(|w| *w == first),
            "logo rows are not aligned: {widths:?}"
        );
        let widest = art_rows()
            .iter()
            .map(|row| row.chars().count())
            .max()
            .expect("artwork has rows");
        assert_eq!(first, widest);
    }

    #[test]
    fn asset_is_the_shared_template() {
        for placeholder in ["{VER}", "{TARGET}", "{BACKEND}", "{MODE}", "{CONCURRENCY}"] {
            assert!(
                BANNER_TEMPLATE.contains(placeholder),
                "assets/banner.txt is missing {placeholder}"
            );
        }
    }

    #[test]
    fn banner_matches_the_shared_template_exactly() {
        let out = render(&Theme::plain(), &meta(), false);
        assert!(out.contains('\u{2588}'), "artwork is rendered");
        // `TorsHammer {VER}` in the template carries no "v" prefix.
        assert!(out.contains("TorsHammer 2.0.0"));
        assert!(!out.contains("TorsHammer v"));
        assert!(out.contains("Security Testing & Vulnerability Assessment Framework"));
        // The template carries exactly these four fields, nothing more.
        assert!(out.contains("Target  : http://localhost"));
        assert!(out.contains("Backend : rust"));
        assert!(out.contains("Mode    : slow-post"));
        assert!(out.contains("Conns   : 256"));
        for extra in ["Engine", "Platform", "Configuration"] {
            assert!(!out.contains(extra), "template must not add a {extra} line");
        }
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
    fn fields_use_the_shared_eight_column_layout() {
        let out = field(&Theme::plain(), "Target", "http://x", false);
        assert_eq!(out, "Target  : http://x");
        let out = field(&Theme::plain(), "Backend", "rust", false);
        assert_eq!(out, "Backend : rust");
        let out = field(&Theme::plain(), "Mode", "slow-post", false);
        assert_eq!(out, "Mode    : slow-post");
        let out = field(&Theme::plain(), "Conns", "256", false);
        assert_eq!(out, "Conns   : 256");
    }
}
