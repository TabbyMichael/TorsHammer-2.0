//! Reusable, dependency-free table renderer for structured CLI results.
//!
//! Handles long values, empty values, Unicode content, narrow terminals, and
//! large result sets. Rendering is a pure function of the table data plus a
//! width budget, so it is trivially testable and safe to use with output that
//! is redirected to a file or a CI log.

/// A left-aligned table with a header row and a separator rule.
#[derive(Debug, Clone)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    unicode: bool,
}

impl Table {
    /// Create a table with the given headers.
    pub fn new<I, S>(headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            headers: headers.into_iter().map(Into::into).collect(),
            rows: Vec::new(),
            unicode: true,
        }
    }

    /// Choose Unicode separators/ellipsis (`true`, default) or ASCII (`false`).
    pub fn with_unicode(mut self, unicode: bool) -> Self {
        self.unicode = unicode;
        self
    }

    /// Append a row. Missing cells render as empty; extra cells are ignored.
    pub fn add_row<I, S>(&mut self, row: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut cells: Vec<String> = row.into_iter().map(Into::into).collect();
        cells.truncate(self.headers.len());
        cells.resize(self.headers.len(), String::new());
        self.rows.push(cells);
    }

    /// Render the table, honoring a maximum terminal width.
    ///
    /// When the natural width exceeds `width_limit`, the widest columns are
    /// reduced and their contents truncated with an ellipsis marker.
    pub fn render(&self, width_limit: usize) -> String {
        let col_count = self.headers.len();
        if col_count == 0 {
            return String::new();
        }

        let mut widths: Vec<usize> = self.headers.iter().map(|h| display_width(h)).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                widths[i] = widths[i].max(display_width(cell));
            }
        }

        shrink(&mut widths, width_limit);
        let ellipsis = if self.unicode { "\u{2026}" } else { "..." };
        let rule = if self.unicode { "\u{2500}" } else { "-" };

        let mut out = String::new();
        // Header row.
        let header: Vec<String> = self
            .headers
            .iter()
            .zip(widths.iter())
            .map(|(h, w)| fit(h, *w, ellipsis))
            .collect();
        out.push_str(&join_row(&header, &widths));
        out.push('\n');
        // Separator row.
        let rule_row: Vec<String> = widths.iter().map(|w| rule.repeat(*w)).collect();
        out.push_str(&join_row(&rule_row, &widths));
        out.push('\n');
        // Body rows.
        for row in &self.rows {
            let cells: Vec<String> = row
                .iter()
                .zip(widths.iter())
                .map(|(c, w)| fit(c, *w, ellipsis))
                .collect();
            out.push_str(&join_row(&cells, &widths));
            out.push('\n');
        }
        out.trim_end_matches('\n').to_string()
    }
}

/// Number of display columns approximated by the character count.
///
/// A single `char` is treated as one column. This is an approximation for
/// wide glyphs (CJK) but keeps the renderer dependency-free and deterministic.
fn display_width(text: &str) -> usize {
    text.chars().count()
}

/// Truncate `text` to at most `width` display columns, appending an ellipsis
/// when content is cut off. Empty input stays empty.
fn fit(text: &str, width: usize, ellipsis: &str) -> String {
    if width == 0 {
        return String::new();
    }
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= width {
        return text.to_string();
    }
    let mark: Vec<char> = ellipsis.chars().collect();
    let keep = width.saturating_sub(mark.len());
    if keep == 0 {
        return mark.iter().take(width).collect();
    }
    let mut out: String = chars[..keep].iter().collect();
    out.extend(mark.iter());
    out
}

/// Left-align each cell into its column and join with two spaces.
fn join_row(cells: &[String], widths: &[usize]) -> String {
    cells
        .iter()
        .zip(widths.iter())
        .map(|(c, w)| format!("{c:<w$}"))
        .collect::<Vec<String>>()
        .join("  ")
}

/// Reduce column widths until the rendered row fits within `width_limit`.
///
/// The budget accounts for the two-space gap between columns. Proportional
/// shrinking keeps relative emphasis; a final greedy pass resolves rounding.
fn shrink(widths: &mut [usize], width_limit: usize) {
    const GAP: usize = 2;
    let cols = widths.len();
    if cols == 0 || width_limit == 0 {
        return;
    }
    let gaps = cols.saturating_sub(1) * GAP;
    let budget = width_limit.saturating_sub(gaps);
    if budget == 0 {
        widths.iter_mut().for_each(|w| *w = 0);
        return;
    }
    let total: usize = widths.iter().sum();
    if total <= budget {
        return;
    }
    // Proportional shrink, with a floor of one column.
    let scaled: Vec<usize> = widths
        .iter()
        .map(|w| ((*w as u64 * budget as u64) / total.max(1) as u64).max(1) as usize)
        .collect();
    widths.copy_from_slice(&scaled);
    // Greedy pass: keep removing a column of the widest column until we fit.
    loop {
        let current: usize = widths.iter().sum();
        if current <= budget {
            break;
        }
        let Some((idx, _)) = widths
            .iter()
            .enumerate()
            .filter(|(_, w)| **w > 0)
            .max_by_key(|(_, w)| **w)
        else {
            break;
        };
        widths[idx] -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_rendering_aligns_columns() {
        let mut t = Table::new(["PORT", "STATE", "SERVICE"]);
        t.add_row(["22", "OPEN", "SSH"]);
        t.add_row(["443", "OPEN", "HTTPS"]);
        t.add_row(["9999", "CLOSED", ""]);
        let out = t.render(80);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 5); // header + rule + 3 data rows

        // Header then a separator rule.
        assert!(lines[0].starts_with("PORT"));
        assert!(lines[1].contains('\u{2500}'));
        // Data rows keep their port in the leading column.
        assert!(lines[2].starts_with("22"));
        assert!(lines[3].starts_with("443"));
        assert!(lines[4].starts_with("9999"));
        // Column values line up: services start at the same character index.
        let idx = lines[2].find("SSH").unwrap();
        assert_eq!(lines[3].as_bytes()[idx], b'H');
    }

    #[test]
    fn ascii_rule_is_used_when_unicode_disabled() {
        let mut t = Table::new(["A", "B"]).with_unicode(false);
        t.add_row(["1", "2"]);
        let out = t.render(80);
        assert!(out.contains("-  -"));
        assert!(!out.contains('\u{2500}'));
    }

    #[test]
    fn long_values_are_truncated_to_fit_narrow_terminals() {
        let mut t = Table::new(["TARGET", "STATUS"]);
        t.add_row(["https://very-long-hostname.example.com/path", "200 OK"]);
        let out = t.render(24);
        for line in out.lines() {
            assert!(line.chars().count() <= 24, "line too wide: {line:?}");
        }
        assert!(out.contains('\u{2026}'), "expected ellipsis marker");
    }

    #[test]
    fn empty_values_render_as_blank_cells() {
        let mut t = Table::new(["A", "B", "C"]);
        t.add_row(["1", "", "3"]);
        let out = t.render(80);
        let row = out.lines().nth(2).unwrap();
        assert!(row.starts_with('1'));
        assert!(row.contains('3'));
    }

    #[test]
    fn unicode_content_is_preserved() {
        let mut t = Table::new(["NAME", "STATUS"]);
        t.add_row(["caf\u{e9}", "\u{2713}"]);
        let out = t.render(80);
        assert!(out.contains("caf\u{e9}"));
        assert!(out.contains('\u{2713}'));
    }

    #[test]
    fn empty_table_renders_headers_only() {
        let mut t = Table::new(["PORT"]);
        t.add_row(["80"]);
        let out = t.render(80);
        assert_eq!(out.lines().count(), 3);
    }

    #[test]
    fn no_headers_renders_nothing() {
        let t = Table::new(Vec::<String>::new());
        assert_eq!(t.render(80), "");
    }

    #[test]
    fn fit_truncates_with_ellipsis() {
        assert_eq!(fit("abcdef", 5, "..."), "ab...");
        assert_eq!(fit("abcdef", 4, "\u{2026}"), "abc\u{2026}");
        assert_eq!(fit("abc", 5, "..."), "abc");
        assert_eq!(fit("", 5, "..."), "");
    }

    #[test]
    fn display_width_counts_chars() {
        assert_eq!(display_width("caf\u{e9}"), 4);
        assert_eq!(display_width("\u{65e5}\u{672c}"), 2);
    }
}
