//! TorsHammer CLI presentation layer.
//!
//! This module is the terminal-facing presentation of the application. It
//! owns how output is rendered (banners, messages, progress, tables, help) but
//! contains **no scanning or security logic**. The engine is expected to
//! produce structured data; this layer decides how that data is presented.

pub mod banner;
pub mod help;

// `table` and `progress` are wired into the live/summary reporting path driven
// by `run_scan` (see `TtyMonitor` in `main.rs`), so they carry no `dead_code`
// allowance. `output`/`theme` keep a few reserved helpers for future styles.
#[allow(dead_code)]
pub mod output;
pub mod progress;
pub mod table;
#[allow(dead_code)]
pub mod theme;
