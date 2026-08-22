//! TorsHammer CLI presentation layer.
//!
//! This module is the terminal-facing presentation of the application. It
//! owns how output is rendered (banners, messages, progress, tables, help) but
//! contains **no scanning or security logic**. The engine is expected to
//! produce structured data; this layer decides how that data is presented.

pub mod banner;
pub mod help;

// Presentation helpers below are intentional API surface reserved for richer
// interactive output modes; they are not wired into the minimal CLI yet.
#[allow(dead_code)]
pub mod output;
#[allow(dead_code)]
pub mod progress;
#[allow(dead_code)]
pub mod table;
#[allow(dead_code)]
pub mod theme;
