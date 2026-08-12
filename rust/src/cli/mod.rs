//! TorsHammer CLI presentation layer.
//!
//! This module is the terminal-facing presentation of the application. It
//! owns how output is rendered (banners, messages, progress, tables, help) but
//! contains **no scanning or security logic**. The engine is expected to
//! produce structured data; this layer decides how that data is presented.

pub mod banner;
pub mod help;
pub mod output;
pub mod progress;
pub mod table;
pub mod theme;
