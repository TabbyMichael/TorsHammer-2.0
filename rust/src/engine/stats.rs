//! Shared atomic counters used by workers and the reporter loop.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Format a byte count as a human readable string (`1.2 MB`).
pub fn human_size(n: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = n;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{:.1} {}", value, UNITS[unit])
}

/// Aggregate counters, updated from many worker threads.
#[derive(Debug)]
pub struct Stats {
    connections: AtomicU64,
    active: AtomicU64,
    peak_active: AtomicU64,
    completed: AtomicU64,
    errors: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    /// Clock timestamp for uptime calculations.
    pub start: Instant,
}

impl Stats {
    /// Create zeroed counters.
    pub fn new() -> Self {
        Self {
            connections: AtomicU64::new(0),
            active: AtomicU64::new(0),
            peak_active: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            start: Instant::now(),
        }
    }

    /// A new connection was established (connections++, active++, peak).
    pub fn record_connect(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
        let active = self.active.fetch_add(1, Ordering::Relaxed) + 1;
        self.peak_active.fetch_max(active, Ordering::Relaxed);
    }

    /// An established connection was closed.
    pub fn record_disconnect(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn record_completed(&self) {
        self.completed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_received(&self, n: u64) {
        self.bytes_received.fetch_add(n, Ordering::Relaxed);
    }

    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }
    pub fn active(&self) -> u64 {
        self.active.load(Ordering::Relaxed)
    }
    pub fn peak_active(&self) -> u64 {
        self.peak_active.load(Ordering::Relaxed)
    }
    pub fn completed(&self) -> u64 {
        self.completed.load(Ordering::Relaxed)
    }
    pub fn errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}