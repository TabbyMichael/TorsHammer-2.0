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

/// Best-effort scan of HTTP response status codes out of whatever peer bytes a
/// profile happens to read. Mirrors the Python `_STATUS_LINE` regex
/// (`HTTP/\\d(?:\\.\\d)?[ \\t]+(\\d{3})`): a status line split across reads is
/// simply not tallied (advisory-only).
fn parse_status_codes(data: &[u8]) -> Vec<u16> {
    let mut codes = Vec::new();
    let mut i = 0usize;
    while i + 5 <= data.len() {
        if data[i..i + 5] == *b"HTTP/" {
            let mut j = i + 5;
            if j < data.len() && data[j].is_ascii_digit() {
                j += 1;
                if j + 1 < data.len() && data[j] == b'.' && data[j + 1].is_ascii_digit() {
                    j += 2;
                }
                while j < data.len() && (data[j] == b' ' || data[j] == b'\t') {
                    j += 1;
                }
                if j + 3 <= data.len()
                    && data[j].is_ascii_digit()
                    && data[j + 1].is_ascii_digit()
                    && data[j + 2].is_ascii_digit()
                {
                    let code = (data[j] - b'0') as u16 * 100
                        + (data[j + 1] - b'0') as u16 * 10
                        + (data[j + 2] - b'0') as u16;
                    codes.push(code);
                    i = j + 3;
                    continue;
                }
            }
        }
        i += 1;
    }
    codes
}

/// Immutable point-in-time view of the aggregate counters.
///
/// The engine produces this snapshot for the presentation layer so the CLI can
/// render live status/summary output without reaching into the atomic counters
/// directly (keeps `engine` free of presentation concerns).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub connections: u64,
    pub active: u64,
    pub peak_active: u64,
    pub completed: u64,
    pub errors: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    // --- impact metering (advisory): what the target actually answered with ---
    pub responses: u64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub resp_latency_count: u64,
    pub resp_latency_total_micros: u64,
}

impl Snapshot {
    /// Mean request->response latency in seconds (0.0 when no samples).
    pub fn mean_response_latency(&self) -> f64 {
        if self.resp_latency_count == 0 {
            0.0
        } else {
            (self.resp_latency_total_micros as f64 / 1_000_000.0) / self.resp_latency_count as f64
        }
    }
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
    // --- impact metering (advisory) ---
    responses: AtomicU64,
    status_2xx: AtomicU64,
    status_3xx: AtomicU64,
    status_4xx: AtomicU64,
    status_5xx: AtomicU64,
    status_other: AtomicU64,
    resp_latency_count: AtomicU64,
    resp_latency_total_micros: AtomicU64,
    /// Clock timestamp for uptime calculations (read by future reporters).
    #[allow(dead_code)]
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
            responses: AtomicU64::new(0),
            status_2xx: AtomicU64::new(0),
            status_3xx: AtomicU64::new(0),
            status_4xx: AtomicU64::new(0),
            status_5xx: AtomicU64::new(0),
            status_other: AtomicU64::new(0),
            resp_latency_count: AtomicU64::new(0),
            resp_latency_total_micros: AtomicU64::new(0),
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

    /// Account for ``data`` received from the peer and tally any HTTP status
    /// codes for the advisory impact verdict (parity with Python
    /// `Stats.record_response_bytes`).
    pub fn record_response_bytes(&self, data: &[u8]) {
        self.add_received(data.len() as u64);
        for code in parse_status_codes(data) {
            self.responses.fetch_add(1, Ordering::Relaxed);
            match code {
                200..=299 => self.status_2xx.fetch_add(1, Ordering::Relaxed),
                300..=399 => self.status_3xx.fetch_add(1, Ordering::Relaxed),
                400..=499 => self.status_4xx.fetch_add(1, Ordering::Relaxed),
                500..=599 => self.status_5xx.fetch_add(1, Ordering::Relaxed),
                _ => self.status_other.fetch_add(1, Ordering::Relaxed),
            };
        }
    }

    /// Record one request->response latency sample, in microseconds.
    pub fn record_response_latency_micros(&self, micros: u64) {
        self.resp_latency_count.fetch_add(1, Ordering::Relaxed);
        self.resp_latency_total_micros
            .fetch_add(micros, Ordering::Relaxed);
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
    pub fn responses(&self) -> u64 {
        self.responses.load(Ordering::Relaxed)
    }
    pub fn status_2xx(&self) -> u64 {
        self.status_2xx.load(Ordering::Relaxed)
    }
    pub fn status_3xx(&self) -> u64 {
        self.status_3xx.load(Ordering::Relaxed)
    }
    pub fn status_4xx(&self) -> u64 {
        self.status_4xx.load(Ordering::Relaxed)
    }
    pub fn status_5xx(&self) -> u64 {
        self.status_5xx.load(Ordering::Relaxed)
    }
    pub fn resp_latency_count(&self) -> u64 {
        self.resp_latency_count.load(Ordering::Relaxed)
    }
    pub fn resp_latency_total_micros(&self) -> u64 {
        self.resp_latency_total_micros.load(Ordering::Relaxed)
    }

    /// Mean request->response latency in seconds (0.0 when no samples).
    pub fn mean_response_latency(&self) -> f64 {
        let count = self.resp_latency_count();
        if count == 0 {
            0.0
        } else {
            (self.resp_latency_total_micros() as f64 / 1_000_000.0) / count as f64
        }
    }

    /// Take an immutable snapshot of every counter for the reporter.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            connections: self.connections(),
            active: self.active(),
            peak_active: self.peak_active(),
            completed: self.completed(),
            errors: self.errors(),
            bytes_sent: self.bytes_sent(),
            bytes_received: self.bytes_received(),
            responses: self.responses(),
            status_2xx: self.status_2xx(),
            status_3xx: self.status_3xx(),
            status_4xx: self.status_4xx(),
            status_5xx: self.status_5xx(),
            resp_latency_count: self.resp_latency_count(),
            resp_latency_total_micros: self.resp_latency_total_micros(),
        }
    }
}

/// Render an `; ...` telemetry suffix, or `""` when nothing was read.
/// Mirrors the Python `_response_telemetry`.
fn response_telemetry(snap: &Snapshot) -> String {
    if snap.responses == 0 && snap.resp_latency_count == 0 {
        return String::new();
    }
    let mut parts: Vec<String> = Vec::new();
    if snap.responses > 0 {
        parts.push(format!(
            "responses={} (2xx={} 3xx={} 4xx={} 5xx={})",
            snap.responses, snap.status_2xx, snap.status_3xx, snap.status_4xx, snap.status_5xx
        ));
    }
    if snap.resp_latency_count > 0 {
        parts.push(format!(
            "mean_resp_latency={:.2}s",
            snap.mean_response_latency()
        ));
    }
    format!("; {}", parts.join(", "))
}

/// Classify a run as an advisory mitigation verdict (never an exit code).
/// Mirrors the Python `classify_verdict` thresholds exactly.
pub fn classify_verdict(snap: &Snapshot) -> (String, String) {
    let total = snap.connections;
    if total == 0 {
        return (
            "INCONCLUSIVE".to_string(),
            "no connections opened; nothing to classify".to_string(),
        );
    }
    let error_share = snap.errors as f64 / total as f64;
    let completed_share = snap.completed as f64 / total as f64;
    let telemetry = response_telemetry(snap);
    if error_share >= 0.5 {
        return (
            "LIKELY_MITIGATED".to_string(),
            format!(
                "{}/{} connections errored (target shed slow connections; check timeouts/WAF){}",
                snap.errors, total, telemetry
            ),
        );
    }
    if snap.peak_active > 0 && completed_share >= 0.2 {
        return (
            "LIKELY_VULNERABLE".to_string(),
            format!(
                "{}/{} slow cycles completed with peak_active={} (workers stayed pinned){}",
                snap.completed, total, snap.peak_active, telemetry
            ),
        );
    }
    if snap.status_5xx >= std::cmp::max(2, total / 10) {
        return (
            "LIKELY_VULNERABLE".to_string(),
            format!(
                "{} server errors (5xx) returned under load (backend degrading while workers held open){}",
                snap.status_5xx, telemetry
            ),
        );
    }
    (
        "INCONCLUSIVE".to_string(),
        format!(
            "errors={} completed={} peak_active={}; rerun longer for a clearer signal{}",
            snap.errors, snap.completed, snap.peak_active, telemetry
        ),
    )
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_codes_finds_each_response_line() {
        let data = b"HTTP/1.1 503 Service Unavailable\r\n\r\nHTTP/1.0 200 OK\r\nHTTP/2 404\r\n";
        assert_eq!(parse_status_codes(data), vec![503, 200, 404]);
    }

    #[test]
    fn parse_status_codes_ignores_non_status_text() {
        assert!(parse_status_codes(b"not a status line at all").is_empty());
        // Missing space between version and code -> not tallied.
        assert!(parse_status_codes(b"HTTP/1.1X503").is_empty());
    }

    #[test]
    fn record_response_bytes_tallies_status_classes_and_bytes() {
        let stats = Stats::new();
        stats.record_response_bytes(b"HTTP/1.1 500 x\r\nHTTP/1.1 201 y\r\n");
        assert_eq!(stats.responses(), 2);
        assert_eq!(stats.status_5xx(), 1);
        assert_eq!(stats.status_2xx(), 1);
        assert_eq!(stats.bytes_received(), 32);
    }

    #[test]
    fn mean_response_latency_zero_without_samples() {
        let stats = Stats::new();
        assert_eq!(stats.mean_response_latency(), 0.0);
        stats.record_response_latency_micros(1_000_000);
        stats.record_response_latency_micros(3_000_000);
        assert!((stats.mean_response_latency() - 2.0).abs() < 1e-9);
    }

    fn snap(connections: u64, errors: u64, completed: u64, peak: u64) -> Snapshot {
        Snapshot {
            connections,
            errors,
            completed,
            peak_active: peak,
            ..Snapshot::default()
        }
    }

    #[test]
    fn verdict_no_connections_is_inconclusive() {
        let (verdict, _) = classify_verdict(&snap(0, 0, 0, 0));
        assert_eq!(verdict, "INCONCLUSIVE");
    }

    #[test]
    fn verdict_high_error_share_is_mitigated() {
        let (verdict, _) = classify_verdict(&snap(10, 8, 0, 0));
        assert_eq!(verdict, "LIKELY_MITIGATED");
    }

    #[test]
    fn verdict_completed_cycles_is_vulnerable() {
        let (verdict, _) = classify_verdict(&snap(10, 0, 5, 3));
        assert_eq!(verdict, "LIKELY_VULNERABLE");
    }

    #[test]
    fn verdict_server_errors_under_load_is_vulnerable() {
        let mut s = snap(10, 0, 0, 1);
        s.status_5xx = 3;
        s.responses = 3;
        let (verdict, reason) = classify_verdict(&s);
        assert_eq!(verdict, "LIKELY_VULNERABLE");
        assert!(reason.contains("5xx"));
    }

    #[test]
    fn parse_status_codes_skips_http_token_without_digit() {
        // "HTTP/" immediately followed by a non-digit falls through the
        // version-digit guard (stats.rs L28/L48) and tallies nothing.
        assert!(parse_status_codes(b"HTTP/x 200 OK").is_empty());
    }

    #[test]
    fn status_other_bucket_captures_unclassified_codes() {
        // A 1xx response is neither 2xx..5xx, so it lands in status_other
        // (the `_ =>` arm at stats.rs L177).
        let stats = Stats::new();
        stats.record_response_bytes(b"HTTP/1.1 100 Continue\r\n");
        assert_eq!(stats.responses(), 1);
        assert_eq!(stats.status_2xx(), 0);
    }

    #[test]
    fn record_error_increments_error_counter() {
        let stats = Stats::default();
        assert_eq!(stats.errors(), 0);
        stats.record_error();
        stats.record_error();
        assert_eq!(stats.errors(), 2);
    }

    #[test]
    fn snapshot_mean_latency_handles_present_and_absent_samples() {
        // The Snapshot method (stats.rs L81-87) mirrors Stats::mean and is the
        // one the reporter actually reads.
        let mut s = Snapshot::default();
        assert_eq!(s.mean_response_latency(), 0.0);
        s.resp_latency_count = 2;
        s.resp_latency_total_micros = 5_000_000;
        assert!((s.mean_response_latency() - 2.5).abs() < 1e-9);
    }

    #[test]
    fn telemetry_includes_latency_when_samples_exist() {
        // Reaching the final INCONCLUSIVE branch (stats.rs L325-331) with both
        // responses and latency recorded exercises the full telemetry suffix
        // including mean_resp_latency (L277-280).
        let mut s = snap(10, 2, 0, 0); // error_share 0.2, peak 0, no 5xx
        s.responses = 4;
        s.status_2xx = 4;
        s.resp_latency_count = 4;
        s.resp_latency_total_micros = 8_000_000;
        let (verdict, reason) = classify_verdict(&s);
        assert_eq!(verdict, "INCONCLUSIVE");
        assert!(reason.contains("responses=4"));
        assert!(reason.contains("mean_resp_latency=2.00s"));
    }
}
