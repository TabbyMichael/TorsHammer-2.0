//! Dependency-free pseudorandom generator and randomization helpers.
//!
//! A SplitMix64 generator keeps the crate zero-dependency (no `rand` crate),
//! is intentionally *not* cryptography-grade, and is far faster than the
//! Python `random` module for the per-connection header/timing randomization
//! the attack profiles need.

/// SplitMix64 PRNG.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    /// Create a generator from an input seed (mixed once at construction).
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_add(0x9E37_79B9_7F4A_7C15))
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform float in `[0, 1)`.
    pub fn f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform float in `[lo, hi]` (inclusive like Python's `random.uniform`).
    ///
    /// A zero (or negative) bound means "no delay at all": callers that pass
    /// `delay_min = delay_max = 0.0` (notably the unit tests) skip the PRNG
    /// draw entirely, so no wall-clock time is ever consumed.
    pub fn range_f64(&mut self, lo: f64, hi: f64) -> f64 {
        if hi <= lo {
            return lo;
        }
        lo + self.f64() * (hi - lo)
    }

    /// Inclusive integer in `[lo, hi]` (mirrors Python's `random.randint`).
    pub fn range_usize(&mut self, lo: usize, hi: usize) -> usize {
        if hi <= lo {
            return lo;
        }
        let span = (hi - lo + 1) as u64;
        lo + (self.next_u64() % span) as usize
    }

    /// Inclusive u8 in `[lo, hi]`.
    pub fn range_u8(&mut self, lo: u8, hi: u8) -> u8 {
        if hi <= lo {
            return lo;
        }
        // Widen before adding 1 so `range_u8(0, 255)` does not overflow `u8`.
        let span = hi as u64 - lo as u64 + 1;
        lo + (self.next_u64() % span) as u8
    }

    /// Pick one element uniformly from a slice.
    pub fn choice<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.range_usize(0, items.len().saturating_sub(1))]
    }

    /// Random boolean with the given probability.
    pub fn chance(&mut self, probability: f64) -> bool {
        self.f64() < probability
    }

    /// Random hex string over `0123456789abcdef` of the given length.
    pub fn hex(&mut self, len: usize) -> String {
        const HEX: &[u8] = b"0123456789abcdef";
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            out.push(HEX[(self.next_u64() & 0x0F) as usize] as char);
        }
        out
    }

    /// Random alphanumeric string (ASCII letters + digits) of the given length.
    pub fn alnum(&mut self, len: usize) -> String {
        const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            out.push(ALNUM[self.range_usize(0, ALNUM.len() - 1)] as char);
        }
        out
    }

    /// Random dotted-quad IPv4 string for spoofed `X-Forwarded-For` headers.
    pub fn random_ip(&mut self) -> String {
        (0..4)
            .map(|_| self.range_usize(0, 255).to_string())
            .collect::<Vec<_>>()
            .join(".")
    }

    /// `n` pseudorandom bytes (mirrors Python `secrets.token_bytes` for the TLS
    /// ClientHello `random`). Not cryptography-grade, but the handshake is never
    /// completed so cryptographic strength is irrelevant here.
    pub fn random_bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            out.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        out.truncate(n);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_stay_in_bounds() {
        let mut rng = Rng::new(7);
        for _ in 0..10_000 {
            let v = rng.range_usize(5, 12);
            assert!((5..=12).contains(&v));
            let f = rng.range_f64(0.0, 3.0);
            assert!((0.0..=3.0).contains(&f));
        }
    }

    #[test]
    fn range_u8_full_span_does_not_overflow() {
        // `range_u8(0, 255)` used to panic on `255u8 + 1` while computing the
        // span; it must return values across the whole u8 range instead.
        let mut rng = Rng::new(21);
        let mut hit_max = false;
        for _ in 0..100_000 {
            let v = rng.range_u8(0, 255);
            if v == 255 {
                hit_max = true;
            }
        }
        assert!(
            hit_max,
            "range_u8(0, 255) never reached the top of its span"
        );
        // Degenerate and inverted ranges clamp to `lo`.
        assert_eq!(Rng::new(1).range_u8(9, 9), 9);
        assert_eq!(Rng::new(1).range_u8(9, 3), 9);
    }

    #[test]
    fn generated_strings_have_expected_charset_and_length() {
        let mut rng = Rng::new(11);
        assert_eq!(rng.hex(6).len(), 6);
        assert!(rng.hex(6).chars().all(|c| c.is_ascii_hexdigit()));
        let s = rng.alnum(9);
        assert_eq!(s.len(), 9);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = Rng::new(1);
        let mut b = Rng::new(2);
        assert!((0..200).any(|_| a.next_u64() != b.next_u64()));
    }

    #[test]
    fn range_f64_degenerate_bounds_clamp_to_lo() {
        // hi <= lo short-circuits to lo (rng.rs L37-38) without drawing.
        let mut rng = Rng::new(2);
        assert_eq!(rng.range_f64(4.0, 4.0), 4.0);
        assert_eq!(rng.range_f64(9.0, 3.0), 9.0);
    }

    #[test]
    fn random_bytes_length_and_divergence() {
        let mut a = Rng::new(3);
        let mut b = Rng::new(4);
        let x = a.random_bytes(32);
        let y = b.random_bytes(32);
        assert_eq!(x.len(), 32);
        assert_eq!(a.random_bytes(0), Vec::<u8>::new());
        // A non-trivial prefix should differ between distinct seeds.
        assert_ne!(&x[..8], &y[..8]);
    }
}
