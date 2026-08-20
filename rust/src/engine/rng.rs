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
        const ALNUM: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
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
}