//! Seed management.
//!
//! Every experiment is reproducible: same seed → same outcome
//! within sampling tolerance. The `check_h{2,3}_seed_pinned.py`
//! tripwires enforce the seed lists are pinned; this module reads
//! and validates them.
//!
//! H2 uses a list of distinct positive-integer seeds (one per
//! adapter trial). H3 uses a single deterministic seed (Byzantine
//! validator selection). Both flow through `ExperimentSeed`.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::path::PathBuf;
use thiserror::Error;

/// A single deterministic seed for one experiment run. Wraps a u64
/// because every downstream RNG (ChaCha20Rng, SmallRng,
/// SplitMix64) accepts u64-or-larger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExperimentSeed(pub u64);

impl ExperimentSeed {
    /// Parse a seed from a pinning file line. Strict: positive
    /// integer, no decoration.
    pub fn parse(raw: &str) -> Result<Self, SeedError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            return Err(SeedError::Skip);
        }
        let value = trimmed
            .parse::<u64>()
            .map_err(|_| SeedError::NotPositiveInteger(trimmed.to_owned()))?;
        if value == 0 {
            return Err(SeedError::Zero);
        }
        Ok(Self(value))
    }

    /// Read seeds from a pinning file. Returns the full ordered
    /// list, preserving file order. Tripwire enforces distinctness;
    /// this reader does NOT — runtime can decide what to do with
    /// duplicates.
    pub fn from_pinning_file(path: &PathBuf) -> Result<Vec<Self>, SeedError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| SeedError::Read(path.clone(), e.to_string()))?;
        let mut out = Vec::new();
        for line in text.lines() {
            match Self::parse(line) {
                Ok(seed) => out.push(seed),
                Err(SeedError::Skip) => continue,
                Err(e) => return Err(e),
            }
        }
        if out.is_empty() {
            return Err(SeedError::Empty(path.clone()));
        }
        Ok(out)
    }

    /// Spawn a deterministic ChaCha20 RNG from this seed. ChaCha20
    /// is the right default — high quality, well-specified across
    /// platforms, and the same RNG `0x0111` uses internally.
    pub fn rng(&self) -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(self.0)
    }
}

/// Type alias for clarity at call sites.
pub type SeededRng = ChaCha20Rng;

/// Errors for seed parsing / loading.
#[derive(Debug, Error)]
pub enum SeedError {
    /// Blank or comment line — not a seed; caller skips.
    #[error("skip (blank or comment)")]
    Skip,
    /// Could not parse `s` as a positive integer.
    #[error("`{0}` is not a positive integer")]
    NotPositiveInteger(String),
    /// `0` is not a valid seed (it produces a degenerate RNG state
    /// in some implementations, and the tripwire rejects it).
    #[error("seed cannot be zero")]
    Zero,
    /// File I/O error.
    #[error("could not read pinning file {0:?}: {1}")]
    Read(PathBuf, String),
    /// File existed but had no seed lines.
    #[error("no seeds in pinning file {0:?}")]
    Empty(PathBuf),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_positive_integers_only() {
        assert_eq!(ExperimentSeed::parse("42").unwrap(), ExperimentSeed(42));
        assert!(matches!(
            ExperimentSeed::parse("0"),
            Err(SeedError::Zero)
        ));
        assert!(matches!(
            ExperimentSeed::parse("not-a-number"),
            Err(SeedError::NotPositiveInteger(_))
        ));
        assert!(matches!(
            ExperimentSeed::parse("# comment"),
            Err(SeedError::Skip)
        ));
        assert!(matches!(ExperimentSeed::parse("   "), Err(SeedError::Skip)));
    }

    #[test]
    fn rng_is_deterministic_per_seed() {
        use rand::RngCore;
        let s = ExperimentSeed(12345);
        let mut a = s.rng();
        let mut b = s.rng();
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_produce_different_streams() {
        use rand::RngCore;
        let mut a = ExperimentSeed(1).rng();
        let mut b = ExperimentSeed(2).rng();
        // Collect first 8 outputs from each; at least one should differ.
        let av: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
        let bv: Vec<u64> = (0..8).map(|_| b.next_u64()).collect();
        assert_ne!(av, bv);
    }
}
