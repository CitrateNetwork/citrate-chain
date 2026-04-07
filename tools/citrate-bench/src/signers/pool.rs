//! Multi-signer pool with per-signer nonce lanes.
//!
//! The pool pairs each signer with its own `NonceLane`. The runner
//! calls `try_acquire` to get a `(Signer, NoncePermit)` pair. Round-
//! robin rotation skips saturated lanes without blocking, so a slow
//! signer cannot starve faster signers. When every lane is full,
//! `try_acquire` returns `None` and the runner applies backpressure.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::nonce::{NonceLane, NoncePermit};
use crate::signers::Signer;
use crate::{Error, Result};

pub struct SignerPool {
    signers: Vec<Arc<Signer>>,
    lanes: Vec<Arc<NonceLane>>,
    cursor: AtomicUsize,
}

impl SignerPool {
    /// Build a new pool from a matched list of signers and their
    /// starting nonces. `max_inflight` applies per-signer.
    pub fn new(
        signers: Vec<Signer>,
        starting_nonces: Vec<u64>,
        max_inflight: usize,
    ) -> Result<Self> {
        if signers.is_empty() {
            return Err(Error::Config("SignerPool requires at least one signer".into()));
        }
        if signers.len() != starting_nonces.len() {
            return Err(Error::Config(format!(
                "signers ({}) and starting_nonces ({}) must have equal length",
                signers.len(),
                starting_nonces.len()
            )));
        }
        let lanes = starting_nonces
            .into_iter()
            .map(|n| NonceLane::new(n, max_inflight))
            .collect::<Vec<_>>();
        let signers = signers.into_iter().map(Arc::new).collect::<Vec<_>>();
        Ok(Self {
            signers,
            lanes,
            cursor: AtomicUsize::new(0),
        })
    }

    pub fn len(&self) -> usize {
        self.signers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signers.is_empty()
    }

    pub fn signer(&self, index: usize) -> Option<&Arc<Signer>> {
        self.signers.get(index)
    }

    pub fn lane(&self, index: usize) -> Option<&Arc<NonceLane>> {
        self.lanes.get(index)
    }

    /// Round-robin acquire. Walks the pool up to `len` times, returning
    /// the first non-saturated lane. Returns `None` if every lane is
    /// full.
    ///
    /// Each call advances the cursor by 1 even on failure, so callers
    /// making rapid-fire `try_acquire` calls won't re-hit the same full
    /// lane first every time.
    pub fn try_acquire(&self) -> Option<(Arc<Signer>, NoncePermit)> {
        let n = self.signers.len();
        for _ in 0..n {
            let idx = self.cursor.fetch_add(1, Ordering::AcqRel) % n;
            if let Some(permit) = self.lanes[idx].try_acquire() {
                return Some((Arc::clone(&self.signers[idx]), permit));
            }
        }
        None
    }

    /// Snapshot of the in-flight count per lane. Used by reporting.
    pub fn inflight_snapshot(&self) -> Vec<usize> {
        self.lanes.iter().map(|l| l.inflight()).collect()
    }

    /// Total in-flight across all lanes.
    pub fn total_inflight(&self) -> usize {
        self.lanes.iter().map(|l| l.inflight()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer_with_last_byte(b: u8) -> Signer {
        let mut k = [0u8; 32];
        k[31] = b;
        Signer::from_key_bytes(&k).expect("signer")
    }

    #[test]
    fn new_rejects_mismatched_lengths() {
        let signers = vec![signer_with_last_byte(1), signer_with_last_byte(2)];
        assert!(SignerPool::new(signers, vec![0], 10).is_err());
    }

    #[test]
    fn new_rejects_empty_signers() {
        assert!(SignerPool::new(Vec::new(), Vec::new(), 10).is_err());
    }

    #[test]
    fn round_robin_distributes_across_signers() {
        let signers = (1..=3).map(signer_with_last_byte).collect::<Vec<_>>();
        let addrs = signers.iter().map(|s| s.address).collect::<Vec<_>>();
        let pool = SignerPool::new(signers, vec![0, 0, 0], 100).expect("pool");

        let mut seen = std::collections::HashSet::new();
        let mut permits = Vec::new();
        for _ in 0..3 {
            let (signer, permit) = pool.try_acquire().expect("acquire");
            seen.insert(signer.address);
            permits.push(permit);
        }
        assert_eq!(seen.len(), 3);
        for a in &addrs {
            assert!(seen.contains(a));
        }
    }

    #[test]
    fn round_robin_skips_saturated_lanes() {
        let signers = (1..=3).map(signer_with_last_byte).collect::<Vec<_>>();
        let pool = SignerPool::new(signers, vec![0, 0, 0], 1).expect("pool");

        // Saturate first two lanes directly.
        let p0 = pool.lane(0).expect("lane 0").try_acquire().expect("0");
        let p1 = pool.lane(1).expect("lane 1").try_acquire().expect("1");
        assert_eq!(pool.total_inflight(), 2);

        // Pool must still find lane 2 on the next round-robin call,
        // regardless of where the cursor starts.
        let (_signer, p2) = pool.try_acquire().expect("lane 2 via pool");
        assert_eq!(pool.total_inflight(), 3);

        // Now all lanes are full.
        assert!(pool.try_acquire().is_none());
        drop(p0);
        drop(p1);
        drop(p2);
    }

    #[test]
    fn pool_reports_zero_inflight_initially() {
        let signers = vec![signer_with_last_byte(1), signer_with_last_byte(2)];
        let pool = SignerPool::new(signers, vec![10, 20], 5).expect("pool");
        assert_eq!(pool.total_inflight(), 0);
        assert_eq!(pool.inflight_snapshot(), vec![0, 0]);
    }

    #[test]
    fn pool_starting_nonces_are_independent() {
        let signers = vec![signer_with_last_byte(1), signer_with_last_byte(2)];
        let pool = SignerPool::new(signers, vec![10, 20], 5).expect("pool");
        assert_eq!(pool.lane(0).expect("lane 0").starting_nonce(), 10);
        assert_eq!(pool.lane(1).expect("lane 1").starting_nonce(), 20);
    }
}
