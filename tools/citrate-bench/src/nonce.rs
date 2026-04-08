//! `NonceLane` — per-signer monotonic nonce counter with in-flight cap.
//!
//! The single biggest reason the old benchmark topped out at ~20 TPS
//! against Citrate testnet was single-signer traffic bumping into the
//! mempool's `max_per_sender = 100` ceiling. Multiple signers with
//! independent nonce counters trivially scale past that. `NonceLane`
//! is the per-signer primitive the runner composes into a pool.
//!
//! Design invariants enforced by tests:
//!
//! 1. Starting nonce is honored exactly. First acquired nonce equals
//!    `starting_nonce`, second equals `starting_nonce + 1`, etc.
//! 2. `max_inflight` is never exceeded. `try_acquire` returns None once
//!    the lane is saturated and does not silently allow over-subscription.
//! 3. Dropping a `NoncePermit` frees exactly one inflight slot.
//! 4. Concurrent threads receive unique nonces without duplication.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Debug)]
pub struct NonceLane {
    starting_nonce: u64,
    next_nonce: AtomicU64,
    max_inflight: usize,
    inflight: AtomicUsize,
}

impl NonceLane {
    pub fn new(starting_nonce: u64, max_inflight: usize) -> Arc<Self> {
        assert!(max_inflight > 0, "max_inflight must be > 0");
        Arc::new(Self {
            starting_nonce,
            next_nonce: AtomicU64::new(starting_nonce),
            max_inflight,
            inflight: AtomicUsize::new(0),
        })
    }

    /// Try to reserve the next nonce. Returns `None` if the lane is
    /// already at `max_inflight`.
    pub fn try_acquire(self: &Arc<Self>) -> Option<NoncePermit> {
        // Reserve an inflight slot first. If that succeeds we own exactly
        // one slot; then we can allocate the nonce. If reservation fails
        // we return None without touching the nonce counter.
        let mut current = self.inflight.load(Ordering::Acquire);
        loop {
            if current >= self.max_inflight {
                return None;
            }
            match self.inflight.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        let nonce = self.next_nonce.fetch_add(1, Ordering::AcqRel);
        Some(NoncePermit {
            lane: Arc::clone(self),
            nonce,
        })
    }

    pub fn starting_nonce(&self) -> u64 {
        self.starting_nonce
    }

    pub fn max_inflight(&self) -> usize {
        self.max_inflight
    }

    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Acquire)
    }

    /// Next nonce value without reserving a slot. Useful for status
    /// reporting only; do not use this to sequence transactions.
    pub fn peek_next_nonce(&self) -> u64 {
        self.next_nonce.load(Ordering::Acquire)
    }
}

/// A reservation for a specific nonce on a specific lane. Drop to
/// release the inflight slot.
#[derive(Debug)]
pub struct NoncePermit {
    lane: Arc<NonceLane>,
    pub nonce: u64,
}

impl NoncePermit {
    pub fn lane(&self) -> &Arc<NonceLane> {
        &self.lane
    }
}

impl Drop for NoncePermit {
    fn drop(&mut self) {
        // Release exactly one inflight slot. Underflow here would be a
        // logic bug; we saturate at 0 rather than panicking because a
        // panic in Drop would abort the process.
        let _ = self.lane.inflight.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |n| Some(n.saturating_sub(1)),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starting_nonce_is_honored() {
        let lane = NonceLane::new(42, 10);
        let p1 = lane.try_acquire().expect("first");
        assert_eq!(p1.nonce, 42);
        let p2 = lane.try_acquire().expect("second");
        assert_eq!(p2.nonce, 43);
    }

    #[test]
    fn max_inflight_enforced() {
        let lane = NonceLane::new(0, 3);
        let _p1 = lane.try_acquire().expect("1");
        let _p2 = lane.try_acquire().expect("2");
        let _p3 = lane.try_acquire().expect("3");
        assert!(lane.try_acquire().is_none(), "4th must be rejected");
        assert_eq!(lane.inflight(), 3);
    }

    #[test]
    fn dropping_permit_frees_slot() {
        let lane = NonceLane::new(0, 2);
        let p1 = lane.try_acquire().expect("1");
        let p2 = lane.try_acquire().expect("2");
        assert!(lane.try_acquire().is_none());
        drop(p1);
        assert_eq!(lane.inflight(), 1);
        let _p3 = lane.try_acquire().expect("reused slot");
        drop(p2);
    }

    #[test]
    fn nonces_are_unique_across_threads() {
        let lane = NonceLane::new(100, 1000);
        let mut handles = Vec::new();
        let collected = Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));
        for _ in 0..8 {
            let lane = Arc::clone(&lane);
            let collected = Arc::clone(&collected);
            handles.push(std::thread::spawn(move || {
                let mut local = Vec::new();
                for _ in 0..100 {
                    if let Some(p) = lane.try_acquire() {
                        local.push(p.nonce);
                        // hold the permit long enough to make contention real
                        std::thread::yield_now();
                    }
                }
                collected
                    .lock()
                    .expect("mutex not poisoned")
                    .extend(local);
            }));
        }
        for h in handles {
            h.join().expect("join");
        }
        let mut nonces = collected.lock().expect("mutex not poisoned").clone();
        nonces.sort_unstable();
        nonces.dedup();
        // 8 threads * 100 acquires = 800 unique nonces starting at 100
        assert_eq!(nonces.len(), 800);
        assert_eq!(nonces.first().copied(), Some(100));
        assert_eq!(nonces.last().copied(), Some(899));
    }

    #[test]
    fn peek_does_not_consume() {
        let lane = NonceLane::new(5, 10);
        assert_eq!(lane.peek_next_nonce(), 5);
        assert_eq!(lane.inflight(), 0);
        let _p = lane.try_acquire().expect("acquired");
        assert_eq!(lane.peek_next_nonce(), 6);
        assert_eq!(lane.inflight(), 1);
    }

    #[test]
    #[should_panic(expected = "max_inflight must be > 0")]
    fn zero_max_inflight_panics() {
        let _ = NonceLane::new(0, 0);
    }
}
