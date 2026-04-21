//! State-version primitives.
//!
//! - [`StateVersion`] is the monotonic commit counter. In the real executor
//!   it's an `AtomicU64` shared across workers, incremented by exactly one on
//!   each successful `TryCommit`.
//! - [`ReadVersion`] is the value a worker pinned at entry. Compared against
//!   per-account versions to detect read-set invalidation.
//!
//! Both correspond to the TLA+ variables `globalVersion` and
//! `workerReadVersion` respectively. The `ReadVersionMonotonic` temporal
//! property proven on the spec says: for every worker, the sequence of pinned
//! versions over time is non-decreasing. In Rust, this holds by construction
//! — every re-pin reads `StateVersion::load`, which itself is monotonic.

use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic commit counter.
///
/// Incremented by exactly one on every successful `TryCommit` or
/// `FallbackToSerial`. Workers read this value at entry to pin their
/// snapshot, and use CAS against it at commit time to detect concurrent
/// commits.
///
/// # Invariants (from TLA+ `ExecutorMVCC.tla`)
///
/// - `AccountVersionBound` — no account version exceeds this value
/// - `GlobalVersionTracksCommits` — `version == len(commitOrder)` always
/// - `ReadVersionNotAhead` — no worker pins a future version
#[derive(Debug)]
pub struct StateVersion {
    inner: AtomicU64,
}

impl StateVersion {
    /// Construct a fresh version counter at zero (genesis).
    pub fn new() -> Self {
        Self { inner: AtomicU64::new(0) }
    }

    /// Read the current global version. Acquire ordering so that subsequent
    /// reads of per-account state see the state committed at this version.
    pub fn load(&self) -> ReadVersion {
        ReadVersion(self.inner.load(Ordering::Acquire))
    }

    /// Attempt to advance the version with a compare-and-swap.
    ///
    /// Returns `Ok(new_version)` if the CAS succeeded (we were the one who
    /// bumped the counter from `expected` to `expected + 1`). Returns
    /// `Err(current_version)` if another worker beat us — callers must
    /// abort-and-retry.
    ///
    /// Release ordering so workers reading this version after a successful
    /// CAS see the state mutations we made.
    ///
    /// Maps to the CAS primitive at the heart of TLA+ `TryCommit`.
    pub fn try_advance(&self, expected: ReadVersion) -> Result<ReadVersion, ReadVersion> {
        match self.inner.compare_exchange(
            expected.0,
            expected.0 + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => Ok(ReadVersion(expected.0 + 1)),
            Err(observed) => Err(ReadVersion(observed)),
        }
    }

    /// Unconditional advance (for `FallbackToSerial`, which holds an
    /// exclusive lock externally and doesn't need CAS).
    ///
    /// Uses `fetch_add` so the operation is atomic even if some CAS races
    /// ran concurrently before we took the fallback lock.
    pub fn advance_unconditional(&self) -> ReadVersion {
        ReadVersion(self.inner.fetch_add(1, Ordering::AcqRel) + 1)
    }
}

impl Default for StateVersion {
    fn default() -> Self {
        Self::new()
    }
}

/// A read version pinned by a worker at entry.
///
/// Used as the basis for read-set validity checks: any account whose
/// version exceeds this value has been modified since the worker pinned,
/// and invalidates the read set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReadVersion(u64);

impl ReadVersion {
    /// Construct a read version from a raw u64. Intended for tests and
    /// for restoring pinned versions from persistent storage.
    pub fn from_raw(v: u64) -> Self {
        Self(v)
    }

    /// Inner numeric value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for ReadVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn new_version_starts_at_zero() {
        let v = StateVersion::new();
        assert_eq!(v.load(), ReadVersion(0));
    }

    #[test]
    fn try_advance_from_zero_succeeds() {
        let v = StateVersion::new();
        let pinned = v.load();
        let new_version = v.try_advance(pinned).expect("CAS should succeed");
        assert_eq!(new_version, ReadVersion(1));
        assert_eq!(v.load(), ReadVersion(1));
    }

    #[test]
    fn try_advance_from_stale_pin_fails() {
        let v = StateVersion::new();
        let stale_pin = v.load();
        // Someone else commits first.
        v.try_advance(stale_pin).expect("first CAS succeeds");
        // Our CAS with the stale pin must fail, reporting current version.
        let result = v.try_advance(stale_pin);
        assert!(result.is_err(), "stale CAS must fail");
        assert_eq!(result.unwrap_err(), ReadVersion(1));
    }

    #[test]
    fn advance_unconditional_always_bumps() {
        let v = StateVersion::new();
        let v1 = v.advance_unconditional();
        let v2 = v.advance_unconditional();
        let v3 = v.advance_unconditional();
        assert_eq!(v1, ReadVersion(1));
        assert_eq!(v2, ReadVersion(2));
        assert_eq!(v3, ReadVersion(3));
    }

    #[test]
    fn concurrent_cas_exactly_one_wins() {
        // Spawn N threads all attempting CAS from the same pinned version;
        // exactly one must succeed and the rest must fail observing the new
        // value. Models the "race to commit" scenario that TLA+ explored.
        let v = Arc::new(StateVersion::new());
        let pin = v.load();
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let v = Arc::clone(&v);
                thread::spawn(move || v.try_advance(pin))
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        let err_count = results.iter().filter(|r| r.is_err()).count();

        assert_eq!(ok_count, 1, "exactly one CAS wins");
        assert_eq!(err_count, 15);
        assert_eq!(v.load(), ReadVersion(1));
    }

    #[test]
    fn read_version_ordering() {
        assert!(ReadVersion(0) < ReadVersion(1));
        assert!(ReadVersion(1) < ReadVersion(2));
        assert_eq!(ReadVersion(5), ReadVersion(5));
    }

    #[test]
    fn read_version_display() {
        let v = ReadVersion(42);
        assert_eq!(format!("{}", v), "v42");
    }

    #[test]
    fn from_raw_round_trips() {
        let v = ReadVersion::from_raw(100);
        assert_eq!(v.as_u64(), 100);
    }
}
