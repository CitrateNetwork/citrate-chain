//! A rate limit for "messages were shed" warnings.
//!
//! The inbound queue sheds messages when the node's receive loop is behind
//! (`PeerManager::forward_incoming`). Each shed message used to move only a
//! counter, so a node could lose peers' blocks for minutes with nothing in
//! its journal. [`ShedLog`] says so: the first shed of a quiet period warns at
//! once, later ones are counted and reported by the next warning, at most one
//! warning per interval.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// See the module docs.
#[derive(Debug)]
pub struct ShedLog {
    every: Duration,
    state: Mutex<ShedState>,
    warnings: AtomicU64,
}

#[derive(Debug, Default)]
struct ShedState {
    last_warn: Option<Instant>,
    since_warn: u64,
}

impl ShedLog {
    /// At most one warning per `every`.
    pub fn new(every: Duration) -> Self {
        Self {
            every,
            state: Mutex::new(ShedState::default()),
            warnings: AtomicU64::new(0),
        }
    }

    /// Record one shed message at `now`. `Some(n)` when a warning is due, `n`
    /// being the messages shed since the previous warning, this one included.
    pub fn on_shed(&self, now: Instant) -> Option<u64> {
        let _ = (now, &self.every, &self.state);
        None
    }

    /// Warnings issued so far.
    pub fn warnings(&self) -> u64 {
        self.warnings.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_shed_warns_and_later_ones_are_counted_into_the_next_warning() {
        let log = ShedLog::new(Duration::from_secs(10));
        let t0 = Instant::now();
        assert_eq!(log.on_shed(t0), Some(1), "the first shed warns at once");
        for _ in 0..99 {
            assert_eq!(log.on_shed(t0 + Duration::from_secs(1)), None);
        }
        assert_eq!(
            log.on_shed(t0 + Duration::from_secs(11)),
            Some(100),
            "the next warning reports everything shed since the last one"
        );
        assert_eq!(log.on_shed(t0 + Duration::from_secs(12)), None);
        assert_eq!(log.warnings(), 2);
    }
}
