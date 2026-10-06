//! HUP-S6.5 / federation F-5: an optional faucet-wide drip cap.
//!
//! The per-address (24 h) and per-IP (1 h) cooldowns in `cooldowns.rs` bound what one caller can
//! take. They do not bound the faucet as a whole: many fresh addresses behind many IPs can still
//! drain the hot wallet. `FAUCET_MAX_DRIPS_PER_HOUR` adds a sliding one-hour window over every
//! successful (or in-flight) drip.
//!
//! **Off unless the operator sets it.** Unset or empty means no global cap, which is exactly the
//! behaviour before this change. The value suggested in `.env.example` is a conservative
//! placeholder pending owner sign-off (faucet ADR O-1).
//!
//! A slot is taken atomically before the send (like the cooldown reservation) and given back if
//! the drip fails, so N concurrent requests can never exceed the cap.

use std::collections::VecDeque;
use std::sync::Mutex;

/// The window the cap counts over.
pub const WINDOW_SECS: u64 = 3600;
/// Largest cap accepted from the environment (a typo guard, not a policy).
pub const MAX_CAP: u32 = 100_000;

/// Sliding-window drip counter.
pub struct GlobalCap {
    max: u32,
    window_secs: u64,
    taken: Mutex<VecDeque<u64>>,
}

impl GlobalCap {
    /// A cap of `max` drips per `window_secs`.
    pub fn new(max: u32, window_secs: u64) -> Self {
        GlobalCap {
            max,
            window_secs,
            taken: Mutex::new(VecDeque::new()),
        }
    }

    /// Parse `FAUCET_MAX_DRIPS_PER_HOUR`. Unset or blank: `Ok(None)` (no cap). A value that is not
    /// a whole number from 1 to [`MAX_CAP`] is a startup error, never silently ignored.
    pub fn from_env(raw: Option<&str>) -> Result<Option<GlobalCap>, String> {
        let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        let max: u32 = s
            .parse()
            .map_err(|_| format!("FAUCET_MAX_DRIPS_PER_HOUR must be a whole number, got {s:?}"))?;
        if max == 0 || max > MAX_CAP {
            return Err(format!(
                "FAUCET_MAX_DRIPS_PER_HOUR must be 1 to {MAX_CAP}, got {max}"
            ));
        }
        Ok(Some(GlobalCap::new(max, WINDOW_SECS)))
    }

    /// The configured cap.
    pub fn max(&self) -> u32 {
        self.max
    }

    fn prune(q: &mut VecDeque<u64>, now: u64, window: u64) {
        while let Some(&front) = q.front() {
            if now.saturating_sub(front) >= window {
                q.pop_front();
            } else {
                break;
            }
        }
    }

    /// Take one slot at `now`. `Err(retry_after_secs)` when the window is full.
    pub fn try_take(&self, now: u64) -> Result<(), u64> {
        let mut q = self.taken.lock().unwrap_or_else(|e| e.into_inner());
        Self::prune(&mut q, now, self.window_secs);
        if q.len() >= self.max as usize {
            let oldest = q.front().copied().unwrap_or(now);
            let retry = self
                .window_secs
                .saturating_sub(now.saturating_sub(oldest))
                .max(1);
            return Err(retry);
        }
        q.push_back(now);
        Ok(())
    }

    /// Give back a slot taken at `at` (the drip failed before it reached the chain).
    pub fn give_back(&self, at: u64) {
        let mut q = self.taken.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = q.iter().rposition(|&t| t == at) {
            q.remove(i);
        }
    }

    /// Drips counted in the current window (for `/status`).
    pub fn in_window(&self, now: u64) -> usize {
        let mut q = self.taken.lock().unwrap_or_else(|e| e.into_inner());
        Self::prune(&mut q, now, self.window_secs);
        q.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn unset_or_blank_means_no_cap() {
        assert!(GlobalCap::from_env(None).expect("ok").is_none());
        assert!(GlobalCap::from_env(Some("  ")).expect("ok").is_none());
    }

    #[test]
    fn bad_values_are_startup_errors() {
        for bad in ["0", "-1", "ten", "1.5", "100001"] {
            assert!(
                GlobalCap::from_env(Some(bad)).is_err(),
                "{bad} must be rejected"
            );
        }
        let cap = GlobalCap::from_env(Some(" 60 "))
            .expect("ok")
            .expect("some");
        assert_eq!(cap.max(), 60);
    }

    #[test]
    fn cap_blocks_after_max_and_reopens_after_the_window() {
        let cap = GlobalCap::new(2, 3600);
        cap.try_take(1_000).expect("first");
        cap.try_take(1_100).expect("second");
        let retry = cap.try_take(1_200).expect_err("third blocked");
        assert_eq!(retry, 3600 - 200, "retry counts from the oldest slot");
        assert_eq!(cap.in_window(1_200), 2);
        // The oldest slot ages out at 1_000 + 3600.
        cap.try_take(4_600).expect("window reopened");
        assert_eq!(cap.in_window(4_600), 2);
    }

    #[test]
    fn give_back_returns_exactly_one_slot() {
        let cap = GlobalCap::new(1, 3600);
        cap.try_take(10).expect("take");
        cap.try_take(11).expect_err("full");
        cap.give_back(10);
        cap.try_take(12).expect("slot returned");
        // Giving back a slot that was never taken changes nothing.
        cap.give_back(99);
        cap.try_take(13).expect_err("still full");
    }

    #[test]
    fn concurrent_takes_never_exceed_the_cap() {
        let cap = Arc::new(GlobalCap::new(3, 3600));
        let handles: Vec<_> = (0..24)
            .map(|_| {
                let cap = cap.clone();
                std::thread::spawn(move || cap.try_take(500).is_ok())
            })
            .collect();
        let wins = handles
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .filter(|ok| *ok)
            .count();
        assert_eq!(wins, 3);
    }
}
