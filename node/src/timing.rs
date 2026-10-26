//! Timers for the node's consensus-timing loops (citrate-chain#310).
//!
//! `tokio::time::interval` defaults to `MissedTickBehavior::Burst`: when the
//! loop body overruns (the producer waiting on the advance lock during a long
//! catch-up, a drain that takes a minute), every tick it missed fires back to
//! back as soon as the loop returns to `tick()`. For block production that
//! sealed ~1,950 empty blocks at ~4/s after a catch-up instead of holding the
//! configured block time. The loops below must not do that, so they build
//! their timers here instead of calling `interval` directly.

use tokio::time::{interval, Duration, Interval, MissedTickBehavior};

/// Block-production timer: one tick per `target_block_time_secs`, and after a
/// delay it resumes on the next cadence boundary without replaying the ticks
/// it missed (`Skip`). This is the timer `BlockProducer::start` runs on.
pub(crate) fn production_interval(target_block_time_secs: u64) -> Interval {
    cadence_interval(Duration::from_secs(target_block_time_secs))
}

/// A fixed-cadence timer that drops missed ticks (`Skip`): after an overrun
/// the next tick lands on the next multiple of `period` from the start, so a
/// slow pass is followed by at most one immediate pass, never a burst.
pub(crate) fn cadence_interval(period: Duration) -> Interval {
    let mut timer = interval(period);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    timer
}

/// A sampling timer whose ticks are always at least `period` apart (`Delay`):
/// after an overrun the schedule restarts from the moment the late tick was
/// taken. For loops that compare consecutive samples (a stall watchdog), so
/// two samples are never taken back to back over a near-zero window.
pub(crate) fn sampling_interval(period: Duration) -> Interval {
    let mut timer = interval(period);
    timer.set_missed_tick_behavior(MissedTickBehavior::Delay);
    timer
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{advance, Instant};

    /// Ticks that are ready right now, without letting time move.
    async fn ready_ticks(timer: &mut Interval) -> usize {
        let mut n = 0;
        while tokio::time::timeout(Duration::ZERO, timer.tick())
            .await
            .is_ok()
        {
            n += 1;
            assert!(n < 10_000, "timer never stopped firing");
        }
        n
    }

    /// The #310 regression: a producer held for many block times (waiting on
    /// the advance lock during a catch-up) gets ONE immediate tick when it
    /// comes back, then ticks every block time again. Under the old default
    /// (`Burst`) it got one tick per missed block time, all at once.
    #[tokio::test(start_paused = true)]
    async fn delayed_producer_resumes_at_cadence_without_burst() {
        const BLOCK_TIME: u64 = 2;
        let mut timer = production_interval(BLOCK_TIME);
        assert_eq!(timer.missed_tick_behavior(), MissedTickBehavior::Skip);
        assert_eq!(timer.period(), Duration::from_secs(BLOCK_TIME));

        // First tick is immediate, then two normal rounds.
        timer.tick().await;
        let t0 = Instant::now();
        timer.tick().await;
        timer.tick().await;
        assert_eq!(t0.elapsed(), Duration::from_secs(2 * BLOCK_TIME));

        // The producer is stuck for 1,000 block times.
        advance(Duration::from_secs(1_000 * BLOCK_TIME)).await;

        // On return: exactly one round is due, not 1,000.
        assert_eq!(ready_ticks(&mut timer).await, 1, "missed ticks burst");

        // And from there it is back on the configured block time.
        let resumed = Instant::now();
        for round in 1..=5u32 {
            timer.tick().await;
            assert_eq!(
                resumed.elapsed(),
                Duration::from_secs(BLOCK_TIME) * round,
                "round {round} off cadence"
            );
            assert_eq!(
                ready_ticks(&mut timer).await,
                0,
                "extra tick after round {round}"
            );
        }
    }

    /// Control: the tokio default the producer used before #310 does burst,
    /// so the test above would catch a revert to plain `interval`.
    #[tokio::test(start_paused = true)]
    async fn default_interval_bursts_after_a_delay() {
        let mut timer = interval(Duration::from_secs(2));
        timer.tick().await;
        advance(Duration::from_secs(2_000)).await;
        assert!(ready_ticks(&mut timer).await >= 1_000);
    }

    /// A round that overruns by a fraction of the block time still gets
    /// exactly one late tick and then snaps back to the original grid.
    #[tokio::test(start_paused = true)]
    async fn production_interval_stays_on_grid_after_partial_overrun() {
        let start = Instant::now();
        let mut timer = production_interval(2);
        timer.tick().await; // t = 0
        advance(Duration::from_millis(5_500)).await; // round ran 5.5 s
        assert_eq!(ready_ticks(&mut timer).await, 1);
        timer.tick().await;
        assert_eq!(
            start.elapsed(),
            Duration::from_secs(6),
            "next tick on the 2 s grid"
        );
    }

    /// The watchdog timer keeps a full period between samples after a delay.
    #[tokio::test(start_paused = true)]
    async fn sampling_interval_keeps_full_period_between_samples() {
        let mut timer = sampling_interval(Duration::from_secs(30));
        assert_eq!(timer.missed_tick_behavior(), MissedTickBehavior::Delay);
        timer.tick().await;
        advance(Duration::from_secs(300)).await;
        assert_eq!(ready_ticks(&mut timer).await, 1);
        let late = Instant::now();
        timer.tick().await;
        assert_eq!(late.elapsed(), Duration::from_secs(30));
    }

    #[tokio::test(start_paused = true)]
    async fn cadence_interval_skips_missed_ticks() {
        let mut timer = cadence_interval(Duration::from_secs(1));
        assert_eq!(timer.missed_tick_behavior(), MissedTickBehavior::Skip);
        timer.tick().await;
        advance(Duration::from_secs(120)).await;
        assert_eq!(ready_ticks(&mut timer).await, 1);
    }
}
