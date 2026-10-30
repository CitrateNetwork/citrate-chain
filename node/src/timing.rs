//! Timers for the node's consensus-timing loops (citrate-chain#310).
//!
//! `tokio::time::interval` defaults to `MissedTickBehavior::Burst`: when the
//! loop body overruns (the producer waiting on the advance lock during a long
//! catch-up, a drain that takes a minute), every tick it missed fires back to
//! back as soon as the loop returns to `tick()`. For block production that
//! sealed ~1,950 empty blocks at ~4/s after a catch-up instead of holding the
//! configured block time. The loops below must not do that, so they build
//! their timers here instead of calling `interval` directly.

use tokio::time::{interval, interval_at, Duration, Interval, MissedTickBehavior};

/// Block-production timer: one tick per `target_block_time_secs`, on the
/// wall-clock slot grid (multiples of the block time since the UNIX epoch),
/// and after a delay it resumes on the next slot boundary without replaying
/// the ticks it missed (`Skip`). This is the timer `BlockProducer::start` runs
/// on.
///
/// Why the wall clock: every producer seals once per slot. A timer anchored at
/// process start gives each producer its own phase within the slot, fixed for
/// its whole uptime. A producer whose phase falls just after another's seal,
/// inside the propagation delay, then always builds a sibling of a block it
/// has not yet received, while producers nearer the first one extend that
/// block. Its blocks never get a child, are only ever merged, and earn
/// nothing. Anchoring every producer to the same NTP-synced grid makes them
/// all build on the previous slot's blocks and compete on equal terms.
pub(crate) fn production_interval(target_block_time_secs: u64) -> Interval {
    production_interval_at(target_block_time_secs, wall_clock_since_epoch())
}

/// [`production_interval`] for a given wall-clock reading (time since the
/// UNIX epoch), so tests can place a producer anywhere in the slot.
///
/// The interval runs on tokio's monotonic clock from the first aligned tick.
/// On Linux NTP slews the monotonic clock along with the wall clock, so the
/// two stay together; only a wall-clock step (which needs a restart to pick
/// up) would move the grid.
pub(crate) fn production_interval_at(target_block_time_secs: u64, wall_now: Duration) -> Interval {
    let period = Duration::from_secs(target_block_time_secs);
    let now = tokio::time::Instant::now();
    let first = now
        .checked_add(delay_to_next_slot(wall_now, period))
        .unwrap_or(now);
    let mut timer = interval_at(first, period);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    timer
}

/// Time until the next multiple of `period` on the wall clock: zero when
/// `wall_now` is already on a boundary, and zero for a zero period.
pub(crate) fn delay_to_next_slot(wall_now: Duration, period: Duration) -> Duration {
    let period_ns = period.as_nanos();
    let Some(into_slot) = wall_now.as_nanos().checked_rem(period_ns) else {
        return Duration::ZERO; // zero period
    };
    if into_slot == 0 {
        return Duration::ZERO;
    }
    // 0 < remaining < period_ns, so it fits back into a Duration.
    let remaining = period_ns.saturating_sub(into_slot);
    let secs = remaining.checked_div(1_000_000_000).unwrap_or(0);
    let nanos = remaining.checked_rem(1_000_000_000).unwrap_or(0);
    Duration::new(
        u64::try_from(secs).unwrap_or(u64::MAX),
        u32::try_from(nanos).unwrap_or(0),
    )
}

fn wall_clock_since_epoch() -> Duration {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
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

    /// A wall-clock reading that sits exactly on a 2 s slot boundary.
    const ON_SLOT: Duration = Duration::from_secs(1_761_652_800);

    /// Slot-start phases (seconds past the even second) the seven r1006
    /// producers ran at on 2026-10-28, each fixed by when its process started.
    const FLEET_PHASES_MS: [u64; 7] = [1_617, 1_227, 292, 433, 1_059, 1_341, 261];

    /// Producers started at different instants must still tick at the same
    /// wall-clock moment. With the timer anchored at process start, each kept
    /// its own phase for its whole uptime, so one producer always sealed a
    /// moment after another and built a sibling of a block it had not yet
    /// received; that sibling never got a child and earned nothing.
    #[tokio::test(start_paused = true)]
    async fn producers_started_at_different_instants_tick_together() {
        let mut ticks = Vec::new();
        for phase_ms in FLEET_PHASES_MS {
            let wall_now = ON_SLOT + Duration::from_millis(phase_ms);
            let started = Instant::now();
            let mut timer = production_interval_at(2, wall_now);
            timer.tick().await;
            let first_tick_wall = wall_now + started.elapsed();
            assert_eq!(
                first_tick_wall.as_millis() % 2_000,
                0,
                "producer started {phase_ms} ms into the slot ticked off the slot boundary"
            );
            ticks.push(first_tick_wall);
        }
        assert!(
            ticks.iter().all(|t| *t == ON_SLOT + Duration::from_secs(2)),
            "first ticks differ across producers: {ticks:?}"
        );
    }

    /// After the first aligned tick the timer stays on the wall-clock grid,
    /// including after an overrun (one late tick, then back on a boundary).
    #[tokio::test(start_paused = true)]
    async fn aligned_production_interval_stays_on_the_wall_clock_grid() {
        let wall_now = ON_SLOT + Duration::from_millis(1_227);
        let started = Instant::now();
        let mut timer = production_interval_at(2, wall_now);
        let wall = |s: Instant| wall_now + s.elapsed();
        for _ in 0..3 {
            timer.tick().await;
            assert_eq!(wall(started).as_millis() % 2_000, 0);
        }
        advance(Duration::from_millis(3_300)).await;
        assert_eq!(ready_ticks(&mut timer).await, 1);
        timer.tick().await;
        assert_eq!(
            wall(started).as_millis() % 2_000,
            0,
            "left the grid after an overrun"
        );
    }

    #[test]
    fn delay_to_next_slot_edges() {
        let two = Duration::from_secs(2);
        assert_eq!(delay_to_next_slot(ON_SLOT, two), Duration::ZERO);
        assert_eq!(
            delay_to_next_slot(ON_SLOT + Duration::from_millis(1_227), two),
            Duration::from_millis(773)
        );
        assert_eq!(
            delay_to_next_slot(ON_SLOT + Duration::from_nanos(1), two),
            two - Duration::from_nanos(1)
        );
        assert_eq!(
            delay_to_next_slot(ON_SLOT - Duration::from_nanos(1), two),
            Duration::from_nanos(1)
        );
        // Degenerate inputs never panic.
        assert_eq!(delay_to_next_slot(ON_SLOT, Duration::ZERO), Duration::ZERO);
        assert_eq!(
            delay_to_next_slot(Duration::MAX, two),
            delay_to_next_slot(Duration::MAX, two)
        );
        assert!(delay_to_next_slot(Duration::MAX, two) < two);
    }

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
        let mut timer = production_interval_at(BLOCK_TIME, ON_SLOT);
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
        let mut timer = production_interval_at(2, ON_SLOT);
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
