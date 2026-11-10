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

/// How far before a slot boundary (by the wall clock) a production tick may
/// fire and still count as that slot's. The tick is scheduled on tokio's
/// monotonic clock from a wall-clock reading taken when the timer was built,
/// so the two can disagree by a few milliseconds; without this allowance a
/// tick a hair early would stamp the previous slot, which the selected parent
/// already holds, and the round would be skipped.
pub(crate) const SLOT_TICK_EARLY_ALLOWANCE_MS: u64 = 250;

const _: () = assert!(
    SLOT_TICK_EARLY_ALLOWANCE_MS < citrate_consensus::slots::SLOT_DURATION_SECS * 1_000 / 2
);

/// The production period: `target_block_time_secs` rounded UP to a whole
/// number of slots, and at least one slot (r1007 G9: one block per proposer
/// per slot, sealed at a slot boundary).
pub(crate) fn production_period_secs(target_block_time_secs: u64) -> u64 {
    let slot = citrate_consensus::slots::SLOT_DURATION_SECS;
    target_block_time_secs
        .div_ceil(slot)
        .max(1)
        .saturating_mul(slot)
}

/// Block-production timer: one tick per production period
/// ([`production_period_secs`]), on the wall-clock slot grid anchored at the
/// genesis timestamp `slot_origin_secs` (ticks at `origin + k * period`), and
/// after a delay it resumes on the next grid boundary without replaying the
/// ticks it missed (`Skip`). This is the timer `BlockProducer::start` runs on.
///
/// Why the wall clock: every producer seals once per slot. A timer anchored at
/// process start gives each producer its own phase within the slot, fixed for
/// its whole uptime. A producer whose phase falls just after another's seal,
/// inside the propagation delay, then always builds a sibling of a block it
/// has not yet received, while producers nearer the first one extend that
/// block. Its blocks never get a child, are only ever merged, and earn
/// nothing. Anchoring every producer to the same NTP-synced grid makes them
/// all build on the previous slot's blocks and compete on equal terms. And
/// under G9 a block's slot is a function of its timestamp, so a round that
/// starts at the slot boundary stamps the slot it was scheduled for.
pub(crate) fn production_interval(target_block_time_secs: u64, slot_origin_secs: u64) -> Interval {
    production_interval_at(
        target_block_time_secs,
        slot_origin_secs,
        wall_clock_since_epoch(),
    )
}

/// [`production_interval`] for a given wall-clock reading (time since the
/// UNIX epoch), so tests can place a producer anywhere in the slot.
///
/// The interval runs on tokio's monotonic clock from the first aligned tick.
/// On Linux NTP slews the monotonic clock along with the wall clock, so the
/// two stay together; only a wall-clock step (which needs a restart to pick
/// up) would move the grid.
pub(crate) fn production_interval_at(
    target_block_time_secs: u64,
    slot_origin_secs: u64,
    wall_now: Duration,
) -> Interval {
    let period = Duration::from_secs(production_period_secs(target_block_time_secs));
    let now = tokio::time::Instant::now();
    let first = now
        .checked_add(delay_to_next_boundary(
            wall_now,
            Duration::from_secs(slot_origin_secs),
            period,
        ))
        .unwrap_or(now);
    let mut timer = interval_at(first, period);
    timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    timer
}

/// Time from `wall_now` until the next grid boundary `origin + k * period`
/// (k >= 0): zero when `wall_now` is on a boundary, the time until `origin`
/// when the clock is still before it, and zero for a zero period.
pub(crate) fn delay_to_next_boundary(
    wall_now: Duration,
    origin: Duration,
    period: Duration,
) -> Duration {
    let Some(since_origin) = wall_now.checked_sub(origin) else {
        return origin.saturating_sub(wall_now);
    };
    let period_ns = period.as_nanos();
    let Some(into_slot) = since_origin.as_nanos().checked_rem(period_ns) else {
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
    use citrate_consensus::slots::SLOT_DURATION_SECS;
    use tokio::time::{advance, Instant};

    /// A genesis timestamp (slot origin) that sits on a slot boundary, as the
    /// canonical one does, and one that does not sit on a 2 s boundary.
    const ORIGIN: u64 = 1_767_225_600;
    const ODD_ORIGIN: u64 = 1_767_225_601;

    /// A wall-clock reading exactly on a 2 s grid boundary from ORIGIN.
    const ON_SLOT: Duration = Duration::from_secs(ORIGIN + 3_600);

    /// Slot-start phases (ms past the even second) the seven r1006 producers
    /// ran at on 2026-10-28, each fixed by when its process started.
    const FLEET_PHASES_MS: [u64; 7] = [1_617, 1_227, 292, 433, 1_059, 1_341, 261];

    /// #184: producers started at different instants tick at the same
    /// wall-clock moment, on a slot boundary from genesis. Anchored at process
    /// start, each kept its own phase for its whole uptime.
    #[tokio::test(start_paused = true)]
    async fn producers_tick_together_on_the_genesis_slot_grid() {
        for (origin, block_time) in [
            (ORIGIN, 2u64),
            (ODD_ORIGIN, 2),
            (ORIGIN, 1),
            (ODD_ORIGIN, 5),
        ] {
            let period = production_period_secs(block_time);
            // A grid boundary of this origin, then each producer's phase
            // within one period.
            let base = Duration::from_secs(origin + 1_000 * period);
            let mut ticks = Vec::new();
            for phase_ms in FLEET_PHASES_MS {
                let phase_ms = phase_ms % (period * 1_000);
                let wall_now = base + Duration::from_millis(phase_ms);
                let started = Instant::now();
                let mut timer = production_interval_at(block_time, origin, wall_now);
                timer.tick().await;
                let tick_wall = wall_now + started.elapsed();
                let since = tick_wall - Duration::from_secs(origin);
                assert_eq!(
                    since.as_nanos() % u128::from(period * 1_000_000_000),
                    0,
                    "producer started {phase_ms} ms in ticked off the grid of origin {origin}"
                );
                assert_eq!(
                    since.as_nanos() % u128::from(SLOT_DURATION_SECS * 1_000_000_000),
                    0,
                    "a production tick is always a slot boundary"
                );
                ticks.push(tick_wall);
            }
            assert!(
                ticks.windows(2).all(|w| w[0] == w[1]),
                "first ticks differ across producers: {ticks:?}"
            );
        }
    }

    /// After the first aligned tick the timer stays on the grid, including
    /// after an overrun (one late tick, then back on a boundary).
    #[tokio::test(start_paused = true)]
    async fn aligned_production_interval_stays_on_the_slot_grid() {
        let wall_now = ON_SLOT + Duration::from_millis(1_227);
        let started = Instant::now();
        let mut timer = production_interval_at(2, ORIGIN, wall_now);
        let wall = |s: Instant| wall_now + s.elapsed() - Duration::from_secs(ORIGIN);
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

    /// The period is a whole number of slots, never zero.
    #[test]
    fn production_period_is_whole_slots() {
        for t in [0u64, 1, 2, 3, 5, 7, 60] {
            let p = production_period_secs(t);
            assert!(p >= SLOT_DURATION_SECS && p >= t);
            assert!(p.is_multiple_of(SLOT_DURATION_SECS));
            assert!(p < t.max(1) + SLOT_DURATION_SECS);
        }
    }

    #[test]
    fn delay_to_next_boundary_edges() {
        let two = Duration::from_secs(2);
        let o = Duration::from_secs(ORIGIN);
        assert_eq!(delay_to_next_boundary(ON_SLOT, o, two), Duration::ZERO);
        assert_eq!(
            delay_to_next_boundary(ON_SLOT + Duration::from_millis(1_227), o, two),
            Duration::from_millis(773)
        );
        assert_eq!(
            delay_to_next_boundary(ON_SLOT + Duration::from_nanos(1), o, two),
            two - Duration::from_nanos(1)
        );
        assert_eq!(
            delay_to_next_boundary(ON_SLOT - Duration::from_nanos(1), o, two),
            Duration::from_nanos(1)
        );
        // An origin off the 2 s epoch grid moves the grid with it.
        let odd = Duration::from_secs(ODD_ORIGIN);
        assert_eq!(
            delay_to_next_boundary(ON_SLOT, odd, two),
            Duration::from_secs(1)
        );
        // Before genesis: wait for genesis itself.
        assert_eq!(
            delay_to_next_boundary(o - Duration::from_secs(5), o, two),
            Duration::from_secs(5)
        );
        // Degenerate inputs never panic.
        assert_eq!(
            delay_to_next_boundary(ON_SLOT, o, Duration::ZERO),
            Duration::ZERO
        );
        assert!(delay_to_next_boundary(Duration::MAX, o, two) < two);
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
        let mut timer = production_interval_at(BLOCK_TIME, ORIGIN, ON_SLOT);
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
        let mut timer = production_interval_at(2, ORIGIN, ON_SLOT);
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
