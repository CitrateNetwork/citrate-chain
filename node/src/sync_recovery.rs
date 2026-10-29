//! Sync recovery helpers that sit beside the fork-point search (`sync_rejoin`):
//!
//! * [`ParentWalk`]: missing-parent recovery that keeps walking back by hash.
//!   SYNC-S3 asks a gossiping peer for ONE missing parent; that answer's lowest
//!   block can defer on its own parent, and nothing asked further back. The walk
//!   asks the answering peer for the lowest deferred block's missing parent, one
//!   height per answer, downwards only, within [`MAX_PARENT_WALK_STEPS`] per
//!   orphan episode (an episode ends when the orphan buffer drains).
//! * [`answer_anchor_was_stale`]: an EMPTY answer is never a stale question. On
//!   a sealing node the tip moves between request and answer, and scoring "the
//!   peer has nothing for my anchor" as `Redundant` hid that signal.
//! * [`initial_sync_complete`]: the producer's one-time initial-sync condition.
//!
//! Nothing here decides validity or fork choice.

// PANIC-S1 G2: sync path; panic-free outside tests.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::string_slice
    )
)]

use std::time::Duration;

use citrate_consensus::types::{Block, Hash};
use citrate_storage::StorageManager;

/// Most missing-parent requests issued for one orphan episode. Each recovers
/// one height; anything deeper is the fork-point search's job (`sync_rejoin`).
pub const MAX_PARENT_WALK_STEPS: u32 = 64;

/// One walk step comes back to a spent peer budget per this interval.
pub const WALK_REFILL_EVERY: std::time::Duration = std::time::Duration::from_secs(2);

/// A producer with no connected peer for this long after start treats its
/// initial sync as complete (a solo or bootstrap node must still produce).
pub const INITIAL_SYNC_SOLO_GRACE: Duration = Duration::from_secs(30);

/// Upper bound on the initial-sync wait. Past it the producer relies on the
/// network-height gate alone, so a peer that advertises a head it never serves
/// cannot keep a producer idle for the life of the process.
pub const INITIAL_SYNC_MAX_WAIT: Duration = Duration::from_secs(600);

/// How far network evidence may lead the applied tip and still count as caught
/// up for the initial-sync condition. Matches the producer refuse band.
pub const INITIAL_SYNC_LEAD: u64 = crate::producer::CATCHUP_REFUSE_GAP;

/// Missing-parent walk state (one per node, owned by the receive loop).
#[derive(Debug, Default)]
pub struct ParentWalk {
    steps: u32,
    last_height: Option<u64>,
    /// `last_height` before the most recent step, so an unsent request can be undone.
    prev_height: Option<u64>,
}

impl ParentWalk {
    pub fn new() -> Self {
        Self::default()
    }

    /// After an answer: `lowest_deferred` is `(height, missing parent)` of the
    /// lowest block of the answer still deferred, `orphans_remaining` whether the
    /// orphan buffer still holds anything. Returns the parent to ask the
    /// answering peer for, with the height bound recorded for scoring.
    pub fn next(
        &mut self,
        lowest_deferred: Option<(u64, Hash)>,
        orphans_remaining: bool,
    ) -> Option<(Hash, u64)> {
        if !orphans_remaining {
            self.steps = 0;
            self.last_height = None;
        }
        let (height, parent) = lowest_deferred?;
        let parent_height = height.saturating_sub(1);
        let lower = self.last_height.is_none_or(|last| parent_height < last);
        if !lower || self.steps >= MAX_PARENT_WALK_STEPS || parent == Hash::new([0u8; 32]) {
            return None;
        }
        self.steps = self.steps.saturating_add(1);
        self.prev_height = self.last_height;
        self.last_height = Some(parent_height);
        Some((parent, parent_height))
    }

    /// The request for the last step was not sent (already pending, or the in-flight
    /// cap): give the step back so the same parent is asked for on a later answer.
    pub fn unsent(&mut self) {
        self.steps = self.steps.saturating_sub(1);
        self.last_height = self.prev_height;
    }
}

/// Missing-parent walks, one per answering peer (see the fix notes in the
/// module docs once it lands). For now a single shared walk, as before.
#[derive(Debug, Default)]
pub struct ParentWalks {
    shared: ParentWalk,
}

impl ParentWalks {
    pub fn new() -> Self {
        Self::default()
    }

    /// After `peer`'s answer: the parent to ask `peer` for next, if any.
    /// `progressed`: the answer admitted a new block; `applied`: the applied
    /// height; `now`: the time of the answer.
    pub fn next(
        &mut self,
        peer: &str,
        lowest_deferred: Option<(u64, Hash)>,
        orphans_remaining: bool,
        progressed: bool,
        applied: u64,
        now: std::time::Instant,
    ) -> Option<(Hash, u64)> {
        let _ = (peer, progressed, applied, now);
        self.shared.next(lowest_deferred, orphans_remaining)
    }

    /// The request for `peer`'s last step was not sent.
    pub fn unsent(&mut self, peer: &str) {
        let _ = peer;
        self.shared.unsent();
    }
}

/// The parent of `block` this node does not hold: the selected parent first,
/// then merge parents. `None` when it holds them all.
pub fn missing_parent(storage: &StorageManager, block: &Block) -> Option<Hash> {
    std::iter::once(block.header.selected_parent_hash)
        .chain(block.header.merge_parent_hashes.iter().copied())
        .find(|p| !storage.blocks.has_block(p).unwrap_or(false))
}

/// `(height, missing parent)` of the lowest of `deferred`.
pub fn lowest_deferred(storage: &StorageManager, deferred: &[&Block]) -> Option<(u64, Hash)> {
    let lowest = deferred.iter().min_by_key(|b| b.header.height)?;
    missing_parent(storage, lowest).map(|p| (lowest.header.height, p))
}

/// Was an answer's lack of new blocks caused by our own tip moving past the
/// anchor (a stale question) rather than by the peer? Only a NON-EMPTY answer
/// can be stale.
pub fn answer_anchor_was_stale(anchor_height: u64, applied_now: u64, served: usize) -> bool {
    served > 0 && anchor_height < applied_now
}

/// The producer's one-time initial-sync condition, evaluated on every sync tick
/// until it first holds.
pub fn initial_sync_complete(
    applied: u64,
    target: u64,
    connected_peers: usize,
    since_start: Duration,
) -> bool {
    if since_start >= INITIAL_SYNC_MAX_WAIT {
        return true;
    }
    if connected_peers == 0 {
        return since_start >= INITIAL_SYNC_SOLO_GRACE;
    }
    applied.saturating_add(INITIAL_SYNC_LEAD) >= target
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Hash {
        Hash::new([b; 32])
    }

    #[test]
    fn empty_answer_is_never_stale_even_when_our_tip_moved() {
        assert!(!answer_anchor_was_stale(49, 50, 0));
        assert!(answer_anchor_was_stale(49, 50, 3));
        assert!(!answer_anchor_was_stale(50, 50, 3));
    }

    #[test]
    fn initial_sync_condition() {
        let s = Duration::from_secs(1);
        assert!(!initial_sync_complete(39, 46, 3, s));
        assert!(initial_sync_complete(43, 46, 3, s));
        assert!(!initial_sync_complete(0, 0, 0, s));
        assert!(initial_sync_complete(0, 0, 0, INITIAL_SYNC_SOLO_GRACE));
        assert!(initial_sync_complete(
            39,
            1_000_000,
            3,
            INITIAL_SYNC_MAX_WAIT
        ));
    }

    #[test]
    fn walk_goes_down_only_within_budget_and_resets_when_orphans_drain() {
        let mut w = ParentWalk::new();
        assert_eq!(w.next(Some((100, h(1))), true), Some((h(1), 99)));
        // Same orphan again: no repeat request.
        assert_eq!(w.next(Some((100, h(1))), true), None);
        let mut steps = 1u32;
        for d in 1..200u64 {
            if w.next(Some((100 - d.min(99), h(2))), true).is_some() {
                steps += 1;
            }
        }
        assert_eq!(steps, MAX_PARENT_WALK_STEPS, "budget bounds the walk");
        // An empty answer while orphans remain does not refill the budget.
        assert_eq!(w.next(None, true), None);
        assert_eq!(w.next(Some((1, h(4))), true), None);
        // Orphans drained: a new episode gets a fresh budget.
        assert_eq!(w.next(None, false), None);
        assert_eq!(w.next(Some((500, h(3))), true), Some((h(3), 499)));
    }

    #[test]
    fn an_unsent_step_is_given_back() {
        let mut w = ParentWalk::new();
        assert_eq!(w.next(Some((100, h(1))), true), Some((h(1), 99)));
        w.unsent();
        assert_eq!(w.next(Some((100, h(1))), true), Some((h(1), 99)));
        for _ in 0..(MAX_PARENT_WALK_STEPS * 2) {
            w.unsent();
            assert!(w.next(Some((100, h(1))), true).is_some());
        }
    }

    /// (c) Each answering peer has its own walk budget: after the walk against
    /// one peer has spent everything, a missing parent from another peer is
    /// still asked for. And a peer's budget comes back: with time, and at once
    /// when its answers admit blocks again.
    #[test]
    fn walk_budget_is_per_peer_and_refills() {
        let t0 = std::time::Instant::now();
        let mut w = ParentWalks::new();
        let mut steps = 0u32;
        for d in 0..1_000u64 {
            if w.next("a", Some((10_000 - d, h(1))), true, false, 10_000, t0)
                .is_some()
            {
                steps += 1;
            }
        }
        assert!(steps > 0, "the walk against peer a starts");
        assert_eq!(
            w.next("a", Some((5_000, h(1))), true, false, 10_000, t0),
            None,
            "peer a's budget is spent"
        );
        assert_eq!(
            w.next("b", Some((10_000, h(2))), true, false, 10_000, t0),
            Some((h(2), 9_999)),
            "another peer's missing parent is still asked for"
        );
        // Progress from peer a refunds its budget.
        assert!(
            w.next("a", Some((9_990, h(3))), true, true, 10_000, t0)
                .is_some(),
            "an answer that admitted blocks refills the peer's budget"
        );
        // Time refills it too.
        let mut w = ParentWalks::new();
        for d in 0..1_000u64 {
            let _ = w.next("a", Some((10_000 - d, h(1))), true, false, 10_000, t0);
        }
        let later = t0 + WALK_REFILL_EVERY * 4;
        assert!(
            w.next("a", Some((10_000, h(4))), true, false, 10_000, later)
                .is_some(),
            "a spent budget refills with time"
        );
    }

    /// Tripwire: the receive loop, sync tick and producer stay wired to these.
    #[test]
    fn main_loop_stays_wired() {
        let main = include_str!("main.rs");
        for needle in [
            "sync_recovery::answer_anchor_was_stale(",
            "sync_recovery::lowest_deferred(",
            "parent_walk.next(",
            "parent_walk.unsent()",
            "attested_for_rx.observe_deferred(&block)",
            "with_initial_sync_gate(initial_sync_done.clone())",
            "sync_recovery::initial_sync_complete(",
            // Both give-up sites: the sync tick (no answer) and the receive loop
            // (after the serve credit, which would otherwise clear the count).
            "sync_peers_for_loop.lock().await.record_give_up(&pid.0)",
            "sel.record_give_up(&pid.0)",
        ] {
            assert!(
                main.contains(needle),
                "main.rs no longer contains `{needle}`"
            );
        }
        // The receive-loop give-up must follow the serve credit.
        let serve = main
            .find("let quality = sel.record_serve(")
            .expect("serve credit");
        let give_up = main.find("sel.record_give_up(&pid.0)").expect("give-up");
        assert!(
            give_up > serve,
            "give-up must be applied after record_serve"
        );
    }
}
