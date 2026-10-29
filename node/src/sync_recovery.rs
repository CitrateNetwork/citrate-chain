//! Sync recovery helpers that sit beside the fork-point search (`sync_rejoin`):
//!
//! * [`ParentWalks`]: missing-parent recovery that keeps walking back by hash.
//!   A block that defers on a missing parent makes this node ask the peer that
//!   sent it for that parent (`GetBlocks` anchored at the parent's hash, which
//!   serves the parent and everything above it). The answer's lowest block can
//!   defer on its own parent, so the walk asks again, one height per answer,
//!   downwards only, until a held block is reached and the whole branch admits.
//!
//!   The walk is kept PER PEER, and each peer's budget refills:
//!   - an episode (one descent) ends when the peer's answer leaves nothing
//!     deferred, admits a block, the orphan buffer drains, or the walk has been
//!     idle for [`WALK_IDLE_RESET`]; a new episode may descend again even while
//!     older orphans stay buffered;
//!   - a peer's step budget ([`MAX_PARENT_WALK_STEPS`], which covers the whole
//!     reorg window) refills by one step per [`WALK_REFILL_EVERY`], and by one
//!     step per block the peer's answers actually admitted.
//!
//!   Amplification bound: requests sent to one peer are at most its budget plus
//!   one per refill interval plus the blocks it delivered that this node
//!   admitted. Across all peers, at most [`MAX_WALKS_IN_FLIGHT`] walk requests
//!   are outstanding, and a node-wide budget ([`NODE_WALK_BURST`], refilled one
//!   step per [`NODE_WALK_REFILL_EVERY`]) bounds peers that come and go. The
//!   walk never asks for a parent more than [`MAX_WALK_DEPTH`] below the applied
//!   tip: deeper forks are the fork-point search's job.
//!
//!   Stuck parents: a missing parent at the bottom of the orphan buffer that is
//!   deferred again and again ([`REFETCH_AFTER_DEFERRALS`]) is fetched by its
//!   own hash from the peer that first delivered its child, starting a new
//!   episode there, at most once per [`REFETCH_EVERY`].
//!
//!   When recovery for a peer stops short (budget, in-flight cap, window), the
//!   step says so ([`Step::GaveUp`]) with a rate-limited log decision.
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

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use citrate_consensus::types::{Block, Hash};
use citrate_storage::StorageManager;

/// Steps one peer's walk budget holds. Each recovers one height; a full budget
/// covers the whole reorg window ([`MAX_WALK_DEPTH`]) with room for repeats.
pub const MAX_PARENT_WALK_STEPS: u32 = 64;

/// One step comes back to a peer's spent budget per this interval (one 2 s sync
/// tick).
pub const WALK_REFILL_EVERY: Duration = Duration::from_secs(2);

/// A peer's walk with no step for this long starts a new episode (its answer
/// was lost, or the peer went quiet).
pub const WALK_IDLE_RESET: Duration = Duration::from_secs(30);

/// A walk request with no answer for this long no longer counts as in flight.
pub const WALK_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Most walk requests outstanding across all peers. Half the sync manager's
/// download window (`SyncConfig::max_concurrent_downloads` = 16), so recovery
/// never takes the slots the forward sync driver needs.
pub const MAX_WALKS_IN_FLIGHT: usize = 8;

/// Node-wide step budget, shared by every peer (bounds peers that reconnect
/// under new identities to get a fresh per-peer budget).
pub const NODE_WALK_BURST: u32 = 512;

/// One step comes back to the node-wide budget per this interval.
pub const NODE_WALK_REFILL_EVERY: Duration = Duration::from_millis(250);

/// Deepest parent the walk asks for, below the applied tip: the reorg window,
/// the deepest fork point the applied chain can move across without a rebuild
/// (the DAG pruner retains at least this much, see `dag_prune`).
pub const MAX_WALK_DEPTH: u64 = crate::canonical_apply::MAX_REORG_DEPTH;

/// Peers with walk state, at most; the least recently seen is dropped first.
pub const MAX_WALK_PEERS: usize = 256;

/// A stuck parent deferred this many times is fetched by its own hash.
pub const REFETCH_AFTER_DEFERRALS: u32 = 3;

/// The same stuck parent is fetched at most once per this interval.
pub const REFETCH_EVERY: Duration = Duration::from_secs(10);

/// Stuck parents tracked, at most; the least recently deferred is dropped.
pub const MAX_STUCK_PARENTS: usize = 64;

/// Stuck parents fetched per call of [`ParentWalks::refetch_stuck`].
pub const MAX_REFETCH_PER_ROUND: usize = 2;

/// Give-up log lines per [`GIVE_UP_LOG_WINDOW`]; the rest are counted.
pub const GIVE_UP_LOGS_PER_WINDOW: u32 = 8;

/// Window for [`GIVE_UP_LOGS_PER_WINDOW`].
pub const GIVE_UP_LOG_WINDOW: Duration = Duration::from_secs(60);

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

/// Why a walk step was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GiveUp {
    /// This peer's step budget is spent.
    PeerBudget,
    /// The node-wide step budget is spent.
    NodeBudget,
    /// [`MAX_WALKS_IN_FLIGHT`] walk requests are already outstanding.
    InFlightCap,
    /// The parent is more than [`MAX_WALK_DEPTH`] below the applied tip.
    BeyondWindow,
}

/// What to do after a deferral or an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Send this peer `GetBlocks` anchored at `parent` (at `height`). If it is
    /// not sent, call [`ParentWalks::unsent`].
    Ask { parent: Hash, height: u64 },
    /// Nothing to ask (nothing deferred, already asked, or a request to this
    /// peer is outstanding).
    Idle,
    /// Recovery stopped short. `log` is `Some(suppressed_before)` when this
    /// give-up should be logged (once per episode per peer, and at most
    /// [`GIVE_UP_LOGS_PER_WINDOW`] lines per window node-wide).
    GaveUp {
        reason: GiveUp,
        parent: Hash,
        height: u64,
        log: Option<u64>,
    },
}

/// One `Blocks` answer, as the walk sees it.
#[derive(Debug, Clone, Copy)]
pub struct WalkAnswer {
    /// `(height, missing parent)` of the lowest block of THIS answer still
    /// deferred ([`lowest_deferred`]).
    pub lowest_deferred: Option<(u64, Hash)>,
    /// Blocks newly admitted while processing this answer.
    pub admitted: usize,
    /// Whether the orphan buffer still holds anything.
    pub orphans_remaining: bool,
    /// The applied height.
    pub applied: u64,
}

/// A stuck parent to fetch by its own hash, from `peer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refetch {
    pub peer: String,
    pub parent: Hash,
    pub height: u64,
}

/// Missing-parent walk state (one per node, shared by every peer).
#[derive(Debug, Default)]
struct ParentWalk {
    steps: u32,
    last_height: Option<u64>,
    /// `last_height` before the most recent step, so an unsent request can be undone.
    prev_height: Option<u64>,
}

impl ParentWalk {
    fn next(
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

    fn unsent(&mut self) {
        self.steps = self.steps.saturating_sub(1);
        self.last_height = self.prev_height;
    }
}

/// Missing-parent walks (see the module docs). Owned by the receive loop.
#[derive(Debug, Default)]
pub struct ParentWalks {
    walk: ParentWalk,
}

impl ParentWalks {
    pub fn new(_now: Instant) -> Self {
        Self::default()
    }

    /// Walk requests outstanding across all peers.
    pub fn in_flight_now(&self, _now: Instant) -> usize {
        0
    }

    /// A block from `peer` deferred on `missing_parent` (gossip path).
    pub fn begin(
        &mut self,
        _peer: &str,
        missing_parent: Hash,
        parent_height: u64,
        _applied: u64,
        _now: Instant,
    ) -> Step {
        Step::Ask {
            parent: missing_parent,
            height: parent_height,
        }
    }

    /// After `peer`'s `Blocks` answer: the parent to ask `peer` for next.
    pub fn next(&mut self, _peer: &str, answer: WalkAnswer, _now: Instant) -> Step {
        match self
            .walk
            .next(answer.lowest_deferred, answer.orphans_remaining)
        {
            Some((parent, height)) => Step::Ask { parent, height },
            None => Step::Idle,
        }
    }

    /// The request for `peer`'s last step was not sent: give the step back.
    pub fn unsent(&mut self, _peer: &str) {
        self.walk.unsent();
    }

    /// Record the missing parents at the bottom of the orphan buffer.
    pub fn note_stuck(&mut self, _roots: &[(Hash, u64)], _source: &str, _now: Instant) {}

    /// Stuck parents due a fetch by their own hash.
    pub fn refetch_stuck(
        &mut self,
        _held: impl Fn(&Hash) -> bool,
        _applied: u64,
        _now: Instant,
    ) -> (Vec<Refetch>, Vec<(String, Step)>) {
        (Vec::new(), Vec::new())
    }
}

/// The parent of `block` this node does not hold: the selected parent first,
/// then merge parents. `None` when it holds them all.
pub fn missing_parent(storage: &StorageManager, block: &Block) -> Option<Hash> {
    std::iter::once(block.header.selected_parent_hash)
        .chain(block.header.merge_parent_hashes.iter().copied())
        .find(|p| !storage.blocks.has_block(p).unwrap_or(false))
}

/// `(height, missing parent)` of the lowest of `from_answer`, followed down
/// through `orphans` (every block still deferred): when that parent is itself
/// a buffered orphan, the walk continues from the bottom of the buffered chain
/// instead of asking again for blocks this node already holds.
pub fn lowest_deferred(
    storage: &StorageManager,
    from_answer: &[&Block],
    _orphans: &[Block],
) -> Option<(u64, Hash)> {
    let lowest = from_answer.iter().min_by_key(|b| b.header.height)?;
    missing_parent(storage, lowest).map(|p| (lowest.header.height, p))
}

/// Carry out a walk step for `peer`: send an [`Step::Ask`] (giving the step
/// back when it is not sent), log a [`Step::GaveUp`] when its log decision says
/// so. Returns whether a request went on the wire.
pub async fn send_step(
    walks: &mut ParentWalks,
    pm: &citrate_network::PeerManager,
    sync: &citrate_network::SyncManager,
    peer: &str,
    step: Step,
    applied: u64,
) -> bool {
    let short = |h: &Hash| h.as_bytes().get(..8).map(hex::encode).unwrap_or_default();
    match step {
        Step::Idle => false,
        Step::GaveUp {
            reason,
            parent,
            height,
            log,
        } => {
            if let Some(suppressed) = log {
                tracing::info!(
                    "SYNCRECOVERY gave up on missing parent {} @ {} from peer={} ({:?}; \
                     applied={} suppressed_before={})",
                    short(&parent),
                    height,
                    peer.get(..14).unwrap_or(peer),
                    reason,
                    applied,
                    suppressed
                );
            }
            false
        }
        Step::Ask { parent, height } => {
            let sent = match pm.get_peer(&citrate_network::PeerId(peer.to_string())) {
                Some(p) => sync
                    .request_blocks(&p, parent, height)
                    .await
                    .unwrap_or_else(|e| {
                        tracing::debug!(
                            "missing-parent request to {} for {} failed: {}",
                            peer,
                            short(&parent),
                            e
                        );
                        false
                    }),
                None => false,
            };
            // Only a request that went on the wire spends a step.
            if !sent {
                walks.unsent(peer);
            }
            sent
        }
    }
}

/// The missing parents at the bottom of `deferred`, as `(parent, parent
/// height)`: a deferred block's missing parent that is not itself deferred.
pub fn deferred_roots(storage: &StorageManager, deferred: &[Block]) -> Vec<(Hash, u64)> {
    let have: HashSet<Hash> = deferred.iter().map(|b| b.header.block_hash).collect();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for b in deferred {
        if let Some(p) = missing_parent(storage, b) {
            if !have.contains(&p) && seen.insert(p) {
                out.push((p, b.header.height.saturating_sub(1)));
            }
        }
    }
    out
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

    fn hn(n: u64) -> Hash {
        let mut b = [0xA0u8; 32];
        b[..8].copy_from_slice(&n.to_be_bytes());
        Hash::new(b)
    }

    fn ans(lowest: Option<(u64, Hash)>, admitted: usize, applied: u64) -> WalkAnswer {
        WalkAnswer {
            lowest_deferred: lowest,
            admitted,
            orphans_remaining: true,
            applied,
        }
    }

    fn is_ask(s: Step) -> bool {
        matches!(s, Step::Ask { .. })
    }

    /// Walk `peer` down from `top`, one height per answer, until it stops.
    /// `applied` is fixed when given; otherwise it follows the walk (so the
    /// window is never what stops it). Returns the steps taken and the last step.
    fn descend(
        w: &mut ParentWalks,
        peer: &str,
        top: u64,
        applied: Option<u64>,
        t: Instant,
    ) -> (u32, Step) {
        let mut steps = 0u32;
        let mut height = top;
        let mut last = w.begin(peer, hn(height - 1), height - 1, applied.unwrap_or(top), t);
        while let Step::Ask { height: ph, .. } = last {
            steps += 1;
            height = ph;
            if height == 0 {
                break;
            }
            let a = applied.unwrap_or(height + 1);
            last = w.next(peer, ans(Some((height, hn(height - 1))), 0, a), t);
        }
        (steps, last)
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
    fn walk_goes_down_only_and_never_repeats_a_height() {
        let t = Instant::now();
        let mut w = ParentWalks::new(t);
        assert_eq!(
            w.next("a", ans(Some((100, h(1))), 0, 100), t),
            Step::Ask {
                parent: h(1),
                height: 99
            }
        );
        // Same orphan again: no repeat request.
        assert_eq!(w.next("a", ans(Some((100, h(1))), 0, 100), t), Step::Idle);
        // Higher than the walk: already covered.
        assert_eq!(w.next("a", ans(Some((150, h(2))), 0, 150), t), Step::Idle);
        assert!(is_ask(w.next("a", ans(Some((99, h(3))), 0, 100), t)));
        // The zero hash is never asked for.
        let mut w = ParentWalks::new(t);
        assert_eq!(
            w.next("a", ans(Some((5, Hash::new([0; 32]))), 0, 5), t),
            Step::Idle
        );
    }

    /// (a) Exhausting recovery against peer A does not block recovery from
    /// peer B, even while A's orphans stay buffered.
    #[test]
    fn exhausting_one_peer_does_not_block_another() {
        let t = Instant::now();
        let mut w = ParentWalks::new(t);
        // Peer A serves an endless branch that never reaches a held block; the
        // applied tip follows so the window is never what stops it.
        let mut steps_a = 0u32;
        let mut stop = Step::Idle;
        for d in 0..10_000u64 {
            let top = 1_000_000 - d;
            match w.next("a", ans(Some((top, hn(top - 1))), 0, top), t) {
                Step::Ask { .. } => steps_a += 1,
                s => {
                    stop = s;
                    break;
                }
            }
        }
        assert_eq!(steps_a, MAX_PARENT_WALK_STEPS, "A's budget bounds A's walk");
        assert!(matches!(
            stop,
            Step::GaveUp {
                reason: GiveUp::PeerBudget,
                ..
            }
        ));
        // Peer B's foreign tip, ABOVE where A's walk ended: still recovered.
        let (steps_b, _) = descend(&mut w, "b", 2_000_000, Some(2_000_000), t);
        assert!(
            steps_b >= 82,
            "B's walk is independent of A's (took {steps_b} steps)"
        );
    }

    /// (b) A spent budget refills: by one step per interval, and by the blocks
    /// the peer's answers admitted (which also start a new episode, so the walk
    /// descends again while older orphans stay buffered).
    #[test]
    fn budget_refills_after_progress_and_with_time() {
        let t0 = Instant::now();
        let mut w = ParentWalks::new(t0);
        let (spent, last) = descend(&mut w, "a", 1_000_000, None, t0);
        assert_eq!(spent, MAX_PARENT_WALK_STEPS);
        assert!(matches!(
            last,
            Step::GaveUp {
                reason: GiveUp::PeerBudget,
                ..
            }
        ));
        // Progress: an answer that admitted 5 blocks and left a new, higher
        // orphan. The walk asks again, though orphans remain.
        assert!(
            is_ask(w.next("a", ans(Some((2_000_000, h(9))), 5, 2_000_000), t0)),
            "an answer that admitted blocks refills the peer's budget"
        );
        // Time: four intervals later, four more steps.
        let mut w = ParentWalks::new(t0);
        descend(&mut w, "a", 1_000_000, None, t0);
        let later = t0 + WALK_REFILL_EVERY * 4;
        let mut refilled = 0u64;
        while is_ask(w.next(
            "a",
            ans(Some((500 - refilled, hn(499 - refilled))), 0, 500),
            later,
        )) {
            refilled += 1;
        }
        assert_eq!(refilled, 4, "one step back per refill interval");
    }

    /// DGX's numbers (r1006 4v3 partition, restarted mid-partition): the fork
    /// point is 82 below the restart tip, inside the reorg window. The old walk
    /// spent its 64 steps at 4159 -> 4096 and never descended again. A fresh
    /// episode must reach the fork.
    #[test]
    fn a_fork_82_deep_is_reached() {
        let t = Instant::now();
        let mut w = ParentWalks::new(t);
        let tip = 4_160u64;
        let fork = tip - 82;
        let mut height = tip;
        let mut step = w.begin("b", hn(tip - 1), tip - 1, tip, t);
        while let Step::Ask { height: ph, .. } = step {
            height = ph;
            if height == fork {
                break;
            }
            step = w.next("b", ans(Some((height, hn(height - 1))), 0, tip), t);
        }
        assert_eq!(
            height, fork,
            "the walk reaches the fork point (stopped: {step:?})"
        );
    }

    /// A walk never asks for a parent below the reorg window.
    #[test]
    fn walk_never_goes_below_the_reorg_window() {
        let t = Instant::now();
        let mut w = ParentWalks::new(t);
        let applied = 10_000u64;
        let (steps, last) = descend(&mut w, "a", applied, Some(applied), t);
        assert_eq!(u64::from(steps), MAX_WALK_DEPTH);
        assert!(matches!(
            last,
            Step::GaveUp {
                reason: GiveUp::BeyondWindow,
                height,
                ..
            } if height == applied - MAX_WALK_DEPTH - 1
        ));
    }

    #[test]
    fn an_unsent_step_is_given_back() {
        let t = Instant::now();
        let mut w = ParentWalks::new(t);
        let ask = Step::Ask {
            parent: h(1),
            height: 99,
        };
        assert_eq!(w.next("a", ans(Some((100, h(1))), 0, 100), t), ask);
        w.unsent("a");
        assert_eq!(w.next("a", ans(Some((100, h(1))), 0, 100), t), ask);
        for _ in 0..(MAX_PARENT_WALK_STEPS * 2) {
            w.unsent("a");
            assert_eq!(w.next("a", ans(Some((100, h(1))), 0, 100), t), ask);
        }
        assert_eq!(w.in_flight_now(t), 1);
        w.unsent("a");
        assert_eq!(w.in_flight_now(t), 0, "an unsent step is not in flight");
        // An unknown peer's unsent is a no-op.
        w.unsent("nobody");
    }

    /// (d) Amplification: a hostile peer sending endless unknown parents, by
    /// gossip and by unsolicited answers, gets at most its budget plus one step
    /// per refill interval out of this node; many hostile identities together
    /// get at most the node budget plus its refill, and no more than
    /// MAX_WALKS_IN_FLIGHT requests are ever outstanding at once.
    #[test]
    fn amplification_is_bounded_under_a_hostile_peer() {
        let t0 = Instant::now();
        let secs = 120u64;
        // One peer, 100 messages a second, every one carrying a fresh unknown
        // parent (alternating gossip and answers, heights going down).
        let mut w = ParentWalks::new(t0);
        let mut asks = 0u64;
        let mut height = 1_000_000u64;
        for i in 0..(secs * 100) {
            let now = t0 + Duration::from_millis(i * 10);
            height -= 1;
            let s = if i % 2 == 0 {
                w.begin("evil", hn(height), height, height, now)
            } else {
                w.next("evil", ans(Some((height + 1, hn(height))), 0, height), now)
            };
            if is_ask(s) {
                asks += 1;
            }
        }
        let bound =
            u64::from(MAX_PARENT_WALK_STEPS) + secs * 1_000 / WALK_REFILL_EVERY.as_millis() as u64;
        assert!(
            asks <= bound,
            "one hostile peer got {asks} requests (bound {bound})"
        );
        // Many identities, nobody ever answering: the in-flight cap holds.
        let mut w = ParentWalks::new(t0);
        let mut max_in_flight = 0usize;
        let mut asks = 0u64;
        for i in 0..10_000u64 {
            let now = t0 + Duration::from_millis(i);
            let peer = format!("sybil-{i}");
            if is_ask(w.begin(&peer, hn(i + 1), 5_000, 5_000, now)) {
                asks += 1;
            }
            max_in_flight = max_in_flight.max(w.in_flight_now(now));
        }
        assert!(
            max_in_flight <= MAX_WALKS_IN_FLIGHT,
            "in flight {max_in_flight}"
        );
        assert!(
            asks <= 10 * MAX_WALKS_IN_FLIGHT as u64 + 8,
            "sybil asks {asks}"
        );
        // Several identities, each answering at once with an ever-lower
        // unknown parent: together they get no more than the node budget.
        let mut w = ParentWalks::new(t0);
        let mut asks = 0u64;
        for i in 0..20_000u64 {
            let now = t0 + Duration::from_millis(i);
            let peer = format!("sybil-{}", i % 8);
            let top = 1_000_000 - i;
            let s = w.next(&peer, ans(Some((top, hn(top - 1))), 0, top), now);
            if is_ask(s) {
                asks += 1;
            }
        }
        let node_bound =
            u64::from(NODE_WALK_BURST) + 20_000 / NODE_WALK_REFILL_EVERY.as_millis() as u64 + 1;
        assert!(asks <= node_bound, "sybil asks {asks} (bound {node_bound})");
    }

    /// Give-ups are reported once per episode per peer, and node-wide at most
    /// GIVE_UP_LOGS_PER_WINDOW lines per window (the rest counted).
    #[test]
    fn give_up_is_reported_once_per_episode_and_rate_limited() {
        let t = Instant::now();
        let mut w = ParentWalks::new(t);
        let applied = 10_000u64;
        let deep = applied - MAX_WALK_DEPTH - 5;
        let first = w.next("a", ans(Some((deep, hn(deep - 1))), 0, applied), t);
        assert!(matches!(
            first,
            Step::GaveUp {
                reason: GiveUp::BeyondWindow,
                log: Some(0),
                ..
            }
        ));
        let again = w.next("a", ans(Some((deep - 1, hn(deep - 2))), 0, applied), t);
        assert!(
            matches!(again, Step::GaveUp { log: None, .. }),
            "same episode: not logged again"
        );
        let mut logged = 0u32;
        for i in 0..50u64 {
            let peer = format!("p{i}");
            if let Step::GaveUp { log: Some(_), .. } =
                w.next(&peer, ans(Some((deep, hn(deep - 1))), 0, applied), t)
            {
                logged += 1;
            }
        }
        assert_eq!(logged, GIVE_UP_LOGS_PER_WINDOW - 1);
        let next_window = t + GIVE_UP_LOG_WINDOW;
        match w.next(
            "z",
            ans(Some((deep, hn(deep - 1))), 0, applied),
            next_window,
        ) {
            Step::GaveUp {
                log: Some(suppressed),
                ..
            } => assert_eq!(suppressed, 43, "suppressed lines are counted"),
            s => panic!("expected a logged give-up, got {s:?}"),
        }
    }

    /// A parent deferred again and again at the bottom of the orphan buffer is
    /// fetched by its own hash from the peer that delivered its child, even
    /// after that peer's walk moved on; at most once per REFETCH_EVERY.
    #[test]
    fn a_stuck_parent_is_fetched_by_hash() {
        let t = Instant::now();
        let mut w = ParentWalks::new(t);
        let stuck = (h(7), 4_095u64);
        // The walk against `b` stopped at the window and moved on.
        descend(&mut w, "b", 4_160, Some(4_160), t);
        let none = |_: &Hash| false;
        for _ in 0..(REFETCH_AFTER_DEFERRALS - 1) {
            w.note_stuck(&[stuck], "b", t);
        }
        assert!(
            w.refetch_stuck(none, 4_160, t).0.is_empty(),
            "not yet repeated"
        );
        w.note_stuck(&[stuck], "c", t);
        let later = t + WALK_REQUEST_TIMEOUT;
        let (asks, _) = w.refetch_stuck(none, 4_160, later);
        assert_eq!(
            asks,
            vec![Refetch {
                peer: "b".into(),
                parent: h(7),
                height: 4_095
            }],
            "fetched by hash from the first source"
        );
        // Its answer continues the walk below it.
        assert!(is_ask(w.next(
            "b",
            ans(Some((4_095, h(8))), 0, 4_160),
            later
        )));
        w.unsent("b");
        // Not fetched again within REFETCH_EVERY, even if it stays stuck.
        for _ in 0..REFETCH_AFTER_DEFERRALS {
            w.note_stuck(&[stuck], "b", later);
        }
        let soon = later + Duration::from_secs(1);
        assert!(w.refetch_stuck(none, 4_160, soon).0.is_empty());
        let due = later + REFETCH_EVERY;
        assert_eq!(w.refetch_stuck(none, 4_160, due).0.len(), 1);
        w.unsent("b");
        // A parent now held is dropped.
        for _ in 0..REFETCH_AFTER_DEFERRALS {
            w.note_stuck(&[stuck], "b", due);
        }
        let held = |p: &Hash| *p == h(7);
        assert!(w
            .refetch_stuck(held, 4_160, due + REFETCH_EVERY)
            .0
            .is_empty());
    }

    /// Tripwire: the receive loop, sync tick and producer stay wired to these.
    #[test]
    fn main_loop_stays_wired() {
        let main = include_str!("main.rs");
        for needle in [
            "sync_recovery::answer_anchor_was_stale(",
            "sync_recovery::lowest_deferred(",
            "sync_recovery::deferred_roots(",
            "parent_walks.next(",
            "parent_walks.begin(",
            "parent_walks.note_stuck(",
            "parent_walks.refetch_stuck(",
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

    /// Tripwire (bug class: an ungated recovery request). Every `GetBlocks` the
    /// receive loop sends goes through one helper, which is only reached with a
    /// step the walk budget granted.
    #[test]
    fn receive_loop_requests_only_through_the_walk() {
        let main = include_str!("main.rs");
        let start = main
            .find("let net_rx_task = tokio::spawn(async move {")
            .expect("receive loop");
        let end = start
            + main[start..]
                .find("net_rx_task.await")
                .expect("end of receive loop");
        let rx = &main[start..end];
        assert_eq!(
            rx.matches(".request_blocks(").count(),
            0,
            "the receive loop must send recovery requests via sync_recovery::send_step"
        );
        assert!(rx.matches("sync_recovery::send_step(").count() >= 3);
    }
}
