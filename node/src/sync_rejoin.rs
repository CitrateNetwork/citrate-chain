// citrate/node/src/sync_rejoin.rs
//
// Rejoining the heavier chain from a side branch.
//
// THE FAILURE (r1006 testnet, 2026-10-28)
//
// A producer restarted with mining on and sealed its first block before any
// peer had connected, on top of the block it had applied (height 38) while
// the network was already a few heights further on. From then on it built
// every block on its own tip. Its peers stored those blocks as side blocks.
// Two hours later it was at height 3,353 on its own branch while the other six
// producers agreed at ~12,476.
//
// Its sync loop never stopped running and never brought it back:
//
// * Every `GetBlocks` was anchored at the APPLIED tip, i.e. the node's own
//   newest block. `serve_blocks` serves BY HEIGHT from the anchor's height, so
//   the answer was the node's own block plus the peers' blocks at the same and
//   following heights. Those peer blocks extend the heavier chain at heights
//   the node never had (everything between the fork point and its own tip), so
//   admission deferred every one of them as missing a parent. Nothing was
//   admitted; the next tick asked the same question one height higher.
// * Nothing ever asked for the blocks between the fork point and the node's
//   own tip. The gossip-side ancestry recovery (SYNC-S3) asks for one missing
//   parent and is deliberately limited to a short distance; the synced-block
//   path defers silently (debug level), so the journal showed only
//   "Validated and imported 32/32" and `SYNCSCORE ... new=0`.
//
// THE FIX
//
// The driver keeps anchoring on the applied tip while that makes progress. When
// answers to the tip anchor repeatedly admit nothing and carry blocks this node
// cannot connect (or come back empty because the peer does not hold the tip),
// the driver looks for the fork point: it anchors at heights below the tip on
// its own executed chain, doubling the distance until an answer is no longer
// unconnected, then bisecting between the deepest unconnected height and the
// shallowest height whose answer held only blocks it already had. As soon as an
// answer admits a new block, the driver follows those blocks upward by height
// (anchoring at the highest block it admitted) until a follow answer brings
// nothing new. By then fork choice has moved the applied tip to the heavier
// branch if it is heavier, and normal tip-anchored sync takes over.
//
// Only answers to the anchor this tracker asked for move it: an answer counts
// when it contains the anchor block (`serve_blocks` always includes it) or is an
// empty answer from the peer that was asked. Unsolicited `Blocks` messages are
// processed as before but never steer the search.
//
// ONE PEER PER SEARCH (r1006 devnet, 2026-10-29)
//
// A producer forked 35 below its tip and 250 behind logged `StartedProbe` and
// `GaveUp` half a second apart. Its tick asked whichever peer the selector
// ranked first, and relayed gossip makes every peer advertise the network
// head, so the probe went to another producer stuck on the SAME branch. That
// peer holds our tip and nothing above it: its answer held only known
// blocks, which reads as "the fork point is above this height", and the
// bisection ended one height below the top. The same answers reset the
// strikes the leading peer's empty answers had built. So strikes now count
// one peer's answers, and a search is pinned to the peer whose answers
// started it: the tick asks only that peer until the search ends, or drops
// it if the peer disconnects (`choose_source`).
//
// SPLIT HEALING (r1006, 2026-10-29)
//
// Producers whose branches grow at the same rate sit at equal heights, so no
// peer is ever ahead, nothing is ever asked, and each one's blocks defer at
// the others forever. When no peer is ahead, a peer at or a few heights below
// our tip whose advertised tip we do not store starts a split pull: the same
// fork-point search, pinned to that peer, straight from the probe (its tip
// answers could only be unconnected). The blocks found are stored, fork
// choice sees both branches, and the next block merges them. Bounded by
// `sync_peer::SplitPullGate`: one pull per peer per window, one in total per
// interval. A split pull only fetches (the applied tip moves only through the
// applicator's fork-choice and strictly-heavier rules), an equal-height answer
// does not end it as "caught up", and its give-up owes no rejoin backoff.
//
// NOTHING HERE DECIDES VALIDITY. The tracker only picks the anchor of the next
// `GetBlocks`. Every block still goes through `SyncManager::handle_blocks` and
// `BlockAdmission::admit`; fork choice still picks the head.

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

use std::collections::HashSet;
use std::time::{Duration, Instant};

use citrate_consensus::types::Hash;
use citrate_storage::StorageManager;

use crate::sync_peer::{SplitCandidate, SplitPullGate, SyncCandidate, SyncPeerSelector};

/// Consecutive unconnected answers to the tip anchor, while behind, before the
/// driver starts looking for the fork point. Two, so a single answer that raced
/// a parent still on the wire does not start a search.
pub const PROBE_AFTER_STRIKES: u32 = 2;

/// After a search gives up, this many unconnected tip answers are ignored
/// before strikes count again; doubled per consecutive give-up, up to
/// [`BACKOFF_MAX_ANSWERS`]. With one request per 2 s tick, 4 is ~8 s and the
/// cap is ~8.5 min.
pub const BACKOFF_BASE_ANSWERS: u32 = 4;
/// Cap on the post-give-up backoff, in answers.
pub const BACKOFF_MAX_ANSWERS: u32 = 256;

/// Requests in a row without a matching answer before a search or follow gives
/// up (see [`RejoinTracker::note_asked`]).
pub const MAX_UNANSWERED: u32 = 8;

/// A follow answer that moves the cursor up by fewer than this many heights
/// trickles: a quarter of one 32-block answer (`sync_peer::MATERIAL_FRACTION`).
pub const FOLLOW_TRICKLE_ADVANCE: u64 = 8;

/// Trickling follow answers in a row before the follow ends. A peer that keeps
/// delivering one admissible block per answer can otherwise hold the tick for
/// as long as it has blocks (DGX review of 49465b5e, P1-2).
pub const MAX_TRICKLE_ANSWERS: u32 = MAX_UNANSWERED;

/// Requests one fork-point search (the probe) may send before it gives up:
/// twice the doubling-then-bisecting bound for `top`, plus the unanswered
/// allowance. A slow peer that answers just often enough to keep `unanswered`
/// below [`MAX_UNANSWERED`] can hold a search no longer than this.
pub fn search_request_cap(top: u64) -> u32 {
    2u32.saturating_mul(64u32.saturating_sub(top.leading_zeros()))
        .saturating_add(MAX_UNANSWERED)
}

/// `SYNCREJOIN` info lines allowed per [`REJOIN_LOG_WINDOW`]; the rest are
/// counted and reported on the next line that is allowed.
pub const REJOIN_LOG_PER_WINDOW: u32 = 8;
/// See [`REJOIN_LOG_PER_WINDOW`].
pub const REJOIN_LOG_WINDOW: Duration = Duration::from_secs(600);

/// What an answer to the tracker's anchor did, judged after admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// At least one block was newly admitted; the highest of them.
    Progress { highest: (Hash, u64) },
    /// Nothing new, and either some served block could not be connected (its
    /// parent is missing) or the answer was empty (the peer does not hold the
    /// anchor).
    Unconnected,
    /// Nothing new and nothing unconnected: every served block was already held.
    Known,
}

/// Classify an answer from what admission did with it.
///
/// `empty` is the answer as received (before validation); `deferred` counts the
/// blocks of THIS answer that admission left waiting for a parent.
pub fn classify(
    empty: bool,
    newly_admitted: usize,
    highest_admitted: Option<(Hash, u64)>,
    deferred: usize,
) -> Answer {
    match highest_admitted {
        Some(highest) if newly_admitted > 0 => Answer::Progress { highest },
        _ if empty || deferred > 0 => Answer::Unconnected,
        _ => Answer::Known,
    }
}

/// Where the next `GetBlocks` is anchored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Normal sync: anchor on the applied tip.
    Tip { strikes: u32 },
    /// Looking for the fork point below `top` (the applied height when the
    /// search started).
    Probe {
        top: u64,
        /// Deepest height whose answer was unconnected.
        unconnected: u64,
        /// Shallowest height whose answer held only known blocks, once seen.
        known: Option<u64>,
        /// Distance below `top` of the next expansion step.
        step: u64,
        /// Height anchored now.
        height: u64,
    },
    /// Following blocks admitted from the search upward by height.
    Follow { cursor: (Hash, u64) },
}

/// A change of mode worth one log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    StartedProbe {
        top: u64,
    },
    /// A pull of a sibling branch from a peer at or near our height.
    StartedSplitPull {
        top: u64,
    },
    Following {
        cursor_height: u64,
    },
    Finished {
        from: &'static str,
    },
    GaveUp {
        at: u64,
    },
}

/// The anchor policy described at the top of this file.
#[derive(Debug)]
pub struct RejoinTracker {
    mode: Mode,
    /// The anchor `(hash, height)` the last request was sent with, and to whom.
    asked: Option<(String, Hash, u64)>,
    /// Consecutive searches that gave up without finding the fork point.
    give_ups: u32,
    /// Unconnected tip answers still to ignore before strikes count again.
    cooldown: u32,
    /// Requests in a row, during a search, that got no matching answer.
    unanswered: u32,
    /// Whether the sync tick's clamped target is above the applied tip (see
    /// [`RejoinTracker::note_sync_target`]).
    target_behind: bool,
    /// The peer whose unconnected answers the current strikes count. An
    /// answer from another peer neither adds to them nor clears them: a
    /// sibling on our own branch holds our tip and says nothing about whether
    /// the striking peer's chain extends it.
    strike_peer: Option<String>,
    /// The peer the running search (probe or follow) is pinned to: the one
    /// whose answers started it. The sync tick asks only this peer while the
    /// search runs (see [`choose_source`]); answers from any other peer were
    /// what moved and ended the search on the r1006 devnet.
    peer: Option<String>,
    /// The peer whose answer [`Self::take_answer`] last matched.
    answered_by: Option<String>,
    /// The running search is a split pull ([`Self::start_split_pull`]): the
    /// peer is at our height, so "not behind" does not end it, and its
    /// give-up owes no rejoin backoff (the split gate rate-limits pulls).
    split: bool,
    /// The applied height a split pull started at; its follow stops
    /// `SPLIT_PULL_HEIGHT_BAND + MAX_REORG_DEPTH` above it.
    split_top: u64,
    /// Requests the running probe has sent (or skipped while its anchor was
    /// pending), against [`search_request_cap`].
    requests: u32,
    /// [`search_request_cap`] of the running probe's top.
    request_cap: u32,
    /// Trickling follow answers in a row ([`FOLLOW_TRICKLE_ADVANCE`]).
    trickles: u32,
}

impl Default for RejoinTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RejoinTracker {
    pub fn new() -> Self {
        Self {
            mode: Mode::Tip { strikes: 0 },
            asked: None,
            give_ups: 0,
            cooldown: 0,
            unanswered: 0,
            target_behind: false,
            strike_peer: None,
            peer: None,
            answered_by: None,
            split: false,
            split_top: 0,
            requests: 0,
            request_cap: 0,
            trickles: 0,
        }
    }

    /// A search starts below `top`: its request budget and follow state.
    fn start_search(&mut self, top: u64) {
        self.requests = 0;
        self.request_cap = search_request_cap(top);
        self.trickles = 0;
    }

    /// The peer the running search is pinned to; `None` in `Tip` mode.
    pub fn search_peer(&self) -> Option<&str> {
        match self.mode {
            Mode::Tip { .. } => None,
            _ => self.peer.as_deref(),
        }
    }

    /// Whether a split pull may start now: no search is running and the node
    /// holds more than genesis.
    pub fn can_start_split(&self, applied_height: u64) -> bool {
        matches!(self.mode, Mode::Tip { .. }) && applied_height > 0
    }

    /// Start pulling a sibling branch from `peer`, a peer at or near our
    /// height whose tip we do not hold. The tip anchor would only be answered
    /// with blocks at and above our own height whose parents we lack, so this
    /// goes straight to the fork-point search below `top` (our applied
    /// height), pinned to `peer`. Fetching only: the blocks go through
    /// admission, and whether the applied tip moves stays with fork choice and
    /// the applicator's strictly-heavier rule.
    pub fn start_split_pull(&mut self, peer: &str, top: u64) -> Option<Transition> {
        if !self.can_start_split(top) {
            return None;
        }
        self.mode = Mode::Probe {
            top,
            unconnected: top,
            known: None,
            step: 1,
            height: top.saturating_sub(1),
        };
        self.peer = Some(peer.to_string());
        self.split = true;
        self.split_top = top;
        self.strike_peer = None;
        self.unanswered = 0;
        self.start_search(top);
        Some(Transition::StartedSplitPull { top })
    }

    /// End the running search because its peer is no longer connected. Not a
    /// failure of the search, so no backoff.
    pub fn abandon(&mut self) -> Option<Transition> {
        self.reset("peer left")
    }

    #[cfg(test)]
    pub fn mode(&self) -> &Mode {
        &self.mode
    }

    /// The anchor for the next `GetBlocks`. `applied` is the applied tip;
    /// `lookup(h)` names a block this node holds at height `h` on its executed
    /// chain (see [`anchor_at_height`]). A probe height that cannot be resolved
    /// ends the search and falls back to the applied tip.
    pub fn anchor(
        &mut self,
        applied: (Hash, u64),
        lookup: impl Fn(u64) -> Option<Hash>,
    ) -> (Hash, u64) {
        match &self.mode {
            Mode::Tip { .. } => applied,
            Mode::Probe { height, .. } => match lookup(*height) {
                Some(h) => (h, *height),
                None => {
                    let at = *height;
                    let _ = self.give_up(at);
                    applied
                }
            },
            Mode::Follow { cursor } => *cursor,
        }
    }

    /// The sync tick's clamped target and the applied height. A target above
    /// the applied tip counts as "behind" for [`Self::on_answer`] in addition
    /// to the caller's gossip evidence: the tick pulls toward peers' advertised
    /// heads too, and a node that hears no new-block gossip (a quiet network, or
    /// one whose only height evidence is the handshake) must still be able to
    /// search. An inflated advertised head can only start a bounded search,
    /// which the give-up backoff caps.
    pub fn note_sync_target(&mut self, target: u64, applied: u64) {
        self.target_behind = target > applied;
    }

    /// Record that a `GetBlocks` anchored at `anchor` went to `peer`. A search
    /// whose requests go [`MAX_UNANSWERED`] ticks without a matching answer
    /// gives up (with the usual backoff), so it can never hang on a peer that
    /// stops answering or always answers something else.
    pub fn note_asked(&mut self, peer: &str, anchor: (Hash, u64)) -> Option<Transition> {
        let mut out = None;
        if self.asked.is_some() && !matches!(self.mode, Mode::Tip { .. }) {
            self.unanswered = self.unanswered.saturating_add(1);
            if self.unanswered >= MAX_UNANSWERED {
                self.unanswered = 0;
                out = self.give_up(anchor.1);
            }
        }
        self.asked = Some((peer.to_string(), anchor.0, anchor.1));
        if out.is_none() {
            out = self.count_probe_request(anchor.1);
        }
        out
    }

    /// One more request (sent or skipped) by the running probe; the probe gives
    /// up once it has used [`search_request_cap`].
    fn count_probe_request(&mut self, at: u64) -> Option<Transition> {
        if !matches!(self.mode, Mode::Probe { .. }) {
            return None;
        }
        self.requests = self.requests.saturating_add(1);
        if self.requests >= self.request_cap {
            return self.give_up(at);
        }
        None
    }

    /// The tick did not send this round's request to `peer` (its anchor was
    /// still pending).
    /// It got no answer this round either, so it counts as unanswered (and
    /// against the probe's request cap): a pinned peer that never answers
    /// ends the search after [`MAX_UNANSWERED`] rounds whether or not the
    /// request was re-sent (DGX review of 49465b5e, P1-2).
    pub fn note_unsent(&mut self, peer: &str) -> Option<Transition> {
        if matches!(self.mode, Mode::Tip { .. }) || self.peer.as_deref() != Some(peer) {
            return None;
        }
        let at = self.asked.as_ref().map(|a| a.2).unwrap_or(0);
        self.unanswered = self.unanswered.saturating_add(1);
        if self.unanswered >= MAX_UNANSWERED {
            self.unanswered = 0;
            return self.give_up(at);
        }
        self.count_probe_request(at)
    }

    /// Whether a `Blocks` message from `peer` answers the outstanding request;
    /// if so, the anchor height it answers. `received` is the answer as it
    /// arrived (only its emptiness is used); `verified` holds the hashes of
    /// its blocks that passed `handle_blocks` (their hashes recompute). Only
    /// the asked peer can answer: empty, or with the anchor block among the
    /// verified ones. Consumes the request, so one request moves the tracker at
    /// most once.
    pub fn take_answer(
        &mut self,
        peer: &str,
        received: &[Hash],
        verified: &HashSet<Hash>,
    ) -> Option<u64> {
        let (asked_peer, anchor, height) = self.asked.as_ref()?;
        // Genesis carries no proposer signature, so it never passes
        // `handle_blocks`; a probe anchored there is matched on the received
        // hash, still only from the asked peer.
        let genesis_anchor = *height == 0 && received.contains(anchor);
        let answers = asked_peer == peer
            && (received.is_empty() || verified.contains(anchor) || genesis_anchor);
        if !answers {
            return None;
        }
        let height = *height;
        self.answered_by = Some(asked_peer.clone());
        self.asked = None;
        self.unanswered = 0;
        Some(height)
    }

    #[cfg(test)]
    pub fn cooldown(&self) -> u32 {
        self.cooldown
    }

    /// Fold in the verdict on an answer. `behind` is whether the node has
    /// evidence of a higher network head than its applied tip; `anchor_height`
    /// is the height the answered request was anchored at.
    pub fn on_answer(
        &mut self,
        answer: Answer,
        behind: bool,
        anchor_height: u64,
    ) -> Option<Transition> {
        let from = self.answered_by.take();
        let behind = behind || self.target_behind || self.split;
        if !behind {
            self.give_ups = 0;
            self.cooldown = 0;
            return self.reset("caught up");
        }
        match (self.mode.clone(), answer) {
            (Mode::Tip { .. }, Answer::Progress { .. }) | (Mode::Tip { .. }, Answer::Known) => {
                // Only the striking peer's own answer clears its strikes.
                if self.strike_peer == from {
                    self.mode = Mode::Tip { strikes: 0 };
                    self.strike_peer = None;
                }
                None
            }
            (Mode::Tip { strikes }, Answer::Unconnected) => {
                if self.cooldown > 0 {
                    self.cooldown = self.cooldown.saturating_sub(1);
                    return None;
                }
                let strikes = if self.strike_peer == from {
                    strikes.saturating_add(1)
                } else {
                    self.strike_peer = from;
                    1
                };
                if strikes < PROBE_AFTER_STRIKES || anchor_height == 0 {
                    self.mode = Mode::Tip { strikes };
                    return None;
                }
                let top = anchor_height;
                self.peer = self.strike_peer.take();
                self.start_search(top);
                self.mode = Mode::Probe {
                    top,
                    unconnected: top,
                    known: None,
                    step: 1,
                    height: top.saturating_sub(1),
                };
                Some(Transition::StartedProbe { top })
            }
            (Mode::Probe { .. }, Answer::Progress { highest })
            | (Mode::Follow { .. }, Answer::Progress { highest }) => {
                let previous = match &self.mode {
                    Mode::Follow { cursor } => Some(cursor.1),
                    _ => None,
                };
                let cursor = match &self.mode {
                    Mode::Follow { cursor } if cursor.1 > highest.1 => *cursor,
                    _ => highest,
                };
                let was_following = previous.is_some();
                // A split pull fetches a sibling branch, never a catch-up: its
                // follow stops past the band plus the reorg window.
                let split_limit = self
                    .split_top
                    .saturating_add(crate::sync_peer::SPLIT_PULL_HEIGHT_BAND)
                    .saturating_add(crate::canonical_apply::MAX_REORG_DEPTH);
                if self.split && cursor.1 > split_limit {
                    return self.give_up(cursor.1);
                }
                if let Some(prev) = previous {
                    if cursor.1.saturating_sub(prev) < FOLLOW_TRICKLE_ADVANCE {
                        self.trickles = self.trickles.saturating_add(1);
                        if self.trickles >= MAX_TRICKLE_ANSWERS {
                            return self.give_up(cursor.1);
                        }
                    } else {
                        self.trickles = 0;
                    }
                }
                // The search found the fork point: no backoff owed.
                self.give_ups = 0;
                self.mode = Mode::Follow { cursor };
                if was_following {
                    None
                } else {
                    Some(Transition::Following {
                        cursor_height: cursor.1,
                    })
                }
            }
            (Mode::Follow { .. }, _) => self.reset("follow"),
            (
                Mode::Probe {
                    top,
                    unconnected,
                    known,
                    step,
                    height,
                },
                verdict,
            ) => {
                // An answer for a height other than the one being probed is
                // stale (the probe moved since it was sent): ignore it.
                if anchor_height != height {
                    return None;
                }
                let (unconnected, known, step) = match verdict {
                    Answer::Unconnected => (height, known, step.saturating_mul(2)),
                    // Progress is handled above; this arm is Known.
                    _ => (unconnected, Some(height), step),
                };
                let next = match known {
                    // Still expanding: the next doubling below the top.
                    None => {
                        if height == 0 {
                            return self.give_up(0);
                        }
                        top.saturating_sub(step)
                    }
                    // Bisect between the known-good and unconnected heights.
                    Some(k) => {
                        let span = unconnected.saturating_sub(k);
                        if span <= 1 {
                            return self.give_up(k);
                        }
                        k.saturating_add(span / 2)
                    }
                };
                self.mode = Mode::Probe {
                    top,
                    unconnected,
                    known,
                    step,
                    height: next,
                };
                None
            }
        }
    }

    fn reset(&mut self, from: &'static str) -> Option<Transition> {
        self.peer = None;
        self.split = false;
        self.strike_peer = None;
        let was = std::mem::replace(&mut self.mode, Mode::Tip { strikes: 0 });
        match was {
            Mode::Tip { .. } => None,
            _ => Some(Transition::Finished { from }),
        }
    }

    fn give_up(&mut self, at: u64) -> Option<Transition> {
        self.mode = Mode::Tip { strikes: 0 };
        self.peer = None;
        self.strike_peer = None;
        if std::mem::take(&mut self.split) {
            // The split gate rate-limits pulls; an ordinary search later
            // must not wait behind this one.
            return Some(Transition::GaveUp { at });
        }
        let shift = self.give_ups.min(31);
        self.cooldown = BACKOFF_BASE_ANSWERS
            .saturating_mul(2u32.saturating_pow(shift))
            .min(BACKOFF_MAX_ANSWERS);
        self.give_ups = self.give_ups.saturating_add(1);
        Some(Transition::GaveUp { at })
    }
}

/// The peer the sync tick asks this round, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A fork-point search or follow is running against this peer.
    Pinned(String),
    /// The selector's pick among peers ahead of us (sync_peer.rs).
    Ahead(String),
    /// A peer at or near our height whose tip we do not hold: pull its branch.
    Split(String),
    /// Nobody to ask.
    Nobody,
}

impl Source {
    pub fn peer(&self) -> Option<&str> {
        match self {
            Source::Pinned(p) | Source::Ahead(p) | Source::Split(p) => Some(p),
            Source::Nobody => None,
        }
    }
}

/// Which peer the sync tick asks this round. `candidates` and `split` describe
/// the same connected peers; `holds(h)` says whether this node stores block
/// `h`. Returns the source and a transition worth one log line.
#[allow(clippy::too_many_arguments)]
pub fn choose_source(
    tracker: &mut RejoinTracker,
    selector: &SyncPeerSelector,
    gate: &mut SplitPullGate,
    candidates: &[SyncCandidate],
    split: &[SplitCandidate],
    applied: (Hash, u64),
    holds: impl Fn(&Hash) -> bool,
    now: Instant,
) -> (Source, Option<Transition>) {
    let mut transition = None;
    if let Some(p) = tracker.search_peer().map(str::to_string) {
        match candidates.iter().find(|c| c.id == p) {
            Some(pinned) => {
                // Another peer more than the catch-up gap ahead of the pinned
                // one ends the pin: the selector asks the peer that can carry
                // us (DGX review of 49465b5e, P1-2).
                let lead = candidates
                    .iter()
                    .filter(|c| c.id != p)
                    .map(|c| c.head_height)
                    .max()
                    .unwrap_or(0);
                let gap = crate::producer::CATCHUP_REFUSE_GAP;
                if lead <= pinned.head_height.saturating_add(gap) {
                    return (Source::Pinned(p), None);
                }
                transition = tracker.reset("a peer is ahead");
            }
            None => transition = tracker.abandon(),
        }
    }
    if let Some(c) = selector.select(candidates, applied.1) {
        return (Source::Ahead(c.id.clone()), transition);
    }
    if !tracker.can_start_split(applied.1) {
        return (Source::Nobody, transition);
    }
    match gate.pick(split, applied, holds, now) {
        Some(c) => {
            let started = tracker.start_split_pull(&c.id, applied.1);
            (Source::Split(c.id.clone()), transition.or(started))
        }
        None => (Source::Nobody, transition),
    }
}

/// Bound on `SYNCREJOIN` info lines: [`REJOIN_LOG_PER_WINDOW`] per
/// [`REJOIN_LOG_WINDOW`]; the rest are counted.
#[derive(Debug)]
pub struct RejoinLogBudget {
    window_start: Option<Instant>,
    used: u32,
    suppressed: u64,
}

impl Default for RejoinLogBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl RejoinLogBudget {
    pub fn new() -> Self {
        Self {
            window_start: None,
            used: 0,
            suppressed: 0,
        }
    }

    /// `Some(n)` when a line may be logged now, `n` being the lines
    /// suppressed since the last one logged; `None` when over budget.
    pub fn allow(&mut self, now: Instant) -> Option<u64> {
        let fresh = match self.window_start {
            Some(start) => now.saturating_duration_since(start) >= REJOIN_LOG_WINDOW,
            None => true,
        };
        if fresh {
            self.window_start = Some(now);
            self.used = 0;
        }
        if self.used >= REJOIN_LOG_PER_WINDOW {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        self.used = self.used.saturating_add(1);
        Some(std::mem::take(&mut self.suppressed))
    }
}

/// A block this node holds at `height` on its executed chain, for use as a
/// `GetBlocks` anchor. `serve_blocks` uses the anchor only for its height, so
/// any held block at that height works; the executed chain's block is the one
/// peers are most likely to hold. Falls back to the stored height index.
pub fn anchor_at_height(storage: &StorageManager, height: u64) -> Option<Hash> {
    storage
        .blocks
        .get_canonical_block_by_height(height)
        .ok()
        .flatten()
        .or_else(|| storage.blocks.get_block_by_height(height).ok().flatten())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::{bound_orphan_buffer, BlockAdmission};
    use crate::block_serve;
    use crate::canonical_apply::{canonical_reward_config, ApplyOutcome, CanonicalApplicator};
    use citrate_consensus::crypto;
    use citrate_consensus::dag_store::DagStore;
    use citrate_consensus::ghostdag::GhostDag;
    use citrate_consensus::hardening::PbaHardening;
    use citrate_consensus::types::{
        blue_work_for_score, Block, BlockBuilder, GhostDagParams, PublicKey, VrfProof,
    };
    use citrate_economics::rewards::RewardCalculator;
    use citrate_execution::revm_adapter::BlockContext;
    use citrate_execution::types::Address;
    use citrate_execution::{Executor, StateDB};
    use citrate_network::sync::{SyncConfig, SyncManager};
    use citrate_network::PeerId;
    use citrate_storage::pruning::PruningConfig;
    use primitive_types::U256;
    use std::sync::Arc;

    // ---------------------------------------------------------------------
    // Fixture: a chain with real state roots, a node wired as `start_node`
    // wires one (storage-backed executor, applicator with GhostDAG fork
    // choice, admission, sync manager), and a peer store served by the real
    // `block_serve::serve_blocks`.
    // ---------------------------------------------------------------------

    const CB: [u8; 20] = [0x33; 20];
    const CHAIN_ID: u64 = 40204;
    const PEER: &str = "peer-main";

    fn h(b: &Block) -> Hash {
        b.header.block_hash
    }

    fn seal(key: &ed25519_dalek::SigningKey, height: u64, parent: Hash, root: Hash) -> Block {
        let mut b = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(parent)
            .coinbase(CB)
            .timestamp(1_000 + height)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new([0x5A; 32]),
            })
            .transactions(vec![])
            .state_root(root)
            .blue_score(height)
            .blue_work(blue_work_for_score(height))
            .proposer(PublicKey::new(key.verifying_key().to_bytes()))
            .build_unhashed();
        b.tx_root = citrate_consensus::tx_auth::tx_root_for_height(
            PbaHardening::off(),
            height,
            &b.transactions,
        );
        b.header.block_hash = b.compute_hash();
        b.signature = crypto::sign_block(&b.header.block_hash, key);
        b
    }

    fn genesis() -> Block {
        let mut g = BlockBuilder::new()
            .version(2)
            .height(0)
            .parent(Hash::default())
            .coinbase(CB)
            .timestamp(1_000)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new([0x5A; 32]),
            })
            .transactions(vec![])
            // The empty genesis state's root, so the deep-fork rebuild (which
            // checks it) can replay from genesis.
            .state_root(Executor::new(Arc::new(StateDB::new())).calculate_state_root())
            .blue_score(0)
            .blue_work(blue_work_for_score(0))
            .build_unhashed();
        g.header.block_hash = g.compute_hash();
        g
    }

    /// State root after applying heights `1..=h`, for every `h <= n`. Blocks
    /// carry no transactions and pay the same coinbase, so the root at a
    /// height is the same on every branch.
    fn roots(n: u64, key: &ed25519_dalek::SigningKey) -> Vec<Hash> {
        let exec = Executor::new(Arc::new(StateDB::new()));
        let rewards = RewardCalculator::new(canonical_reward_config());
        let treasury = canonical_reward_config().treasury_address;
        let mut out = vec![Hash::default()];
        for height in 1..=n {
            exec.set_block_context(BlockContext {
                coinbase: CB,
                prevrandao: [0x5A; 32],
                block_hashes: std::collections::HashMap::new(),
            });
            let provisional = seal(key, height, Hash::default(), Hash::default());
            let r = rewards.calculate_reward(&provisional).expect("reward");
            for (addr, amt) in [
                (Address(CB), r.validator_reward),
                (treasury, r.treasury_reward),
            ] {
                if amt > U256::zero() {
                    let bal = exec.get_balance(&addr);
                    exec.set_balance(&addr, bal + amt);
                }
            }
            out.push(exec.calculate_state_root());
        }
        out
    }

    /// Blocks `from..=to` sealed by `key` on top of `parent`.
    fn extend(
        key: &ed25519_dalek::SigningKey,
        parent: Hash,
        from: u64,
        to: u64,
        roots: &[Hash],
    ) -> Vec<Block> {
        let mut parent = parent;
        let mut out = Vec::new();
        for height in from..=to {
            let b = seal(key, height, parent, roots[height as usize]);
            parent = h(&b);
            out.push(b);
        }
        out
    }

    /// The network: a common prefix `1..=fork`, the heavier main chain
    /// `fork+1..=main_tip` and the node's own side branch `fork+1..=side_tip`.
    struct Net {
        genesis: Block,
        prefix: Vec<Block>,
        main: Vec<Block>,
        side: Vec<Block>,
    }

    fn net(fork: u64, side_tip: u64, main_tip: u64) -> Net {
        let main_key = crypto::generate_keypair();
        let side_key = crypto::generate_keypair();
        let r = roots(main_tip.max(side_tip), &main_key);
        let g = genesis();
        let prefix = extend(&main_key, h(&g), 1, fork, &r);
        let fork_hash = prefix.last().map(h).unwrap_or_else(|| h(&g));
        let main = extend(&main_key, fork_hash, fork + 1, main_tip, &r);
        let side = extend(&side_key, fork_hash, fork + 1, side_tip, &r);
        Net {
            genesis: g,
            prefix,
            main,
            side,
        }
    }

    fn peer_store(net: &Net, with_side: bool, dir: &std::path::Path) -> Arc<StorageManager> {
        let s = Arc::new(StorageManager::new(dir, PruningConfig::default()).expect("storage"));
        s.blocks.put_block(&net.genesis).expect("genesis");
        for b in net.prefix.iter().chain(net.main.iter()) {
            s.blocks.put_block(b).expect("put");
        }
        if with_side {
            for b in &net.side {
                s.blocks.put_block(b).expect("put");
            }
        }
        s
    }

    struct Node {
        storage: Arc<StorageManager>,
        executor: Arc<Executor>,
        app: Arc<CanonicalApplicator>,
        admission: Arc<BlockAdmission>,
        sync: SyncManager,
        ghostdag: Arc<GhostDag>,
    }

    /// A node that applied `own` (prefix and, optionally, its side branch).
    async fn node(net: &Net, own: &[Block], dir: &std::path::Path) -> Node {
        let storage =
            Arc::new(StorageManager::new(dir, PruningConfig::default()).expect("storage"));
        let g = &net.genesis;
        storage.blocks.put_block(g).expect("genesis");
        storage
            .blocks
            .put_applied_tip(&g.header.block_hash, 0)
            .expect("tip");
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        dag.set_configured_genesis(g.header.block_hash);
        dag.store_block(g.clone()).await.expect("genesis dag");
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));
        ghostdag.add_block(g).await.expect("genesis ghostdag");
        let executor = Arc::new(Executor::with_storage_and_chain_id(
            Arc::new(StateDB::new()),
            Some(storage.state.clone()),
            CHAIN_ID,
        ));
        executor.set_pba_hardening(PbaHardening::off());
        let app = Arc::new(
            CanonicalApplicator::new(executor.clone(), storage.clone())
                .with_fork_choice(ghostdag.clone()),
        );
        // As start_node: genesis wired for the deep-fork rebuild, and the DAG
        // marked hydrated.
        app.set_genesis(
            Executor::new(Arc::new(StateDB::new())).state_snapshot(),
            g.header.block_hash,
        );
        ghostdag.reconcile_tips_from_dag_store().await;
        let admission = Arc::new(BlockAdmission::new(
            storage.clone(),
            dag,
            ghostdag.clone(),
            Some(app.clone()),
        ));
        let sync = SyncManager::new(SyncConfig::default())
            .with_local_height(app.applied_height_handle())
            .with_pba_hardening(PbaHardening::off());
        let n = Node {
            storage,
            executor,
            app,
            admission,
            sync,
            ghostdag,
        };
        let fx = n.admission.admit_to_fixpoint(own.to_vec(), |_, _| {}).await;
        assert_eq!(fx.newly_admitted, own.len(), "own blocks admit");
        assert_eq!(
            n.applied(),
            own.last().map(|b| (h(b), b.header.height)),
            "node starts on its own tip"
        );
        n
    }

    impl Node {
        fn applied(&self) -> Option<(Hash, u64)> {
            self.storage.blocks.get_applied_tip().expect("tip read")
        }
    }

    #[derive(Debug, Default)]
    struct Run {
        rounds: usize,
        /// Heights every request was anchored at, in order.
        anchors: Vec<u64>,
        modes: Vec<Mode>,
    }

    /// One `Blocks` message through the steps the node's `Blocks` handler
    /// runs: `handle_blocks`, match against the asked anchor on the validated
    /// blocks, admission to a fixpoint (orphans buffered), the periodic drain,
    /// then the tracker judges the answer if it was ours.
    async fn deliver(
        node: &Node,
        tracker: &mut RejoinTracker,
        orphans: &mut Vec<Block>,
        from: &str,
        answer: Vec<Block>,
        network_height: u64,
    ) -> (usize, u64) {
        let received: Vec<Hash> = answer.iter().map(h).collect();
        node.sync
            .handle_blocks(&PeerId(from.to_string()), answer)
            .await
            .expect("validate");
        let mut pending = node.sync.drain_validated_blocks().await;
        let verified: HashSet<Hash> = pending.iter().map(h).collect();
        let answered = tracker.take_answer(from, &received, &verified);
        let reprocessed = !pending.is_empty();
        if reprocessed {
            pending.append(orphans);
            pending = bound_orphan_buffer(pending);
        }
        let fx = node.admission.admit_to_fixpoint(pending, |_, _| {}).await;
        let deferred = fx
            .deferred
            .iter()
            .filter(|b| verified.contains(&h(b)))
            .count();
        if reprocessed {
            *orphans = bound_orphan_buffer(fx.deferred);
        }
        node.app.drive_drain().await;
        let applied_now = node.applied().expect("applied tip").1;
        if let Some(ah) = answered {
            let verdict = classify(
                received.is_empty(),
                fx.newly_admitted,
                fx.highest_admitted,
                deferred,
            );
            tracker.on_answer(verdict, network_height > applied_now, ah);
        }
        (
            fx.newly_admitted,
            fx.highest_admitted.map(|(_, ht)| ht).unwrap_or(0),
        )
    }

    /// Drive the node's sync against one peer the way the 2 s tick and the
    /// `Blocks` handler do. `interfere(anchor)` yields messages from other
    /// peers that arrive after the request and before the asked peer's answer.
    #[allow(clippy::too_many_arguments)]
    async fn drive_with(
        node: &Node,
        tracker: &mut RejoinTracker,
        peer: &StorageManager,
        target: Hash,
        network_height: u64,
        max_rounds: usize,
        interfere: impl Fn(&Node, (Hash, u64)) -> Vec<(String, Vec<Block>)>,
    ) -> Run {
        let mut run = Run::default();
        let mut orphans: Vec<Block> = Vec::new();
        while run.rounds < max_rounds {
            let applied = node.applied().expect("applied tip");
            if applied.0 == target {
                break;
            }
            run.rounds += 1;
            let anchor = tracker.anchor(applied, |ht| anchor_at_height(&node.storage, ht));
            tracker.note_asked(PEER, anchor);
            run.anchors.push(anchor.1);
            for (from, msg) in interfere(node, anchor) {
                deliver(node, tracker, &mut orphans, &from, msg, network_height).await;
            }
            let answer = block_serve::serve_blocks(peer, &anchor.0, 32);
            deliver(node, tracker, &mut orphans, PEER, answer, network_height).await;
            run.modes.push(tracker.mode().clone());
        }
        run
    }

    async fn drive(
        node: &Node,
        tracker: &mut RejoinTracker,
        peer: &StorageManager,
        target: Hash,
        network_height: u64,
        max_rounds: usize,
    ) -> Run {
        drive_with(
            node,
            tracker,
            peer,
            target,
            network_height,
            max_rounds,
            |_, _| Vec::new(),
        )
        .await
    }

    /// Like [`drive`], with the tracker's "behind" signal coming only from the
    /// sync tick's target: peers advertise `advertised` (Hello/HelloAck) and no
    /// new-block gossip ever arrives, so gossip evidence is 0 throughout.
    async fn drive_advertised(
        node: &Node,
        tracker: &mut RejoinTracker,
        peer: &StorageManager,
        target: Hash,
        advertised: u64,
        max_rounds: usize,
    ) -> Run {
        let mut run = Run::default();
        let mut orphans: Vec<Block> = Vec::new();
        while run.rounds < max_rounds {
            let applied = node.applied().expect("applied tip");
            if applied.0 == target {
                break;
            }
            run.rounds += 1;
            // As the tick: clamped target from the advertised head.
            tracker.note_sync_target(advertised, applied.1);
            let anchor = tracker.anchor(applied, |ht| anchor_at_height(&node.storage, ht));
            tracker.note_asked(PEER, anchor);
            run.anchors.push(anchor.1);
            let answer = block_serve::serve_blocks(peer, &anchor.0, 32);
            deliver(node, tracker, &mut orphans, PEER, answer, 0).await;
            run.modes.push(tracker.mode().clone());
        }
        run
    }

    /// A side-branch node whose only height evidence is a peer's advertised
    /// head (no new-block gossip) still searches and rejoins: 10 blocks deep.
    /// (A 1-deep branch needs no search: the tip anchor's own height group
    /// carries the heavier sibling; that case is pinned too.)
    #[tokio::test]
    async fn advertised_head_without_gossip_rejoins_shallow() {
        for side_tip in [7u64, 16] {
            advertised_rejoin(side_tip).await;
        }
    }

    async fn advertised_rejoin(side_tip: u64) {
        let net = net(6, side_tip, 48);
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, true, pdir.path());
        let ndir = tempfile::tempdir().expect("tempdir");
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let n = node(&net, &own, ndir.path()).await;
        let main_tip = net.main.last().expect("main");
        let mut tracker = RejoinTracker::new();
        let run = drive_advertised(&n, &mut tracker, &peer, h(main_tip), 48, 60).await;
        assert_eq!(
            n.applied(),
            Some((h(main_tip), 48)),
            "no gossip: the node stayed on its side branch: anchors {:?}",
            run.anchors
        );
    }

    /// Same, side branch deeper than the reorg window.
    #[tokio::test]
    async fn advertised_head_without_gossip_rejoins_deep() {
        let net = net(6, 150, 400);
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, true, pdir.path());
        let ndir = tempfile::tempdir().expect("tempdir");
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let n = node(&net, &own, ndir.path()).await;
        let main_tip = net.main.last().expect("main");
        let mut tracker = RejoinTracker::new();
        let run = drive_advertised(&n, &mut tracker, &peer, h(main_tip), 400, 200).await;
        assert_eq!(
            n.applied(),
            Some((h(main_tip), 400)),
            "no gossip: the node stayed on its side branch after {} rounds: anchors {:?}",
            run.rounds,
            run.anchors
        );
    }

    /// The tick target only adds evidence: with the target at the applied tip
    /// and no gossip, a node is not behind and never searches.
    #[test]
    fn a_target_at_the_tip_is_not_behind() {
        let mut t = RejoinTracker::new();
        t.note_sync_target(50, 50);
        for _ in 0..5 {
            t.on_answer(Answer::Unconnected, false, 50);
        }
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
        t.note_sync_target(60, 50);
        t.on_answer(Answer::Unconnected, false, 50);
        assert_eq!(t.mode(), &Mode::Tip { strikes: 1 });
    }

    /// A block whose `block_hash` field names `anchor` but whose contents are
    /// another block's: it does not survive `handle_blocks`.
    fn tagged(anchor: Hash, body: &Block) -> Block {
        let mut b = body.clone();
        b.header.block_hash = anchor;
        b
    }

    /// Another peer's message arriving before the asked peer's answer, carrying
    /// a block tagged with the anchor hash and the genuine anchor block, must
    /// not consume the request: the side-branch node still rejoins.
    #[tokio::test]
    async fn another_peers_message_does_not_consume_the_request() {
        let net = net(6, 14, 48);
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, true, pdir.path());
        let ndir = tempfile::tempdir().expect("tempdir");
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let n = node(&net, &own, ndir.path()).await;
        let main_tip = net.main.last().expect("main");
        let body = net.prefix[0].clone();
        let mut tracker = RejoinTracker::new();
        let run = drive_with(
            &n,
            &mut tracker,
            &peer,
            h(main_tip),
            48,
            60,
            |node, anchor| {
                let mut msg = vec![tagged(anchor.0, &body)];
                if let Ok(Some(real)) = node.storage.blocks.get_block(&anchor.0) {
                    msg.push(real);
                }
                vec![("peer-other".to_string(), msg)]
            },
        )
        .await;
        assert_eq!(
            n.applied(),
            Some((h(main_tip), 48)),
            "another peer's message steered the search: anchors {:?}",
            run.anchors
        );
    }

    /// The same message plus one real block far ahead (unconnectable) must not
    /// push a node that is merely behind on the same chain into a search.
    #[tokio::test]
    async fn another_peers_unconnected_message_does_not_start_a_search() {
        let net = net(6, 6, 200);
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, false, pdir.path());
        let ndir = tempfile::tempdir().expect("tempdir");
        let n = node(&net, &net.prefix, ndir.path()).await;
        let main_tip = net.main.last().expect("main");
        let body = net.prefix[0].clone();
        let far = net.main[180].clone();
        let mut tracker = RejoinTracker::new();
        let run = drive_with(
            &n,
            &mut tracker,
            &peer,
            h(main_tip),
            200,
            200,
            |node, anchor| {
                let mut msg = vec![tagged(anchor.0, &body)];
                if let Ok(Some(real)) = node.storage.blocks.get_block(&anchor.0) {
                    msg.push(real);
                }
                msg.push(far.clone());
                vec![("peer-other".to_string(), msg)]
            },
        )
        .await;
        assert_eq!(n.applied(), Some((h(main_tip), 200)));
        assert!(
            run.modes
                .iter()
                .all(|m| matches!(m, Mode::Tip { strikes: 0 })),
            "{:?}",
            run.modes
        );
    }

    /// `anchor_at_height` names the EXECUTED chain's block, not whatever the
    /// raw height index last stored at that height (a sibling that never
    /// executed and that peers may not hold).
    #[tokio::test]
    async fn probe_anchor_is_the_executed_block_not_the_last_stored() {
        let net = net(6, 14, 48);
        let ndir = tempfile::tempdir().expect("tempdir");
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let n = node(&net, &own, ndir.path()).await;
        // Store (not execute) main-chain siblings at heights 7..=14: the raw
        // height index now names them; the executed chain is still the side.
        for b in &net.main[..8] {
            n.storage.blocks.put_block(b).expect("put");
        }
        for (i, side) in net.side.iter().enumerate() {
            let height = side.header.height;
            assert_eq!(
                n.storage.blocks.get_block_by_height(height).expect("read"),
                Some(h(&net.main[i])),
                "fixture: the raw index must disagree at {height}"
            );
            assert_eq!(anchor_at_height(&n.storage, height), Some(h(side)));
        }
    }

    /// The r1006 shape, scaled down: a node sealed its own blocks from height
    /// `fork + 1` while the network built a heavier chain from the same
    /// parent. Its peer holds both branches (it stored the node's blocks as
    /// side blocks). Tip-anchored sync is answered with the node's own block
    /// plus peer blocks at the same heights, none of which connect. The node
    /// must find the fork point, fetch the heavier branch, and switch to it.
    #[tokio::test]
    async fn node_on_a_short_side_branch_rejoins_the_heavier_chain() {
        let net = net(6, 14, 48);
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, true, pdir.path());
        let ndir = tempfile::tempdir().expect("tempdir");
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let n = node(&net, &own, ndir.path()).await;
        let main_tip = net.main.last().expect("main");
        let mut tracker = RejoinTracker::new();
        let run = drive(&n, &mut tracker, &peer, h(main_tip), 48, 60).await;
        assert_eq!(
            n.applied(),
            Some((h(main_tip), 48)),
            "the node stayed on its side branch: anchors {:?}, modes {:?}",
            run.anchors,
            run.modes
        );
        assert_eq!(
            n.executor.calculate_state_root(),
            main_tip.state_root,
            "executed state is the heavier chain's"
        );
        // The search is short: a few probes, then one request per batch.
        assert!(
            run.rounds <= 20,
            "took {} rounds: {:?}",
            run.rounds,
            run.anchors
        );
    }

    /// A side branch deeper than the in-memory reorg window (100 blocks): the
    /// switch goes through the applicator's rebuild from genesis, which the
    /// periodic drain triggers. The search itself is unchanged.
    #[tokio::test]
    async fn side_branch_deeper_than_the_reorg_window_rejoins() {
        let net = net(6, 150, 400);
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, true, pdir.path());
        let ndir = tempfile::tempdir().expect("tempdir");
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let n = node(&net, &own, ndir.path()).await;
        let main_tip = net.main.last().expect("main");
        let mut tracker = RejoinTracker::new();
        let run = drive(&n, &mut tracker, &peer, h(main_tip), 400, 200).await;
        assert_eq!(
            n.applied(),
            Some((h(main_tip), 400)),
            "the node stayed on its side branch after {} rounds: anchors {:?}",
            run.rounds,
            run.anchors
        );
        assert_eq!(n.executor.calculate_state_root(), main_tip.state_root);
        // ~log2(144) probes, then one request per 32-block batch up to 400.
        assert!(
            run.rounds <= 40,
            "took {} rounds: {:?}",
            run.rounds,
            run.anchors
        );
    }

    /// Same, but the peer never received the node's blocks (the node sealed its
    /// first block before any peer connected), so every tip-anchored request
    /// comes back empty.
    #[tokio::test]
    async fn side_branch_the_peer_never_saw_still_rejoins() {
        let net = net(6, 14, 48);
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, false, pdir.path());
        let ndir = tempfile::tempdir().expect("tempdir");
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let n = node(&net, &own, ndir.path()).await;
        let main_tip = net.main.last().expect("main");
        let mut tracker = RejoinTracker::new();
        let run = drive(&n, &mut tracker, &peer, h(main_tip), 48, 60).await;
        assert_eq!(
            n.applied(),
            Some((h(main_tip), 48)),
            "the node stayed on its side branch: anchors {:?}",
            run.anchors
        );
    }

    /// Negative control: a node on the heavier chain that is merely behind
    /// syncs on the tip anchor only. No request is ever anchored below its
    /// applied tip and the tracker never leaves `Tip`.
    #[tokio::test]
    async fn node_behind_on_the_same_chain_never_searches() {
        let net = net(6, 6, 200);
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, false, pdir.path());
        let ndir = tempfile::tempdir().expect("tempdir");
        let n = node(&net, &net.prefix, ndir.path()).await;
        let main_tip = net.main.last().expect("main");
        let mut tracker = RejoinTracker::new();
        let run = drive(&n, &mut tracker, &peer, h(main_tip), 200, 200).await;
        assert_eq!(n.applied(), Some((h(main_tip), 200)));
        assert!(
            run.modes
                .iter()
                .all(|m| matches!(m, Mode::Tip { strikes: 0 })),
            "{:?}",
            run.modes
        );
        assert!(
            run.anchors.windows(2).all(|w| w[1] >= w[0]),
            "an anchor went below the previous one: {:?}",
            run.anchors
        );
    }

    // ---------------------------------------------------------------------
    // Restart with a pruned DAG store (r1006 prod-5, 2026-10-28): a node on
    // the canonical chain whose DAG store holds only the retained window
    // restarts, hears one answer it cannot connect, and then syncs. Its
    // applied tip must never move below where it restarted.
    // ---------------------------------------------------------------------

    /// Wire a node over `storage` as `start_node` does after a restart: the
    /// DAG store loaded from its persistent column families, genesis seeded,
    /// GhostDAG tips reconciled (hydration complete), the applicator seeded
    /// from the persisted applied tip with genesis wired.
    ///
    /// `boot_state`, when given, stands in for `start_node`'s world-state boot
    /// hydration (it loads every persisted account into the trie).
    async fn wire_persistent(
        storage: Arc<StorageManager>,
        g: &Block,
        boot_state: Option<citrate_execution::state::StateSnapshot>,
    ) -> (Node, Arc<DagStore>) {
        use crate::persistent_dag::RocksDbKvStore;
        let kv = Arc::new(RocksDbKvStore::new(storage.db.clone()));
        let dag = Arc::new(DagStore::persistent_with_strict_vrf(kv, false).expect("dag load"));
        dag.set_configured_genesis(g.header.block_hash);
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));
        let executor = Arc::new(Executor::with_storage_and_chain_id(
            Arc::new(StateDB::new()),
            Some(storage.state.clone()),
            CHAIN_ID,
        ));
        executor.set_pba_hardening(PbaHardening::off());
        if let Some(state) = boot_state {
            executor.state_restore(state);
        }
        let app = Arc::new(
            CanonicalApplicator::new(executor.clone(), storage.clone())
                .with_fork_choice(ghostdag.clone())
                .with_dag_prune_floor(dag.clone()),
        );
        app.set_genesis(
            Executor::new(Arc::new(StateDB::new())).state_snapshot(),
            g.header.block_hash,
        );
        let admission = Arc::new(BlockAdmission::new(
            storage.clone(),
            dag.clone(),
            ghostdag.clone(),
            Some(app.clone()),
        ));
        admission.seed_genesis().await;
        ghostdag.reconcile_tips_from_dag_store().await;
        let sync = SyncManager::new(SyncConfig::default())
            .with_local_height(app.applied_height_handle())
            .with_pba_hardening(PbaHardening::off());
        (
            Node {
                storage,
                executor,
                app,
                admission,
                sync,
                ghostdag,
            },
            dag,
        )
    }

    /// A node that applied `own`, its DAG store pruned to the last
    /// `dag_prune::MIN_RETAIN_BLOCKS` when `prune`, restarted. Returns the
    /// restarted node and its storage dir.
    async fn restarted_node(net: &Net, own: &[Block], prune: bool) -> (Node, tempfile::TempDir) {
        restarted_node_retaining(
            net,
            own,
            prune.then_some(crate::dag_prune::MIN_RETAIN_BLOCKS),
        )
        .await
    }

    /// [`restarted_node`] with the DAG store pruned to the last `retain`
    /// blocks (any window, below the node's configured minimum too).
    async fn restarted_node_retaining(
        net: &Net,
        own: &[Block],
        retain: Option<u64>,
    ) -> (Node, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage =
            Arc::new(StorageManager::new(dir.path(), PruningConfig::default()).expect("storage"));
        let g = &net.genesis;
        storage.blocks.put_block(g).expect("genesis");
        storage
            .blocks
            .put_applied_tip(&g.header.block_hash, 0)
            .expect("tip");
        let tip = own.last().expect("own blocks");
        let tip_height = tip.header.height;
        let boot_state = {
            let (n, dag) = wire_persistent(storage.clone(), g, None).await;
            let fx = n.admission.admit_to_fixpoint(own.to_vec(), |_, _| {}).await;
            assert_eq!(fx.newly_admitted, own.len(), "own blocks admit");
            n.app.drive_drain().await;
            assert_eq!(n.applied(), Some((h(tip), tip_height)), "fixture: applied");
            if let Some(retain) = retain {
                let point = tip_height - retain;
                let at = storage
                    .blocks
                    .get_canonical_block_by_height(point)
                    .expect("canonical read")
                    .expect("canonical block at the pruning point");
                dag.update_pruning_point(at).await.expect("pruning point");
                let dropped = dag.prune().await.expect("prune");
                assert!(dropped > 0, "fixture: the DAG store was pruned");
            }
            n.executor.state_snapshot()
        };
        // Restart: everything in memory is rebuilt from the stores.
        let (n, _dag) = wire_persistent(storage, g, Some(boot_state)).await;
        assert_eq!(
            n.applied(),
            Some((h(tip), tip_height)),
            "fixture: the restart seeds the applied tip"
        );
        assert_eq!(
            n.executor.calculate_state_root(),
            tip.state_root,
            "fixture: state root verified at restart"
        );
        (n, dir)
    }

    /// Records the lowest durable applied height seen while it runs: a
    /// from-genesis rebuild resets the durable tip to genesis and replays, so
    /// a poller sees it even though the rebuild finishes inside one drain.
    struct TipWatch {
        stop: Arc<std::sync::atomic::AtomicBool>,
        lowest: Arc<std::sync::atomic::AtomicU64>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl TipWatch {
        fn start(storage: Arc<StorageManager>) -> Self {
            use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
            let stop = Arc::new(AtomicBool::new(false));
            let lowest = Arc::new(AtomicU64::new(u64::MAX));
            let (s, l) = (stop.clone(), lowest.clone());
            let handle = std::thread::spawn(move || {
                while !s.load(Ordering::SeqCst) {
                    if let Ok(Some((_, h))) = storage.blocks.get_applied_tip() {
                        l.fetch_min(h, Ordering::SeqCst);
                    }
                }
            });
            Self {
                stop,
                lowest,
                handle: Some(handle),
            }
        }

        fn finish(mut self) -> u64 {
            use std::sync::atomic::Ordering;
            self.stop.store(true, Ordering::SeqCst);
            if let Some(h) = self.handle.take() {
                h.join().expect("watch thread");
            }
            self.lowest.load(Ordering::SeqCst)
        }
    }

    /// Sync after the restart, as [`drive`] does, recording the applied height
    /// after every delivered answer. `first` is delivered before the loop as an
    /// answer from `PEER` to a request the tracker did not make (the r1006
    /// missing-parent request: anchored above the applied tip).
    async fn drive_recording(
        node: &Node,
        tracker: &mut RejoinTracker,
        peer: &StorageManager,
        first: Vec<Block>,
        target: Hash,
        network_height: u64,
        max_rounds: usize,
    ) -> (Run, Vec<u64>) {
        let mut run = Run::default();
        let mut applied = Vec::new();
        let mut orphans: Vec<Block> = Vec::new();
        deliver(node, tracker, &mut orphans, PEER, first, network_height).await;
        applied.push(node.applied().expect("applied tip").1);
        while run.rounds < max_rounds {
            let tip = node.applied().expect("applied tip");
            if tip.0 == target {
                break;
            }
            run.rounds += 1;
            tracker.note_sync_target(network_height, tip.1);
            let anchor = tracker.anchor(tip, |ht| anchor_at_height(&node.storage, ht));
            tracker.note_asked(PEER, anchor);
            run.anchors.push(anchor.1);
            let answer = block_serve::serve_blocks(peer, &anchor.0, 32);
            deliver(node, tracker, &mut orphans, PEER, answer, network_height).await;
            applied.push(node.applied().expect("applied tip").1);
            run.modes.push(tracker.mode().clone());
        }
        (run, applied)
    }

    /// r1006 prod-5: restarted at its applied tip on the canonical chain with
    /// the DAG store pruned below the retained window, one barren answer
    /// (anchored above the applied tip), then ordinary sync. The applied tip
    /// never moves below the restart tip, and the node reaches the network tip.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pruned_restart_then_barren_answer_never_rewinds() {
        let tip_height = 1_200u64;
        let network_tip = tip_height + 89;
        let net = net(tip_height, tip_height, network_tip);
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, false, pdir.path());
        let (n, _ndir) = restarted_node(&net, &net.prefix, true).await;
        let main_tip = net.main.last().expect("main");
        // The barren answer: what the peer serves for an anchor 87 above the
        // applied tip (nothing in it connects).
        let barren_anchor = &net.main[86];
        let barren = block_serve::serve_blocks(&peer, &h(barren_anchor), 32);
        assert!(!barren.is_empty(), "fixture: the peer serves that range");
        let mut tracker = RejoinTracker::new();
        let (run, applied) = drive_recording(
            &n,
            &mut tracker,
            &peer,
            barren,
            h(main_tip),
            network_tip,
            200,
        )
        .await;
        let lowest = applied.iter().copied().min().unwrap_or(0);
        assert!(
            lowest >= tip_height,
            "the applied tip moved below the restart tip {tip_height}: lowest {lowest}; \
             applied {applied:?}; anchors {:?}; modes {:?}",
            run.anchors,
            run.modes
        );
        assert!(
            applied.windows(2).all(|w| w[1] >= w[0]),
            "the applied tip moved backwards: {applied:?}"
        );
        assert_eq!(
            n.applied(),
            Some((h(main_tip), network_tip)),
            "the node reaches the network tip: anchors {:?}",
            run.anchors
        );
    }

    /// The same restart, but the node's last block (its own, sealed before it
    /// stopped) never reached the network: the restart tip is one block off
    /// the heavier chain. The restart keeps the reorg window (the undo records
    /// persisted with every applied block), so the node reverts that one block
    /// and follows the heavier chain; the durable applied tip never goes below
    /// the fork point (no replay from genesis, which a pruned node refuses).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pruned_restart_one_block_off_never_rewinds_below_the_fork_point() {
        let fork = 1_199u64;
        let network_tip = fork + 90;
        let net = net(fork, fork + 1, network_tip);
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, false, pdir.path());
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let (n, _ndir) = restarted_node(&net, &own, true).await;
        let main_tip = net.main.last().expect("main");
        let barren = block_serve::serve_blocks(&peer, &h(&net.main[87]), 32);
        let watch = TipWatch::start(n.storage.clone());
        let mut tracker = RejoinTracker::new();
        let (run, applied) = drive_recording(
            &n,
            &mut tracker,
            &peer,
            barren,
            h(main_tip),
            network_tip,
            200,
        )
        .await;
        let lowest = watch
            .finish()
            .min(applied.iter().copied().min().unwrap_or(0));
        assert!(
            lowest >= fork,
            "the durable applied tip went below the fork point {fork}: lowest {lowest}; \
             applied {applied:?}; anchors {:?}",
            run.anchors
        );
        assert_eq!(
            n.applied(),
            Some((h(main_tip), network_tip)),
            "the node reorgs onto the heavier chain from its persisted reorg window: \
             anchors {:?}",
            run.anchors
        );
        assert_eq!(n.executor.calculate_state_root(), main_tip.state_root);
    }

    /// A restarted node on the canonical chain hears of a sibling of its tip
    /// (same height, same score, smaller hash: the fork-choice tie-break
    /// prefers it until the tip's children arrive). The durable applied tip
    /// must never go below the restart tip's parent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pruned_restart_tip_sibling_never_rewinds() {
        let tip_height = 1_200u64;
        let network_tip = tip_height + 89;
        let net = net(tip_height, tip_height, network_tip);
        let tip = net.prefix.last().expect("prefix");
        let parent = h(&net.prefix[net.prefix.len() - 2]);
        let sibling = loop {
            let k = crypto::generate_keypair();
            let b = seal(&k, tip_height, parent, tip.state_root);
            if h(&b) < h(tip) {
                break b;
            }
        };
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, false, pdir.path());
        let (n, _ndir) = restarted_node(&net, &net.prefix, true).await;
        let main_tip = net.main.last().expect("main");
        let watch = TipWatch::start(n.storage.clone());
        let mut tracker = RejoinTracker::new();
        let (run, applied) = drive_recording(
            &n,
            &mut tracker,
            &peer,
            vec![sibling],
            h(main_tip),
            network_tip,
            200,
        )
        .await;
        let lowest = watch
            .finish()
            .min(applied.iter().copied().min().unwrap_or(0));
        assert!(
            lowest >= tip_height - 1,
            "the durable applied tip went below {}: lowest {lowest}; applied {applied:?}; \
             anchors {:?}",
            tip_height - 1,
            run.anchors
        );
        assert_eq!(n.applied(), Some((h(main_tip), network_tip)));
    }

    // ---------------------------------------------------------------------
    // Wiring: the node's GetBlocks anchor comes from the tracker, and the
    // Blocks handler feeds it every answer it recognises.
    // ---------------------------------------------------------------------

    /// The problems with `src`'s wiring, if any.
    fn wiring_problems(src: &str) -> Vec<&'static str> {
        let mut out = Vec::new();
        let tick = src.find("let applied_tip = storage_for_sync");
        let anchor = src.find(".anchor(applied_tip,");
        let request = src.find(".request_blocks(&peer, block_from, block_height)");
        let asked = src.find(".note_asked(&pid.0, (block_from, block_height))");
        match (tick, anchor, request, asked) {
            (Some(t), Some(a), Some(r), Some(n)) if t < a && a < r && r < n => {}
            _ => out.push("sync tick: GetBlocks anchor must come from RejoinTracker::anchor"),
        }
        match (src.find("} else if matches!(sent, Ok(true)) {"), asked) {
            (Some(g), Some(n)) if g < n && src[g..n].lines().count() < 6 => {}
            _ => {
                out.push("sync tick: note_asked must run only when request_blocks sent (Ok(true))")
            }
        }
        match (src.find(".note_sync_target(target, applied_tip.1)"), anchor) {
            (Some(t), Some(a)) if t < a => {}
            _ => {
                out.push("sync tick: the tracker must get the clamped sync target before anchor()")
            }
        }
        // Split healing: the tick's source comes from `choose_source` (a
        // running search stays on its peer; equal-height siblings are pulled),
        // never from the selector alone.
        match (src.find("sync_rejoin::choose_source("), tick) {
            (Some(c), Some(t)) if c < t => {}
            _ => out.push("sync tick: the request peer must come from sync_rejoin::choose_source"),
        }
        if src.contains(".select(&candidates,") {
            out.push("sync tick: the selector is asked directly, bypassing a pinned search");
        }
        if src.contains(".request_blocks(&peer, start_from, start_height)") {
            out.push("sync tick: a GetBlocks still anchored on the applied tip directly");
        }
        let arm = src.find("NetworkMessage::Blocks { blocks } => {");
        let handle = arm.and_then(|a| src[a..].find(".handle_blocks(&pid, blocks)").map(|i| a + i));
        let take = src.find(".take_answer(");
        let judge = src.find(".on_answer(answer, gap > 0, anchor_height)");
        match (arm, handle, take, judge) {
            // Matched AFTER validation, on the validated set.
            (Some(a), Some(hb), Some(t), Some(j)) if a < hb && hb < t && t < j => {}
            _ => out.push("Blocks handler: answers must reach RejoinTracker::on_answer"),
        }
        if let Some(t) = take {
            if !src[t..]
                .get(..200)
                .unwrap_or("")
                .contains("&verified_hashes")
            {
                out.push("Blocks handler: take_answer must match on the validated hashes");
            }
        }
        if !src.contains(".admit_to_fixpoint(pending,") {
            out.push("Blocks handler: admission must use BlockAdmission::admit_to_fixpoint");
        }
        out
    }

    #[test]
    fn start_node_wiring() {
        assert_eq!(wiring_problems(include_str!("main.rs")), Vec::<&str>::new());
    }

    /// A same-height sibling of `tip` sealed by a fresh key whose hash is
    /// smaller: equal blue score, so the fork-choice tie-break prefers it.
    fn tie_winning_sibling(tip: &Block, parent: Hash) -> Block {
        loop {
            let k = crypto::generate_keypair();
            let b = seal(&k, tip.header.height, parent, tip.state_root);
            if h(&b) < h(tip) {
                break b;
            }
        }
    }

    /// Every node, pruned or not: a restarted node on the canonical chain
    /// hears one same-height sibling of its restart tip that wins the
    /// tie-break. An equal-weight head never triggers a rebuild from genesis.
    /// The restart keeps the reorg window, so the node follows the tie-break
    /// as a running node does (a one-block reorg): the durable applied tip
    /// never goes below the fork point, the restart tip's parent, and the
    /// node converges as the tip's children arrive.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unpruned_restart_tip_sibling_never_rewinds() {
        let tip_height = 1_200u64;
        let network_tip = tip_height + 89;
        let net = net(tip_height, tip_height, network_tip);
        let tip = net.prefix.last().expect("prefix");
        let sibling = tie_winning_sibling(tip, h(&net.prefix[net.prefix.len() - 2]));
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, false, pdir.path());
        let (n, _ndir) = restarted_node(&net, &net.prefix, false).await;
        let main_tip = net.main.last().expect("main");
        let watch = TipWatch::start(n.storage.clone());
        let mut tracker = RejoinTracker::new();
        let (run, applied) = drive_recording(
            &n,
            &mut tracker,
            &peer,
            vec![sibling],
            h(main_tip),
            network_tip,
            200,
        )
        .await;
        let lowest = watch
            .finish()
            .min(applied.iter().copied().min().unwrap_or(0));
        assert!(
            lowest >= tip_height - 1,
            "the durable applied tip went below the fork point {}: lowest {lowest}; \
             applied {applied:?}; anchors {:?}",
            tip_height - 1,
            run.anchors
        );
        assert_eq!(n.applied(), Some((h(main_tip), network_tip)));
        assert_eq!(n.executor.calculate_state_root(), main_tip.state_root);
    }

    /// Control: an unpruned node restarted on a side branch deeper than the
    /// reorg window, off a genuinely heavier chain, still rebuilds onto it
    /// (the from-genesis rebuild is kept for a strictly heavier head).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unpruned_restart_deeper_than_the_window_still_rebuilds_onto_the_heavier_chain() {
        let fork = 1_199u64;
        let side_tip = fork + crate::canonical_apply::MAX_REORG_DEPTH + 5;
        let network_tip = side_tip + 90;
        let net = net(fork, side_tip, network_tip);
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, false, pdir.path());
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let (n, _ndir) = restarted_node(&net, &own, false).await;
        let main_tip = net.main.last().expect("main");
        let barren = block_serve::serve_blocks(&peer, &h(&net.main[87]), 32);
        let watch = TipWatch::start(n.storage.clone());
        let mut tracker = RejoinTracker::new();
        let (run, _applied) = drive_recording(
            &n,
            &mut tracker,
            &peer,
            barren,
            h(main_tip),
            network_tip,
            200,
        )
        .await;
        let lowest = watch.finish();
        assert_eq!(
            n.applied(),
            Some((h(main_tip), network_tip)),
            "the node rebuilds onto the heavier chain: anchors {:?}",
            run.anchors
        );
        assert_eq!(n.executor.calculate_state_root(), main_tip.state_root);
        assert!(
            lowest < fork,
            "control: the switch went through the from-genesis rebuild (lowest {lowest})"
        );
    }

    /// The rebuild itself re-checks the weight: asked to rebuild toward an
    /// equal-weight sibling (bypassing the drain's check), an unpruned node
    /// keeps its tip.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_rebuild_refuses_an_equal_weight_head() {
        // An equal-length rival branch forking deeper than the reorg window:
        // only a rebuild from genesis could switch to it.
        let fork = 1_200u64 - crate::canonical_apply::MAX_REORG_DEPTH - 5;
        let net = net(fork, 1_200, 1_200);
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let (n, _ndir) = restarted_node(&net, &own, false).await;
        let fx = n
            .admission
            .admit_to_fixpoint(net.main.clone(), |_, _| {})
            .await;
        assert_eq!(
            fx.newly_admitted,
            net.main.len(),
            "fixture: the rival admits"
        );
        let rival = net.main.last().expect("main");
        let watch = TipWatch::start(n.storage.clone());
        n.app.maybe_runtime_rebuild(h(rival)).await;
        let lowest = watch.finish();
        assert!(
            lowest >= 1_200,
            "rebuilt toward an equal-weight head: {lowest}"
        );
        assert_eq!(
            n.applied(),
            Some((h(net.side.last().expect("side")), 1_200))
        );
    }

    /// The rebuild itself re-checks the prune floor: asked to rebuild toward
    /// a heavier head (bypassing the drain's check), a pruned node keeps its
    /// tip.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runtime_rebuild_refuses_on_a_pruned_node() {
        // The node's own branch is deeper than the reorg window.
        let fork = 1_199u64;
        let side_tip = fork + crate::canonical_apply::MAX_REORG_DEPTH + 5;
        let net = net(fork, side_tip, side_tip + 40);
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let (n, _ndir) = restarted_node(&net, &own, true).await;
        let fx = n
            .admission
            .admit_to_fixpoint(net.main.clone(), |_, _| {})
            .await;
        assert_eq!(fx.newly_admitted, net.main.len(), "fixture: main admits");
        let main_tip = net.main.last().expect("main");
        let watch = TipWatch::start(n.storage.clone());
        n.app.maybe_runtime_rebuild(h(main_tip)).await;
        let lowest = watch.finish();
        assert!(lowest > fork, "rebuilt on a pruned node: {lowest}");
        assert_eq!(
            n.applied(),
            Some((h(net.side.last().expect("side")), side_tip))
        );
    }

    /// A restarted node whose DAG store is pruned to a small window (50
    /// blocks at height 500) sits on its own branch, 40 blocks off a heavier
    /// chain. It switches by a bounded reorg from its persisted reorg window:
    /// the durable tip never goes below the fork point, and it ends on the
    /// heavier chain's state. (Before, the switch needed a replay from
    /// genesis, which a pruned node refuses: the node held its tip forever.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pruned_restart_40_off_reorgs_within_the_window() {
        let fork = 460u64;
        let net = net(fork, 500, 530);
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let (n, _ndir) = restarted_node_retaining(&net, &own, Some(50)).await;
        let fx = n
            .admission
            .admit_to_fixpoint(net.main.clone(), |_, _| {})
            .await;
        assert_eq!(fx.newly_admitted, net.main.len(), "fixture: main admits");
        let main_tip = net.main.last().expect("main");
        let watch = TipWatch::start(n.storage.clone());
        n.app.drive_drain().await;
        let lowest = watch.finish();
        assert!(
            lowest >= fork,
            "the durable tip went below the fork point {fork}: {lowest}"
        );
        assert_eq!(
            n.applied(),
            Some((h(main_tip), 530)),
            "the pruned node switches to the heavier chain"
        );
        assert_eq!(n.executor.calculate_state_root(), main_tip.state_root);
    }

    /// The same pruned node (150 retained) with its fork point deeper than the
    /// reorg window (105 below its tip): still refused, as before. The node keeps its tip
    /// and its state; an operator resync moves it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pruned_restart_deeper_than_the_window_still_refuses() {
        let fork = 395u64;
        let net = net(fork, 500, 530);
        let own: Vec<Block> = net.prefix.iter().chain(net.side.iter()).cloned().collect();
        let (n, _ndir) = restarted_node_retaining(&net, &own, Some(150)).await;
        let fx = n
            .admission
            .admit_to_fixpoint(net.main.clone(), |_, _| {})
            .await;
        assert_eq!(fx.newly_admitted, net.main.len(), "fixture: main admits");
        let own_tip = net.side.last().expect("side");
        let root = n.executor.calculate_state_root();
        let watch = TipWatch::start(n.storage.clone());
        n.app.drive_drain().await;
        let lowest = watch.finish();
        assert_eq!(lowest, 500, "the durable tip never moved");
        assert_eq!(n.applied(), Some((h(own_tip), 500)));
        assert_eq!(n.executor.calculate_state_root(), root);
    }

    /// The node's applicator is built with the DAG prune floor wired, on the
    /// same DAG store fork choice reads: without it a pruned node rebuilds
    /// from genesis after a restart (see the `pruned_restart_*` tests).
    #[test]
    fn start_node_wires_the_dag_prune_floor() {
        let src = include_str!("main.rs");
        let build = src
            .find("canonical_apply::CanonicalApplicator::new(executor.clone(), storage.clone())")
            .expect("applicator construction");
        let tail = src.get(build..).expect("slice");
        let end = tail.find(';').expect("end of statement");
        let stmt = tail.get(..end).expect("statement");
        assert!(
            stmt.contains(".with_fork_choice(shared_ghostdag.clone())")
                && stmt.contains(".with_dag_prune_floor(shared_dag_store.clone())"),
            "the applicator must be built with the DAG prune floor: {stmt}"
        );
        assert!(
            src.contains("GhostDag::new(\n        GhostDagParams::default(),\n        shared_dag_store.clone(),"),
            "fork choice and the prune floor must read the same DAG store"
        );
    }

    /// Negative control: the pre-fix tick (anchored on the applied tip) and a
    /// handler that never judges answers are both caught.
    #[test]
    fn wiring_check_catches_the_old_tick() {
        let main = include_str!("main.rs");
        let old_tick = main.replace(
            ".request_blocks(&peer, block_from, block_height)",
            ".request_blocks(&peer, start_from, start_height)",
        );
        assert!(!wiring_problems(&old_tick).is_empty());
        let no_judge = main.replace(".on_answer(answer, gap > 0, anchor_height)", ".ignore()");
        assert!(!wiring_problems(&no_judge).is_empty());
        // note_asked on any Ok (a suppressed request counted as asked).
        let any_ok = main.replace("} else if matches!(sent, Ok(true)) {", "} else {");
        assert!(!wiring_problems(&any_ok).is_empty());
        // Gossip-only "behind".
        let gossip_only = main.replace(".note_sync_target(target, applied_tip.1)", ".len()");
        assert!(!wiring_problems(&gossip_only).is_empty());
    }

    // ---------------------------------------------------------------------
    // The state machine on its own.
    // ---------------------------------------------------------------------

    fn hx(n: u8) -> Hash {
        Hash::new([n; 32])
    }

    fn progress() -> Answer {
        Answer::Progress {
            highest: (hx(9), 0),
        }
    }

    /// Model of an honest peer holding the heavier chain: an answer anchored at
    /// `h` connects iff `h <= fork + 1`, and holds only known blocks iff it
    /// ends below the fork (`h + span < fork`).
    fn model(fork: u64, span: u64, h: u64) -> Answer {
        if h.saturating_add(span) < fork {
            Answer::Known
        } else if h <= fork + 1 {
            Answer::Progress {
                highest: (hx(7), h + span),
            }
        } else {
            Answer::Unconnected
        }
    }

    fn search(fork: u64, top: u64, span: u64) -> (usize, Mode) {
        let mut t = RejoinTracker::new();
        for _ in 0..PROBE_AFTER_STRIKES {
            t.on_answer(Answer::Unconnected, true, top);
        }
        let mut probes = 0usize;
        loop {
            let (_, at) = t.anchor((hx(1), top), |_| Some(hx(2)));
            if !matches!(t.mode(), Mode::Probe { .. }) {
                return (probes, t.mode().clone());
            }
            probes += 1;
            assert!(probes < 200, "search did not end");
            t.on_answer(model(fork, span, at), true, at);
        }
    }

    /// r1006 numbers: fork at 38, own tip at 3,353. The search ends in the
    /// follow mode within a logarithmic number of probes, from any depth.
    #[test]
    fn fork_point_search_is_logarithmic() {
        for (fork, top) in [
            (38u64, 3_353u64),
            (0, 1_000_000),
            (999_990, 1_000_000),
            (5, 7),
        ] {
            for span in [0u64, 1, 10, 31] {
                let (probes, mode) = search(fork, top, span);
                assert!(
                    matches!(mode, Mode::Follow { .. }),
                    "fork {fork} top {top} span {span}: ended in {mode:?}"
                );
                let bound = 2 * (64 - (top - fork).leading_zeros() as usize) + 2;
                assert!(
                    probes <= bound,
                    "fork {fork} top {top}: {probes} probes > {bound}"
                );
            }
        }
    }

    #[test]
    fn one_unconnected_answer_does_not_start_a_search() {
        let mut t = RejoinTracker::new();
        assert_eq!(t.on_answer(Answer::Unconnected, true, 50), None);
        assert_eq!(t.mode(), &Mode::Tip { strikes: 1 });
        t.on_answer(Answer::Known, true, 50);
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
        t.on_answer(Answer::Unconnected, true, 51);
        assert_eq!(
            t.on_answer(Answer::Unconnected, true, 52),
            Some(Transition::StartedProbe { top: 52 })
        );
    }

    #[test]
    fn not_behind_never_searches_and_ends_a_search() {
        let mut t = RejoinTracker::new();
        for _ in 0..10 {
            t.on_answer(Answer::Unconnected, false, 50);
        }
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
        t.on_answer(Answer::Unconnected, true, 50);
        t.on_answer(Answer::Unconnected, true, 50);
        assert!(matches!(t.mode(), Mode::Probe { .. }));
        assert_eq!(
            t.on_answer(Answer::Unconnected, false, 49),
            Some(Transition::Finished { from: "caught up" })
        );
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
    }

    /// Only the answer to the anchor we asked moves the tracker: a `Blocks`
    /// message without that block, or an empty one from another peer, does
    /// not count, and one request is consumed at most once.
    #[test]
    fn only_the_answer_to_our_anchor_counts() {
        let set = |hs: &[Hash]| hs.iter().copied().collect::<HashSet<Hash>>();
        let mut t = RejoinTracker::new();
        assert_eq!(
            t.take_answer(PEER, &[], &set(&[])),
            None,
            "nothing asked yet"
        );
        t.note_asked(PEER, (hx(3), 40));
        assert_eq!(
            t.take_answer("other", &[], &set(&[])),
            None,
            "empty, other peer"
        );
        assert_eq!(
            t.take_answer(PEER, &[hx(4), hx(5)], &set(&[hx(4), hx(5)])),
            None,
            "anchor absent"
        );
        assert_eq!(
            t.take_answer("other", &[hx(4), hx(3)], &set(&[hx(4), hx(3)])),
            None,
            "the anchor block from another peer"
        );
        assert_eq!(
            t.take_answer(PEER, &[hx(3)], &set(&[])),
            None,
            "the anchor hash on a block that failed validation"
        );
        assert_eq!(
            t.take_answer(PEER, &[hx(4), hx(3)], &set(&[hx(4), hx(3)])),
            Some(40)
        );
        assert_eq!(
            t.take_answer(PEER, &[hx(3)], &set(&[hx(3)])),
            None,
            "consumed"
        );
        t.note_asked(PEER, (hx(3), 41));
        assert_eq!(
            t.take_answer(PEER, &[], &set(&[])),
            Some(41),
            "empty from the asked peer"
        );
    }

    /// A probe answer for a height other than the one being probed (sent before
    /// the probe moved) is ignored.
    #[test]
    fn stale_probe_answers_are_ignored() {
        let mut t = RejoinTracker::new();
        t.on_answer(Answer::Unconnected, true, 100);
        t.on_answer(Answer::Unconnected, true, 100);
        let before = t.mode().clone();
        assert!(matches!(before, Mode::Probe { height: 99, .. }));
        assert_eq!(t.on_answer(Answer::Known, true, 100), None);
        assert_eq!(t.mode(), &before);
    }

    /// A peer that answers every probe empty (it holds nothing we hold, or
    /// lies) cannot keep the node searching: the search walks to genesis in
    /// log steps and gives up, back to the tip anchor.
    #[test]
    fn a_peer_that_never_connects_ends_the_search_at_genesis() {
        let mut t = RejoinTracker::new();
        t.on_answer(Answer::Unconnected, true, 1_000_000);
        t.on_answer(Answer::Unconnected, true, 1_000_000);
        let mut steps = 0;
        let last = loop {
            let (_, at) = t.anchor((hx(1), 1_000_000), |_| Some(hx(2)));
            steps += 1;
            assert!(steps < 64, "did not give up");
            if let Some(tr) = t.on_answer(Answer::Unconnected, true, at) {
                break tr;
            }
        };
        assert_eq!(last, Transition::GaveUp { at: 0 });
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
    }

    /// A probe height this node cannot name a block for ends the search.
    #[test]
    fn an_unresolvable_probe_height_falls_back_to_the_tip() {
        let mut t = RejoinTracker::new();
        t.on_answer(Answer::Unconnected, true, 10);
        t.on_answer(Answer::Unconnected, true, 10);
        assert_eq!(t.anchor((hx(1), 10), |_| None), (hx(1), 10));
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
    }

    /// Following ends when an answer brings nothing new; the cursor never
    /// moves down.
    #[test]
    fn follow_advances_and_ends_when_nothing_new() {
        let mut t = RejoinTracker::new();
        t.on_answer(Answer::Unconnected, true, 10);
        t.on_answer(Answer::Unconnected, true, 10);
        t.on_answer(
            Answer::Progress {
                highest: (hx(5), 20),
            },
            true,
            9,
        );
        assert_eq!(
            t.mode(),
            &Mode::Follow {
                cursor: (hx(5), 20)
            }
        );
        t.on_answer(
            Answer::Progress {
                highest: (hx(6), 18),
            },
            true,
            20,
        );
        assert_eq!(
            t.mode(),
            &Mode::Follow {
                cursor: (hx(5), 20)
            }
        );
        assert_eq!(t.anchor((hx(1), 10), |_| None), (hx(5), 20));
        assert_eq!(
            t.on_answer(Answer::Known, true, 20),
            Some(Transition::Finished { from: "follow" })
        );
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
    }

    #[test]
    fn classify_answers() {
        assert_eq!(classify(true, 0, None, 0), Answer::Unconnected);
        assert_eq!(classify(false, 0, None, 3), Answer::Unconnected);
        assert_eq!(classify(false, 0, None, 0), Answer::Known);
        assert_eq!(
            classify(false, 2, Some((hx(1), 9)), 5),
            Answer::Progress {
                highest: (hx(1), 9)
            }
        );
    }

    #[test]
    fn progress_on_the_tip_anchor_keeps_the_tip() {
        let mut t = RejoinTracker::new();
        t.on_answer(Answer::Unconnected, true, 10);
        assert_eq!(t.on_answer(progress(), true, 10), None);
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
    }

    /// After a search gives up, the next one waits out a backoff that doubles
    /// per consecutive give-up and is capped; catching up clears it.
    #[test]
    fn a_search_that_gives_up_backs_off_before_the_next() {
        let mut t = RejoinTracker::new();
        let mut waits = Vec::new();
        for _ in 0..10 {
            // Answers until a search starts.
            let mut answers = 0u32;
            loop {
                answers += 1;
                assert!(answers < 10_000, "never searched again");
                if let Some(Transition::StartedProbe { .. }) =
                    t.on_answer(Answer::Unconnected, true, 1_000)
                {
                    break;
                }
            }
            waits.push(answers);
            // A peer that never connects: the search walks to genesis.
            loop {
                let (_, at) = t.anchor((hx(1), 1_000), |_| Some(hx(2)));
                if let Some(Transition::GaveUp { .. }) = t.on_answer(Answer::Unconnected, true, at)
                {
                    break;
                }
            }
        }
        let p = PROBE_AFTER_STRIKES;
        assert_eq!(waits[0], p, "first search needs only the strikes");
        assert_eq!(waits[1], p + BACKOFF_BASE_ANSWERS);
        assert_eq!(waits[2], p + 2 * BACKOFF_BASE_ANSWERS);
        assert!(waits.windows(2).all(|w| w[1] >= w[0]), "{waits:?}");
        assert_eq!(
            *waits.last().expect("waits"),
            p + BACKOFF_MAX_ANSWERS,
            "{waits:?}"
        );
        // Caught up: no backoff owed.
        t.on_answer(Answer::Unconnected, false, 1_000);
        assert_eq!(t.cooldown(), 0);
    }

    /// A search that finds the fork point clears the backoff.
    #[test]
    fn finding_the_fork_point_clears_the_backoff() {
        let mut t = RejoinTracker::new();
        t.on_answer(Answer::Unconnected, true, 10);
        t.on_answer(Answer::Unconnected, true, 10);
        loop {
            let (_, at) = t.anchor((hx(1), 10), |_| Some(hx(2)));
            if t.on_answer(Answer::Unconnected, true, at).is_some() {
                break;
            }
        }
        assert_eq!(t.cooldown(), BACKOFF_BASE_ANSWERS);
        for _ in 0..BACKOFF_BASE_ANSWERS + PROBE_AFTER_STRIKES {
            t.on_answer(Answer::Unconnected, true, 10);
        }
        assert!(matches!(t.mode(), Mode::Probe { .. }));
        let (_, at) = t.anchor((hx(1), 10), |_| Some(hx(2)));
        t.on_answer(
            Answer::Progress {
                highest: (hx(5), 12),
            },
            true,
            at,
        );
        t.on_answer(Answer::Known, true, 12);
        // Next trouble: searched again after just the strikes.
        t.on_answer(Answer::Unconnected, true, 10);
        assert!(t.on_answer(Answer::Unconnected, true, 10).is_some());
    }

    #[test]
    fn rejoin_log_lines_are_budgeted() {
        let mut b = RejoinLogBudget::new();
        let t0 = Instant::now();
        for _ in 0..REJOIN_LOG_PER_WINDOW {
            assert_eq!(b.allow(t0), Some(0));
        }
        for _ in 0..5 {
            assert_eq!(b.allow(t0 + Duration::from_secs(1)), None);
        }
        assert_eq!(
            b.allow(t0 + REJOIN_LOG_WINDOW),
            Some(5),
            "reports the suppressed count"
        );
        assert_eq!(b.allow(t0 + REJOIN_LOG_WINDOW), Some(0));
    }

    /// A search whose requests never get a matching answer gives up after
    /// MAX_UNANSWERED ticks instead of holding its anchor forever.
    #[test]
    fn a_search_without_answers_gives_up() {
        let mut t = RejoinTracker::new();
        t.on_answer(Answer::Unconnected, true, 10);
        t.on_answer(Answer::Unconnected, true, 10);
        let mut ticks = 0;
        let last = loop {
            ticks += 1;
            assert!(ticks <= MAX_UNANSWERED + 1, "never gave up");
            let a = t.anchor((hx(1), 10), |_| Some(hx(2)));
            if let Some(tr) = t.note_asked(PEER, a) {
                break tr;
            }
            // An answer from the asked peer that is not for this anchor.
            assert_eq!(
                t.take_answer(PEER, &[hx(8)], &[hx(8)].into_iter().collect()),
                None
            );
        };
        assert!(matches!(last, Transition::GaveUp { .. }));
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
        // In Tip mode unanswered requests are the ordinary penalty box's job.
        for _ in 0..3 * MAX_UNANSWERED {
            assert_eq!(t.note_asked(PEER, (hx(1), 10)), None);
        }
    }

    // ---------------------------------------------------------------------
    // No rewind below a verified tip after a restart (r1006, 2026-10-28).
    //
    // A producer restarted at applied height 99,591 with DAG pruning on.
    // Within a second of its first sync answer its applied tip started over
    // from genesis and climbed at ~27 blocks/s; the stall watchdog killed the
    // process at 2,331 and that height was durable. After a restart the reorg
    // snapshot ring holds only the applied tip, so ANY fork-choice head that is
    // not a descendant of it (a same-height sibling, an ancestor, a branch one
    // block below) walked past the ring and was reported `BeyondReorgWindow`,
    // and the runtime fallback rebuilt the applied state from genesis. That
    // rebuild resets the durable tip to genesis first and holds the advance
    // lock for the whole replay, so the receive path stalls behind it.
    // ---------------------------------------------------------------------

    /// Applied height at or above which the restarted fixtures sit.
    const RESTART_TIP: u64 = 1_200;
    /// DAG retention the restarted fixtures prune to (`dag_prune` floor).
    const RESTART_RETAIN: u64 = 1_000;

    /// One chain `1..=n` sealed by `key` on `genesis`, with its roots.
    fn chain(key: &ed25519_dalek::SigningKey, g: &Block, n: u64, r: &[Hash]) -> Vec<Block> {
        extend(key, h(g), 1, n, r)
    }

    /// A block at `height` on `parent` sealed by `key` whose hash sorts on the
    /// `below` side of `than` (fork choice breaks equal-score ties toward the
    /// SMALLEST hash). Same transactions and coinbase as the chain, so the
    /// same state root.
    fn sibling(
        key: &ed25519_dalek::SigningKey,
        height: u64,
        parent: Hash,
        root: Hash,
        than: Hash,
        below: bool,
    ) -> Block {
        for salt in 1..=u16::MAX {
            let mut b = seal(key, height, parent, root);
            // Vary the VRF output (no transactions read it) rather than the
            // timestamp, which must stay parent-monotonic for its children.
            let mut out = [0x5A; 32];
            out[..2].copy_from_slice(&salt.to_be_bytes());
            b.header.vrf_reveal.output = Hash::new(out);
            b.header.block_hash = b.compute_hash();
            b.signature = crypto::sign_block(&b.header.block_hash, key);
            if (b.header.block_hash < than) == below {
                return b;
            }
        }
        panic!("no sibling hash on the requested side");
    }

    /// The node after a restart, built the way `start_node` builds one over an
    /// existing data dir: the SAME executor and store (state as of the applied
    /// tip), a fresh `CanonicalApplicator` (its reorg ring holds only the
    /// applied tip), a fresh DAG store holding only the range DAG pruning
    /// retains (`[tip - retain, tip]`, pruning point set), GhostDAG rehydrated
    /// from the chain store block by block and reconciled (marks hydration),
    /// and genesis wired for the runtime rebuild.
    async fn restart(
        before: &Node,
        g: &Block,
        retain: u64,
    ) -> (Node, Arc<GhostDag>, Arc<DagStore>) {
        let (tip_hash, tip_height) = before.applied().expect("applied tip");
        let point = tip_height.saturating_sub(retain);
        let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
        dag.set_configured_genesis(h(g));
        let ghostdag = Arc::new(GhostDag::new(GhostDagParams::default(), dag.clone()));
        // Producer rehydration: every stored height is registered with GhostDAG;
        // only the retained range is in the DAG store (below the pruning point
        // the store write fails in production: no parent for the VRF check).
        let mut walk = Vec::new();
        let mut cursor = tip_hash;
        while let Some(b) = before.storage.blocks.get_block(&cursor).expect("read") {
            cursor = b.selected_parent();
            let at_genesis = b.header.height == 0;
            walk.push(b);
            if at_genesis {
                break;
            }
        }
        walk.reverse();
        for b in &walk {
            if b.header.height >= point {
                dag.store_block(b.clone()).await.expect("retained block");
            }
            ghostdag.register_existing_block(b).await.expect("register");
        }
        let point_hash = walk
            .iter()
            .find(|b| b.header.height == point)
            .map(h)
            .expect("pruning point");
        dag.update_pruning_point(point_hash).await.expect("point");
        ghostdag.reconcile_tips_from_dag_store().await;
        let app = Arc::new(
            CanonicalApplicator::new(before.executor.clone(), before.storage.clone())
                .with_fork_choice(ghostdag.clone()),
        );
        app.set_genesis(
            Executor::new(Arc::new(StateDB::new())).state_snapshot(),
            h(g),
        );
        assert_eq!(
            app.applied_tip().await.height,
            tip_height,
            "restart seeds the applied tip"
        );
        let admission = Arc::new(BlockAdmission::new(
            before.storage.clone(),
            dag.clone(),
            ghostdag.clone(),
            Some(app.clone()),
        ));
        let sync = SyncManager::new(SyncConfig::default())
            .with_local_height(app.applied_height_handle())
            .with_pba_hardening(PbaHardening::off());
        (
            Node {
                storage: before.storage.clone(),
                executor: before.executor.clone(),
                app,
                admission,
                sync,
                ghostdag: ghostdag.clone(),
            },
            ghostdag,
            dag,
        )
    }

    /// Lowest DURABLE applied height seen while `f` runs, sampled from a
    /// separate OS thread (a crash at any moment leaves exactly that height).
    async fn lowest_durable_tip_during<F: std::future::Future>(
        storage: &Arc<StorageManager>,
        f: F,
    ) -> (F::Output, u64) {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        let stop = Arc::new(AtomicBool::new(false));
        let low = Arc::new(AtomicU64::new(u64::MAX));
        let sampler = {
            let (stop, low, storage) = (stop.clone(), low.clone(), storage.clone());
            std::thread::spawn(move || loop {
                if let Ok(Some((_, height))) = storage.blocks.get_applied_tip() {
                    low.fetch_min(height, Ordering::SeqCst);
                }
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::yield_now();
            })
        };
        let out = f.await;
        stop.store(true, Ordering::SeqCst);
        sampler.join().expect("sampler");
        (out, low.load(Ordering::SeqCst))
    }

    /// RED (r1006 2026-10-28), the incident end to end (DGX). A node on the
    /// canonical chain restarts at height N with DAG pruning on. One peer
    /// advertises a higher head and answers the tip anchor with nothing (it
    /// never held the node's tip); when the fork-point search probes below the
    /// tip it serves a validly signed sibling of the tip that fork choice ranks
    /// first (equal score, smaller hash). The restart keeps the reorg window,
    /// so the node follows the tie-break as a running node does: a one-block
    /// reorg. An equal-weight head never starts a from-genesis rebuild (owner
    /// decision 2026-10-28): the durable applied tip never goes below the fork
    /// point and no rebuild runs. (A legitimate rebuild must not stall the
    /// receive path: `the_receive_path_does_not_wait_on_a_rebuild`.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn restarted_node_keeps_its_verified_height_through_a_rebuild() {
        let key = crypto::generate_keypair();
        let other = crypto::generate_keypair();
        let r = roots(RESTART_TIP, &key);
        let g = genesis();
        let own = chain(&key, &g, RESTART_TIP, &r);
        let tip = own.last().expect("tip").clone();
        let parent = own[own.len() - 2].header.block_hash;
        // Validly signed by another proposer, same height and parent, smaller hash.
        let rival = sibling(
            &other,
            RESTART_TIP,
            parent,
            r[RESTART_TIP as usize],
            h(&tip),
            true,
        );
        let net = Net {
            genesis: g.clone(),
            prefix: own[..own.len() - 1].to_vec(),
            main: vec![rival.clone()],
            side: Vec::new(),
        };
        // The peer holds the common prefix and the rival, not the node's tip.
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = Arc::new(peer_store(&net, false, pdir.path()));
        let ndir = tempfile::tempdir().expect("tempdir");
        let before = node(&net, &own, ndir.path()).await;
        let (n, _, _) = restart(&before, &g, RESTART_RETAIN).await;
        let flag = n.app.rebuild_in_progress_handle();
        let (run, lowest) = lowest_durable_tip_during(&n.storage, async {
            let mut tracker = RejoinTracker::new();
            drive_advertised(&n, &mut tracker, &peer, h(&rival), RESTART_TIP + 89, 24).await
        })
        .await;
        assert!(
            lowest >= RESTART_TIP - 1,
            "the durable applied tip dropped to {lowest}, below the fork point {}: \
             anchors {:?}",
            RESTART_TIP - 1,
            run.anchors
        );
        assert!(!flag.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            n.applied(),
            Some((h(&rival), RESTART_TIP)),
            "the node follows the tie-break by a one-block reorg, as a running node does"
        );
    }

    /// RED. After a restart with pruned DAG history, a fork-choice head that is
    /// an ANCESTOR of the applied tip (below the DAG pruning point, so nothing
    /// but the chain store knows it) is not a fork: the applied chain already
    /// contains it. The drain must leave the applied tip where it is.
    #[tokio::test]
    async fn a_pruned_applied_ancestor_is_never_a_rebuild_target() {
        let key = crypto::generate_keypair();
        let r = roots(RESTART_TIP, &key);
        let g = genesis();
        let own = chain(&key, &g, RESTART_TIP, &r);
        let net = Net {
            genesis: g.clone(),
            prefix: own.clone(),
            main: Vec::new(),
            side: Vec::new(),
        };
        let ndir = tempfile::tempdir().expect("tempdir");
        let before = node(&net, &own, ndir.path()).await;
        let (n, _, _) = restart(&before, &g, RESTART_RETAIN).await;
        let ancestor = &own[149]; // height 150, below the pruning point (200)
        let head = Arc::new(parking_lot::Mutex::new(Some(h(ancestor))));
        let app = CanonicalApplicator::new(n.executor.clone(), n.storage.clone())
            .with_fork_choice_cell(head);
        app.set_genesis(
            Executor::new(Arc::new(StateDB::new())).state_snapshot(),
            h(&g),
        );
        app.drive_drain().await;
        assert_eq!(
            n.applied(),
            Some((h(own.last().expect("tip")), RESTART_TIP)),
            "the applied chain was rewound to its own ancestor"
        );
    }

    /// RED. While a rebuild holds the advance lock, the receive path (block
    /// admission -> `apply_received`) must not wait for it: the P2P handler
    /// stalled behind the rebuild and the stall watchdog exited the node
    /// mid-replay, which is how the rewound height became durable.
    #[tokio::test]
    async fn the_receive_path_does_not_wait_on_a_rebuild() {
        let key = crypto::generate_keypair();
        let r = roots(40, &key);
        let g = genesis();
        let own = chain(&key, &g, 40, &r);
        let net = Net {
            genesis: g.clone(),
            prefix: own[..30].to_vec(),
            main: Vec::new(),
            side: Vec::new(),
        };
        let ndir = tempfile::tempdir().expect("tempdir");
        let n = node(&net, &own[..30], ndir.path()).await;
        let flag = n.app.rebuild_in_progress_handle();
        let lock = n.app.advance_lock();
        // A rebuild in progress: flag set, advance lock held.
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        let held = lock.lock().await;
        let answered = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            n.app.apply_received(&own[30]),
        )
        .await;
        drop(held);
        flag.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(
            matches!(answered, Ok(ApplyOutcome::Deferred)),
            "the receive path waited on the rebuild: {answered:?}"
        );
        // Once the rebuild is over, the drain applies what was deferred.
        n.storage.blocks.put_block(&own[30]).expect("put");
        n.app.drive_drain().await;
        assert_eq!(n.applied(), Some((h(&own[30]), 31)));
    }

    /// RED. A fork-choice head that DESCENDS from the applied tip but sits
    /// beyond the forward cap (the drain stopped on an ambiguous child) is
    /// reached by applying forward in bounded steps, never by a from-genesis
    /// rebuild of a chain the node already executed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_far_ahead_descendant_is_applied_forward_not_rebuilt() {
        let key = crypto::generate_keypair();
        let other = crypto::generate_keypair();
        let top = 400u64;
        let r = roots(top, &key);
        let g = genesis();
        let all = chain(&key, &g, top, &r);
        let net = Net {
            genesis: g.clone(),
            prefix: all.clone(),
            main: Vec::new(),
            side: Vec::new(),
        };
        let ndir = tempfile::tempdir().expect("tempdir");
        let applied_to = 250usize;
        let n = node(&net, &all[..applied_to], ndir.path()).await;
        // Stored, not applied: the rest of the chain plus a sibling of the next
        // block (two stored children make the linear drain stop).
        let next = &all[applied_to];
        let rival = sibling(
            &other,
            next.header.height,
            next.selected_parent(),
            next.state_root,
            h(next),
            false,
        );
        n.storage.blocks.put_block(&rival).expect("put");
        for b in &all[applied_to..] {
            n.storage.blocks.put_block(b).expect("put");
        }
        let head = Arc::new(parking_lot::Mutex::new(Some(h(all.last().expect("top")))));
        let app = CanonicalApplicator::new(n.executor.clone(), n.storage.clone())
            .with_fork_choice_cell(head);
        app.set_genesis(
            Executor::new(Arc::new(StateDB::new())).state_snapshot(),
            h(&g),
        );
        crate::canonical_apply::test_reorg_forward::set(Some(50));
        let storage = n.storage.clone();
        let ((), lowest) = lowest_durable_tip_during(&storage, async {
            for _ in 0..10 {
                app.drive_drain().await;
            }
        })
        .await;
        crate::canonical_apply::test_reorg_forward::set(None);
        assert!(
            lowest >= applied_to as u64,
            "durable applied tip fell to {lowest} below the verified {applied_to}"
        );
        assert_eq!(n.applied(), Some((h(all.last().expect("top")), top)));
    }

    /// Control for the red tests above: after the same restart, a STRICTLY
    /// heavier branch forking one block below the tip still wins. The reorg
    /// ring cannot reach its fork point, so the switch goes through the
    /// from-genesis rebuild, which the precondition allows.
    #[tokio::test]
    async fn restarted_node_on_a_losing_sibling_rejoins_a_heavier_branch() {
        let key = crypto::generate_keypair();
        let other = crypto::generate_keypair();
        let top = RESTART_TIP + 5;
        let r = roots(top, &key);
        let g = genesis();
        let own = chain(&key, &g, RESTART_TIP, &r);
        let tip = own.last().expect("tip").clone();
        let parent = own[own.len() - 2].header.block_hash;
        let rival = sibling(
            &other,
            RESTART_TIP,
            parent,
            r[RESTART_TIP as usize],
            h(&tip),
            false,
        );
        let mut heavier = vec![rival.clone()];
        heavier.extend(extend(&other, h(&rival), RESTART_TIP + 1, top, &r));
        let net = Net {
            genesis: g.clone(),
            prefix: own[..own.len() - 1].to_vec(),
            main: heavier.clone(),
            side: Vec::new(),
        };
        let pdir = tempfile::tempdir().expect("tempdir");
        let peer = peer_store(&net, false, pdir.path());
        let ndir = tempfile::tempdir().expect("tempdir");
        let before = node(&net, &own, ndir.path()).await;
        let (n, _, _) = restart(&before, &g, RESTART_RETAIN).await;
        let head = heavier.last().expect("head");
        let mut tracker = RejoinTracker::new();
        let run = drive_advertised(&n, &mut tracker, &peer, h(head), top, 40).await;
        assert_eq!(
            n.applied(),
            Some((h(head), top)),
            "the restarted node did not switch to the heavier branch: anchors {:?}",
            run.anchors
        );
        assert_eq!(n.executor.calculate_state_root(), head.state_root);
    }

    /// The rebuild precondition, case by case, on a node restarted at 30 with
    /// blocks stored beyond it. Every refusal leaves the applied tip alone.
    #[tokio::test]
    async fn rebuild_target_refuses_everything_but_an_outranking_connected_branch() {
        use crate::canonical_apply::RebuildRefusal;
        let key = crypto::generate_keypair();
        let other = crypto::generate_keypair();
        let r = roots(40, &key);
        let g = genesis();
        let all = chain(&key, &g, 40, &r);
        let net = Net {
            genesis: g.clone(),
            prefix: all[..30].to_vec(),
            main: Vec::new(),
            side: Vec::new(),
        };
        let ndir = tempfile::tempdir().expect("tempdir");
        let before = node(&net, &all[..30], ndir.path()).await;
        let (n, ghostdag, dag) = restart(&before, &g, RESTART_RETAIN).await;
        let tip = all[29].clone();
        // Stored, not applied: the chain's continuation, and a block whose
        // parent this node never had.
        for b in &all[30..] {
            n.storage.blocks.put_block(b).expect("put");
        }
        let orphan = seal(&other, 33, Hash::new([0xEE; 32]), r[33]);
        n.storage.blocks.put_block(&orphan).expect("put");
        // Known to fork choice (stored + scored), not applied: the tip's
        // equal-score siblings on both sides of the hash tie-break, and a
        // heavier branch on the losing one.
        let wins = sibling(&other, 30, tip.selected_parent(), r[30], h(&tip), true);
        let loses = sibling(&other, 30, tip.selected_parent(), r[30], h(&tip), false);
        let heavier = extend(&other, h(&loses), 31, 32, &r);
        for b in [&wins, &loses].into_iter().chain(heavier.iter()) {
            n.storage.blocks.put_block(b).expect("put");
            dag.store_block(b.clone()).await.expect("dag");
            ghostdag.add_block(b).await.expect("scored");
        }
        let lock = n.app.advance_lock();
        let state = lock.lock().await;
        let verdict = |head: Hash| n.app.rebuild_target(&state, head, h(&g));
        assert_eq!(
            verdict(h(&all[10])).await,
            Err(RebuildRefusal::OnAppliedChain { height: 11 }),
            "an applied ancestor"
        );
        assert_eq!(
            verdict(h(&tip)).await,
            Err(RebuildRefusal::OnAppliedChain { height: 30 })
        );
        assert_eq!(
            verdict(h(&all[39])).await,
            Err(RebuildRefusal::DescendsFromTip)
        );
        assert_eq!(
            verdict(h(&orphan)).await,
            Err(RebuildRefusal::MissingAncestor {
                missing: Hash::new([0xEE; 32])
            }),
            "a missing ancestor is not divergence"
        );
        assert!(
            matches!(
                verdict(h(&loses)).await,
                Err(RebuildRefusal::NotHeavier { .. })
            ),
            "an equal-score sibling that loses the tie-break"
        );
        for head in [h(&wins), h(heavier.last().expect("heavier"))] {
            let plan = verdict(head).await.expect("outranks the tip");
            assert_eq!(plan.fork.hash, tip.selected_parent());
            assert_eq!((plan.fork.height, plan.abandoned), (29, 1));
        }
        drop(state);
        assert_eq!(n.applied(), Some((h(&tip), 30)));
    }

    /// Tripwire for the one fail-open case of the rebuild weight check: an
    /// applied-tip pointer to a block this node no longer stores. Peers must
    /// not be able to cause it. In the code this binary runs, a chain-store
    /// block is deleted only by
    /// - the start-up purge of invalid blocks (`hardening_rejoin`, run in
    ///   `start_node` before the peer manager exists), and
    /// - the operator's offline `rollback` subcommand.
    ///
    /// The chain-store pruner (`Pruner`) exists but is never started (no
    /// caller of `start_services` / `start_auto_pruning` outside the storage
    /// crate). A storage read error is never taken as "not stored".
    #[test]
    fn the_applied_tip_can_vanish_only_through_local_purges() {
        use std::path::{Path, PathBuf};
        fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
            let Ok(rd) = std::fs::read_dir(dir) else {
                return;
            };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name != "tests" && name != "target" && name != "benches" {
                        rust_files(&p, out);
                    }
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        /// The production part of a source file: everything before its
        /// `#[cfg(test)]` test module, and nothing from `*_tests.rs` files.
        fn production(path: &Path) -> String {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.ends_with("_tests.rs") || name == "tests.rs" {
                return String::new();
            }
            let src = std::fs::read_to_string(path).unwrap_or_default();
            let cut = [
                "#[cfg(test)]\nmod tests",
                "#[cfg(test)]\npub(crate) mod tests",
                "#[cfg(test)]\npub mod tests",
            ]
            .iter()
            .filter_map(|m| src.find(m))
            .min()
            .unwrap_or(src.len());
            src[..cut].to_string()
        }
        let node = Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = node.parent().expect("workspace root");
        let mut files = Vec::new();
        rust_files(&node.join("src"), &mut files);
        rust_files(&root.join("core"), &mut files);
        assert!(files.len() > 50, "fixture: source files found");
        let rel = |p: &Path| {
            p.strip_prefix(root)
                .map(|r| r.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default()
        };
        let allowed = [
            "node/src/hardening_rejoin.rs",
            "node/src/rollback.rs",
            "core/storage/src/pruning/pruner.rs",
        ];
        for f in &files {
            let code = production(f);
            let r = rel(f);
            for call in [".purge_blocks(", ".delete_block("] {
                assert!(
                    !code.contains(call) || allowed.contains(&r.as_str()),
                    "{r} deletes chain-store blocks ({call}); a peer-reachable deletion would \
                     open the rebuild's not-stored exception"
                );
            }
            if !r.starts_with("core/storage/src/") {
                for call in ["start_services(", "start_auto_pruning("] {
                    assert!(
                        !code.contains(call),
                        "{r} starts the chain-store pruner ({call}), which can delete an \
                         applied tip that lags the stored height"
                    );
                }
            }
        }
        // The start-up purge runs before any peer exists.
        let main = include_str!("main.rs");
        let purge = main.find("hardening_rejoin::purge_invalid_post_activation(");
        let peers = main.find("PeerManager::new(");
        assert!(
            matches!((purge, peers), (Some(a), Some(b)) if a < b),
            "the start-up purge must run before the peer manager is created"
        );
        // A read error is never "not stored".
        let apply = include_str!("canonical_apply.rs");
        assert!(
            apply.contains(".has_block(&state.tip.hash)\n                .unwrap_or(true);"),
            "the tip-held read must treat a storage error as held"
        );
    }

    /// Tripwire: no header-claimed blue score reaches the rebuild decision
    /// (SECREM-01 CONS-2; DGX P1 at 14afe643). The applicator's production code
    /// never reads `header.blue_score`; weights come only from fork choice.
    #[test]
    fn the_rebuild_decision_never_reads_a_header_score() {
        let src = include_str!("canonical_apply.rs");
        let prod = src
            .split("#[cfg(test)]\npub(crate) mod tests {")
            .next()
            .expect("production part");
        assert!(
            !prod.contains("header.blue_score"),
            "canonical_apply.rs production code reads a header blue score"
        );
        assert!(
            prod.contains("g.fork_choice_score(&h)"),
            "weights come from fork choice"
        );
    }

    /// Tripwire: the guards stay on the paths that move the applied tip down.
    #[test]
    fn rewind_guards_stay_wired() {
        let src = include_str!("canonical_apply.rs");
        let body = |name: &str| -> &str {
            let start = src.find(name).unwrap_or_else(|| panic!("{name} is gone"));
            let rest = &src[start..];
            let end = rest[1..]
                .find("\n    pub async fn ")
                .map_or(rest.len(), |e| e + 1);
            let end = rest[1..]
                .find("\n    async fn ")
                .map_or(end, |e| end.min(e + 1));
            &rest[..end]
        };
        // The rebuild checks its target before the reset that moves the durable
        // tip to genesis, and refuses a spine that does not reach genesis.
        let rebuild = body("async fn recover_to_head_inner(");
        let gate = rebuild.find("self.rebuild_target(&state, head, genesis_hash)");
        let complete = rebuild.find("if !reached_genesis {");
        let reset = rebuild.find("Some((genesis_hash, 0)),");
        assert!(
            matches!((gate, complete, reset), (Some(g), Some(c), Some(r)) if g < c && c < r),
            "recover_to_head must check rebuild_target and the spine before the genesis reset"
        );
        // Every caller goes through the flag-owning wrapper.
        let outer = body("async fn recover_guarded(");
        assert!(outer.contains("self.rebuild_in_progress.swap(true"));
        for entry in [
            "pub async fn recover_to_head(",
            "pub(crate) async fn recover_automatic(",
        ] {
            assert!(
                body(entry).contains("self.recover_guarded("),
                "{entry} must go through recover_guarded"
            );
        }
        // The node's own triggers apply the strictly-heavier / prune-floor
        // policy before the reset.
        let policy = rebuild.find("rebuild_decision(below_ring, floor, head_w, tip_w, tip_held)");
        assert!(
            matches!((policy, reset), (Some(p), Some(r)) if p < r),
            "the automatic rebuild policy must run before the genesis reset"
        );
        let runtime = body("pub(crate) async fn maybe_runtime_rebuild(");
        assert!(runtime.contains(".recover_automatic("));
        let main = include_str!("main.rs");
        assert!(
            main.contains(".recover_automatic(genesis_snapshot.clone(), genesis_hash, head)")
                && !main.contains(".recover_to_head("),
            "start_node's start-up recovery must use recover_automatic"
        );
        // `reorg_to` asks the applied chain, not only the ring, before walking.
        let reorg = body("pub async fn reorg_to(");
        let applied = reorg.find("self.is_applied(state, new_tip, nb.header.height)");
        let walk = reorg.find("let revert_floor =");
        assert!(
            matches!((applied, walk), (Some(a), Some(w)) if a < w),
            "reorg_to must check is_applied before the fork-point walk"
        );
        // The receive path never waits behind a rebuild.
        let recv = body("pub async fn apply_received(");
        let flag = recv.find("self.rebuild_in_progress.load(");
        let lock = recv.find("self.lock.lock()");
        assert!(
            matches!((flag, lock), (Some(f), Some(l)) if f < l),
            "apply_received must check the rebuild flag before waiting for the lock"
        );
        assert!(recv.contains("tokio::time::timeout(RECEIVE_LOCK_POLL"));
        // A far-ahead descendant is stepped forward, not rebuilt.
        assert!(
            body("pub async fn drive_drain(").contains("self.forward_step_toward(&state, new_tip)")
        );
    }

    // ---------------------------------------------------------------------
    // Split healing (r1006, 2026-10-29). Producers on branches that grow at
    // the same rate sit at equal heights, so no peer is ever "ahead" and the
    // tick never asked anyone; and a forked node that IS behind had its search
    // steered, then ended, by answers from peers on its own branch.
    //
    // The mesh below runs every node's 2 s tick as `start_node` runs it:
    // `choose_source` (the same function main.rs calls), the tracker's anchor,
    // `note_asked`, the answer from the asked peer's real `serve_blocks`, the
    // `Blocks` steps in `deliver`, and the serve credit the handler records.
    // ---------------------------------------------------------------------

    use crate::sync_peer::{SplitCandidate, SplitPullGate, SyncCandidate, SyncPeerSelector};

    struct MeshNode {
        name: String,
        node: Node,
        tracker: RejoinTracker,
        selector: SyncPeerSelector,
        gate: SplitPullGate,
        orphans: Vec<Block>,
        /// Advertised head when relayed gossip inflated it (I4): the height
        /// and the hash of the relayed block.
        inflated: Option<(Hash, u64)>,
        /// Every source this node chose, with the anchor height it asked.
        asked: Vec<(Source, u64)>,
        _dir: tempfile::TempDir,
    }

    impl MeshNode {
        fn advertised(&self) -> (Hash, u64) {
            let own = self.node.applied().expect("applied tip");
            match self.inflated {
                Some(inf) if inf.1 > own.1 => inf,
                _ => own,
            }
        }
    }

    async fn mesh_node(name: &str, net: &Net, own: &[Block]) -> MeshNode {
        let dir = tempfile::tempdir().expect("tempdir");
        let node = node(net, own, dir.path()).await;
        MeshNode {
            name: name.to_string(),
            node,
            tracker: RejoinTracker::new(),
            selector: SyncPeerSelector::new(),
            gate: SplitPullGate::new(),
            orphans: Vec::new(),
            inflated: None,
            asked: Vec::new(),
            _dir: dir,
        }
    }

    /// One 2 s sync tick on `mesh[i]` at `now`. Returns the source it chose.
    async fn mesh_tick(mesh: &mut [MeshNode], i: usize, now: Instant) -> Source {
        let applied = mesh[i].node.applied().expect("applied tip");
        let mut cands = Vec::new();
        let mut split = Vec::new();
        for (j, m) in mesh.iter().enumerate() {
            if j == i {
                continue;
            }
            let (hash, height) = m.advertised();
            cands.push(SyncCandidate {
                id: m.name.clone(),
                head_height: height,
            });
            split.push(SplitCandidate {
                id: m.name.clone(),
                head_height: height,
                head_hash: hash,
            });
        }
        let target = cands
            .iter()
            .map(|c| c.head_height)
            .max()
            .unwrap_or(0)
            .max(applied.1);
        let me = &mut mesh[i];
        me.tracker.note_sync_target(target, applied.1);
        let storage = me.node.storage.clone();
        let (source, _) = choose_source(
            &mut me.tracker,
            &me.selector,
            &mut me.gate,
            &cands,
            &split,
            applied,
            |hh| storage.blocks.has_block(hh).unwrap_or(true),
            now,
        );
        let Some(peer) = source.peer().map(str::to_string) else {
            me.asked.push((source.clone(), applied.1));
            return source;
        };
        let anchor = me
            .tracker
            .anchor(applied, |ht| anchor_at_height(&me.node.storage, ht));
        me.tracker.note_asked(&peer, anchor);
        me.asked.push((source.clone(), anchor.1));
        let j = mesh
            .iter()
            .position(|m| m.name == peer)
            .expect("asked a mesh peer");
        let answer = block_serve::serve_blocks(&mesh[j].node.storage, &anchor.0, 32);
        let served = answer.len();
        let me = &mut mesh[i];
        let (newly, highest) = deliver(
            &me.node,
            &mut me.tracker,
            &mut me.orphans,
            &peer,
            answer,
            target,
        )
        .await;
        let applied_now = me.node.applied().expect("applied tip").1;
        let stale = crate::sync_recovery::answer_anchor_was_stale(anchor.1, applied_now, served);
        me.selector.record_serve(
            &peer,
            newly,
            highest,
            target.saturating_sub(applied_now),
            32,
            stale,
        );
        source
    }

    /// One round: every node ticks once, `now` advances one tick.
    async fn mesh_round(mesh: &mut [MeshNode], now: Instant) {
        for i in 0..mesh.len() {
            mesh_tick(mesh, i, now).await;
        }
    }

    /// Seal the block `m` would produce now, as the producer does: drain, the
    /// initial-sync gate (#126), fork choice's tip as the selected parent and
    /// only when it is the applied tip (MP-S1), the other tips as merge
    /// parents (heaviest-parent and MP-DEPTH filters). `None` when the
    /// producer would refuse.
    async fn mesh_produce(
        m: &MeshNode,
        key: &ed25519_dalek::SigningKey,
        r: &[Hash],
        target: u64,
    ) -> Option<Block> {
        m.node.app.drive_drain().await;
        let applied = m.node.applied().expect("applied tip");
        if !crate::sync_recovery::initial_sync_complete(
            applied.1,
            target,
            1,
            std::time::Duration::from_secs(1),
        ) {
            return None;
        }
        let sp_hash = m.node.ghostdag.select_tip().await.ok()?;
        if sp_hash != applied.0 {
            return None;
        }
        let sp = m.node.storage.blocks.get_block(&sp_hash).ok()??;
        let height = sp.header.height + 1;
        let mut merges = Vec::new();
        for tip in m.node.ghostdag.get_tips().await {
            if tip == sp_hash || merges.len() + 1 >= GhostDagParams::default().max_parents {
                continue;
            }
            let Ok(Some(b)) = m.node.storage.blocks.get_block(&tip) else {
                continue;
            };
            if b.header.blue_score <= sp.header.blue_score
                && height - b.header.height <= citrate_consensus::ghostdag::MERGE_PARENT_MAX_DEPTH
            {
                merges.push(tip);
            }
        }
        merges.sort();
        let score = sp.header.blue_score + 1;
        let mut b = BlockBuilder::new()
            .version(2)
            .height(height)
            .parent(sp_hash)
            .merge_parents(merges)
            .coinbase(CB)
            .timestamp(sp.header.timestamp + 1)
            .vrf_reveal(VrfProof {
                proof: vec![],
                output: Hash::new([0x5A; 32]),
            })
            .transactions(vec![])
            .state_root(r[height as usize])
            .blue_score(score)
            .blue_work(blue_work_for_score(score))
            .proposer(PublicKey::new(key.verifying_key().to_bytes()))
            .build_unhashed();
        b.tx_root = citrate_consensus::tx_auth::tx_root_for_height(
            PbaHardening::off(),
            height,
            &b.transactions,
        );
        b.header.block_hash = b.compute_hash();
        b.signature = crypto::sign_block(&b.header.block_hash, key);
        Some(b)
    }

    /// `block` produced by `mesh[from]`: admitted there, gossiped to the rest.
    /// A receiver that defers it on a missing parent asks the sender for that
    /// parent (SYNC-S3, `main.rs` NewBlock arm: anchored at the parent, so the
    /// answer carries the parent's whole height group).
    async fn mesh_gossip(mesh: &mut [MeshNode], from: usize, block: &Block, target: u64) {
        let fx = mesh[from]
            .node
            .admission
            .admit_to_fixpoint(vec![block.clone()], |_, _| {})
            .await;
        assert_eq!(fx.newly_admitted, 1, "the producer admits its own block");
        mesh[from].node.app.drive_drain().await;
        let name = mesh[from].name.clone();
        let sender = mesh[from].node.storage.clone();
        for (j, m) in mesh.iter_mut().enumerate() {
            if j == from {
                continue;
            }
            deliver(
                &m.node,
                &mut m.tracker,
                &mut m.orphans,
                &name,
                vec![block.clone()],
                target,
            )
            .await;
            if !holds(m, block) {
                let missing = block
                    .parents()
                    .into_iter()
                    .find(|p| !m.node.storage.blocks.has_block(p).expect("read"));
                if let Some(parent) = missing {
                    let answer = block_serve::serve_blocks(&sender, &parent, 32);
                    deliver(
                        &m.node,
                        &mut m.tracker,
                        &mut m.orphans,
                        &name,
                        answer,
                        target,
                    )
                    .await;
                }
            }
            m.node.app.drive_drain().await;
        }
    }

    fn holds(m: &MeshNode, b: &Block) -> bool {
        m.node.storage.blocks.has_block(&h(b)).expect("read")
    }

    /// Producers on equal-height branches: a common prefix `1..=fork`, then
    /// each producer's own `len` blocks on it. Blocks pay the same coinbase,
    /// so every branch has the same state roots.
    struct Split {
        net: Net,
        roots: Vec<Hash>,
        keys: Vec<ed25519_dalek::SigningKey>,
        branches: Vec<Vec<Block>>,
    }

    fn split_net(fork: u64, len: u64, producers: usize) -> Split {
        let common = crypto::generate_keypair();
        let r = roots(fork + len + 40, &common);
        let g = genesis();
        let prefix = extend(&common, h(&g), 1, fork, &r);
        let fork_hash = prefix.last().map(h).unwrap_or_else(|| h(&g));
        let keys: Vec<_> = (0..producers).map(|_| crypto::generate_keypair()).collect();
        let branches = keys
            .iter()
            .map(|k| extend(k, fork_hash, fork + 1, fork + len, &r))
            .collect();
        Split {
            net: Net {
                genesis: g,
                prefix,
                main: Vec::new(),
                side: Vec::new(),
            },
            roots: r,
            keys,
            branches,
        }
    }

    async fn split_mesh(sp: &Split) -> Vec<MeshNode> {
        let mut mesh = Vec::new();
        for (i, br) in sp.branches.iter().enumerate() {
            let own: Vec<Block> = sp.net.prefix.iter().chain(br.iter()).cloned().collect();
            mesh.push(mesh_node(&format!("prod-{i}"), &sp.net, &own).await);
        }
        mesh
    }

    /// Pull rounds until every node stores every branch, at most `max`.
    /// Returns the rounds used and the lowest durable applied height any node
    /// had meanwhile.
    async fn heal_rounds(mesh: &mut [MeshNode], sp: &Split, max: usize) -> (usize, u64) {
        let watches: Vec<TipWatch> = mesh
            .iter()
            .map(|m| TipWatch::start(m.node.storage.clone()))
            .collect();
        let t0 = Instant::now();
        let mut rounds = 0;
        while rounds < max {
            let all = mesh
                .iter()
                .all(|m| sp.branches.iter().flatten().all(|b| holds(m, b)));
            if all {
                break;
            }
            mesh_round(mesh, t0 + std::time::Duration::from_secs(2 * rounds as u64)).await;
            rounds += 1;
        }
        let lowest = watches.into_iter().map(TipWatch::finish).min().unwrap_or(0);
        (rounds, lowest)
    }

    /// After the pull, produce round-robin (each producer seals when its gates
    /// pass, the block is gossiped, then every node ticks once) until every
    /// node stores every branch, applies the same block, and that block is
    /// its only DAG tip (every other branch is merged into its past). At most
    /// `max` rounds. Returns that block, the blocks produced, and the rounds
    /// in which the nodes' applied tips differed after the first block.
    async fn converge(
        mesh: &mut [MeshNode],
        sp: &Split,
        max: usize,
    ) -> Option<(Block, Vec<Block>, usize)> {
        let mut disagreed = 0;
        let t0 = Instant::now() + std::time::Duration::from_secs(3_600);
        let mut produced = Vec::new();
        for round in 0..max {
            let target = mesh.iter().map(|m| m.advertised().1).max().unwrap_or(0);
            let i = round % mesh.len();
            if let Some(b) = mesh_produce(&mesh[i], &sp.keys[i], &sp.roots, target).await {
                mesh_gossip(mesh, i, &b, target + 1).await;
                produced.push(b);
            }
            mesh_round(mesh, t0 + std::time::Duration::from_secs(2 * round as u64)).await;
            for m in mesh.iter() {
                m.node.app.drive_drain().await;
            }
            let Some(last) = produced.last() else {
                continue;
            };
            let want = Some((h(last), last.header.height));
            if mesh.iter().any(|m| m.node.applied() != want) {
                disagreed += 1;
            }
            let mut done = true;
            for m in mesh.iter() {
                done &= m.node.applied() == want
                    && sp.branches.iter().flatten().all(|b| holds(m, b))
                    && m.node.ghostdag.get_tips().await == vec![h(last)];
            }
            if done {
                return Some((last.clone(), produced, disagreed));
            }
        }
        None
    }

    /// RED. Two producers, 10 own blocks each on a common prefix, at equal
    /// height, connected, nothing in flight. Neither is ahead, so neither ever
    /// asks the other for anything and each producer's blocks defer at the
    /// other forever. The tick must pull the sibling branch from the peer whose
    /// tip it does not hold, so both nodes store both branches; GhostDAG then
    /// selects one and the next block merges the other, and both nodes apply
    /// that block. Nothing rewinds while the branches are fetched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn equal_height_producers_pull_each_others_branch_and_converge() {
        let sp = split_net(6, 10, 2);
        let mut mesh = split_mesh(&sp).await;
        let (rounds, lowest) = heal_rounds(&mut mesh, &sp, 30).await;
        for m in &mesh {
            for (k, br) in sp.branches.iter().enumerate() {
                assert!(
                    br.iter().all(|b| holds(m, b)),
                    "{} does not store prod-{k}'s branch after {rounds} rounds: asked {:?}",
                    m.name,
                    m.asked
                );
            }
        }
        // An equal-weight in-window reorg may pass through the fork point;
        // a rebuild from genesis would reset the durable tip below it.
        assert!(
            lowest >= 6,
            "a durable applied tip fell to {lowest}, below the fork point: the pull \
             must never cause a rebuild from genesis"
        );
        // Both nodes hold the same DAG, so fork choice agrees.
        let a = mesh[0].node.ghostdag.select_tip().await.expect("tip");
        let b = mesh[1].node.ghostdag.select_tip().await.expect("tip");
        assert_eq!(a, b, "fork choice disagrees over the same DAG");
        let (tip, produced, disagreed) = converge(&mut mesh, &sp, 4).await.expect("converged");
        assert_eq!(produced.len(), 1, "one block converges both nodes");
        assert_eq!(disagreed, 0);
        let tips: Vec<Hash> = sp
            .branches
            .iter()
            .map(|br| h(br.last().expect("tip")))
            .collect();
        let parents = tip.parents();
        assert!(
            tips.iter().all(|t| parents.contains(t)),
            "the converged block merges both branch tips: parents {parents:?}"
        );
    }

    /// RED. Seven producers, one own block each at the same height (the
    /// shape of a 7-way partition that healed its links but not its
    /// branches). The pulls spread the siblings (a peer's advertised tip names
    /// one block, so a node learns of the rest through what that peer serves),
    /// production merges what each producer holds, and ordinary sync fetches
    /// the merge parents a node lacks: every node ends up storing all seven,
    /// applying the same block, with no other DAG tip.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn seven_equal_height_singletons_converge() {
        let sp = split_net(6, 1, 7);
        let mut mesh = split_mesh(&sp).await;
        let (rounds, lowest) = heal_rounds(&mut mesh, &sp, 60).await;
        for m in &mesh {
            let held = sp.branches.iter().flatten().filter(|b| holds(m, b)).count();
            assert!(
                held >= 2,
                "{} stores {held} of 7 siblings after {rounds} rounds: asked {:?}",
                m.name,
                m.asked
            );
        }
        assert!(lowest >= 6, "a durable applied tip fell to {lowest}");
        let (tip, produced, disagreed) = converge(&mut mesh, &sp, 14).await.expect("converged");
        // One selected chain from the first block on: every node applies
        // each produced block. Merging finishes within one turn per producer
        // (a sibling nobody pulled is merged by its own producer).
        assert_eq!(
            disagreed, 0,
            "the nodes' applied tips differed after a block"
        );
        assert!(
            produced.len() <= 7,
            "took {} blocks to merge every sibling",
            produced.len()
        );
        let merged: usize = produced.iter().map(|b| b.parents().len() - 1).sum();
        assert_eq!(merged, 6, "the six other siblings are merged once each");
        assert_eq!(tip.header.height, 7 + produced.len() as u64);
    }

    /// RED, the devnet shape (DGX, fed#331 c.6502292059). A producer
    /// restarted onto its own branch: forked 35 below its tip, the network 250
    /// ahead of it on the other branch. Two other producers stuck on the SAME
    /// side branch advertise the network head (relayed gossip inflates it,
    /// I4), so the selector alternates between the leading producer, which
    /// does not hold our tip (empty answers), and siblings that hold our tip
    /// and nothing above it (answers we already have). Those sibling answers
    /// reset the search's strikes and, once a probe ran, ended it on the first
    /// probe ("StartedProbe { top } then GaveUp { at: top - 1 } 0.5 s later").
    /// Every stuck node must find the fork point against the leading
    /// producer, fetch its branch, switch to it, and produce again (it was
    /// held by the initial-sync gate), with its block accepted by the leader.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forked_and_behind_node_rejoins_and_produces_again() {
        let fork = 100u64;
        let side_tip = fork + 35;
        let main_tip = side_tip + 250;
        let leader_key = crypto::generate_keypair();
        let side_key = crypto::generate_keypair();
        let r = roots(main_tip + 4, &leader_key);
        let g = genesis();
        let prefix = extend(&leader_key, h(&g), 1, fork, &r);
        let fork_hash = h(prefix.last().expect("prefix"));
        let main = extend(&leader_key, fork_hash, fork + 1, main_tip, &r);
        let side = extend(&side_key, fork_hash, fork + 1, side_tip, &r);
        let net = Net {
            genesis: g,
            prefix: prefix.clone(),
            main: main.clone(),
            side: side.clone(),
        };
        let main_own: Vec<Block> = prefix.iter().chain(main.iter()).cloned().collect();
        let side_own: Vec<Block> = prefix.iter().chain(side.iter()).cloned().collect();
        let head = main.last().expect("main tip").clone();
        let mut mesh = vec![mesh_node("a-leader", &net, &main_own).await];
        let stuck = ["b-stuck", "c-stuck", "d-stuck"];
        for name in stuck {
            let mut m = mesh_node(name, &net, &side_own).await;
            m.inflated = Some((h(&head), main_tip));
            // History before the stall: the other stuck producers delivered
            // this node's branch, the leader only the common prefix. So once
            // scores tie, the served watermark ranks every sibling above the
            // leader (sync_peer.rs ordering), as on the devnet.
            for sib in stuck.iter().filter(|s| **s != name) {
                m.selector.record_serve(sib, 32, side_tip, 32, 32, false);
            }
            m.selector.record_serve("a-leader", 32, fork, 32, 32, false);
            mesh.push(m);
        }
        let watches: Vec<TipWatch> = mesh
            .iter()
            .map(|m| TipWatch::start(m.node.storage.clone()))
            .collect();
        let t0 = Instant::now();
        let mut rounds = 0;
        while rounds < 120
            && !mesh
                .iter()
                .all(|m| m.node.applied() == Some((h(&head), main_tip)))
        {
            mesh_round(&mut mesh, t0 + std::time::Duration::from_secs(2 * rounds)).await;
            rounds += 1;
        }
        let lowest = watches.into_iter().map(TipWatch::finish).min().unwrap_or(0);
        for m in &mesh[1..] {
            assert!(
                main.iter().all(|b| holds(m, b)),
                "{} did not store the leader's branch after {rounds} rounds",
                m.name
            );
            assert_eq!(
                m.node.applied(),
                Some((h(&head), main_tip)),
                "{} stayed on its branch after {rounds} rounds: asked {:?}",
                m.name,
                m.asked
                    .iter()
                    .map(|(s, a)| (s.peer().map(str::to_string), *a))
                    .collect::<Vec<_>>()
            );
            assert_eq!(m.node.executor.calculate_state_root(), head.state_root);
        }
        assert!(
            lowest >= fork,
            "a durable applied tip fell to {lowest}, below the fork point {fork}: the \
             switch is an in-window reorg, never a rebuild from genesis"
        );
        // Produces again: past the initial-sync gate, on the network head,
        // and the leader applies the block.
        let stuck_key = crypto::generate_keypair();
        let b = mesh_produce(&mesh[1], &stuck_key, &r, main_tip)
            .await
            .expect("the rejoined producer produces");
        assert_eq!(b.selected_parent(), h(&head));
        mesh_gossip(&mut mesh, 1, &b, main_tip + 1).await;
        for m in &mesh {
            assert_eq!(
                m.node.applied(),
                Some((h(&b), main_tip + 1)),
                "{} did not apply the rejoined producer's block",
                m.name
            );
        }
    }

    /// Control: a peer strictly ahead on our own chain is synced from as
    /// before (the selector's pick, tip anchors only), and no split pull or
    /// search ever starts on either side.
    #[tokio::test]
    async fn a_peer_strictly_ahead_still_syncs_as_before() {
        let net = net(6, 6, 120);
        let ahead: Vec<Block> = net.prefix.iter().chain(net.main.iter()).cloned().collect();
        let mut mesh = vec![
            mesh_node("a-ahead", &net, &ahead).await,
            mesh_node("b-behind", &net, &net.prefix).await,
        ];
        let tip = net.main.last().expect("tip");
        let t0 = Instant::now();
        for round in 0..20u64 {
            if mesh[1].node.applied() == Some((h(tip), 120)) {
                break;
            }
            mesh_round(&mut mesh, t0 + std::time::Duration::from_secs(2 * round)).await;
        }
        assert_eq!(mesh[1].node.applied(), Some((h(tip), 120)));
        let mut applied = 6;
        for (src, anchor) in &mesh[1].asked {
            assert!(
                matches!(src, Source::Ahead(p) if p == "a-ahead") || *src == Source::Nobody,
                "behind node chose {src:?}"
            );
            assert!(*anchor >= applied, "anchored below the tip: {anchor}");
            applied = *anchor;
        }
        assert!(
            mesh[0].asked.iter().all(|(s, _)| *s == Source::Nobody),
            "the node ahead asked: {:?}",
            mesh[0].asked
        );
        assert_eq!(mesh[1].tracker.mode(), &Mode::Tip { strikes: 0 });
    }

    /// Control: equal height on the SAME tip, and a peer whose advertised tip
    /// we already hold, are not split pulls; nothing is ever asked.
    #[tokio::test]
    async fn no_pull_when_the_peer_tip_is_held() {
        let net = net(6, 6, 20);
        let chain: Vec<Block> = net.prefix.iter().chain(net.main.iter()).cloned().collect();
        let mut mesh = [
            mesh_node("a", &net, &chain).await,
            mesh_node("b", &net, &chain).await,
            mesh_node("c", &net, &chain[..chain.len() - 3]).await,
        ];
        let t0 = Instant::now();
        for round in 0..10u64 {
            mesh_round(
                &mut mesh[..2],
                t0 + std::time::Duration::from_secs(2 * round),
            )
            .await;
        }
        for m in &mesh[..2] {
            assert!(
                m.asked.iter().all(|(s, _)| *s == Source::Nobody),
                "{} asked {:?}",
                m.name,
                m.asked
            );
        }
        // `a` sees `c` 3 below with a tip on a's own chain: held, no pull.
        let applied = mesh[0].node.applied().expect("tip");
        let c = mesh[2].node.applied().expect("tip");
        let storage = mesh[0].node.storage.clone();
        let m0 = &mut mesh[0];
        let (src, _) = choose_source(
            &mut m0.tracker,
            &m0.selector,
            &mut m0.gate,
            &[SyncCandidate {
                id: "c".into(),
                head_height: c.1,
            }],
            &[SplitCandidate {
                id: "c".into(),
                head_height: c.1,
                head_hash: c.0,
            }],
            applied,
            |hh| storage.blocks.has_block(hh).unwrap_or(true),
            t0,
        );
        assert_eq!(src, Source::Nobody);
    }

    /// A split pull is a search against one peer: while it runs, the tick
    /// keeps asking that peer even when the selector would pick another, an
    /// equal-height answer does not end it as "caught up", and a peer that
    /// stops answering ends it after `MAX_UNANSWERED` requests without
    /// throttling the next ordinary search.
    #[test]
    fn a_split_pull_is_pinned_bounded_and_does_not_throttle_rejoin() {
        let mut t = RejoinTracker::new();
        let sel = SyncPeerSelector::new();
        let mut gate = SplitPullGate::new();
        let now = Instant::now();
        let split = [SplitCandidate {
            id: "sib".into(),
            head_height: 50,
            head_hash: hx(9),
        }];
        let cands = [SyncCandidate {
            id: "sib".into(),
            head_height: 50,
        }];
        let (src, tr) = choose_source(
            &mut t,
            &sel,
            &mut gate,
            &cands,
            &split,
            (hx(1), 50),
            |_| false,
            now,
        );
        assert_eq!(src, Source::Split("sib".into()));
        assert!(matches!(tr, Some(Transition::StartedSplitPull { top: 50 })));
        assert!(matches!(t.mode(), Mode::Probe { height: 49, .. }));
        // An equal-height answer (not behind) does not end the pull.
        let a = t.anchor((hx(1), 50), |_| Some(hx(2)));
        t.note_asked("sib", a);
        assert_eq!(t.take_answer("sib", &[], &HashSet::new()), Some(49));
        t.on_answer(Answer::Unconnected, false, 49);
        assert!(
            matches!(t.mode(), Mode::Probe { height: 48, .. }),
            "{:?}",
            t.mode()
        );
        // A peer now ahead does not take over the running pull.
        let ahead = [
            SyncCandidate {
                id: "sib".into(),
                head_height: 50,
            },
            SyncCandidate {
                id: "aaa".into(),
                head_height: 90,
            },
        ];
        let (src, _) = choose_source(
            &mut t,
            &sel,
            &mut gate,
            &ahead,
            &split,
            (hx(1), 50),
            |_| false,
            now,
        );
        // P1-2: a peer more than the catch-up gap ahead of the pinned one ends
        // the pin; the selector's peer is asked instead.
        assert_eq!(src, Source::Ahead("aaa".into()));
        let _ = t.start_split_pull("sib", 50);
        // No answers: bounded, then over, with no rejoin cooldown owed.
        let mut gave_up = false;
        for _ in 0..=MAX_UNANSWERED {
            let a = t.anchor((hx(1), 50), |_| Some(hx(2)));
            if let Some(Transition::GaveUp { .. }) = t.note_asked("sib", a) {
                gave_up = true;
                break;
            }
        }
        assert!(gave_up, "a silent split peer must end the pull");
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
        assert_eq!(
            t.cooldown(),
            0,
            "a split pull's give-up must not throttle rejoin"
        );
        // Within the per-peer window the same peer is not pulled again.
        let (src, _) = choose_source(
            &mut t,
            &sel,
            &mut gate,
            &cands,
            &split,
            (hx(1), 50),
            |_| false,
            now + std::time::Duration::from_secs(20),
        );
        assert_eq!(src, Source::Nobody);
    }

    /// P1-2: a pinned peer whose re-sends are skipped (its anchor is still
    /// pending in the sync manager) gets no answer either: those rounds count
    /// as unanswered, so a silent pin ends after `MAX_UNANSWERED` rounds.
    #[test]
    fn a_pinned_search_whose_resends_are_skipped_ends() {
        let mut t = RejoinTracker::new();
        let _ = t.start_split_pull("sib", 50);
        let a = t.anchor((hx(1), 50), |_| Some(hx(2)));
        t.note_asked("sib", a);
        let mut ended = false;
        for _ in 0..MAX_UNANSWERED {
            if let Some(Transition::GaveUp { .. }) = t.note_unsent("sib") {
                ended = true;
                break;
            }
        }
        assert!(ended, "a silent pin held the tick: {:?}", t.mode());
        assert_eq!(t.search_peer(), None);
    }

    /// P1-2: a slow peer answering one request in seven keeps `unanswered`
    /// below its limit forever. The search still ends within its request cap,
    /// which is sized to the search's own log bound.
    #[test]
    fn a_slow_peer_cannot_hold_a_search_past_its_request_cap() {
        let top = 86_000u64;
        let bound = 2 * (64 - top.leading_zeros()) + MAX_UNANSWERED;
        let mut t = RejoinTracker::new();
        let _ = t.start_split_pull("slow", top);
        let mut requests = 0u32;
        while t.search_peer().is_some() && requests < 10_000 {
            let a = t.anchor((hx(1), top), |_| Some(hx(2)));
            t.note_asked("slow", a);
            requests += 1;
            if requests.is_multiple_of(7) && t.search_peer().is_some() {
                if let Some(ah) = t.take_answer("slow", &[], &HashSet::new()) {
                    t.on_answer(Answer::Unconnected, true, ah);
                }
            }
        }
        assert!(
            requests <= bound,
            "the search took {requests} requests (bound {bound})"
        );
    }

    /// P1-2: a follow that admits one block per answer never runs dry. A split
    /// follow stops at its height bound; any follow that only trickles ends.
    #[test]
    fn an_endless_follow_ends_within_its_bound() {
        use crate::sync_peer::SPLIT_PULL_HEIGHT_BAND;
        let depth = crate::canonical_apply::MAX_REORG_DEPTH;
        for split in [true, false] {
            let mut t = RejoinTracker::new();
            let top = 500u64;
            if split {
                let _ = t.start_split_pull("drip", top);
            } else {
                t.note_sync_target(top + 10_000, top);
                for _ in 0..PROBE_AFTER_STRIKES {
                    let a = t.anchor((hx(1), top), |_| Some(hx(2)));
                    t.note_asked("drip", a);
                    let ah = t.take_answer("drip", &[], &HashSet::new()).expect("answer");
                    t.on_answer(Answer::Unconnected, true, ah);
                }
            }
            let mut cursor = top - 1;
            let mut answers = 0u32;
            while t.search_peer().is_some() && answers < 10_000 {
                let a = t.anchor((hx(1), top), |_| Some(hx(2)));
                t.note_asked("drip", a);
                let ah = t
                    .take_answer("drip", &[a.0], &[a.0].into_iter().collect())
                    .expect("answer");
                cursor += 1;
                t.on_answer(
                    Answer::Progress {
                        highest: (hx(3), cursor),
                    },
                    true,
                    ah,
                );
                answers += 1;
            }
            assert!(
                t.search_peer().is_none(),
                "split={split}: the follow never ended"
            );
            assert!(
                cursor <= top + SPLIT_PULL_HEIGHT_BAND + depth,
                "split={split}: followed to {cursor}"
            );
            assert!(
                answers <= 2 * MAX_UNANSWERED,
                "split={split}: {answers} trickling answers"
            );
        }
    }

    /// P3: the tick's split-pull check reads no storage under the selector
    /// lock: held heads are looked up before it is taken.
    #[test]
    fn choose_source_reads_no_storage_under_the_selector_lock() {
        let main = include_str!("main.rs");
        assert!(
            main.contains("|h| held_heads.contains(h)"),
            "choose_source's `holds` must use heads looked up before the selector lock"
        );
    }

    /// A pinned peer that disconnects ends the search; the tick falls back to
    /// the selector at once.
    #[test]
    fn a_search_whose_peer_left_is_abandoned() {
        let mut t = RejoinTracker::new();
        let sel = SyncPeerSelector::new();
        let mut gate = SplitPullGate::new();
        let now = Instant::now();
        let split = [SplitCandidate {
            id: "sib".into(),
            head_height: 50,
            head_hash: hx(9),
        }];
        let (src, _) = choose_source(
            &mut t,
            &sel,
            &mut gate,
            &[SyncCandidate {
                id: "sib".into(),
                head_height: 50,
            }],
            &split,
            (hx(1), 50),
            |_| false,
            now,
        );
        assert_eq!(src, Source::Split("sib".into()));
        let other = [SyncCandidate {
            id: "other".into(),
            head_height: 60,
        }];
        let (src, tr) = choose_source(
            &mut t,
            &sel,
            &mut gate,
            &other,
            &[],
            (hx(1), 50),
            |_| false,
            now,
        );
        assert_eq!(src, Source::Ahead("other".into()));
        assert!(matches!(tr, Some(Transition::Finished { .. })), "{tr:?}");
        assert_eq!(t.mode(), &Mode::Tip { strikes: 0 });
    }

    /// An advertised head is self-reported and is raised by gossip before the
    /// block is validated, so it is no evidence that its peer can carry us.
    /// A search pinned to an honest leader that keeps answering stays pinned
    /// while another peer advertises any height, however large, and serves
    /// nothing.
    #[test]
    fn an_advertised_lead_alone_never_ends_a_pinned_search() {
        for liar_head in [1_000_000_000u64, u64::MAX / 2, u64::MAX] {
            let mut t = RejoinTracker::new();
            let sel = SyncPeerSelector::new();
            let mut gate = SplitPullGate::new();
            let top = 500u64;
            let fork = 450u64;
            // Two unconnected tip answers from the leader start the search,
            // pinned to it.
            let mut tr = None;
            for _ in 0..PROBE_AFTER_STRIKES {
                t.note_asked("leader", (hx(1), top));
                let ah = t
                    .take_answer("leader", &[], &HashSet::new())
                    .expect("answer");
                tr = t.on_answer(Answer::Unconnected, true, ah);
            }
            assert_eq!(tr, Some(Transition::StartedProbe { top }));
            let t0 = Instant::now();
            let mut leader_head = 600u64;
            let mut followed = false;
            // Well past any stall bound, one tick per second.
            for tick in 0..240u64 {
                let now = t0 + Duration::from_secs(tick);
                let cands = [
                    SyncCandidate {
                        id: "leader".into(),
                        head_height: leader_head,
                    },
                    SyncCandidate {
                        id: "liar".into(),
                        head_height: liar_head,
                    },
                ];
                let (src, tr) = choose_source(
                    &mut t,
                    &sel,
                    &mut gate,
                    &cands,
                    &[],
                    (hx(1), top),
                    |_| true,
                    now,
                );
                assert_eq!(
                    src,
                    Source::Pinned("leader".into()),
                    "liar@{liar_head} tick {tick}: {tr:?} mode={:?}",
                    t.mode()
                );
                assert!(
                    !matches!(tr, Some(Transition::Finished { .. })),
                    "liar@{liar_head} tick {tick}: {tr:?}"
                );
                // The leader answers this tick's request.
                let a = t.anchor((hx(1), top), |_| Some(hx(2)));
                t.note_asked("leader", a);
                let ah = t
                    .take_answer("leader", &[a.0], &[a.0].into_iter().collect())
                    .expect("the leader answers");
                let answer = match t.mode() {
                    Mode::Follow { cursor } => Answer::Progress {
                        highest: (hx(7), cursor.1 + FOLLOW_TRICKLE_ADVANCE),
                    },
                    _ => model(fork, 64, a.1),
                };
                if let Answer::Progress { highest } = answer {
                    leader_head = leader_head.max(highest.1);
                }
                t.on_answer(answer, true, ah);
                followed |= matches!(t.mode(), Mode::Follow { .. });
                assert_eq!(
                    t.search_peer(),
                    Some("leader"),
                    "liar@{liar_head} tick {tick}: the search ended: {:?}",
                    t.mode()
                );
            }
            assert!(
                followed,
                "liar@{liar_head}: the search never found the fork"
            );
        }
    }

    /// Strikes count unconnected answers from ONE peer. An answer from a peer
    /// on our own branch (it holds our tip, nothing above) says nothing about
    /// whether the striking peer extends us and must not reset them; the
    /// search that starts is pinned to the striking peer.
    #[test]
    fn a_sibling_answer_does_not_reset_another_peers_strikes() {
        let mut t = RejoinTracker::new();
        let ask = |t: &mut RejoinTracker, peer: &str, empty: bool| {
            t.note_asked(peer, (hx(1), 50));
            let got: Vec<Hash> = if empty { vec![] } else { vec![hx(1)] };
            let verified: HashSet<Hash> = got.iter().copied().collect();
            t.take_answer(peer, &got, &verified).expect("answers")
        };
        let ah = ask(&mut t, "leader", true);
        t.on_answer(Answer::Unconnected, true, ah);
        let ah = ask(&mut t, "sibling", false);
        t.on_answer(Answer::Known, true, ah);
        let ah = ask(&mut t, "leader", true);
        let tr = t.on_answer(Answer::Unconnected, true, ah);
        assert_eq!(
            tr,
            Some(Transition::StartedProbe { top: 50 }),
            "{:?}",
            t.mode()
        );
        let sel = SyncPeerSelector::new();
        let mut gate = SplitPullGate::new();
        let (src, _) = choose_source(
            &mut t,
            &sel,
            &mut gate,
            &[
                SyncCandidate {
                    id: "leader".into(),
                    head_height: 300,
                },
                SyncCandidate {
                    id: "sibling".into(),
                    head_height: 300,
                },
            ],
            &[],
            (hx(1), 50),
            |_| true,
            Instant::now(),
        );
        assert_eq!(src, Source::Pinned("leader".into()));
    }
}
