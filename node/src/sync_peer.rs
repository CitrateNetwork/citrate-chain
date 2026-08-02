// citrate/node/src/sync_peer.rs
//
// #85 — which peer does the periodic sync tick pull from?
//
// WHY THIS IS A MODULE AND NOT FIVE LINES INLINE
//
// The selection used to live inside the sync-tick `tokio::spawn` closure in
// main.rs, where it was unreachable from any test. It wedged the live fleet
// twice. It is extracted here so the invariants below are pinned by tests
// rather than by comments.
//
// THE LIVE WEDGE THIS CLOSES (chain 40204, 2026-07-29, ~7 h)
//
// After the GhostDAG halt at 54600, rpc-1 restarted and produced on to 68k
// while boot1/boot2/boot3 sat frozen at exactly 54600 — applied tip correctly
// persisted and recovered on all three, peers connected, gossip flowing, and
// the producer holding a contiguous chain right across the gap. Every follower
// re-imported the SAME block forever:
//
//     Validated and imported 1/1 blocks (height 54600-54600)   [every 2 s]
//
// Meanwhile rpc-1 — the only node on the network holding 54601 — received
// ZERO `GetBlocks` requests anchored at 54600 across a 20-minute window.
//
// Two independent defects in the old selection produced that:
//
// D1. A PEER AT OUR OWN HEIGHT COULD WIN.
//     The scan maximised `info.head_height > best_h` from `best_h = 0`. It
//     never compared a candidate's head against OUR applied height, so a peer
//     stuck at exactly our tip out-scored "no peer at all". boot1 locked onto
//     boot2 (head 54600 == boot1's tip); `serve_blocks` anchored at our own tip
//     correctly returns just the anchor group, so the response carried nothing
//     to advance on. A peer that is not ahead of us is not a sync source.
//
// D2. THE PENALTY BOX HAD A SELF-LATCHING DEAD BAND.
//     A peer was excluded from selection at `>= 3` sync timeouts, but the only
//     paths that RESET the counter fired at `>= 5` (drop-and-rehandshake, or
//     the sole-peer escape). A peer sitting at 3 or 4 was therefore excluded
//     from selection => never requested from => never timed out again => never
//     reached 5 => never reset. Permanent blacklist for the process lifetime,
//     from a handful of transient timeouts during the boot thundering-herd.
//     boot1 took 4 increments between 08:56 and 08:57 and never logged
//     `Dropped peer` (which needs 5 on ONE peer) for the rest of the day.
//
//     The two compose into the observed deadlock: the penalty box removed the
//     producer, and D1 let a same-height sibling take its place, so the node
//     looked busy — issuing requests, getting answers, importing blocks — while
//     making no progress at all. That is why it read as a stall and not a stop.
//
// THE INVARIANTS
//
//   I1. Only a peer whose advertised head is ABOVE our applied height is a
//       candidate. Nothing else can move us forward.
//   I2. The failure count is a PREFERENCE among useful peers, never a veto on
//       all of them. If penalties would empty a non-empty useful set, the set is
//       used anyway. Being behind is present-tense evidence; a stale timeout is
//       not.
//   I3. Service clears. A peer that actually delivers is not a failing peer (see
//       `record_useful`, credited from the receive path).
//   I4. ADVERTISED IS NOT HELD. A peer's advertised head is bumped by any relayed
//       gossip block, so it proves the peer SAW that height, never that it holds
//       it. Only blocks we could admit are evidence of a real source; a peer that
//       answers with nothing new is de-preferred however high it advertises.
//
// I4 EXISTS BECAUSE I1 ALONE WAS DEFEATED (chain 40204, 2026-08-01).
//
// Our node and boot3 both sat at height 177,771. Gossip had inflated every peer's
// advertised head to the network tip (~213k), so I1 passed for all four and they
// all TIED — and the old tie-break (`b.id.cmp(&a.id)`) hands ties to the SMALLEST
// peer id, which was boot3. It answered "Sending 1 blocks" thirty times in three
// minutes: our own anchor group, nothing new. Every one of those replies called
// the old `record_success`, clearing its penalty and reconfirming it as our
// preferred source. We sent boot3 63 of 66 requests while rpc-1 (at the tip) and
// boot1/boot2 (17k ahead) went unasked. A genesis→tip cold sync fell from 445 to
// 18 blocks/min and began LOSING ground to a chain growing at 30.
//
// I1 was not wrong; it was reading a number that gossip had made meaningless.
// That is the general lesson: a selection invariant is only as good as the
// evidence behind the field it tests.
//
// I2 is the one that breaks the latch, and it is deliberately stated as "use it
// anyway" rather than "raise the threshold": any fixed pair of exclude/reset
// thresholds reintroduces a dead band somewhere. The escape must be keyed on
// need, not on a bigger number.
//
// I2 deliberately does NOT clear the counter on the escape. Selecting the peer
// is what unfreezes it — an excluded peer's count is stuck only because it is
// never requested from. Preserving the count keeps the EXISTING escalation
// intact: the peer keeps accruing timeouts, reaches the drop threshold, and is
// dropped so it re-handshakes fresh (main.rs). Clearing on escape would cap the
// count below that threshold forever and silently disable that recovery — the
// same class of bug as the dead band, just relocated.

use std::collections::HashMap;

/// How far above our applied tip a gossiped block may be and still trigger
/// SYNC-S3 depth-1 ancestry recovery.
///
/// Derived, not picked: `SyncConfig::block_batch_size` (32) x
/// `max_concurrent_downloads` (16) is the most a node with a completely full
/// in-flight window can legitimately be behind. Anything further away is not a
/// fork we narrowly missed — it is the gap, and the 2s forward driver owns the
/// gap.
pub const ANCESTRY_RECOVERY_WINDOW: u64 = 32 * 16;

/// Should a gossiped block that deferred on a missing parent trigger a direct
/// ancestry request to the peer that sent it?
///
/// #150. SYNC-S3 recovery exists for the 2026-07-27 silent partition: a peer
/// gossips a block whose parent we narrowly missed, so we ask THAT peer for the
/// parent directly and self-heal at depth 1. That is correct and stays.
///
/// What was missing is a distance bound. When a node is far behind, EVERY
/// gossiped tip block is "missing its parent" — so every one queued a request
/// for a parent tens of thousands of blocks deep, none of which could ever be
/// applied. Measured on boot1 at a 33,000-block gap: **125 of 159 batches (79%)
/// landed at the network tip**, unappliable, while those same requests consumed
/// the in-flight budget (`pending_counts() < 8`) that the one useful forward
/// request needs. The recovery mechanism was starving the catch-up it was
/// supposed to assist.
///
/// Note this is keyed on the BLOCK's height, not the missing parent's: we do not
/// have the parent (that is why it is missing), so its height is unknown. The
/// child's height bounds it from above, which is the direction that matters.
pub fn should_attempt_ancestry_recovery(block_height: u64, applied_height: u64) -> bool {
    block_height <= applied_height.saturating_add(ANCESTRY_RECOVERY_WINDOW)
}

/// Sync timeouts against one peer before it is DE-PREFERRED as a sync source.
///
/// This is a preference, not a ban — see I2 and [`SyncPeerSelector::select`].
pub const DEPREFER_AT_FAILURES: u32 = 3;

/// A connected peer considered as a block source for this tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCandidate {
    /// Peer id string (`PeerInfo.id.0`) — the key failures are tracked under.
    pub id: String,
    /// The head height this peer advertises (Hello/HelloAck/gossip).
    pub head_height: u64,
}

/// Consecutive responses that admitted NOTHING NEW before a peer is treated as
/// proven-useless rather than merely unlucky.
///
/// Two is deliberate and low. A peer that hands us only blocks we already hold
/// is not congested or slow — it is at or behind our own tip, and no number of
/// further requests changes that. One response can legitimately be a duplicate
/// (a race with the drain, an overlapping batch); two in a row is a position,
/// not an accident.
pub const USELESS_SERVES_BEFORE_DEMOTION: u32 = 2;

/// Newly-admitted blocks a response must carry to count as REAL service — the
/// evidence required to decay a demotion.
///
/// #154. Not every non-zero response is service. The measured pathology was a
/// peer answering with ONE new block at a time (438 x `imported 1/1` in twenty
/// minutes) while we needed twenty-two thousand: enough to look productive, far
/// too little to carry us, and — with a naive decay — enough to keep undoing its
/// own demotion. A peer that can actually advance us returns full batches
/// (`209 x 32/32` in the healthy window immediately before).
///
/// A quarter of `SyncConfig::block_batch_size` (32): generous enough that a
/// genuinely-serving peer near the tip, or one whose batch was clipped by a
/// height-group boundary, still counts; strict enough that trickling one block
/// per response never buys forgiveness.
pub const MEANINGFUL_SERVE_BLOCKS: usize = 8;

/// Ceiling on the useless streak, and therefore on how long recovery takes.
///
/// #154. The streak DECAYS by one per useful serve rather than clearing (see
/// `record_useful`), which is what makes a demotion durable. Uncapped, that would
/// also make it unbounded: a peer demoted 300 times would need 300 good serves to
/// return, which is a permanent exclusion in all but name — the same "latch"
/// failure mode this module keeps having to unlearn.
///
/// Four times the demotion threshold: comfortably outlasts the occasional lucky
/// block from a peer that is still behind, while letting one that genuinely
/// caught up rejoin within a handful of good responses.
pub const USELESS_STREAK_CAP: u32 = USELESS_SERVES_BEFORE_DEMOTION * 4;

/// Per-peer sync accounting plus the selection policy built on it.
///
/// Shared (behind a mutex) between the sync tick task, which records timeouts and
/// selects, and the network message handler, which records what a response
/// actually delivered — the tick task alone can only ever observe failures, so I3
/// and I4 have to be credited from the receive side. The counters are
/// process-local by design: a restart is a legitimate clean slate, which is also
/// why restarting a wedged node was a (partial, short-lived) workaround for
/// several of the bugs this module now pins.
#[derive(Debug, Default)]
pub struct SyncPeerSelector {
    failures: HashMap<String, u32>,
    /// Highest height this peer has actually DELIVERED to us and we could admit.
    ///
    /// #153 — THE DIFFERENCE BETWEEN *SEEN* AND *HELD*.
    ///
    /// `SyncCandidate::head_height` comes from `PeerInfo.head_height`, which the
    /// gossip handler bumps on ANY relayed `NewBlock`. Relaying a block proves the
    /// peer SAW it; it does not prove the peer HOLDS it, and it certainly does not
    /// prove the peer holds its ancestry. On chain 40204 every peer therefore
    /// advertised ~the network tip regardless of what it actually stored.
    ///
    /// This watermark is the honest number: it only moves when a peer hands us a
    /// block we did not have and could apply.
    served: HashMap<String, u64>,
    /// Consecutive responses from this peer that admitted nothing new.
    useless: HashMap<String, u32>,
}

impl SyncPeerSelector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a sync request that timed out against `id`. Returns the new count.
    pub fn record_timeout(&mut self, id: &str) -> u32 {
        let e = self.failures.entry(id.to_string()).or_insert(0);
        *e = e.saturating_add(1);
        *e
    }

    /// `id` delivered blocks we did not have and could admit, the highest at
    /// `height`. This is the ONLY evidence that a peer is a real source (I4).
    ///
    /// Clears the timeout penalty (the old I3 meaning — it answered) and the
    /// useless streak, and raises its served watermark.
    pub fn record_useful(&mut self, id: &str, height: u64, blocks: usize) {
        // Answering at all is still evidence of liveness, so the timeout penalty
        // clears regardless of size (I3 unchanged).
        self.failures.remove(id);

        // #154: a demotion DECAYS, and only against REAL service.
        //
        // Two defects, both measured on the same live cold-sync:
        //
        //   1. Clearing the streak outright meant one new block bought complete
        //      forgiveness, so a peer needed two fresh useless serves before
        //      demotion could fire again -> demote / forgive / re-select / demote,
        //      THIRTY-EIGHT times against `noise_2b49…` at ~15 blocks/min.
        //   2. Counting ANY non-zero response as service is what made that lucky
        //      block qualify. The pathology WAS one-block responses: 438 x
        //      `imported 1/1` in twenty minutes, against `209 x 32/32` in the
        //      healthy window immediately before.
        //
        // So: decay by one, and only when the response carried a real batch. A
        // peer that can actually advance us clears its streak in a handful of
        // proper serves; one trickling single blocks never does, however many it
        // sends. The judgement should cost about as much to reverse as to earn.
        if blocks >= MEANINGFUL_SERVE_BLOCKS {
            if let Some(e) = self.useless.get_mut(id) {
                *e = e.saturating_sub(1);
                if *e == 0 {
                    self.useless.remove(id);
                }
            }
        }

        let e = self.served.entry(id.to_string()).or_insert(0);
        if height > *e {
            *e = height;
        }
    }

    /// `id` answered, but the response admitted NOTHING NEW.
    ///
    /// #153 — this used to be indistinguishable from success. The Blocks handler
    /// called `record_success` on ANY response, so a peer sitting at our exact
    /// height, serving back our own anchor group one block at a time, had its
    /// penalty cleared on every reply and stayed the preferred source forever.
    /// Delivering a block we already hold is not service; counting it as service
    /// is what made the node reinforce the one peer that could not help it.
    pub fn record_useless(&mut self, id: &str) {
        let e = self.useless.entry(id.to_string()).or_insert(0);
        // #154: capped so the streak is STICKY but never a life sentence. With
        // decay-on-success (see `record_useful`), an uncapped streak would take as
        // many good serves to clear as it took bad ones — a peer that spent an
        // hour behind us and then genuinely caught up would be excluded for
        // hundreds of responses. The cap bounds recovery at
        // USELESS_STREAK_CAP successful serves, which is long enough to outlast
        // the occasional lucky block and short enough that a recovered peer
        // rejoins promptly.
        *e = e.saturating_add(1).min(USELESS_STREAK_CAP);
    }

    /// Highest height `id` has actually delivered (0 if it never has).
    pub fn served(&self, id: &str) -> u64 {
        self.served.get(id).copied().unwrap_or(0)
    }

    /// Consecutive no-progress responses from `id`.
    pub fn useless_streak(&self, id: &str) -> u32 {
        self.useless.get(id).copied().unwrap_or(0)
    }

    /// Clear `id`'s failure count because it is being dropped and will
    /// re-handshake — the reconnection starts from a clean slate. Distinct from
    /// [`record_success`] only in intent, but the two are not interchangeable
    /// evidence and the call sites read very differently.
    pub fn reset(&mut self, id: &str) {
        self.failures.remove(id);
    }

    /// Current failure count for `id` (0 when never seen).
    pub fn failures(&self, id: &str) -> u32 {
        self.failures.get(id).copied().unwrap_or(0)
    }

    /// Pick the peer to pull blocks from this tick, or `None` when no connected
    /// peer is ahead of us.
    ///
    /// I1: candidates are filtered to `head_height > applied_height` — a peer at
    /// or below our tip cannot advance us, and selecting one is what made the
    /// live fleet re-import its own anchor every 2 s for seven hours.
    ///
    /// I2: among those, de-preferred peers (>= [`DEPREFER_AT_FAILURES`]) are
    /// skipped ONLY while a clean useful peer exists. When every useful peer is
    /// de-preferred, the best is used anyway — otherwise the penalty box can
    /// blacklist the entire network. Counters are NOT cleared on that escape;
    /// see the module docs for why that would disable the drop-and-re-handshake
    /// escalation.
    ///
    /// Ties on height break on peer id so the choice is deterministic and does
    /// not oscillate between two equal peers across ticks.
    ///
    /// Takes `&self`: selection is a pure read of the counters. Every mutation
    /// is an explicit `record_*` / `reset` call, so "does choosing a peer change
    /// its standing?" is answerable from the signature alone — the question that
    /// the clear-on-escape draft got wrong.
    pub fn select<'a>(
        &self,
        candidates: &'a [SyncCandidate],
        applied_height: u64,
    ) -> Option<&'a SyncCandidate> {
        // I1 — only peers strictly ahead of our applied tip can help.
        let useful: Vec<&SyncCandidate> = candidates
            .iter()
            .filter(|c| c.head_height > applied_height)
            .collect();
        if useful.is_empty() {
            return None;
        }

        // #153 — TIE-BREAK ON DEMONSTRATED SERVICE, NOT ON PEER ID.
        //
        // Gossip bumps every peer's advertised head to ~the network tip (see
        // `served`), so on this fleet all four candidates TIE on `head_height`
        // permanently. The old tie-break was `b.id.cmp(&a.id)` — inside `max_by`
        // that makes the SMALLEST peer id win. It is deterministic, which the
        // oscillation test wanted, but deterministic toward an arbitrary peer
        // chosen by key material.
        //
        // Live consequence on chain 40204: boot3 (`noise_2b49…`, lowest id of the
        // four) won every tie while holding EXACTLY our own height. We sent it 63
        // of 66 requests in three minutes; it answered "Sending 1 blocks" thirty
        // times. Throughput fell 445 -> 18 blocks/min and the node began losing
        // ground to the tip, while boot1/boot2 (17k ahead) and rpc-1 (at the tip)
        // sat unasked.
        //
        // Ordering by served watermark first makes the tie-break mean something:
        // among peers that look equally good on paper, prefer the one that has
        // actually handed us blocks. Peer id remains the final key so the choice
        // stays deterministic and cannot oscillate between two equal peers.
        let pick = |set: &[&'a SyncCandidate]| -> Option<&'a SyncCandidate> {
            set.iter().copied().max_by(|a, b| {
                a.head_height
                    .cmp(&b.head_height)
                    .then_with(|| self.served(&a.id).cmp(&self.served(&b.id)))
                    .then_with(|| b.id.cmp(&a.id))
            })
        };

        // I4 — a peer PROVEN unable to advance us is not a candidate while any
        // unproven or productive peer exists. "Proven" is deliberately narrow: it
        // has answered `USELESS_SERVES_BEFORE_DEMOTION` times in a row with
        // nothing we could admit, AND its served watermark is at or below our own
        // tip, so there is positive evidence it is not ahead of us in substance —
        // not merely that it was unlucky. A peer we have never pulled from is
        // never demoted by this rule; it has to earn the demotion.
        let productive = |c: &SyncCandidate| -> bool {
            self.useless_streak(&c.id) < USELESS_SERVES_BEFORE_DEMOTION
                || self.served(&c.id) > applied_height
        };

        let clean: Vec<&SyncCandidate> = useful
            .iter()
            .copied()
            .filter(|c| self.failures(&c.id) < DEPREFER_AT_FAILURES && productive(c))
            .collect();
        if !clean.is_empty() {
            return pick(&clean);
        }

        // Everything clean is also proven-useless: fall back to peers that are
        // merely un-penalised, so a transient no-progress streak cannot strand us.
        let unpenalised: Vec<&SyncCandidate> = useful
            .iter()
            .copied()
            .filter(|c| self.failures(&c.id) < DEPREFER_AT_FAILURES)
            .collect();
        if !unpenalised.is_empty() {
            return pick(&unpenalised);
        }

        // I2 — every peer that could advance us is in the penalty box. That is
        // the latch: excluded peers are never requested from, so their counters
        // can never move again. Selecting one is what unfreezes it. The counter
        // is left ALONE: a peer that genuinely cannot serve keeps accruing
        // timeouts and escalates to the drop-and-re-handshake path, while one
        // that answers is cleared by `record_success`. Either way it moves.
        pick(&useful)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(id: &str, head_height: u64) -> SyncCandidate {
        SyncCandidate {
            id: id.to_string(),
            head_height,
        }
    }

    /// D1 RED TEST — the live 40204 shape. Our applied tip is 54600. Two
    /// followers are stuck at exactly 54600; the producer is at 68091 and is the
    /// only node holding 54601. The old scan maximised head over `best_h = 0`
    /// with no comparison against our own height, so a same-height sibling was a
    /// valid winner and the node pulled from a peer that could only ever return
    /// its own anchor.
    #[test]
    fn a_peer_at_our_own_height_is_never_a_sync_source() {
        let sel = SyncPeerSelector::new();
        let peers = [cand("boot2", 54600), cand("boot3", 54600)];
        assert_eq!(
            sel.select(&peers, 54600),
            None,
            "no peer is ahead of us — pulling from a same-height peer returns our \
             own anchor and re-imports 1/1 blocks (54600-54600) forever"
        );
    }

    /// And with the producer present it must be the pick, not the siblings.
    #[test]
    fn the_peer_that_is_actually_ahead_wins() {
        let sel = SyncPeerSelector::new();
        let peers = [cand("boot2", 54600), cand("rpc1", 68091), cand("boot3", 54600)];
        assert_eq!(
            sel.select(&peers, 54600).map(|c| c.id.as_str()),
            Some("rpc1")
        );
    }

    /// D2 RED TEST — the self-latching dead band, reproduced exactly.
    ///
    /// rpc-1 takes 4 transient timeouts during the boot thundering-herd. The old
    /// policy excluded it at >= 3 but only reset at >= 5. Excluded means never
    /// requested from; never requested from means never timed out again; so the
    /// count froze at 4 and rpc-1 — the ONLY node holding the blocks we need —
    /// was blacklisted for the process lifetime.
    ///
    /// The counter is deliberately parked INSIDE [3, 5) because that is the
    /// unreachable band; a fix that merely raises the exclusion threshold moves
    /// the band without removing it.
    #[test]
    fn a_de_preferred_peer_is_still_used_when_it_is_the_only_one_ahead() {
        let mut sel = SyncPeerSelector::new();
        for _ in 0..4 {
            sel.record_timeout("rpc1");
        }
        assert_eq!(sel.failures("rpc1"), 4, "parked in the old [3,5) dead band");

        let peers = [cand("boot2", 54600), cand("rpc1", 68091), cand("boot3", 54600)];
        assert_eq!(
            sel.select(&peers, 54600).map(|c| c.id.as_str()),
            Some("rpc1"),
            "I2: the penalty box must not veto the only peer that can advance us"
        );
        assert_eq!(
            sel.failures("rpc1"),
            4,
            "and the counter is PRESERVED — being selected is what unfreezes it; \
             clearing here would cap it below the drop threshold forever and \
             silently disable the re-handshake escalation"
        );
    }

    /// The I2 escape must not become a NEW latch. A de-preferred peer that is
    /// still the only one ahead keeps being selected AND keeps accruing
    /// timeouts, so it reaches the drop threshold and gets re-handshaked. An
    /// earlier draft cleared the counter on the escape, which pinned it below
    /// that threshold forever — the dead band relocated rather than removed.
    #[test]
    fn the_escape_still_escalates_to_the_drop_threshold() {
        const DROP_AT: u32 = 5; // main.rs drop-and-re-handshake threshold
        let mut sel = SyncPeerSelector::new();
        let peers = [cand("dead", 68091), cand("sibling", 54600)];
        let mut ticks = 0;
        while sel.failures("dead") < DROP_AT {
            let chosen = sel.select(&peers, 54600).map(|c| c.id.clone());
            assert_eq!(
                chosen.as_deref(),
                Some("dead"),
                "the only peer ahead stays selected even while de-preferred"
            );
            sel.record_timeout("dead");
            ticks += 1;
            assert!(ticks < 50, "counter must escalate, not plateau");
        }
        assert_eq!(sel.failures("dead"), DROP_AT);
    }

    /// `reset` is the drop-path clear; it must behave as a clean slate so the
    /// re-handshaked peer competes on head height again.
    #[test]
    fn reset_clears_for_a_re_handshake() {
        let mut sel = SyncPeerSelector::new();
        for _ in 0..5 {
            sel.record_timeout("rpc1");
        }
        sel.reset("rpc1");
        assert_eq!(sel.failures("rpc1"), 0);
    }

    /// The escape is need-driven, not a blanket amnesty: while a clean useful
    /// peer exists, the de-preferred one stays skipped even though it is higher.
    #[test]
    fn a_de_preferred_peer_is_skipped_while_a_clean_peer_can_serve() {
        let mut sel = SyncPeerSelector::new();
        for _ in 0..DEPREFER_AT_FAILURES {
            sel.record_timeout("flaky");
        }
        let peers = [cand("flaky", 70000), cand("good", 68091)];
        assert_eq!(
            sel.select(&peers, 54600).map(|c| c.id.as_str()),
            Some("good"),
            "prefer the peer that answers, even though it is lower"
        );
        assert_eq!(
            sel.failures("flaky"),
            DEPREFER_AT_FAILURES,
            "and the penalty survives — it is only cleared when nothing else can serve"
        );
    }

    /// I3: an answer clears the penalty, so a peer that recovers is a first-class
    /// source again rather than limping at 2 failures until it trips once more.
    #[test]
    fn success_clears_the_penalty() {
        let mut sel = SyncPeerSelector::new();
        for _ in 0..DEPREFER_AT_FAILURES {
            sel.record_timeout("rpc1");
        }
        // #153: `record_success` (credited on ANY reply) is now `record_useful`,
        // credited only when the reply admitted something new. I3's meaning is
        // unchanged — a peer that genuinely serves us sheds its penalty — but the
        // evidence required is now service rather than mere responsiveness.
        sel.record_useful("rpc1", 68_000, 32);
        assert_eq!(sel.failures("rpc1"), 0);
        let peers = [cand("rpc1", 68091), cand("other", 68000)];
        assert_eq!(
            sel.select(&peers, 54600).map(|c| c.id.as_str()),
            Some("rpc1"),
            "cleared peers compete on head height again"
        );
    }

    /// Deterministic tie-break: two equally-ahead peers must not oscillate
    /// across ticks (an oscillating anchor re-requests the same range forever).
    #[test]
    fn equal_heights_break_deterministically() {
        let sel = SyncPeerSelector::new();
        let peers = [cand("bbb", 68091), cand("aaa", 68091)];
        let first = sel.select(&peers, 54600).map(|c| c.id.clone());
        let second = sel.select(&peers, 54600).map(|c| c.id.clone());
        assert_eq!(first, second);
        assert_eq!(first.as_deref(), Some("aaa"));
    }

    /// A node already at the head has nothing to pull — no candidate, no request.
    #[test]
    fn a_synced_node_selects_nothing() {
        let sel = SyncPeerSelector::new();
        let peers = [cand("rpc1", 68091)];
        assert_eq!(sel.select(&peers, 68091), None);
        assert_eq!(sel.select(&[], 0), None);
    }

    /// RED TEST — #153, the live 40204 shape that collapsed a cold sync from 445
    /// to 18 blocks/min while every diagnostic read healthy.
    ///
    /// Our applied tip is 177,771. boot3 holds EXACTLY 177,771 — it cannot advance
    /// us by a single block. But gossip bumps `PeerInfo.head_height` on any relayed
    /// `NewBlock`, so boot3 advertises the network tip (213,222) like everyone else.
    /// I1 therefore passes for all four peers, they all TIE on advertised head, and
    /// the old tie-break (`b.id.cmp(&a.id)`, smallest id wins inside `max_by`)
    /// picked `noise_2b49…` — boot3 — deterministically, forever.
    ///
    /// Measured: 63 of 66 requests went to boot3, which answered "Sending 1 blocks"
    /// thirty times, while rpc-1 (at the tip) and boot1/boot2 (17k ahead) sat
    /// unasked. Every one of those replies called `record_success` and reconfirmed
    /// boot3 as the preferred source.
    #[test]
    fn a_peer_that_serves_nothing_new_stops_being_chosen() {
        let applied = 177_771;
        let tip = 213_222;
        // Every peer advertises the gossip-inflated tip. This is the real defect
        // condition: advertised head carries no information here.
        let peers = [
            cand("noise_2b49_boot3", tip),
            cand("noise_4ed2_boot2", tip),
            cand("noise_6ee5_rpc1", tip),
            cand("noise_f356_boot1", tip),
        ];
        let mut sel = SyncPeerSelector::new();

        // Pre-fix, boot3 wins on the id tie-break. That part is unchanged and fine
        // — with no service history there is nothing better to go on.
        let first = sel.select(&peers, applied).map(|c| c.id.clone());
        assert_eq!(first.as_deref(), Some("noise_2b49_boot3"));

        // boot3 answers twice with our own anchor group: nothing admitted.
        sel.record_useless("noise_2b49_boot3");
        sel.record_useless("noise_2b49_boot3");

        let next = sel.select(&peers, applied).map(|c| c.id.clone());
        assert_ne!(
            next.as_deref(),
            Some("noise_2b49_boot3"),
            "a peer that has served nothing admissible twice must stop winning \
             selection — it is at or behind our tip however high it advertises"
        );
        assert!(next.is_some(), "and we must still have a source");
    }

    /// The positive half: a peer that has actually delivered outranks one that
    /// merely advertises well. This is what makes the tie-break mean something on
    /// a fleet where gossip pins every advertised head to the tip.
    #[test]
    fn demonstrated_service_outranks_an_equal_advertised_head() {
        let applied = 177_771;
        let tip = 213_222;
        let peers = [cand("aaa_lowest_id", tip), cand("zzz_highest_id", tip)];
        let mut sel = SyncPeerSelector::new();

        // With no history the id tie-break applies and the lowest id wins.
        assert_eq!(
            sel.select(&peers, applied).map(|c| c.id.as_str()),
            Some("aaa_lowest_id")
        );

        // The other peer proves it can actually advance us.
        sel.record_useful("zzz_highest_id", applied + 5_000, 32);
        assert_eq!(
            sel.select(&peers, applied).map(|c| c.id.as_str()),
            Some("zzz_highest_id"),
            "proven service must beat an arbitrary id tie-break — that tie-break \
             is what sent 63 of 66 requests to the one peer that could not help"
        );
    }

    /// RED TEST — #154, the oscillation measured on the live cold-sync.
    ///
    /// `record_useful` used to CLEAR the useless streak. A peer far behind us
    /// still lands the occasional genuinely-new block during churn, and a full
    /// reset made that one block buy complete forgiveness — so it needed two
    /// fresh useless serves before demotion could fire again. Result: demote ->
    /// one lucky block -> forgiven -> re-selected -> demote, THIRTY-EIGHT times
    /// against `noise_2b49…`, while throughput sat at ~15 blocks/min.
    ///
    /// Decay, not reset: one good block must not undo two bad ones.
    #[test]
    fn one_lucky_block_does_not_undo_a_demotion() {
        let applied = 207_878;
        let mut sel = SyncPeerSelector::new();

        // Two useless serves earn the demotion.
        sel.record_useless("laggard");
        sel.record_useless("laggard");
        assert!(sel.useless_streak("laggard") >= USELESS_SERVES_BEFORE_DEMOTION);

        // One lucky block from a peer still far behind us — its watermark stays
        // below our tip, so this is not evidence it can carry us.
        sel.record_useful("laggard", applied - 20_000, 1);
        assert!(
            sel.useless_streak("laggard") >= USELESS_SERVES_BEFORE_DEMOTION,
            "a single new block must not clear a demotion — that reset is exactly \
             what produced 38 demote/forgive cycles at ~15 blocks/min"
        );
    }

    /// But stickiness must not become a life sentence: a peer that genuinely
    /// catches up has to be able to return, in a BOUNDED number of good serves.
    /// An unbounded streak would be the same latch failure this module keeps
    /// having to unlearn (see D2 and the [3,5) dead band).
    #[test]
    fn a_recovered_peer_climbs_out_in_bounded_time() {
        let mut sel = SyncPeerSelector::new();
        for _ in 0..200 {
            sel.record_useless("was_behind");
        }
        assert_eq!(
            sel.useless_streak("was_behind"),
            USELESS_STREAK_CAP,
            "the streak is capped, so recovery cost is bounded regardless of how \
             long the peer was useless"
        );
        for _ in 0..USELESS_STREAK_CAP {
            sel.record_useful("was_behind", 500_000, 32);
        }
        assert_eq!(
            sel.useless_streak("was_behind"),
            0,
            "a peer that genuinely caught up rejoins after at most \
             USELESS_STREAK_CAP good serves"
        );
    }

    /// I2 must survive: the new demotion is a PREFERENCE, never a veto. If every
    /// peer looks useless we still pick one, because a node with no source is
    /// strictly worse than a node pulling from a poor one.
    #[test]
    fn demotion_never_leaves_us_with_no_source() {
        let applied = 100;
        let peers = [cand("a", 5_000), cand("b", 5_000)];
        let mut sel = SyncPeerSelector::new();
        for _ in 0..USELESS_SERVES_BEFORE_DEMOTION + 3 {
            sel.record_useless("a");
            sel.record_useless("b");
        }
        assert!(
            sel.select(&peers, applied).is_some(),
            "I2: an empty useful set is never the answer, even when every peer is \
             demoted — being sourceless is the worse failure"
        );
    }

    /// A peer proven useful ABOVE our tip is not demoted by a later dry response.
    /// Its watermark is positive evidence it is genuinely ahead, so a single
    /// duplicate batch (a race with the drain, an overlapping range) must not
    /// unseat a peer that is demonstrably serving us.
    #[test]
    fn a_proven_peer_survives_a_duplicate_response() {
        let applied = 1_000;
        let peers = [cand("good", 9_000), cand("other", 9_000)];
        let mut sel = SyncPeerSelector::new();
        sel.record_useful("good", 5_000, 32); // served well above our tip
        for _ in 0..USELESS_SERVES_BEFORE_DEMOTION + 2 {
            sel.record_useless("good");
        }
        assert_eq!(
            sel.select(&peers, applied).map(|c| c.id.as_str()),
            Some("good"),
            "served watermark above our tip is positive evidence; a dry streak \
             alone must not discard a peer that has demonstrably advanced us"
        );
    }

    /// RED TEST — #150, at boot1's measured shape. A node 33,000 blocks behind
    /// receives the live tip by gossip. Pre-fix this queued an ancestry request
    /// for a parent 33,000 blocks deep, and did so for EVERY gossiped block:
    /// 79% of its downloads landed at the network tip, unappliable, while
    /// starving the one forward request that could actually advance it.
    #[test]
    fn a_far_behind_node_does_not_chase_tip_ancestry() {
        let applied = 126_254; // boot1's applied tip
        let tip_block = 159_001; // the sequencer's head, gossiped to it
        assert!(
            !should_attempt_ancestry_recovery(tip_block, applied),
            "a block {} above our tip is the GAP, not a fork — the forward driver owns it",
            tip_block - applied
        );
    }

    /// And the case SYNC-S3 exists for still fires: the 2026-07-27 partition was
    /// a block whose parent we missed by one. Recovery must remain unconditional
    /// in that neighbourhood or two producers re-partition permanently.
    #[test]
    fn a_narrowly_missed_parent_still_triggers_recovery() {
        let applied = 126_254;
        assert!(
            should_attempt_ancestry_recovery(applied + 1, applied),
            "depth-1 is the whole point of SYNC-S3"
        );
        assert!(
            should_attempt_ancestry_recovery(applied, applied),
            "a sibling at our own height must still be recoverable"
        );
    }

    /// The boundary is a real edge, so pin both sides of it. A node legitimately
    /// lagging by a full in-flight window is still syncing normally and must keep
    /// self-healing; one block further is the regime that starved catch-up.
    #[test]
    fn the_window_boundary_is_exact() {
        let applied = 1_000;
        assert!(
            should_attempt_ancestry_recovery(applied + ANCESTRY_RECOVERY_WINDOW, applied),
            "a full in-flight window behind is normal syncing, not a gap"
        );
        assert!(
            !should_attempt_ancestry_recovery(applied + ANCESTRY_RECOVERY_WINDOW + 1, applied),
            "one past the window is where chasing tip ancestry starts costing forward progress"
        );
    }

    /// A node at genesis must not chase the tip either — this is the cold-start
    /// case, where the gap is the entire chain and every gossiped block defers.
    #[test]
    fn a_cold_starting_node_does_not_chase_the_tip() {
        assert!(
            !should_attempt_ancestry_recovery(159_001, 0),
            "a fresh node has the whole chain to fetch; chasing tip ancestry is pure waste"
        );
    }
}
