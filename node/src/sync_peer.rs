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
//   I3. Success clears. A peer that answers is not a failing peer (see
//       `record_success`, credited from the receive path).
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

/// Per-peer sync-timeout accounting plus the selection policy built on it.
///
/// Owned by the sync tick task; not `Sync`, not shared. The counters are
/// process-local by design — a restart is a legitimate clean slate.
#[derive(Debug, Default)]
pub struct SyncPeerSelector {
    failures: HashMap<String, u32>,
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

    /// Clear `id`'s failure count because it ANSWERED us (I3).
    pub fn record_success(&mut self, id: &str) {
        self.failures.remove(id);
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
    pub fn select<'a>(
        &mut self,
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

        let pick = |set: &[&'a SyncCandidate]| -> Option<&'a SyncCandidate> {
            set.iter()
                .copied()
                .max_by(|a, b| {
                    a.head_height
                        .cmp(&b.head_height)
                        .then_with(|| b.id.cmp(&a.id))
                })
        };

        let clean: Vec<&SyncCandidate> = useful
            .iter()
            .copied()
            .filter(|c| self.failures(&c.id) < DEPREFER_AT_FAILURES)
            .collect();
        if !clean.is_empty() {
            return pick(&clean);
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
        let mut sel = SyncPeerSelector::new();
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
        let mut sel = SyncPeerSelector::new();
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
        sel.record_success("rpc1");
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
        let mut sel = SyncPeerSelector::new();
        let peers = [cand("bbb", 68091), cand("aaa", 68091)];
        let first = sel.select(&peers, 54600).map(|c| c.id.clone());
        let second = sel.select(&peers, 54600).map(|c| c.id.clone());
        assert_eq!(first, second);
        assert_eq!(first.as_deref(), Some("aaa"));
    }

    /// A node already at the head has nothing to pull — no candidate, no request.
    #[test]
    fn a_synced_node_selects_nothing() {
        let mut sel = SyncPeerSelector::new();
        let peers = [cand("rpc1", 68091)];
        assert_eq!(sel.select(&peers, 68091), None);
        assert_eq!(sel.select(&[], 0), None);
    }
}
