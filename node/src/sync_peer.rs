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
//   I3. Liveness and usefulness are SEPARATE axes. Answering clears the timeout
//       count (it proves the peer is alive); how much it delivered moves the
//       usefulness score. A live peer that serves nothing sheds its timeouts and
//       still loses standing.
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
// I5 (#155). STANDING IS ONE NUMBER, AND SELECTION IS ONE ORDERING.
//
// I2's warning — "any fixed pair of thresholds reintroduces a dead band
// somewhere" — was correct and I violated it twice while trying to honour it:
//
//   #153  "any non-zero response is service"  -> a 1-block trickle looked useful
//   #154  "8+ blocks is service"              -> 1-7 credited nothing and debited
//                                                nothing, so a peer trickling one
//                                                block per response was untouchable.
//                                                Node froze at 214,796 with 200 x 1/1.
//
// The root problem was never the numbers. It was that a peer's standing lived in
// several counters with filter stages between them, so there were regions the
// transitions did not cover. Standing is now a single clamped score; every
// response moves it in exactly one direction; selection takes the maximum over a
// total order. There is no region to hide in because there is one axis, and I2
// stops being a fallback branch because a maximum over a non-empty set is always
// a peer.
//
// Classification is RELATIVE to the gap: the same block count is a complete
// answer near the tip and a stall 36,000 blocks out. Absolute thresholds are
// wrong at one end of that range by construction.
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

/// Bounds on a peer's usefulness score. Clamped so no peer can accumulate an
/// unrecoverable deficit (a permanent ban in all but name) or an unassailable
/// lead (which would let a peer that HAS gone bad coast on old credit).
pub const SCORE_MAX: i32 = 8;
pub const SCORE_MIN: i32 = -8;

/// A response is MATERIAL if it carries at least this fraction of what a healthy
/// peer could have sent. Expressed as a divisor: 4 means "a quarter of what we
/// could have received".
pub const MATERIAL_FRACTION: usize = 4;

/// What one response did for us. Total over the outcome space: every response
/// classifies as exactly one of these, which is the property the previous design
/// lacked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeQuality {
    /// Carried a real share of what we still need. Evidence of a usable source.
    Material,
    /// Carried something, but far less than the gap warrants — the `1/1`
    /// pathology. Answering is not serving.
    Trickle,
    /// Carried nothing we could admit.
    Barren,
    /// Carried nothing we could admit, but WE asked the wrong question: the
    /// anchor we sent had already been passed by our own applied tip before the
    /// response came back. The peer answered exactly what it was asked. Scored
    /// neutral — see `classify_serve` for why this cannot be folded into Barren.
    Redundant,
}

/// Classify one response RELATIVE TO WHAT WE STILL NEED.
///
/// #155 — WHY THIS IS RELATIVE AND NOT ABSOLUTE.
///
/// Every previous attempt used a fixed threshold, and each one was wrong at one
/// end of the range. "Non-zero is useful" made a 1-block response look like
/// service while we needed 36,000 more. "8+ is useful" fixed that and created a
/// DEAD BAND at 1-7 where a peer was neither credited nor debited — so a peer
/// trickling exactly one block per response could never accumulate a demotion,
/// and a node sat frozen at 214,796 with 200 consecutive `imported 1/1`.
///
/// The same count means opposite things depending on the gap: one block when we
/// are one behind is a complete answer; one block when we are 36,000 behind is a
/// peer that cannot carry us. So the yardstick is the gap itself, capped by what
/// a single response could physically hold.
/// #156 — WHY AN EMPTY RESPONSE IS NOT ALWAYS THE PEER'S FAULT.
///
/// Measured on chain 40204, 2026-08-03, cold-syncing against rpc-1 as the SOLE
/// peer. rpc-1 was healthy by every server-side measure: producing at the
/// nominal 2s, answering 965 GetBlocks in 10 minutes at a FULL 32/32 fill, mean
/// serve latency 0.66s — identical to the peers that were syncing fine. It was
/// nonetheless scored `Barren` 191 times against 21 `Trickle`, driven to the
/// -8 floor, because our node kept re-requesting an anchor its own applied tip
/// had already passed: the same 32-block range imported 6-8 times per cycle,
/// every duplicate landing as `new_blocks == 0`.
///
/// That is our defect being charged to the peer. With one peer it wasted ~7/8 of
/// throughput; with four it flattened EVERY peer to -8, left nothing selectable,
/// and collapsed the sync — the mechanism behind six failed tip runs whose
/// collapse points (175k, 207k, 214k, 220k, 227k) drifted with threshold tuning
/// that never touched the cause.
///
/// `stale_anchor` is the ONLY thing separating this from the #153 pathology, and
/// the two are indistinguishable from response content alone. Both show
/// `new_blocks == 0` with the peer's advertised head far above our tip:
///   - #153: boot3 sat at OUR height with a gossip-inflated head, and served our
///     own anchor group back 30 times. Anchor was CURRENT; the peer genuinely
///     had nothing. Must stay Barren, or it is re-promoted and re-wedges us.
///   - #156: rpc-1 had 293k blocks we needed and would have sent them had we
///     asked from the right place. Anchor was BEHIND our applied tip.
///
/// So the discriminator is not what came back, it is whether the question was
/// still valid when the answer arrived.
pub fn classify_serve(
    new_blocks: usize,
    gap: u64,
    batch_size: usize,
    stale_anchor: bool,
) -> ServeQuality {
    if new_blocks == 0 {
        return if stale_anchor {
            ServeQuality::Redundant
        } else {
            ServeQuality::Barren
        };
    }
    // The most a healthy peer could have sent us in one response.
    let attainable = (gap as usize).min(batch_size);
    if attainable == 0 {
        // We are at the tip; any block at all is a complete answer.
        return ServeQuality::Material;
    }
    if new_blocks.saturating_mul(MATERIAL_FRACTION) >= attainable {
        ServeQuality::Material
    } else {
        ServeQuality::Trickle
    }
}

/// Per-peer sync accounting plus the selection policy built on it.
///
/// #155 — RESTATED AS A SCORE, NOT A LATTICE OF FLAGS.
///
/// The previous shape carried three interacting pieces of state (a useless
/// streak, a served watermark, a demotion predicate) with four thresholds
/// between them. Every fix added a threshold, and every threshold created a
/// region the transitions did not cover:
///
///   D2  (#136) exclude at >=3, reset at >=5   -> peers stranded in [3,5)
///   #153      "any non-zero response is service" -> a 1-block trickle looked useful
///   #154      "8+ is service"                    -> 1-7 credited nothing, debited
///                                                   nothing; a peer trickling one
///                                                   block per response was
///                                                   untouchable. Node froze at
///                                                   214,796 with 200 x `1/1`.
///
/// The lesson is structural, not arithmetic: a peer's standing was a POINT IN A
/// MULTI-DIMENSIONAL SPACE, and no one checked that the transitions covered it.
/// So standing is now ONE number. Every response moves it, in exactly one
/// direction, by a bounded amount. There is no region to hide in because there is
/// only one axis and every outcome maps onto it.
///
/// It also makes I2 structural rather than a special case. Selection takes the
/// MAXIMUM score among candidates, so "never veto every peer" is not a fallback
/// branch that could be forgotten — it is what `max` means. A network of uniformly
/// terrible peers still yields the least-terrible one.
///
/// `failures` stays separate on purpose: it counts TIMEOUTS and drives the
/// drop-and-re-handshake escalation in main.rs, which is about connection health,
/// not usefulness. A peer can be perfectly responsive and useless (that is exactly
/// what boot3 was), or slow and invaluable. Conflating them is what made
/// `record_success` clear a penalty for a peer that had served nothing.
#[derive(Debug, Default)]
pub struct SyncPeerSelector {
    /// Sync-request timeouts. Drives drop-and-re-handshake (connection health).
    failures: HashMap<String, u32>,
    /// Usefulness, in [SCORE_MIN, SCORE_MAX]. Absent == 0 == unproven/neutral,
    /// so a peer we have never pulled from competes on equal footing and has to
    /// earn its standing either way.
    score: HashMap<String, i32>,
    /// Highest height this peer actually delivered and we admitted. Kept for the
    /// tie-break and for diagnostics: unlike advertised head it cannot be
    /// inflated by relayed gossip (I4).
    served: HashMap<String, u64>,
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

    /// Clear `id`'s TIMEOUT count because it is being dropped and will
    /// re-handshake — the reconnection starts from a clean slate.
    ///
    /// Deliberately does NOT touch the usefulness score: a peer that was useless
    /// before a reconnect is very likely still useless after it (it is the same
    /// node at the same height), and forgetting that on every drop is how a bad
    /// source keeps getting re-selected. Connection health resets; standing does
    /// not.
    pub fn reset(&mut self, id: &str) {
        self.failures.remove(id);
    }

    /// Record what one response actually did for us. THE single usefulness entry
    /// point — there is deliberately no way to credit a peer without saying how
    /// much it delivered relative to what we needed.
    ///
    /// Returns the classification so the caller can log it.
    pub fn record_serve(
        &mut self,
        id: &str,
        new_blocks: usize,
        highest_height: u64,
        gap: u64,
        batch_size: usize,
        stale_anchor: bool,
    ) -> ServeQuality {
        let quality = classify_serve(new_blocks, gap, batch_size, stale_anchor);
        let delta = match quality {
            // Answering with real content also clears the timeout penalty: it is
            // live AND useful (I3).
            ServeQuality::Material => {
                self.failures.remove(id);
                1
            }
            // Answering at all proves liveness, so the timeout penalty clears —
            // but usefulness falls. These two facts are independent and must not
            // cancel each other out.
            ServeQuality::Trickle => {
                self.failures.remove(id);
                -1
            }
            // Nothing admissible. Liveness is real but standing drops faster:
            // serving back only blocks we already hold is the strongest evidence
            // a peer is at or behind us.
            ServeQuality::Barren => {
                self.failures.remove(id);
                -2
            }
            // #156: the peer answered the question we asked; the question was
            // stale. Liveness is proven (so the timeout penalty clears) but
            // standing must not move — crediting it would let a genuinely
            // useless peer launder duplicates into a positive score, and
            // debiting it is what drove a healthy sole source to -8.
            ServeQuality::Redundant => {
                self.failures.remove(id);
                0
            }
        };
        let e = self.score.entry(id.to_string()).or_insert(0);
        *e = (*e + delta).clamp(SCORE_MIN, SCORE_MAX);

        if new_blocks > 0 {
            let w = self.served.entry(id.to_string()).or_insert(0);
            if highest_height > *w {
                *w = highest_height;
            }
        }
        quality
    }

    /// Current usefulness score (0 when never pulled from).
    pub fn score(&self, id: &str) -> i32 {
        self.score.get(id).copied().unwrap_or(0)
    }

    /// Highest height `id` has actually delivered (0 if it never has).
    pub fn served(&self, id: &str) -> u64 {
        self.served.get(id).copied().unwrap_or(0)
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
        // I1 — only peers strictly ahead of our applied tip can help. Advertised
        // head is unreliable (I4), but it is a valid NECESSARY condition: a peer
        // that does not even claim to be ahead certainly cannot advance us.
        let useful: Vec<&SyncCandidate> = candidates
            .iter()
            .filter(|c| c.head_height > applied_height)
            .collect();
        if useful.is_empty() {
            return None;
        }

        // #155 — ONE ORDERING, NO FILTERS, NO FALLBACK LADDER.
        //
        // The old body was three successive filter-then-pick stages (clean ->
        // unpenalised -> everything), each with its own predicate. Every stage
        // boundary was a place for a peer to be excluded by one rule and not
        // re-admitted by any other; that is how the [3,5) dead band, the
        // "1-7 blocks" dead band, and the 38-cycle demote/forgive oscillation all
        // happened.
        //
        // Now there is a single total order and we take its maximum. Ranking, in
        // order of decreasing authority:
        //
        //   1. usefulness score  — what the peer has actually DONE for us
        //   2. served watermark  — how far it has actually carried us
        //   3. advertised head   — the weakest evidence, gossip-inflatable (I4)
        //   4. peer id           — deterministic tie-break, never oscillates
        //
        // Score outranks advertised head deliberately: on this fleet gossip pins
        // every advertised head to the tip, so ranking on it first is ranking on
        // noise. A peer that has served us is preferred over one that merely
        // claims height, which is the whole content of I4.
        //
        // I2 is now STRUCTURAL. "Never veto every peer" is not a fallback branch
        // that a future edit could forget — taking a maximum over a non-empty set
        // always yields a peer. A network of uniformly bad peers still returns the
        // least-bad one, and its score recovers the moment it serves.
        //
        // Timeouts still de-prefer, but as a term in the order rather than a
        // filter: a peer with failures is ranked below an equal peer without them,
        // and can still be selected when it is all we have — which is what
        // unfreezes its counter.
        useful.into_iter().max_by(|a, b| {
            let fa = i32::from(self.failures(&a.id) >= DEPREFER_AT_FAILURES);
            let fb = i32::from(self.failures(&b.id) >= DEPREFER_AT_FAILURES);
            // Lower penalty flag is better, so compare b to a.
            fb.cmp(&fa)
                .then_with(|| self.score(&a.id).cmp(&self.score(&b.id)))
                .then_with(|| self.served(&a.id).cmp(&self.served(&b.id)))
                .then_with(|| a.head_height.cmp(&b.head_height))
                .then_with(|| b.id.cmp(&a.id))
        })
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
        // #155: any RESPONSE clears the timeout penalty — answering proves
        // liveness, which is what a timeout measured. Usefulness is a separate
        // axis now (`score`), so a live-but-useless peer sheds its timeouts and
        // still loses standing. Conflating the two is what let `record_success`
        // reward a peer that had served nothing.
        sel.record_serve("rpc1", 32, 68_000, 13_491, 32, false);
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

    /// #155 — THE CLASSIFIER HAS NO DEAD BAND. Every (blocks, gap) pair maps to
    /// exactly one quality. This is the property both previous designs lacked, and
    /// it is checked exhaustively over the interesting range rather than asserted.
    #[test]
    fn every_response_classifies_somewhere() {
        for gap in [0u64, 1, 5, 31, 32, 1_000, 36_000, 200_000] {
            for blocks in 0..=64usize {
                let q = classify_serve(blocks, gap, 32, false);
                // Total: the match is exhaustive by construction, but pin the
                // boundary semantics that the dead bands violated.
                match q {
                    ServeQuality::Barren => assert_eq!(blocks, 0,
                        "only an empty response is barren (gap={})", gap),
                    // #156: unreachable on a CURRENT anchor — an empty response
                    // is only excused when we asked from behind our own tip.
                    ServeQuality::Redundant => panic!(
                        "a current anchor must never classify Redundant (gap={}, blocks={})",
                        gap, blocks
                    ),
                    ServeQuality::Trickle | ServeQuality::Material => assert!(blocks > 0),
                }
            }
        }
    }

    /// RED (#156) — a healthy peer answering a question our own applied tip has
    /// already passed must NOT be penalized. Live shape: rpc-1 serving a full
    /// 32/32 at 0.66s while we re-asked an anchor 31 blocks behind our tip; it
    /// was scored Barren 191 times and driven to the -8 floor.
    #[test]
    fn a_duplicate_caused_by_our_own_stale_anchor_does_not_penalize_the_peer() {
        assert_eq!(
            classify_serve(0, 293_116, 32, true),
            ServeQuality::Redundant,
            "our stale anchor is not the peer's failure"
        );
        let mut sel = SyncPeerSelector::new();
        // Six duplicate cycles — the measured per-stall count.
        for _ in 0..6 {
            sel.record_serve("noise_6ee5_rpc1", 0, 0, 293_116, 32, true);
        }
        assert_eq!(
            sel.score("noise_6ee5_rpc1"),
            0,
            "a peer serving full batches must not drift toward the floor because \
             WE asked from behind our own tip"
        );
    }

    /// The #153 pathology must SURVIVE the #156 fix. A peer sitting at our own
    /// height with a gossip-inflated head, serving our anchor group back, is
    /// genuinely useless and must still be demoted — the anchor there is
    /// CURRENT, so `stale_anchor` is false and the verdict stays Barren.
    #[test]
    fn a_peer_with_nothing_new_on_a_current_anchor_is_still_barren() {
        assert_eq!(
            classify_serve(0, 35_451, 32, false),
            ServeQuality::Barren,
            "#153 must not be laundered into Redundant"
        );
        let mut sel = SyncPeerSelector::new();
        for _ in 0..6 {
            sel.record_serve("noise_2b49_boot3", 0, 0, 35_451, 32, false);
        }
        assert!(
            sel.score("noise_2b49_boot3") < 0,
            "a peer that truly has nothing for us must still lose standing"
        );
    }

    /// RED — the #154 dead band, at the exact shape that froze a node at 214,796
    /// with 200 consecutive `imported 1/1`. One block against a 36,000 gap must
    /// be a TRICKLE: previously it was credited as service (>0) and then, once
    /// the threshold moved to 8, credited as nothing at all — neither up nor
    /// down, so the peer could never be demoted.
    #[test]
    fn one_block_against_a_huge_gap_is_a_trickle() {
        assert_eq!(classify_serve(1, 36_000, 32, false), ServeQuality::Trickle);
        // …and the whole former dead band 1-7 is now on the debit side.
        for blocks in 1..=7 {
            assert_eq!(
                classify_serve(blocks, 36_000, 32, false),
                ServeQuality::Trickle,
                "{} blocks against a 36k gap must count against the peer — this \
                 range was the dead band that froze the node",
                blocks
            );
        }
    }

    /// The other end of the range, which absolute thresholds always got wrong:
    /// near the tip a small response is a COMPLETE answer and must not be
    /// punished, or a healthy at-tip peer would be demoted for being caught up.
    #[test]
    fn a_small_response_near_the_tip_is_material() {
        assert_eq!(classify_serve(1, 1, 32, false), ServeQuality::Material);
        assert_eq!(classify_serve(2, 2, 32, false), ServeQuality::Material);
        assert_eq!(classify_serve(1, 0, 32, false), ServeQuality::Material);
        // A full batch is material at any distance.
        assert_eq!(classify_serve(32, 200_000, 32, false), ServeQuality::Material);
    }

    /// The live 40204 shape: every peer advertises the gossip-inflated tip, so
    /// advertised head carries no signal. The peer that has actually served must
    /// win, and the one trickling must fall away — without any filter stage.
    #[test]
    fn the_peer_that_serves_outranks_the_one_that_only_claims() {
        let applied = 177_771;
        let tip = 213_222;
        let peers = [
            cand("noise_2b49_boot3", tip), // lowest id — won every old tie-break
            cand("noise_6ee5_rpc1", tip),
        ];
        let mut sel = SyncPeerSelector::new();

        // Unproven: the id tie-break still decides, which is fine — no evidence yet.
        assert_eq!(
            sel.select(&peers, applied).map(|c| c.id.as_str()),
            Some("noise_2b49_boot3")
        );

        // boot3 trickles twice; rpc-1 serves a real batch once.
        sel.record_serve("noise_2b49_boot3", 1, applied, 35_451, 32, false);
        sel.record_serve("noise_2b49_boot3", 1, applied, 35_451, 32, false);
        sel.record_serve("noise_6ee5_rpc1", 32, applied + 32, 35_451, 32, false);

        assert_eq!(
            sel.select(&peers, applied).map(|c| c.id.as_str()),
            Some("noise_6ee5_rpc1"),
            "demonstrated service must beat an equal advertised head — this is the \
             boot3 trap that sent 63 of 66 requests to the one useless peer"
        );
    }

    /// I2, now STRUCTURAL: a maximum over a non-empty set is always a peer. Even
    /// when every candidate has bottomed out, selection returns one — being
    /// sourceless is the worse failure, and this can no longer be forgotten
    /// because there is no fallback branch to forget.
    #[test]
    fn selection_never_returns_none_while_any_peer_is_ahead() {
        let peers = [cand("a", 9_000), cand("b", 9_000)];
        let mut sel = SyncPeerSelector::new();
        for _ in 0..50 {
            sel.record_serve("a", 0, 0, 8_000, 32, false);
            sel.record_serve("b", 0, 0, 8_000, 32, false);
            sel.record_timeout("a");
            sel.record_timeout("b");
        }
        assert_eq!(sel.score("a"), SCORE_MIN, "score is clamped, not unbounded");
        assert!(
            sel.select(&peers, 1_000).is_some(),
            "I2: a maximum over a non-empty candidate set is always a peer"
        );
    }

    /// Recovery is bounded in both directions by the clamp: a peer that bottomed
    /// out climbs back with a bounded number of real serves, so a bad patch is
    /// never a life sentence (the D2 latch, restated).
    #[test]
    fn a_bottomed_out_peer_recovers_in_bounded_time() {
        let mut sel = SyncPeerSelector::new();
        for _ in 0..100 {
            sel.record_serve("recovering", 0, 0, 50_000, 32, false);
        }
        assert_eq!(sel.score("recovering"), SCORE_MIN);
        for _ in 0..(SCORE_MAX - SCORE_MIN) {
            sel.record_serve("recovering", 32, 99_999, 50_000, 32, false);
        }
        assert_eq!(
            sel.score("recovering"),
            SCORE_MAX,
            "a peer that genuinely starts serving climbs all the way back within \
             SCORE_MAX-SCORE_MIN good responses, however long it was bad"
        );
    }

    /// Timeouts de-prefer but never veto — now expressed as a term in the order
    /// rather than a filter stage, so a penalised peer is still reachable when it
    /// is all we have (which is what lets its counter move again).
    #[test]
    fn a_timed_out_peer_is_still_reachable_when_it_is_all_we_have() {
        let peers = [cand("only", 9_000)];
        let mut sel = SyncPeerSelector::new();
        for _ in 0..DEPREFER_AT_FAILURES + 2 {
            sel.record_timeout("only");
        }
        assert_eq!(
            sel.select(&peers, 100).map(|c| c.id.as_str()),
            Some("only"),
            "the penalty box must never be a veto on the last peer"
        );
    }

    /// …but is ranked below an equal peer without penalties.
    #[test]
    fn a_clean_peer_outranks_a_timed_out_one() {
        let peers = [cand("flaky", 9_000), cand("clean", 9_000)];
        let mut sel = SyncPeerSelector::new();
        for _ in 0..DEPREFER_AT_FAILURES {
            sel.record_timeout("flaky");
        }
        assert_eq!(
            sel.select(&peers, 100).map(|c| c.id.as_str()),
            Some("clean")
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
