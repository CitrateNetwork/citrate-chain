// node/src/finality_driver.rs
//
// WP-S.3 Stage 1a — feeds the consensus `FinalityGadget` from this node's
// canonical chain (docs/consensus/CHECKPOINT_FINALITY_WIRING.md §3, §4.2–4.3).
//
// Once per second the driver reads the APPLIED tip (the chain this node has
// executed and state-root-verified — `CanonicalApplicator::applied_tip`), walks
// its selected-parent chain down through the block store
// (`StorageManager.blocks.get_header`), and for every checkpoint boundary height
// H that is now buried at least `vote_depth` blocks below the tip (§3: never vote
// at the tip) hands `(H, hash_at_H, header.vrf_reveal.output)` to the gadget,
// which proposes, signs (if this node is a committee member) and replays early
// votes. The resulting votes are broadcast as `NetworkMessage::CheckpointVote`.
//
// Restart safety (no equivocation) is NOT this loop's job: the gadget records
// every signing decision durably — synced, before the vote exists — and refuses
// a different hash at an already-signed height, in this process or any later
// one (`checkpoint_gadget::SignRefusal`). So boundaries already buried when the
// process starts are processed like any other (bounded by
// MAX_BOUNDARIES_PER_PASS), which also lets a restarted validator re-broadcast
// the identical vote it signed before going down.
//
// Own-vote retry: the cursor advances past every boundary it hands to the
// gadget, but a boundary whose own vote failed for a TRANSIENT reason (the
// durable signed-vote store was unavailable — `BuriedOutcome::own_vote_retryable`)
// is remembered in `OwnVoteRetries` and reported again on later passes, so a
// storage hiccup does not cost this validator its vote until restart. Retries
// are bounded (attempts, height horizon, entry count), run after the new
// boundaries of the pass, and use their own canonical walk, so they never
// delay or block progress on later boundaries. They end on success, on a
// permanent refusal, or once the checkpoint is finalized / below the floor
// (the gadget then reports it as not retryable).
//
// Safety-stop revisit (Stage 1c): while the finality floor verifier holds the
// safety stop, the gadget proposes and signs nothing, so boundaries buried
// during the halt are recorded in the same `OwnVoteRetries` (as
// `Followup::Halted`, consuming no attempt) instead of being lost behind the
// cursor. Nothing is due while the stop is engaged; once it clears they are
// reported again on a fresh canonical walk from the current tip — bounded to
// MAX_HALT_REVISITS boundaries within OWN_VOTE_RETRY_HORIZON_BLOCKS. Each
// revisit goes through the gadget's normal path (signing gate, durable
// signed-vote record), so a height already signed for a different hash before
// the halt is still refused.
//
// Held own vote: an own vote the gadget signed just BEFORE the stop engaged
// (still under its signing gate) is withheld from broadcast while the stop is
// engaged. The gadget has already submitted it locally, so a later report of
// the same boundary finds it pending and emits nothing — the vote would never
// reach peers until restart. The driver therefore keeps that already-signed
// vote with the halted boundary and, on the revisit after the stop clears,
// re-broadcasts the SAME recorded vote (only if its block is still canonical at
// that height). No new signature is created for it; the broadcast is still
// withheld while the stop is engaged.
//
// Spawned ONLY when the compiled switch (`checkpoint_voting_pinned`) is on for the
// running chain; with it off this module never runs.

// PANIC-S1 G2: runs on the live node; panic-free outside tests.
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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use citrate_consensus::checkpoint::CheckpointVote;
use citrate_consensus::checkpoint_gadget::{
    FinalityGadget, FinalizeRetryOutcome, SignRefusal, SkipReason, EARLY_VOTE_HORIZON_BLOCKS,
};
use citrate_consensus::crypto::Ed25519SigningKey;
use citrate_consensus::types::{Hash, PublicKey};
use citrate_network::peer::PeerManager;
use citrate_network::NetworkMessage;
use citrate_storage::StorageManager;
use tracing::{debug, info, warn};

use crate::canonical_apply::CanonicalApplicator;

/// How many boundary heights one pass may process. Bounds the selected-parent
/// walk after a pause (e.g. a long catch-up): older boundaries are skipped, not
/// queued — a checkpoint is only useful near the tip.
pub const MAX_BOUNDARIES_PER_PASS: u64 = 8;

/// Attempts per boundary at re-casting an own vote that failed recoverably
/// (one attempt per driver pass, i.e. about one per second).
pub const MAX_OWN_VOTE_ATTEMPTS: u32 = 60;
/// Boundaries tracked for own-vote retry at once; past it the LOWEST is dropped
/// (a checkpoint is only useful near the tip).
pub const MAX_OWN_VOTE_RETRIES: usize = 16;
/// Boundaries tracked for a revisit after the safety stop clears; past it the
/// LOWEST is dropped (a checkpoint is only useful near the tip).
pub const MAX_HALT_REVISITS: usize = 32;
/// A retried or revisited boundary more than this many blocks below the
/// highest buried boundary is dropped (the same horizon the gadget's early-vote
/// buffer uses).
pub const OWN_VOTE_RETRY_HORIZON_BLOCKS: u64 = EARLY_VOTE_HORIZON_BLOCKS;

/// What a boundary needs after one report to the gadget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Followup {
    /// Nothing: proposed/voted, permanently refused, finalized, or not
    /// applicable. Report it again only if it shows up as a new boundary.
    Done,
    /// The own vote failed for a transient reason
    /// (`BuriedOutcome::own_vote_retryable`): retry on later passes, bounded by
    /// [`MAX_OWN_VOTE_ATTEMPTS`].
    Retry,
    /// The Stage 1c safety stop was engaged (the gadget skipped or refused it,
    /// or its outbound votes were withheld): revisit it once the stop clears.
    /// Consumes no retry attempt.
    Halted,
}

/// Boundaries to report again on later passes: own votes that failed
/// recoverably (with the attempts made so far) and boundaries passed while the
/// safety stop was engaged. Bounded by entry count and height horizon; nothing
/// is due while the stop is engaged.
#[derive(Debug, Default)]
pub struct OwnVoteRetries {
    attempts: BTreeMap<u64, u32>,
    halted: BTreeSet<u64>,
    /// Own votes already signed (before the stop engaged) but withheld from
    /// broadcast, keyed by height. Always a subset of `halted`: re-broadcast
    /// as-is on the revisit after the stop clears, never re-signed.
    held: BTreeMap<u64, CheckpointVote>,
}

impl OwnVoteRetries {
    /// Record the result of one report at `height`.
    pub fn record(&mut self, height: u64, followup: Followup) {
        match followup {
            Followup::Done => {
                self.attempts.remove(&height);
                self.halted.remove(&height);
                self.held.remove(&height);
            }
            Followup::Halted => {
                self.attempts.remove(&height);
                self.mark_halted(height);
            }
            Followup::Retry => {
                self.halted.remove(&height);
                self.held.remove(&height);
                let made = self
                    .attempts
                    .get(&height)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(1);
                if made >= MAX_OWN_VOTE_ATTEMPTS {
                    self.attempts.remove(&height);
                    warn!(
                        "checkpoint {}: own vote still not cast after {} attempts; giving up",
                        height, made
                    );
                    return;
                }
                self.attempts.insert(height, made);
                while self.attempts.len() > MAX_OWN_VOTE_RETRIES {
                    if self.attempts.pop_first().is_none() {
                        break;
                    }
                }
            }
        }
    }

    /// Track `height` for a revisit after the stop clears (bounded: past
    /// [`MAX_HALT_REVISITS`] the LOWEST is dropped with its held vote).
    fn mark_halted(&mut self, height: u64) {
        self.halted.insert(height);
        while self.halted.len() > MAX_HALT_REVISITS {
            match self.halted.pop_first() {
                Some(dropped) => {
                    self.held.remove(&dropped);
                }
                None => break,
            }
        }
    }

    /// Keep this node's own vote, already signed but withheld because the
    /// safety stop is engaged, for re-broadcast on the revisit after the stop
    /// clears. The first vote held at a height is kept (the durable signed-vote
    /// record admits only one hash per height, so a second one is the same).
    pub fn hold(&mut self, vote: CheckpointVote) {
        let height = vote.height;
        self.attempts.remove(&height);
        self.mark_halted(height);
        if self.halted.contains(&height) {
            self.held.entry(height).or_insert(vote);
        }
    }

    /// Whether an own vote is held at `height`.
    pub fn has_held(&self, height: u64) -> bool {
        self.held.contains_key(&height)
    }

    /// Take the own vote held at `height`, if any.
    pub fn take_held(&mut self, height: u64) -> Option<CheckpointVote> {
        self.held.remove(&height)
    }

    /// Forget `height` (e.g. it is no longer on the canonical chain).
    pub fn forget(&mut self, height: u64) {
        self.attempts.remove(&height);
        self.halted.remove(&height);
        self.held.remove(&height);
    }

    /// Drop boundaries more than [`OWN_VOTE_RETRY_HORIZON_BLOCKS`] below
    /// `highest`, then return the heights due for another report, ascending:
    /// none while `halted` (the gadget would refuse them; entries are kept),
    /// otherwise every retry and every boundary passed during the stop.
    pub fn due(&mut self, highest: u64, halted: bool) -> Vec<u64> {
        let floor = highest.saturating_sub(OWN_VOTE_RETRY_HORIZON_BLOCKS);
        self.attempts.retain(|h, _| *h >= floor);
        self.halted.retain(|h| *h >= floor);
        self.held.retain(|h, _| *h >= floor);
        if halted {
            return Vec::new();
        }
        let mut due: BTreeSet<u64> = self.attempts.keys().copied().collect();
        due.extend(self.halted.iter().copied());
        due.into_iter().collect()
    }

    /// Number of boundaries tracked.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.attempts.len().saturating_add(self.halted.len())
    }

    /// Number of own votes held for re-broadcast.
    #[cfg(test)]
    fn held_len(&self) -> usize {
        self.held.len()
    }
}

/// This node's voting key as it appears in [`CheckpointVote::voter`].
fn signer_pk(signer: Option<&Ed25519SigningKey>) -> Option<PublicKey> {
    signer.map(|k| PublicKey::new(k.verifying_key().to_bytes()))
}

/// Hold this node's own votes out of `votes` (withheld because the safety stop
/// is engaged) for re-broadcast after it clears. Other votes (replayed early
/// votes, relays) are dropped as before: their signers broadcast them.
fn hold_own_votes(
    retries: &mut OwnVoteRetries,
    signer: Option<&Ed25519SigningKey>,
    votes: Vec<CheckpointVote>,
) {
    let Some(me) = signer_pk(signer) else {
        return;
    };
    for vote in votes {
        if vote.voter == me {
            debug!(
                "checkpoint {}: holding already-signed own vote for {} until the safety stop clears",
                vote.height, vote.block_hash
            );
            retries.hold(vote);
        }
    }
}

/// Broadcast gate applied after a pass: if the safety stop is engaged now,
/// nothing is returned for broadcast and this node's own votes are held for
/// re-broadcast after it clears (see module docs); otherwise `outbound` is
/// returned unchanged.
pub fn gate_outbound(
    gadget: &FinalityGadget,
    signer: Option<&Ed25519SigningKey>,
    retries: &mut OwnVoteRetries,
    outbound: Vec<CheckpointVote>,
) -> Vec<CheckpointVote> {
    if !gadget.halted() {
        return outbound;
    }
    if !outbound.is_empty() {
        debug!(
            "checkpoint finality: safety stop engaged; withholding {} outbound vote(s)",
            outbound.len()
        );
    }
    hold_own_votes(retries, signer, outbound);
    Vec::new()
}

/// A canonical checkpoint block buried at least `vote_depth` deep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuriedCheckpoint {
    pub height: u64,
    pub hash: Hash,
    /// The block's ECVRF beacon (`header.vrf_reveal.output`): the committee seed.
    pub seed: Hash,
}

/// The header fields the walk needs: (height, selected parent, VRF output).
pub type HeaderView = (u64, Hash, Hash);

/// The highest boundary height buried at least `depth` blocks below `tip_height`
/// (i.e. `<= tip_height - depth`), or `None` if there is none yet. `depth` is
/// clamped to >= 1 so a misconfigured 0 can never vote at the tip.
pub fn highest_buried_boundary(tip_height: u64, interval: u64, depth: u64) -> Option<u64> {
    if interval == 0 {
        return None;
    }
    let buried = tip_height.checked_sub(depth.max(1))?;
    let b = buried.checked_sub(buried.checked_rem(interval)?)?;
    (b > 0).then_some(b)
}

/// Boundary heights in `(after, highest_buried]`, ascending, at most
/// [`MAX_BOUNDARIES_PER_PASS`] of the highest ones.
pub fn boundaries_to_process(after: u64, highest: u64, interval: u64) -> Vec<u64> {
    let mut out = Vec::new();
    if interval == 0 {
        return out;
    }
    let mut h = highest;
    while h > after && h > 0 && (out.len() as u64) < MAX_BOUNDARIES_PER_PASS {
        out.push(h);
        match h.checked_sub(interval) {
            Some(next) => h = next,
            None => break,
        }
    }
    out.reverse();
    out
}

/// Walk the selected-parent chain down from `(tip_hash, tip_height)` and return
/// the canonical block at each height in `wanted`. A wanted height the chain
/// steps over (a selected parent more than one height below its child) is
/// simply absent — there is no canonical block "at" it on this chain, and every
/// node on the same chain skips it identically.
///
/// Data source: `lookup` — in production `StorageManager.blocks.get_header`.
pub fn canonical_at_heights<F>(
    tip_hash: Hash,
    tip_height: u64,
    wanted: &[u64],
    lookup: F,
) -> Result<Vec<BuriedCheckpoint>, String>
where
    F: Fn(&Hash) -> Result<Option<HeaderView>, String>,
{
    let want: BTreeSet<u64> = wanted.iter().copied().collect();
    let Some(&lowest) = want.first() else {
        return Ok(Vec::new());
    };
    let mut found = Vec::new();
    let mut cursor = tip_hash;
    // Each step strictly lowers the height, so this bounds the walk.
    let mut steps_left = tip_height.saturating_sub(lowest).saturating_add(1);
    while steps_left > 0 {
        steps_left = steps_left.saturating_sub(1);
        let Some((height, parent, seed)) = lookup(&cursor)? else {
            return Err(format!("canonical walk: header {cursor} missing"));
        };
        if want.contains(&height) {
            found.push(BuriedCheckpoint {
                height,
                hash: cursor,
                seed,
            });
        }
        if height <= lowest || height == 0 {
            break;
        }
        cursor = parent;
    }
    found.sort_by_key(|c| c.height);
    Ok(found)
}

fn to_message(vote: &CheckpointVote) -> NetworkMessage {
    NetworkMessage::CheckpointVote {
        height: vote.height,
        block_hash: vote.block_hash,
        voter_pubkey: vote.voter.as_bytes().to_vec(),
        signature: vote.signature.as_bytes().to_vec(),
    }
}

/// Broadcast votes the gadget produced (own vote, replayed early votes, relays).
pub async fn broadcast_votes(peers: &PeerManager, votes: &[CheckpointVote]) {
    for vote in votes {
        if let Err(e) = peers.broadcast(&to_message(vote)).await {
            warn!("checkpoint {}: vote broadcast failed: {}", vote.height, e);
        }
    }
}

/// Spawn the driver loop. `signer` is this node's consensus key (`proposer.key`,
/// the pubkey registered in `ValidatorRegistry`); `None` = observer node that
/// proposes and aggregates but never signs.
pub fn spawn(
    gadget: Arc<FinalityGadget>,
    applicator: Arc<CanonicalApplicator>,
    storage: Arc<StorageManager>,
    peers: Arc<PeerManager>,
    signer: Option<Ed25519SigningKey>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = gadget.manager().config().interval;
        let depth = gadget.manager().config().vote_depth.max(1);
        let mut tick = crate::timing::cadence_interval(Duration::from_secs(1));
        // Highest boundary already handed to the gadget. Starts at 0: there is no
        // "skip what was buried at startup" heuristic — equivocation across
        // restarts is prevented by the gadget's durable signed-vote record, which
        // is consulted on every sign attempt (see module docs).
        let mut cursor: u64 = 0;
        let mut retries = OwnVoteRetries::default();
        info!(
            "checkpoint finality: producer path ON (interval {}, vote depth {}, signer {})",
            interval,
            depth,
            if signer.is_some() { "present" } else { "none" }
        );
        let lookup = |h: &Hash| {
            storage
                .blocks
                .get_header(h)
                .map(|o| o.map(|hd| (hd.height, hd.selected_parent_hash, hd.vrf_reveal.output)))
                .map_err(|e| e.to_string())
        };
        loop {
            tick.tick().await;
            // A quorum checkpoint whose certificate write failed is retried
            // here (capped backoff), not only when another vote arrives.
            retry_finalizations(&gadget, Instant::now()).await;
            let tip = applicator.applied_tip().await;
            gadget.observe_tip(tip.height).await;
            let outbound = run_pass(
                &gadget,
                signer.as_ref(),
                &mut cursor,
                &mut retries,
                tip.hash,
                tip.height,
                &lookup,
            )
            .await;
            // Same rule as `report`: nothing is emitted once the stop is
            // engaged; this node's own already-signed votes are held and
            // re-broadcast after it clears.
            let outbound = gate_outbound(&gadget, signer.as_ref(), &mut retries, outbound);
            if outbound.is_empty() {
                continue;
            }
            broadcast_votes(&peers, &outbound).await;
        }
    })
}

/// Finalization retry step of the driver tick: re-attempt, with capped
/// backoff, every checkpoint that reached quorum but whose certificate could
/// not be written (`FinalityGadget::retry_finalizations`), so finality does
/// not wait for another vote that may never come.
pub async fn retry_finalizations(gadget: &FinalityGadget, now: Instant) -> FinalizeRetryOutcome {
    let out = gadget.retry_finalizations(now).await;
    crate::metrics::record_finality_finalize_retry(
        out.finalized.len().saturating_add(out.failed.len()),
        out.finalized.len(),
        out.pending,
    );
    if !out.failed.is_empty() {
        warn!(
            "checkpoint finality: certificate write still failing for {:?}; {} checkpoint(s) \
             awaiting a finalize retry",
            out.failed, out.pending
        );
    }
    out
}

/// One driver pass over the applied tip `(tip_hash, tip_height)`: report the
/// newly buried boundaries after `cursor` (advancing it), then the boundaries
/// due for another report ([`OwnVoteRetries::due`]: transient own-vote
/// failures, and boundaries passed while the safety stop was engaged once it
/// has cleared). Returns the votes to broadcast, in order.
///
/// Data source: `lookup` — in production `StorageManager.blocks.get_header`.
pub async fn run_pass<F>(
    gadget: &FinalityGadget,
    signer: Option<&Ed25519SigningKey>,
    cursor: &mut u64,
    retries: &mut OwnVoteRetries,
    tip_hash: Hash,
    tip_height: u64,
    lookup: &F,
) -> Vec<CheckpointVote>
where
    F: Fn(&Hash) -> Result<Option<HeaderView>, String>,
{
    let mut outbound = Vec::new();
    let interval = gadget.manager().config().interval;
    let depth = gadget.manager().config().vote_depth.max(1);
    let Some(highest) = highest_buried_boundary(tip_height, interval, depth) else {
        return outbound;
    };
    let heights = boundaries_to_process(*cursor, highest, interval);
    if !heights.is_empty() {
        match canonical_at_heights(tip_hash, tip_height, &heights, lookup) {
            Ok(found) => {
                for cp in found {
                    let next = report(gadget, signer, &cp, &mut outbound, retries).await;
                    retries.record(cp.height, next);
                }
            }
            Err(e) => {
                // The applied chain's headers are persisted before the tip
                // advances, so this is an anomaly (e.g. pruned store). Skip this
                // window rather than wedge on it forever: a missed checkpoint
                // costs finality latency, never safety.
                warn!(
                    "checkpoint finality: canonical walk failed, skipping boundaries {:?}: {}",
                    heights, e
                );
                *cursor = highest;
                return outbound;
            }
        }
        *cursor = highest;
    }
    revisit(
        gadget,
        signer,
        retries,
        tip_hash,
        tip_height,
        highest,
        lookup,
        &mut outbound,
    )
    .await;
    outbound
}

/// Hand one buried checkpoint to the gadget and collect what it produced for
/// broadcast. Returns what the boundary needs next. An own vote signed before
/// the safety stop engaged is held in `retries` (not broadcast) for the
/// revisit after the stop clears.
async fn report(
    gadget: &FinalityGadget,
    signer: Option<&Ed25519SigningKey>,
    cp: &BuriedCheckpoint,
    outbound: &mut Vec<CheckpointVote>,
    retries: &mut OwnVoteRetries,
) -> Followup {
    let out = gadget
        .on_buried_checkpoint(cp.height, cp.hash, &cp.seed, signer)
        .await;
    if let Some(reason) = &out.skipped {
        debug!("checkpoint {}: not proposed ({:?})", cp.height, reason);
    }
    // The gadget already logged the refusal at error level; nothing was
    // signed, submitted or queued for broadcast for it.
    if let Some(refusal) = &out.sign_refused {
        debug!("checkpoint {}: own vote refused ({:?})", cp.height, refusal);
    }
    // Safety stop engaged since the gadget returned: emit nothing. Any own
    // vote in `outbound` was signed before the stop, under the gadget's
    // signing gate; it is held and re-broadcast (not re-signed) on the revisit
    // after the stop clears, so withholding it only costs latency.
    if gadget.halted() {
        debug!(
            "checkpoint {}: safety stop engaged; withholding {} outbound vote(s)",
            cp.height,
            out.outbound.len()
        );
        hold_own_votes(retries, signer, out.outbound);
        return Followup::Halted;
    }
    if out.skipped == Some(SkipReason::Halted) || out.sign_refused == Some(SignRefusal::Halted) {
        // The stop was engaged during the call and has cleared since.
        return Followup::Halted;
    }
    outbound.extend(out.outbound);
    if out.own_vote_retryable {
        Followup::Retry
    } else {
        Followup::Done
    }
}

/// Re-report the boundaries due in `retries` (see module docs). Uses its own
/// canonical walk so a failure here never affects new boundaries.
#[allow(clippy::too_many_arguments)]
async fn revisit<F>(
    gadget: &FinalityGadget,
    signer: Option<&Ed25519SigningKey>,
    retries: &mut OwnVoteRetries,
    tip_hash: Hash,
    tip_height: u64,
    highest: u64,
    lookup: &F,
    outbound: &mut Vec<CheckpointVote>,
) where
    F: Fn(&Hash) -> Result<Option<HeaderView>, String>,
{
    let due = retries.due(highest, gadget.halted());
    if due.is_empty() {
        return;
    }
    let found = match canonical_at_heights(tip_hash, tip_height, &due, lookup) {
        Ok(f) => f,
        Err(e) => {
            warn!(
                "checkpoint finality: canonical walk for checkpoint revisit {:?} failed: {}",
                due, e
            );
            // Counts as an attempt, so a persistent walk failure is bounded too.
            // A boundary holding an already-signed own vote stays as it is
            // (bounded by the horizon) so the vote is not lost to a walk error.
            for h in due {
                if !retries.has_held(h) {
                    retries.record(h, Followup::Retry);
                }
            }
            return;
        }
    };
    for h in &due {
        // No canonical block at `h` on the current chain any more.
        if !found.iter().any(|cp| cp.height == *h) {
            retries.forget(*h);
        }
    }
    for cp in found {
        let held = retries.take_held(cp.height);
        let next = report(gadget, signer, &cp, outbound, retries).await;
        retries.record(cp.height, next);
        let Some(vote) = held else {
            continue;
        };
        if next == Followup::Halted {
            // Still (or again) halted: keep the vote for the next revisit.
            retries.hold(vote);
        } else if vote.block_hash != cp.hash {
            // The block it signs is no longer canonical at this height.
            debug!(
                "checkpoint {}: dropping held own vote for {} (canonical block is now {})",
                cp.height, vote.block_hash, cp.hash
            );
        } else if !outbound
            .iter()
            .any(|v| v.height == vote.height && v.voter == vote.voter)
        {
            // Re-broadcast the recorded vote as-is; nothing is signed here.
            outbound.push(vote);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn h(n: u8) -> Hash {
        Hash::new([n; 32])
    }

    #[test]
    fn never_votes_at_the_tip() {
        // depth 3, interval 2: tip 10 => buried 7 => boundary 6.
        assert_eq!(highest_buried_boundary(10, 2, 3), Some(6));
        assert_eq!(highest_buried_boundary(9, 2, 3), Some(6));
        assert_eq!(
            highest_buried_boundary(4, 2, 3),
            None,
            "only height 1 buried"
        );
        // depth 0 is clamped to 1: the tip itself is never a vote target.
        assert_eq!(highest_buried_boundary(10, 2, 0), Some(8));
        assert_eq!(highest_buried_boundary(10, 0, 3), None);
        assert_eq!(highest_buried_boundary(2, 2, 3), None);
    }

    #[test]
    fn boundaries_are_ascending_and_bounded() {
        assert_eq!(boundaries_to_process(4, 10, 2), vec![6, 8, 10]);
        assert_eq!(boundaries_to_process(10, 10, 2), Vec::<u64>::new());
        let many = boundaries_to_process(0, 1000, 2);
        assert_eq!(many.len() as u64, MAX_BOUNDARIES_PER_PASS);
        assert_eq!(many.last().copied(), Some(1000));
        assert_eq!(boundaries_to_process(0, 10, 0), Vec::<u64>::new());
    }

    /// Linear chain 0..=12 (hash n+1 at height n) with a sibling at 6 that is
    /// NOT on the selected-parent chain: the walk returns the canonical block.
    #[test]
    fn walk_returns_canonical_blocks_only() {
        let mut headers: HashMap<Hash, HeaderView> = HashMap::new();
        for n in 0u8..=12 {
            let parent = if n == 0 { Hash::default() } else { h(n) };
            headers.insert(
                h(n.saturating_add(1)),
                (u64::from(n), parent, h(n.saturating_add(100))),
            );
        }
        headers.insert(h(200), (6, h(6), h(201))); // orphan sibling at height 6
        let found = canonical_at_heights(h(13), 12, &[6, 8], |x| Ok(headers.get(x).copied()))
            .expect("walk");
        assert_eq!(
            found,
            vec![
                BuriedCheckpoint {
                    height: 6,
                    hash: h(7),
                    seed: h(106)
                },
                BuriedCheckpoint {
                    height: 8,
                    hash: h(9),
                    seed: h(108)
                },
            ]
        );
    }

    #[test]
    fn walk_errors_on_missing_header_and_skips_stepped_over_heights() {
        let headers: HashMap<Hash, HeaderView> = HashMap::from([
            (h(10), (10, h(7), h(1))),
            (h(7), (7, h(5), h(2))), // selected parent jumps from 10 to 7
            (h(5), (5, h(4), h(3))),
        ]);
        let found = canonical_at_heights(h(10), 10, &[8, 6], |x| Ok(headers.get(x).copied()))
            .expect("walk");
        assert!(found.is_empty(), "8 and 6 are stepped over: {found:?}");
        let err = canonical_at_heights(h(10), 10, &[2], |x| Ok(headers.get(x).copied()));
        assert!(err.is_err(), "missing header at 4 must defer, not guess");
    }

    #[test]
    fn own_vote_retries_are_bounded_and_cleared() {
        let mut r = OwnVoteRetries::default();
        r.record(10, Followup::Retry);
        r.record(12, Followup::Retry);
        r.record(14, Followup::Done); // never tracked
        assert_eq!(r.due(14, false), vec![10, 12]);
        // Success (not retryable) clears the entry.
        r.record(10, Followup::Done);
        assert_eq!(r.due(14, false), vec![12]);
        // Attempts are bounded.
        for _ in 1..MAX_OWN_VOTE_ATTEMPTS {
            r.record(12, Followup::Retry);
        }
        assert!(
            r.due(14, false).is_empty(),
            "dropped after MAX_OWN_VOTE_ATTEMPTS"
        );
        // Horizon: entries far below the highest buried boundary are dropped.
        r.record(20, Followup::Retry);
        r.record(400, Followup::Retry);
        assert_eq!(
            r.due(
                20u64
                    .saturating_add(OWN_VOTE_RETRY_HORIZON_BLOCKS)
                    .saturating_add(2),
                false
            ),
            vec![400]
        );
        // forget() removes one entry.
        r.forget(400);
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn own_vote_retries_cap_keeps_the_highest_boundaries() {
        let mut r = OwnVoteRetries::default();
        let n = (MAX_OWN_VOTE_RETRIES as u64).saturating_add(4);
        for i in 1..=n {
            r.record(i.saturating_mul(2), Followup::Retry);
        }
        assert_eq!(r.len(), MAX_OWN_VOTE_RETRIES);
        let due = r.due(n.saturating_mul(2), false);
        assert_eq!(due.first().copied(), Some(10), "lowest four dropped");
        assert_eq!(due.last().copied(), Some(n.saturating_mul(2)));
    }

    /// Boundaries passed while the safety stop is engaged consume no attempt,
    /// are never due while it is engaged, are due once it clears, and are
    /// bounded (count + horizon).
    #[test]
    fn halted_boundaries_wait_for_the_stop_to_clear_and_are_bounded() {
        let mut r = OwnVoteRetries::default();
        r.record(10, Followup::Retry);
        r.record(10, Followup::Halted); // a retry that hit the stop
        r.record(12, Followup::Halted);
        assert!(r.due(12, true).is_empty(), "nothing is due while halted");
        assert_eq!(r.len(), 2, "kept while halted");
        assert_eq!(r.due(12, false), vec![10, 12]);
        // A halted entry can be reported many times without being dropped.
        for _ in 0..MAX_OWN_VOTE_ATTEMPTS {
            r.record(12, Followup::Halted);
        }
        assert_eq!(r.due(12, false), vec![10, 12]);
        // Done clears it; Retry moves it to the bounded retry set.
        r.record(10, Followup::Done);
        r.record(12, Followup::Retry);
        assert_eq!(r.due(12, false), vec![12]);
        r.forget(12);
        // Count cap keeps the highest boundaries.
        let n = (MAX_HALT_REVISITS as u64).saturating_add(3);
        for i in 1..=n {
            r.record(i.saturating_mul(2), Followup::Halted);
        }
        assert_eq!(r.len(), MAX_HALT_REVISITS);
        let due = r.due(n.saturating_mul(2), false);
        assert_eq!(due.first().copied(), Some(8), "lowest three dropped");
        // Horizon applies while halted too.
        let far = n
            .saturating_mul(2)
            .saturating_add(OWN_VOTE_RETRY_HORIZON_BLOCKS)
            .saturating_add(2);
        assert!(r.due(far, true).is_empty());
        assert_eq!(r.len(), 0, "all below the horizon");
    }

    /// Held own votes ride on the halted boundary: due only once the stop
    /// clears, dropped with it (Done / Retry / forget / count cap / horizon).
    #[test]
    fn held_own_votes_follow_their_halted_boundary() {
        use citrate_consensus::types::{PublicKey, Signature};
        let vote = |height: u64| CheckpointVote {
            height,
            block_hash: h(9),
            voter: PublicKey::new([3; 32]),
            signature: Signature::new([4; 64]),
        };
        let mut r = OwnVoteRetries::default();
        r.record(10, Followup::Retry);
        r.hold(vote(10));
        assert!(r.has_held(10));
        assert!(r.due(10, true).is_empty(), "nothing due while halted");
        assert_eq!(r.due(10, false), vec![10], "moved from retry to halted");
        assert_eq!(r.len(), 1);
        // The first held vote at a height is kept.
        let mut other = vote(10);
        other.signature = Signature::new([5; 64]);
        r.hold(other);
        assert_eq!(
            r.take_held(10).map(|v| v.signature.as_bytes().to_vec()),
            Some(vec![4u8; 64]),
            "first held vote kept"
        );
        assert!(r.take_held(10).is_none());
        // Done / Retry / forget drop it.
        r.hold(vote(12));
        r.record(12, Followup::Done);
        assert!(!r.has_held(12));
        r.hold(vote(14));
        r.record(14, Followup::Retry);
        assert!(!r.has_held(14));
        r.hold(vote(16));
        r.forget(16);
        assert!(!r.has_held(16));
        r.forget(10);
        r.forget(14);
        assert_eq!(r.len(), 0);
        // Count cap: the lowest boundary is dropped together with its vote.
        let n = (MAX_HALT_REVISITS as u64).saturating_add(1);
        for i in 1..=n {
            r.hold(vote(i.saturating_mul(2)));
        }
        assert_eq!(r.held_len(), MAX_HALT_REVISITS);
        assert!(!r.has_held(2), "lowest dropped");
        // Horizon.
        let far = n
            .saturating_mul(2)
            .saturating_add(OWN_VOTE_RETRY_HORIZON_BLOCKS)
            .saturating_add(2);
        assert!(r.due(far, false).is_empty());
        assert_eq!(r.held_len(), 0);
    }

    mod revisit_after_halt {
        use super::super::*;
        use citrate_consensus::checkpoint::{CheckpointConfig, CheckpointManager};
        use citrate_consensus::checkpoint_gadget::SignRefusal;
        use citrate_consensus::dag_store::DagStore;
        use citrate_consensus::types::{BlockBuilder, PublicKey};
        use citrate_consensus::vrf::VrfProposerSelector;
        use std::collections::HashMap;

        use crate::persistent_dag::RocksDbKvStore;

        const CHAIN: u64 = 40204;

        fn key(i: u8) -> Ed25519SigningKey {
            Ed25519SigningKey::from_bytes(&[i.saturating_add(1); 32])
        }

        fn pk(k: &Ed25519SigningKey) -> PublicKey {
            PublicKey::new(k.verifying_key().to_bytes())
        }

        /// Interval 2, vote depth 3, committee of 4 (quorum 3: one own vote
        /// never finalizes).
        fn config() -> CheckpointConfig {
            CheckpointConfig {
                interval: 2,
                committee_size: 100,
                quorum_threshold: 67,
                chain_id: CHAIN,
                vote_depth: 3,
            }
        }

        /// A chain 0..=len-1 stored in `dag`; `tag` makes the hashes distinct
        /// per chain. Returns the header map the driver walks and the hashes.
        async fn chain(dag: &DagStore, len: u8, tag: u8) -> (HashMap<Hash, HeaderView>, Vec<Hash>) {
            let mut headers = HashMap::new();
            let mut hashes = Vec::new();
            let mut parent = Hash::default();
            for i in 0..len {
                let mut raw = [i.saturating_add(1); 32];
                raw[0] = tag;
                let b = BlockBuilder::new()
                    .hash(Hash::new(raw))
                    .height(u64::from(i))
                    .parent(parent)
                    .build_unhashed();
                let hash = b.hash();
                headers.insert(hash, (u64::from(i), parent, Hash::new([7; 32])));
                hashes.push(hash);
                parent = hash;
                dag.store_block(b).await.expect("store test block");
            }
            (headers, hashes)
        }

        async fn gadget_over(
            dag: Arc<DagStore>,
            storage: &StorageManager,
            committee: &[Ed25519SigningKey],
        ) -> FinalityGadget {
            let mgr = Arc::new(CheckpointManager::with_persistence(
                config(),
                dag,
                Arc::new(RocksDbKvStore::new(storage.db.clone())),
            ));
            let sel = VrfProposerSelector::new().with_snapshot_schedule(1000, 999);
            let set: Vec<(PublicKey, u128)> = committee.iter().map(|k| (pk(k), 1000u128)).collect();
            sel.sync_active_set_at(1, set, 1).await;
            FinalityGadget::with_switch(mgr, Some(Arc::new(sel)), true)
        }

        fn heights(votes: &[CheckpointVote]) -> Vec<u64> {
            votes.iter().map(|v| v.height).collect()
        }

        /// L1: boundaries buried while the safety stop is engaged are not lost
        /// behind the cursor. Once the stop clears, the next pass proposes them
        /// and casts this node's vote on each.
        #[tokio::test]
        async fn boundaries_buried_during_a_halt_are_voted_after_it_clears() {
            let (_exec, storage, _dir) = crate::canonical_apply::tests::fresh();
            let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
            let (headers, hashes) = chain(&dag, 16, 0).await;
            let lookup = |x: &Hash| Ok(headers.get(x).copied());
            let tip = |h: u64| hashes.get(h as usize).copied().expect("tip hash");
            let ks: Vec<Ed25519SigningKey> = (0..4u8).map(key).collect();
            let me = ks.first().expect("key 0");
            let g = gadget_over(dag, &storage, &ks).await;
            let (mut cursor, mut retries) = (0u64, OwnVoteRetries::default());

            // Tip 6: boundary 2 is buried (6 - 3 = 3 -> 2) and voted normally.
            let out = run_pass(&g, Some(me), &mut cursor, &mut retries, tip(6), 6, &lookup).await;
            assert_eq!(heights(&out), vec![2]);

            // Safety stop engaged; the chain advances and buries 4, 6, 8.
            g.safety_stop().engage().await;
            let out = run_pass(
                &g,
                Some(me),
                &mut cursor,
                &mut retries,
                tip(12),
                12,
                &lookup,
            )
            .await;
            assert!(out.is_empty(), "nothing emitted while halted");
            assert_eq!(cursor, 8, "the cursor moved past them");
            for h in [4u64, 6, 8] {
                assert!(!g.manager().has_pending_vote(h, &pk(me)).await);
                assert_eq!(g.signed_vote_at(h), None, "nothing signed while halted");
            }
            // Still halted: another pass does nothing and keeps them.
            let out = run_pass(
                &g,
                Some(me),
                &mut cursor,
                &mut retries,
                tip(12),
                12,
                &lookup,
            )
            .await;
            assert!(out.is_empty());
            assert_eq!(retries.len(), 3);

            // Stop clears (mismatch resolved by fork choice): the next pass, with
            // no new boundary, revisits 4, 6, 8 and votes them.
            g.safety_stop().clear().await;
            let out = run_pass(
                &g,
                Some(me),
                &mut cursor,
                &mut retries,
                tip(12),
                12,
                &lookup,
            )
            .await;
            assert_eq!(heights(&out), vec![4, 6, 8]);
            for (h, i) in [(4u64, 4usize), (6, 6), (8, 8)] {
                let hash = hashes.get(i).copied().expect("hash");
                assert!(g.manager().has_pending_vote(h, &pk(me)).await);
                assert_eq!(g.signed_vote_at(h), Some(hash));
            }
            assert_eq!(retries.len(), 0, "revisited once, then forgotten");
            let out = run_pass(
                &g,
                Some(me),
                &mut cursor,
                &mut retries,
                tip(12),
                12,
                &lookup,
            )
            .await;
            assert!(out.is_empty(), "no repeat");
        }

        /// L1a: an own vote signed just before the safety stop engaged is
        /// withheld from broadcast, held, and re-broadcast — the SAME recorded
        /// vote, no new signature — on the first pass after the stop clears.
        /// Without the hold the revisit finds the vote already pending and emits
        /// nothing, so peers never receive it until restart.
        #[tokio::test]
        async fn own_vote_signed_before_a_halt_is_rebroadcast_after_it_clears() {
            let (_exec, storage, _dir) = crate::canonical_apply::tests::fresh();
            let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
            let (headers, hashes) = chain(&dag, 16, 0).await;
            let lookup = |x: &Hash| Ok(headers.get(x).copied());
            let tip = |h: u64| hashes.get(h as usize).copied().expect("tip hash");
            let ks: Vec<Ed25519SigningKey> = (0..4u8).map(key).collect();
            let me = ks.first().expect("key 0");
            let g = gadget_over(dag, &storage, &ks).await;
            let (mut cursor, mut retries) = (0u64, OwnVoteRetries::default());

            // Boundary 2 is signed in this pass ...
            let out = run_pass(&g, Some(me), &mut cursor, &mut retries, tip(6), 6, &lookup).await;
            assert_eq!(heights(&out), vec![2]);
            let signed = out.first().cloned().expect("own vote");
            assert_eq!(signed.voter, pk(me));
            assert_eq!(g.signed_vote_at(2), Some(signed.block_hash));
            // ... and the stop engages before it is broadcast.
            g.safety_stop().engage().await;
            let sent = gate_outbound(&g, Some(me), &mut retries, out);
            assert!(sent.is_empty(), "withheld while halted");
            assert!(retries.has_held(2));

            // Still halted: nothing is emitted, the vote stays held.
            let out = run_pass(&g, Some(me), &mut cursor, &mut retries, tip(6), 6, &lookup).await;
            let out = gate_outbound(&g, Some(me), &mut retries, out);
            assert!(out.is_empty());
            assert!(retries.has_held(2));
            // The gadget alone would never re-emit it: it is already pending.
            assert!(g.manager().has_pending_vote(2, &pk(me)).await);

            // Stop clears: the next pass re-broadcasts the identical vote.
            g.safety_stop().clear().await;
            let out = run_pass(&g, Some(me), &mut cursor, &mut retries, tip(6), 6, &lookup).await;
            let out = gate_outbound(&g, Some(me), &mut retries, out);
            let key_of = |v: &CheckpointVote| {
                (
                    v.height,
                    v.block_hash,
                    v.voter,
                    v.signature.as_bytes().to_vec(),
                )
            };
            assert_eq!(
                out.iter().map(key_of).collect::<Vec<_>>(),
                vec![key_of(&signed)],
                "the recorded vote, re-sent as-is"
            );
            assert_eq!(
                g.signed_vote_at(2),
                Some(signed.block_hash),
                "record unchanged"
            );
            assert!(!retries.has_held(2));
            assert_eq!(retries.len(), 0);
            let out = run_pass(&g, Some(me), &mut cursor, &mut retries, tip(6), 6, &lookup).await;
            assert!(out.is_empty(), "sent once");
        }

        /// A held own vote whose block is no longer canonical at that height
        /// when the stop clears is dropped, and the gadget still refuses to sign
        /// the new canonical block there (durable record).
        #[tokio::test]
        async fn held_own_vote_is_dropped_if_its_block_left_the_canonical_chain() {
            let (_exec, storage, _dir) = crate::canonical_apply::tests::fresh();
            let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
            let (ha, a) = chain(&dag, 8, 0xA0).await;
            let (hb, b) = chain(&dag, 8, 0xB0).await;
            let ks: Vec<Ed25519SigningKey> = (0..4u8).map(key).collect();
            let me = ks.first().expect("key 0");
            let g = gadget_over(dag, &storage, &ks).await;
            let (mut cursor, mut retries) = (0u64, OwnVoteRetries::default());
            let lookup_a = |x: &Hash| Ok(ha.get(x).copied());
            let tip_a = a.get(6).copied().expect("a6");
            let out = run_pass(&g, Some(me), &mut cursor, &mut retries, tip_a, 6, &lookup_a).await;
            assert_eq!(heights(&out), vec![2]);
            g.safety_stop().engage().await;
            assert!(gate_outbound(&g, Some(me), &mut retries, out).is_empty());
            assert!(retries.has_held(2));

            // The node is now on branch B; the stop clears.
            g.safety_stop().clear().await;
            let lookup_b = |x: &Hash| Ok(hb.get(x).copied());
            let tip_b = b.get(6).copied().expect("b6");
            let out = run_pass(&g, Some(me), &mut cursor, &mut retries, tip_b, 6, &lookup_b).await;
            assert!(
                out.iter().all(|v| v.height != 2),
                "neither the stale held vote nor a new signature at 2: {out:?}"
            );
            assert_eq!(g.signed_vote_at(2), a.get(2).copied(), "record unchanged");
            assert!(!retries.has_held(2));
            assert_eq!(retries.len(), 0);
        }

        /// The revisit is still bound by the durable signed-vote record: a
        /// height this key signed for a different hash before the halt (here:
        /// before a restart onto another branch) is refused, nothing is emitted
        /// for it, and it is not revisited again.
        #[tokio::test]
        async fn revisit_after_halt_still_refuses_a_different_hash() {
            let (_exec, storage, _dir) = crate::canonical_apply::tests::fresh();
            let dag = Arc::new(DagStore::with_permissive_vrf_for_testing());
            let (_ha, a) = chain(&dag, 12, 0xA0).await;
            let (hb, b) = chain(&dag, 12, 0xB0).await;
            let ks: Vec<Ed25519SigningKey> = (0..4u8).map(key).collect();
            let me = ks.first().expect("key 0");
            let a4 = a.get(4).copied().expect("a4");
            {
                // Earlier run: signed (4, a4).
                let g = gadget_over(dag.clone(), &storage, &ks).await;
                let out = g
                    .on_buried_checkpoint(4, a4, &Hash::new([7; 32]), Some(me))
                    .await;
                assert!(out.signed_own_vote);
            }
            // Restart on branch B, halted before boundary 4 is reported.
            let g = gadget_over(dag, &storage, &ks).await;
            let lookup = |x: &Hash| Ok(hb.get(x).copied());
            let tip = b.get(8).copied().expect("tip");
            let (mut cursor, mut retries) = (0u64, OwnVoteRetries::default());
            g.safety_stop().engage().await;
            let out = run_pass(&g, Some(me), &mut cursor, &mut retries, tip, 8, &lookup).await;
            assert!(out.is_empty());
            assert_eq!(retries.len(), 2, "2 and 4 deferred");
            g.safety_stop().clear().await;
            let out = run_pass(&g, Some(me), &mut cursor, &mut retries, tip, 8, &lookup).await;
            assert_eq!(heights(&out), vec![2], "4 is refused, not emitted");
            assert_eq!(g.signed_vote_at(4), Some(a4), "record unchanged");
            assert!(!g.manager().has_pending_vote(4, &pk(me)).await);
            assert_eq!(retries.len(), 0, "a permanent refusal is not revisited");
            // Direct confirmation of the refusal reason.
            let again = g
                .on_buried_checkpoint(
                    4,
                    b.get(4).copied().expect("b4"),
                    &Hash::new([7; 32]),
                    Some(me),
                )
                .await;
            assert_eq!(
                again.sign_refused,
                Some(SignRefusal::Conflicting { signed: a4 })
            );
        }
    }

    #[test]
    fn vote_message_round_trips_fields() {
        use citrate_consensus::types::{PublicKey, Signature};
        let v = CheckpointVote {
            height: 42,
            block_hash: h(9),
            voter: PublicKey::new([3; 32]),
            signature: Signature::new([4; 64]),
        };
        match to_message(&v) {
            NetworkMessage::CheckpointVote {
                height,
                block_hash,
                voter_pubkey,
                signature,
            } => {
                assert_eq!(height, 42);
                assert_eq!(block_hash, h(9));
                assert_eq!(voter_pubkey, vec![3u8; 32]);
                assert_eq!(signature, vec![4u8; 64]);
            }
            other => panic!("unexpected message {other:?}"),
        }
    }
}
